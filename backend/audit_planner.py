"""Repository observations and required-AI audit/lab planning.

Heuristics provide source context; production audits require a verified AI
response. Failed or malformed required responses never become successful plans.
Offline callers may request source-only heuristic plans explicitly. Runtime
attestation and coverage remain independent requirements after planning.
"""
from __future__ import annotations

import json
import asyncio
import os
import re
import hashlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from backend.lab_analyzer import gather_build_context
from backend.lab_builder import analyze_repo_requirements, discover_lab_artifacts
from backend.ai_readiness import AIRequiredError


class AuditPlanQualityError(AIRequiredError):
    """A model answered, but neither bounded attempt produced a valid plan."""

    def __init__(self, diagnostic, *, response=None):
        self.diagnostic = diagnostic
        super().__init__(f"Audit plan rejected at {diagnostic['path']}: {diagnostic['reason']}", response=response)


_PLAN_FIELDS = ("install_steps", "start_command", "smoke_test", "extra_packages", "phase2_tasks", "audit_focus")
_TASK_FIELDS = ("title", "category", "priority", "target", "technique", "why")
AUDIT_PLAN_SCHEMA = {
    "type": "object",
    "anyOf": [{"required": [field]} for field in _PLAN_FIELDS],
    "properties": {
        **{field: {"type": "array", "items": {"type": "string"}}
           for field in ("install_steps", "extra_packages", "audit_focus", "notes")},
        **{field: {"type": "string"} for field in ("start_command", "smoke_test")},
        "phase2_tasks": {"type": "array", "maxItems": 24, "items": {
            "type": "object", "required": ["title"],
            "properties": {field: {"type": "string", **({"pattern": "\\S"} if field == "title" else {})}
                           for field in _TASK_FIELDS}}},
    },
}


def _plan_validation_error(obj):
    """Return only fixed validation text/paths, never model or source content."""
    def problem(code, path, reason):
        return {"code": code, "path": path, "reason": reason}
    if not isinstance(obj, dict) or not any(field in obj for field in _PLAN_FIELDS):
        return problem("plan_object_required", "$", "Return a JSON object with at least one declared plan field")
    for field in ("install_steps", "extra_packages", "audit_focus", "notes"):
        if field in obj and (not isinstance(obj[field], list) or any(not isinstance(item, str) for item in obj[field])):
            return problem("plan_string_list_required", "$." + field, "Use an array of strings, or [] when none apply")
    for field in ("start_command", "smoke_test"):
        if field in obj and not isinstance(obj[field], str):
            return problem("plan_command_string_required", "$." + field, 'Use a string; use "" when no command applies, never null')
    if "phase2_tasks" in obj:
        tasks = obj["phase2_tasks"]
        if not isinstance(tasks, list) or len(tasks) > 24:
            return problem("plan_task_list_required", "$.phase2_tasks", "Use an array of at most 24 task objects")
        for index, task in enumerate(tasks):
            path = f"$.phase2_tasks[{index}]"
            if not isinstance(task, dict) or not isinstance(task.get("title"), str) or not task["title"].strip():
                return problem("plan_task_title_required", path + ".title", "Each task needs a nonempty string title")
            for field in _TASK_FIELDS:
                if field in task and not isinstance(task[field], str):
                    return problem("plan_task_string_required", path + "." + field, "Use a string for this task field")
    if re.search(r"\|\|[^\n]*python(?:3)?\s+-m\s+http\.server", str(obj.get("start_command") or "")):
        return problem("plan_synthetic_service_forbidden", "$.start_command", "A failed target cannot be replaced by a synthetic file server")
    return None


MANIFEST_LANGS = (
    ("mix.exs", "elixir"),
    ("Cargo.toml", "rust"),
    ("go.mod", "go"),
    ("pom.xml", "java"),
    ("build.gradle", "java"),
    ("build.gradle.kts", "java"),
    ("package.json", "node"),
    ("requirements.txt", "python"),
    ("pyproject.toml", "python"),
    ("Gemfile", "ruby/rails"),
    ("composer.json", "php"),
    ("CMakeLists.txt", "c/cpp"),
    ("*.csproj", "csharp"),
    ("*.sln", "csharp"),
    ("build.sbt", "scala"),
    ("pubspec.yaml", "dart"),
    ("Package.swift", "swift"),
    ("build.zig", "zig"),
)


def _nested_manifest(dest: Path, filename: str, max_depth: int = 4) -> bool:
    """True if filename exists at dest or within max_depth (skips vendor/target)."""
    dest = Path(dest)
    skip = {".git", "node_modules", "vendor", "target", "third_party", ".venv", "build"}
    if (dest / filename).is_file():
        return True
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".")]
        rel = Path(root).relative_to(dest)
        if len(rel.parts) > max_depth:
            dirs.clear()
            continue
        if filename in files:
            return True
    return False


def detect_secondary_languages(dest: Path) -> List[str]:
    """All stacks present, including nested monorepo crates (CubeAPI, execd)."""
    dest = Path(dest)
    found: List[str] = []
    checks = [
        (_nested_manifest(dest, "mix.exs"), "elixir"),
        (_nested_manifest(dest, "Cargo.toml"), "rust"),
        (_nested_manifest(dest, "go.mod"), "go"),
        ((dest / "pom.xml").exists() or (dest / "build.gradle").exists()
         or (dest / "build.gradle.kts").exists(), "java"),
        (_nested_manifest(dest, "package.json"), "node"),
        ((dest / "requirements.txt").exists() or (dest / "pyproject.toml").exists()
         or (dest / "setup.py").exists(), "python"),
        ((dest / "Gemfile").exists() or any(dest.glob("*.gemspec")), "ruby/rails"),
        ((dest / "composer.json").exists(), "php"),
        ((dest / "CMakeLists.txt").exists() or (dest / "Makefile").exists(), "c/cpp"),
        (any(dest.glob("*.csproj")) or any(dest.glob("*.sln")), "csharp"),
        ((dest / "build.sbt").exists(), "scala"),
        ((dest / "pubspec.yaml").exists(), "dart"),
        ((dest / "Package.swift").exists(), "swift"),
        ((dest / "build.zig").exists(), "zig"),
        ((dest / "config.m4").exists(), "c/cpp"),
    ]
    for ok, lang in checks:
        if ok and lang not in found:
            found.append(lang)
    return found


def _heuristic_extra_for_language(dest: Path, language: str, app_type: str) -> Dict[str, Any]:
    """Install/start/smoke for stacks the older template path missed."""
    dest = Path(dest)
    extra: Dict[str, Any] = {
        "install_steps": [],
        "start_command": None,
        "smoke_test": None,
        "extra_packages": [],
        "env_vars": {},
        "notes": [],
    }
    lang = (language or "").lower()

    if lang == "rust" and (dest / "Cargo.toml").exists():
        extra["extra_packages"] = ["curl", "pkg-config"]
        extra["install_steps"] = [
            "command -v cargo >/dev/null || "
            "(curl -sSf https://sh.rustup.rs | sh -s -- -y && . $HOME/.cargo/env)",
            ". $HOME/.cargo/env 2>/dev/null; cargo build --offline 2>/dev/null || cargo build",
        ]
        extra["smoke_test"] = ". $HOME/.cargo/env 2>/dev/null; cargo --version && echo SMOKE_OK"
        if app_type in ("web-app", "api-service"):
            extra["start_command"] = (
                ". $HOME/.cargo/env 2>/dev/null; "
                "cargo run --release -- --port ${PORT}"
            )
        extra["notes"].append("Rust: rustup during lab build (network allowed)")

    elif lang == "elixir" and (dest / "mix.exs").exists():
        extra["extra_packages"] = ["elixir", "erlang-dev", "erlang-nox"]
        extra["install_steps"] = [
            "mix local.hex --force && mix local.rebar --force",
            "mix deps.get",
            "MIX_ENV=test mix compile",
        ]
        extra["smoke_test"] = "elixir -e 'IO.puts(\"SMOKE_OK\")'"
        if app_type in ("web-app", "api-service"):
            extra["start_command"] = (
                "mix phx.server"
            )
        extra["notes"].append("Elixir/Phoenix: mix deps + compile")

    elif lang in ("csharp", "c#", "dotnet") and (
        any(dest.glob("*.csproj")) or any(dest.glob("*.sln"))
    ):
        extra["install_steps"] = [
            "command -v dotnet >/dev/null || "
            "(curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --channel 8.0)",
            "export PATH=\"$PATH:$HOME/.dotnet\"; dotnet restore && dotnet build -c Release --no-restore",
        ]
        extra["smoke_test"] = "export PATH=\"$PATH:$HOME/.dotnet\"; dotnet --version && echo SMOKE_OK"
        extra["notes"].append("C#/.NET: dotnet-install during lab build")
        extra["env_vars"]["PATH"] = "$PATH:/root/.dotnet:$HOME/.dotnet"

    elif lang == "scala" and (dest / "build.sbt").exists():
        extra["extra_packages"] = ["openjdk-21-jdk-headless"]
        extra["install_steps"] = [
            "command -v sbt >/dev/null || (curl -sL https://github.com/sbt/sbt/releases/download/v1.10.2/sbt-1.10.2.tgz | tar xz -C /usr/local --strip-components=1)",
            "sbt -batch compile",
        ]
        extra["smoke_test"] = "sbt -batch about && echo SMOKE_OK"
        extra["notes"].append("Scala: sbt compile during lab build")

    elif lang == "kotlin":
        extra["install_steps"] = [
            "if [ -f build.gradle ] || [ -f build.gradle.kts ]; then gradle build -x test --no-daemon; fi",
        ]
        extra["smoke_test"] = "echo SMOKE_OK"
        extra["notes"].append("Kotlin: gradle when present")

    elif lang == "dart" and (dest / "pubspec.yaml").exists():
        extra["install_steps"] = [
            "command -v dart >/dev/null",
            "dart pub get",
        ]
        extra["smoke_test"] = "dart --version && echo SMOKE_OK"
        extra["notes"].append("Dart: pub get")

    elif lang == "zig" and (dest / "build.zig").exists():
        extra["install_steps"] = [
            "command -v zig >/dev/null || (curl -sL https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz | tar xJ -C /usr/local && ln -sf /usr/local/zig-linux-x86_64-0.13.0/zig /usr/local/bin/zig)",
            "zig build",
        ]
        extra["smoke_test"] = "zig version && echo SMOKE_OK"
        extra["notes"].append("Zig: zig build")

    elif lang == "swift" and (dest / "Package.swift").exists():
        extra["install_steps"] = ["swift build"]
        extra["smoke_test"] = "swift --version && echo SMOKE_OK"
        extra["notes"].append("Swift: swift build")

    elif lang in ("ruby", "ruby/rails") and any(dest.glob("*.gemspec")) and not (dest / "Gemfile").exists():
        extra["install_steps"] = [
            "gem install bundler:2.4.22 2>/dev/null || true",
            "RUBYLIB=/app/lib:$RUBYLIB; "
            "(cd /app && gem build *.gemspec && gem install --no-document *.gem) || true",
        ]
        extra["smoke_test"] = "RUBYLIB=/app/lib ruby -e 'puts %(SMOKE_OK)'"
        extra["notes"].append("Ruby gem without Gemfile: gemspec build + RUBYLIB=/app/lib")

    elif lang == "go" and (dest / "go.mod").exists() and app_type in ("web-app", "api-service"):
        extra["start_command"] = (
            "/app/app --port ${PORT}"
        )

    elif lang == "php" and (dest / "composer.json").exists() and app_type in ("web-app", "api-service"):
        extra["start_command"] = "php -S 0.0.0.0:${PORT} -t /app/public 2>/dev/null || php -S 0.0.0.0:${PORT} -t /app"

    return extra


def heuristic_plan(dest: Path, language: str, app_type: str) -> Dict[str, Any]:
    dest = Path(dest)
    artifacts = discover_lab_artifacts(dest)
    reqs = analyze_repo_requirements(dest, language, app_type)
    extra = _heuristic_extra_for_language(dest, language, app_type)
    langs = detect_secondary_languages(dest)
    if language and language not in langs:
        langs.insert(0, language)

    if artifacts.get("compose_usable"):
        strategy = "compose"
    elif artifacts.get("published_images"):
        strategy = "published-image"
    elif artifacts.get("dockerfile_usable"):
        strategy = "dockerfile"
    else:
        strategy = "generated"

    install = list(reqs.get("install_steps") or [])
    for step in extra.get("install_steps") or []:
        if step not in install:
            install.append(step)

    notes = list(reqs.get("analysis_notes") or []) + list(extra.get("notes") or [])
    env = dict(reqs.get("env_vars") or {})
    env.update(extra.get("env_vars") or {})
    focus = _default_audit_focus(language, app_type, artifacts)

    return {
        "language": language,
        "languages": langs,
        "app_type": app_type,
        "lab_strategy": strategy,
        "install_steps": install,
        "start_command": extra.get("start_command") or reqs.get("start_command"),
        "smoke_test": extra.get("smoke_test") or reqs.get("smoke_test"),
        "package_test_command": reqs.get("package_test_command"),
        "extra_packages": extra.get("extra_packages") or [],
        "system_libs": list(reqs.get("system_libs") or []),
        "env_vars": env,
        "phase2_tasks": _heuristic_phase2_tasks(
            language, app_type, focus, artifacts, langs,
            package_test_command=reqs.get("package_test_command"),
        ),
        "audit_focus": focus,
        "notes": notes,
        "source": "heuristic",
        "has_compose": bool(artifacts.get("has_compose")),
        "has_dockerfile": bool(artifacts.get("has_dockerfile")),
        "published_images": [
            (img.get("image") if isinstance(img, dict) else str(img))
            for img in (artifacts.get("published_images") or [])
        ],
    }


def _heuristic_phase2_tasks(
    language: str, app_type: str, focus: List[str], artifacts: Dict[str, Any],
    langs: Optional[List[str]] = None,
    package_test_command: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Default methodology and executable language-specific runtime checks.

    Phase 2 retains exact targetless methodology as planning context. Package,
    consumer-harness and fuzz runtime checks remain executable obligations.
    """
    tasks: List[Dict[str, Any]] = []
    stack = {language, *list(langs or [])}

    def t(title: str, category: str, why: str, technique: str = "lab-poc", command: str = "") -> None:
        row = {
            "title": title, "category": category, "priority": "high",
            "target": "", "technique": technique, "why": why,
        }
        if command:
            row["command"] = command
        tasks.append(row)

    t("Prove or DISPROVE every ≥7 lead in the local lab with measurements",
      "validation", "Nothing is a finding until a lab PoC shows impact")
    if "published-image-lab" in focus:
        t("Prefer published image / compose over compiling a multi-hour toolchain",
          "lab", "README/GHCR image is the supported runtime")
    if stack & {"c/cpp", "rust"}:
        t("Unauthenticated admin/protocol commands and fail-open auth",
          "protocol-admin", "Brokers/DBs often ship AnonAuthenticator + always-true authorize")
        t("Stubbed privilege checks (if (!(true)), no_priv_needed, skip_sys_table_check)",
          "authz", "USAGE-only mutating admin is high-severity when impact is measured")
    if stack & {"ruby/rails", "ruby", "python", "php"}:
        t("Unsafe deserialization and Marshal/pickle/unserialize sinks",
          "deser", "Library APIs that decode attacker bytes")
    if stack & {"go", "rust"}:
        t("Empty-token / skip-middleware fail-open on mutating HTTP (command, sandbox create)",
          "authz-bypass", "Default-allow APIs and if token==\"\" { Next() } are default-insecure RCE")
        t("sh -c of config commands, filepath.Join absolute escape, gob/proto of network bytes",
          "deser", "Go control-plane sinks missed by Ruby/Java deser scanners")
        t("Redis/queue Inspector as admin plane when Redis has no AUTH",
          "insecure-default", "Enqueue a worker type; oracle is handler side-effect not queue-wipe DoS")
        t("Walk trust-boundary map: unauth mutating HTTP, bind-all, sibling missing guard",
          "control-plane", "Phase 1 trust-boundary.json lists verbs Phase 2 must lab-prove")
        t("Walk handler-sink traces: unauth verb → RCE/write/SSRF/deser/Join",
          "control-plane", "Phase 1 handler_sinks.json ranks edges Phase 2 must lab-prove")
        t("Walk component-lab map: each go.mod/Cargo.toml/Dockerfile is its own TCB + lab recipe",
          "control-plane", "Monorepos must not be labbed as the primary language only")
    if "c/cpp" in stack:
        t("FFmpeg nested protocol/file open from untrusted media (not CLI -i)",
          "lab-poc", "HLS file: / movie= / concat -safe 0; DISPROVE operator argv file read")
    if app_type in ("library", "cli-tool"):
        # A library has no HTTP application surface to probe. Its own tests and
        # package import are the relevant executable evidence, so make this a
        # first-class Phase 2 task instead of silently skipping all validation.
        # Node's maintained test command is allowlisted and executable; other
        # ecosystems receive an explicit adapter-gap row rather than being
        # silently omitted from the consumer/protocol coverage denominator.
        if language == "node" and package_test_command:
            t(
                "Run the repository's Node test suite in the isolated lab",
                "package-test",
                "Exercise the enrolled package with its maintained tests; failures are evidence gaps, not vulnerabilities.",
                technique="repository-test",
                command=package_test_command,
            )
        t(
            f"Run generated {language} consumer harness (HTTP/HTTPS/WebSocket, redirects, headers, timeout, config variants)",
            "library-harness",
            "A package can pass its own tests while a real consumer reaches an unsafe protocol/configuration path. Unsupported language adapters are recorded as explicit skips.",
            technique="generated-consumer-harness",
        )
        t(
            f"Run bounded {language} public-API fuzzing with coverage instrumentation",
            "library-fuzz",
            "Exercise malformed options and exported constructors while retaining coverage and crash/exception counts; unavailable instrumentation is a visible gap.",
            technique="coverage-guided-smoke-fuzz",
        )

    if app_type in ("web-app", "api-service"):
        t("Authz bypass on mutating endpoints (sibling missing guard)",
          "authz-bypass", "Compare privileged vs unprivileged clients")
    if artifacts.get("published_images") or artifacts.get("compose_usable"):
        t("Default-insecure quickstart (empty root password, no auth)",
          "insecure-default", "Qualify as default-insecure, still lab-prove impact")
    return tasks


def _default_audit_focus(language: str, app_type: str, artifacts: Dict[str, Any]) -> List[str]:
    focus = ["phase1-recon", "lab-poc", "proof-gates"]
    if app_type in ("web-app", "api-service"):
        focus.extend(["http-poc", "authz-bypass", "injection"])
    if app_type in ("cli-tool", "library"):
        focus.extend(["cli-argv", "library-api", "deser"])
    if language in ("c/cpp", "rust"):
        focus.extend(["memory-safety", "protocol-admin"])
    if artifacts.get("published_images"):
        focus.append("published-image-lab")
    return focus


def _extract_json_object(text: str) -> Optional[dict]:
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def merge_ai_into_plan(plan: Dict[str, Any], ai_obj: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(plan)
    for key in ("start_command", "smoke_test"):
        val = ai_obj.get(key)
        if isinstance(val, str):
            out[key] = val.strip()
    for key in ("install_steps", "extra_packages", "audit_focus", "notes"):
        val = ai_obj.get(key)
        if isinstance(val, list):
            merged = list(out.get(key) or [])
            for item in val:
                s = str(item).strip()
                if s and s not in merged:
                    merged.append(s)
            out[key] = merged
    tasks = ai_obj.get("phase2_tasks") or []
    parsed_tasks: List[Dict[str, Any]] = []
    if isinstance(tasks, list):
        for t in tasks[:24]:
            if not isinstance(t, dict):
                continue
            title = str(t.get("title") or "").strip()
            if not title:
                continue
            parsed_tasks.append({
                "title": title[:160],
                "category": str(t.get("category") or "validation")[:40],
                "priority": str(t.get("priority") or "high")[:20],
                "target": str(t.get("target") or "")[:120],
                "technique": str(t.get("technique") or "lab-poc")[:80],
                "why": str(t.get("why") or "AI audit plan")[:400],
            })
    if parsed_tasks:
        existing = list(out.get("phase2_tasks") or [])
        seen = {(t.get("title") if isinstance(t, dict) else "") for t in existing}
        for t in parsed_tasks:
            if t["title"] not in seen:
                existing.append(t)
                seen.add(t["title"])
        out["phase2_tasks"] = existing
    out["source"] = "heuristic+ai"
    return out


def build_plan_prompt(dest: Path, plan: Dict[str, Any]) -> str:
    ctx = gather_build_context(dest, max_chars=6000)
    return (
        "You are planning a frictionless security-audit lab for this repository.\n"
        "Return ONLY a JSON object with keys:\n"
        "  install_steps: string[] (shell commands for generated OCI image build stages: build user root, source directory /app; no Docker daemon or socket commands)\n"
        "  start_command: string (how to run the built app as a non-root service; ${PORT} is the lab port)\n"
        "  smoke_test: string (command that prints SMOKE_OK on success)\n"
        "  extra_packages: string[] (apt package names not already in ubuntu)\n"
        "  audit_focus: string[] (bug classes / surfaces to prioritize: RCE, authz, deser, ...)\n"
        "  phase2_tasks: [{title, category, priority, target, technique, why}]  (8-15 tasks)\n"
        "  notes: string[]\n"
        "Rules: no markdown. Prefer existing repository image recipes or published OCI images over compiling multi-hour C++.\n"
        'A library, CLI or data-only repository need not run a network service. Use start_command="" when no service applies; never use null for any command.\n'
        "Use [] for list fields with no applicable values. Keep task explanations concise.\n"
        "Image construction runs in the selected provider's builder; build-time root does not imply root at service runtime.\n"
        "Do not emit exploit payloads; tasks are validation/reproduction plans.\n\n"
        f"Detected language={plan.get('language')} app_type={plan.get('app_type')} "
        f"lab_strategy={plan.get('lab_strategy')} languages={plan.get('languages')}\n"
        f"Heuristic install_steps={plan.get('install_steps')}\n"
        f"Heuristic start={plan.get('start_command')}\n\n"
        f"Exact output schema (also used for a correction attempt): {json.dumps(AUDIT_PLAN_SCHEMA, separators=(',', ':'))}\n"
        f"--- build files ---\n{ctx}\n"
    )


async def _owned_plan_response(ai_call, request):
    """Cancel and drain the exact bounded model call before releasing the audit."""
    from threading import Event
    from backend.ai_gateway import independent_review_transport
    stopped = Event()

    def invoke():
        with independent_review_transport(stopped):
            return ai_call(request)

    work = asyncio.create_task(asyncio.to_thread(invoke))
    try:
        return await asyncio.shield(work)
    except asyncio.CancelledError:
        stopped.set()
        while not work.done():
            try:
                await asyncio.wait([work], timeout=.05)
            except asyncio.CancelledError:
                continue
        try:
            work.result()
        except BaseException:
            pass
        raise


async def _required_ai_plan(plan, prompt, ai_call, send, repo_id):
    """Two model attempts per explicit invocation; no inferred replacement."""
    attempts = []
    request = prompt
    for attempt in (1, 2):
        # Provider authentication/transport recovery belongs to ai_runtime.
        # Platform exceptions here must not be mistaken for invalid credentials.
        raw = await _owned_plan_response(ai_call, request)
        if hasattr(raw, "__await__"):
            raw = await raw
        if hasattr(raw, "status") and str(getattr(raw.status, "value", raw.status)) != "ok":
            raise AIRequiredError("The model did not return a successful audit-plan response", response=raw)
        text = raw if isinstance(raw, str) else getattr(raw, "text", "") or ""
        metadata = getattr(raw, "meta", None)
        quality = metadata.get("response_quality") if isinstance(metadata, dict) else None
        quality = quality if isinstance(quality, dict) else {}
        # A syntactically valid prefix of a truncated response is incomplete.
        # Never merge it or execute it, even when it happens to satisfy schema.
        rejected = next((key for key in ("truncated", "empty", "invalid_provider_payload", "response_body_rejected")
                         if quality.get(key) is True), None)
        diagnostic = ({"code": "plan_response_" + rejected, "path": "$",
                       "reason": "The provider response was " + rejected.replace("_", " ") +
                                 "; return one complete bounded plan"} if rejected else None)
        obj = None if diagnostic else _extract_json_object(text)
        diagnostic = diagnostic or _plan_validation_error(obj)
        if diagnostic is None:
            # Merging errors are platform errors, outside validation recovery.
            enriched = merge_ai_into_plan(plan, obj)
            diagnostic = _plan_validation_error({"start_command": enriched.get("start_command") or ""})
        attempts.append({"attempt": attempt, "status": "rejected" if diagnostic else "accepted",
                         "response_sha256": hashlib.sha256(text.encode()).hexdigest(),
                         **({"diagnostic": diagnostic} if diagnostic else {})})
        if diagnostic is None:
            enriched["ai_plan_validation"] = {"schema_version": 1, "status": "accepted", "attempts": attempts}
            if send:
                await send(repo_id, f"AI enriched audit plan ({len(enriched.get('phase2_tasks') or [])} Phase 2 tasks)", level="info")
            return enriched
        if attempt == 2:
            raise AuditPlanQualityError({**diagnostic, "attempts": attempts, "max_attempts": 2}, response=raw)
        if send:
            await send(repo_id, f"Audit plan needs a correction at {diagnostic['path']}: {diagnostic['reason']}. Retrying once with the same validation rules.",
                       level="warning", detail_id=f"{repo_id}-audit-plan-validation",
                       detail={"type": "audit_plan_validation", "status": "repairing", **diagnostic, "attempt": 1, "max_attempts": 2})
        request = (prompt + "\nThe previous response was rejected and was not executed. Generate one complete corrected JSON object using the identical schema above.\n"
                   + f"Validation: {diagnostic['path']} — {diagnostic['reason']}\n")


def persist_plan(dest: Path, plan: Dict[str, Any]) -> Path:
    out_dir = Path(dest) / ".lotus"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "audit_plan.json"
    path.write_text(json.dumps(plan, indent=2, default=str), encoding="utf-8")
    return path


def apply_plan_to_requirements(reqs: Dict[str, Any], plan: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Overlay planner output onto lab_builder requirements."""
    if not plan:
        return reqs
    out = dict(reqs)
    if plan.get("install_steps"):
        merged = list(out.get("install_steps") or [])
        for s in plan["install_steps"]:
            if s not in merged:
                merged.append(s)
        out["install_steps"] = merged
    if isinstance(plan.get("start_command"), str):
        out["start_command"] = plan["start_command"]
    if isinstance(plan.get("smoke_test"), str):
        out["smoke_test"] = plan["smoke_test"]
    if plan.get("package_test_command"):
        out["package_test_command"] = plan["package_test_command"]
    if plan.get("extra_packages"):
        libs = list(out.get("system_libs") or [])
        for p in plan["extra_packages"]:
            if p not in libs:
                libs.append(p)
        out["system_libs"] = libs
    env = dict(out.get("env_vars") or {})
    env.update(plan.get("env_vars") or {})
    out["env_vars"] = env
    return out


async def build_audit_plan(
    dest: Path,
    language: str,
    app_type: str,
    *,
    send: Optional[Callable] = None,
    repo_id: int = 0,
    ai_call: Optional[Callable[..., Any]] = None,
    repo_source: str = "",
    reuse_prior_artifacts: bool = False,
    required_ai: bool = False,
) -> Dict[str, Any]:
    """Combine source observations with AI; required mode fails closed."""
    dest = Path(dest)
    plan = heuristic_plan(dest, language, app_type)
    try:
        from backend.learned_memory import overlay_retrospectives
        if reuse_prior_artifacts:
            plan = overlay_retrospectives(plan, dest, repo_source=repo_source)
    except Exception:
        pass
    if send:
        await send(
            repo_id,
            f"Audit plan: {plan['lab_strategy']} lab for {language}/{app_type} "
            f"(stacks={','.join(plan['languages']) or language})",
            level="info",
        )

    if required_ai:
        if ai_call is None:
            raise AIRequiredError("A verified AI model is required to produce the audit plan")
        plan = await _required_ai_plan(plan, build_plan_prompt(dest, plan), ai_call, send, repo_id)
        persist_plan(dest, plan)
        return plan
    if ai_call is not None:
        try:
            raw = await asyncio.to_thread(ai_call, build_plan_prompt(dest, plan))
            if hasattr(raw, "__await__"):
                raw = await raw
            text = raw if isinstance(raw, str) else getattr(raw, "text", "") or ""
            obj = _extract_json_object(text)
            if obj:
                plan = merge_ai_into_plan(plan, obj)
                if send:
                    await send(repo_id, f"AI enriched audit plan ({len(plan.get('phase2_tasks') or [])} Phase 2 tasks)", level="info")
        except Exception as error:
            plan.setdefault("notes", []).append(f"AI plan skipped: {error}")
            if send:
                await send(repo_id, f"AI audit plan skipped ({str(error)[:80]}); using heuristics", level="warning")

    try:
        persist_plan(dest, plan)
    except Exception:
        pass
    return plan
