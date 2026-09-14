"""Phase-1 test-coverage vs attack-surface gap analyzer.

A repository's *own* test suite is a high-signal map of what the authors
considered worth verifying. The security-relevant inverse is far more
interesting for bug discovery: **functions that carry attack surface (they read
untrusted input and/or reach a dangerous sink) yet are never exercised by the
repo's own tests.** Those are exactly the places where a regression, an unhandled
edge case, or an unsanitized path is most likely to survive undetected — prime,
pre-triaged leads for Phase 2 to dig into.

This analyzer is deliberately:

* **Language-agnostic / friction-free.** It ships its own universal
  function-definition, source, and sink lexers spanning Python, JS/TS, Go, Java,
  Ruby, PHP, C/C++, Rust, C#, Kotlin, Scala, Swift. Unknown extensions fall back
  to a generic ``name(...) { ... }`` extractor, so *any* repo produces data with
  zero build or toolchain requirements. It never raises; on any error it returns
  an empty list.
* **Deterministic first, AI-optional.** Scoring and gap detection are pure
  scripts (fast, reproducible, testable). An optional AI enrichment hook
  (:func:`ai_annotate_untested`) can rank/annotate the top gaps when credentials
  exist; it is fully guarded and off unless explicitly enabled.

Output: PoC-ready *leads* (never confirmed findings), plus a persisted coverage
report (:func:`build_coverage_report`) that Phase 2 and the report layer consume.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# File discovery
# --------------------------------------------------------------------------- #

_SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "target", "build", "dist",
    "third_party", "thirdparty", ".tox", "__pycache__", ".bundle", ".gradle",
    "bower_components", "site-packages", ".next", ".cache", "coverage",
    # Vendored / bundled third-party trees: not the repo's *own* attack surface,
    # and their code would otherwise dominate the untested-surface report. The
    # repo's own tests are not expected to cover vendored libraries.
    "3rd", "3rdparty", "external", "externals", "extern", "deps", "submodules",
    "packages", ".pnp", "godeps", "bundled",
}

# Extensions we understand, grouped into a "family" that selects the lexer.
_EXT_FAMILY = {
    ".py": "py",
    ".js": "cstyle", ".jsx": "cstyle", ".mjs": "cstyle", ".cjs": "cstyle",
    ".ts": "cstyle", ".tsx": "cstyle",
    ".go": "go",
    ".java": "cstyle", ".kt": "cstyle", ".kts": "cstyle", ".scala": "cstyle",
    ".cs": "cstyle", ".swift": "cstyle",
    ".rb": "ruby",
    ".php": "php",
    ".c": "cstyle", ".h": "cstyle", ".cc": "cstyle", ".cpp": "cstyle",
    ".cxx": "cstyle", ".hpp": "cstyle", ".hxx": "cstyle", ".hh": "cstyle",
    ".rs": "rust",
}

# A path is a test file if it lives under a test tree OR its filename matches a
# common test-naming convention across ecosystems.
_TEST_DIR_HINTS = (
    "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/", "/it/", "/e2e/",
    "integration-test", "integration_test", "systest", "/testing/", "/qa/",
)
_TEST_NAME = re.compile(
    r"(^test_|_test\.|_test$|\.test\.|\.spec\.|_spec\.|spec_|tests?\.rs$|"
    r"Test[A-Z]|Tests?\.(java|kt|scala|cs)$|\.t\.(cpp|cc)$)",
    re.I,
)


def _is_test_path(rel: str, name: str) -> bool:
    low = ("/" + rel.replace("\\", "/")).lower()
    if any(h in low for h in _TEST_DIR_HINTS):
        return True
    return bool(_TEST_NAME.search(name))


def _iter_source_files(dest: Path, max_files: int = 6000, *, scope=None):
    """Bound content reads while counting every safely enumerated source path."""
    scope = scope if scope is not None else {"discovered": 0, "eligible": 0, "omitted": Counter(), "untraversed": 0}
    n = 0
    def walk_error(_error):
        scope["untraversed"] += 1
    for root, dirs, files in os.walk(dest, followlinks=False, onerror=walk_error):
        kept = []
        for name in sorted(dirs):
            if name in {".git", ".lotus"}:
                continue
            if (Path(root) / name).is_symlink():
                scope["untraversed"] += 1
            else:
                kept.append(name)
        dirs[:] = kept
        for fname in sorted(files):
            ext = Path(fname).suffix.lower()
            if ext not in _EXT_FAMILY:
                continue
            p = Path(root) / fname
            scope["discovered"] += 1
            parents = p.relative_to(dest).parts[:-1]
            if any(name in _SKIP_DIRS or name.startswith(".") for name in parents):
                scope["omitted"]["excluded_directory"] += 1
                continue
            try:
                if p.is_symlink() or not p.is_file():
                    scope["omitted"]["unsafe_path"] += 1
                    continue
                if p.stat().st_size > 800_000:
                    scope["omitted"]["oversized"] += 1
                    continue
            except OSError:
                scope["omitted"]["unreadable"] += 1
                continue
            scope["eligible"] += 1
            if n >= max_files:
                scope["omitted"]["file_cap"] += 1
                continue
            n += 1
            yield p


# --------------------------------------------------------------------------- #
# Universal lexers: function definitions, sources, sinks
# --------------------------------------------------------------------------- #

_FUNC_DEF = {
    # name-capturing regexes; group("name") is the function/method identifier.
    "py": re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*\("),
    "go": re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\("),
    "ruby": re.compile(r"^\s*def\s+(?:self\.)?(?P<name>[A-Za-z_]\w*[!?=]?)"),
    "php": re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+(?P<name>[A-Za-z_]\w*)\s*\("),
    "rust": re.compile(r"^\s*(?:pub\s+(?:\([^)]*\)\s*)?)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_]\w*)\s*[<(]"),
    # C-style covers JS/TS, Java, C/C++, C#, Kotlin, Scala, Swift.
    "cstyle": re.compile(
        r"(?:function\s+(?P<n1>[A-Za-z_]\w*)\s*\()"                       # JS function foo(
        r"|(?:\b(?P<n2>[A-Za-z_]\w*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)"  # const foo = (..)=>
        r"|(?:\b(?P<n3>[A-Za-z_]\w*)\s*:\s*(?:async\s*)?function\b)"      # foo: function
        r"|(?:\bfun\s+(?P<n4>[A-Za-z_]\w*)\s*\()"                          # kotlin fun foo(
        r"|(?:\bfunc\s+(?P<n5>[A-Za-z_]\w*)\s*\()"                         # swift func foo(
        r"|(?:\bdef\s+(?P<n6>[A-Za-z_]\w*)\s*[\(:])"                       # scala def foo(
        r"|(?:(?:public|private|protected|internal|static|final|virtual|override|inline|def)\s+)+"
        r"[A-Za-z_][\w<>,\[\]\.\* &:]*\s+(?P<n7>[A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const\s*)?\{?"  # typed method
    ),
}


def _cstyle_name(m: re.Match) -> Optional[str]:
    for g in ("n1", "n2", "n3", "n4", "n5", "n6", "n7"):
        v = m.groupdict().get(g)
        if v:
            return v
    return None


# Untrusted-input sources (union across languages). Presence in a function body
# marks it as attacker-reachable surface.
_SOURCE_TOKENS = (
    # web / request
    "request.args", "request.form", "request.json", "request.data", "request.get",
    "req.query", "req.body", "req.params", "request.getparameter", "request.body",
    "params[", "request.", "getparameter", "@requestparam", "@pathvariable",
    "r.url.query", "r.form", "r.body", "c.query", "c.param", "ctx.request",
    # process / env / cli
    "os.getenv", "sys.argv", "process.argv", "process.env", "os.args", "os.getenv",
    "env::var", "std::env::args", "getenv(", "argv", "environ", "env[",
    # io / network
    "stdin", "std::cin", "scanf", "fgets", "recv(", "read(", "socket", "readline",
    "input(", "raw_input(", "bufio.newreader", "ioutil.readall", "io.readall",
    "getline", "$_get", "$_post", "$_request", "$_cookie", "$_server", "$_files",
)

# Dangerous sinks (union). Presence marks a security-relevant operation.
_SINK_TOKENS = (
    # command / code exec
    "system(", "popen(", "exec(", "execl", "execv", "execve", "eval(", "exec.command",
    "subprocess", "os.system", "child_process", "runtime.getruntime().exec",
    "processbuilder", "shell_exec", "passthru(", "proc_open", "spawn(", "popen(",
    "command::new", "std::process::command", "assert_eval", "compile(", "vm.run",
    # sql
    ".execute(", ".query(", "executequery", "createquery", "db.query", "sql.open",
    "rawquery", "raw(", "prepare(", "mysqli_query", "pg_query", "cursor.execute",
    # deserialization
    "pickle.load", "yaml.load", "marshal.load", "unserialize", "objectinputstream",
    "readobject", "json.unmarshal", "deserialize", "fromjson", "load(",
    # filesystem / path
    "open(", "fopen(", "readfile", "fs.readfile", "fs.writefile", "file.read",
    "file.write", "os.open", "ioutil.readfile", "os.readfile", "sendfile",
    "include(", "require(", "require_once", "include_once", "std::fs::",
    # memory (C/C++)
    "strcpy(", "strcat(", "sprintf(", "vsprintf(", "memcpy(", "memmove(", "gets(",
    "alloca(", "strncpy(", "snprintf(", "malloc(", "realloc(",
    # crypto / auth-sensitive
    "verify(", "sign(", "decrypt(", "encrypt(", "hmac", "compare_digest",
    "checkpassword", "authenticate", "settoken", "createtoken", "jwt.",
    # ssrf / templating
    "requests.get", "urllib.request", "http.get", "fetch(", "axios.", "render_template_string",
    "template.render", "jinja", "sstitemplate",
)

# Filename / function-name hints that raise attack-surface weight even without an
# explicit sink token (handlers, parsers, auth, admin, etc.).
_SURFACE_NAME_HINTS = (
    "parse", "handle", "handler", "route", "controller", "endpoint", "dispatch",
    "auth", "login", "logout", "session", "token", "password", "credential",
    "admin", "privileg", "sudo", "root", "exec", "command", "cmd", "shell",
    "query", "sql", "deserial", "unmarshal", "upload", "download", "import",
    "render", "template", "eval", "decrypt", "encrypt", "verify", "validate",
    "sanitize", "escape", "decode", "unzip", "extract", "load", "read", "fetch",
    "request", "connect", "bind", "listen", "callback", "webhook", "rpc",
)

# Common short identifiers that would make "tested" matching noisy.
_COMMON = {
    "main", "init", "new", "get", "set", "run", "test", "name", "value", "data",
    "size", "len", "self", "this", "type", "list", "map", "add", "call", "make",
    "read", "write", "open", "close", "start", "stop", "next", "prev", "print",
    "log", "info", "warn", "error", "debug", "assert", "expect", "should", "check",
    "true", "false", "null", "none", "with", "from", "into", "todo", "func",
}

_CALL_RE = re.compile(r"(?:\.|\b)([A-Za-z_]\w{2,})\s*\(")


def _lexer_for(ext: str) -> str:
    return _EXT_FAMILY.get(ext, "cstyle")


def _scan_body_flags(body: str) -> Tuple[bool, List[str], bool, List[str]]:
    low = body.lower()
    src_hits = sorted({t for t in _SOURCE_TOKENS if t in low})
    sink_hits = sorted({t for t in _SINK_TOKENS if t in low})
    return bool(src_hits), src_hits[:6], bool(sink_hits), sink_hits[:6]


def _extract_functions(text: str, ext: str) -> List[Dict[str, Any]]:
    """Return [{name, line, body}] for a single source file (best-effort)."""
    fam = _lexer_for(ext)
    rx = _FUNC_DEF[fam]
    lines = text.splitlines()
    starts: List[Tuple[int, str]] = []  # (line_index, name)
    for i, ln in enumerate(lines):
        if len(ln) > 4000:
            continue
        m = rx.search(ln)
        if not m:
            continue
        name = _cstyle_name(m) if fam == "cstyle" else m.groupdict().get("name")
        if not name:
            continue
        # Filter obvious control keywords captured by the typed-method arm.
        if name.lower() in ("if", "for", "while", "switch", "catch", "return", "else"):
            continue
        starts.append((i, name))
    out: List[Dict[str, Any]] = []
    for idx, (li, name) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else min(len(lines), li + 160)
        end = min(end, li + 160)
        body = "\n".join(lines[li:end])
        out.append({"name": name, "line": li + 1, "body": body})
    return out


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def _surface_score(name: str, rel: str, has_source: bool, has_sink: bool) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    if has_sink:
        score += 3
        reasons.append("reaches a dangerous sink")
    if has_source:
        score += 2
        reasons.append("reads untrusted input")
    hay = (name + " " + rel).lower()
    name_hits = [h for h in _SURFACE_NAME_HINTS if h in hay]
    if name_hits:
        score += min(2, len(name_hits))
        reasons.append("security-relevant name (" + ", ".join(sorted(set(name_hits))[:3]) + ")")
    # Exported/public heuristic: not a private/dunder name.
    if not name.startswith("_"):
        score += 1
    return score, reasons


def _primitive_for(sink_hits: List[str], src_hits: List[str]) -> str:
    s = " ".join(sink_hits)
    if any(k in s for k in ("system", "popen", "exec", "command", "spawn", "shell", "eval")):
        return "command_injection"
    if any(k in s for k in ("query", "execute", "sql", "prepare")):
        return "sql_injection"
    if any(k in s for k in ("pickle", "yaml", "unserialize", "readobject", "unmarshal", "deserialize")):
        return "unsafe_deserialization"
    if any(k in s for k in ("strcpy", "strcat", "sprintf", "memcpy", "gets", "alloca", "malloc")):
        return "memory_safety"
    if any(k in s for k in ("open", "readfile", "writefile", "include", "require", "fs.")):
        return "path_traversal"
    if any(k in s for k in ("decrypt", "encrypt", "verify", "sign", "hmac", "jwt", "token")):
        return "crypto_auth"
    return "untrusted_input_handling"


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def build_coverage_report(dest: Path, language: str = "", *, max_files: int = 6000) -> Dict[str, Any]:
    """Compute the test-coverage vs attack-surface report for ``dest``.

    Returns a dict with per-function gap records and aggregate metrics. Never
    raises; returns a minimal report on error.
    """
    dest = Path(dest)
    try:
        if type(max_files) is not int or max_files < 1:
            raise ValueError("Source inventory file budget must be a positive integer")
        scope = {"discovered": 0, "eligible": 0, "omitted": Counter(), "untraversed": 0}
        decoding_loss = 0
        prod_funcs: List[Dict[str, Any]] = []
        tested_symbols: set = set()
        test_file_count = 0
        prod_file_count = 0

        for p in _iter_source_files(dest, max_files=max_files, scope=scope):
            try:
                rel = p.relative_to(dest).as_posix()
            except Exception:
                rel = p.name
            try:
                from backend.source_index import _open_source
                with _open_source(dest, rel) as handle:
                    raw = handle.read(800_001)
                if len(raw) > 800_000:
                    scope["omitted"]["oversized"] += 1
                    continue
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw.decode("utf-8", errors="replace")
                    decoding_loss += 1
            except (OSError, ValueError):
                scope["omitted"]["unreadable"] += 1
                continue
            ext = p.suffix.lower()
            if _is_test_path(rel, p.name):
                test_file_count += 1
                # Collect every called identifier in the test as a coverage token.
                for m in _CALL_RE.finditer(text):
                    tested_symbols.add(m.group(1).lower())
                continue
            prod_file_count += 1
            for fn in _extract_functions(text, ext):
                has_src, src_hits, has_sink, sink_hits = _scan_body_flags(fn["body"])
                score, reasons = _surface_score(fn["name"], rel, has_src, has_sink)
                # Only attack-surface functions are interesting. Threshold 3 means
                # at least a sink, or (input + name hint), etc.
                if score < 3 or not (has_src or has_sink):
                    continue
                prod_funcs.append({
                    "name": fn["name"],
                    "file": rel,
                    "line": fn["line"],
                    "score": score,
                    "reasons": reasons,
                    "has_source": has_src,
                    "has_sink": has_sink,
                    "source_hits": src_hits,
                    "sink_hits": sink_hits,
                    "primitive_type": _primitive_for(sink_hits, src_hits),
                })

        # Decide tested vs untested. A function is "tested" only when a test file
        # references its (distinctive) name as a call.
        def _is_tested(name: str) -> bool:
            low = name.rstrip("!?=").lower()
            if len(low) < 4 or low in _COMMON:
                # Too-generic to attribute; treat as tested to avoid noise.
                return True
            return low in tested_symbols

        untested = [f for f in prod_funcs if not _is_tested(f["name"])]
        tested = [f for f in prod_funcs if _is_tested(f["name"])]
        untested.sort(key=lambda f: (f["score"], f["has_sink"], f["has_source"]), reverse=True)

        surface_total = len(prod_funcs)
        covered = len(tested)
        coverage_pct = round(covered / surface_total * 100, 1) if surface_total else 0.0

        # Per-primitive breakdown of the untested gap.
        by_primitive: Dict[str, int] = {}
        for f in untested:
            by_primitive[f["primitive_type"]] = by_primitive.get(f["primitive_type"], 0) + 1

        reasons = {"file_cap": "Source files exceed the configured static test-reference file budget",
                   "excluded_directory": "Dependency or generated source directories were excluded from this first-party test-reference inventory",
                   "oversized": "Source files exceed the 800000-byte parser budget",
                   "unreadable": "Source content could not be read safely",
                   "unsafe_path": "Source aliases or nonregular files were not followed"}
        gaps = [{"code": key, "count": count, "reason": reasons[key]} for key, count in sorted(scope["omitted"].items()) if count]
        if scope["untraversed"]:
            gaps.append({"code": "untraversed_directory", "count": scope["untraversed"], "reason": "Some directories could not be safely enumerated; omitted file count is unknown"})
        if decoding_loss:
            gaps.append({"code": "decoding_loss", "count": decoding_loss, "reason": "Invalid UTF-8 required replacement; static parsing is incomplete"})
        source_scope = {"schema_version": 1, "max_files": max_files, "max_file_bytes": 800_000,
                        "discovered_source_files": scope["discovered"], "eligible_source_files": scope["eligible"],
                        "examined_files": prod_file_count + test_file_count, "omitted_files": sum(scope["omitted"].values()),
                        "omitted_by_reason": dict(scope["omitted"]), "untraversed_directories": scope["untraversed"],
                        "decoding_loss_files": decoding_loss, "inventory_complete": scope["untraversed"] == 0,
                        "complete": not gaps, "coverage_gaps": gaps}

        return {
            "language": language,
            "has_tests": test_file_count > 0,
            "test_file_count": test_file_count,
            "production_file_count": prod_file_count,
            "attack_surface_functions": surface_total,
            "tested_surface_functions": covered,
            "untested_surface_functions": len(untested),
            "attack_surface_coverage_pct": coverage_pct,
            "untested_by_primitive": by_primitive,
            "untested": untested,
            "source_scope": source_scope,
            "coverage_basis": "Static function-name references in test source; no tests were executed and neither reachability nor runtime coverage is established",
        }
    except Exception as e:  # never break Phase 1
        return {"error": str(e)[:200], "untested": [], "attack_surface_functions": 0}


def _lead_cvss(f: Dict[str, Any]) -> float:
    if f["has_sink"] and f["has_source"]:
        return 6.5
    if f["has_sink"]:
        return 5.5
    return 4.5


def collect_coverage_gap_leads(dest: Path, language: str = "", *, max_leads: int = 30) -> List[Dict[str, Any]]:
    """Emit untested-attack-surface *leads* for Phase 2, and persist the report."""
    report = build_coverage_report(dest, language)
    untested = report.get("untested") or []

    # Persist the full report for Phase 2 planning + the report layer.
    try:
        out_dir = Path(dest) / ".lotus"
        out_dir.mkdir(parents=True, exist_ok=True)
        if out_dir.is_symlink():
            raise ValueError("Coverage artifact directory must not be a symlink")
        descriptor, pending = tempfile.mkstemp(prefix=".test-coverage-gap-", suffix=".json", dir=out_dir)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(report, handle, ensure_ascii=False, separators=(",", ":"))
                handle.write("\n")
            os.replace(pending, out_dir / "test_coverage_gap.json")
        finally:
            if os.path.exists(pending):
                os.unlink(pending)
    except (OSError, ValueError, TypeError) as error:
        raise RuntimeError("Complete static test-reference artifact could not be persisted") from error

    leads: List[Dict[str, Any]] = []
    for f in untested[:max_leads]:
        why = "; ".join(f.get("reasons") or [])
        tok = ", ".join((f.get("sink_hits") or []) + (f.get("source_hits") or []))
        cov = report.get("attack_surface_coverage_pct")
        leads.append({
            "tool": "test-coverage-gap",
            "title": f"Untested attack surface: {f['name']} ({f['primitive_type'].replace('_', ' ')})",
            "cvss": _lead_cvss(f),
            "description": (
                f"Function `{f['name']}` at {f['file']}:{f['line']} carries attack surface "
                f"({why}; signals: {tok}) but is not exercised by the repository's own test "
                f"suite (repo attack-surface test coverage ≈ {cov}%). Untested security-relevant "
                f"code is where unsanitized paths and regressions survive. Phase 2: trace the "
                f"untrusted input into this function, craft a payload for the {f['primitive_type']} "
                f"primitive, and prove impact in the lab."
            ),
            "file": f["file"],
            "line": f["line"],
            "confidence": "low",
            "primitive_type": f["primitive_type"],
            "phase2_hint": "untested-attack-surface",
            "tags": ["coverage-gap", "untested-surface", f["primitive_type"]],
            "coverage_gap": {
                "score": f["score"],
                "has_sink": f["has_sink"],
                "has_source": f["has_source"],
                "sink_hits": f["sink_hits"],
                "source_hits": f["source_hits"],
                "repo_surface_coverage_pct": cov,
            },
        })

    # Optional AI enrichment (guarded, off unless enabled + creds present).
    if leads and _ai_enabled():
        try:
            ai_annotate_untested(dest, leads)
        except Exception:
            pass
    return leads


def _ai_enabled() -> bool:
    if str(os.environ.get("LOTUS_COVERAGE_GAP_AI", "")).lower() in ("1", "true", "yes"):
        return True
    return False


def ai_annotate_untested(dest: Path, leads: List[Dict[str, Any]], *, top_n: int = 12) -> None:
    """Best-effort AI ranking/annotation of the top untested-surface leads.

    Mutates ``leads`` in place, adding an ``ai_note`` to the top entries. Fully
    guarded: any failure (no creds, offline, parse error) leaves ``leads``
    unchanged. Kept optional because deterministic scoring is the primary signal.
    """
    try:
        from backend.main import call_ai, SessionLocal, Settings  # type: ignore
        from backend.ai_gateway import AITask  # type: ignore
    except Exception:
        return
    db = SessionLocal()
    try:
        settings = db.query(Settings).first()
    finally:
        db.close()
    if not settings:
        return
    subset = leads[:top_n]
    catalog = "\n".join(
        f"{i+1}. {l['title']} @ {l['file']}:{l['line']} "
        f"[{l['coverage_gap'].get('sink_hits')}|{l['coverage_gap'].get('source_hits')}]"
        for i, l in enumerate(subset)
    )
    prompt = (
        "You are a vulnerability researcher triaging UNTESTED attack-surface functions "
        "(no test coverage) for deeper Phase-2 analysis. For each item, in one sentence, "
        "state the most likely concrete vulnerability and the single highest-value payload "
        "to try. Reply as JSON list of objects {index, note}.\n\n" + catalog
    )
    try:
        resp = call_ai(prompt, settings, 40, task=AITask.RECON)
    except Exception:
        return
    if not resp or resp.startswith("[ai-"):
        return
    try:
        start = resp.find("[")
        end = resp.rfind("]")
        parsed = json.loads(resp[start:end + 1]) if start >= 0 and end > start else None
    except Exception:
        parsed = None
    if not isinstance(parsed, list):
        return
    for obj in parsed:
        try:
            i = int(obj.get("index")) - 1
            if 0 <= i < len(subset) and obj.get("note"):
                subset[i]["ai_note"] = str(obj["note"])[:400]
        except Exception:
            continue


def _run_test_coverage_gap(dest: Path, language: str) -> List[dict]:
    """Pipeline entrypoint (mirrors the other analyzer wrappers)."""
    return collect_coverage_gap_leads(Path(dest), language)
