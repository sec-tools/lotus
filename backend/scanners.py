import asyncio
import hashlib
import inspect
import json
import os
import re
import shlex
import shutil
import time
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from backend.async_process import terminate_and_reap


class ToolUnavailable(RuntimeError):
    """Raised when an applicable native package auditor is not installed."""


class ScannerExecutionError(RuntimeError):
    """Raised when an applicable scanner did not produce a trustworthy result."""


class NativeAuditAggregateError(ScannerExecutionError):
    """One or more native audits failed after other targets produced leads.

    Monorepos routinely contain several independently deployable packages.  A
    successful audit of one package must never make a failed sibling audit look
    clean, so the orchestrator carries the successful observations alongside a
    terminal error for the caller to persist.
    """

    def __init__(self, message: str, *, partial_findings: Optional[List[Dict[str, Any]]] = None,
                 target_results: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.partial_findings = list(partial_findings or [])
        self.target_results = list(target_results or [])


_NATIVE_MANIFESTS = {
    "node": ("package.json",),
    "python": ("requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock"),
    "go": ("go.mod",),
    "rust": ("Cargo.toml",),
    "php": ("composer.json",),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
}
_NATIVE_AUDIT_SKIP_DIRS = {
    ".git", ".lotus", "node_modules", "vendor", "third_party", "target",
    "build", "dist", ".venv", "venv", ".tox", "coverage", "out",
}
# Dependency manifests under test fixtures and examples describe a deliberately
# non-production graph (often with intentionally vulnerable packages or a
# different runtime/toolchain). Auditing them as deployable components creates
# noise and can make one missing fixture tool look like a production coverage
# gap. They remain available through an explicit opt-in for researchers who
# intentionally want that broader scope.
_NATIVE_AUDIT_NON_PRODUCTION_DIRS = {
    "test", "tests", "testdata", "__tests__", "fixture", "fixtures",
    "example", "examples", "sample", "samples",
}
_NATIVE_AUDIT_TOOLS = {
    "node": "npm audit --omit=dev",
    "python": "pip-audit",
    "go": "gosec / govulncheck",
    "rust": "cargo audit",
    "php": "composer audit",
    "java": "OWASP dependency-check",
}


def native_nonproduction_audit_option(source: Path, readiness: Optional[dict] = None) -> bool:
    """Keep preflight and dispatch on the same captured package selection."""
    if (isinstance(readiness, dict) and readiness.get("schema_version") == 1
            and readiness.get("source_root") == str(Path(source).resolve())
            and type(readiness.get("include_nonproduction_fixtures")) is bool):
        return readiness["include_nonproduction_fixtures"]
    return os.environ.get("LOTUS_INCLUDE_NONPRODUCTION_DEPENDENCY_AUDITS", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def discover_native_audit_targets(
    dest: Path,
    language: Optional[str] = None,
    *,
    max_depth: int = 4,
    max_targets: int = 32,
    include_nonproduction_fixtures: bool = False,
    inventory: Optional[Dict[str, Any]] = None,
) -> List[tuple[str, Path]]:
    """Enumerate bounded, first-party package roots for native audits.

    The old root-only check missed nested npm workspaces, Python services,
    Cargo crates, and Java modules.  This helper is intentionally conservative:
    it ignores vendored/generated trees, limits depth/count, and returns one
    target per ecosystem/root so a dependency audit cannot recurse into
    ``node_modules`` or a checked-in third-party project. Test, fixture, and
    example manifests are excluded by default because they are not a common
    deployment dependency graph; callers can explicitly opt in when that is
    the intended audit scope.
    """
    root = Path(dest).resolve()
    wanted = str(language or "").lower()
    languages = [wanted] if wanted in _NATIVE_MANIFESTS else list(_NATIVE_MANIFESTS)
    rows: List[tuple[str, Path]] = []
    seen: set[tuple[str, str]] = set()
    scope = {"schema_version": 1, "inventory_complete": False,
             "max_depth": max_depth, "max_targets": max_targets,
             "include_nonproduction_fixtures": bool(include_nonproduction_fixtures),
             "exclude_hidden_directories": True,
             "excluded_directories": sorted(_NATIVE_AUDIT_SKIP_DIRS | (
                 set() if include_nonproduction_fixtures else _NATIVE_AUDIT_NON_PRODUCTION_DIRS)),
             "gaps": []}
    if inventory is not None:
        inventory.clear()
        inventory.update(scope)

    def gap(reason, path):
        # Retain bounded diagnostics, while completeness stays false even if
        # more excluded subtrees exist than can fit in this receipt.
        scope["truncated"] = True
        scope["targets_discovered"] = len(rows)
        if len(scope["gaps"]) < 32:
            scope["gaps"].append({"reason": reason, "path": str(path)})
        if inventory is not None:
            inventory.update(scope)

    def walk_error(error):
        raise error

    try:
        if not root.is_dir():
            raise FileNotFoundError("Native package source root is unavailable")
        walker = os.walk(root, onerror=walk_error)
        for current, dirs, files in walker:
            current_path = Path(current)
            try:
                rel = current_path.relative_to(root)
            except ValueError:
                continue
            if len(rel.parts) > max_depth:
                gap("package discovery depth limit", rel)
                dirs[:] = []
                continue
            if (
                not include_nonproduction_fixtures
                and any(part.casefold() in _NATIVE_AUDIT_NON_PRODUCTION_DIRS for part in rel.parts)
            ):
                dirs[:] = []
                continue
            dirs[:] = [
                d for d in dirs
                if d not in _NATIVE_AUDIT_SKIP_DIRS
                and not d.startswith(".")
                and (
                    include_nonproduction_fixtures
                    or d.casefold() not in _NATIVE_AUDIT_NON_PRODUCTION_DIRS
                )
            ]
            for directory in dirs:
                if (current_path / directory).is_symlink():
                    gap("directory alias was not traversed", rel / directory)
            file_set = set(files)
            for lang in languages:
                markers = _NATIVE_MANIFESTS[lang]
                marker = next((m for m in markers if m in file_set), None)
                if marker is None:
                    continue
                key = (lang, str(current_path))
                if key in seen:
                    continue
                seen.add(key)
                rows.append((lang, current_path))
                if len(rows) >= max(1, int(max_targets)):
                    gap("package discovery target limit", rel)
                    return sorted(rows, key=lambda item: (0 if item[1] == root else 1, str(item[1])))
    except OSError:
        # A permission/read error is represented by the caller's scanner
        # failure path; silently returning an empty list would be a false clean.
        raise
    scope["inventory_complete"] = not scope.get("truncated", False)
    scope["targets_discovered"] = len(rows)
    if inventory is not None:
        inventory.update(scope)
    return sorted(rows, key=lambda item: (0 if item[1] == root else 1, str(item[1])))


def native_audit_applicability(dest: Path, language: str) -> tuple[bool, str]:
    """Return whether a native package auditor is meaningful for this tree.

    The pipeline must not count a no-op ``run_language_audit`` invocation as a
    successful clean audit.  Manifest-less trees are explicitly not applicable;
    supported manifests are applicable even when their executable is absent so
    the missing capability is recorded as ``not-installed``.  Ecosystems for
    which Lotus has no safe native auditor yet are skipped with a reason and are
    still covered by the generic dependency/OSV passes when available.
    """
    dest = Path(dest)
    language = str(language or "").lower()
    manifests = {
        "node": ("package.json", "npm audit --omit=dev"),
        "python": (("requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock"), "pip-audit"),
        "go": ("go.mod", "govulncheck"),
        "rust": ("Cargo.toml", "cargo audit"),
        "php": ("composer.json", "composer audit"),
        "java": (("pom.xml", "build.gradle", "build.gradle.kts"), "OWASP dependency-check"),
    }
    spec = manifests.get(language)
    if spec is None:
        return False, f"not applicable: no native package auditor is defined for {language or 'unknown'}; generic dependency/OSV coverage applies"
    marker, tool = spec
    if isinstance(marker, tuple):
        present = any((dest / name).is_file() for name in marker)
    else:
        present = (dest / marker).is_file()
    if not present:
        return False, f"{tool} not applicable (no supported dependency manifest)"
    if language == "go":
        from backend.native_readiness import go_module_has_source
        if not go_module_has_source(dest):
            return False, "Go source analyzer not applicable: module metadata has no Go source; recorded dependency graph remains in dependency-map/OSV scope"
    return True, ""


async def run_native_audits_for_tree(
    dest: Path,
    repo_id: int,
    send: Callable,
    *,
    primary_language: Optional[str] = None,
    include_root: bool = False,
    max_targets: int = 32,
    include_nonproduction_fixtures: Optional[bool] = None,
    readiness: Optional[dict] = None,
) -> List[Dict[str, Any]]:
    """Run native production dependency audits for nested package roots.

    The primary root audit remains the backwards-compatible ``lockfile-audit``
    task.  This companion covers all additional package roots and ecosystems,
    preserving per-target status in ``.lotus/native_package_audits.json`` and
    failing closed if any applicable target cannot be analyzed.
    """
    root = Path(dest).resolve()
    if include_nonproduction_fixtures is None:
        include_nonproduction_fixtures = native_nonproduction_audit_option(root, readiness)
    inventory = {}
    targets = discover_native_audit_targets(
        root,
        None,
        max_targets=max_targets,
        include_nonproduction_fixtures=bool(include_nonproduction_fixtures),
        inventory=inventory,
    )
    inventory_gap = ({"name": "native-package-inventory", "kind": "inventory-gap", "status": "blocked",
                      "reason": "Native package discovery was incomplete; additional package roots may be unreviewed",
                      "applicability": inventory}
                     if inventory.get("inventory_complete") is not True else None)
    primary_key = (str(primary_language or "").lower(), root)
    selected = [item for item in targets if include_root or item != primary_key]
    if not selected:
        try:
            artifact = root / ".lotus" / "native_package_audits.json"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text(json.dumps({
                "schema_version": 1, "status": "failed" if inventory_gap else "skipped",
                "targets": [inventory_gap] if inventory_gap else [],
                "errors": [inventory_gap["reason"]] if inventory_gap else [], "findings_count": 0,
                "reason": inventory_gap["reason"] if inventory_gap else "no additional first-party package roots discovered",
                "inventory": inventory,
                "scope": {
                    "include_nonproduction_fixtures": bool(include_nonproduction_fixtures),
                    "excluded_by_default": sorted(_NATIVE_AUDIT_NON_PRODUCTION_DIRS),
                },
            }, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:
            # The caller still receives the explicit skipped task row; failure
            # to write this optional convenience artifact must not turn a
            # manifest-less repository into an execution exception.
            pass
        if inventory_gap:
            raise NativeAuditAggregateError(inventory_gap["reason"], partial_findings=[],
                                            target_results=[inventory_gap])
        return []
    findings: List[Dict[str, Any]] = []
    target_results: List[Dict[str, Any]] = []
    # A missing auditor binary (pip-audit, cargo audit, ...) is a *capability
    # gap*, not an execution failure. Track it separately from genuine failures
    # so a not-installed tool degrades to an honest ``not-installed`` task result
    # instead of a hard ``failed`` that scares operators and inflates the
    # coverage-gap count (observed: kamaji's python `docs` tree failing the whole
    # native-package-audits task because pip-audit was absent).
    failures: List[str] = []
    unavailable: List[str] = []
    blocked: List[str] = []
    for lang, target in selected:
        rel = "." if target == root else str(target.relative_to(root))
        _progress = send(repo_id, f"▶ Native package audit: {lang} ({rel})", level="info")
        if inspect.isawaitable(_progress):
            await _progress
        started = time.monotonic()
        row: Dict[str, Any] = {
            "language": lang, "root": rel, "status": "running",
            "tool": _NATIVE_AUDIT_TOOLS.get(lang, "native-package-audit"),
        }
        try:
            assessed = None
            if readiness is not None:
                from backend.native_readiness import NativePrerequisiteUnavailable
                if (readiness.get("schema_version") != 1
                        or Path(readiness.get("source_root") or "").resolve() != root):
                    raise NativePrerequisiteUnavailable("Native readiness is not bound to this source root")
                matches = [entry for entry in readiness.get("targets", []) if isinstance(entry, dict)
                           and entry.get("language") == lang and entry.get("root") == rel]
                if len(matches) != 1:
                    raise NativePrerequisiteUnavailable("Native package target has no unique prerequisite assessment")
                assessed = matches[0]
                row["tool"] = assessed.get("tool") or row["tool"]
                if assessed.get("status") == "blocked":
                    raise NativePrerequisiteUnavailable(str(assessed.get("reason") or "Package prerequisites are unavailable"))
            applicable, reason = native_audit_applicability(target, lang)
            if not applicable:
                row.update(status="skipped", reason=reason or "not applicable")
                row["duration_ms"] = int((time.monotonic() - started) * 1000)
                target_results.append(row)
                continue
            if readiness is not None and (assessed or {}).get("status") != "ready":
                raise NativePrerequisiteUnavailable("Applicable native target has not passed its installed-tool prerequisite checks")
            execution_scope = "host"
            try:
                from backend.k8s_runtime import kubernetes_selected
                selected_k8s = lang in {"node", "java", "go", "python"} and kubernetes_selected(repo_id)
                if selected_k8s:
                    chunk = await run_language_audit(target, repo_id, lang, send, source_root=root)
                    execution_scope = "kubernetes-tool-job"
                else:
                    chunk = await run_language_audit(target, repo_id, lang, send)
            except ToolUnavailable:
                # Phase 1 runs concurrently with lab construction, so a host
                # may lack npm even though the isolated target image has it.
                # Retry only the Node production graph in that target's lab
                # after startup; other ecosystems retain their explicit
                # not-installed/failed result until a validated adapter exists.
                if lang != "node" or selected_k8s:
                    raise
                try:
                    from backend import lab as _lab
                    if not _lab.get_lab_container(repo_id):
                        raise
                except ImportError:
                    raise
                chunk = await run_npm_audit_in_lab(
                    repo_id, send, target_rel=rel, timeout=180,
                )
                execution_scope = "isolated-lab-equivalent"
            for finding in chunk:
                if isinstance(finding, dict):
                    finding = dict(finding)
                    finding["native_target"] = rel
                    finding["native_language"] = lang
                    findings.append(finding)
            row.update(
                status="completed",
                findings_count=len(chunk),
                reason=(
                    f"native {lang} audit completed in {execution_scope}; "
                    f"{len(chunk)} leads observed"
                ),
                execution_scope=execution_scope,
            )
        except Exception as exc:
            from backend.native_readiness import NativePrerequisiteUnavailable
            from backend.ext_analyzers import AnalyzerUnavailable
            resource_policy = getattr(exc, "resource_policy", None)
            if isinstance(resource_policy, dict):
                row["resource_policy"] = resource_policy
                row["configure_tool"] = getattr(exc, "configure_tool", None)
            _is_prerequisite = isinstance(exc, NativePrerequisiteUnavailable) or (
                isinstance(exc, AnalyzerUnavailable) and isinstance(resource_policy, dict))
            _is_unavailable = isinstance(exc, ToolUnavailable)
            row.update(
                status=("blocked" if _is_prerequisite else "not-installed" if _is_unavailable else "failed"),
                reason=str(exc)[:500],
            )
            (blocked if _is_prerequisite else unavailable if _is_unavailable else failures).append(
                f"{lang} ({rel}): {str(exc)[:220]}")
        row["duration_ms"] = int((time.monotonic() - started) * 1000)
        target_results.append(row)
    if inventory_gap:
        target_results.append(inventory_gap)
        failures.append(inventory_gap["reason"])
    errors = failures + blocked + unavailable
    try:
        artifact = root / ".lotus" / "native_package_audits.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(json.dumps({
            "schema_version": 1,
            "targets": target_results,
            "errors": errors,
            "unavailable": unavailable,
            "blocked": blocked,
            "findings_count": len(findings),
            "inventory": inventory,
            "scope": {
                "include_nonproduction_fixtures": bool(include_nonproduction_fixtures),
                "excluded_by_default": sorted(_NATIVE_AUDIT_NON_PRODUCTION_DIRS),
            },
        }, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        failures.append(f"could not persist native package audit artifact: {exc}")
    # Fail closed when either (a) a genuine execution failure occurred, or (b) a
    # not-installed auditor sits alongside successful siblings -- a green success
    # must never hide an applicable auditor that did not run. Partial findings are
    # preserved on the error so no lead is lost from the evidence set.
    if failures or (unavailable and findings):
        raise NativeAuditAggregateError(
            "native package audit target(s) failed or unavailable: "
            + "; ".join((failures + blocked + unavailable)[:8]),
            partial_findings=findings,
            target_results=target_results,
        )
    if blocked:
        from backend.native_readiness import NativePrerequisiteUnavailable
        raise NativePrerequisiteUnavailable(
            "native package prerequisites are blocked: " + "; ".join((blocked + unavailable)[:8]),
            partial_findings=findings, target_results=target_results,
        )
    # Pure capability gap: every applicable target was simply not-installed and
    # nothing else produced leads. Surface this as an honest ``not-installed``
    # task (a coverage gap) rather than a scary hard ``failed`` -- the exact
    # kamaji case where a lone python `docs` tree lacked pip-audit.
    if unavailable:
        gap = ToolUnavailable(
            "native package auditor(s) not installed: " + "; ".join(unavailable[:8]))
        # Preserve the per-target breakdown for the coverage/report layer.
        gap.target_results = target_results  # type: ignore[attr-defined]
        gap.partial_findings = findings  # type: ignore[attr-defined]
        raise gap
    return findings


def _json_result_or_error(output: str, tool: str) -> Any:
    """Parse a scanner response without turning execution failure into zero leads."""
    text = str(output or "").strip()
    if not text or text.lower().startswith(("error:", "timed out")):
        raise ScannerExecutionError(f"{tool} produced no usable output: {text[:240] or 'empty output'}")
    try:
        return json.loads(text)
    except Exception as first_exc:
        # npm and several native auditors emit warnings on stderr around an
        # otherwise valid JSON document.  The process boundary intentionally
        # combines stdout/stderr, so accept one self-contained JSON value when
        # it can be located unambiguously; reject all other shapes.
        decoder = json.JSONDecoder()
        for match in re.finditer(r"[\[{]", text):
            try:
                value, _end = decoder.raw_decode(text[match.start():])
                return value
            except Exception:
                continue
        raise ScannerExecutionError(
            f"{tool} output was not valid JSON: {str(first_exc)[:180]}"
        ) from first_exc


def _npm_audit_findings(output: str) -> List[Dict[str, Any]]:
    """Parse npm's JSON document into leads, failing closed on audit errors.

    npm returns a JSON ``error`` object for several operational failures (for
    example ENOLOCK and unsupported flags).  Treating that document as an
    empty vulnerability map is a dangerous false negative, so the parser is
    shared by host and lab executions and always raises for an unusable graph.
    """
    data = _json_result_or_error(output, "npm audit")
    if not isinstance(data, dict):
        raise ScannerExecutionError("npm audit returned a non-object JSON document")
    # A registry/network failure is sometimes emitted as ``{"message": ...}``
    # with no ``error`` key.  A trustworthy audit document always has the
    # vulnerabilities map (possibly empty), so reject any other shape.
    if "vulnerabilities" not in data:
        detail = data.get("message") or data.get("error") or "missing vulnerabilities map"
        raise ScannerExecutionError(
            f"npm audit could not analyze the dependency graph: {str(detail)[:240]}"
        )
    # Any explicit npm error is an operational failure.  Even if npm happens
    # to include a partial vulnerability map alongside it, that map is not a
    # trustworthy production dependency result and must not become a clean or
    # complete signal.
    if data.get("error"):
        err = data.get("error")
        detail = err.get("summary") if isinstance(err, dict) else str(err)
        raise ScannerExecutionError(
            f"npm audit could not analyze the dependency graph: {str(detail)[:240]}"
        )
    findings: List[Dict[str, Any]] = []
    for vuln_id, vuln in (data.get("vulnerabilities") or {}).items():
        if not isinstance(vuln, dict):
            continue
        via = vuln.get("via") or []
        first_via = via[0] if isinstance(via, list) and via and isinstance(via[0], dict) else {}
        findings.append({
            "tool": "npm-audit",
            "title": f"npm vulnerable package: {vuln_id}",
            "cvss": 7.0,
            "description": (
                f"npm audit --omit=dev reported {vuln.get('severity', 'unknown')} severity "
                f"for {vuln_id} ({first_via.get('title', '')}). Production dependency graph only; "
                "verify first-party reachability before reporting."
            ),
            "file": "package.json",
            "line": 0,
            "confidence": "high",
        })
    return findings


async def _run_tool(
    repo_id: int,
    cmd: List[str],
    cwd: Path,
    send: Callable,
    timeout: int = 120,
) -> str:
    started = time.monotonic()
    await send(repo_id, f"Running {' '.join(cmd[:5])}")
    proc = None
    scratch = None
    try:
        from backend.target_snapshots import snapshot_root
        scratch_root = snapshot_root().parent / "scanner_tmp"
        if scratch_root.is_symlink():
            raise RuntimeError("Scanner temporary directory must not be a symlink")
        scratch_root.mkdir(mode=0o700, exist_ok=True)
        scratch = tempfile.TemporaryDirectory(prefix=f"audit-{int(repo_id)}-", dir=scratch_root)
        child_env = {**_controlled_child_env(), "TMPDIR": scratch.name, "TMP": scratch.name, "TEMP": scratch.name}
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=child_env,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        text = out.decode(errors="ignore")
        await _persist_scanner_tool_artifact(
            repo_id, cmd, cwd, status="completed" if proc.returncode in (0, 1) else "failed",
            exit_code=proc.returncode, output=text, duration_ms=int((time.monotonic() - started) * 1000),
            send=send,
        )
        return text
    except asyncio.CancelledError:
        await _terminate(proc)
        raise
    except asyncio.TimeoutError:
        # Reap the orphaned child so a stuck external tool (npm audit, gitleaks,
        # gosec, …) cannot linger, leak resources, or wedge the child watcher.
        await _terminate(proc)
        text = "timed out"
        await _persist_scanner_tool_artifact(
            repo_id, cmd, cwd, status="failed", exit_code=getattr(proc, "returncode", None),
            output=text, duration_ms=int((time.monotonic() - started) * 1000), send=send,
        )
        return text
    except Exception as e:
        await _terminate(proc)
        text = f"error: {e}"
        await _persist_scanner_tool_artifact(
            repo_id, cmd, cwd, status="failed", exit_code=getattr(proc, "returncode", None),
            output=text, duration_ms=int((time.monotonic() - started) * 1000), send=send,
        )
        return text


    finally:
        if scratch is not None:
            # The child has completed or been reaped above. Crash leftovers
            # remain under managed audit data, so either reset can remove them.
            try:
                scratch.cleanup()
            except OSError:
                import logging
                logging.getLogger(__name__).warning("Scanner temporary files could not be removed; retained under managed audit data for reset cleanup")


def _redact_scanner_output(value: Any) -> str:
    """Bound/redact native-tool output before persisting a clickable artifact.

    Native secret/dependency tools can echo credential material in diagnostics.
    The raw parser still receives the original output, while the durable UI
    artifact keeps enough context to reproduce the run without becoming a
    second secret store.
    """
    text = str(value or "")[-12000:]
    patterns = (
        (r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)[^\s]+", r"\1[REDACTED]"),
        (r"(?i)(api[_-]?key\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]"),
        (r"(?i)(password\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]"),
        (r"(?i)(secret\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]"),
        (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]"),
        (r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", "[REDACTED_GITHUB_TOKEN]"),
        (r"-----BEGIN [^-]+ PRIVATE KEY-----.*?-----END [^-]+ PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text, flags=re.DOTALL)
    return text


async def _persist_scanner_tool_artifact(
    repo_id: int,
    cmd: List[str],
    cwd: Path,
    *,
    status: str,
    exit_code: Any,
    output: str,
    duration_ms: int,
    send: Optional[Callable] = None,
    safe_writer: Optional[Callable] = None,
) -> Optional[str]:
    """Persist a bounded command receipt for native scanners.

    Scanner adapters historically returned only a string, which meant the
    report could say a tool completed without retaining the exact command or
    diagnostic output.  This sidecar is best-effort telemetry: parser failures
    still fail closed, but a filesystem issue cannot turn a valid scan into a
    fabricated clean result.
    """
    try:
        root = Path(cwd).resolve()
        if not root.is_dir():
            return None
        artifact_dir = root / ".lotus" / "tool_runs"
        if safe_writer is None:
            artifact_dir.mkdir(parents=True, exist_ok=True)
        argv = [str(item) for item in (cmd or [])]
        digest = hashlib.sha256(
            json.dumps({"argv": argv, "cwd": str(root), "output": str(output or "")}, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]
        executable = Path(argv[0]).name if argv else "tool"
        executable = re.sub(r"[^A-Za-z0-9_.-]+", "_", executable)[:50] or "tool"
        path = artifact_dir / f"{executable}-{digest}.json"
        safe_output = _redact_scanner_output(output)
        payload = {
            "schema_version": 1,
            "kind": "native-scanner-command",
            "repo_id": int(repo_id),
            "argv": argv,
            "cwd": str(root),
            "status": str(status),
            "exit_code": exit_code,
            "duration_ms": int(duration_ms or 0),
            "output_sha256": "sha256:" + hashlib.sha256(str(output or "").encode("utf-8", errors="replace")).hexdigest(),
            "output_tail": safe_output,
        }
        if safe_writer is None:
            path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        else:
            safe_writer(root, path.name, payload)
        if send:
            detail_id = f"{repo_id}-scanner-{digest}"
            detail = {
                "kind": "command",
                "tool": argv[0] if argv else "scanner",
                "status": str(status),
                "argv": argv,
                "cwd": str(root),
                "exit_code": exit_code,
                "duration_ms": int(duration_ms or 0),
                "artifact_path": str(path),
                "output_sha256": payload["output_sha256"],
                "output_tail": safe_output,
            }
            emitted = send(repo_id, f"Native scanner artifact: {path.name}", level="info", detail_id=detail_id, detail=detail)
            if inspect.isawaitable(emitted):
                await emitted
        return str(path)
    except Exception:
        return None


def _controlled_child_env() -> Dict[str, str]:
    """Do not expose API credentials/settings to repo-facing scanners."""
    try:
        from backend.lab import _controlled_child_env as lab_env
        return lab_env()
    except Exception:
        names = {"PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR"}
        return {k: v for k, v in os.environ.items() if k in names}


async def _terminate(proc) -> None:
    """Kill a subprocess and drain its pipe transports; never raises."""
    await terminate_and_reap(proc)


def _tool_present(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _secret_regex_findings(dest: Path) -> List[Dict[str, Any]]:
    """Fallback secret detection when no specialized scanner is installed."""
    patterns = [
        (r"AKIA[0-9A-Z]{16}", "AWS access key", 7.5),
        (r"ghp_[A-Za-z0-9_]{36}", "GitHub personal access token", 8.5),
        (r"glpat-[A-Za-z0-9_\-]{20,}", "GitLab personal access token", 8.5),
        (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "Slack token", 7.5),
        (r"sk-[A-Za-z0-9]{32,}", "OpenAI / Stripe secret key", 8.5),
        (r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key material", 8.5),
        (r"api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "Hardcoded API key", 7.0),
        (r"password\s*[:=]\s*['\"][^'\"]{6,}['\"]", "Hardcoded password", 7.0),
    ]
    results: List[Dict[str, Any]] = []
    for f in dest.rglob("*"):
        if not f.is_file() or f.stat().st_size > 1_000_000:
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for pat, name, cvss in patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                line = text[:m.start()].count("\n") + 1
                results.append({
                    "tool": "secret-grep",
                    "title": f"Possible {name}",
                    "cvss": cvss,
                    "description": f"Regex matched {name} in {f.name} line {line}. Verify before reporting.",
                    "file": str(f.relative_to(dest)),
                    "line": line,
                    "confidence": "low",
                })
    return results


def _parse_trufflehog_output(output: str) -> List[Dict[str, Any]]:
    """Separate detector records from JSON diagnostics without retaining secrets.

    TruffleHog also writes structured updater/runtime logs to the combined
    command stream. A JSON object alone is not evidence of a credential.
    Valid detections survive sibling errors, while the tool remains incomplete.
    """
    findings: List[Dict[str, Any]] = []
    invalid_records = error_records = informational_records = 0
    for raw_line in output.splitlines():
        if not raw_line.strip():
            continue
        try:
            obj = json.loads(raw_line)
        except (ValueError, TypeError):
            invalid_records += 1
            continue
        if not isinstance(obj, dict):
            invalid_records += 1
            continue
        # Recognize the logger envelope, never a diagnostic-looking substring
        # in a genuine detector record. Warning/error logs cannot prove clean.
        is_log = ("DetectorName" not in obj and "SourceMetadata" not in obj
                  and isinstance(obj.get("level"), str)
                  and isinstance(obj.get("msg"), str)
                  and isinstance(obj.get("logger"), str))
        if is_log:
            if (re.fullmatch(r"(?:info|debug|trace)(?:-[0-5])?", obj["level"].lower())
                    and not obj.get("error")):
                informational_records += 1
            else:
                error_records += 1
            continue
        detector = obj.get("DetectorName")
        detector_type = obj.get("DetectorType")
        source_metadata = obj.get("SourceMetadata")
        data = source_metadata.get("Data") if isinstance(source_metadata, dict) else None
        filesystem = data.get("Filesystem") if isinstance(data, dict) else None
        source = filesystem.get("file") if isinstance(filesystem, dict) else None
        line = filesystem.get("line", 0) if isinstance(filesystem, dict) else None
        if (not isinstance(detector, str) or not detector.strip() or len(detector) > 160
                or any(ord(c) < 32 for c in detector)
                or type(detector_type) is not int or detector_type < 0
                or not any(isinstance(obj.get(key), str) for key in ("Raw", "RawV2", "Redacted"))
                or not isinstance(source, str) or not source.strip() or len(source) > 4096
                or any(ord(c) < 32 for c in source)
                or type(line) is not int or not 0 <= line <= 2147483647):
            invalid_records += 1
            continue
        findings.append({
            "tool": "trufflehog", "title": f"Secret detected by {detector}",
            "cvss": 7.5,
            "description": f"trufflehog identified {detector} in {source}. Verify before reporting.",
            "file": source, "line": line, "confidence": "medium",
        })
    if invalid_records or error_records:
        failure = ScannerExecutionError(
            f"trufflehog result is incomplete: {error_records} error/warning diagnostic record(s), "
            f"{invalid_records} malformed/unrecognized record(s); "
            f"{len(findings)} valid detection(s) retained. Inspect the recorded scanner artifact."
        )
        failure.partial_findings = findings
        failure.runtime_diagnostic = {
            "kind": "scanner-output-validation", "tool": "trufflehog",
            "error_records": error_records, "invalid_records": invalid_records,
            "informational_records": informational_records,
            "retained_detections": len(findings), "coverage_complete": False,
        }
        raise failure
    return findings


async def run_secret_scan(dest: Path, repo_id: int, send: Callable) -> List[Dict[str, Any]]:
    """Run the best available secret scanner, failing closed on bad output.

    A specialized scanner that is installed but crashes, times out, or emits
    malformed output must not silently fall through to the lightweight regex
    detector and be reported as a successful clean pass.  The fallback is only
    used when no specialized binary is present; an installed scanner's valid
    empty result is authoritative for this tool row.
    """
    if _tool_present("trufflehog"):
        out = await _run_tool(
            repo_id,
            ["trufflehog", "filesystem", ".", "--json", "--no-verification", "--no-update"],
            dest,
            send,
            timeout=120,
        )
        if str(out or "").strip().lower().startswith(("error:", "timed out")):
            raise ScannerExecutionError(f"trufflehog execution failed: {str(out)[:300]}")
        return _parse_trufflehog_output(out)

    if _tool_present("gitleaks"):
        out = await _run_tool(
            repo_id,
            ["gitleaks", "detect", "--source", ".", "--no-git", "-f", "json"],
            dest,
            send,
            timeout=120,
        )
        if not str(out or "").strip():
            # gitleaks emits an empty stream for a clean --no-git scan on some
            # versions. Treat that as a valid empty result, not as permission
            # to substitute a different detector.
            return []
        try:
            data = _json_result_or_error(out, "gitleaks")
        except ScannerExecutionError:
            raise
        if not isinstance(data, list):
            raise ScannerExecutionError("gitleaks JSON result was not an array")
        findings = []
        for leak in data:
            if not isinstance(leak, dict):
                raise ScannerExecutionError("gitleaks JSON contained a non-object result")
            findings.append({
                "tool": "gitleaks",
                "title": f"Secret: {leak.get('RuleID', 'unknown')}",
                "cvss": 7.5,
                "description": f"gitleaks matched rule {leak.get('RuleID')} in {leak.get('File')}:{leak.get('StartLine')}. Verify before reporting.",
                "file": leak.get("File", ""),
                "line": leak.get("StartLine", 0) or 0,
                "confidence": "medium",
            })
        return findings

    return _secret_regex_findings(dest)


async def run_npm_audit(dest: Path, repo_id: int, send: Callable) -> List[Dict[str, Any]]:
    if not _tool_present("npm") or not (dest / "package.json").exists():
        return []
    # Production reachability is the default package boundary.  Auditing the
    # repository's dev tree first inflated findings with test/build tooling that
    # is not shipped to consumers.  ``--omit=dev`` is supported by modern npm;
    # the ``--production`` fallback keeps older npm 6/7 images auditable.
    out = await _run_tool(repo_id, ["npm", "audit", "--omit=dev", "--json"], dest, send, timeout=120)
    try:
        probe = json.loads(out or "")
    except Exception:
        probe = None
    # npm 6/7 can encode an unsupported flag as a valid JSON ``error`` object,
    # not just a usage string.  Retry the equivalent legacy production form in
    # that case; otherwise fail closed below so an operational error cannot
    # masquerade as zero vulnerabilities.
    probe_error = probe.get("error") if isinstance(probe, dict) else None
    probe_error_text = json.dumps(probe_error, sort_keys=True) if probe_error else ""
    if re.search(
        r"unknown option|invalid option|unexpected argument|usage:|invalid arg",
        (out or "") + " " + probe_error_text,
        re.I,
    ):
        out = await _run_tool(repo_id, ["npm", "audit", "--production", "--json"], dest, send, timeout=120)
    return _npm_audit_findings(out)


async def run_npm_audit_in_lab(
    repo_id: int,
    send: Optional[Callable] = None,
    *,
    target_rel: str = ".",
    timeout: int = 180,
) -> List[Dict[str, Any]]:
    """Run the native npm auditor inside the enrolled, built lab image.

    A Lotus API host may intentionally have no Node/npm installation.  The
    generated lab image does have npm (and the target's installed lockfile), so
    using that isolated runtime preserves the native ``npm audit`` signal rather
    than recording a permanent host-tool blind spot.  Network/cache failures
    remain explicit scanner errors; they never become an empty result.
    """
    from backend import lab

    if not lab.get_lab_container(repo_id):
        raise ToolUnavailable("isolated lab container is unavailable for npm audit")
    # ``target_rel`` is produced by bounded first-party manifest discovery.  It
    # is still validated here because this function is also a public runner
    # boundary and must never turn a caller-controlled path into a shell escape.
    rel = str(target_rel or ".").replace("\\", "/").strip()
    rel_path = Path(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise ScannerExecutionError("invalid native audit target path")
    app_target = "." if rel in ("", ".") else f"./{rel_path.as_posix()}"
    command = (
        f"cd {shlex.quote('/app/' + rel_path.as_posix()) if app_target != '.' else '/app'} && "
        "HOME=/tmp NPM_CONFIG_CACHE=/tmp/npm-cache TMPDIR=/tmp "
        "npm audit --omit=dev --json"
    )
    result = await lab.exec_in_lab(repo_id, command, timeout=timeout)
    output = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
    # npm may print a JSON error while exiting non-zero.  Parse first so the
    # report contains its actionable reason; any other non-zero output fails
    # closed below.
    try:
        probe = json.loads((result.get("stdout") or "").strip() or "")
    except Exception:
        probe = None
    probe_error = probe.get("error") if isinstance(probe, dict) else None
    probe_error_text = json.dumps(probe_error, sort_keys=True) if probe_error else ""
    if re.search(
        r"unknown option|invalid option|unexpected argument|usage:|invalid arg",
        output + " " + probe_error_text,
        re.I,
    ):
        fallback = await lab.exec_in_lab(
            repo_id,
            f"cd {shlex.quote('/app/' + rel_path.as_posix()) if app_target != '.' else '/app'} && "
            "HOME=/tmp NPM_CONFIG_CACHE=/tmp/npm-cache TMPDIR=/tmp "
            "npm audit --production --json",
            timeout=timeout,
        )
        result = fallback
        output = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
    if not result.get("success") and not (result.get("stdout") or "").strip():
        raise ScannerExecutionError(
            f"npm audit in lab exited {result.get('exit_code')}: {str(result.get('stderr') or '')[:240]}"
        )
    return _npm_audit_findings(output)


async def run_pip_audit(dest: Path, repo_id: int, send: Callable) -> List[Dict[str, Any]]:
    if not _tool_present("pip-audit"):
        return []
    out = await _run_tool(repo_id, ["pip-audit", "--format=json"], dest, send, timeout=120)
    findings: List[Dict[str, Any]] = []
    data = _json_result_or_error(out, "pip-audit")
    if isinstance(data, list):
        dependencies = data
    elif isinstance(data, dict) and isinstance(data.get("dependencies"), list):
        dependencies = data["dependencies"]
    else:
        raise ScannerExecutionError("pip-audit JSON missing dependencies list")
    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        for vuln in dep.get("vulns", []):
            findings.append({
                "tool": "pip-audit",
                "title": f"PyPI vulnerable package: {dep.get('name')} ({vuln.get('id')})",
                "cvss": 7.0,
                "description": f"pip-audit reported {vuln.get('id')} for {dep.get('name')} {dep.get('version')}.",
                "file": "requirements.txt",
                "line": 0,
                "confidence": "high",
            })
    return findings


async def run_gosec(dest: Path, repo_id: int, send: Callable) -> List[Dict[str, Any]]:
    if not _tool_present("gosec") or not (dest / "go.mod").exists():
        return []
    out = await _run_tool(repo_id, ["gosec", "-fmt", "json", "./..."], dest, send, timeout=120)
    findings: List[Dict[str, Any]] = []
    data = _json_result_or_error(out, "gosec")
    if not isinstance(data, dict) or "Issues" not in data:
        raise ScannerExecutionError("gosec JSON missing Issues field")
    for issue in data.get("Issues", []):
        findings.append({
            "tool": "gosec",
            "title": issue.get("details", "Go security issue"),
            "cvss": 6.5,
            "description": f"gosec: {issue.get('rule_id')} at {issue.get('file')}:{issue.get('line')}. {issue.get('details')}",
            "file": issue.get("file", ""),
            "line": issue.get("line", 0) or 0,
            "confidence": "medium",
        })
    return findings


async def run_cargo_audit(dest: Path, repo_id: int, send: Callable) -> List[Dict[str, Any]]:
    if not _tool_present("cargo-audit") or not (dest / "Cargo.toml").exists():
        return []
    out = await _run_tool(repo_id, ["cargo", "audit", "--json"], dest, send, timeout=120)
    findings: List[Dict[str, Any]] = []
    data = _json_result_or_error(out, "cargo audit")
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), dict):
        raise ScannerExecutionError("cargo audit JSON missing vulnerabilities object")
    for vuln in data.get("vulnerabilities", {}).get("list", []):
        advisory = vuln.get("advisory", {})
        findings.append({
            "tool": "cargo-audit",
            "title": f"Rust crate vulnerability: {advisory.get('id', 'unknown')}",
            "cvss": 7.0,
            "description": f"cargo-audit: {advisory.get('title', '')} in {vuln.get('package', {}).get('name', '')}.",
            "file": "Cargo.toml",
            "line": 0,
            "confidence": "high",
        })
    return findings


async def run_composer_audit(dest: Path, repo_id: int, send: Callable) -> List[Dict[str, Any]]:
    if not _tool_present("composer") or not (dest / "composer.json").exists():
        return []
    out = await _run_tool(repo_id, ["composer", "audit", "--format=json"], dest, send, timeout=120)
    findings: List[Dict[str, Any]] = []
    data = _json_result_or_error(out, "composer audit")
    if not isinstance(data, dict) or not isinstance(data.get("advisories"), dict):
        raise ScannerExecutionError("composer audit JSON missing advisories object")
    for pkg, advisories in data.get("advisories", {}).items():
        for adv in advisories:
            findings.append({
                "tool": "composer-audit",
                "title": f"PHP package vulnerability: {pkg} ({adv.get('cve', 'N/A')})",
                "cvss": 7.0,
                "description": f"composer audit: {adv.get('title', '')} in {pkg}.",
                "file": "composer.json",
                "line": 0,
                "confidence": "high",
            })
    return findings


def _java_report_paths(dest: Path) -> List[Path]:
    """Find dependency-check JSON reports without trusting arbitrary repo JSON."""
    roots = [dest / ".lotus" / "dependency-check", dest / "target", dest / "build" / "reports"]
    paths: List[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            paths.extend(p for p in root.rglob("dependency-check-report.json") if p.is_file())
        except OSError:
            continue
    return paths


def _parse_java_dependency_report(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse OWASP dependency-check JSON into unqualified leads.

    The native report is deliberately only a lead source.  Dependency
    reachability and lab proof remain separate gates before publication.
    """
    if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
        raise ScannerExecutionError("Java dependency audit JSON missing dependencies field")
    findings: List[Dict[str, Any]] = []
    for dep in report.get("dependencies", []):
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("fileName") or dep.get("packages") or "unknown dependency")
        for vuln in dep.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vid = str(vuln.get("name") or vuln.get("id") or "unknown-advisory")
            cvss = 7.0
            for key in ("cvssv3", "cvssv2"):
                score = vuln.get(key)
                if isinstance(score, dict):
                    try:
                        cvss = float(score.get("baseScore") or score.get("score") or cvss)
                        break
                    except (TypeError, ValueError):
                        pass
            findings.append({
                "tool": "java-dependency-audit",
                "title": f"Java dependency advisory: {vid}",
                "cvss": max(0.0, min(10.0, cvss)),
                "description": (
                    f"OWASP dependency-check reported {vid} for {name}. "
                    "Confirm runtime scope and first-party reachability before reporting."
                ),
                "file": "pom.xml" if str(name).endswith((".jar", ".war")) else "build.gradle",
                "line": 0,
                "confidence": "high",
            })
    return findings


async def run_java_dependency_audit(dest: Path, repo_id: int, send: Callable) -> List[Dict[str, Any]]:
    """Run an isolated native Maven/Gradle dependency-check audit.

    OWASP dependency-check is used because Maven/Gradle themselves do not
    provide a vulnerability database.  The command is production-oriented
    (tests excluded), writes a machine-readable report, and fails closed when
    the build or report is unavailable instead of returning an empty list.
    """
    dest = Path(dest)
    out_dir = dest / ".lotus" / "dependency-check"
    out_dir.mkdir(parents=True, exist_ok=True)
    # Never trust a report left by an earlier run.  A failed build must not be
    # paired with stale JSON and presented as this audit's evidence.
    for stale in _java_report_paths(dest):
        try:
            stale.unlink()
        except OSError:
            pass
    started = time.time()
    if (dest / "pom.xml").is_file() and _tool_present("mvn"):
        cmd = [
            "mvn", "-B", "-DskipTests", "-DskipTestScope=true",
            "org.owasp:dependency-check-maven:check",
            "-Dformat=JSON", f"-DoutputDirectory={out_dir}",
        ]
    elif (dest / "gradlew").is_file() or (dest / "build.gradle").is_file() or (dest / "build.gradle.kts").is_file():
        gradle = str(dest / "gradlew") if (dest / "gradlew").is_file() else "gradle"
        if gradle != "gradle" and not os.access(gradle, os.X_OK):
            raise ToolUnavailable("Gradle wrapper exists but is not executable")
        if gradle == "gradle" and not _tool_present("gradle"):
            raise ToolUnavailable("gradle is not installed; Java dependency audit could not run")
        cmd = [
            gradle, "--no-daemon", "dependencyCheckAnalyze",
            "-DskipTestScope=true", "-Dformat=JSON", f"-DoutputDirectory={out_dir}",
        ]
    else:
        raise ToolUnavailable("mvn/gradle is not installed; Java dependency audit could not run")
    out = await _run_tool(repo_id, cmd, dest, send, timeout=300)
    reports = [p for p in _java_report_paths(dest) if p.stat().st_mtime >= started - 1.0]
    if not reports:
        raise ScannerExecutionError(
            f"Java dependency audit produced no dependency-check-report.json (tool output: {out[-240:]})"
        )
    try:
        report = json.loads(reports[0].read_text(errors="ignore"))
    except Exception as exc:
        raise ScannerExecutionError(f"Java dependency audit report JSON was invalid: {exc}") from exc
    return _parse_java_dependency_report(report)


async def run_language_audit(dest: Path, repo_id: int, language: str, send: Callable,
                             *, source_root: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Run the appropriate optional language-level audit for the detected stack."""
    if language == "python":
        from backend.k8s_runtime import kubernetes_selected
        if kubernetes_selected(repo_id):
            from backend.python_dependency_audit import run_python_package_audit
            return await run_python_package_audit(dest, repo_id, send, source_root=source_root)
    if language == "go":
        if not native_audit_applicability(dest, language)[0]:
            return []
        from backend import ext_analyzers
        # Dependency audit is govulncheck, not a duplicate host-only gosec SAST
        # invocation. Nested module roots retain the full bound source volume.
        return await ext_analyzers.run_govulncheck(dest, repo_id=repo_id, source_root=source_root)
    if language in {"node", "java"}:
        from backend.k8s_runtime import kubernetes_selected
        if kubernetes_selected(repo_id):
            if not native_audit_applicability(dest, language)[0]:
                return []
            from backend.native_k8s import run_package_audit
            return await run_package_audit(dest, repo_id, language, send, source_root=source_root)
    if language == "node":
        if (dest / "package.json").exists() and not _tool_present("npm"):
            raise ToolUnavailable("npm is not installed; production dependency audit could not run")
        return await run_npm_audit(dest, repo_id, send)
    if language == "python":
        if any((dest / name).exists() for name in ("requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock")) and not _tool_present("pip-audit"):
            raise ToolUnavailable("pip-audit is not installed; Python dependency audit could not run")
        return await run_pip_audit(dest, repo_id, send)
    if language == "rust":
        if (dest / "Cargo.toml").exists() and not _tool_present("cargo-audit"):
            raise ToolUnavailable("cargo-audit is not installed; Rust dependency audit could not run")
        return await run_cargo_audit(dest, repo_id, send)
    if language == "php":
        if (dest / "composer.json").exists() and not _tool_present("composer"):
            raise ToolUnavailable("composer is not installed; PHP dependency audit could not run")
        return await run_composer_audit(dest, repo_id, send)
    if language == "java":
        if not native_audit_applicability(dest, language)[0]:
            return []
        return await run_java_dependency_audit(dest, repo_id, send)
    return []
