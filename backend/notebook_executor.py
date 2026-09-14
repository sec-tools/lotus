"""Restricted Python notebook process executor.

Provides an opt-in, resource-limited host process for the API documentation
tab's interactive notebook feature. Code runs in a restricted subprocess
with AST-level validation, module allowlisting, and resource limits. These
controls are not an OS isolation boundary for hostile Python.
"""
from __future__ import annotations

import ast
import json
import os
import resource
import signal
import subprocess
import sys
import tempfile
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Set

# Modules allowed to be imported in notebook cells
ALLOWED_MODULES: Set[str] = {
    # Standard library (safe subset)
    "json", "datetime", "collections", "itertools", "functools",
    "re", "math", "statistics", "textwrap", "string", "enum",
    "dataclasses", "typing", "copy", "pprint", "operator",
    "decimal", "fractions", "random", "hashlib", "hmac",
    "base64", "binascii", "struct", "csv", "io",
    # Lotus SDK
    "backend.sdk", "backend.sdk.models", "backend.sdk.exceptions",
}

# AST node types that are NEVER allowed
FORBIDDEN_AST_NODES = {
    # No exec/eval (redundant with import blocking, but defense in depth)
}

# Function names that are blocked
FORBIDDEN_CALLS: Set[str] = {
    "exec", "eval", "compile", "__import__", "globals", "locals",
    "getattr", "setattr", "delattr", "vars", "dir",
    "open", "input", "breakpoint", "exit", "quit",
}

# Attribute access patterns that are blocked
FORBIDDEN_ATTRIBUTES: Set[str] = {
    "__subclasses__", "__bases__", "__mro__", "__class__",
    "__import__", "__builtins__", "__loader__", "__spec__",
    "__code__", "__globals__", "__closure__",
}

# Resource limits for subprocess
MAX_MEMORY_BYTES = 256 * 1024 * 1024  # 256 MB
MAX_CPU_SECONDS = 30
MAX_OUTPUT_BYTES = 1024 * 1024  # 1 MB

# Rate limiting
_rate_lock = Lock()
_rate_history: deque = deque(maxlen=100)
RATE_LIMIT_PER_MINUTE = 10


@dataclass
class ExecutionResult:
    """Result of notebook cell execution."""
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    execution_time_ms: int = 0
    success: bool = False
    cell_id: str = ""
    isolation_type: str = "restricted_host_process"
    output_truncated: bool = False


class CodeValidationError(ValueError):
    """Raised when code fails AST validation."""
    pass


def validate_code(code: str) -> None:
    """Validate Python code at the AST level before execution.

    Raises CodeValidationError if code contains forbidden constructs.
    """
    if not code or not code.strip():
        raise CodeValidationError("Empty code")

    if len(code) > 50000:
        raise CodeValidationError("Code exceeds maximum length (50000 chars)")

    # Parse AST
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        raise CodeValidationError(f"Syntax error: {e}")

    # Walk AST and check all nodes
    for node in ast.walk(tree):
        # Check imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                _check_module(alias.name)

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                _check_module(node.module)

        # Check function calls
        elif isinstance(node, ast.Call):
            func_name = _get_call_name(node)
            if func_name in FORBIDDEN_CALLS:
                raise CodeValidationError(
                    f"Forbidden function call: {func_name}()"
                )

        # Check attribute access
        elif isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_ATTRIBUTES:
                raise CodeValidationError(
                    f"Forbidden attribute access: .{node.attr}"
                )


def _check_module(module_name: str) -> None:
    """Check if a module import is allowed."""
    # Check exact match and prefix match
    parts = module_name.split(".")
    for i in range(len(parts)):
        prefix = ".".join(parts[: i + 1])
        if prefix in ALLOWED_MODULES:
            return

    raise CodeValidationError(
        f"Import not allowed: {module_name}. "
        f"Allowed modules: {', '.join(sorted(ALLOWED_MODULES))}"
    )


def _get_call_name(node: ast.Call) -> str:
    """Extract function name from a Call AST node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _check_rate_limit() -> None:
    """Enforce rate limiting on code execution."""
    now = time.time()
    with _rate_lock:
        # Remove entries older than 60 seconds
        while _rate_history and _rate_history[0] < now - 60:
            _rate_history.popleft()

        if len(_rate_history) >= RATE_LIMIT_PER_MINUTE:
            raise CodeValidationError(
                f"Rate limit exceeded: maximum {RATE_LIMIT_PER_MINUTE} executions per minute"
            )

        _rate_history.append(now)


def _run_restricted_process(script_path: str, tmp_dir: str, cancel_event=None) -> dict:
    """Bound pipe collection and reap an owned process group on every exit.

    This is a resource-limited host process, not an OS security sandbox. The
    caller must retain explicit host-execution policy checks.
    """
    import selectors
    proc = None
    selector = selectors.DefaultSelector()
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    timed_out = output_limited = cancelled = False
    try:
        proc = subprocess.Popen(
            [sys.executable, script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=tmp_dir, env=_sandbox_env(tmp_dir), start_new_session=True,
        )
        for name in chunks:
            selector.register(getattr(proc, name), selectors.EVENT_READ, name)
        deadline = time.monotonic() + MAX_CPU_SECONDS
        while selector.get_map():
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                destination = chunks[key.data]
                room = max(0, MAX_OUTPUT_BYTES - len(destination))
                destination.extend(data[:room])
                if len(data) > room:
                    output_limited = True
                    break
            if output_limited:
                break
        if not timed_out and not output_limited and not cancelled:
            try:
                proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        # Kill the entire session even after a normal leader exit: inherited
        # pipe handles and child processes must not outlive a notebook cell.
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                proc.wait()
                for stream in (proc.stdout, proc.stderr):
                    if stream:
                        stream.close()
        selector.close()
    return {"stdout": bytes(chunks["stdout"]).decode(errors="replace"),
            "stderr": bytes(chunks["stderr"]).decode(errors="replace"),
            "returncode": proc.returncode, "timed_out": timed_out,
            "output_limited": output_limited, "cancelled": cancelled}


def execute_code(code: str, cell_id: str = "", lotus_url: str = "http://localhost:8000", context: Optional[dict] = None, cancel_event=None) -> ExecutionResult:
    """Execute Python code in a sandboxed subprocess.

    The code is:
    1. Validated at the AST level (no forbidden imports, calls, or attributes)
    2. Written to a temporary file
    3. Executed in a subprocess with resource limits
    4. Output captured and returned

    Args:
        code: Python code to execute
        cell_id: Optional cell identifier
        lotus_url: Lotus server URL for SDK initialization

    Returns:
        ExecutionResult with stdout, stderr, timing, and success status
    """
    result = ExecutionResult(cell_id=cell_id)

    # Rate limit check
    try:
        _check_rate_limit()
    except CodeValidationError as e:
        result.error = str(e)
        return result

    # AST validation
    try:
        validate_code(code)
    except CodeValidationError as e:
        result.error = str(e)
        return result

    # Wrap code with SDK initialization preamble
    wrapped = _wrap_code(code, lotus_url, context=context)

    # Write to temp file
    tmp_dir = tempfile.mkdtemp(prefix="lotus_notebook_")
    script_path = os.path.join(tmp_dir, "cell.py")

    try:
        with open(script_path, "w") as f:
            f.write(wrapped)

        # Execute in subprocess with resource limits
        start_time = time.monotonic()

        try:
            completed = _run_restricted_process(script_path, tmp_dir, cancel_event=cancel_event)
            result.stdout, result.stderr = completed["stdout"], completed["stderr"]
            result.output_truncated = completed["output_limited"]
            result.success = completed["returncode"] == 0 and not completed["output_limited"] and not completed["timed_out"] and not completed["cancelled"]
            if completed["cancelled"]:
                result.error = "Execution cancelled"
            elif completed["timed_out"] or completed["returncode"] == -getattr(signal, "SIGXCPU", 24):
                result.error = f"Execution timed out after {MAX_CPU_SECONDS} seconds"
            elif completed["output_limited"]:
                result.error = "Execution stopped at the output size limit"
            elif not result.success:
                lines = result.stderr.strip().split("\n")
                result.error = lines[-1] if result.stderr else f"Execution stopped (exit {completed['returncode']})"

        except subprocess.TimeoutExpired:
            result.error = f"Execution timed out after {MAX_CPU_SECONDS} seconds"
        except Exception as e:
            result.error = f"Execution error: {str(e)[:500]}"

        elapsed = time.monotonic() - start_time
        result.execution_time_ms = int(elapsed * 1000)

    finally:
        # Clean up temp files
        try:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

    return result


def _wrap_code(code: str, lotus_url: str, context: Optional[dict] = None) -> str:
    """Wrap user code with sandbox preamble and SDK setup."""
    return f'''
import sys
import resource

# Set resource limits
try:
    resource.setrlimit(resource.RLIMIT_AS, ({MAX_MEMORY_BYTES}, {MAX_MEMORY_BYTES}))
except (ValueError, resource.error):
    pass  # Not all platforms support RLIMIT_AS

# CPU time supplements the parent wall deadline. Fail closed if essential
# process limits cannot be installed; unsupported address space limits above
# are documented separately and are not a security boundary.
resource.setrlimit(resource.RLIMIT_CPU, ({MAX_CPU_SECONDS}, {MAX_CPU_SECONDS + 1}))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

# Pre-configure Lotus SDK
import os
os.environ["LOTUS_SDK_URL"] = {repr(lotus_url)}

# Restrict builtins
import builtins
_original_import = builtins.__import__

_ALLOWED = {repr(ALLOWED_MODULES)}

def _safe_import(name, *args, **kwargs):
    parts = name.split(".")
    for i in range(len(parts)):
        prefix = ".".join(parts[:i+1])
        if prefix in _ALLOWED:
            return _original_import(name, *args, **kwargs)
    raise ImportError(f"Import not allowed: {{name}}")

builtins.__import__ = _safe_import

# Remove dangerous builtins
for _name in ["exec", "eval", "compile", "open", "input", "breakpoint", "exit", "quit"]:
    if hasattr(builtins, _name):
        try:
            delattr(builtins, _name)
        except (AttributeError, TypeError):
            pass

# Read-only-by-convention copy of recorded provenance; changing it cannot alter
# the server binding or promote notebook observations to verified findings.
LOTUS_CONTEXT = {repr(context or {})}

# --- User code below ---
{code}
'''


def _sandbox_env(work_dir: str = "/tmp") -> Dict[str, str]:
    """Create a minimal environment for the sandbox subprocess."""
    env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": work_dir,
        "TMPDIR": work_dir,
        "LANG": "en_US.UTF-8",
        "PYTHONPATH": str(Path(__file__).resolve().parent.parent),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
    }
    # Inherit virtualenv if present
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        env["VIRTUAL_ENV"] = venv
        env["PATH"] = f"{venv}/bin:{env['PATH']}"
    return env


def get_api_spec() -> List[Dict]:
    """Generate API documentation specification for the docs tab.

    Returns a list of endpoint descriptions with examples.
    """
    return [
        {
            "group": "Repositories",
            "endpoints": [
                {
                    "method": "GET", "path": "/api/repos",
                    "description": "List all active repositories",
                    "sdk_example": 'repos = client.list_repos()\nfor r in repos:\n    print(f"{r.source} - {r.status}")',
                    "response_example": '[{"id": 1, "source": "https://github.com/org/repo", "branch": "main", "status": "idle"}]',
                },
                {
                    "method": "POST", "path": "/api/repos",
                    "description": "Add a repository for scanning",
                    "body": '{"source": "https://github.com/org/repo", "branch": "main"}',
                    "sdk_example": 'repo = client.add_repo("https://github.com/org/repo")\nprint(f"Added repo #{repo.id}")',
                },
                {
                    "method": "POST", "path": "/api/repos/{repo_id}/scan",
                    "description": "Trigger a scan on a repository",
                    "sdk_example": 'result = client.scan_repo(repo_id=1)\nprint(result)',
                },
                {
                    "method": "GET", "path": "/api/repos/{repo_id}/audit-summary",
                    "description": "Get structured summary of the most recent audit",
                    "sdk_example": 'summary = client.get_audit_summary(repo_id=1)\nprint(summary["findings_confirmed"], "findings confirmed")',
                },
                {
                    "method": "POST", "path": "/api/repos/{repo_id}/audit-chat",
                    "description": "AI-powered chat about audit intel, steering, and findings",
                    "body": '{"message": "What did Phase 1 recon discover?", "action": "query-intel"}',
                    "sdk_example": 'res = client.audit_chat(repo_id=1, message="What did Phase 1 discover?", action="query-intel")\nprint(res["response"])',
                },
                {
                    "method": "POST", "path": "/api/repos/{repo_id}/restart-phase2",
                    "description": "Restart Phase 2 analysis with custom guidance",
                    "body": '{"guidance": "Focus on auth bypass and deserialization"}',
                    "sdk_example": 'res = client.restart_phase2(repo_id=1, guidance="Focus on auth bypass")\nprint(res["message"])',
                },
                {
                    "method": "DELETE", "path": "/api/repos/{repo_id}",
                    "description": "Archive a repository (soft delete)",
                    "sdk_example": 'client.delete_repo(repo_id=1)',
                },
            ],
        },
        {
            "group": "Findings",
            "endpoints": [
                {
                    "method": "GET", "path": "/api/findings",
                    "description": "List all findings ordered by CVSS score",
                    "sdk_example": 'findings = client.list_findings(min_cvss=7.0)\nfor f in findings:\n    print(f"{f.title} - CVSS {f.cvss}")',
                },
                {
                    "method": "GET", "path": "/api/findings/{finding_id}",
                    "description": "Get a specific finding by ID",
                    "sdk_example": 'finding = client.get_finding(finding_id=1)\nprint(finding.description)',
                },
                {
                    "method": "POST", "path": "/api/findings/{finding_id}/validate",
                    "description": "Run a finding through proof gates",
                    "sdk_example": 'result = client.validate_finding(finding_id=1)\nprint(f"Status: {result[\'status\']}")',
                },
                {
                    "method": "GET", "path": "/api/findings/{finding_id}/fixes",
                    "description": "Get ranked remediation suggestions",
                    "sdk_example": 'fixes = client.get_finding_fixes(finding_id=1)\nprint(json.dumps(fixes, indent=2))',
                },
            ],
        },
        {
            "group": "Reports",
            "endpoints": [
                {
                    "method": "GET", "path": "/api/reports",
                    "description": "List all generated reports",
                    "sdk_example": 'reports = client.list_reports()\nfor r in reports:\n    print(f"Report #{r.id} - {r.created_at}")',
                },
                {
                    "method": "POST", "path": "/api/reports",
                    "description": "Generate a report from eligible findings",
                    "body": '{"repo_id": 1}',
                    "sdk_example": 'report = client.create_report(repo_id=1)\nprint(report.markdown[:200])',
                },
                {
                    "method": "PUT", "path": "/api/reports/{report_id}",
                    "description": "Update report markdown content",
                    "body": '{"markdown": "# Updated Report\\n..."}',
                    "sdk_example": 'client.update_report(report_id=1, markdown="# Updated\\n...")',
                },
                {
                    "method": "GET", "path": "/api/reports/{report_id}/findings",
                    "description": "Get findings associated with this report",
                    "sdk_example": 'findings = client.get_report_findings(report_id=1)\nfor f in findings:\n    print(f["title"], f["cvss"])',
                },
                {
                    "method": "POST", "path": "/api/reports/{report_id}/chat",
                    "description": "AI chat assistant for report editing",
                    "body": '{"message": "Rewrite the executive summary", "action": "rewrite"}',
                    "sdk_example": 'result = client.report_chat(\n    report_id=1,\n    message="Simplify for executives",\n    action="summarize"\n)\nprint(result["suggested_markdown"])',
                },
                {
                    "method": "POST", "path": "/api/reports/{report_id}/poc/run",
                    "description": "Execute PoC code in the isolated lab pod",
                    "body": '{"code": "print(1+1)", "language": "python", "mode": "lab"}',
                    "sdk_example": 'result = client.run_poc(\n    report_id=1,\n    code="import json; print(json.dumps({}))",\n    language="python",\n    mode="lab",\n)\nprint(result["stdout"])',
                },
                {
                    "method": "POST", "path": "/api/reports/{report_id}/poc/launch-lab",
                    "description": "Launch an isolated lab pod for PoC testing",
                    "sdk_example": 'status = client.launch_lab(report_id=1)\nprint(status["status"])',
                },
                {
                    "method": "POST", "path": "/api/reports/{report_id}/poc/stop-lab",
                    "description": "Stop this report's isolated lab pod (does not touch other lotus-* labs)",
                    "sdk_example": 'status = client.stop_lab(report_id=1)\nprint(status["status"])',
                },
                {
                    "method": "GET", "path": "/api/reports/{report_id}/poc/lab-status",
                    "description": "Check if lab container is running",
                    "sdk_example": 'status = client.get_lab_status(report_id=1)\nprint("Lab running:", status["running"])',
                },
                {
                    "method": "GET", "path": "/api/reports/{report_id}/pdf",
                    "description": "Download report as PDF",
                    "sdk_example": 'client.export_pdf(report_id=1, output_path="report.pdf")',
                },
            ],
        },
        {
            "group": "Harness",
            "endpoints": [
                {
                    "method": "GET", "path": "/api/harness",
                    "description": "List all AI harness runs",
                    "sdk_example": 'runs = client.list_harness_runs()\nfor r in runs:\n    print(f"Run #{r.id} - {r.status} - {r.findings_count} findings")',
                },
                {
                    "method": "POST", "path": "/api/harness",
                    "description": "Create a new AI harness run",
                    "body": '{"repo_id": 1, "max_tokens": 100000, "max_hours": 2.0, "max_findings": 10}',
                    "sdk_example": 'run = client.create_harness_run(\n    repo_id=1,\n    max_tokens=100000,\n    max_hours=2.0\n)',
                },
            ],
        },
        {
            "group": "Settings",
            "endpoints": [
                {
                    "method": "GET", "path": "/api/settings",
                    "description": "Get current platform settings",
                    "sdk_example": 's = client.get_settings()\nprint(f"CVSS threshold: {s.cvss_threshold}")\nprint(f"Audit depth: {s.audit_depth}")',
                },
                {
                    "method": "POST", "path": "/api/settings",
                    "description": "Update platform settings",
                    "body": '{"cvss_threshold": 8.0, "audit_depth": 3}',
                    "sdk_example": 's = client.update_settings(\n    cvss_threshold=8.0,\n    audit_depth=3\n)\nprint(f"Updated: depth={s.audit_depth}")',
                },
            ],
        },
        {
            "group": "Dashboard & System",
            "endpoints": [
                {
                    "method": "GET", "path": "/api/dashboard",
                    "description": "Get dashboard summary statistics",
                    "sdk_example": 'd = client.dashboard()\nprint(f"Repos: {d.repos}, Findings: {d.findings_total}")',
                },
                {
                    "method": "GET", "path": "/api/debug/stats",
                    "description": "Get detailed system statistics",
                    "sdk_example": 'stats = client.stats()\nprint(json.dumps(stats, indent=2))',
                },
                {
                    "method": "GET", "path": "/api/console",
                    "description": "Get console log lines",
                    "sdk_example": 'logs = client.get_console_logs()\nfor line in logs[-10:]:\n    print(line)',
                },
            ],
        },
    ]
