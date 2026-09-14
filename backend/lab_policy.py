"""Policy: audit execution (PoCs, repro, target tests, builds) runs on lab pods.

Phase-1 static reconnaissance still reads the cloned source on the Lotus host;
every dynamic action — PoC, reproduction, fix-verify, harness prove-loop,
Debug → Run Tests — must execute inside a disposable ``lotus-*`` container
unless labs are explicitly disabled (``LOTUS_DISABLE_LAB=1``).
"""
from __future__ import annotations

import os
import shutil
from typing import Optional


def labs_disabled() -> bool:
    return os.environ.get("LOTUS_DISABLE_LAB", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def host_sandbox_allowed() -> bool:
    """Host-side Python sandbox is for the API-docs notebook and unit tests.

    Audit PoCs (report ▶ Run / Repro / shell) need explicit host opt-in via
    LOTUS_ALLOW_HOST_SANDBOX=1 or labs disabled, regardless of lab provider.
    """
    if labs_disabled():
        return True
    return os.environ.get("LOTUS_ALLOW_HOST_SANDBOX", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def docker_available() -> bool:
    return bool(shutil.which("docker"))


def default_audit_exec_mode() -> str:
    """Where report/audit PoCs run when the client omits ``mode``."""
    if labs_disabled() or not docker_available():
        return "sandbox" if host_sandbox_allowed() else "lab"
    return "lab"


def refuse_host_audit_poc(mode: str) -> Optional[dict]:
    """Return an error payload if ``mode`` is host sandbox during a live audit.

    ``None`` means the requested mode is allowed.
    """
    requested = (mode or default_audit_exec_mode()).strip().lower()
    if requested != "sandbox":
        return None
    if host_sandbox_allowed():
        return None
    if docker_available():
        return {
            "success": False,
            "stdout": "",
            "stderr": (
                "Audit PoCs must run in an isolated lab pod. "
                "Click Launch Isolated Lab Pod, then Run. "
                "Host sandbox is disabled for audit execution."
            ),
            "exit_code": -1,
            "execution_time_ms": 0,
            "mode": "lab",
        }
    return {
        "success": False,
        "stdout": "",
        "stderr": (
            "Host sandbox is not allowed for audit execution. "
            "Check the selected lab provider in Settings and /readyz, "
            "then launch an isolated lab pod."
        ),
        "exit_code": -1,
        "execution_time_ms": 0,
        "mode": "lab",
    }
