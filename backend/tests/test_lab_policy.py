"""Unit tests for lab-pod execution policy (no Docker required)."""
from __future__ import annotations

import os
import shutil

import pytest

from backend.lab_policy import (
    default_audit_exec_mode,
    host_sandbox_allowed,
    labs_disabled,
    refuse_host_audit_poc,
)


def test_sandbox_allowed_when_flag_set(monkeypatch):
    monkeypatch.setenv("LOTUS_ALLOW_HOST_SANDBOX", "1")
    monkeypatch.delenv("LOTUS_DISABLE_LAB", raising=False)
    assert host_sandbox_allowed() is True
    assert refuse_host_audit_poc("sandbox") is None


def test_sandbox_refused_when_docker_and_no_flag(monkeypatch):
    monkeypatch.delenv("LOTUS_ALLOW_HOST_SANDBOX", raising=False)
    monkeypatch.delenv("LOTUS_DISABLE_LAB", raising=False)
    monkeypatch.setattr("backend.lab_policy.docker_available", lambda: True)
    refused = refuse_host_audit_poc("sandbox")
    assert refused is not None
    assert refused["success"] is False
    assert "lab pod" in refused["stderr"].lower()
    assert refused["mode"] == "lab"


def test_lab_mode_never_refused(monkeypatch):
    monkeypatch.delenv("LOTUS_ALLOW_HOST_SANDBOX", raising=False)
    monkeypatch.setattr("backend.lab_policy.docker_available", lambda: True)
    assert refuse_host_audit_poc("lab") is None


def test_labs_disabled_allows_sandbox(monkeypatch):
    monkeypatch.setenv("LOTUS_DISABLE_LAB", "1")
    monkeypatch.delenv("LOTUS_ALLOW_HOST_SANDBOX", raising=False)
    assert labs_disabled() is True
    assert host_sandbox_allowed() is True
    assert refuse_host_audit_poc("sandbox") is None


def test_default_mode_is_lab_when_docker(monkeypatch):
    monkeypatch.delenv("LOTUS_DISABLE_LAB", raising=False)
    monkeypatch.setattr("backend.lab_policy.docker_available", lambda: True)
    assert default_audit_exec_mode() == "lab"


def test_selftest_skip_pod_does_not_spawn(monkeypatch):
    monkeypatch.setenv("LOTUS_SELFTEST_SKIP_POD", "1")
    from backend.lab_selftest import run_debug_tests
    payload = run_debug_tests()
    assert "markdown" in payload
    names = [d["name"] for d in payload["details"]]
    assert "lab-pod-pytest" in names
    pod = next(d for d in payload["details"] if d["name"] == "lab-pod-pytest")
    assert pod["ok"] is True
    assert "skipped" in pod["message"].lower()


def test_selftest_pod_command_includes_report_deps():
    from pathlib import Path
    src = Path(__file__).resolve().parents[1] / "lab_selftest.py"
    text = src.read_text(encoding="utf-8")
    assert "fpdf2" in text
    assert "no:warnings" in text
    assert "LOTUS_BACKUP_DIR" in text


@pytest.mark.skipif(
    os.environ.get("LOTUS_VERIFY_DOCKER") != "1" or not shutil.which("docker"),
    reason="live Docker cleanup requires LOTUS_VERIFY_DOCKER=1 and Docker",
)
def test_teardown_lab_removes_only_the_registered_container():
    """Stop must target the registered name, never a lotus-* glob."""
    import subprocess
    import time
    from backend.lab import get_lab_container, register_lab_container, teardown_lab
    name = f"lotus-selftest-stop-{os.getpid()}-{int(time.time())}"
    before = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=10,
    )
    preexisting = {n for n in before.stdout.splitlines() if n.strip()}
    run = subprocess.run(
        ["docker", "run", "-d", "--name", name, "python:3.12-slim", "sleep", "90"],
        capture_output=True, text=True, timeout=60,
    )
    if run.returncode != 0:
        pytest.skip(run.stderr[-200:] or "could not start python:3.12-slim")
    try:
        register_lab_container(424242, name)
        assert get_lab_container(424242) == name
        import asyncio
        asyncio.run(teardown_lab(424242))
        assert get_lab_container(424242) == ""
        gone = subprocess.run(["docker", "inspect", name], capture_output=True, timeout=10)
        assert gone.returncode != 0
        after = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=10,
        )
        still = {n for n in after.stdout.splitlines() if n.strip()}
        assert preexisting <= still
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)
