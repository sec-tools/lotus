"""Run a focused platform battery in the explicitly selected isolated runtime.

Kubernetes uses the packaged Lotus image and existing restricted tool runner.
Only an authored marker is copied to its unique source PVC; current application
data and credentials never enter the test Job. Docker remains an explicit
backup. LOTUS_SELFTEST_SKIP_POD is reserved for hermetic API/unit tests.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent

# Keep this list short and hermetic: no live Git clones, no Docker-in-Docker,
# no 5-repo audits. Coverage of API/UI contracts + lab policy is the point.
SELFTEST_PYTEST = [
    "backend/tests/test_ops_endpoints.py",
    "backend/tests/test_lab_policy.py",
    "backend/tests/test_ui_api_contract.py",
]

# These packaged tests exercise API/DB/frontend contracts and required tool
# isolation with mocked cluster transports. No audit or live-runtime opt-in.
K8S_SELFTEST_PYTEST = [
    "backend/tests/test_ops_endpoints.py",
    "backend/tests/test_lab_policy.py",
    "backend/tests/test_ui_api_contract.py::test_every_onclick_handler_is_defined",
    "backend/tests/test_ui_api_contract.py::test_ui_api_literals_exist_on_server",
    "backend/tests/test_k8s_tool_isolation.py",
]

SELFTEST_IMAGE = os.environ.get("LOTUS_SELFTEST_IMAGE", "python:3.12-slim")
SELFTEST_TIMEOUT = int(os.environ.get("LOTUS_SELFTEST_TIMEOUT", "240"))
PIP_CACHE_VOLUME = os.environ.get("LOTUS_PIP_CACHE_VOLUME", "lotus-pip-cache")


def _skip_pod() -> bool:
    return os.environ.get("LOTUS_SELFTEST_SKIP_POD", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _progress(message: str) -> None:
    try:
        from backend.main import log_console
        log_console("Debug tests: " + message)
    except ImportError:
        pass


def _health_checks(runtime: str) -> List[Tuple[str, bool, str]]:
    results: List[Tuple[str, bool, str]] = []
    results.append(("python-runtime", True, f"Python {sys.version.split()[0]}"))

    if runtime == "k8s-job":
        if _skip_pod():
            results.append(("kubernetes-control-plane", True, "skipped (hermetic self-test mode)"))
        else:
            from backend.deploy_profile import lab_runtime_status
            status = lab_runtime_status(probe=True)
            results.append(("kubernetes-control-plane", bool(status.get("available")), str(status.get("message") or status.get("status"))))
    elif not _skip_pod():
        results.append(_docker_health_check())
    else:
        results.append(("docker-daemon", True, "skipped (hermetic self-test mode)"))

    db = None
    try:
        from backend.main import get_db
        from sqlalchemy import text
        db = get_db()
        db.execute(text("SELECT 1"))
        results.append(("database-connection", True, "connected"))
    except Exception as e:
        results.append(("database-connection", False, str(e)[:200]))
    finally:
        if db is not None:
            db.close()

    results.append(("isolation-policy", True, f"selected runtime: {runtime}; disposable test execution required"))
    return results


def _docker_health_check() -> Tuple[str, bool, str]:
    try:
        out = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=8,
        )
        ok = out.returncode == 0
        msg = (out.stdout or out.stderr or "").strip()[:200]
        return "docker-daemon", ok, msg or ("reachable" if ok else "unreachable")
    except Exception as e:
        return "docker-daemon", False, str(e)[:200]


async def _kubernetes_selftest_image(*, use_explicit_override: bool = True) -> str:
    from backend import k8s_lab
    explicit = os.environ.get("LOTUS_SELFTEST_IMAGE", "").strip() if use_explicit_override else ""
    if explicit:
        if not re.fullmatch(r"[^\s]+@sha256:[a-fA-F0-9]{64}", explicit):
            raise ValueError("Kubernetes LOTUS_SELFTEST_IMAGE must be a digest-pinned Lotus application image")
        return explicit
    # A host-side operator must configure an explicit image. In-cluster, use
    # the current application Pod's spec plus resolved runtime digest.
    account = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    pod_name = os.environ.get("LOTUS_POD_NAME") or os.environ.get("HOSTNAME", "")
    if not account.joinpath("token").is_file() or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", pod_name):
        raise ValueError("Set LOTUS_SELFTEST_IMAGE to a digest-pinned Lotus image when testing outside its Kubernetes application Pod")
    doc, rc, _ = await k8s_lab.get_json("pod", pod_name, timeout=15)
    metadata = doc.get("metadata") or {}
    if rc or metadata.get("name") != pod_name or metadata.get("namespace") != k8s_lab.namespace():
        raise ValueError("Current Kubernetes application Pod image could not be verified")
    containers = [item for item in (doc.get("spec") or {}).get("containers", []) if item.get("name") == "lotus"]
    statuses = [item for item in (doc.get("status") or {}).get("containerStatuses", []) if item.get("name") == "lotus"]
    if len(containers) != 1 or len(statuses) != 1:
        raise ValueError("Current Kubernetes Pod lacks one identifiable Lotus application container")
    image = str(containers[0].get("image") or "")
    digest = re.search(r"sha256:[a-fA-F0-9]{64}$", str(statuses[0].get("imageID") or ""))
    if not digest or not image or any(char.isspace() for char in image):
        raise ValueError("Current Kubernetes application image lacks an immutable runtime digest")
    if re.fullmatch(r"[^\s]+@sha256:[a-fA-F0-9]{64}", image):
        # Pod spec may pin an OCI index while imageID identifies its selected
        # platform manifest/config. They are different digest domains; retain
        # the verified Pod's immutable pull reference rather than compare them.
        return image
    repository = image.split("@", 1)[0]
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    pullable = re.sub(r"^[a-z-]+://", "", str(statuses[0].get("imageID") or ""))
    if re.fullmatch(re.escape(repository) + r"@sha256:[a-fA-F0-9]{64}", pullable):
        return pullable
    raise ValueError("Current Kubernetes image uses a mutable tag without a verified repository digest; configure digest-pinned LOTUS_SELFTEST_IMAGE")


def _kubernetes_test_script(marker: str) -> str:
    check = (
        "import json, os; from pathlib import Path; "
        f"assert json.loads(Path('/src/selftest.json').read_text())['run_id'] == {marker!r}; "
        "assert os.getuid() != 0; "
        "assert not Path('/var/run/secrets/kubernetes.io/serviceaccount/token').exists(); "
        "Path('/tmp/selftest-write').write_text('scratch usable'); "
        "print('Kubernetes source delivery, non-root user, absent service-account token, writable scratch: PASS')"
    )
    # PATH is removed only for pytest; the runner's shell/frame utilities keep
    # their normal path. Nested tests cannot discover Docker/kubectl binaries.
    return ("set -eu; mkdir -p /tmp/lotus-selftest /tmp/lotus-selftest-home; cd /app; /usr/local/bin/python -c " + shlex.quote(check) + "; "
            "if touch /src/must-remain-read-only 2>/dev/null; then echo 'Source mount was writable' >&2; exit 71; fi; "
            "PATH=/tmp/lotus-selftest-no-tools /usr/local/bin/python -m pytest "
            + " ".join(shlex.quote(path) for path in K8S_SELFTEST_PYTEST)
            + " -q --tb=line -p no:warnings --disable-warnings -p no:cacheprovider")


async def _run_pytest_in_kubernetes() -> Tuple[bool, str]:
    from backend import k8s_lab, k8s_runtime
    from backend.reset_runtime_ownership import delete_k8s_uid
    image = await _kubernetes_selftest_image()
    # Reserve a unique fixture ID outside ordinary repository IDs. Check the
    # exact name before source admission; never reuse the runtime PVC cache.
    fixture_id = 10**15 + int(uuid.uuid4().hex[:12], 16)
    pvc_name = k8s_runtime.source_pvc_name(fixture_id)
    prior, rc, raw = await k8s_lab.get_json("pvc", pvc_name, timeout=15)
    if rc == 0 or "notfound" not in raw.lower().replace(" ", ""):
        return False, "Kubernetes self-test could not reserve an unused source volume"
    marker = uuid.uuid4().hex
    pvc_uid = ""
    result = (False, "Kubernetes self-test did not execute")
    try:
        with tempfile.TemporaryDirectory(prefix="lotus-selftest-source-") as directory:
            Path(directory, "selftest.json").write_text(json.dumps({"run_id": marker}))
            _progress("Kubernetes: creating a unique marker-only source PVC and checking required policies")
            populated = await k8s_runtime.ensure_source_pvc(fixture_id, Path(directory), size="64Mi", timeout=min(SELFTEST_TIMEOUT, 180))
        doc, read_rc, _ = await k8s_lab.get_json("pvc", pvc_name, timeout=15)
        meta = doc.get("metadata") or {}
        labels = meta.get("labels") or {}
        if (read_rc or meta.get("name") != pvc_name or meta.get("namespace") != k8s_lab.namespace()
                or labels.get("lotus.io/repo-id") != str(fixture_id) or labels.get("role") != "tool-source" or not meta.get("uid")):
            raise ValueError("Kubernetes self-test PVC ownership was not verified; no unknown resource will be deleted")
        pvc_uid = meta["uid"]
        if not populated:
            raise ValueError("Kubernetes self-test source delivery failed")
        _progress("Kubernetes: running packaged API, UI-contract and isolation tests in a tokenless, non-root, no-egress Job")
        stdout, stderr, code = await k8s_runtime.run_to_completion(fixture_id, "selftest", image,
            script=_kubernetes_test_script(marker), workdir="/app", timeout=SELFTEST_TIMEOUT,
            allow_egress=False, mem_limit="2Gi", cpu_limit="1", mem_request="256Mi", cpu_request="250m",
            env={"LOTUS_NO_SEED": "1", "LOTUS_SELFTEST_SKIP_POD": "1", "LOTUS_RUNTIME": "k8s-job",
                 "LOTUS_DISABLE_LAB": "1", "LOTUS_REQUIRE_LAB_PROVIDER": "0", "LOTUS_REQUIRE_DOCKER": "0",
                 "LOTUS_VERIFY_DOCKER": "0", "LOTUS_ALLOW_HOST_SANDBOX": "1", "LOTUS_AUTH_TOKEN": "",
                 "LOTUS_DEPLOY_PROFILE": "single", "WEB_CONCURRENCY": "1", "PYTHONPATH": "/app",
                 "DATABASE_URL": "sqlite:////tmp/lotus-selftest/lotus.db", "LOTUS_DATA_DIR": "/tmp/lotus-selftest",
                 "LOTUS_SKILLS_DIR": "/tmp/lotus-selftest/skills", "LOTUS_REPOS_DIR": "/tmp/lotus-selftest/repos",
                 "LOTUS_BACKUP_DIR": "/tmp/lotus-selftest/backups", "LOTUS_CREDENTIALS_PATH": "/tmp/lotus-selftest/credentials.json",
                 "HOME": "/tmp/lotus-selftest-home", "XDG_CACHE_HOME": "/tmp/lotus-selftest-home/.cache",
                 "XDG_CONFIG_HOME": "/tmp/lotus-selftest-home/.config", "XDG_DATA_HOME": "/tmp/lotus-selftest-home/.local/share",
                 "KUBECONFIG": "/tmp/lotus-selftest-no-cluster", "PYTHONDONTWRITEBYTECODE": "1"})
        result = (code == 0, ((stdout or "") + "\n" + (stderr or "")).strip()[-800:] or f"Kubernetes pytest exit {code}")
    except Exception as exc:
        result = False, "Kubernetes self-test failed: " + str(exc)[:500]
    finally:
        k8s_runtime._POPULATED.pop(fixture_id, None)
        if not pvc_uid:
            # Source upload can fail after PVC creation. Recover only this
            # previously absent, uniquely addressed fixture's owned UID.
            try:
                document, read_rc, _ = await k8s_lab.get_json("pvc", pvc_name, timeout=15)
                metadata = document.get("metadata") or {}
                labels = metadata.get("labels") or {}
                if (read_rc == 0 and metadata.get("name") == pvc_name and metadata.get("namespace") == k8s_lab.namespace()
                        and labels.get("role") == "tool-source" and labels.get("lotus.io/repo-id") == str(fixture_id)):
                    pvc_uid = str(metadata.get("uid") or "")
            except Exception:
                pass
        if pvc_uid:
            try:
                await delete_k8s_uid("persistentvolumeclaim", pvc_name, k8s_lab.namespace(), pvc_uid)
                _progress("Kubernetes: removed the self-test source PVC using its recorded UID")
            except Exception as exc:
                result = False, result[1] + "; source cleanup failed: " + str(exc)[:200]
    return result


def _run_pytest_in_lab_pod() -> Tuple[bool, str]:
    """Spawn a one-shot container and run the focused pytest battery inside it."""
    if not shutil.which("docker"):
        return False, "docker binary not found"
    name = f"lotus-selftest-{os.getpid()}-{int(time.time())}"
    tests = " ".join(SELFTEST_PYTEST)
    inner = (
        "pip install -q pytest fastapi 'sqlalchemy>=2' httpx starlette pydantic "
        "python-multipart 'uvicorn[standard]' fpdf2 && "
        f"PYTHONPATH=/workspace LOTUS_NO_SEED=1 LOTUS_SELFTEST_SKIP_POD=1 "
        "PYTHONWARNINGS=ignore DATABASE_URL=sqlite:////tmp/lotus_selftest.db "
        "LOTUS_BACKUP_DIR=/tmp/lotus_backups "
        f"python -m pytest {tests} -q --tb=line -p no:warnings --disable-warnings"
    )
    cmd = [
        "docker", "run", "--rm",
        "--name", name,
        "-v", f"{ROOT}:/workspace:ro",
        "-v", f"{PIP_CACHE_VOLUME}:/root/.cache/pip",
        "-w", "/workspace",
        "-e", "LOTUS_NO_SEED=1",
        "-e", "LOTUS_SELFTEST_SKIP_POD=1",
        "-e", "PYTHONPATH=/workspace",
        "-e", "LOTUS_BACKUP_DIR=/tmp/lotus_backups",
        SELFTEST_IMAGE,
        "sh", "-c", inner,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=SELFTEST_TIMEOUT,
        )
        combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        keep: list[str] = []
        for ln in combined.splitlines():
            if "DeprecationWarning" in ln or "warnings.warn" in ln:
                continue
            if "/workspace/" in ln and "Warning" in ln:
                continue
            keep.append(ln)
        summary = [ln for ln in keep if any(tok in ln.lower() for tok in ("failed", "passed", "error", "===", "fail "))]
        snippet = "\n".join((summary[-8:] or keep[-12:] or [combined[-600:]]))
        ok = proc.returncode == 0
        return ok, (snippet.strip() or ("pass" if ok else f"exit {proc.returncode}"))[:800]
    except subprocess.TimeoutExpired:
        # Best-effort: never docker rm -f lotus-* labs; only our unique selftest name.
        try:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=10)
        except Exception:
            pass
        return False, f"lab-pod pytest timed out after {SELFTEST_TIMEOUT}s"
    except Exception as e:
        return False, str(e)[:500]


def run_debug_tests() -> Dict[str, Any]:
    from backend.lab_provider import provider_name
    try:
        runtime = provider_name()
    except ValueError as exc:
        return {"markdown": str(exc), "terminal": str(exc), "passed": False, "runtime": "invalid", "details": [], "lab_pod": False}
    label = "Kubernetes" if runtime == "k8s-job" else "Docker backup"
    _progress(label + ": checking selected runtime and database connectivity")
    results = _health_checks(runtime)
    runtime_ok = any(n in {"docker-daemon", "kubernetes-control-plane"} and ok for n, ok, _ in results)

    if _skip_pod():
        results.append(("lab-pod-pytest", True, "skipped (LOTUS_SELFTEST_SKIP_POD=1)"))
    elif runtime_ok:
        _progress(label + ": starting focused isolated test battery")
        try:
            ok, msg = asyncio.run(_run_pytest_in_kubernetes()) if runtime == "k8s-job" else _run_pytest_in_lab_pod()
        except Exception as exc:
            ok, msg = False, label + " self-test unavailable: " + str(exc)[:500]
        results.append(("lab-pod-pytest", ok, msg[:800]))
    else:
        results.append(("lab-pod-pytest", False, label + " unavailable; no alternate runtime was invoked"))

    output = f"# Lotus Diagnostics — {label}\n\n"
    for name, ok, msg in results:
        status = "PASS" if ok else "FAIL"
        snippet = msg.replace("\n", " ")[:240]
        output += f"- **{name}**: `{status}` - {snippet}\n"

    all_pass = all(ok for _, ok, _ in results) and not _skip_pod()
    overall = "SKIPPED" if _skip_pod() else ("PASS" if all_pass else "FAIL")
    output += f"\n**Overall**: {overall}\n"
    _progress(label + ": " + overall)
    terminal = output.replace("**", "").replace("`", "")
    return {
        "markdown": output,
        "terminal": terminal,
        "passed": all_pass,
        "details": [{"name": n, "ok": o, "message": m} for n, o, m in results],
        "runtime": runtime,
        "execution": "skipped" if _skip_pod() else ("attempted" if runtime_ok else "blocked"),
        "lab_pod": (not _skip_pod()) and runtime_ok,
    }
