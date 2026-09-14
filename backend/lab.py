import asyncio
import hashlib
import json
import logging
import os
import re
import random
import string
import shutil
import shlex
import uuid
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.async_process import terminate_and_reap
from backend import docker_budget

HEALTH_TIMEOUT = 45  # seconds  - Flask/app boot may take longer than plain http.server
BUILD_TIMEOUT = 300  # seconds to wait for a per-repo lab image build
USER_DOCKERFILE_TIMEOUT = int(os.environ.get("LOTUS_USER_DOCKERFILE_TIMEOUT", "900"))
COMPOSE_TIMEOUT = int(os.environ.get("LOTUS_COMPOSE_TIMEOUT", "900"))  # pull+start remote images
BASE_IMAGE_BUILD_TIMEOUT = 600  # seconds to build the reusable base image


class GeneratedLabPlanError(RuntimeError):
    """A Lotus-generated lab cannot honestly establish a target runtime."""


def _build_timeout_for_target(dest: Path, *, baseline: int = BUILD_TIMEOUT) -> int:
    """Choose a bounded build timeout from target size, not a fixed guess.

    A five-minute cap is adequate for a small fixture but systematically
    truncates large Go/Java/C++ repositories after dependency resolution. The
    old timeout made a timeout look like a normal fallback and prevented any
    deployment-backed proof. Scale only for source trees (ignore VCS,
    dependency caches, and Lotus artifacts), keep an operator override, and
    cap the result so an untrusted repository cannot reserve a worker forever.
    """
    try:
        override = int(os.environ.get("LOTUS_BUILD_TIMEOUT", "0") or 0)
    except (TypeError, ValueError):
        override = 0
    if override > 0:
        return max(60, min(1800, override))

    count = 0
    total_bytes = 0
    root = Path(dest)
    ignored = {".git", ".lotus", "node_modules", "vendor", "target", "build", "dist"}
    try:
        for path in root.rglob("*"):
            if any(part in ignored for part in path.parts):
                continue
            if not path.is_file():
                continue
            count += 1
            try:
                total_bytes += path.stat().st_size
            except OSError:
                pass
            # Coarse buckets are sufficient; stop walking a huge monorepo once
            # the highest bucket is known.
            if count > 1200 or total_bytes > 120 * 1024 * 1024:
                break
    except OSError:
        return max(60, min(1800, int(baseline)))

    if count > 800 or total_bytes > 80 * 1024 * 1024:
        return max(int(baseline), 1200)
    if count > 300 or total_bytes > 25 * 1024 * 1024:
        return max(int(baseline), 900)
    if count > 120 or total_bytes > 10 * 1024 * 1024:
        return max(int(baseline), 600)
    return max(60, min(1800, int(baseline)))

# Track audit slugs per repo_id for consistent naming within a scan
_AUDIT_SLUGS: Dict[int, str] = {}
# Per-scan lab runtime: container name, compose project, kind
_LAB_STATE: Dict[int, Dict[str, Any]] = {}
_CMD_LOG_REPO: ContextVar[Optional[int]] = ContextVar("lotus_lab_cmd_repo", default=None)


def register_lab_container(repo_id: int, container: str, **extra: Any) -> None:
    state = _LAB_STATE.setdefault(repo_id, {})
    state["container"] = container
    state.update(extra)


def bind_command_log(repo_id: Optional[int]):
    """Associate subsequent docker/lab subprocesses with a scan's command log."""
    return _CMD_LOG_REPO.set(repo_id)


def reset_command_log(token) -> None:
    try:
        _CMD_LOG_REPO.reset(token)
    except Exception:
        pass


def get_lab_state(repo_id: int) -> Dict[str, Any]:
    return dict(_LAB_STATE.get(repo_id) or {})


def get_lab_container(repo_id: int) -> str:
    """Name of the running lab container, or '' if this audit has no registered pod.

    Do not invent ``lotus-{slug}`` names here: docker exec against a guessed name
    looks like a successful lab launch and then fails with 'No such container'.
    """
    state = _LAB_STATE.get(repo_id) or {}
    return str(state.get("container") or "")


def generate_audit_slug(repo_source: str, repo_id: int) -> str:
    """Generate a k8s-style audit slug from repo URL.
    Example: https://github.com/kellyjonbrazil/jc -> jc-x7k2
    """
    # Extract repo name from URL
    name = repo_source.rstrip("/").split("/")[-1]
    name = re.sub(r"\.git$", "", name)
    name = re.sub(r"[^a-z0-9]", "", name.lower())[:12]
    if not name:
        name = "repo"
    # Add random 4-char alphanumeric suffix
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    slug = f"{name}-{suffix}"
    _AUDIT_SLUGS[repo_id] = slug
    return slug


def get_audit_slug(repo_id: int) -> str:
    """Get the audit slug for a repo, or generate a fallback."""
    if repo_id in _AUDIT_SLUGS:
        return _AUDIT_SLUGS[repo_id]
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    slug = f"audit-{suffix}"
    _AUDIT_SLUGS[repo_id] = slug
    return slug

LAB_BASE_IMAGE = os.environ.get("LOTUS_LAB_BASE_IMAGE", "lotus-lab-ubuntu:26.04")
# Dockerfile that ships all language runtimes and dynamic analysis tools
LAB_BASE_DOCKERFILE = Path(__file__).parent / "lab" / "Dockerfile"


def _log_lab_command(cmd: List[str], cwd: Optional[Path], rc: int, output: str) -> None:
    repo_id = _CMD_LOG_REPO.get()
    if not repo_id:
        return
    try:
        from backend.pipeline import record_command
        record_command(
            int(repo_id),
            cmd,
            cwd=cwd or "",
            rc=rc,
            stdout=output or "",
            stderr="",
            phase="lab",
            name="lab-cmd",
        )
    except Exception:
        pass


async def _run_cmd(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
    input_data: Optional[bytes] = None,
    env: Optional[Dict[str, str]] = None,
) -> tuple:
    """Run a subprocess under the Docker VM memory admission gate.

    A ``docker run`` carrying a ``--memory`` cap reserves that much of the
    global Docker-VM budget for its duration, so a lab container cannot
    overcommit the VM on top of the analyzers and OOM the daemon. Builds,
    compose, and other commands request zero and pass straight through.
    """
    _mem_mb = 0
    try:
        if isinstance(cmd, (list, tuple)) and len(cmd) >= 2 and cmd[0] == "docker" and cmd[1] == "run" and "--memory" in cmd:
            _mem_mb = docker_budget.parse_memory_to_mb(cmd[cmd.index("--memory") + 1])
    except Exception:
        _mem_mb = 0
    async with docker_budget.reserve(_mem_mb, label="lab"):
        return await _run_cmd_raw(cmd, cwd=cwd, timeout=timeout, input_data=input_data, env=env)


async def _run_cmd_raw(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
    input_data: Optional[bytes] = None,
    env: Optional[Dict[str, str]] = None,
) -> tuple:
    """Run a subprocess with a hard timeout and return (stdout+stderr, returncode)."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd) if cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            env=env,
        )
        if timeout:
            out, _ = await asyncio.wait_for(
                proc.communicate(input=input_data), timeout=timeout
            )
        else:
            out, _ = await proc.communicate(input=input_data)
        text = out.decode(errors="ignore")
        _log_lab_command(cmd, cwd, proc.returncode, text)
        return text, proc.returncode
    except asyncio.CancelledError:
        await terminate_and_reap(proc)
        raise
    except asyncio.TimeoutError:
        await terminate_and_reap(proc)
        _log_lab_command(cmd, cwd, -1, f"timed out after {timeout}s")
        return f"timed out after {timeout}s", -1
    except Exception as e:
        await terminate_and_reap(proc)
        _log_lab_command(cmd, cwd, -1, f"error: {e}")
        return f"error: {e}", -1


async def _docker_attestation(repo_id: int) -> Dict[str, str]:
    """Collect immutable daemon identities for a proof receipt.

    Names and tags are mutable.  If the daemon cannot return every identity, the
    caller must leave the result unproven instead of manufacturing a receipt.
    """
    state = _LAB_STATE.get(repo_id) or {}
    container = str(state.get("container") or "")
    network = str(state.get("net_name") or "")
    if not container or not network:
        return {}
    container_id, crc = await _run_cmd(["docker", "inspect", "-f", "{{.Id}}", container], timeout=10)
    image_id, irc = await _run_cmd(["docker", "inspect", "-f", "{{.Image}}", container], timeout=10)
    network_id, nrc = await _run_cmd(["docker", "network", "inspect", "-f", "{{.Id}}", network], timeout=10)
    # Compose services use a project-scoped network rather than the placeholder
    # lotus-net-* network.  Attest the network(s) actually attached to the
    # inspected container and reject an empty/unrelated network identity.
    attached_json, arc = await _run_cmd(
        ["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", container], timeout=10,
    )
    if crc != 0 or irc != 0 or arc != 0:
        return {}
    try:
        attached = json.loads(attached_json.strip() or "{}")
        attached_ids = [str(v.get("NetworkID") or "") for v in attached.values() if isinstance(v, dict)]
    except Exception:
        attached_ids = []
    if not attached_ids:
        return {}
    if nrc == 0 and network_id.strip() and network_id.strip() in attached_ids:
        selected_network = network_id.strip()
    else:
        # For Compose, use the real project network ID rather than the empty
        # per-audit placeholder.  This still proves daemon identity and avoids
        # claiming a network attachment that never existed.
        selected_network = attached_ids[0]
    return {
        "container_id": container_id.strip(),
        "image_digest": image_id.strip(),
        "network_id": selected_network,
        "lab_run_id": str(state.get("lab_run_id") or ""),
        "target_tree_hash": str(state.get("target_tree_hash") or ""),
        "target_revision": str(state.get("target_revision") or ""),
    }


async def _k8s_attestation(repo_id: int) -> Dict[str, str]:
    """Collect immutable Kubernetes Job/Pod identities for proof receipts."""
    state = _LAB_STATE.get(repo_id) or {}
    pod = str(state.get("container") or state.get("pod") or "")
    if not pod or str(state.get("provider") or "") != "k8s-job":
        return {}
    try:
        from backend import k8s_lab
        doc, rc, _raw = await k8s_lab.get_json("pod", pod, timeout=20)
        if rc != 0 or not doc:
            return {}
        meta = doc.get("metadata") or {}
        uid = str(meta.get("uid") or state.get("pod_uid") or "")
        image = k8s_lab.image_digest(doc)
        if not uid or not image:
            return {}
        job_name = str(state.get("job_name") or "")
        job_doc, jrc, _ = await k8s_lab.get_json("job", job_name, timeout=20) if job_name else ({}, 1, "")
        job_uid = str((job_doc.get("metadata") or {}).get("uid") or "") if jrc == 0 else ""
        return {
            "container_id": f"k8s-pod:{uid}",
            "image_digest": image,
            # Kubernetes NetworkPolicy identity is represented by the
            # namespace/pod UID pair; it is immutable for this lab run.
            "network_id": f"k8s:{state.get('namespace') or k8s_lab.namespace()}:{uid}",
            "lab_run_id": str(state.get("lab_run_id") or f"k8s:{job_name}:{uid}"),
            "target_tree_hash": str(state.get("target_tree_hash") or ""),
            "target_revision": str(state.get("target_revision") or ""),
            "pod_uid": uid,
            "job_uid": job_uid,
        }
    except Exception:
        return {}


async def lab_attestation(repo_id: int) -> Dict[str, str]:
    """Return an attestation from the active provider (Docker or Kubernetes)."""
    state = _LAB_STATE.get(repo_id) or {}
    if str(state.get("provider") or "") == "k8s-job":
        return await _k8s_attestation(repo_id)
    return await _docker_attestation(repo_id)


async def _wait_for_http(url: str, timeout: int = HEALTH_TIMEOUT, path: str = "/") -> bool:
    """Return True once HTTP responds (any status), not merely TCP accept."""
    try:
        import httpx
    except ImportError:
        return await _wait_for_port("127.0.0.1", int(url.rsplit(":", 1)[-1].split("/")[0]), timeout)
    t0 = datetime.utcnow()
    async with httpx.AsyncClient(follow_redirects=True, timeout=3.0) as client:
        while (datetime.utcnow() - t0).total_seconds() < timeout:
            try:
                r = await client.get(f"{url.rstrip('/')}{path}")
                if r.status_code > 0:
                    return True
            except Exception:
                pass
            await asyncio.sleep(2)
    return False


async def _wait_for_port(host: str, port: int, timeout: int = HEALTH_TIMEOUT) -> bool:
    """Return True once the TCP port accepts a connection."""
    t0 = datetime.utcnow()
    while (datetime.utcnow() - t0).total_seconds() < timeout:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            await asyncio.sleep(1)
    return False


async def _docker_log_tail(name: str, lines: int = 80) -> str:
    """Fetch the last N lines of docker logs for a named container."""
    if not shutil.which("docker"):
        return "docker binary not found"
    out, _ = await _run_cmd(["docker", "logs", "--tail", str(lines), name], timeout=30)
    return out


async def _docker_images_present(name: str) -> bool:
    out, rc = await _run_cmd(["docker", "images", "-q", name], timeout=20)
    return rc == 0 and bool(out.strip())


async def _ensure_base_image(send, repo_id: int) -> Optional[str]:
    """Build the reusable Lotus lab base image if it is not already present."""
    if await _docker_images_present(LAB_BASE_IMAGE):
        return LAB_BASE_IMAGE

    if not LAB_BASE_DOCKERFILE.exists():
        return None

    await send(repo_id, f"Building reusable lab base image {LAB_BASE_IMAGE}", level="info")
    repo_root = Path(__file__).parent.parent
    out, rc = await _run_cmd(
        ["docker", "build", "-t", LAB_BASE_IMAGE, "-f", str(LAB_BASE_DOCKERFILE), "."],
        cwd=repo_root,
        timeout=BASE_IMAGE_BUILD_TIMEOUT,
        env=_controlled_child_env({"DOCKER_BUILDKIT": "1"}),
    )
    if rc != 0:
        await send(repo_id, f"Base lab image build failed: {out[:500]}", level="warning")
        return None
    await send(repo_id, f"Reusable lab base image {LAB_BASE_IMAGE} ready", level="info")
    return LAB_BASE_IMAGE


# Per-container resource limits (env provides the fallback; Settings override at runtime)
LAB_MEMORY_LIMIT = os.environ.get("LOTUS_LAB_MEMORY", "4g")
LAB_CPU_LIMIT = os.environ.get("LOTUS_LAB_CPUS", "2")
LAB_DISK_LIMIT = os.environ.get("LOTUS_LAB_DISK", "10g")  # --storage-opt (requires overlay2)
LAB_PIDS_LIMIT = os.environ.get("LOTUS_LAB_PIDS", "512")


def lab_limits() -> dict:
    """Resolve effective lab container caps from Settings, falling back to env defaults.

    Returns docker-ready strings: ``memory`` (e.g. "4096m"), ``cpus`` (e.g. "2.0"),
    ``pids`` (e.g. "512"). Best-effort - never raises, so lab startup is unaffected
    if the DB/Settings are unavailable.
    """
    mem, cpus, pids = LAB_MEMORY_LIMIT, str(LAB_CPU_LIMIT), str(LAB_PIDS_LIMIT)
    try:
        from backend.main import SessionLocal, Settings
        db = SessionLocal()
        try:
            s = db.query(Settings).first()
            if s is not None:
                if getattr(s, "lab_memory_mb", 0):
                    mem = f"{int(s.lab_memory_mb)}m"
                if getattr(s, "lab_cpus", 0):
                    cpus = str(float(s.lab_cpus))
                if getattr(s, "lab_pids_limit", 0):
                    pids = str(int(s.lab_pids_limit))
        finally:
            db.close()
    except Exception:
        pass
    return {"memory": mem, "cpus": cpus, "pids": pids}


def hardened_runtime_args(repo_id: Optional[int] = None) -> List[str]:
    """Docker flags that every Lotus-owned target container must receive.

    The target is untrusted.  These flags are intentionally assembled centrally so
    generated, Dockerfile and published-image launch paths cannot drift.  A fixed
    high UID avoids inheriting image-default root; writable scratch is confined to
    tmpfs while the image filesystem remains read-only.
    """
    limits = lab_limits()
    args = [
        "--memory", limits["memory"],
        "--cpus", limits["cpus"],
        "--pids-limit", limits["pids"],
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt", "no-new-privileges:true",
        "--user", os.environ.get("LOTUS_LAB_UID", "65532:65532"),
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m",
        "--tmpfs", "/run:rw,noexec,nosuid,nodev,size=32m",
    ]
    # Stable labels make orphan cleanup auditable and prevent a future cleanup
    # routine from resorting to broad lotus-* name globs.
    if repo_id is not None:
        args.extend(["--label", f"lotus.audit.repo_id={int(repo_id)}"])
        state = _LAB_STATE.get(repo_id) or {}
        run_id = str(state.get("lab_run_id") or "")
        if run_id:
            args.extend(["--label", f"lotus.audit.run_id={run_id}"])
        # Persist the immutable target identity in daemon metadata so a
        # restarted API can hydrate lab controls without trusting a mutable
        # checkout or a guessed container name.
        for key, value in (
            ("target_revision", state.get("target_revision")),
            ("target_tree_hash", state.get("target_tree_hash")),
        ):
            text = str(value or "").strip()
            if text and "\n" not in text and "\r" not in text:
                args.extend(["--label", f"lotus.audit.{key}={text[:512]}"])
    return args


def _controlled_child_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return a minimal environment for repo-controlled Docker operations."""
    names = {
        "PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "DOCKER_CONFIG",
        "DOCKER_BUILDKIT", "COMPOSE_PROJECT_NAME", "HOST_PORT", "WAIT_PORTS",
    }
    allowed = {k: v for k, v in os.environ.items() if k in names}
    configured = (os.environ.get("LOTUS_CHILD_ENV_ALLOWLIST") or "").strip()
    if configured:
        for name in (n.strip() for n in configured.split(",")):
            if name and name in os.environ:
                allowed[name] = os.environ[name]
    if extra:
        allowed.update({str(k): str(v) for k, v in extra.items()})
    return allowed


def _harden_build_context(dest: Path) -> None:
    """Ensure disposable Docker build contexts cannot copy host-side secrets."""
    path = Path(dest) / ".dockerignore"
    # The build policy is generated after target identity is captured. Preserve
    # the exact source file (including its absence) so the source tree can be
    # restored before audit integrity/content hashes are published.
    backup = Path(dest) / ".lotus" / "dockerignore.original"
    if not backup.exists():
        try:
            backup.parent.mkdir(parents=True, exist_ok=True)
            if path.is_file():
                backup.write_bytes(b"1\n" + path.read_bytes())
            else:
                backup.write_bytes(b"0\n")
        except OSError as exc:
            raise RuntimeError("could not preserve source .dockerignore") from exc
    required = [
        ".git", ".hg", ".svn", ".lotus", ".env", ".env.*",
        "*.pem", "*.key", "*.p12", "*.pfx", "*credentials*", "*secret*",
        "node_modules", ".venv", "venv", "__pycache__",
    ]
    try:
        existing = path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else ""
        lines = [line.strip() for line in existing.splitlines() if line.strip()]
        # Put mandatory entries last so a repository's negation rule cannot
        # re-include a secret after our policy line.
        merged = list(dict.fromkeys(lines + required))
        path.write_text("\n".join(merged) + "\n", encoding="utf-8")
    except OSError:
        # A failed ignore write is a policy failure at the call site; avoid
        # silently building a context that may contain credentials.
        raise RuntimeError("could not write mandatory lab .dockerignore")


def restore_hardened_build_context(dest: Path) -> bool:
    """Restore the source ``.dockerignore`` after a disposable build.

    Returns ``True`` when a Lotus backup existed and was restored.  A missing
    backup is not treated as success: callers should surface that provenance
    gap rather than claiming the target content hash still matches.
    """
    root = Path(dest)
    backup = root / ".lotus" / "dockerignore.original"
    if not backup.is_file():
        return False
    try:
        raw = backup.read_bytes()
        marker, sep, content = raw.partition(b"\n")
        path = root / ".dockerignore"
        if marker == b"1":
            path.write_bytes(content)
        elif marker == b"0":
            if path.exists() or path.is_symlink():
                path.unlink()
        else:
            return False
        backup.unlink()
        return True
    except OSError:
        return False


async def _notify_build(repo_id: int, send, message: str, level: str = "warning") -> None:
    """Emit a build-lifecycle notification, gated by the user's in-app prefs.

    Routes through the pipeline's classified notifier (so operators can toggle
    build notifications in Settings); falls back to the raw ``send`` stream if the
    router is unavailable for any reason.
    """
    try:
        from backend.pipeline import notify_internal
        surfaced = await notify_internal(repo_id, "build_retry", message, level=level)
        if surfaced:
            return
    except Exception:
        pass
    try:
        await send(repo_id, message, level=level)
    except Exception:
        pass


def build_retry_policy() -> tuple:
    """Return (max_retries, backoff_base_seconds) for builds, from Settings/env."""
    retries, backoff = 1, 10
    try:
        from backend.main import SessionLocal, Settings
        db = SessionLocal()
        try:
            s = db.query(Settings).first()
            if s is not None:
                retries = int(getattr(s, "build_max_retries", 1) or 0)
                backoff = int(getattr(s, "build_retry_backoff_s", 10) or 0)
        finally:
            db.close()
    except Exception:
        pass
    return max(0, retries), max(0, backoff)


def _install_and_start_commands(language: str, port: int, app_type: str = 'unknown') -> str:
    """Return Dockerfile RUN/CMD instructions for the detected language.

    Web/API labs must start the *application* (Flask/etc.), not only a static
    file server  - otherwise PoC routes never execute and proof gates stay empty.
    CLI/library labs keep a dummy listener for health checks.
    """
    # Language-specific dependency installation
    install = ""
    if language in ("ruby/rails", "ruby"):
        install = (
            "RUN gem install bundler:2.4.22 2>/dev/null || true\n"
            "RUN (test -f Gemfile && bundle config set --local path 'vendor/bundle' && "
            "bundle install --jobs 4 --retry 3) 2>/dev/null || true\n"
            "RUN (ls /app/*.gemspec >/dev/null 2>&1 && "
            "RUBYLIB=/app/lib:$RUBYLIB gem build /app/*.gemspec && "
            "gem install --no-document /app/*.gem) 2>/dev/null || true\n"
        )
    elif language == "python":
        install = (
            "RUN (test -f requirements.txt && pip3 install --no-cache-dir -r requirements.txt) 2>/dev/null || true\n"
            "RUN (test -f pyproject.toml && pip3 install --no-cache-dir .) 2>/dev/null || true\n"
            "RUN (test -f setup.py && pip3 install --no-cache-dir -e .) 2>/dev/null || true\n"
            "RUN pip3 install --no-cache-dir flask 2>/dev/null || true\n"
        )
    elif language == "node":
        install = "RUN npm install --ignore-scripts 2>/dev/null || true\n"
    elif language == "go":
        install = (
            "RUN go mod download 2>/dev/null || true\n"
            "RUN go build -o /app/app ./... 2>/dev/null || true\n"
        )
    elif language == "java":
        install = (
            "# Java/Maven: compile and package (skip tests for speed)\n"
            "RUN if [ -f pom.xml ]; then "
            "mvn -q package -DskipTests -Dmaven.javadoc.skip=true 2>/dev/null || "
            "mvn -q dependency:resolve -DskipTests 2>/dev/null || true; fi\n"
            "RUN if [ -f build.gradle ] || [ -f build.gradle.kts ]; then "
            "gradle build -x test --no-daemon 2>/dev/null || "
            "gradle dependencies --no-daemon 2>/dev/null || true; fi\n"
            "# Find and prepare the WAR/JAR for deployment\n"
            "RUN find /app -name '*.war' -o -name '*.jar' 2>/dev/null | head -5 > /tmp/java_artifacts.txt || true\n"
        )
    elif language == "php":
        install = "RUN (test -f composer.json && composer install --no-interaction --no-dev) 2>/dev/null || true\n"
    elif language == "c/cpp":
        install = (
            "# Build C/C++ project (PHP extension, Makefile, or CMake)\n"
            "USER root\n"
            "RUN if [ -f config.m4 ]; then "
            "phpize 2>/dev/null && ./configure 2>/dev/null && make -j$(nproc) 2>/dev/null && make install 2>/dev/null && "
            "echo 'extension=yaml.so' > $(php -i 2>/dev/null | grep 'Scan this dir' | cut -d'>' -f2 | tr -d ' ')/99-yaml.ini 2>/dev/null; "
            "elif [ -f Makefile ]; then make -j$(nproc) 2>/dev/null; "
            "elif [ -f CMakeLists.txt ]; then mkdir -p build && cd build && cmake .. && make -j$(nproc) 2>/dev/null; "
            "fi || true\n"
            "USER lotus\n"
        )
    elif language == "rust":
        install = (
            "RUN command -v cargo >/dev/null 2>&1 || "
            "(curl -sSf https://sh.rustup.rs | sh -s -- -y)\n"
            "ENV PATH=/root/.cargo/bin:$PATH\n"
            "RUN cargo build --release 2>/dev/null || cargo build || true\n"
        )
    elif language == "elixir":
        install = (
            "RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y --no-install-recommends elixir erlang-dev erlang-nox "
            "&& rm -rf /var/lib/apt/lists/* || true\n"
            "RUN mix local.hex --force && mix local.rebar --force && mix deps.get && mix compile || true\n"
        )
    elif language in ("csharp", "dotnet"):
        install = (
            "RUN curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --channel 8.0 || true\n"
            "ENV PATH=$PATH:/root/.dotnet\n"
            "RUN dotnet restore && dotnet build -c Release --no-restore || true\n"
        )
    elif language == "scala":
        install = (
            "RUN command -v sbt >/dev/null 2>&1 || true\n"
            "RUN sbt -batch compile 2>/dev/null || true\n"
        )
    elif language == "kotlin":
        install = (
            "RUN if [ -f build.gradle ] || [ -f build.gradle.kts ]; then "
            "gradle build -x test --no-daemon 2>/dev/null || true; fi\n"
        )
    elif language == "dart":
        install = "RUN dart pub get 2>/dev/null || true\n"
    elif language == "zig":
        install = "RUN zig build 2>/dev/null || true\n"
    elif language == "swift":
        install = "RUN swift build 2>/dev/null || true\n"

    # A generic static server is acceptable only to keep a *classified*
    # CLI/library container alive for non-HTTP harness work. For a service/API
    # it would turn a missing application into a misleading healthy listener.
    fallback = f"python3 -m http.server {port} --bind 0.0.0.0 --directory /app"
    target_start_failed = "echo 'Lotus target launcher failed; target runtime is unproven' >&2; exit 64"

    def _json_shell_cmd(script: str) -> str:
        """Encode a launcher as Docker JSON CMD (avoids nested-quote bugs)."""
        return f"CMD {json.dumps(['bash', '-lc', script])}\n"

    if app_type in ("cli-tool", "library"):
        cmd = f"CMD {fallback}\n"
    elif language == "python" and app_type in ("web-app", "api-service", "unknown"):
        # Launcher prefers Flask app.run so PoC routes execute. A failed app
        # startup exits rather than serving repository files as a fake API.
        start_py = (
            "RUN cat > /app/lotus_lab_start.py <<'LOTUS_EOF'\n"
            "import os, runpy, sys\n"
            f"port = int(os.environ.get('LOTUS_LAB_PORT', '{port}'))\n"
            "started = False\n"
            "for c in ('app.py', 'main.py', 'wsgi.py', 'server.py'):\n"
            "    p = os.path.join('/app', c)\n"
            "    if not os.path.isfile(p):\n"
            "        continue\n"
            "    try:\n"
            "        ns = runpy.run_path(p)\n"
            "        app = ns.get('app')\n"
            "        if app is not None and hasattr(app, 'run'):\n"
            "            app.run(host='0.0.0.0', port=port, debug=False)\n"
            "            started = True\n"
            "            break\n"
            "    except Exception as e:\n"
            "        sys.stderr.write('lotus start %s failed: %s\\n' % (c, e))\n"
            "if not started:\n"
            "    sys.stderr.write('lotus could not start a detected Python application; target runtime is unproven\\n')\n"
            "    raise SystemExit(64)\n"
            "LOTUS_EOF\n"
        )
        install = f"{install}{start_py}"
        cmd = 'CMD ["python3", "/app/lotus_lab_start.py"]\n'
    elif language == "ruby/rails" and app_type in ("web-app", "api-service", "unknown"):
        cmd = _json_shell_cmd(
            f"bundle exec rails s -b 0.0.0.0 -p {port} 2>/dev/null || "
            f"bundle exec puma -b tcp://0.0.0.0:{port} 2>/dev/null || {{ {target_start_failed}; }}"
        )
    elif language == "node" and app_type in ("web-app", "api-service", "unknown"):
        cmd = _json_shell_cmd(
            f"PORT={port} npm start 2>/dev/null || "
            f"node server.js 2>/dev/null || node index.js 2>/dev/null || {{ {target_start_failed}; }}"
        )
    elif language == "java" and app_type in ("web-app", "api-service", "unknown"):
        # Java web apps: find WAR/JAR and run with embedded Tomcat/Jetty/Spring Boot
        cmd = _json_shell_cmd(
            f"JAR=$(find /app -name '*.jar' -path '*/target/*' ! -name '*-sources*' ! -name '*-tests*' | head -1); "
            f"WAR=$(find /app -name '*.war' -path '*/target/*' | head -1); "
            f"if [ -n \"$JAR\" ]; then java -jar \"$JAR\" --server.port={port} 2>/dev/null || "
            f"java -Dserver.port={port} -jar \"$JAR\" 2>/dev/null; "
            f"elif [ -n \"$WAR\" ]; then java -jar \"$WAR\" --server.port={port} 2>/dev/null; "
            f"else {target_start_failed}; fi"
        )
    elif language == "c/cpp" and app_type in ("web-app", "api-service", "unknown"):
        cmd = _json_shell_cmd(target_start_failed)
    elif language == "rust" and app_type in ("web-app", "api-service", "unknown"):
        cmd = _json_shell_cmd(
            f"export PATH=/root/.cargo/bin:$HOME/.cargo/bin:$PATH; "
            f"cargo run --release -- --port {port} 2>/dev/null || {{ {target_start_failed}; }}"
        )
    elif language == "elixir" and app_type in ("web-app", "api-service", "unknown"):
        cmd = _json_shell_cmd(
            f"mix phx.server 2>/dev/null || mix run --no-halt 2>/dev/null || {{ {target_start_failed}; }}"
        )
    elif language in ("go",) and app_type in ("web-app", "api-service", "unknown"):
        cmd = _json_shell_cmd(
            f"/app/app --port {port} 2>/dev/null || /app/app 2>/dev/null || {{ {target_start_failed}; }}"
        )
    elif language == "php" and app_type in ("web-app", "api-service", "unknown"):
        cmd = _json_shell_cmd(
            f"php -S 0.0.0.0:{port} -t /app/public 2>/dev/null || "
            f"php -S 0.0.0.0:{port} -t /app 2>/dev/null || {{ {target_start_failed}; }}"
        )
    elif language in ("csharp", "dotnet") and app_type in ("web-app", "api-service", "unknown"):
        cmd = _json_shell_cmd(
            f"export PATH=$PATH:/root/.dotnet:$HOME/.dotnet; "
            f"dotnet run --urls http://0.0.0.0:{port} 2>/dev/null || {{ {target_start_failed}; }}"
        )
    else:
        cmd = _json_shell_cmd(target_start_failed) if app_type in ("web-app", "api-service", "unknown") else f"CMD {fallback}\n"

    return (
        f"{install}"
        f"ENV LOTUS_LAB_PORT={port}\n"
        f"EXPOSE {port}\n"
        f"{cmd}"
    )


def _write_repo_dockerfile(dest: Path, language: str, port: int, app_type: str = 'unknown', ai_dockerfile: str = None) -> Path:
    """Generate a per-repo Dockerfile from docs/manifests (or AI if provided).

    This is the fallback path used when the repo does not ship a Dockerfile/compose
    (or that file failed to build). Install steps are required to succeed. A
    planning/generation failure is deliberately terminal for the generated lab:
    a generic HTTP listener is not evidence that the enrolled target runs.
    """
    dockerfile_path = dest / "Dockerfile.lotus"

    requires_target_runtime = str(app_type or "unknown").lower() in {
        "web-app", "api-service", "unknown",
    }
    if ai_dockerfile and "FROM" in ai_dockerfile and "RUN" in ai_dockerfile:
        content = ai_dockerfile
        if requires_target_runtime and re.search(r"\bpython(?:3)?\s+-m\s+http\.server\b", content, re.I):
            raise GeneratedLabPlanError(
                "AI-generated service Dockerfile uses a synthetic static listener; target runtime remains unproven"
            )
        if f"EXPOSE {port}" not in content and "EXPOSE" not in content:
            content += f"\nEXPOSE {port}\n"
    else:
        try:
            from backend.lab_builder import analyze_repo_requirements, generate_dockerfile_from_requirements
            reqs = analyze_repo_requirements(dest, language, app_type)
            plan_path = Path(dest) / ".lotus" / "audit_plan.json"
            if plan_path.is_file():
                try:
                    from backend.audit_planner import apply_plan_to_requirements
                    reqs = apply_plan_to_requirements(reqs, json.loads(plan_path.read_text(encoding="utf-8")))
                except Exception:
                    pass
            content = generate_dockerfile_from_requirements(reqs, port)
        except Exception as exc:
            raise GeneratedLabPlanError(
                f"could not construct a deterministic target lab plan: {exc}"
            ) from exc

    dockerfile_path.write_text(content, encoding="utf-8")
    return dockerfile_path


def _health_wrapper_dockerfile(from_image: str, port: int) -> str:
    """Keep a repo-built image alive on the Lotus lab port for health checks / HTTP probes."""
    return (
        f"FROM {from_image}\n"
        "USER root\n"
        "RUN command -v python3 >/dev/null 2>&1 || "
        "(apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 "
        "&& rm -rf /var/lib/apt/lists/*)\n"
        f"ENV LOTUS_LAB_PORT={port}\n"
        f"EXPOSE {port}\n"
        f'CMD ["sh", "-c", "python3 -m http.server {port} --bind 0.0.0.0"]\n'
    )


async def _clean_container(name: str):
    """Remove a named container if it exists."""
    if not shutil.which("docker"):
        return
    await _run_cmd(["docker", "rm", "-f", name], timeout=20)


async def _clean_network(name: str):
    """Remove an internal bridge network if it exists."""
    if not shutil.which("docker"):
        return
    # Ignore errors; network may not exist
    await _run_cmd(["docker", "network", "rm", name], timeout=20)


async def _prune_orphan_lab_networks(keep: str = "") -> int:
    """Compatibility no-op: empty networks do not establish orphan ownership.

    Another Lotus instance may have reserved an empty network before starting
    its container. Only explicit maintenance with durable audit identities can
    authorize cleanup; a prefix, repository label, or attachment count cannot.
    """
    return 0


async def reap_orphan_labs() -> Dict[str, int]:
    """Preserve every runtime at startup, including legacy opt-in installations.

    Startup has no authority to classify a kept/active lab from another process
    as abandoned. Retain the historical zero-count response for callers, and
    direct old configurations to explicit ownership-checked Reset maintenance.
    """
    if os.environ.get("LOTUS_REAP_ORPHAN_LABS", "").strip().lower() in ("1", "true", "yes", "on"):
        logging.getLogger(__name__).warning(
            "LOTUS_REAP_ORPHAN_LABS is diagnostic-only; startup preserves existing labs and networks. "
            "Use Debug Reset in single-instance maintenance mode for ownership-checked cleanup."
        )
    return {"networks": 0, "containers": 0}


async def _ensure_internal_network(name: str, send=None, repo_id: int = 0) -> bool:
    """Create a bridge network for the lab container.

    We use a regular bridge (not --internal) for generated labs because Docker's
    --internal flag blocks host publishing on supported runtimes.  The pipeline
    cuts egress after every dynamic operation; Compose gets a managed internal
    network override from the start.

    Address-pool exhaustion is reported without pruning other runtime networks.
    """
    if not shutil.which("docker"):
        return False
    out, rc = await _run_cmd(["docker", "network", "ls", "--format", "{{.Name}}"], timeout=20)
    if rc == 0 and name in out.splitlines():
        return True
    create_cmd = ["docker", "network", "create"]
    if repo_id:
        create_cmd.extend(["--label", f"lotus.audit.repo_id={int(repo_id)}"])
        run_id = str((_LAB_STATE.get(repo_id) or {}).get("lab_run_id") or "")
        if run_id:
            create_cmd.extend(["--label", f"lotus.audit.run_id={run_id}"])
    create_cmd.append(name)
    out, rc = await _run_cmd(create_cmd, timeout=20)
    if rc == 0:
        return True
    if send:
        await send(repo_id, "Lab network creation failed: " + str(out)[-300:] +
                   ". Use ownership-checked Debug Reset during maintenance if old audit resources need cleanup.", level="warning")
    return False


async def _free_lab_port(port: int, send, repo_id: int):
    """Report port conflicts without deleting a different audit's container."""
    out, rc = await _run_cmd(
        ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Ports}}"],
        timeout=20,
    )
    if rc != 0 or not out:
        return
    keep = {"lotus-ollama", "lotus-control-plane"}
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, ports = line.split("\t", 1)
        if name in keep or not name.startswith("lotus"):
            continue
        if f":{port}->" in ports or f":{port}/" in ports:
            await send(repo_id, f"Lab port {port} is occupied by {name}; resolve the owned runtime through maintenance before retrying", level="warning")


def _audit_image_build_labels(repo_id: int) -> list[str]:
    """Label only audit-specific images using the run's captured source identity.

    The shared common base never calls this helper. Missing identity leaves an
    image unowned for reset; a tag alone must never authorize deletion.
    """
    state = _LAB_STATE.get(repo_id) or {}
    run_id, tree = state.get("lab_run_id"), state.get("target_tree_hash")
    if (type(repo_id) is not int or repo_id <= 0 or not isinstance(run_id, str)
            or not 0 < len(run_id) <= 128 or not isinstance(tree, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", tree)):
        return []
    labels = {"lotus.audit.repo_id": str(repo_id), "lotus.audit.run_id": run_id,
              "lotus.audit.target_tree_hash": tree, "lotus.audit.generated_image": "true",
              "lotus.audit.image_purpose": "audit-lab"}
    return [argument for key, value in labels.items() for argument in ("--label", key + "=" + value)]


async def _build_and_run_default_lab(
    repo_id: int,
    dest: Path,
    language: str,
    send,
    app_type: str = 'unknown',
) -> Dict[str, Any]:
    """Build a per-repo image from the reusable base and run it on an isolated network."""
    base = await _ensure_base_image(send, repo_id)
    if not base:
        return {
            "status": "base-image-missing",
            "healthy": False,
            "url": None,
            "logs": "Lotus lab base image could not be built or found",
        }

    slug = get_audit_slug(repo_id)
    port = 3000 + (repo_id * 10)
    name = f"lotus-{slug}"
    net_name = f"lotus-net-{slug}"
    image = f"lotus-{slug}:run"
    build_timeout = _build_timeout_for_target(dest)

    await _clean_container(name)
    await _clean_network(net_name)
    if not await _ensure_internal_network(net_name, send, repo_id):
        return {
            "status": "network-create-failed",
            "healthy": False,
            "url": None,
            "logs": "Could not create internal lab network",
        }

    await send(repo_id, "Generating lab Dockerfile from repository docs, manifests, and build files", level="info")
    try:
        _harden_build_context(dest)
    except Exception as e:
        await _clean_network(net_name)
        return {"status": "policy-rejected", "healthy": False, "url": None, "logs": str(e)[:2000]}
    try:
        dockerfile_path = _write_repo_dockerfile(dest, language, port, app_type, ai_dockerfile=None)
    except GeneratedLabPlanError as exc:
        await send(repo_id, f"Generated lab plan is not proof-eligible: {exc}", level="warning")
        await _clean_network(net_name)
        return {
            "status": "target-runtime-unproven",
            "healthy": False,
            "target_runtime_verified": False,
            "proof_eligible": False,
            "url": None,
            "logs": str(exc)[:2000],
        }
    from backend.lab_builder import ComposePolicyError, validate_dockerfile_for_lab
    try:
        validate_dockerfile_for_lab(dockerfile_path, root=dest)
    except ComposePolicyError as e:
        await _clean_network(net_name)
        return {"status": "policy-rejected", "healthy": False, "url": None, "logs": str(e)[:2000]}
    await send(
        repo_id,
        f"Building isolated lab image {image} (network allowed for package install; timeout {build_timeout}s)",
        level="info",
    )
    out, rc = await _run_cmd(
        ["docker", "build", *_audit_image_build_labels(repo_id), "-t", image, "-f", str(dockerfile_path.relative_to(dest)), "."],
        cwd=dest,
        timeout=build_timeout,
        env=_controlled_child_env({"DOCKER_BUILDKIT": "1"}),
    )
    if rc != 0:
        tail = "\n".join((out or "").strip().splitlines()[-24:])[:1800]
        await send(repo_id, "Generated Dockerfile failed to build — trying AI-assisted lab Dockerfile", level="warning")
        if tail:
            await send(repo_id, f"Build error: {tail}", level="warning")
        ai_dockerfile = None
        try:
            from backend.lab_analyzer import build_lab_analysis_prompt, parse_dockerfile_from_ai
            from backend.main import call_ai_result, Settings as _SettingsModel, LOCAL_PROVIDERS
            from backend.main import get_db as _get_db
            _db = _get_db()
            _settings = _db.query(_SettingsModel).first()
            _db.close()
            _provider = (_settings.ai_provider or "") if _settings else ""
            _is_local = _provider in LOCAL_PROVIDERS
            _has_creds = _is_local or (_settings and _settings.ai_api_key)
            if _settings and _has_creds and _provider not in ("", "none"):
                prompt = build_lab_analysis_prompt(dest, language, port)
                import asyncio as _aio
                from backend.ai_gateway import AITask as _AITask
                ai_resp = await _aio.to_thread(
                    call_ai_result, prompt, _settings, 60, task=_AITask.LAB_BUILD,
                )
                from backend.lab_adapters import require_complete_response
                from backend.ai_gateway import AIStatus
                if ai_resp and ai_resp.status == AIStatus.OK and not (ai_resp.meta or {}).get("mock") and not (ai_resp.meta or {}).get("simulated"):
                    require_complete_response(ai_resp)
                    parsed = parse_dockerfile_from_ai(ai_resp.text, port)
                    if parsed and "RUN" in parsed:
                        ai_dockerfile = (
                            f"FROM {LAB_BASE_IMAGE}\nUSER root\nWORKDIR /app\nCOPY . /app\n"
                            f"{parsed}\nUSER lotus\n"
                        )
        except Exception as e:
            await send(repo_id, f"AI lab analysis failed ({str(e)[:50]})", level="warning")
        if ai_dockerfile:
            try:
                dockerfile_path = _write_repo_dockerfile(
                    dest, language, port, app_type, ai_dockerfile=ai_dockerfile,
                )
            except GeneratedLabPlanError as exc:
                await send(repo_id, f"AI lab plan is not proof-eligible: {exc}", level="warning")
                await _clean_network(net_name)
                return {
                    "status": "target-runtime-unproven",
                    "healthy": False,
                    "target_runtime_verified": False,
                    "proof_eligible": False,
                    "url": None,
                    "logs": str(exc)[:2000],
                }
            try:
                validate_dockerfile_for_lab(dockerfile_path, root=dest)
            except ComposePolicyError as e:
                await _clean_network(net_name)
                return {"status": "policy-rejected", "healthy": False, "url": None, "logs": str(e)[:2000]}
            out, rc = await _run_cmd(
                ["docker", "build", *_audit_image_build_labels(repo_id), "-t", image, "-f", str(dockerfile_path.relative_to(dest)), "."],
                cwd=dest,
                timeout=build_timeout,
                env=_controlled_child_env({"DOCKER_BUILDKIT": "1"}),
            )
        if rc != 0:
            # Retry the same deterministic/AI-derived build for transient
            # registry or resource failures. Never replace a failed target
            # build with a tolerant file server: that would turn unavailable
            # runtime evidence into a false healthy lab.
            max_retries, backoff = build_retry_policy()
            for attempt in range(1, max_retries + 1):
                delay = backoff * (2 ** (attempt - 1)) if backoff else 0
                await _notify_build(
                    repo_id, send,
                    f"Lab build failed — retry {attempt}/{max_retries}"
                    + (f" in {delay}s" if delay else ""),
                    level="warning",
                )
                if delay:
                    await asyncio.sleep(delay)
                out, rc = await _run_cmd(
                    ["docker", "build", *_audit_image_build_labels(repo_id), "-t", image, "-f", str(dockerfile_path.relative_to(dest)), "."],
                    cwd=dest,
                    timeout=build_timeout,
                    env=_controlled_child_env({"DOCKER_BUILDKIT": "1"}),
                )
                if rc == 0:
                    await _notify_build(
                        repo_id, send,
                        f"Lab build recovered on retry {attempt}/{max_retries}",
                        level="success",
                    )
                    break
        if rc != 0:
            await send(
                repo_id,
                f"Lab image build failed (exit {rc}); target runtime is unproven and no synthetic fallback was started",
                level="error",
            )
            await _clean_network(net_name)
            return {
                "status": "build-failed",
                "healthy": False,
                "target_runtime_verified": False,
                "proof_eligible": False,
                "url": None,
                "logs": out[:2000],
                "build_timeout_seconds": build_timeout,
            }
    await send(repo_id, f"Lab image {image} built successfully", level="info")

    await send(repo_id, f"Starting isolated lab container {name} on {net_name}", level="info")
    await _free_lab_port(port, send, repo_id)
    out, rc = await _run_cmd(
        ["docker", "run", "-d", "--name", name, "--network", net_name]
        + hardened_runtime_args(repo_id)
        + ["-p", f"127.0.0.1:{port}:{port}", image],
        timeout=30,
    )
    if rc != 0:
        logs = await _docker_log_tail(name)
        err = (out or logs or "").strip()[-800:]
        await send(repo_id, f"Lab container failed to start (exit {rc}){(': ' + err) if err else ''}", level="error")
        await _clean_container(name)
        await _clean_network(net_name)
        return {
            "status": "run-failed",
            "healthy": False,
            "url": None,
            "logs": logs[:2000],
        }

    await send(repo_id, f"Waiting for lab to become healthy on port {port}...", level="info")
    healthy = await _wait_for_port("127.0.0.1", port)
    if not healthy:
        logs = await _docker_log_tail(name)
        await send(repo_id, f"Lab did not become healthy within {HEALTH_TIMEOUT}s", level="warning")
        await _clean_container(name)
        await _clean_network(net_name)
        return {
            "status": "unhealthy",
            "healthy": False,
            "url": None,
            "logs": logs[:2000],
        }
    await send(
        repo_id,
        f"Lab port is reachable at http://127.0.0.1:{port}; target runtime smoke is still required before proof qualification",
        level="success",
    )
    register_lab_container(
        repo_id, name, lab_kind="generated", net_name=net_name, dest=str(dest),
        url=f"http://127.0.0.1:{port}", port=port,
    )

    return {
        "status": "running",
        "healthy": True,
        "url": f"http://127.0.0.1:{port}",
        "logs": out[:500] + "\n...\nContainer started and health-checked.",
        "lab_kind": "generated",
        "container": name,
        "application_surface": "runtime-only" if app_type in ("cli-tool", "library") else "http",
        "health_semantics": (
            "container-port-only; target is not an HTTP service"
            if app_type in ("cli-tool", "library") else "container-port-open; target runtime smoke pending"
        ),
        # A TCP connect verifies only that something listens. The pipeline's
        # revision-bound smoke gate is the authority for proof eligibility.
        "target_runtime_verified": False,
        "proof_eligible": False,
        "build_timeout_seconds": build_timeout,
    }


async def _wait_for_lab_http(url: str, timeout: int) -> bool:
    """Try common health/API paths until any HTTP response is received."""
    paths = (
        "/",
        "/health",
        "/openmrs/health/alive",
        "/openmrs",
        "/v1/shell/exec",
        "/v1/sandbox",
    )
    remaining = timeout
    for path in paths:
        slice_t = max(15, remaining // max(1, len(paths) - paths.index(path)))
        if await _wait_for_http(url, timeout=min(slice_t, remaining), path=path):
            return True
        remaining = max(0, remaining - slice_t)
        if remaining <= 0:
            break
    return False


async def _compose_app_container(project: str) -> Optional[str]:
    """Pick the non-database compose service container for PoC exec."""
    out, rc = await _run_cmd(
        ["docker", "compose", "-p", project, "ps", "--format", "{{.Name}} {{.Service}}"],
        timeout=20,
    )
    if rc != 0 or not out.strip():
        return None
    skip = {"db", "mysql", "mariadb", "postgres", "redis", "es", "elasticsearch", "grafana"}
    names: List[str] = []
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        svc = parts[1].lower() if len(parts) > 1 else ""
        names.append(name)
        if svc not in skip and "db" not in svc:
            return name
    return names[0] if names else None


async def _run_user_lab(
    repo_id: int,
    dest: Path,
    port: int,
    send,
    dockerfile: Optional[Path] = None,
    compose: Optional[Path] = None,
) -> Dict[str, Any]:
    """Build/run a repo-provided Dockerfile or docker-compose, still on an isolated network."""
    slug = get_audit_slug(repo_id)
    name = f"lotus-{slug}"
    net_name = f"lotus-net-{slug}"
    project = f"lotus{repo_id}"
    build_timeout = _build_timeout_for_target(dest)
    await _clean_container(name)
    await _clean_network(net_name)

    if not await _ensure_internal_network(net_name, send, repo_id):
        return {"status": "network-create-failed", "healthy": False, "url": None, "logs": "network create failed"}

    out = ""
    used_compose = False
    synthetic_health_wrapper = False

    if compose is not None and Path(compose).exists():
        used_compose = True
        try:
            _harden_build_context(dest)
        except Exception as e:
            await _clean_network(net_name)
            return {"status": "policy-rejected", "healthy": False, "url": None, "logs": str(e)[:2000]}
        rel = compose.name
        await send(repo_id, f"Using the repository's {rel} to start the lab on port {port}", level="info")
        env = _controlled_child_env({
            "HOST_PORT": str(port),
            "COMPOSE_PROJECT_NAME": project,
        })
        compose_text = ""
        try:
            compose_text = Path(compose).read_text(errors="ignore")[:8000]
        except Exception:
            pass
        if re.search(r"^\s+build:", compose_text, re.M) and (os.environ.get("LOTUS_ALLOW_REPO_DOCKERFILE") or "").strip().lower() not in ("1", "true", "yes", "on"):
            await send(repo_id, "Compose source builds are disabled by default because repository Dockerfiles execute in the host Docker daemon; set LOTUS_ALLOW_REPO_DOCKERFILE=1 only for a disposable trusted runner", level="warning")
            await _clean_network(net_name)
            return {"status": "policy-rejected", "healthy": False, "url": None, "logs": "repository Dockerfile build requires explicit opt-in"}

        from backend.lab_builder import ComposePolicyError, rewrite_compose_for_lab
        lotus_compose = dest / ".lotus-compose.yml"
        native_ports = []
        try:
            tr = dest / ".lotus" / "phase1_trace.json"
            if tr.is_file():
                native_ports = list((json.loads(tr.read_text()).get("trace") or {}).get("ports") or [])
        except Exception:
            native_ports = []
        if not native_ports:
            # Common broker/DB listen ports when compose forgets to publish them
            native_ports = [30114, 2881, 3306]
        try:
            rewrite_compose_for_lab(Path(compose), lotus_compose, port, slug, native_ports=native_ports)
            compose_file = lotus_compose
        except ComposePolicyError as e:
            await send(repo_id, f"Compose rejected by untrusted-lab policy: {e}", level="error")
            await _clean_network(net_name)
            return {"status": "policy-rejected", "healthy": False, "url": None, "logs": str(e)[:2000]}
        except Exception as e:
            # Never pass the repository's original file through after a rewrite
            # failure: that would silently bypass port and policy enforcement.
            await send(repo_id, f"Could not safely remap compose ports ({e})", level="error")
            await _clean_network(net_name)
            return {"status": "policy-rejected", "healthy": False, "url": None, "logs": f"compose rewrite failed: {e}"[:2000]}

        # Apply a Lotus-owned runtime override after validating/re-writing the
        # repository file.  This is what makes Compose services receive the same
        # read-only, non-root, cap-drop and resource controls as docker run.
        try:
            from backend.lab_builder import validate_compose_for_lab, write_compose_hardening_override
            validated = validate_compose_for_lab(Path(compose), root=dest)
            hardening = write_compose_hardening_override(
                dest, validated["services"], networks=validated.get("networks"),
                repo_id=repo_id, run_id=str((_LAB_STATE.get(repo_id) or {}).get("lab_run_id") or ""),
                target_revision=str((_LAB_STATE.get(repo_id) or {}).get("target_revision") or ""),
                target_tree_hash=str((_LAB_STATE.get(repo_id) or {}).get("target_tree_hash") or ""),
                lab_kind="compose", compose_project=project,
            )
        except ComposePolicyError as e:
            await send(repo_id, f"Compose hardening rejected: {e}", level="error")
            await _clean_network(net_name)
            return {"status": "policy-rejected", "healthy": False, "url": None, "logs": str(e)[:2000]}
        compose_cmd = ["docker", "compose", "-f", str(compose_file.resolve()), "-f", str(hardening.resolve())]
        if "agent-infra/sandbox" in compose_text or "SANDBOX_SRV_PORT" in compose_text:
            env["WAIT_PORTS"] = os.environ.get("LOTUS_SANDBOX_WAIT_PORTS", "8091")
            override = dest / ".lotus-compose.override.yml"
            try:
                override.write_text(
                    "services:\n"
                    "  sandbox:\n"
                    "    environment:\n"
                    f"      WAIT_PORTS: \"{env['WAIT_PORTS']}\"\n",
                    encoding="utf-8",
                )
                compose_cmd.extend(["-f", str(override.resolve())])
                await send(
                    repo_id,
                    f"Sandbox compose override WAIT_PORTS={env['WAIT_PORTS']}",
                    level="info",
                )
            except Exception as e:
                await send(repo_id, f"Could not write compose override: {e}", level="warning")

        has_build = bool(re.search(r"^\s+build:", compose_text, re.M))
        has_image = bool(re.search(r"^\s+image:", compose_text, re.M))
        compose_cmd.extend(["-p", project, "up", "-d", "--pull", "missing"])
        if has_build and not has_image:
            compose_cmd.append("--build")
            await send(repo_id, "Compose has no published image — building from enrolled source", level="info")

        await _free_lab_port(port, send, repo_id)
        out, rc = await _run_cmd(compose_cmd, cwd=dest, timeout=COMPOSE_TIMEOUT, env=env)
        if rc != 0 and has_build:
            await send(repo_id, "Source build via compose failed; retrying with the published image", level="warning")
            retry = [c for c in compose_cmd if c != "--build"]
            out, rc = await _run_cmd(retry, cwd=dest, timeout=COMPOSE_TIMEOUT, env=env)
        if rc != 0:
            await _clean_network(net_name)
            return {"status": "compose-failed", "healthy": False, "url": None, "logs": out[:2000]}
        await asyncio.sleep(3)
        app_name = await _compose_app_container(project)
        if app_name:
            name = app_name
        register_lab_container(
            repo_id, name, lab_kind="compose", compose_project=project,
            compose_file=str(compose_file), compose_hardening=str(hardening),
            dest=str(dest), net_name=net_name,
        )
        try:
            _clim = lab_limits()
            await _run_cmd(
                ["docker", "update", "--memory", _clim["memory"],
                 "--pids-limit", _clim["pids"], "--cpus", _clim["cpus"], name],
                timeout=30,
            )
            await send(
                repo_id,
                f"Applied lab resource caps to compose service ({_clim['memory']}, {_clim['cpus']} cpus, pids={_clim['pids']})",
                level="info",
            )
        except Exception as cap_err:
            await send(repo_id, f"Could not apply compose resource caps: {cap_err}", level="warning")

    elif dockerfile is not None and Path(dockerfile).exists():
        if (os.environ.get("LOTUS_ALLOW_REPO_DOCKERFILE") or "").strip().lower() not in ("1", "true", "yes", "on"):
            await send(repo_id, "Repository Dockerfile execution is disabled by default; generating a Lotus-owned lab image instead", level="warning")
            await _clean_network(net_name)
            return {"status": "policy-rejected", "healthy": False, "url": None, "logs": "repository Dockerfile requires explicit opt-in"}
        from backend.lab_builder import ComposePolicyError, dockerfile_needs_health_wrapper, validate_dockerfile_for_lab
        try:
            validate_dockerfile_for_lab(Path(dockerfile), root=dest)
        except ComposePolicyError as e:
            await send(repo_id, f"Dockerfile rejected by untrusted-lab policy: {e}", level="error")
            await _clean_network(net_name)
            return {"status": "policy-rejected", "healthy": False, "url": None, "logs": str(e)[:2000]}
        try:
            _harden_build_context(dest)
        except Exception as e:
            await _clean_network(net_name)
            return {"status": "policy-rejected", "healthy": False, "url": None, "logs": str(e)[:2000]}
        try:
            rel = str(Path(dockerfile).resolve().relative_to(Path(dest).resolve()))
        except ValueError:
            rel = Path(dockerfile).name
        await send(repo_id, f"Using the repository's Dockerfile ({rel}) to build the lab", level="info")
        image = f"lotus-{slug}:user"
        df_flag = str(Path(dockerfile).resolve())
        env = _controlled_child_env({"DOCKER_BUILDKIT": "1"})
        out, rc = await _run_cmd(
            ["docker", "build", *_audit_image_build_labels(repo_id), "-t", image, "-f", df_flag, "."],
            cwd=dest,
            timeout=USER_DOCKERFILE_TIMEOUT,
            env=env,
        )
        if rc != 0:
            await _clean_network(net_name)
            return {"status": "build-failed", "healthy": False, "url": None, "logs": out[:2000]}

        run_image = image
        if dockerfile_needs_health_wrapper(Path(dockerfile)):
            await send(
                repo_id,
                "Repo Dockerfile has no long-running service — wrapping it with a health-check server",
                level="info",
            )
            wrap_path = dest / "Dockerfile.lotus"
            wrap_path.write_text(_health_wrapper_dockerfile(image, port))
            wrap_image = f"lotus-{slug}:run"
            wout, wrc = await _run_cmd(
                ["docker", "build", *_audit_image_build_labels(repo_id), "-t", wrap_image, "-f", "Dockerfile.lotus", "."],
                cwd=dest,
                timeout=build_timeout,
                env=_controlled_child_env({"DOCKER_BUILDKIT": "1"}),
            )
            if wrc == 0:
                run_image = wrap_image
                synthetic_health_wrapper = True
            else:
                # The original image was explicitly classified as lacking a
                # long-running service.  Starting it after its wrapper failed
                # merely burns the health timeout and can produce a misleading
                # port-only result if a child process happens to listen. Fail
                # this provider attempt closed so ``run_lab`` can choose the
                # generated/AI path and retain the actionable build log.
                await send(repo_id, f"Health wrapper build failed: {wout[:500]}", level="warning")
                await _clean_network(net_name)
                return {
                    "status": "health-wrapper-failed",
                    "healthy": False,
                    "url": None,
                    "logs": (wout or "health wrapper build failed")[:2000],
                    "image": image,
                    "wrapper_image": wrap_image,
                    "wrapper_exit_code": wrc,
                    "execution_scope": "repository-dockerfile",
                }

        await _free_lab_port(port, send, repo_id)
        # Apply the same resource caps as the generated path so a heavy/hostile repo
        # Dockerfile can't starve the host (previously only the generated lab was capped).
        _, rc = await _run_cmd(
            ["docker", "run", "-d", "--name", name, "--network", net_name]
            + hardened_runtime_args(repo_id)
            + ["-p", f"127.0.0.1:{port}:{port}", run_image],
            timeout=30,
        )
        if rc != 0:
            logs = await _docker_log_tail(name)
            await _clean_container(name)
            await _clean_network(net_name)
            return {"status": "run-failed", "healthy": False, "url": None, "logs": logs[:2000]}
        register_lab_container(repo_id, name, lab_kind="user-dockerfile", net_name=net_name, dest=str(dest))

    else:
        await _clean_network(net_name)
        return {
            "status": "no-user-lab",
            "healthy": False,
            "url": None,
            "logs": "no compose/Dockerfile provided",
        }

    url = f"http://127.0.0.1:{port}"
    register_lab_container(repo_id, name, url=url, port=port, dest=str(dest))
    # Native brokers/DBs never speak HTTP on the listen port. TCP is the health gate.
    healthy = await _wait_for_port("127.0.0.1", port, timeout=max(HEALTH_TIMEOUT, 120))
    http_ok = False
    if healthy:
        http_ok = await _wait_for_lab_http(url, timeout=8)
    if not healthy:
        logs = await _docker_log_tail(name) if not used_compose else (out or "")[:2000]
        if not used_compose:
            await _clean_container(name)
            await _clean_network(net_name)
        else:
            try:
                await _run_cmd(
                    ["docker", "compose", "-f", str(compose_file.resolve()), "-p", project, "down", "-v"],
                    cwd=dest, timeout=120, env=env,
                )
            except Exception:
                pass
            await _clean_network(net_name)
        return {"status": "unhealthy", "healthy": False, "url": None, "logs": logs[:2000],
                "host": "127.0.0.1", "port": port}
    proto = "http" if http_ok else "tcp"
    if synthetic_health_wrapper:
        await send(
            repo_id,
            "Repository image is reachable only through a synthetic health wrapper; target runtime smoke is required before any proof claim",
            level="warning",
        )
    else:
        await send(
            repo_id,
            f"Lab port is reachable at {proto}://127.0.0.1:{port} (using repo {'compose' if used_compose else 'Dockerfile'}); target runtime smoke is still required before proof qualification",
            level="success",
        )
    return {
        "status": "running",
        "healthy": True,
        "url": url if http_ok else f"tcp://127.0.0.1:{port}",
        "host": "127.0.0.1",
        "port": port,
        "published_port": port,
        "logs": (out or "")[:500],
        "lab_kind": "compose" if used_compose else "user-dockerfile",
        "container": name,
        "health_semantics": (
            "synthetic-wrapper-port-only; target runtime smoke pending"
            if synthetic_health_wrapper else "container-port-open; target runtime smoke pending"
        ),
        "target_runtime_verified": False,
        "proof_eligible": False,
    }


async def run_dynamic_recon(
    repo_id: int,
    dest: Path,
    lab_status: Dict[str, Any],
    language: str,
    send,
    app_type: str = 'unknown',
) -> tuple:
    """Run lightweight dynamic probes and data-flow traces against the lab.

    Returns (findings, dynamic_summary). The summary records which endpoints
    responded and which tracing tools (httpx, strace, tcpdump) were available.
    """
    if not lab_status or not lab_status.get("healthy"):
        status = lab_status.get("status", "unknown") if lab_status else "unknown"
        await send(repo_id, f"Lab not healthy ({status}); dynamic Phase 1 recon skipped", level="warning")
        return [], {
            "status": "skipped",
            "reason": f"isolated lab unavailable ({status}); dynamic recon was not executed",
            "probed": False,
            "endpoints": [],
            "traces": [],
            "logs": lab_status.get("logs", "") if lab_status else "",
            "tools": {},
        }

    # Kubernetes native CLI discovery uses exact recorded Pod execution, not
    # Docker discovery or shell-expanded test payloads on the controller.
    if app_type in ('cli-tool', 'library') and (
            lab_status.get("provider") == "k8s-job" or get_lab_state(repo_id).get("provider") == "k8s-job"):
        from backend.k8s_cli_recon import discover
        return await discover(repo_id, dest, lab_status, send)

    url = lab_status.get("url", "")
    if not url:
        await send(repo_id, "Lab has no URL; dynamic Phase 1 recon skipped", level="warning")
        return [], {
            "status": "skipped",
            "reason": "lab did not expose a probe URL; dynamic HTTP recon was not applicable",
            "probed": False, "endpoints": [], "traces": [], "logs": "", "tools": {},
        }

    findings: List[Dict[str, Any]] = []
    endpoints = []
    traces = []
    tools: Dict[str, bool] = {"httpx": True}
    errors: List[Dict[str, str]] = []
    status = "completed"
    reason = "dynamic recon completed"

    if app_type in ('cli-tool', 'library'):
        await send(repo_id, f"Dynamic Phase 1 recon skipping HTTP probes for {app_type}; running runtime/package testing instead")
        try:
            name = get_lab_container(repo_id)
            if not name:
                raise RuntimeError("lab container identity is unavailable")
            out, rc = await _run_cmd(["docker", "exec", name, "sh", "-c", "find /app -type f -executable -not -path '*/\\.*' -not -path '*/node_modules/*' -not -name '*.pyc' | head -1"], timeout=10)
            entrypoint = out.strip()
            if not entrypoint:
                out, rc = await _run_cmd(["docker", "exec", name, "sh", "-c", "ls -1 /app/bin/* /app/__main__.py /app/console_scripts 2>/dev/null | head -1"], timeout=10)
                entrypoint = out.strip()
                
            if entrypoint:
                await send(repo_id, f"Found CLI entry point: {entrypoint}, testing with payload variants", level="info")
                endpoints.append({"path": entrypoint, "status": "executable", "size": 0})
                
                # Test --help/--version
                for arg in ["--help", "--version"]:
                    await _run_cmd(["docker", "exec", name, "sh", "-c", f"{entrypoint} {arg}"], timeout=10)
                
                # Malicious inputs  - only promote with concrete oracle + lab_evidence
                for payload in ["$(id)", "`id`", "'; id; '", "../../../../etc/passwd", "A"*1000]:
                    out, rc = await _run_cmd(
                        ["docker", "exec", name, "sh", "-c", f"{entrypoint} {payload}"],
                        timeout=10,
                    )
                    argv = [entrypoint, payload]
                    uid_hit = bool(re.search(r"uid=\d+", out or ""))
                    passwd_hit = bool(re.search(r"root:.*:0:0:", out or ""))
                    if uid_hit or passwd_hit:
                        findings.append({
                            "tool": "dynamic-recon",
                            "title": f"CLI injection proven via {entrypoint} {payload!r}",
                            "cvss": 9.0,
                            "description": (
                                f"docker-exec PoC: {entrypoint} with payload {payload!r} "
                                f"produced oracle output (exit {rc})."
                            ),
                            "file": entrypoint,
                            "line": 0,
                            "confidence": "high",
                            "qualification": "QUALIFIED",
                            "conviction_level": 3,
                            "proven_in_lab": True,
                            "lab_evidence": [{
                                "path": "docker-exec",
                                "params": {"argv": argv},
                                "argv": argv,
                                "status": rc,
                                "snippet": (out or "")[:160],
                                "anomaly_type": "command_injection" if uid_hit else "path_traversal",
                                "method": "exec",
                            }],
                            "poc": {"command": " ".join(argv), "argv": argv},
                            "poc_result": "triggered",
                        })
                    elif rc == 139:  # segfault  - signal only, not report-eligible without oracle
                        findings.append({
                            "tool": "dynamic-recon",
                            "title": f"CLI crash (SIGSEGV) with payload {payload!r}",
                            "cvss": 5.0,
                            "description": (
                                f"Executing {entrypoint} with {payload!r} segfaulted (exit 139). "
                                f"Unproven until a reliable PoC/oracle is attached."
                            ),
                            "file": entrypoint,
                            "line": 0,
                            "confidence": "medium",
                            "qualification": "QUALIFIED",
                            "conviction_level": 1,
                        })
        except Exception as e:
            errors.append({"scope": "cli", "error": str(e)[:500]})
            await send(repo_id, f"CLI dynamic recon failed: {e}", level="warning")
        if not endpoints:
            if app_type == "library":
                status = "skipped"
                reason = "no executable entry point discovered; HTTP dynamic recon is not applicable to a library"
            else:
                status = "failed"
                reason = "no executable entry point discovered; CLI runtime recon could not execute"
        elif errors:
            status = "failed"
            reason = f"CLI dynamic recon completed with {len(errors)} error(s)"
        else:
            reason = f"CLI runtime recon completed; {len(endpoints)} executable surface(s) tested"
    else:
        await send(repo_id, f"Dynamic Phase 1 recon probing {url}")
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
                for path in ["/", "/health", "/api/v2/storefront/products", "/api/v2/storefront/taxons", "/products", "/admin"]:
                    try:
                        r = await client.get(f"{url}{path}")
                        endpoints.append({"path": path, "status": r.status_code, "size": len(r.text)})
                        findings.append({
                            "tool": "dynamic-recon",
                            "title": f"Lab endpoint {path} returned HTTP {r.status_code}",
                            "cvss": 0.0,
                            "description": f"GET {url}{path} returned HTTP {r.status_code} ({len(r.text)} bytes). Used for reachability baseline.",
                            "file": "lab",
                            "line": 0,
                            "confidence": "info",
                        })
                    except Exception as e:
                        errors.append({"scope": path, "error": str(e)[:500]})
        except Exception as e:
            await send(repo_id, f"httpx dynamic recon failed: {e}", level="warning")
            tools["httpx"] = False
            errors.append({"scope": "httpx", "error": str(e)[:500]})
        if not tools.get("httpx"):
            status = "failed"
            reason = "httpx was unavailable; HTTP dynamic recon was not executed"
        elif not endpoints and errors:
            status = "failed"
            reason = f"all HTTP dynamic recon probes failed ({len(errors)} error(s))"
        elif errors:
            reason = f"dynamic recon completed with {len(errors)} probe error(s); {len(endpoints)} endpoint(s) responded"
        else:
            reason = f"dynamic recon completed; {len(endpoints)} endpoint(s) responded"

    if shutil.which("docker"):
        name = get_lab_container(repo_id)
        # strace is pre-installed in the base image
        trace_proc = None
        try:
            trace_proc = await asyncio.create_subprocess_exec(
                "docker", "exec", name, "sh", "-c",
                "pgrep -f 'puma|unicorn|thin|webrick|rails|python|node|go|http.server' | head -1 > /tmp/lotus_target.pid; "
                "PID=$(cat /tmp/lotus_target.pid); "
                "[ -n \"$PID\" ] && timeout 4 strace -f -p $PID -e trace=network,file,process,openat,read,write -o /tmp/lotus_strace.log 2>/dev/null; "
                "cat /tmp/lotus_strace.log 2>/dev/null | tail -60",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_controlled_child_env(),
            )
            out, _ = await asyncio.wait_for(trace_proc.communicate(), timeout=20)
            trace_out = out.decode(errors="ignore")
            if trace_out:
                traces.append({"tool": "strace", "output": trace_out[:2000]})
                tools["strace"] = True
        except asyncio.CancelledError:
            await terminate_and_reap(trace_proc)
            raise
        except asyncio.TimeoutError:
            await terminate_and_reap(trace_proc)
            tools["strace"] = False
        except Exception:
            await terminate_and_reap(trace_proc)
            tools["strace"] = False

    return findings, {
        "status": status,
        "reason": reason,
        "probed": True,
        "endpoints": endpoints,
        "traces": traces,
        "logs": "",
        "tools": tools,
        "errors": errors[:50],
    }


async def disconnect_lab_network(repo_id: int, send=None):
    """Finalize the recorded audit network without claiming general isolation.

    A successful Docker operation detaches only the named audit network. Other
    attachments and live egress are not inspected here. Kubernetes/Compose keep
    their configured network policy; absence of a runtime requires no action.
    """
    state = _LAB_STATE.get(repo_id) or {}
    name = str(state.get("container") or state.get("pod") or "").strip()
    result = {"schema_version": 1, "repo_id": int(repo_id),
              "provider": str(state.get("provider") or "unknown"),
              "egress_verified": False, "network_disconnected": False}
    if not name:
        return {**result, "status": "not-required", "action": "none",
                "reason": "No owned lab runtime is registered; no network action was attempted"}
    result["container"] = name
    if state.get("provider") == "k8s-job":
        return {**result, "status": "policy-managed", "action": "none",
                "reason": "Kubernetes network policy remains managed by the lab provider; live egress was not independently verified here"}
    if state.get("lab_kind") == "compose":
        return {**result, "status": "policy-managed", "action": "none",
                "reason": "Compose network configuration is retained; live network attachments and egress were not independently verified here"}
    if state.get("provider") not in (None, "", "docker"):
        return {**result, "status": "failed", "action": "none", "failure_kind": "unsupported-provider",
                "reason": "The recorded lab provider does not support this network finalization action"}
    net_name = str(state.get("net_name") or "").strip()
    if not net_name:
        return {**result, "status": "failed", "action": "none", "failure_kind": "missing-network",
                "reason": "No audit network is recorded for this lab; no network name was guessed"}
    result.update(provider="docker", network=net_name)
    if not shutil.which("docker"):
        return {**result, "status": "failed", "action": "none", "failure_kind": "missing-cli",
                "reason": "The Docker CLI is unavailable; the recorded audit network was not disconnected"}
    try:
        _output, rc = await _run_cmd(
            ["docker", "network", "disconnect", "-f", net_name, name], timeout=15)
    except Exception as error:
        return {**result, "status": "failed", "action": "disconnect-audit-network",
                "error_type": type(error).__name__,
                "reason": "The recorded audit-network disconnect failed; live egress remains unverified"}
    if type(rc) is not int:
        return {**result, "status": "failed", "action": "disconnect-audit-network",
                "failure_kind": "invalid-exit-code",
                "reason": "The audit-network disconnect returned no valid process exit code; live egress remains unverified"}
    if rc != 0:
        return {**result, "status": "failed", "action": "disconnect-audit-network", "exit_code": rc,
                "reason": "Docker did not disconnect the recorded audit network; live egress remains unverified"}
    return {**result, "status": "audit-network-disconnected", "action": "disconnect-audit-network",
            "exit_code": 0, "network_disconnected": True,
            "reason": "Docker disconnected the recorded audit network; other network attachments and live egress were not verified"}


async def inspect_lab(repo_id: int) -> Dict[str, Any]:
    """Live look-in: container, URL, port, health, keep flag."""
    state = dict(_LAB_STATE.get(repo_id) or {})
    name = str(state.get("container") or "")
    running = False
    if state.get("provider") == "k8s-job":
        try:
            from backend import k8s_lab
            pod_doc, rc, raw = await k8s_lab.get_json("pod", name, timeout=20)
            if rc == 0 and pod_doc:
                phase = str((pod_doc.get("status") or {}).get("phase") or "")
                running = phase == "Running"
            return {
                "repo_id": repo_id, "container": name or None, "pod": name or None,
                "running": running, "url": state.get("url"), "port": state.get("port"),
                "kind": state.get("lab_kind") or "k8s-job", "provider": "k8s-job",
                "job_name": state.get("job_name"), "service_name": state.get("service_name"),
                "namespace": state.get("namespace"), "pod_uid": state.get("pod_uid"),
                "keep": bool(state.get("keep")), "error": "" if rc == 0 else raw[-500:],
                "slug": _AUDIT_SLUGS.get(repo_id),
                "state": {k: v for k, v in state.items() if k != "inspect"},
            }
        except Exception as exc:
            return {"repo_id": repo_id, "container": name or None, "running": False, "provider": "k8s-job", "error": str(exc)[:300]}
    if name and shutil.which("docker"):
        out, rc = await _run_cmd(
            ["docker", "inspect", "-f", "{{.State.Running}}", name], timeout=10,
        )
        running = rc == 0 and "true" in (out or "").lower()
    port = state.get("port")
    url = state.get("url") or (f"http://127.0.0.1:{port}" if port else None)
    return {
        "repo_id": repo_id,
        "container": name or None,
        "provider": state.get("provider") or "docker",
        "running": running,
        "status": "running" if running else "stopped",
        "url": url,
        "port": port,
        "kind": state.get("lab_kind"),
        "keep": bool(state.get("keep")),
        "slug": _AUDIT_SLUGS.get(repo_id),
        "state": {k: v for k, v in state.items() if k != "inspect"},
    }


async def lab_logs(repo_id: int, tail: int = 200) -> Dict[str, Any]:
    name = get_lab_container(repo_id)
    if not name:
        return {"container": None, "running": False, "logs": ""}
    state = _LAB_STATE.get(repo_id) or {}
    if state.get("provider") == "k8s-job":
        try:
            from backend import k8s_lab
            out, rc = await k8s_lab._run(["logs", name, "-n", str(state.get("namespace") or k8s_lab.namespace()), "--tail", str(max(20, min(int(tail or 200), 2000)))], timeout=30)
            info = await inspect_lab(repo_id)
            return {"container": name, "pod": name, "running": bool(info.get("running")), "logs": out or "", "provider": "k8s-job", "exit_code": rc}
        except Exception as exc:
            return {"container": name, "pod": name, "running": False, "logs": str(exc)[:500], "provider": "k8s-job", "exit_code": -1}
    logs = await _docker_log_tail(name, lines=max(20, min(int(tail or 200), 2000)))
    info = await inspect_lab(repo_id)
    return {"container": name, "running": bool(info.get("running")), "logs": logs or ""}


def set_keep_lab(repo_id: int, keep: bool = True) -> Dict[str, Any]:
    state = _LAB_STATE.setdefault(repo_id, {})
    state["keep"] = bool(keep)
    return {"repo_id": repo_id, "keep": bool(keep), "container": state.get("container")}


async def list_labs() -> Dict[str, Any]:
    """List active local lab pods/containers across both providers.

    The in-process registry is supplemented with a Kubernetes label query so
    operators can find pods after an API restart.  Docker remains best-effort
    because the daemon may be intentionally unavailable in a network profile.
    """
    rows: List[Dict[str, Any]] = []
    from backend.lab_provider import provider_name
    try:
        _active_provider = provider_name()
    except ValueError as exc:
        return {"labs": [{"provider": "invalid", "running": False, "error": str(exc)}], "count": 1, "providers": ["invalid"]}
    _inventory_all = os.environ.get("LOTUS_LAB_INVENTORY_ALL_PROVIDERS", "").strip().lower() in ("1", "true", "yes", "on")
    for repo_id, state in list(_LAB_STATE.items()):
        try:
            item = await inspect_lab(int(repo_id))
        except Exception as exc:
            item = {"repo_id": int(repo_id), "provider": state.get("provider", "docker"), "running": False, "error": str(exc)[:240]}
        rows.append(item)
    # Docker inventory is queried by the same stable label used for orphan
    # cleanup.  This makes stopped/running containers discoverable after an API
    # restart instead of relying on the process-local registry.  ``inspect`` is
    # deliberately per-container and bounded so a noisy daemon cannot consume
    # unbounded memory or latency.
    try:
        # Avoid probing an unrelated daemon on every dashboard refresh.  In a
        # Docker deployment the in-process rows plus Docker label query are
        # authoritative; in a Kubernetes deployment the pod query is.  Set
        # LOTUS_LAB_INVENTORY_ALL_PROVIDERS=1 for an operator intentionally
        # running both backends on one host.
        _docker_inventory = _inventory_all or _active_provider == "docker"
        if _docker_inventory and shutil.which("docker"):
            out, rc = await _run_cmd(
                ["docker", "ps", "-a", "--filter", "label=lotus.audit.repo_id", "--format", "{{.Names}}"],
                timeout=8,
            )
            if rc == 0:
                known = {str(r.get("container") or r.get("pod") or "") for r in rows}
                for cname in [v.strip() for v in out.splitlines() if v.strip()][:500]:
                    if cname in known:
                        continue
                    raw, irc = await _run_cmd(["docker", "inspect", cname], timeout=15)
                    if irc != 0:
                        rows.append({"provider": "docker", "container": cname, "running": False, "error": raw[-500:]})
                        continue
                    try:
                        doc = json.loads(raw)
                        info = (doc[0] if isinstance(doc, list) and doc else {})
                    except Exception:
                        info = {}
                    labels = ((info.get("Config") or {}).get("Labels") or {}) if isinstance(info, dict) else {}
                    state = (info.get("State") or {}) if isinstance(info, dict) else {}
                    config = (info.get("Config") or {}) if isinstance(info, dict) else {}
                    try:
                        rid = int(labels.get("lotus.audit.repo_id"))
                    except (TypeError, ValueError):
                        rid = None
                    network_settings = (info.get("NetworkSettings") or {}) if isinstance(info, dict) else {}
                    networks = network_settings.get("Networks") or {}
                    network_name = next(iter(networks or {}), None)
                    # Recover a useful loopback URL when a process restart
                    # erased the in-memory registry.  Port bindings are
                    # metadata only; the lab remains reachable through the
                    # same explicitly published loopback port.
                    discovered_port = None
                    for bindings in (network_settings.get("Ports") or {}).values():
                        if not isinstance(bindings, list):
                            continue
                        for binding in bindings:
                            if isinstance(binding, dict) and str(binding.get("HostPort") or "").isdigit():
                                discovered_port = int(binding["HostPort"])
                                break
                        if discovered_port is not None:
                            break
                    compose_project = str(labels.get("com.docker.compose.project") or labels.get("lotus.audit.compose_project") or "")
                    discovered_kind = str(labels.get("lotus.audit.lab_kind") or ("compose" if compose_project else "discovered"))
                    rows.append({
                        "repo_id": rid, "provider": "docker", "container": cname,
                        "running": bool(state.get("Running")), "status": state.get("Status"),
                        "image": config.get("Image"), "image_digest": info.get("Image"),
                        "network": network_name, "net_name": network_name,
                        "run_id": labels.get("lotus.audit.run_id"),
                        "target_revision": labels.get("lotus.audit.target_revision"),
                        "target_tree_hash": labels.get("lotus.audit.target_tree_hash"),
                        "port": discovered_port,
                        "url": f"http://127.0.0.1:{discovered_port}" if discovered_port else None,
                        "lab_kind": discovered_kind,
                        "compose_project": compose_project or None,
                        "orphaned": rid is None,
                    })
                    # Hydrate the same registry used by logs/exec/teardown.
                    # Listing is intentionally the recovery boundary after an
                    # API restart; without this, a dashboard row would be
                    # visible but every interaction would report “no lab”.
                    if rid is not None and rid not in _LAB_STATE:
                        register_lab_container(
                            rid, cname, provider="docker", lab_kind=discovered_kind,
                            net_name=network_name or "", compose_project=compose_project,
                            lab_run_id=str(labels.get("lotus.audit.run_id") or ""),
                            target_revision=str(labels.get("lotus.audit.target_revision") or ""),
                            target_tree_hash=str(labels.get("lotus.audit.target_tree_hash") or ""),
                            url=f"http://127.0.0.1:{discovered_port}" if discovered_port else None,
                            port=discovered_port,
                        )
    except Exception as exc:
        rows.append({"provider": "docker", "running": False, "error": str(exc)[:300]})
    try:
        from backend import k8s_lab
        _k8s_inventory = _inventory_all or _active_provider == "k8s-job"
        if _k8s_inventory and shutil.which(k8s_lab.kubectl_binary()):
            doc, rc, raw = await k8s_lab.get_json("pods", selector="role=lab-container", timeout=8)
            if rc == 0:
                known = {str(r.get("pod") or r.get("container") or "") for r in rows}
                for pod in doc.get("items") or []:
                    meta = pod.get("metadata") or {}
                    status = pod.get("status") or {}
                    pod_name = str(meta.get("name") or "")
                    if not pod_name or pod_name in known:
                        continue
                    labels = meta.get("labels") or {}
                    try:
                        rid = int(labels.get("lotus.io/repo-id"))
                    except (TypeError, ValueError):
                        rid = None
                    annotations = meta.get("annotations") or {}
                    job_name = str(labels.get("job-name") or labels.get("lotus.io/job") or "")
                    pod_namespace = str(meta.get("namespace") or k8s_lab.namespace())
                    service_name = f"{job_name}-svc" if job_name else ""
                    service_port = None
                    if service_name:
                        # Recover the ClusterIP service port as well as the pod
                        # identity.  Without this lookup a post-restart row was
                        # visible but its PoC/HTTP controls had no usable URL.
                        try:
                            service_doc, service_rc, _service_raw = await k8s_lab.get_json(
                                "service", service_name, timeout=8,
                            )
                            if service_rc == 0:
                                service_ports = ((service_doc.get("spec") or {}).get("ports") or [])
                                if service_ports and isinstance(service_ports[0], dict):
                                    candidate_port = service_ports[0].get("port")
                                    if str(candidate_port).isdigit():
                                        service_port = int(candidate_port)
                        except Exception:
                            service_port = None
                    service_url = (
                        f"http://{service_name}.{pod_namespace}.svc.cluster.local:{service_port}"
                        if service_name and service_port else None
                    )
                    rows.append({
                        "repo_id": rid, "provider": "k8s-job", "pod": pod_name,
                        "container": pod_name, "running": str(status.get("phase") or "") == "Running",
                        "phase": status.get("phase"), "pod_uid": meta.get("uid"),
                        "job_name": job_name,
                        "service_name": service_name or None, "port": service_port, "url": service_url,
                        "namespace": pod_namespace,
                        "target_revision": annotations.get("lotus.io/target-revision"),
                        "target_tree": annotations.get("lotus.io/target-tree"),
                        "target_tree_hash": annotations.get("lotus.io/target-tree-hash"),
                        "orphaned": rid is None,
                    })
                    if rid is not None and rid not in _LAB_STATE:
                        register_lab_container(
                            rid, pod_name, provider="k8s-job", lab_kind="k8s-job",
                            job_name=job_name, service_name=service_name,
                            namespace=pod_namespace, pod_uid=str(meta.get("uid") or ""),
                            port=service_port, url=service_url,
                            target_revision=str(annotations.get("lotus.io/target-revision") or ""),
                            target_tree=str(annotations.get("lotus.io/target-tree") or ""),
                            target_tree_hash=str(annotations.get("lotus.io/target-tree-hash") or ""),
                        )
            elif raw:
                rows.append({"provider": "k8s-job", "running": False, "error": raw[-500:]})
        elif _k8s_inventory:
            rows.append({"provider": "k8s-job", "running": False, "error": "Configured Kubernetes provider requires kubectl; Docker inventory was not substituted."})
    except Exception as exc:
        rows.append({"provider": "k8s-job", "running": False, "error": str(exc)[:300]})
    return {"labs": rows, "count": len(rows), "providers": sorted({str(r.get("provider") or "unknown") for r in rows})}


async def teardown_lab(repo_id: int, force: bool = False, *, expected_context=None, expected_state=None):
    """Remove the lab container and its internal network after scan completion."""
    from copy import deepcopy
    registered = _LAB_STATE.get(repo_id)
    state = deepcopy(registered or {})
    def assert_owner():
        if _LAB_STATE.get(repo_id) is not registered or (_LAB_STATE.get(repo_id) or {}) != state:
            raise RuntimeError("Lab runtime changed during cleanup; replacement retained")
    if expected_state is not None and state != expected_state:
        raise RuntimeError("Lab runtime changed before cleanup; replacement retained")
    if expected_context is not None:
        from backend.report_context import require_runtime_binding
        require_runtime_binding(expected_context, state)
    if not state:
        return {"status": "stopped"}
    if state.get("keep") and not force:
        return {"status": "kept"}
    if state.get("provider") == "k8s-job":
        from backend import k8s_lab
        deleted = await k8s_lab.delete(str(state.get("job_name") or ""), str(state.get("service_name") or ""),
                                      expected_state={**state, "repo_id": repo_id}, assert_owner=assert_owner)
        if deleted.get("errors"):
            raise RuntimeError("; ".join(deleted["errors"]))
        assert_owner()
        _AUDIT_SLUGS.pop(repo_id, None)
        _LAB_STATE.pop(repo_id, None)
        return {"status": "stopped"}
    errors = []

    async def remove(command, *, cwd=None, env=None):
        assert_owner()
        output, rc = await _run_cmd(command, cwd=cwd, timeout=60, env=env)
        # Keep recoverable state for failed removals, so Dashboard can retry.
        absent = any(message in str(output).lower() for message in (
            "no such container", "no such network", "network not found",
        ))
        if rc != 0 and not absent:
            errors.append(str(output)[-500:] or f"{command[:3]} exited {rc}")
    if expected_context is not None:
        # A historical notebook may never address a Docker name/project that
        # can be replaced while inspection is pending. Stop its exact IDs only.
        from backend.reset_runtime_ownership import _docker_inspect, _check_labels
        if state.get("lab_kind") == "compose" or state.get("compose_project"):
            raise RuntimeError("Notebook Compose cleanup requires a complete immutable resource inventory; use owned maintenance cleanup")
        binding = expected_context.get("binding") or {}
        expected = binding.get("lab") or {}
        record = {**state, "repo_id": repo_id, "scan_job_id": binding.get("scan_job_id")}
        container = await _docker_inspect("container", expected.get("container_id") or state.get("container_id") or state["container"])
        network = await _docker_inspect("network", state.get("network_id") or state.get("net_name")) if state.get("net_name") else None
        if container:
            _check_labels((container.get("Config") or {}).get("Labels") or {}, record)
            if expected.get("container_id") and container["Id"] != expected["container_id"]:
                raise RuntimeError("Notebook Docker container identity changed; replacement retained")
        if network:
            _check_labels(network.get("Labels") or {}, record, source=False)
            if set((network.get("Containers") or {})) - ({container["Id"]} if container else set()):
                raise RuntimeError("Notebook Docker network has unrelated containers; cleanup refused")
        if container:
            await remove(["docker", "rm", "-f", container["Id"]])
        if network:
            await remove(["docker", "network", "rm", network["Id"]])
        if errors:
            raise RuntimeError("Lab teardown incomplete: " + "; ".join(errors))
        assert_owner()
        _AUDIT_SLUGS.pop(repo_id, None)
        _LAB_STATE.pop(repo_id, None)
        return {"status": "stopped"}
    if state.get("lab_kind") == "compose" and state.get("compose_project") and state.get("compose_file") and Path(str(state.get("compose_file"))).exists():
        cmd = ["docker", "compose", "-p", state["compose_project"]]
        cmd.extend(["-f", state["compose_file"]])
        if state.get("compose_hardening"):
            cmd.extend(["-f", state["compose_hardening"]])
        cmd.extend(["down", "-v", "--remove-orphans"])
        await remove(cmd, cwd=Path(state["dest"]) if state.get("dest") else None,
                     env=_controlled_child_env())
    elif state.get("lab_kind") == "compose" and state.get("compose_project") and shutil.which("docker"):
        # After an API restart the source checkout and generated override may
        # no longer exist.  Remove only Compose containers carrying Lotus's
        # stable repo/project labels; never run ``compose down`` in an
        # arbitrary current working directory.
        project = str(state.get("compose_project"))
        repo_filter = f"lotus.audit.repo_id={int(repo_id)}"
        out, rc = await _run_cmd(
            ["docker", "ps", "-aq", "--filter", f"label={repo_filter}",
             "--filter", f"label=com.docker.compose.project={project}"], timeout=20,
        )
        if rc == 0:
            for container_id in [v.strip() for v in out.splitlines() if v.strip()][:100]:
                await remove(["docker", "rm", "-f", container_id])
        else:
            errors.append(str(out)[-500:] or "Compose inventory failed during teardown")
    name = state.get("container")
    net_name = state.get("net_name")
    if name:
        await remove(["docker", "rm", "-f", name])
    if net_name:
        await remove(["docker", "network", "rm", net_name])
    if errors:
        raise RuntimeError("Lab teardown incomplete: " + "; ".join(errors))
    assert_owner()
    _AUDIT_SLUGS.pop(repo_id, None)
    _LAB_STATE.pop(repo_id, None)
    return {"status": "stopped"}


def _bounded_exec_command(command: str, timeout: int, pidfile: str) -> str:
    """Bound the process inside the lab, not merely the Docker/kubectl client."""
    return (
        "command -v timeout >/dev/null 2>&1 || { printf 'Lab execution requires the timeout utility' >&2; exit 125; }; "
        f"timeout -k 2 {max(1, int(timeout))} sh -c {shlex.quote(command)} & "
        f"lotus_exec_pid=$!; printf '%s' \"$lotus_exec_pid\" > {shlex.quote(pidfile)}; "
        f"wait \"$lotus_exec_pid\"; lotus_exec_rc=$?; rm -f {shlex.quote(pidfile)}; exit \"$lotus_exec_rc\""
    )


async def _stop_lab_execution(container: str, pidfile: str, *, namespace: str = "") -> None:
    # The random execution token scopes cleanup to one command. Killing the
    # client alone leaves its remote process running after Cancel or timeout.
    cleanup = (f"if test -f {shlex.quote(pidfile)}; then "
               f"read lotus_exec_pid < {shlex.quote(pidfile)}; "
               "case \"$lotus_exec_pid\" in ''|*[!0-9]*) exit 1;; esac; "
               "kill -TERM \"$lotus_exec_pid\" 2>/dev/null || true; "
               f"rm -f {shlex.quote(pidfile)}; fi")
    if namespace:
        from backend import k8s_lab
        await k8s_lab._run(["exec", "-n", namespace, container, "-c", "lab", "--", "sh", "-c", cleanup], timeout=5)
    else:
        await _run_cmd(["docker", "exec", container, "sh", "-c", cleanup], timeout=5, env=_controlled_child_env())


async def exec_in_lab(repo_id: int, command: str, timeout: int = 30, *, expected_context=None) -> Dict[str, Any]:
    """Execute a command inside the running lab container via docker exec.

    This is the core PoC execution mechanism. Phase 2 uses this to:
    - Run crafted inputs against the target (e.g., php -r 'yaml_parse(...)')
    - Check for crashes, error output, unexpected behavior
    - Validate findings with concrete proof

    Returns: {success: bool, stdout: str, stderr: str, exit_code: int}
    """
    container = get_lab_container(repo_id)
    if not container:
        return {
            "success": False,
            "stdout": "",
            "stderr": "No lab container running. Launch Isolated Lab Pod first.",
            "exit_code": -1,
        }
    state = dict(_LAB_STATE.get(repo_id) or {})
    bound_runtime = None
    if expected_context is not None:
        from backend.notebook_lab import resolve_runtime, guard_command
        bound_runtime = await resolve_runtime(repo_id, expected_context, state)
        container = bound_runtime["container"]
        command = guard_command(command, bound_runtime)

    async def check_after_execution():
        if bound_runtime is not None:
            current = await resolve_runtime(repo_id, expected_context, get_lab_state(repo_id))
            if current != bound_runtime:
                raise ValueError("Notebook runtime changed during execution; its result cannot be bound to this report.")
    pidfile = f"/tmp/.lotus-exec-{uuid.uuid4().hex}.pid"
    bounded_command = _bounded_exec_command(command, timeout, pidfile)
    if state.get("provider") == "k8s-job":
        try:
            from backend import k8s_lab
            ns = str(state.get("namespace") or k8s_lab.namespace())
            out, rc = await k8s_lab._run(
                ["exec", "-n", ns, container, "-c", "lab", "--", "sh", "-c", bounded_command],
                timeout=max(1, int(timeout)) + 3,
            )
            # kubectl combines stdout/stderr for this path; preserve a bounded
            # transcript and the exact command for the durable evidence log.
            await check_after_execution()
            result = {"success": rc == 0, "stdout": out[:4000] if rc == 0 else "", "stderr": out[:2000] if rc != 0 else "", "exit_code": rc, "provider": "k8s-job", "pod": container,
                      "output_truncated": len(out) > (4000 if rc == 0 else 2000)}
            try:
                from backend.pipeline import record_command
                record_command(repo_id, ["kubectl", "exec", "-n", ns, container, "-c", "lab", "--", "sh", "-c", command], rc=rc, stdout=result["stdout"], stderr=result["stderr"], phase="lab-exec", name="lab-exec")
            except Exception:
                pass
            return result
        except asyncio.CancelledError:
            await _stop_lab_execution(container, pidfile, namespace=ns)
            raise
        except Exception as exc:
            error = str(exc)[:500]
            try:
                from backend.pipeline import record_command
                record_command(
                    repo_id,
                    ["kubectl", "exec", "-n", ns, container, "-c", "lab", "--", "sh", "-c", command],
                    rc=-1, stderr=error, phase="lab-exec", name="lab-exec",
                )
            except Exception:
                pass
            return {"success": False, "stdout": "", "stderr": error, "exit_code": -1, "provider": "k8s-job", "pod": container}
    if not shutil.which("docker"):
        return {"success": False, "stdout": "", "stderr": "docker not available", "exit_code": -1}

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", container, "sh", "-c", bounded_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_controlled_child_env(),
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=max(1, int(timeout)) + 3)
        await check_after_execution()
        decoded_stdout, decoded_stderr = stdout.decode(errors="ignore"), stderr.decode(errors="ignore")
        result = {
            "success": proc.returncode == 0,
            "stdout": decoded_stdout[:4000],
            "stderr": decoded_stderr[:2000],
            "exit_code": proc.returncode,
            "output_truncated": len(decoded_stdout) > 4000 or len(decoded_stderr) > 2000,
        }
        try:
            from backend.pipeline import record_command
            record_command(
                repo_id,
                ["docker", "exec", container, "sh", "-c", command],
                cwd="",
                rc=proc.returncode,
                stdout=result["stdout"],
                stderr=result["stderr"],
                phase="lab-exec",
                name="lab-exec",
            )
        except Exception:
            pass
        return result
    except asyncio.CancelledError:
        await terminate_and_reap(proc)
        await _stop_lab_execution(container, pidfile)
        raise
    except asyncio.TimeoutError:
        await terminate_and_reap(proc)
        await _stop_lab_execution(container, pidfile)
        error = f"timed out after {timeout}s"
        try:
            from backend.pipeline import record_command
            record_command(repo_id, ["docker", "exec", container, "sh", "-c", command], rc=-1, stderr=error, phase="lab-exec", name="lab-exec")
        except Exception:
            pass
        return {"success": False, "stdout": "", "stderr": error, "exit_code": -1}
    except Exception as e:
        await terminate_and_reap(proc)
        error = str(e)[:200]
        try:
            from backend.pipeline import record_command
            record_command(repo_id, ["docker", "exec", container, "sh", "-c", command], rc=-1, stderr=error, phase="lab-exec", name="lab-exec")
        except Exception:
            pass
        return {"success": False, "stdout": "", "stderr": error, "exit_code": -1}


async def run_poc_in_lab(
    repo_id: int,
    poc_commands: list,
    send=None,
    finding_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run a sequence of PoC commands in the lab and collect evidence.

    Each command is executed in order. If any command produces evidence of
    a vulnerability (crash, unexpected output, error), it's captured as
    investigative evidence.  Only a signed receipt can pass report gates.

    Returns: {triggered: bool, evidence: list, output: str}
    """
    evidence = []
    all_output = []

    for cmd in poc_commands:
        if send:
            await send(repo_id, f"  PoC exec: {cmd[:80]}...", level="info")
        result = await exec_in_lab(repo_id, cmd, timeout=15)
        all_output.append(f"$ {cmd}\n{result['stdout']}{result['stderr']}")

        # Detect vulnerability indicators (RCE/deser/auth/injection prioritized)
        combined = result["stdout"] + result["stderr"]
        # Running a canary directly in the lab proves only that docker exec
        # works, not that the target reached a dangerous sink.  Require the
        # canary to be produced by a non-trivial target-driving command.
        normalized_cmd = str(cmd).strip().lower()
        direct_canary = bool(re.fullmatch(r"(?:/usr/bin/|/bin/)?id(?:\s+-[a-z]+)?(?:\s*[;&|]+\s*)?", normalized_cmd))
        direct_canary = direct_canary or bool(re.fullmatch(r"(?:sh|bash)\s+-c\s+['\"]?(?:/usr/bin/|/bin/)?id(?:\s+-[a-z]+)?['\"]?", normalized_cmd))
        direct_canary = direct_canary or bool(re.fullmatch(r"(?:cat|head|tail)\s+(?:-n\s+\d+\s+)?/etc/passwd(?:\s*[;&|]+\s*)?", normalized_cmd))
        if re.search(r"\b(?:python3?|ruby|node|php)\s+-(?:c|e|r)\b", normalized_cmd) and re.search(r"\bid\b", normalized_cmd):
            target_file = str((finding_context or {}).get("file") or "").lower()
            # Inline interpreter snippets that contain the canary but never
            # reference the enrolled target are analog demonstrations, not a
            # proof that the target reached its sink.
            direct_canary = direct_canary or not (target_file and Path(target_file).name.lower() in normalized_cmd)
        indicators = {
            "command_execution": (not direct_canary) and "uid=" in result["stdout"] and "gid=" in result["stdout"],
            "code_execution": (not direct_canary) and result["exit_code"] == 0 and "uid=" in combined,
            "crash": result["exit_code"] in (-6, -11, 134, 139),  # SIGABRT, SIGSEGV
            "asan_hit": "AddressSanitizer" in result["stderr"] or "ERROR: AddressSanitizer" in result["stderr"],
            "ubsan_hit": "UndefinedBehaviorSanitizer" in result["stderr"],
            "segfault": "Segmentation fault" in result["stderr"] or result["exit_code"] == 139,
            "auth_bypass": (not direct_canary) and ("uid=0" in result["stdout"] or "root:" in result["stdout"]),
            "info_leak": (not direct_canary) and ("root:x:0" in result["stdout"] or "daemon:" in result["stdout"]),
            "deserialization_rce": (not direct_canary) and "uid=" in combined and any(x in cmd for x in ("pickle", "yaml", "marshal", "unserialize")),
            "prototype_pollution": "true" in result["stdout"] and "polluted" in cmd,
            "path_traversal": (not direct_canary) and ("root:x:" in result["stdout"] or "/bin/" in result["stdout"]),
        }

        triggered = any(indicators.values())
        if triggered:
            anomaly_type = next(k for k, v in indicators.items() if v)
            evidence.append({
                "command": cmd,
                "snippet": (result["stdout"] + result["stderr"])[:500],
                "anomaly_type": anomaly_type,
                "exit_code": result["exit_code"],
                "path": cmd.split()[0] if cmd else "unknown",
            })

    result: Dict[str, Any] = {
        "triggered": bool(evidence),
        "evidence": evidence,
        "output": "\n---\n".join(all_output)[:4000],
    }
    # Raw command output is intentionally not proof.  A receipt is only issued
    # when the caller supplied a baseline and finding context and the daemon
    # identities/source digest can be collected.  Missing signing configuration
    # therefore degrades to an unproven candidate.
    if evidence and finding_context and finding_context.get("proof_baseline"):
        try:
            from backend.proof_receipts import issue_receipt
            identity = await lab_attestation(repo_id)
            output_hash = "sha256:" + hashlib.sha256(result["output"].encode("utf-8")).hexdigest()
            evidence_hash = "sha256:" + hashlib.sha256(json.dumps(evidence, sort_keys=True).encode("utf-8")).hexdigest()
            receipt = issue_receipt(
                audit_id=str(repo_id),
                finding=finding_context,
                target_revision=identity.get("target_revision", ""),
                target_tree_hash=identity.get("target_tree_hash", ""),
                lab_run_id=identity.get("lab_run_id", ""),
                container_id=identity.get("container_id", ""),
                image_digest=identity.get("image_digest", ""),
                network_id=identity.get("network_id", ""),
                command_argv=["sh", "-c", "\n".join(str(c) for c in poc_commands)],
                request=finding_context.get("poc") if isinstance(finding_context.get("poc"), dict) else None,
                baseline=finding_context.get("proof_baseline"),
                observed={"evidence": evidence, "output_hash": output_hash},
                oracle_kind=str(evidence[0].get("anomaly_type") or "unknown"),
                artifact_hashes=[output_hash, evidence_hash],
            )
            if receipt:
                result["proof_receipt"] = receipt
        except Exception:
            # Never turn a receipt-generation failure into a confirmation.
            pass
    return result


async def _run_published_image_lab(
    repo_id: int, dest: Path, host_port: int, send, spec: Dict[str, Any],
) -> Dict[str, Any]:
    """Pull a README-documented image (e.g. oceanbase/seekdb) and publish its native port."""
    image = spec.get("image") or ""
    cport = int(spec.get("container_port") or 0) or 2881
    if not image:
        return {"status": "no-image", "healthy": False, "url": None, "logs": "no image"}
    slug = get_audit_slug(repo_id)
    name = f"lotus-{slug}"
    net_name = f"lotus-net-{slug}"
    await _clean_container(name)
    await _clean_network(net_name)
    if not await _ensure_internal_network(net_name, send, repo_id):
        return {"status": "network-create-failed", "healthy": False, "url": None, "logs": "network create failed"}
    platform = spec.get("platform") or ""
    await send(repo_id, f"Pulling published lab image {image} (native port {cport})", level="info")
    await _free_lab_port(host_port, send, repo_id)
    pull_cmd = ["docker", "pull"]
    if platform:
        pull_cmd.extend(["--platform", platform])
    pull_cmd.append(image)
    pull_out, pull_rc = await _run_cmd(pull_cmd, timeout=COMPOSE_TIMEOUT, env=_controlled_child_env())
    if pull_rc != 0 and platform:
        # Retry un-pinned in case the host already matches the image arch.
        pull_out, pull_rc = await _run_cmd(["docker", "pull", image], timeout=COMPOSE_TIMEOUT, env=_controlled_child_env())
    if pull_rc != 0:
        await _clean_network(net_name)
        return {"status": "pull-failed", "healthy": False, "url": None, "logs": pull_out[:1500]}
    run_cmd = [
        "docker", "run", "-d", "--name", name, "--network", net_name,
    ] + hardened_runtime_args(repo_id) + ["-p", f"127.0.0.1:{host_port}:{cport}"]
    if platform:
        run_cmd.extend(["--platform", platform])
    hostname = spec.get("hostname")
    if hostname:
        run_cmd.extend(["-h", str(hostname)])
    for vol in spec.get("volumes") or []:
        src_raw = vol.get("src") or vol.get("source") or ""
        dst = vol.get("dst") or vol.get("destination") or ""
        if not src_raw or not dst:
            continue
        src = Path(src_raw)
        if not src.is_absolute():
            src = Path(dest) / src_raw
        try:
            src_resolved = src.resolve()
            dest_resolved = Path(dest).resolve()
            if src_resolved != dest_resolved and dest_resolved not in src_resolved.parents:
                await send(repo_id, f"Published-image host mount rejected outside enrolled source: {src_raw}", level="warning")
                continue
        except Exception:
            continue
        if not src_resolved.exists() or "docker.sock" in str(src_resolved):
            continue
        mode = "ro" if vol.get("readonly") or vol.get("ro") else "rw"
        # Even source-relative mounts are immutable by default; a published
        # image README must not gain a writable host path as a side effect.
        mode = "ro"
        run_cmd.extend(["-v", f"{src_resolved}:{dst}:{mode}"])
    run_cmd.append(image)
    extra_cmd = spec.get("command")
    if extra_cmd:
        run_cmd.extend(extra_cmd if isinstance(extra_cmd, list) else [str(extra_cmd)])
    out, rc = await _run_cmd(run_cmd, timeout=60)
    if rc != 0:
        await _clean_container(name)
        await _clean_network(net_name)
        return {"status": "run-failed", "healthy": False, "url": None, "logs": (out or "")[:1500]}
    register_lab_container(
        repo_id, name, lab_kind="published-image", net_name=net_name, image=image,
        dest=str(dest), url=f"tcp://127.0.0.1:{host_port}", port=host_port,
    )
    # DB bootstrap (seekdb/OceanBase) can take minutes.
    healthy = await _wait_for_port("127.0.0.1", host_port, timeout=180)
    if not healthy:
        logs = await _docker_log_tail(name)
        await _clean_container(name)
        await _clean_network(net_name)
        return {"status": "unhealthy", "healthy": False, "url": None, "logs": logs[:2000]}
    await send(repo_id, f"Lab healthy at tcp://127.0.0.1:{host_port} ({image})", level="success")
    return {
        "status": "running",
        "healthy": True,
        "url": f"tcp://127.0.0.1:{host_port}",
        "host": "127.0.0.1",
        "port": host_port,
        "published_port": host_port,
        "container_port": cport,
        "logs": (out or "")[:400],
        "lab_kind": "published-image",
        "container": name,
        "image": image,
    }


async def run_lab(repo_id: int, dest: Path, language: str, send, app_type: str = 'unknown') -> Dict[str, Any]:
    """Deploy the repo in a disposable Docker lab with bounded runtime policy.

    Generated labs expose a loopback-only health port during dynamic validation;
    the pipeline disconnects their bridge after all lab-dependent work. Compose
    labs receive an internal-network override so their app/database topology has
    no external egress while remaining reachable through the published port.

    Priority:
      1. Repository docker-compose / Dockerfile (never Lotus-generated files)
      2. Generated Dockerfile from README, manifests, and build files
      3. AI-assisted Dockerfile only if (2) fails to build
    """
    # Keep a bounded provider-attempt ledger in the returned lab status.  A
    # fallback can otherwise hide the fact that compose, a published image,
    # and a repository Dockerfile all failed before generation was attempted;
    # that is especially misleading when the final result is simply
    # ``build-failed``.  The ledger is diagnostic only and never affects the
    # proof decision (``healthy`` remains the sole deployment authority).
    attempts: List[Dict[str, Any]] = []

    def _record_attempt(provider: str, result: Any) -> None:
        if not isinstance(result, dict):
            result = {"status": str(result)}
        attempts.append({
            "provider": provider,
            "status": str(result.get("status") or "unknown"),
            "healthy": bool(result.get("healthy")),
            "logs": str(result.get("logs") or "")[-1200:],
        })

    def _with_attempts(result: Any) -> Dict[str, Any]:
        payload = dict(result) if isinstance(result, dict) else {"status": str(result)}
        payload["provider_attempts"] = list(attempts)
        return payload

    if os.environ.get("LOTUS_DISABLE_LAB"):
        await send(repo_id, "Lab execution disabled (LOTUS_DISABLE_LAB); simulating", level="info")
        result = {
            "status": "disabled",
            "healthy": False,
            "url": None,
            "logs": "simulated",
        }
        _record_attempt("disabled", result)
        return _with_attempts(result)

    if not shutil.which("docker"):
        await send(repo_id, "Docker not available; cannot deploy lab", level="warning")
        result = {
            "status": "unavailable",
            "healthy": False,
            "url": None,
            "logs": "docker binary not found in PATH",
        }
        _record_attempt("docker-runtime", result)
        return _with_attempts(result)

    # A present docker *binary* does not mean the *daemon* is reachable. A
    # dead or unresponsive Docker Desktop (common under host memory pressure)
    # otherwise makes ``docker build``/``docker run`` block until the
    # multi-minute build timeout, holding a worker and stalling Phase 2 -- the
    # ~20-minute "lab-build hang" operators reported. Probe the daemon with a
    # short, hard-bounded ping and fail fast with an actionable message so the
    # audit degrades to static evidence in seconds instead of minutes.
    try:
        _ping_timeout = int(os.environ.get("LOTUS_DOCKER_PING_TIMEOUT", "12") or 12)
    except (TypeError, ValueError):
        _ping_timeout = 12
    _pf_out, _pf_rc = await _run_cmd(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        timeout=max(3, _ping_timeout),
    )
    if _pf_rc != 0 or not str(_pf_out).strip() or "cannot connect" in str(_pf_out).lower():
        await send(
            repo_id,
            "Docker daemon is not reachable (is Docker Desktop running?); "
            "skipping the isolated lab so the audit finishes on static evidence",
            level="warning",
        )
        result = {
            "status": "docker-daemon-unreachable",
            "healthy": False,
            "url": None,
            "logs": ("docker daemon ping failed: " + str(_pf_out)[:500]).strip(),
        }
        _record_attempt("docker-daemon", result)
        return _with_attempts(result)

    # A lab run gets a durable logical identity and source-content digest before
    # any target process starts.  The pipeline captures the source identity in
    # audit_plan.json before this function is scheduled; reuse that snapshot so
    # generated Dockerfiles/evidence cannot silently change what a receipt means.
    try:
        from backend.proof_receipts import content_tree_digest
        tree_hash = content_tree_digest(Path(dest))
    except Exception:
        tree_hash = ""
    plan_identity: Dict[str, Any] = {}
    try:
        plan_path = Path(dest) / ".lotus" / "audit_plan.json"
        if plan_path.is_file():
            parsed = json.loads(plan_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                plan_identity = parsed
    except Exception:
        plan_identity = {}
    target_tree_hash = str(plan_identity.get("target_tree_hash") or tree_hash)
    target_revision = str(plan_identity.get("target_revision") or tree_hash)
    _LAB_STATE[repo_id] = {
        "lab_run_id": str(uuid.uuid4()),
        "target_tree_hash": target_tree_hash,
        "target_revision": target_revision,
        "target_tree": str(plan_identity.get("target_tree") or ""),
        "dest": str(dest),
    }

    port = 3000 + (repo_id * 10)
    from backend.lab_builder import discover_lab_artifacts
    artifacts = discover_lab_artifacts(dest)
    for note in artifacts.get("notes") or []:
        await send(repo_id, note, level="info")

    compose_file = artifacts.get("compose") if artifacts.get("compose_usable") else None
    if artifacts.get("compose") and not artifacts.get("compose_usable"):
        await send(
            repo_id,
            "Repository compose would compile a multi-hour toolchain — skipping source build",
            level="info",
        )
    dockerfile = artifacts.get("dockerfile") if artifacts.get("dockerfile_usable") else None
    published = artifacts.get("published_images") or []

    if compose_file is not None:
        result = await _run_user_lab(
            repo_id, dest, port, send, dockerfile=None, compose=compose_file,
        )
        _record_attempt("repository-compose", result)
        if result.get("healthy"):
            return _with_attempts(result)
        if result.get("status") == "policy-rejected":
            # Never route a policy rejection into a different execution path; a
            # generated fallback would silently bypass the untrusted-repo policy.
            return _with_attempts(result)
        nxt = "trying a published image" if published else (
            "trying the repository Dockerfile" if dockerfile is not None else "generating one from project docs"
        )
        await send(
            repo_id,
            f"Repository docker-compose did not produce a healthy lab — {nxt}",
            level="warning",
        )

    if published:
        result = await _run_published_image_lab(repo_id, dest, port, send, published[0])
        _record_attempt("published-image", result)
        if result.get("healthy"):
            return _with_attempts(result)
        await send(repo_id, "Published README image did not become healthy — continuing", level="warning")

    if dockerfile is not None:
        result = await _run_user_lab(
            repo_id, dest, port, send, dockerfile=dockerfile, compose=None,
        )
        _record_attempt("repository-dockerfile", result)
        if result.get("healthy"):
            return _with_attempts(result)
        await send(
            repo_id,
            "Repository Dockerfile did not produce a healthy lab — generating one from project docs and build files",
            level="warning",
        )

    await send(repo_id, "No usable repo Dockerfile/compose — generating a lab image from README and build files", level="info")
    result = await _build_and_run_default_lab(repo_id, dest, language, send, app_type)
    _record_attempt("generated-lab", result)
    return _with_attempts(result)
