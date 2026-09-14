"""Containerized external static analyzers for Phase 1 reconnaissance.

The platform's host frequently lacks language-native toolchains (Go, Java build
tools) and pinning analyzer versions on the host is fragile. Instead - mirroring
the Joern integration (:mod:`backend.joern`) - each analyzer runs inside its
official Docker image with the repo bind-mounted read-only. This gives us:

* **Go** coverage, previously a blind spot for our Go targets (tailscale,
  authelia, casbin): ``gosec`` (SAST), ``govulncheck`` (call-graph *reachable*
  known-vuln detection - not just "dependency present"), and ``staticcheck``
  (nil-deref / logic / correctness).
* **Universal** coverage: ``semgrep`` with curated rulesets (OWASP + language
  packs spanning Java/Python/Go), and ``osv-scanner`` for lockfile CVE
  correlation across ecosystems.

Every runner:
  - returns findings in the platform's standard shape (``tool``, ``title``,
    ``cvss``, ``description``, ``file``, ``line``, ``confidence``, plus
    ``discovery_technique`` and a ``qualification`` used by the metrics/gates);
  - distinguishes capability gaps from execution failures.  If Docker or the
    image is unavailable the runner raises :class:`AnalyzerUnavailable`; if an
    installed analyzer emits malformed/empty output it raises
    :class:`AnalyzerExecutionError`.  The pipeline records either condition as
    an explicit non-clean terminal tool result instead of manufacturing a
    zero-lead success;
  - is time-bounded so a pathological repo cannot wedge an audit.

Images are configurable via environment variables so a deployment can pin
digests or use a mirror. ``ensure_images`` pre-pulls them (best-effort).
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import re
import shlex
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.async_process import terminate_and_reap


class AnalyzerUnavailable(RuntimeError):
    """Raised when an applicable containerized analyzer cannot be provided.

    An empty result is a valid *clean* result only after the requested analyzer
    actually executed.  Keeping image-pull/runtime availability distinct lets
    the pipeline count this as ``not-installed`` instead of manufacturing a
    false negative.
    """


class AnalyzerExecutionError(RuntimeError):
    """Raised when an available analyzer did not produce a trustworthy result."""

# ---------------------------------------------------------------------------
# Image configuration (override via env for pinning / mirrors)
# ---------------------------------------------------------------------------
# govulncheck + staticcheck need a Go toolchain; use the official golang image
# with scanner binaries installed at image build time. The current packaged
# image is Go 1.27.1; incompatible target versions remain explicit gaps instead
# of silently downloading a different toolchain during an audit.
GOLANG_IMAGE = os.environ.get("LOTUS_GO_TOOLS_IMAGE", os.environ.get("LOTUS_GOLANG_IMAGE", ""))
# gosec also needs the Go toolchain to discover buildable packages and build a
# type-correct package list. Scanner binaries live in the immutable image.
GOSEC_IMAGE = os.environ.get("LOTUS_GOSEC_IMAGE", GOLANG_IMAGE)
SEMGREP_IMAGE = os.environ.get("LOTUS_SEMGREP_IMAGE", "semgrep/semgrep:latest")
OSV_IMAGE = os.environ.get("LOTUS_OSV_IMAGE", "ghcr.io/google/osv-scanner:latest")

# Named Docker volume caching target Go modules and build cache across runs
# when the hardened uid can write it. Scanner binaries stay in the image. Rootless/userns
# engines automatically use a bounded ephemeral cache instead of failing.
_GO_CACHE_VOLUME = os.environ.get("LOTUS_GO_CACHE_VOLUME", "lotus-go-cache")

# The analyzer containers deliberately run as the unprivileged ``lotus`` uid.
# Some Docker engines create a named-volume root as uid 0 (or use a userns
# mapping that refuses chown), so merely mounting a cache at /go can make
# target module/build caching fail before either analyzer starts. Cache readiness is a
# process-local record: True means the named volume passed a real write probe;
# False means runners use a bounded ephemeral /go tmpfs instead.
_GO_CACHE_READY: Dict[str, bool] = {}


async def prepared_go_image(use_k8s: bool, *, gosec: bool = False) -> str:
    """Use installed scanners in an immutable image; never bootstrap mid-audit."""
    image = (os.environ.get("LOTUS_GOSEC_IMAGE", "") if gosec else "").strip()
    image = image or os.environ.get("LOTUS_GO_TOOLS_IMAGE", "").strip() or os.environ.get("LOTUS_GOLANG_IMAGE", "").strip()
    if not image and use_k8s:
        try:
            from backend.lab_selftest import _kubernetes_selftest_image
            image = await _kubernetes_selftest_image(use_explicit_override=False)
        except (ValueError, OSError):
            raise AnalyzerUnavailable("The installed Go analyzer image could not be identified; deploy the packaged image or set LOTUS_GO_TOOLS_IMAGE to its immutable digest") from None
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-fA-F0-9]{64}", image):
        raise AnalyzerUnavailable("Go analyzers require a preinstalled immutable LOTUS_GO_TOOLS_IMAGE (@sha256); a generic Go image or mutable tag is not an installed scanner")
    return image


def _installed_go_script(tool: str) -> str:
    if tool not in {"gosec", "govulncheck", "staticcheck"}:
        raise ValueError("unknown installed Go analyzer")
    return ("set -eu; export PATH=/usr/local/go/bin:/opt/lotus-tools:/usr/local/bin:/usr/bin:/bin; "
            "export HOME=/tmp GOPATH=/go GOTOOLCHAIN=local; "
            "export GOTMPDIR=/go/gotmp TMPDIR=/go/gotmp XDG_CACHE_HOME=/go/xdgcache; "
            "mkdir -p /go/gotmp /go/xdgcache /go/cache /go/pkg/mod; "
            "export GOFLAGS='-buildvcs=false -p=2' GOMAXPROCS=2 GOMEMLIMIT=3GiB; "
            "printf '%s\\n' prerequisites > /tmp/lotus-tool-stage; "
            "command -v go >/dev/null && command -v " + tool + " >/dev/null "
            "|| { echo 'Required Go analyzer was not installed in the selected image; run platform prerequisite checks' >&2; exit 69; }; "
            # Validate the actual mounted module/workspace with Go's own
            # parser before building packages. This offline check also covers
            # callers outside the pipeline and changed/custom runtime images.
            "GOPROXY=off GOSUMDB=off go list -m >/dev/null "
            "|| { echo 'Go module/toolchain prerequisites did not pass; no analyzer was run' >&2; exit 69; }; ")


def _require_go_prerequisites(code: int, error: str) -> None:
    if code == 68:
        raise AnalyzerExecutionError("Go package inventory failed; dependency or build-configuration coverage remains incomplete. " + error[-1200:])
    if code == 69:
        from backend.native_readiness import NativePrerequisiteUnavailable
        # Preserve only the useful, source-independent toolchain diagnostic.
        version = re.search(r"requires go >= ([0-9.]+).*?running go ([0-9.]+)", error)
        detail = (f"Target requires Go >= {version[1]}; installed Go is {version[2]}. "
                  if version else "")
        raise NativePrerequisiteUnavailable(detail + "Go module/toolchain prerequisites did not pass; install a compatible qualified tools image before retrying. No Go analyzer was run")

_DEFAULT_TIMEOUT = int(os.environ.get("LOTUS_EXT_ANALYZER_TIMEOUT", "420"))

def _go_timeout(timeout: Optional[int], tool: Optional[str] = None) -> int:
    """Give cold Go graph loading its own budget; explicit limits always win."""
    if timeout is not None:
        value = int(timeout)
        if value <= 0:
            raise ValueError("Go analyzer timeout must be positive")
        return value
    if tool:
        from backend.analyzer_resources import selected_tool
        policy = selected_tool(tool)
        if policy and policy.get("effective", {}).get("timeout_seconds"):
            return policy["effective"]["timeout_seconds"]
    raw = os.environ.get("LOTUS_GO_ANALYZER_TIMEOUT") or os.environ.get("LOTUS_EXT_ANALYZER_TIMEOUT")
    if raw:
        try:
            value = int(raw)
        except ValueError:
            raise AnalyzerUnavailable("Go analyzer timeout must be a positive integer in seconds") from None
        if not 1 <= value <= 7200:
            raise AnalyzerUnavailable("Configured Go analyzer timeout must be between 1 and 7200 seconds")
        return value
    return 1800


# Each native analyzer already loads and type-checks its package graph. Doing a
# whole-tree build first, then rebuilding packages one by one on any error,
# exhausted the old 420s budget before analysis on large cold repositories.
# Inventory dependencies without compiling or silently dropping broken packages.
# Keep the exact ./... scope: package errors must remain explicit coverage gaps.
_GO_PACKAGE_INVENTORY_SH = (
    "printf '%s\\n' dependencies > /tmp/lotus-tool-stage; "
    "go list ./... >/tmp/lotus-go-packages "
    "|| { echo 'Go package dependencies could not be resolved; no analyzer was run' >&2; exit 68; }; "
    "[ -s /tmp/lotus-go-packages ] "
    "|| { echo 'No Go packages were available for analysis' >&2; exit 68; }; "
    "pkgs='./...'; printf '%s\\n' analysis > /tmp/lotus-tool-stage; "
)
# gosec's independent package-worker default follows host CPU count, which can
# exceed the container quota even when GOMAXPROCS is set. Bound package loaders
# to the same two CPUs; all packages and configured rules remain in scope.
_GOSEC_ANALYSIS_COMMAND = "gosec -concurrency=2 -fmt=json -nosec=false $pkgs"
_GO_PROGRESS_STAGES = {
    "prerequisites": "Checking the installed Go toolchain against the repository",
    "dependencies": "Resolving Go module dependencies and enumerating packages",
    "analysis": "Loading package types and running the Go analyzer",
}


def docker_available() -> bool:
    return shutil.which("docker") is not None


def _container_runtime_args(repo_id: int = 0) -> List[str]:
    """Use the same containment policy as the application lab for analyzers.

    Static analyzers process attacker-controlled source and may execute build
    hooks, language plugins, or parser code.  Keeping their Docker flags in one
    place prevents a new analyzer from silently running privileged/root with
    unlimited resources.  The import is lazy so parser-only/unit-test use does
    not introduce an import cycle.
    """
    try:
        from backend.lab import hardened_runtime_args
        return list(hardened_runtime_args(repo_id if repo_id else None))
    except Exception:
        # A missing policy import must not silently run a repo-controlled
        # analyzer as root with unlimited resources.
        return ["--memory", "4g", "--cpus", "2", "--pids-limit", "512",
                "--read-only", "--cap-drop=ALL", "--security-opt",
                "no-new-privileges:true", "--user", "65532:65532",
                "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m",
                "--tmpfs", "/run:rw,noexec,nosuid,nodev,size=32m"]


async def _run(cmd: List[str], timeout: int = _DEFAULT_TIMEOUT) -> Tuple[str, str, int]:
    """Run a subprocess, returning (stdout, stderr, rc). Never raises."""
    try:
        try:
            from backend.lab import _controlled_child_env
            child_env = _controlled_child_env()
        except Exception:
            child_env = None
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=child_env,
            start_new_session=True,
        )
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out_b.decode(errors="ignore"), err_b.decode(errors="ignore"), proc.returncode or 0
    except asyncio.CancelledError:
        await terminate_and_reap(locals().get("proc"), process_group=True)
        raise
    except asyncio.TimeoutError:
        await terminate_and_reap(locals().get("proc"), process_group=True)
        return "", f"timed out after {timeout}s", -1
    except Exception as e:  # pragma: no cover - defensive
        await terminate_and_reap(locals().get("proc"), process_group=True)
        return "", str(e), -1


async def _image_present(image: str) -> bool:
    """Resolve the exact local reference, including name@digest on containerd stores.

    ``docker images`` filters names/tags and can return no rows for a cached
    immutable reference. Inspect performs the same exact lookup as Docker run;
    a successful command and one valid image ID are both required.
    """
    if not docker_available():
        return False
    out, _, rc = await _run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", "--", image], timeout=20,
    )
    return rc == 0 and re.fullmatch(r"sha256:[a-fA-F0-9]{64}", out.strip()) is not None


async def ensure_images(images: Optional[List[str]] = None) -> Dict[str, bool]:
    """Best-effort pre-pull of analyzer images. Returns {image: available}."""
    images = images or [GOSEC_IMAGE, GOLANG_IMAGE, SEMGREP_IMAGE, OSV_IMAGE]
    result: Dict[str, bool] = {}
    for img in images:
        result[img] = await _ensure_image(img)
    return result


# Process-wide cache of images we've confirmed present/pulled, so a runner that
# self-heals once doesn't re-shell `docker pull`/`images` on every subsequent
# audit. Plain-dict writes are atomic under the GIL, so this is safe to share
# across the per-scan worker event loops (unlike an asyncio.Lock, which binds to
# a single loop). We intentionally avoid a lock: concurrent `docker pull` of the
# same tag is de-duplicated by the docker daemon, and the post-pull presence
# re-check makes the operation idempotent.
_IMAGE_READY: Dict[str, bool] = {}


async def _ensure_image(image: str, *, pull_timeout: int = 420) -> bool:
    """Return True if ``image`` is usable, pulling it once on-demand if absent.

    This makes the containerized analyzers **self-healing**: the first audit that
    needs an analyzer pulls its image (previously the runners silently returned
    ``[]`` forever when images were never pre-pulled — the root cause of Go
    targets producing zero high-signal leads). Subsequent audits hit the cache.
    Degrades to False (never raises) when docker or the registry is unavailable.
    """
    if not docker_available():
        return False
    if _IMAGE_READY.get(image):
        return True
    if await _image_present(image):
        _IMAGE_READY[image] = True
        return True
    await _run(["docker", "pull", image], timeout=pull_timeout)
    # Pull output/exit alone is not a usable local image receipt. A concurrent
    # pull may also succeed even when this request fails, so inspect either way.
    ok = await _image_present(image)
    _IMAGE_READY[image] = ok
    return ok


def _ephemeral_go_cache_args() -> List[str]:
    """Return a hardened writable /go fallback for rootless/unmappable volumes."""
    size = str(os.environ.get("LOTUS_GO_EPHEMERAL_CACHE_SIZE", "768m") or "768m").strip().lower()
    match = re.fullmatch(r"(\d+)([kmg]?)", size)
    if not match:
        size = "768m"
    else:
        amount = int(match.group(1))
        unit = match.group(2) or "m"
        multiplier = {"k": 1 / 1024, "m": 1, "g": 1024}[unit]
        # A cache smaller than 128 MiB cannot reliably install the Go tools;
        # a giant setting can starve concurrent audits. Clamp the fallback's
        # addressable size while preserving an operator-visible env override.
        mib = max(128, min(1536, int(amount * multiplier)))
        size = f"{mib}m"
    # Go executes the installed analyzer from $GOPATH/bin, so unlike /tmp this
    # mount must permit execute. It is still non-persistent, no-suid, no-dev,
    # and bounded by the analyzer container's memory limit.
    return ["--tmpfs", f"/go:rw,exec,nosuid,nodev,size={size},mode=1777"]


async def _ensure_go_cache_writable() -> List[str]:
    """Return a verified writable Go cache mount for the hardened analyzer.

    We *probe* the persistent volume as uid 65532 rather than attempting a
    privileged recursive chown. User-namespace Docker deployments can reject
    that chown even for container root; the old approach therefore hid a usable
    analyzer behind cache setup errors. If the probe fails, a per-run tmpfs
    gives the analyzer a safe writable GOPATH instead of claiming a clean scan.
    """
    if _GO_CACHE_VOLUME in _GO_CACHE_READY:
        return (
            ["-v", f"{_GO_CACHE_VOLUME}:/go"]
            if _GO_CACHE_READY[_GO_CACHE_VOLUME]
            else _ephemeral_go_cache_args()
        )
    cmd = [
        "docker", "run", "--rm", "--network", "none",
        "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
        "--memory", "256m", "--cpus", "0.5", "--pids-limit", "64",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m",
        "--user", "65532:65532", "-v", f"{_GO_CACHE_VOLUME}:/go",
        GOLANG_IMAGE,
        "sh", "-ec",
        (
            "mkdir -p /go/bin /go/cache /go/pkg/mod /go/gotmp /go/xdgcache; "
            "touch /go/cache/.lotus-write-probe; "
            "rm -f /go/cache/.lotus-write-probe; "
            "rm -rf /go/gotmp/* 2>/dev/null || true"
        ),
    ]
    _out, _err, rc = await _run(cmd, timeout=90)
    if rc != 0:
        # A prior root-run can leave GOCACHE/GOPATH owned ``root:root 0755``,
        # which the hardened uid (65532) cannot write. That silently degrades
        # every Go analyzer onto the small RAM tmpfs fallback -- the real
        # cause of "no space left on device" during Go builds and toolchain
        # downloads even though the disk-backed volume has hundreds of GB
        # free. Self-heal the volume ownership once (best effort, throwaway
        # root container, no network, dropped caps). Userns-remap deployments
        # may still reject the chown; those correctly keep the tmpfs fallback.
        repair = [
            "docker", "run", "--rm", "--network", "none",
            "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
            "--memory", "256m", "--cpus", "0.5", "--pids-limit", "64",
            "--user", "0:0", "-v", f"{_GO_CACHE_VOLUME}:/go",
            GOLANG_IMAGE, "sh", "-ec",
            (
                "mkdir -p /go/bin /go/cache /go/pkg/mod /go/gotmp /go/xdgcache; "
                "chown -R 65532:65532 /go 2>/dev/null || chmod -R a+rwX /go 2>/dev/null || true"
            ),
        ]
        await _run(repair, timeout=180)
        # Re-probe regardless of the repair's own exit status: a partial
        # chmod (some paths can be unchmodable under the VM's mount) can
        # still leave the cache writable, and the probe is the source of
        # truth for whether the disk-backed volume is usable.
        _out, _err, rc = await _run(cmd, timeout=90)
    _GO_CACHE_READY[_GO_CACHE_VOLUME] = rc == 0
    return (
        ["-v", f"{_GO_CACHE_VOLUME}:/go"]
        if rc == 0
        else _ephemeral_go_cache_args()
    )


# ---------------------------------------------------------------------------
# Runtime dispatch: Kubernetes Jobs (preferred) vs Docker (break-glass)
# ---------------------------------------------------------------------------
# Points the Go toolchain at the writable /go scratch mount and a writable HOME.
# Shared by the Kubernetes runs of the Go analyzers (the wrapper script sets the
# rest); mirrors the ``-e`` flags used on the Docker path.
_K8S_GO_ENV = {
    "GOMODCACHE": "/go/pkg/mod", "GOCACHE": "/go/cache", "GOPATH": "/go",
    "HOME": "/tmp", "XDG_CACHE_HOME": "/go/xdgcache",
    "GOTMPDIR": "/go/gotmp", "TMPDIR": "/go/gotmp", "GOTOOLCHAIN": "local",
    "GOMAXPROCS": "2", "GOMEMLIMIT": "3GiB",
}


# Per-tool k8s resource envelope. Requests drive scheduler admission (pods queue
# as Pending under contention). These analyzers reserve their full memory limit;
# unrelated workloads can still exceed requests, so this is not a node-wide OOM
# guarantee. Operator quotas and actual node allocatable remain authoritative.
_K8S_TOOL_RESOURCES: Dict[str, Dict[str, str]] = {
    "_default":    {"mem_request": "2Gi",   "mem_limit": "2Gi", "cpu_request": "250m", "cpu_limit": "1"},
    "gosec":       {"mem_request": "4Gi",   "mem_limit": "4Gi", "cpu_request": "500m", "cpu_limit": "2"},
    "govulncheck": {"mem_request": "4Gi",   "mem_limit": "4Gi", "cpu_request": "500m", "cpu_limit": "2"},
    "staticcheck": {"mem_request": "4Gi",   "mem_limit": "4Gi", "cpu_request": "500m", "cpu_limit": "2"},
    "semgrep":     {"mem_request": "2Gi",   "mem_limit": "2Gi", "cpu_request": "500m", "cpu_limit": "1"},
    "osv-scanner": {"mem_request": "1Gi",   "mem_limit": "1Gi", "cpu_request": "250m", "cpu_limit": "1"},
}

_K8S_GO_MEMORY_OPTIONS = {
    "gosec": "LOTUS_K8S_GOSEC_MEMORY_MIB",
    "govulncheck": "LOTUS_K8S_GOVULNCHECK_MEMORY_MIB",
    "staticcheck": "LOTUS_K8S_STATICCHECK_MEMORY_MIB",
}


def _k8s_tool_resources(name: str) -> Dict[str, str]:
    """Allow explicit capacity increases without reducing analysis scope.

    The complete limit is also reserved for scheduling. Overrides cannot lower
    the qualified default, alter another tool, or mutate the shared defaults.
    This does not provision node capacity or authorize quota changes.
    """
    resources = dict(_K8S_TOOL_RESOURCES.get(name, _K8S_TOOL_RESOURCES["_default"]))
    from backend.analyzer_resources import selected_tool
    policy = selected_tool(name)
    if policy and policy.get("effective", {}).get("memory_mb"):
        resources["mem_request"] = resources["mem_limit"] = f"{policy['effective']['memory_mb']}Mi"
        if name == "semgrep":
            resources["cpu_request"] = policy["effective"]["cpu_request"]
            resources["cpu_limit"] = policy["effective"]["cpu_limit"]
        return resources
    if name == "semgrep":
        from backend.analyzer_resources import _env_int, MEMORY_ENV
        amount, _ = _env_int(MEMORY_ENV[name], 2048, 512, 65536)
        resources["mem_request"] = resources["mem_limit"] = f"{amount}Mi"
        return resources
    option = _K8S_GO_MEMORY_OPTIONS.get(name)
    raw = os.environ.get(option, "").strip() if option else ""
    if raw:
        if not re.fullmatch(r"[0-9]{4,5}", raw) or not 4096 <= int(raw) <= 65536:
            raise AnalyzerUnavailable(f"{option} must be an integer from 4096 to 65536 MiB; no analyzer was started")
        resources["mem_request"] = resources["mem_limit"] = f"{int(raw)}Mi"
    return resources


def analyzer_uses_kubernetes(repo_id: int = 0) -> bool:
    """Respect unified runtime policy and explicitly permitted tool overrides."""
    from backend.k8s_runtime import kubernetes_selected
    selected = kubernetes_selected(repo_id)
    if int(repo_id or 0) <= 0:
        return False
    override = (os.environ.get("LOTUS_ANALYZER_RUNTIME") or "").strip().lower()
    if override in ("docker", "local") and selected:
        from backend.lab_provider import _allow_fallback, _strict
        if _strict() or not _allow_fallback():
            raise AnalyzerUnavailable("Docker analyzer override conflicts with Kubernetes policy; explicitly permit backup and disable strict mode to use it.")
        return False
    if override not in ("", "docker", "local", "k8s", "k8s-job", "kubernetes", "job"):
        raise AnalyzerUnavailable("Unknown LOTUS_ANALYZER_RUNTIME; select Kubernetes or an explicitly permitted Docker backup.")
    return selected or override in ("k8s", "k8s-job", "kubernetes", "job")


def container_runtime_available(repo_id: int = 0) -> bool:
    """Applicability includes a configured cluster without a Docker binary."""
    return analyzer_uses_kubernetes(repo_id) or docker_available()


async def _use_k8s_runtime(repo_id: int = 0) -> bool:
    return analyzer_uses_kubernetes(repo_id)


async def _run_tool(use_k8s: bool, repo_id: int, dest: Path, name: str, image: str,
                    docker_cmd: Optional[List[str]], *, script: Optional[str] = None,
                    argv: Optional[List[str]] = None, go_cache: bool = False,
                    env: Optional[Dict[str, str]] = None,
                    timeout: int = _DEFAULT_TIMEOUT, source_root: Optional[Path] = None,
                    diagnostic_sink=None) -> Tuple[str, str, int]:
    """Execute one analyzer, returning the ``(stdout, stderr, rc)`` contract.

    The tuple is identical across runtimes, so every analyzer's output parsing
    is runtime-agnostic.  On the Kubernetes path the target source is delivered
    through the per-audit read-only PVC; a populate failure returns ``rc=-1`` (an
    honest tool failure the pipeline records as a skip) rather than silently
    escaping the cluster to Docker.
    """
    from backend import analyzer_resources as resource_policy
    policy = resource_policy.selected_tool(name)
    if name == "semgrep" and policy is None:
        policy = next(row for row in resource_policy.snapshot_policy({})["tools"] if row["id"] == name)
    if use_k8s and policy is not None and name in resource_policy.TOOLS:
        policy = await resource_policy.refresh_tool_admission(policy)
    def resource_error(reason, *, failed=False, diagnostic=None):
        error = AnalyzerExecutionError(reason) if failed else AnalyzerUnavailable(reason)
        metadata = resource_policy.task_resource_metadata(name, policy, reason, failed=failed, diagnostic=diagnostic)
        for key, value in metadata.items():
            setattr(error, key, value)
        return error
    if policy and policy.get("state") not in ("ready", "unknown"):
        raise resource_error(policy["reason"])
    if use_k8s:
        from backend import k8s_runtime as kr
        res = _k8s_tool_resources(name)
        root = Path(source_root or dest).resolve()
        target = Path(dest).resolve()
        if not target.is_relative_to(root):
            return "", "analyzer target is outside its source root", -1
        execution = resource_policy.execution_identity(name, image, target.relative_to(root).as_posix(), script, env,
            {**res, "timeout_seconds": timeout, "queue_timeout_seconds": (policy or {}).get("effective", {}).get("queue_timeout_seconds")}) if name in resource_policy.TOOLS else None
        previous = resource_policy.prior_resource_failure(execution)
        if previous:
            raise resource_error(
                "The same revision, analyzer image and resource envelope previously ended with a verified Pod OOMKilled. "
                "Increase this analyzer's memory with sufficient node capacity, or explicitly disable and re-enable it to retry. "
                "Coverage remains incomplete.", diagnostic=previous["diagnostic"])
        diagnostic = {}
        def capture_diagnostic(value):
            diagnostic.update(value)
            if execution:
                diagnostic.update({key: execution[key] for key in (
                    "scan_job_id", "target_tree_hash", "target_revision", "target_path", "scope_hash")})
            try:
                resource_policy.record_resource_failure(execution, diagnostic)
            except OSError:
                diagnostic["receipt_persisted"] = False
        try:
            pvc = await kr.ensure_source_pvc(int(repo_id), root)
        except kr.KubernetesSourceUnavailable as exc:
            return "", str(exc), -1
        if not pvc:
            return "", "kubernetes source volume unavailable for analyzer", -1
        out, err, code = await kr.run_to_completion(
            int(repo_id), name, image, script=script, argv=argv,
            workdir="/src" if target == root else "/src/" + target.relative_to(root).as_posix(), timeout=timeout, allow_egress=True,
            writable_paths=(["/go"] if go_cache else None), env=env,
            mem_request=res["mem_request"], mem_limit=res["mem_limit"],
            cpu_request=res["cpu_request"], cpu_limit=res["cpu_limit"],
            progress_stages=_GO_PROGRESS_STAGES if name in {"gosec", "govulncheck", "staticcheck"} else None,
            # OSV128 means no extracted packages. It is only an observation;
            # the adapter must still verify complete compatible-input absence.
            observation_exit_codes=(1, 128) if name == "osv-scanner" else (1,) if name == "semgrep" else (),
            **({"queue_timeout": policy["effective"]["queue_timeout_seconds"]} if policy and policy.get("effective") else {}),
            **({"diagnostic_sink": capture_diagnostic} if name in resource_policy.TOOLS or name == "semgrep" else {}),
        )
        if diagnostic_sink is not None:
            diagnostic_sink(copy.deepcopy(diagnostic))
        if diagnostic.get("classification") in {"oom_killed", "queue_timeout", "execution_timeout", "evicted"}:
            reason = {"oom_killed": "Owned Kubernetes Pod was OOMKilled; provide sufficient node capacity and increase analyzer memory",
                      "queue_timeout": "Kubernetes resource/startup wait expired; inspect capacity, quota, image and volume prerequisites",
                      "execution_timeout": "Analyzer execution budget expired; increase its execution budget after reviewing progress",
                      "evicted": "Owned Kubernetes Pod was evicted; inspect node memory and scratch/storage capacity"}[diagnostic["classification"]]
            error = resource_error(reason + "; coverage remains incomplete", failed=True, diagnostic=diagnostic)
            if name == "semgrep":
                rows, scanner_error = semgrep_results(out, err, code, runtime_diagnostic=diagnostic)
                error.partial_semgrep_results = rows
                error.runtime_diagnostic = scanner_error.runtime_diagnostic
            raise error
        if code == 137 and name in _K8S_GO_MEMORY_OPTIONS:
            # Exit 137 alone (or target-controlled stderr) cannot prove an OOM.
            # Keep the diagnosis conditional on the actual Pod termination state.
            err += (f"\n{name} exited 137. If Pod diagnostics report OOMKilled at its "
                    f"{res['mem_limit']} memory limit, provide enough node allocatable memory "
                    f"and namespace quota, then increase "
                    f"{_K8S_GO_MEMORY_OPTIONS[name]} and retry. Partial output is not complete coverage.")
        return out, err, code
    from backend.docker_analyzer import run_owned
    effective = (policy or {}).get("effective") or {}
    diagnostic = {}
    backup_options = {}
    if effective:
        backup_options = {"memory_mb": effective.get("memory_mb"),
                          "queue_timeout": effective.get("queue_timeout_seconds")}
        if name != "semgrep":
            timeout = effective.get("timeout_seconds") or timeout
    try:
        result = await run_owned(docker_cmd or [], image=image, repo_id=repo_id, tool=name, timeout=timeout,
                                 diagnostic_sink=diagnostic.update, **backup_options)
    except Exception as exc:
        if name in resource_policy.TOOLS or name == "semgrep":
            reason = str(exc) or "Docker analyzer allocation or cleanup did not complete"
            raise resource_error(reason + "; coverage remains incomplete", failed=True, diagnostic=diagnostic) from exc
        raise
    if diagnostic_sink is not None:
        diagnostic_sink(copy.deepcopy(diagnostic))
    if (name in resource_policy.TOOLS or name == "semgrep") and diagnostic.get("classification") in {"oom_killed", "queue_timeout", "execution_timeout"}:
        reason = {"oom_killed": "Owned Docker analyzer was OOMKilled; provide capacity and increase its memory limit",
                  "queue_timeout": "Docker analyzer allocation budget expired; inspect daemon capacity and image prerequisites",
                  "execution_timeout": "Docker analyzer execution budget expired; review progress and configure its time budget"}[diagnostic["classification"]]
        error = resource_error(reason + "; coverage remains incomplete", failed=True, diagnostic=diagnostic)
        if name == "semgrep":
            rows, scanner_error = semgrep_results(*result, runtime_diagnostic=diagnostic)
            error.partial_semgrep_results = rows
            error.runtime_diagnostic = scanner_error.runtime_diagnostic
        raise error
    return result


def _docker_run(image: str, args: List[str], dest: Path, *,
                writable: bool = False, extra: Optional[List[str]] = None,
                workdir: str = "/src", name: Optional[str] = None,
                repo_id: int = 0) -> List[str]:
    """Assemble a ``docker run`` command with the repo bind-mounted at /src.

    ``writable`` mounts read-write (needed by tools that build, e.g. govulncheck);
    otherwise the mount is read-only for safety.
    """
    mount = f"{dest}:/src" + ("" if writable else ":ro")
    cmd = ["docker", "run", "--rm"]
    if name:
        cmd += ["--name", name]
    cmd += _container_runtime_args(repo_id)
    cmd += ["-v", mount, "-w", workdir]
    # Keep analyzers off the network by default (supply-chain safety); tools that
    # must fetch (govulncheck DB, osv-scanner) opt in via `extra`.
    if extra:
        cmd += extra
    cmd += [image] + args
    return cmd


def _rel(path: str, dest: Path) -> str:
    """Normalise a container path (/src/...) back to a repo-relative path."""
    p = (path or "").strip()
    for prefix in ("/src/", "/src"):
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    return p.lstrip("/")


# ---------------------------------------------------------------------------
# gosec - Go SAST
# ---------------------------------------------------------------------------
# gosec rule IDs -> (cvss, short label). Focus on the request's priority classes.
_GOSEC_SEVERITY = {
    "G204": (8.8, "Subprocess launched with tainted input (command injection)"),
    "G201": (8.2, "SQL string formatted with input (SQL injection)"),
    "G202": (8.2, "SQL string concatenated with input (SQL injection)"),
    "G304": (7.5, "File path from tainted input (path traversal)"),
    "G107": (7.5, "URL from tainted input (SSRF)"),
    "G101": (7.0, "Hardcoded credentials"),
    "G402": (7.0, "TLS verification disabled / weak config"),
    "G403": (5.5, "Weak RSA key length"),
    "G404": (5.0, "Insecure random source"),
    "G501": (5.0, "Weak crypto import"),
}


async def run_gosec(dest: Path, timeout: Optional[int] = None, repo_id: int = 0,
                    *, strict_output: bool = False) -> List[dict]:
    """Run gosec; parse JSON issues into findings.

    gosec is preinstalled in the immutable tools image and loads the complete
    package scope itself. Package/type errors remain explicit incomplete
    coverage instead of silently excluding packages or claiming a clean run.
    """
    timeout = _go_timeout(timeout, "gosec")
    use_k8s = await _use_k8s_runtime(repo_id)
    go_image = await prepared_go_image(use_k8s, gosec=True)
    gosec_script = _installed_go_script("gosec") + _GO_PACKAGE_INVENTORY_SH + _GOSEC_ANALYSIS_COMMAND
    image_ok = not use_k8s and await _ensure_image(go_image)
    if not use_k8s and not image_ok:
        raise AnalyzerUnavailable(f"gosec analyzer image unavailable: {go_image}")
    # Share the Go module/build cache so gosec doesn't re-download the target's
    # entire dependency tree on every audit (that cold download is what made gosec
    # blow past its timeout and return nothing on large modules like gost).
    cmd: Optional[List[str]] = None
    if image_ok:
        go_cache_args = await _ensure_go_cache_writable()
        cmd = _docker_run(
            go_image, ["bash", "-c", gosec_script], dest,
            extra=go_cache_args + ["--network", "bridge",
                   "-e", "GOMODCACHE=/go/pkg/mod", "-e", "GOCACHE=/go/cache",
                   "-e", "GOPATH=/go", "-e", "HOME=/tmp",
                   "-e", "XDG_CACHE_HOME=/go/xdgcache",
                   "-e", "GOTMPDIR=/go/gotmp", "-e", "TMPDIR=/go/gotmp",
                   "-e", "GOTOOLCHAIN=local"], repo_id=repo_id,
        )
    out, err, rc = await _run_tool(
        use_k8s, repo_id, dest, "gosec", go_image, cmd,
        script=gosec_script, env=_K8S_GO_ENV, go_cache=True, timeout=timeout,
    )
    _require_go_prerequisites(rc, err)
    # gosec uses exit 1 for a run that found issues, but negative values are
    # reserved by our subprocess wrapper for timeout/launch failure.  Never
    # accept a parseable partial JSON document from a timed-out process as a
    # complete scan.
    if rc not in (0, 1):
        _diag = (err[-240:] or out[-240:])
        _low = (err + out).lower()
        # A resource-exhausted analyzer is a coverage GAP, not a broken
        # audit. Classify container OOM (137/SIGKILL) and out-of-space as
        # unavailable (a skip with actionable remediation) so it does not
        # read as a hard failure -- Go coverage still comes from
        # govulncheck/staticcheck/semgrep. A negative rc is a timeout/launch
        # failure from _run and must stay an execution error.
        if rc == 137 or "signal: killed" in _low or "out of memory" in _low or "cannot allocate memory" in _low:
            raise AnalyzerUnavailable(
                "gosec could not complete under memory pressure (container OOM, "
                "exit 137). Go coverage remains from govulncheck/staticcheck/"
                "semgrep; free host/Docker memory or lower "
                "LOTUS_MAX_CONCURRENT_ANALYZERS to restore gosec. "
                f"Detail: {_diag}"
            )
        if "no space left on device" in _low:
            raise AnalyzerUnavailable(
                "gosec could not complete: no space left on device in the "
                f"analyzer cache. Reclaim Docker/disk space. Detail: {_diag}"
            )
        raise AnalyzerExecutionError(
            f"gosec exited {rc}: {_diag}"
        )
    data = _safe_json(out)
    if not data and not strict_output and rc == 0 and not out.strip():
        # Parser/unit-test compatibility for callers that only inspect the
        # invocation.  The production pipeline enables strict_output so an
        # applicable analyzer can never silently become a clean result.
        return []
    if not isinstance(data, dict) or "Issues" not in data:
        raise AnalyzerExecutionError(
            f"gosec returned no usable JSON Issues result (rc={rc}, output={out[-240:]!r}, stderr={err[-160:]!r})"
        )
    package_errors = data.get("Golang errors") or {}
    if package_errors and (not isinstance(package_errors, dict) or any(package_errors.values())):
        raise AnalyzerExecutionError("gosec could not load every package; coverage remains incomplete. "
                                     + json.dumps(package_errors, ensure_ascii=True)[:1200])
    findings: List[dict] = []
    for issue in data.get("Issues", []) or []:
        rule = issue.get("rule_id", "")
        cvss, label = _GOSEC_SEVERITY.get(rule, (5.0, issue.get("details", "gosec issue")))
        sev = str(issue.get("severity", "")).upper()
        conf = str(issue.get("confidence", "medium")).lower()
        line = issue.get("line", "0")
        try:
            line_i = int(str(line).split("-")[0])
        except ValueError:
            line_i = 0
        findings.append({
            "tool": "gosec",
            "title": f"[{rule}] {label}",
            "cvss": cvss if sev != "LOW" else min(cvss, 5.5),
            "description": (
                f"{issue.get('details', '')} (rule {rule}, severity {sev}). "
                f"Code: {str(issue.get('code', '')).strip()[:200]}"
            ),
            "file": _rel(issue.get("file", ""), dest),
            "line": line_i,
            "confidence": conf if conf in ("low", "medium", "high") else "medium",
            "discovery_technique": "gosec-sast",
            "qualification": "LATENT",
            "cwe": (issue.get("cwe") or {}).get("id"),
        })
    return findings


# ---------------------------------------------------------------------------
# govulncheck - Go reachable known-vuln detection (call-graph aware)
# ---------------------------------------------------------------------------
async def run_govulncheck(dest: Path, timeout: Optional[int] = None, repo_id: int = 0, *, source_root: Optional[Path] = None) -> List[dict]:
    """Run govulncheck via the golang image.

    govulncheck is high-signal: it reports vulns whose *vulnerable symbol is
    actually reachable* from the module's call graph, not merely present in
    go.sum. Reachable results are marked QUALIFIED (proven reachability) which
    prioritises them for Phase-2 PoC work.
    """
    if not (dest / "go.mod").exists():
        return []
    timeout = _go_timeout(timeout, "govulncheck")
    use_k8s = await _use_k8s_runtime(repo_id)
    # The preinstalled auditor runs with JSON output; only target modules use scratch.
    # NOTE: use ``bash -c`` (NOT ``-lc``): a login shell re-sources /etc/profile
    # in the golang image, which overwrites PATH and drops /usr/local/go/bin, so
    # ``go`` becomes "command not found" and the tool silently produced 0 leads.
    # We set PATH explicitly (go toolchain + GOPATH/bin) for the same reason.
    # Whole-graph compiler/dependency errors invalidate coverage and are
    # surfaced below. Never spend a second compilation pass or silently trim
    # broken packages out of the audit's declared scope.
    go_image = await prepared_go_image(use_k8s)
    script = _installed_go_script("govulncheck") + _GO_PACKAGE_INVENTORY_SH + "govulncheck -json $pkgs"
    image_ok = not use_k8s and await _ensure_image(go_image)
    if not use_k8s and not image_ok:
        raise AnalyzerUnavailable(f"Go analyzer image unavailable: {go_image}")
    # Prepare a Docker command only for the explicitly selected backup path.
    cmd: Optional[List[str]] = None
    if image_ok:
        go_cache_args = await _ensure_go_cache_writable()
        cmd = _docker_run(
            go_image, ["bash", "-c", script], dest,
            writable=False,
            extra=go_cache_args + ["--network", "bridge",
                   "-e", "GOMODCACHE=/go/pkg/mod", "-e", "GOCACHE=/go/cache",
                   "-e", "GOPATH=/go", "-e", "HOME=/tmp",
                   "-e", "XDG_CACHE_HOME=/go/xdgcache", "-e", "GOTMPDIR=/go/gotmp", "-e", "TMPDIR=/go/gotmp", "-e", "GOTOOLCHAIN=local"], repo_id=repo_id,
        )
    out, err, rc = await _run_tool(
        use_k8s, repo_id, dest, "govulncheck", go_image, cmd,
        script=script, env=_K8S_GO_ENV, go_cache=True, timeout=timeout, source_root=source_root,
    )
    _require_go_prerequisites(rc, err)
    # In JSON mode govulncheck documents an exit code of 0 whether or not it
    # reports vulnerabilities. A non-zero status therefore means the analysis
    # itself failed; accepting a partial JSON prefix would manufacture a proof
    # receipt from an incomplete scan.
    if rc != 0:
        raise AnalyzerExecutionError(
            f"govulncheck exited {rc}: {err[-480:] or out[-480:]}"
        )
    parsed_objects = list(_iter_json_objects(out))
    if not parsed_objects:
        raise AnalyzerExecutionError(
            "govulncheck returned no parseable JSON stream "
            f"(stderr={err[-480:]!r}, output={out[-240:]!r})"
        )
    # Avoid parsing the stream a second time while retaining the established
    # parser contract used by unit tests and callers.
    return _parse_govulncheck(out, dest)


def _parse_govulncheck(out: str, dest: Path) -> List[dict]:
    """Parse govulncheck streaming JSON (one JSON object per line or concatenated).

    The stream interleaves ``osv`` (vuln metadata) and ``finding`` records. A
    finding with a non-empty ``trace`` that reaches the module is *reachable*.
    """
    osv: Dict[str, dict] = {}
    reachable: Dict[str, dict] = {}
    for obj in _iter_json_objects(out):
        if "osv" in obj and isinstance(obj["osv"], dict):
            o = obj["osv"]
            osv[o.get("id", "")] = o
        finding = obj.get("finding")
        if isinstance(finding, dict):
            osv_id = finding.get("osv", "")
            trace = finding.get("trace") or []
            # A trace entry with a "function" means the vulnerable symbol is
            # reachable (module-level frames carry only a package).
            is_reachable = any(t.get("function") for t in trace)
            top = trace[0] if trace else {}
            prev = reachable.get(osv_id)
            if prev is None or (is_reachable and not prev.get("_reachable")):
                reachable[osv_id] = {
                    "osv_id": osv_id,
                    "_reachable": is_reachable,
                    "pkg": top.get("package") or top.get("module") or "",
                    "func": top.get("function") or "",
                    "file": _rel(top.get("position", {}).get("filename", ""), dest) if top.get("position") else "",
                    "line": (top.get("position") or {}).get("line", 0),
                }
    findings: List[dict] = []
    for osv_id, info in reachable.items():
        meta = osv.get(osv_id, {})
        summary = meta.get("summary") or (meta.get("details", "")[:120])
        aliases = ", ".join(meta.get("aliases", [])[:4])
        is_reach = info.get("_reachable")
        findings.append({
            "tool": "govulncheck",
            "title": f"{'Reachable' if is_reach else 'Imported'} Go vuln {osv_id}"
                     + (f" ({aliases})" if aliases else ""),
            "cvss": 8.0 if is_reach else 5.0,
            "description": (
                f"{summary}. Package {info.get('pkg')}"
                + (f", reachable via {info.get('func')}" if info.get("func") else "")
                + (". Vulnerable symbol is reachable from application code (call-graph proven)."
                   if is_reach else ". Imported but no reachable call site found.")
            ),
            "file": info.get("file", ""),
            "line": info.get("line", 0) or 0,
            "confidence": "high" if is_reach else "medium",
            "discovery_technique": "govulncheck-reachability",
            # Reachability is a proven boundary property -> QUALIFIED for Phase 2.
            "qualification": "QUALIFIED" if is_reach else "LATENT",
            "lead_depth": 3 if is_reach else 1,
        })
    return findings


# ---------------------------------------------------------------------------
# staticcheck - Go correctness / logic
# ---------------------------------------------------------------------------
# Checks most correlated with security-relevant logic bugs (nil deref, unreachable
# guards, impossible conditions). We keep cvss modest; these are leads for Phase 2.
_STATICCHECK_INTEREST = {
    "SA5011": (6.5, "Possible nil pointer dereference"),
    "SA4006": (5.0, "Value never read (dead assignment - possible logic error)"),
    "SA4017": (5.5, "Pure function result discarded"),
    "SA9003": (5.0, "Empty branch (guard does nothing)"),
    "SA1019": (4.0, "Deprecated API in use"),
    "SA4023": (5.5, "Impossible comparison (always true/false)"),
}


async def run_staticcheck(dest: Path, timeout: Optional[int] = None, repo_id: int = 0) -> List[dict]:
    if not (dest / "go.mod").exists():
        return []
    timeout = _go_timeout(timeout, "staticcheck")
    use_k8s = await _use_k8s_runtime(repo_id)
    # See run_govulncheck: ``bash -c`` + explicit PATH so ``go`` is found (a login
    # shell drops /usr/local/go/bin from PATH in the golang image), and scan only
    # the buildable packages so stale/broken code can't zero out results.
    go_image = await prepared_go_image(use_k8s)
    script = _installed_go_script("staticcheck") + _GO_PACKAGE_INVENTORY_SH + "staticcheck -f json $pkgs"
    image_ok = not use_k8s and await _ensure_image(go_image)
    if not use_k8s and not image_ok:
        raise AnalyzerUnavailable(f"Go analyzer image unavailable: {go_image}")
    # Prepare a Docker command only for the explicitly selected backup path.
    cmd: Optional[List[str]] = None
    if image_ok:
        go_cache_args = await _ensure_go_cache_writable()
        cmd = _docker_run(
            go_image, ["bash", "-c", script], dest,
            extra=go_cache_args + ["--network", "bridge",
                   "-e", "GOMODCACHE=/go/pkg/mod", "-e", "GOCACHE=/go/cache",
                   "-e", "GOPATH=/go", "-e", "HOME=/tmp",
                   "-e", "XDG_CACHE_HOME=/go/xdgcache", "-e", "GOTMPDIR=/go/gotmp", "-e", "TMPDIR=/go/gotmp", "-e", "GOTOOLCHAIN=local"], repo_id=repo_id,
        )
    out, err, rc = await _run_tool(
        use_k8s, repo_id, dest, "staticcheck", go_image, cmd,
        script=script, env=_K8S_GO_ENV, go_cache=True, timeout=timeout,
    )
    _require_go_prerequisites(rc, err)
    # staticcheck may use 1 when diagnostics exist, but any other non-zero
    # status (including -1 timeout) invalidates the output even if a partial
    # JSONL prefix happened to be emitted before termination.
    if rc not in (0, 1):
        raise AnalyzerExecutionError(
            f"staticcheck exited {rc}: {err[-240:] or out[-240:]}"
        )
    if rc != 0 and not out.strip():
        raise AnalyzerExecutionError(
            f"staticcheck exited {rc} without machine-readable output: {err[-240:]}"
        )
    if out.strip() and not list(_iter_json_objects(out)):
        raise AnalyzerExecutionError("staticcheck output was not parseable JSONL")
    objects = list(_iter_json_objects(out))
    compile_errors = [str(obj.get("message") or "package compilation failed") for obj in objects if obj.get("code") == "compile"]
    if compile_errors:
        raise AnalyzerExecutionError("staticcheck could not compile every package; coverage remains incomplete. " + "; ".join(compile_errors)[:1200])
    findings: List[dict] = []
    for obj in objects:
        code = obj.get("code", "")
        if code not in _STATICCHECK_INTEREST:
            continue
        cvss, label = _STATICCHECK_INTEREST[code]
        loc = obj.get("location", {}) or {}
        findings.append({
            "tool": "staticcheck",
            "title": f"[{code}] {label}",
            "cvss": cvss,
            "description": f"{obj.get('message', '')} ({code}).",
            "file": _rel(loc.get("file", ""), dest),
            "line": loc.get("line", 0) or 0,
            "confidence": "medium",
            "discovery_technique": "staticcheck-correctness",
            "qualification": "LATENT",
        })
    return findings


# ---------------------------------------------------------------------------
# semgrep - universal SAST with curated rulesets
# ---------------------------------------------------------------------------
def _semgrep_display_text(value: str, limit: int) -> str:
    """Bound untrusted scanner text; never use it as a runtime attestation."""
    from backend.scanners import _redact_scanner_output
    text = _redact_scanner_output(value[:12000])
    patterns = (
        (r"(?i)\b(Bearer|Basic)\s+[^\s,;]+", r"\1 [REDACTED]"),
        (r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{8,}", "[REDACTED]"),
        (r"(?i)(?:https?://)[^\s/@]+:[^\s/@]+@", "https://[REDACTED]@"),
        (r'''(?i)(["']?(?:api[_-]?key|password|secret|(?:access_|refresh_)?token)["']?\s*[:=]\s*["']?)[^\s,;'"&]+''', r"\1[REDACTED]"),
        (r"-----BEGIN [^-]*PRIVATE KEY-----.*", "[REDACTED_PRIVATE_KEY]"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text, flags=re.DOTALL)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return "".join(char for char in text if char in "\n\t" or ord(char) >= 32)[:limit]


def _semgrep_error_advisory(value):
    """Select scanner-reported rule identity without attesting its accuracy."""
    advisory = {}
    for field in ("rule_id", "check_id"):
        rule_id = value.get(field)
        if (isinstance(rule_id, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", rule_id)
                and _semgrep_display_text(rule_id, 256) == rule_id):
            advisory.update(rule_id=rule_id, rule_id_source=f"scanner_error.{field}", rule_id_verified=False)
            break
    if value.get("type") == "Internal matching error":
        advisory["advisory"] = {
            "kind": "rule_evaluation_incomplete", "basis": "scanner_error_type",
            "reason": "The scanner reports an incomplete rule evaluation; no resource cause or retry remedy is established.",
        }
        if "rule_id" not in advisory and isinstance(value.get("message"), str):
            # This is a narrow display hint from untrusted prose, never an
            # authenticated rule binding or evidence that a retry will work.
            match = re.match(r"Internal matching error when running ([A-Za-z0-9_.-]{1,256}) on ", value["message"][:512])
            if match and _semgrep_display_text(match[1], 256) == match[1]:
                advisory.update(rule_id=match[1], rule_id_source="message_extraction_advisory", rule_id_verified=False)
    return advisory


def _semgrep_scanner_diagnostic(data, err, rc, malformed, retained):
    errors = data.get("errors", []) if isinstance(data, dict) else None
    selected = []
    for value in errors[:8] if isinstance(errors, list) else []:
        if not isinstance(value, dict):
            selected.append({"malformed": True})
            continue
        row = {}
        for key, limit in (("type", 128), ("level", 32), ("message", 768), ("short_msg", 256), ("long_msg", 768)):
            if isinstance(value.get(key), str):
                row[key] = _semgrep_display_text(value[key], limit)
        if type(value.get("code")) is int:
            row["code"] = value["code"]
        if isinstance(value.get("path"), str):
            row["path_sha256"] = hashlib.sha256(value["path"].encode()).hexdigest()
        row.update(_semgrep_error_advisory(value))
        selected.append(row or {"malformed": True})
    return {"schema_version": 1, "trust": "untrusted_tool_output",
        "process_exit_code": rc if type(rc) is int else None,
        "stdout_json_object": isinstance(data, dict), "malformed_results_count": malformed,
        "valid_observations_retained": retained,
        "scan_errors_count": len(errors) if isinstance(errors, list) else None,
        "scan_errors_malformed": not isinstance(errors, list), "scan_errors": selected,
        "scan_errors_truncated": isinstance(errors, list) and len(errors) > 8,
        "stderr_excerpt": _semgrep_display_text(err, 2048) if isinstance(err, str) else "",
        "stderr_truncated": isinstance(err, str) and len(err) > 2048,
        "coverage_complete": False}


def semgrep_results(out: str, err: str, rc: int, *, runtime_diagnostic=None):
    """Keep execution failures ahead of parsing, with valid partial observations.

    A process exit or target-controlled message cannot establish an OOM or
    timeout. Only the caller's owned transport receipt supplies that diagnosis.
    """
    data = _safe_json(out)
    raw = data.get("results") if isinstance(data, dict) else None
    rows = []
    malformed = 0
    if isinstance(raw, list):
        for row in raw:
            valid = (isinstance(row, dict) and isinstance(row.get("check_id"), str)
                and bool(row["check_id"]) and isinstance(row.get("path"), str)
                and bool(row["path"]) and isinstance(row.get("start"), dict)
                and type(row["start"].get("line")) is int and row["start"]["line"] > 0
                and isinstance(row.get("extra"), dict)
                and isinstance(row["extra"].get("message", ""), str)
                and isinstance(row["extra"].get("metadata", {}), dict))
            if valid:
                rows.append(row)
            else:
                malformed += 1
    errors = data.get("errors", []) if isinstance(data, dict) else []
    diagnostic = runtime_diagnostic if isinstance(runtime_diagnostic, dict) else {}
    owned_failure = (diagnostic.get("ownership_verified") is True
        and diagnostic.get("tool_id") == "semgrep"
        and diagnostic.get("provider") in {"local", "kubernetes", "docker"}
        and diagnostic.get("classification") in {"execution_timeout", "queue_timeout", "oom_killed", "evicted"})
    reason = None
    if owned_failure:
        label = {"execution_timeout": "execution budget expired", "queue_timeout": "runtime queue budget expired",
                 "oom_killed": "owned runtime was OOMKilled", "evicted": "owned runtime was evicted"}[diagnostic["classification"]]
        budget = diagnostic.get("timeout_seconds")
        reason = "semgrep " + label + (f" ({budget}s)" if diagnostic["classification"] == "execution_timeout" and isinstance(budget, (int, float)) else "")
    elif rc not in (0, 1):
        reason = f"semgrep execution failed (rc={rc})"
    elif not isinstance(raw, list):
        reason = "semgrep returned no usable JSON results list"
    elif malformed:
        reason = f"semgrep returned {malformed} malformed result rows"
    elif not isinstance(errors, list) or errors:
        reason = (f"semgrep recorded {len(errors)} scan errors" if isinstance(errors, list)
                  else "semgrep returned malformed scan-error metadata")
    if reason is None:
        return rows, None
    error = AnalyzerExecutionError(reason + f"; {len(rows)} valid observations retained; coverage remains incomplete")
    recorded = copy.deepcopy(diagnostic)
    recorded["scanner_diagnostic"] = _semgrep_scanner_diagnostic(data, err, rc, malformed, len(rows))
    error.runtime_diagnostic = recorded
    from backend import analyzer_resources as resource_policy
    policy = resource_policy.selected_tool("semgrep")
    if policy is None:
        policy = next(row for row in resource_policy.snapshot_policy({})["tools"] if row["id"] == "semgrep")
    metadata = resource_policy.task_resource_metadata("semgrep", policy, str(error), failed=True, diagnostic=recorded)
    if not owned_failure:
        metadata["resource_policy"]["state"] = "execution_failed"
    for key, value in metadata.items():
        setattr(error, key, value)
    error.partial_semgrep_results = rows
    return rows, error


_SEMGREP_CONFIGS = os.environ.get(
    "LOTUS_SEMGREP_CONFIGS",
    "p/security-audit,p/owasp-top-ten,p/command-injection,p/insecure-transport",
).split(",")
# Explicit registry baseline works with metrics disabled. Semgrep rejects the
# dynamic "auto" configuration when --metrics=off; this pack is not claimed to
# be equivalent to repository-dependent auto selection.
SEMGREP_BASELINE_CONFIG = "p/default"


def semgrep_timeout(timeout=None):
    from backend.analyzer_resources import selected_tool, _env_int
    if timeout is not None:
        if type(timeout) is not int or not 1 <= timeout <= 7200:
            raise AnalyzerUnavailable("Semgrep execution timeout must be an integer from 1 to 7200 seconds")
        return timeout
    policy = selected_tool("semgrep")
    if policy and policy.get("effective", {}).get("timeout_seconds"):
        return policy["effective"]["timeout_seconds"]
    name = "LOTUS_SEMGREP_TIMEOUT" if os.environ.get("LOTUS_SEMGREP_TIMEOUT") else "LOTUS_EXT_ANALYZER_TIMEOUT"
    return _env_int(name, 420, 1, 7200)[0]


async def run_semgrep_auto(dest: Path, timeout: Optional[int] = None, repo_id: int = 0) -> List[dict]:
    """Compatibility entry point for the explicit, telemetry-disabled baseline."""
    return await _run_semgrep(dest, timeout, repo_id, auto=True)


async def run_semgrep_container(dest: Path, timeout: Optional[int] = None, repo_id: int = 0) -> List[dict]:
    return await _run_semgrep(dest, timeout, repo_id, auto=False)


async def _run_semgrep(dest: Path, timeout: Optional[int], repo_id: int, *, auto: bool) -> List[dict]:
    """Run the explicit baseline or curated packs with metrics disabled.

    Registry pack retrieval requires network access unless the selected runtime
    already has a usable cache. Retrieval failures remain coverage gaps.
    """
    use_k8s = await _use_k8s_runtime(repo_id)
    timeout = semgrep_timeout(timeout)
    semgrep_image = os.environ.get("LOTUS_SEMGREP_IMAGE", "").strip() or SEMGREP_IMAGE
    if use_k8s and not os.environ.get("LOTUS_SEMGREP_IMAGE", "").strip() and shutil.which("semgrep"):
        try:
            from backend.lab_selftest import _kubernetes_selftest_image
            semgrep_image = await _kubernetes_selftest_image(use_explicit_override=False)
        except (ValueError, OSError):
            # Outside the verified controller Pod, retain the configured
            # analyzer image; never infer an immutable image from a tag.
            pass
    args = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--jobs", "1"]
    if not auto:
        args += ["--timeout", "40", "--max-target-bytes", "2000000"]
    for cfg in ([SEMGREP_BASELINE_CONFIG] if auto else _SEMGREP_CONFIGS):
        cfg = cfg.strip()
        if cfg:
            args += ["--config", cfg]
    args += ["."]
    # The hardened runtime intentionally makes the root filesystem read-only
    # and runs as an arbitrary unprivileged uid. Semgrep otherwise tries to
    # create $HOME/.cache and fails before producing JSON. /tmp is a bounded
    # writable tmpfs supplied by the containment policy.
    cmd: Optional[List[str]] = None
    if not use_k8s:
        if not await _ensure_image(semgrep_image):
            raise AnalyzerUnavailable(f"Semgrep analyzer image unavailable: {semgrep_image}")
        cmd = _docker_run(
            semgrep_image, args, dest,
            extra=[
                "--network", "bridge",
                "-e", "HOME=/tmp",
                "-e", "XDG_CACHE_HOME=/tmp/.cache",
                "-e", "SEMGREP_SEND_METRICS=off",
            ],
            repo_id=repo_id,
        )
        if "--cpus" in cmd:
            cmd[cmd.index("--cpus") + 1] = "1"
    # k8s: run semgrep under sh so $HOME/.cache is writable; the registry pack
    # names and flags are shell-safe (no spaces or metacharacters).
    semgrep_script = "mkdir -p /tmp/.cache; " + shlex.join(args)
    failure = None
    diagnostic = {}
    try:
        out, err, rc = await _run_tool(
            use_k8s, repo_id, dest, "semgrep", semgrep_image, cmd,
            script=semgrep_script,
            env={"HOME": "/tmp", "XDG_CACHE_HOME": "/tmp/.cache", "SEMGREP_SEND_METRICS": "off"},
            timeout=timeout,
            diagnostic_sink=diagnostic.update,
        )
        rows, failure = semgrep_results(out, err, rc, runtime_diagnostic=diagnostic)
    except AnalyzerExecutionError as error:
        rows, failure = getattr(error, "partial_semgrep_results", []), error
    findings: List[dict] = []
    for r in rows:
        if auto:
            findings.append({"tool": "semgrep", "title": r["check_id"], "cvss": 6.5,
                "description": f"{r['extra'].get('message')} at {r['path']}:{r['start']['line']}",
                "file": _rel(r["path"], dest), "line": r["start"]["line"], "confidence": "medium"})
            continue
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        sev = str(extra.get("severity", "WARNING")).upper()
        cvss = {"ERROR": 7.5, "WARNING": 6.0, "INFO": 4.0}.get(sev, 6.0)
        # Prefer explicit CWE/OWASP-driven cvss bumps for priority classes.
        cwe = meta.get("cwe")
        cwe_s = " ".join(cwe) if isinstance(cwe, list) else str(cwe or "")
        if any(k in cwe_s for k in ("77", "78", "94", "502")):  # cmd/code inj, deser
            cvss = max(cvss, 8.5)
        elif any(k in cwe_s for k in ("287", "285", "862", "863")):  # authn/authz
            cvss = max(cvss, 8.0)
        findings.append({
            "tool": "semgrep",
            "title": r.get("check_id", "semgrep"),
            "cvss": cvss,
            "description": (
                f"{extra.get('message', '')[:400]} "
                f"[{cwe_s}]" if cwe_s else extra.get("message", "")[:400]
            ),
            "file": _rel(r.get("path", ""), dest),
            "line": (r.get("start", {}) or {}).get("line", 0) or 0,
            "confidence": str(meta.get("confidence", "medium")).lower() or "medium",
            "discovery_technique": "semgrep-registry",
            "qualification": "LATENT",
            "cwe": cwe_s or None,
        })
    if failure is not None:
        failure.partial_findings = findings
        raise failure
    return findings


# ---------------------------------------------------------------------------
# osv-scanner - lockfile CVE correlation across ecosystems
# ---------------------------------------------------------------------------
async def run_osv_scanner(dest: Path, timeout: int = _DEFAULT_TIMEOUT, repo_id: int = 0) -> List[dict]:
    use_k8s = await _use_k8s_runtime(repo_id)
    # osv-scanner returns rc=1 when vulns are found; that's expected.
    # osv-scanner v2.x requires the explicit "source" subcommand and writes
    # structured JSON to stdout. The older v1 flat "scan" subcommand is gone.
    args = ["scan", "source", "--format", "json", "-r", "/src"]
    image_ok = not use_k8s and await _ensure_image(OSV_IMAGE)
    if not use_k8s and not image_ok:
        raise AnalyzerUnavailable(f"OSV scanner image unavailable: {OSV_IMAGE}")
    # Prepare a Docker command only for the explicitly selected backup path.
    cmd: Optional[List[str]] = None
    if image_ok:
        cmd = _docker_run(OSV_IMAGE, args, dest, extra=["--network", "bridge"], workdir="/src", repo_id=repo_id)
    # osv-scanner is distroless (no /bin/sh): direct entrypoint mode, with the
    # real exit code read from the terminated container.
    out, err, rc = await _run_tool(
        use_k8s, repo_id, dest, "osv-scanner", OSV_IMAGE, cmd,
        argv=args, timeout=timeout,
    )
    data = _safe_json(out)
    if rc == 128 and (data is None or isinstance(data, dict) and data.get("results") == []):
        from backend.analyzer_applicability import AnalyzerNotApplicable, osv_no_sources_scope
        from backend.analyzer_execution import invoke_analyzer
        scope = await invoke_analyzer(lambda: osv_no_sources_scope(dest, out, err, rc),
                                      repo_id=repo_id, name="osv-scanner applicability")
        if scope is not None:
            raise AnalyzerNotApplicable(scope["reason"], scope=scope)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise AnalyzerExecutionError(
            f"osv-scanner returned no usable JSON results (rc={rc}, output={out[-240:]!r}, stderr={err[-160:]!r})"
        )
    if rc not in (0, 1):
        raise AnalyzerExecutionError(f"osv-scanner exited {rc}: {err[-240:] or out[-240:]}")
    findings: List[dict] = []
    for res in data.get("results", []) or []:
        source = (res.get("source", {}) or {}).get("path", "")
        for pkg in res.get("packages", []) or []:
            info = pkg.get("package", {}) or {}
            name = info.get("name", "")
            ver = info.get("version", "")
            for vuln in pkg.get("vulnerabilities", []) or []:
                vid = vuln.get("id", "")
                aliases = ", ".join(vuln.get("aliases", [])[:4])
                summary = vuln.get("summary") or (vuln.get("details", "")[:140])
                findings.append({
                    "tool": "osv-scanner",
                    "title": f"Vulnerable dependency {name}@{ver} ({vid}{'/' + aliases if aliases else ''})",
                    "cvss": 7.0,
                    "description": f"{summary} Ecosystem package {name} {ver}.",
                    "file": _rel(source, dest),
                    "line": 0,
                    "confidence": "high",
                    "discovery_technique": "osv-lockfile",
                    "qualification": "LATENT",
                    "dependency": name,
                })
    return findings


# ---------------------------------------------------------------------------
# JSON parsing helpers
# ---------------------------------------------------------------------------
def _safe_json(text: str) -> Optional[dict]:
    text = (text or "").strip()
    if not text:
        return None
    # Some tools print warnings before the JSON body; find the first '{'.
    start = text.find("{")
    if start > 0:
        text = text[start:]
    try:
        return json.loads(text)
    except Exception:
        return None


def _iter_json_objects(text: str):
    """Yield JSON objects from a stream that may be JSONL or concatenated.

    govulncheck/staticcheck emit either one object per line or a pretty-printed
    stream of concatenated objects; handle both via a brace-depth scanner.
    """
    text = text or ""
    # Fast path: JSONL
    parsed_any = False
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
            parsed_any = True
        except Exception:
            parsed_any = False
            break
    if parsed_any:
        return
    # Fallback: brace-depth scan over the whole blob.
    depth = 0
    buf = []
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            buf.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            buf.append(ch)
            continue
        if ch == "{":
            depth += 1
            buf.append(ch)
        elif ch == "}":
            depth -= 1
            buf.append(ch)
            if depth == 0 and buf:
                chunk = "".join(buf).strip()
                buf = []
                try:
                    yield json.loads(chunk)
                except Exception:
                    pass
        elif depth > 0:
            buf.append(ch)
