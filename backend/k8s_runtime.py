"""Kubernetes runtime for ephemeral *run-to-completion* tool Jobs.

This complements :mod:`backend.k8s_lab` (which runs long-lived *service* Jobs for
the dynamic lab).  Static analyzers and other one-shot tools need a different
shape: mount the target source read-only, run a container to completion, capture
its stdout/stderr/exit-code, then tear the Job down.

Design decisions
----------------
* **Source delivery = per-audit PVC, copied once, mounted read-only.**  A single
  ``ReadWriteOnce`` PersistentVolumeClaim per audit is populated one time from
  the on-disk enrolled workspace (via ``kubectl cp``, which tar-streams), then
  mounted read-only into every tool Job.  This is faithful to exactly what the
  pipeline prepared (Lotus's harden/build-context edits, generated files, the
  phase-1 trace) and is efficient when many analyzers read the same tree.  On a
  single-node cluster (kind / Docker Desktop) RWO permits concurrent same-node
  pods; multi-node clusters need an RWX StorageClass (``LOTUS_K8S_STORAGE_CLASS``).
* **PodSecurity ``restricted`` compliant.**  The ``lotus`` namespace enforces the
  restricted standard, so every pod here runs non-root, drops all capabilities,
  sets ``seccompProfile=RuntimeDefault`` and disallows privilege escalation.
* **Faithful stream separation.**  ``kubectl logs`` merges stdout+stderr, which
  would corrupt JSON-on-stdout analyzers.  We run the tool under ``sh`` with its
  streams redirected to files and re-emit them base64-framed, so the caller gets
  the same ``(stdout, stderr, rc)`` contract as the Docker path.
* **k8s-native resource bounds.**  Every Job carries ``resources.requests/limits``
  so the scheduler accounts for reserved memory. Go analyzers reserve their
  full memory limit; other workloads and mismatched node/VM capacity can still
  cause node pressure. This is not a node-wide OOM guarantee.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import json
import inspect
import os
import re
import shutil
import stat
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from concurrent.futures import Future
from contextvars import ContextVar
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from backend import k8s_lab
from backend.k8s_lab import apply, get_json, namespace

# Process-local record of which audits already have a populated source PVC, so
# a scan with a dozen analyzers copies the tree exactly once.
_POPULATED: Dict[int, str] = {}
_SOURCE_LOCKS: Dict[tuple, threading.Lock] = {}
_SOURCE_LOCKS_GUARD = threading.Lock()
_SOURCE_ADMISSION_OWNERS: Dict[tuple, asyncio.Task] = {}
_SOURCE_RECEIPTS: Dict[tuple, dict] = {}
_SOURCE_INFLIGHT: Dict[tuple, tuple[str, Future]] = {}
# The pipeline can bind its normal task-update callback without a runtime→
# pipeline import cycle. Direct callers can pass send= instead.
TOOL_PROGRESS: ContextVar = ContextVar("kubernetes_tool_progress", default=None)
TOOL_TASK: ContextVar = ContextVar("kubernetes_tool_task", default=None)


class KubernetesSourceUnavailable(RuntimeError):
    """Source delivery failed before any analyzer was admitted."""


def _source_key(repo_id: int) -> tuple:
    return (namespace(), tuple(k8s_lab._context_args()), os.environ.get("KUBECONFIG", ""), int(repo_id))


def source_admission_owned(repo_id: int) -> bool:
    """True only for the exact task holding this source's admission lock."""
    try:
        task = asyncio.current_task()
    except RuntimeError:
        return False
    with _SOURCE_LOCKS_GUARD:
        return task is not None and _SOURCE_ADMISSION_OWNERS.get(_source_key(repo_id)) is task


@asynccontextmanager
async def _source_admission(repo_id: int, timeout: int):
    # Audits can use different event loops/threads. An asyncio.Lock alone is
    # insufficient; acquire this process-local lock without blocking any loop.
    key = _source_key(repo_id)
    with _SOURCE_LOCKS_GUARD:
        lock = _SOURCE_LOCKS.setdefault(key, threading.Lock())
    deadline = asyncio.get_running_loop().time() + max(1, timeout)
    while not lock.acquire(blocking=False):
        if asyncio.get_running_loop().time() >= deadline:
            raise KubernetesSourceUnavailable("Kubernetes source delivery timed out waiting for the current upload")
        await asyncio.sleep(0.05)
    with _SOURCE_LOCKS_GUARD:
        _SOURCE_ADMISSION_OWNERS[key] = asyncio.current_task()
    try:
        yield key
    finally:
        with _SOURCE_LOCKS_GUARD:
            _SOURCE_ADMISSION_OWNERS.pop(key, None)
        lock.release()


def _source_tree_identity(dest: Path, size: str) -> str:
    """Bound traversal and refuse unsupported input before tar-streaming it."""
    from backend.proof_receipts import content_tree_digest
    if not dest.is_dir():
        raise KubernetesSourceUnavailable("Kubernetes source directory is unavailable")
    try:
        byte_limit = min(_mem_to_bytes(size), int(os.environ.get("LOTUS_K8S_SOURCE_MAX_BYTES", str(2 * 1024**3))))
        file_limit = int(os.environ.get("LOTUS_K8S_SOURCE_MAX_FILES", "200000"))
    except ValueError as exc:
        raise KubernetesSourceUnavailable("Invalid Kubernetes source transfer limit") from exc
    if byte_limit <= 0 or file_limit <= 0:
        raise KubernetesSourceUnavailable("Kubernetes source transfer limits must be positive")
    total = count = 0
    def fail_walk(error):
        raise KubernetesSourceUnavailable("Kubernetes source tree could not be read") from error
    for directory, dirs, files in os.walk(dest, followlinks=False, onerror=fail_walk):
        for name in dirs + files:
            path = Path(directory, name)
            info = path.lstat()
            count += 1
            if stat.S_ISLNK(info.st_mode):
                if not path.resolve().is_relative_to(dest):
                    raise KubernetesSourceUnavailable("Kubernetes source contains a link outside its source directory")
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
            elif not stat.S_ISDIR(info.st_mode):
                raise KubernetesSourceUnavailable("Kubernetes source contains an unsupported special file")
            if total > byte_limit or count > file_limit:
                raise KubernetesSourceUnavailable("Kubernetes source exceeds its configured transfer byte/file budget")
    identity = content_tree_digest(dest)
    if not identity:
        raise KubernetesSourceUnavailable("Kubernetes source identity could not be verified")
    return identity


def source_volume_identity(repo_id: int) -> dict:
    """Recorded immutable ownership for teardown/checkpointing; no source data."""
    receipt = _SOURCE_RECEIPTS.get(_source_key(repo_id)) or {}
    return {key: receipt[key] for key in ("provider", "repo_id", "name", "namespace", "uid", "owner", "source_tree_hash") if key in receipt}


async def _source_read(kind: str, name: str) -> Optional[dict]:
    document, rc, text = await get_json(kind, name, timeout=20)
    if rc and "notfound" in str(text).lower().replace(" ", ""):
        return None
    if rc or not isinstance(document, dict) or not (document.get("metadata") or {}).get("uid"):
        raise KubernetesSourceUnavailable(f"Kubernetes {kind} inspection failed: {str(text)[-400:]}")
    return document


def _source_owned(document: dict, receipt: dict, *, role: str, name: str) -> bool:
    meta = document.get("metadata") or {}
    labels = meta.get("labels") or {}
    return (meta.get("name") == name and meta.get("namespace") == receipt["namespace"]
            and labels.get("role") == role and labels.get("lotus.io/repo-id") == str(receipt["repo_id"])
            and labels.get("lotus.io/source-owner") == receipt["owner"])


async def _delete_source_owned(kind: str, name: str, receipt: dict, *, role: str, uid: str = "") -> None:
    from backend.reset_runtime_ownership import delete_k8s_uid
    document = await _source_read(kind, name)
    if document is None:
        return
    actual_uid = document["metadata"]["uid"]
    if not _source_owned(document, receipt, role=role, name=name) or (uid and actual_uid != uid):
        raise KubernetesSourceUnavailable(f"Kubernetes {kind} cleanup refused: recorded ownership changed")
    await delete_k8s_uid(kind, name, receipt["namespace"], actual_uid)

def kubernetes_selected(repo_id: int = 0) -> bool:
    """Choose the execution boundary independently of cluster availability.

    An unavailable selected cluster is a tool failure, never permission to run
    source on the API host's Docker daemon. Parser-only callers have no audit
    identity and retain their existing local adapter behavior.
    """
    if int(repo_id or 0) <= 0:
        return False
    from backend.lab_provider import provider_name
    return provider_name() == "k8s-job"


async def use_k8s_runtime(repo_id: int = 0) -> bool:
    """Compatibility adapter for existing asynchronous tool dispatchers."""
    return kubernetes_selected(repo_id)


# Only stderr and the exit code are framed; the tool's stdout streams RAW and
# first, so a large JSON result is neither inflated ~33% by base64 nor lost to
# kubelet log rotation. The rc marker is the final line (survives head rotation).
_ERR_MARK = "===LOTUS_ERR_B64==="
_RC_MARK = "===LOTUS_RC:"


def _storage_class() -> str:
    return (os.environ.get("LOTUS_K8S_STORAGE_CLASS") or "").strip()


def source_pvc_name(repo_id: int) -> str:
    return f"lotus-src-{int(repo_id)}"


def _restricted_pod_security() -> Dict:
    """Pod-level securityContext satisfying PodSecurity ``restricted``."""
    return {
        "runAsNonRoot": True,
        "runAsUser": 1000,
        "runAsGroup": 1000,
        "fsGroup": 1000,
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _restricted_container_security(read_only_root: bool = True) -> Dict:
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": read_only_root,
        "capabilities": {"drop": ["ALL"]},
    }


# ---------------------------------------------------------------------------
# Namespace resource governance (the k8s-native replacement for the Docker VM
# memory admission gate). A LimitRange supplies default per-container
# requests/limits and a ResourceQuota bounds the namespace's aggregate CPU/memory
# so concurrent tool Jobs cannot overcommit the node into an OOM. It is sized
# from live node allocatable (adaptive to kind or a large prod cluster) and is
# fully overridable by env. Resource governance is optional, but required
# network policies must be installed and read back before each tool admission.
# ---------------------------------------------------------------------------
_GOVERNED: Dict[str, object] = {"done": False}
_LOGGER = logging.getLogger(__name__)


class KubernetesIsolationUnavailable(RuntimeError):
    """The selected cluster cannot establish the required tool policy."""


def _governance_enabled() -> bool:
    return (os.environ.get("LOTUS_K8S_GOVERNANCE") or "on").strip().lower() \
        not in ("0", "off", "false", "no")


def _mem_to_bytes(q: str) -> int:
    """Parse a Kubernetes memory quantity ('8148012Ki', '2Gi', '512M', '1e9')."""
    s = str(q).strip()
    if not s:
        return 0
    units = {"Ki": 1024, "Mi": 1024 ** 2, "Gi": 1024 ** 3, "Ti": 1024 ** 4,
             "K": 1000, "M": 1000 ** 2, "G": 1000 ** 3, "T": 1000 ** 4, "k": 1000}
    for suf, mult in units.items():
        if s.endswith(suf):
            try:
                return int(float(s[:-len(suf)]) * mult)
            except ValueError:
                return 0
    try:
        return int(float(s))
    except ValueError:
        return 0


def _cpu_to_millicores(q: str) -> int:
    s = str(q).strip()
    if not s:
        return 0
    try:
        if s.endswith("m"):
            return int(float(s[:-1]))
        if s.endswith("n"):
            return int(float(s[:-1]) / 1_000_000)
        return int(float(s) * 1000)
    except ValueError:
        return 0


def _fmt_mem_mib(nbytes: int) -> str:
    return f"{max(1, int(nbytes // (1024 * 1024)))}Mi"


def _fmt_cpu_m(millicores: int) -> str:
    return f"{max(1, int(millicores))}m"


async def _node_allocatable() -> Tuple[int, int]:
    """Best-effort (total_cpu_millicores, total_mem_bytes) across nodes."""
    doc, rc, _ = await get_json("nodes", timeout=20)
    if rc != 0 or not isinstance(doc, dict):
        return 0, 0
    cpu_m = 0
    mem_b = 0
    for node in doc.get("items") or []:
        alloc = (node.get("status") or {}).get("allocatable") or {}
        cpu_m += _cpu_to_millicores(str(alloc.get("cpu") or "0"))
        mem_b += _mem_to_bytes(str(alloc.get("memory") or "0"))
    return cpu_m, mem_b


def _frac(env_key: str, default: str) -> float:
    try:
        return max(0.05, min(8.0, float(os.environ.get(env_key, default))))
    except ValueError:
        return float(default)


def _governance_manifests(cpu_m: int, mem_b: int) -> List[Dict]:
    ns = namespace()
    labels = {"app": "lotus", "lotus.io/governance": "true"}
    # Defaults so any pod that omits resources still satisfies the ResourceQuota
    # (a quota on requests/limits otherwise rejects such pods at admission).
    limitrange = {
        "apiVersion": "v1", "kind": "LimitRange",
        "metadata": {"name": "lotus-defaults", "namespace": ns, "labels": labels},
        "spec": {"limits": [{
            "type": "Container",
            "default": {"cpu": os.environ.get("LOTUS_K8S_DEFAULT_CPU_LIMIT", "2"),
                        "memory": os.environ.get("LOTUS_K8S_DEFAULT_MEM_LIMIT", "2Gi")},
            "defaultRequest": {"cpu": os.environ.get("LOTUS_K8S_DEFAULT_CPU_REQUEST", "250m"),
                               "memory": os.environ.get("LOTUS_K8S_DEFAULT_MEM_REQUEST", "256Mi")},
        }]},
    }
    manifests = [limitrange]
    explicit = [os.environ.get(key, "").strip() for key in (
        "LOTUS_K8S_QUOTA_LIMITS_MEM", "LOTUS_K8S_QUOTA_REQUESTS_MEM",
        "LOTUS_K8S_QUOTA_LIMITS_CPU", "LOTUS_K8S_QUOTA_REQUESTS_CPU")]
    if (mem_b > 0 and cpu_m > 0) or all(explicit):
        # Quota counts Pending pods too. Allow a normal analyzer backlog while
        # the scheduler admits only requests that fit node allocatable. Complete
        # explicit quotas also work with the narrow controller RBAC (no Nodes).
        # Kubernetes validates operator-supplied quantities at apply time.
        lim_mem = os.environ.get("LOTUS_K8S_QUOTA_LIMITS_MEM") or _fmt_mem_mib(int(mem_b * _frac("LOTUS_K8S_QUOTA_MEM_FRACTION", "3.0")))
        req_mem = os.environ.get("LOTUS_K8S_QUOTA_REQUESTS_MEM") or _fmt_mem_mib(int(mem_b * _frac("LOTUS_K8S_QUOTA_REQ_FRACTION", "3.0")))
        lim_cpu = os.environ.get("LOTUS_K8S_QUOTA_LIMITS_CPU") or _fmt_cpu_m(int(cpu_m * _frac("LOTUS_K8S_QUOTA_CPU_LIMIT_FRACTION", "4.0")))
        req_cpu = os.environ.get("LOTUS_K8S_QUOTA_REQUESTS_CPU") or _fmt_cpu_m(int(cpu_m * _frac("LOTUS_K8S_QUOTA_CPU_REQ_FRACTION", "1.5")))
        manifests.append({
            "apiVersion": "v1", "kind": "ResourceQuota",
            "metadata": {"name": "lotus-compute", "namespace": ns, "labels": labels},
            "spec": {"hard": {
                "requests.cpu": req_cpu, "requests.memory": req_mem,
                "limits.cpu": lim_cpu, "limits.memory": lim_mem,
                "pods": str(os.environ.get("LOTUS_K8S_QUOTA_PODS", "24")),
            }},
        })
    return manifests


def _tool_network_policies() -> List[Dict]:
    """Static NetworkPolicies for tool-job pods (enforced by a NP-capable CNI).

    ``default-deny`` denies all ingress and egress for every tool pod; the
    additive ``egress-web`` reopens DNS + HTTP(S) for pods labelled
    ``lotus.io/egress=web`` (set when ``allow_egress`` is requested), so a tool
    that does not need the network gets no egress at all. Inert on CNIs that do
    not enforce NetworkPolicy (e.g. kindnet), correct on Calico/Cilium.
    """
    ns = namespace()
    labels = {"app": "lotus", "lotus.io/governance": "true"}
    deny = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "lotus-tool-default-deny", "namespace": ns, "labels": labels},
        "spec": {"podSelector": {"matchLabels": {"role": "tool-job"}},
                 "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []},
    }
    web = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "lotus-tool-egress-web", "namespace": ns, "labels": labels},
        "spec": {"podSelector": {"matchLabels": {"role": "tool-job", "lotus.io/egress": "web"}},
                 "policyTypes": ["Egress"],
                 "egress": [
                     {"ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
                     {"ports": [{"protocol": "TCP", "port": 80}, {"protocol": "TCP", "port": 443}]},
                 ]},
    }
    return [deny, web]


async def ensure_namespace_governance() -> None:
    """Verify tool isolation on every admission, then best-effort resource limits.

    A previous success never bypasses policy checks: an operator may have
    removed a policy or changed namespace/context since the preceding Job.
    Policy presence is a prerequisite, not proof of CNI traffic enforcement.
    LOTUS_K8S_GOVERNANCE disables only the optional quota/LimitRange setup.
    """
    _GOVERNED["done"] = False
    for manifest in _tool_network_policies():
        name = manifest["metadata"]["name"]
        try:
            output, rc = await apply(manifest, timeout=30)
            if rc != 0:
                raise KubernetesIsolationUnavailable(f"Required tool NetworkPolicy {name} apply failed: {output[-500:]}")
            observed, rc, output = await get_json("networkpolicy", name, timeout=20)
            expected = manifest["spec"]
            metadata, spec = observed.get("metadata") or {}, observed.get("spec") or {}
            if (rc != 0 or observed.get("kind") != "NetworkPolicy"
                    or metadata.get("name") != name or metadata.get("namespace") != manifest["metadata"]["namespace"]
                    or spec.get("podSelector") != expected["podSelector"]
                    or set(spec.get("policyTypes") or []) != set(expected["policyTypes"])
                    or (spec.get("ingress") or []) != expected.get("ingress", [])
                    or (spec.get("egress") or []) != expected.get("egress", [])):
                raise KubernetesIsolationUnavailable(f"Required tool NetworkPolicy {name} read-back did not match the isolation contract")
        except asyncio.CancelledError:
            raise
        except KubernetesIsolationUnavailable:
            raise
        except Exception as exc:
            raise KubernetesIsolationUnavailable(f"Required tool NetworkPolicy {name} could not be verified: {str(exc)[:300]}") from exc
    _GOVERNED["done"] = True
    scope = (namespace(), tuple(k8s_lab._context_args()))
    if not _governance_enabled() or _GOVERNED.get("resources_scope") == scope:
        return
    try:
        cpu_m, mem_b = await _node_allocatable()
    except Exception:
        # The controller intentionally has no cluster-wide Node permission.
        # Explicit per-Job resources and the LimitRange still bound each pod.
        cpu_m, mem_b = 0, 0
    resource_ok = True
    resource_manifests = _governance_manifests(cpu_m, mem_b)
    if not any(item["kind"] == "ResourceQuota" for item in resource_manifests):
        _LOGGER.info("No generated Kubernetes ResourceQuota: node allocatable is unavailable; "
                     "provision a namespace quota or set all four LOTUS_K8S_QUOTA_{REQUESTS,LIMITS}_{CPU,MEM} values")
    for manifest in resource_manifests:
        try:
            output, rc = await apply(manifest, timeout=30)
            if rc != 0:
                resource_ok = False
                _LOGGER.warning("Optional Kubernetes %s unavailable: %s", manifest["kind"], output[-300:])
        except Exception as exc:
            resource_ok = False
            _LOGGER.warning("Optional Kubernetes %s unavailable: %s", manifest["kind"], str(exc)[:300])
    if resource_ok:
        _GOVERNED["resources_scope"] = scope


def _pvc_manifest(repo_id: int, size: str) -> Dict:
    spec: Dict = {
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": size}},
    }
    sc = _storage_class()
    if sc:
        spec["storageClassName"] = sc
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": source_pvc_name(repo_id),
            "namespace": namespace(),
            "labels": {"lotus.io/repo-id": str(int(repo_id)), "role": "tool-source"},
        },
        "spec": spec,
    }


def _populator_pod(repo_id: int, pod_name: str) -> Dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": namespace(),
            "labels": {"lotus.io/repo-id": str(int(repo_id)), "role": "tool-source-populator"},
        },
        "spec": {
            "automountServiceAccountToken": False,
            "securityContext": _restricted_pod_security(),
            "restartPolicy": "Never",
            "activeDeadlineSeconds": int(os.environ.get("LOTUS_K8S_POPULATE_DEADLINE", "600")),
            "containers": [{
                "name": "pop",
                "image": str(os.environ.get("LOTUS_K8S_POPULATOR_IMAGE") or "alpine:3.20"),
                # Idle while we tar-stream the workspace in; a short TTL bounds it.
                "command": ["sh", "-c", "sleep 600"],
                "securityContext": _restricted_container_security(read_only_root=False),
                "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                              "limits": {"cpu": "1", "memory": "512Mi"}},
                "volumeMounts": [{"name": "src", "mountPath": "/src"}],
            }],
            "volumes": [{"name": "src", "persistentVolumeClaim": {"claimName": source_pvc_name(repo_id)}}],
        },
    }


async def _wait_pod_phase(pod_name: str, phases: Tuple[str, ...], *, timeout: int) -> Tuple[str, Dict]:
    deadline = asyncio.get_running_loop().time() + max(3, timeout)
    last: Dict = {}
    while asyncio.get_running_loop().time() < deadline:
        doc, rc, _ = await get_json("pod", pod_name, timeout=20)
        if rc == 0 and isinstance(doc, dict):
            last = doc
            phase = str((doc.get("status") or {}).get("phase") or "")
            if phase in phases:
                return phase, doc
            if phase == "Failed" and "Failed" not in phases:
                return phase, doc
        await asyncio.sleep(1.0)
    return "timeout", last


async def ensure_source_pvc(repo_id: int, dest: Path, send=None, *,
                            size: Optional[str] = None, timeout: int = 300) -> Optional[str]:
    """Deliver one verified source per provider/repository; failures retain their cause.

    Waiting callers share the completed upload. Cancelling a waiter does not
    cancel its owner; cancelling the owner drains its owned resources before
    another caller can retry. An existing unknown PVC is never overwritten.
    """
    key, source = _source_key(repo_id), str(Path(dest).resolve())
    with _SOURCE_LOCKS_GUARD:
        flight = _SOURCE_INFLIGHT.get(key)
        owner = flight is None
        if owner:
            flight = (source, Future())
            _SOURCE_INFLIGHT[key] = flight
    if flight[0] != source:
        raise KubernetesSourceUnavailable("A different source directory is already being delivered for this repository")
    if not owner:
        # Shield the shared result: cancelling one analyzer cannot cancel an
        # upload still needed by the remaining analyzers, even across loops.
        try:
            return await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(flight[1])), timeout=max(1, timeout))
        except asyncio.TimeoutError as exc:
            raise KubernetesSourceUnavailable("Kubernetes source delivery timed out waiting for the current upload") from exc
    try:
        result = await _ensure_source_pvc(repo_id, Path(source), send, size=size, timeout=timeout)
        flight[1].set_result(result)
        return result
    except BaseException as exc:
        flight[1].set_exception(KubernetesSourceUnavailable("Kubernetes source upload owner was cancelled; retry required")
                                if isinstance(exc, asyncio.CancelledError) else exc)
        raise
    finally:
        with _SOURCE_LOCKS_GUARD:
            _SOURCE_INFLIGHT.pop(key, None)


async def _ensure_source_pvc(repo_id: int, dest: Path, send, *, size: Optional[str], timeout: int) -> str:
    from backend.source_volume_ownership import cleanup_owned_source, load_source_receipt, remove_source_receipt, save_source_receipt
    async with _source_admission(repo_id, timeout) as key:
        await ensure_namespace_governance()
        dest = Path(dest).resolve()
        size = size or str(os.environ.get("LOTUS_K8S_SRC_PVC_SIZE") or "8Gi")
        try:
            tree_hash = await asyncio.to_thread(_source_tree_identity, dest, size)
            pvc = source_pvc_name(repo_id)
            prior = await _source_read("persistentvolumeclaim", pvc)
            durable = load_source_receipt(repo_id)
            cached = _SOURCE_RECEIPTS.get(key)
            if cached and cached.get("ready"):
                if prior is not None:
                    if cached["source_path"] != str(dest) or cached["source_tree_hash"] != tree_hash:
                        raise KubernetesSourceUnavailable("Kubernetes source identity changed; stop the previous audit's owned source volume before retrying")
                    if (not _source_owned(prior, cached, role="tool-source", name=pvc)
                            or prior["metadata"]["uid"] != cached["uid"]
                            or (prior["metadata"].get("annotations") or {}).get("lotus.io/source-tree") != tree_hash
                            or not durable or any(durable.get(field) != cached.get(field) for field in ("uid", "owner", "source_tree_hash"))):
                        raise KubernetesSourceUnavailable("Kubernetes source volume identity changed; cached volume cannot be reused")
                    _POPULATED[repo_id] = pvc
                    return pvc
                _SOURCE_RECEIPTS.pop(key, None)
                _POPULATED.pop(repo_id, None)
            if durable:
                # Durable ownership permits verified stale cleanup, never
                # source reuse: a restarted controller must upload afresh.
                await cleanup_owned_source(durable, caller_holds_admission=True)
                prior = None
            if prior is not None:
                raise KubernetesSourceUnavailable("Kubernetes source volume already exists without a current verified source binding; owned cleanup is required")
            receipt = {"provider": "k8s-job", "repo_id": int(repo_id), "name": pvc, "namespace": namespace(),
                       "owner": uuid.uuid4().hex, "source_tree_hash": tree_hash, "source_path": str(dest), "ready": False}
            pod_name = f"lotus-src-pop-{int(repo_id)}-{uuid.uuid4().hex[:6]}"
            created = False
            success = False
            pod_uid = ""
            guard = None
            from backend import k8s_network_guard
            try:
                manifest = _pvc_manifest(repo_id, size)
                manifest["metadata"]["labels"]["lotus.io/source-owner"] = receipt["owner"]
                manifest["metadata"]["annotations"] = {"lotus.io/source-tree": tree_hash}
                # Create, rather than apply, cannot adopt an object created by
                # another controller between the read and this request.
                created = True  # request completion can be ambiguous on cancellation
                out, rc = await k8s_lab._run(["create", "-f", "-"], input_data=json.dumps(manifest).encode(), timeout=60)
                if rc:
                    raise KubernetesSourceUnavailable(f"Kubernetes source PVC create failed: {out[-500:]}")
                document = await _source_read("persistentvolumeclaim", pvc)
                if not document or not _source_owned(document, receipt, role="tool-source", name=pvc):
                    raise KubernetesSourceUnavailable("Kubernetes source PVC ownership could not be verified")
                receipt["uid"] = document["metadata"]["uid"]
                receipt = save_source_receipt(receipt)
                _SOURCE_RECEIPTS[key] = receipt
                populator = _populator_pod(repo_id, pod_name)
                populator["metadata"]["labels"]["lotus.io/source-owner"] = receipt["owner"]
                guard = await k8s_network_guard.prepare(populator, profile="isolated")
                populator = guard.manifest
                out, rc = await apply(populator, timeout=60)
                if rc:
                    raise KubernetesSourceUnavailable(f"Kubernetes source populator create failed: {out[-500:]}")
                await guard.release()
                phase, pod = await _wait_pod_phase(pod_name, ("Running",), timeout=min(timeout, 180))
                if phase != "Running":
                    status = pod.get("status") or {}
                    reasons = [str(c.get("reason") or "") + ": " + str(c.get("message") or "")
                               for c in status.get("conditions", []) if c.get("status") != "True"]
                    reasons += [str(c.get("state", {}).get("waiting") or c.get("state", {}).get("terminated") or "")
                                for c in status.get("containerStatuses", [])]
                    raise KubernetesSourceUnavailable(f"Kubernetes source populator not Running ({phase}): {'; '.join(reasons)[-500:]}")
                if not _source_owned(pod, receipt, role="tool-source-populator", name=pod_name) or not pod.get("metadata", {}).get("uid"):
                    raise KubernetesSourceUnavailable("Kubernetes source populator ownership could not be verified")
                pod_uid = pod["metadata"]["uid"]
                # The original workspace remains read-only to this function.
                out, rc = await k8s_lab._run(["cp", f"{dest}/.", f"{receipt['namespace']}/{pod_name}:/src", "-c", "pop"], timeout=timeout)
                if rc:
                    raise KubernetesSourceUnavailable(f"Kubernetes source upload failed: {out[-500:]}")
                if await asyncio.to_thread(_source_tree_identity, dest, size) != tree_hash:
                    raise KubernetesSourceUnavailable("Kubernetes source changed during upload; partial source will not be used")
                pod = await _source_read("pod", pod_name)
                if not pod or pod["metadata"]["uid"] != pod_uid or not _source_owned(pod, receipt, role="tool-source-populator", name=pod_name):
                    raise KubernetesSourceUnavailable("Kubernetes source populator changed during upload")
                document = await _source_read("persistentvolumeclaim", pvc)
                if (not document or not _source_owned(document, receipt, role="tool-source", name=pvc)
                        or document["metadata"]["uid"] != receipt["uid"]):
                    raise KubernetesSourceUnavailable("Kubernetes source PVC changed during upload")
                success = True
            finally:
                async def cleanup():
                    errors = []
                    if created:
                        for kind, name, role, uid in ([("pod", pod_name, "tool-source-populator", pod_uid)]
                                + ([] if success else [("persistentvolumeclaim", pvc, "tool-source", receipt.get("uid", ""))])):
                            try:
                                await _delete_source_owned(kind, name, receipt, role=role, uid=uid)
                            except Exception as exc:
                                errors.append(str(exc))
                    try:
                        await k8s_network_guard.close(guard)
                    except Exception as exc:
                        errors.append(str(exc))
                    if errors:
                        _LOGGER.warning("Kubernetes source cleanup incomplete: %s", "; ".join(errors)[:600])
                        if send:
                            await send(repo_id, "Kubernetes source cleanup incomplete: " + "; ".join(errors)[:600], level="warning")
                    elif not success:
                        try:
                            remove_source_receipt(receipt)
                            _SOURCE_RECEIPTS.pop(key, None)
                        except Exception as exc:
                            errors.append(str(exc))
                    return errors
                cleanup_task = asyncio.create_task(cleanup())
                try:
                    cleanup_errors = await asyncio.shield(cleanup_task)
                except asyncio.CancelledError:
                    await cleanup_task
                    raise
                if success and cleanup_errors:
                    raise KubernetesSourceUnavailable("Kubernetes source upload completed but populator cleanup is incomplete")
            receipt = save_source_receipt({**receipt, "ready": True})
            _SOURCE_RECEIPTS[key] = receipt
            _POPULATED[repo_id] = pvc
            if send:
                await send(repo_id, f"Kubernetes source volume ready ({pvc})", level="info")
            return pvc
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = exc if isinstance(exc, KubernetesSourceUnavailable) else KubernetesSourceUnavailable("Kubernetes source delivery failed: " + str(exc)[:500])
            _LOGGER.warning("%s", error)
            if send:
                await send(repo_id, str(error), level="warning")
            raise error


_CACHE_PVCS: Dict[str, bool] = {}


async def ensure_cache_pvc(name: str, *, size: str, timeout: int = 60) -> Optional[str]:
    """Create (once) a persistent, cross-audit writable cache PVC; return its name.

    Unlike the per-audit source PVC this is not populated and not torn down at
    audit end -- it is the k8s equivalent of a named Docker cache volume (e.g.
    the shared Go module/build cache). RWO permits concurrent same-node pods on
    single-node clusters; a multi-node cluster needs an RWX StorageClass. Returns
    ``None`` on failure so callers can fall back to an ephemeral emptyDir cache.
    """
    safe = re.sub(r"[^a-z0-9-]", "-", str(name).lower()).strip("-")[:63] or "lotus-cache"
    if _CACHE_PVCS.get(safe):
        return safe
    spec: Dict = {"accessModes": ["ReadWriteOnce"],
                  "resources": {"requests": {"storage": size}}}
    sc = _storage_class()
    if sc:
        spec["storageClassName"] = sc
    manifest = {
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {"name": safe, "namespace": namespace(),
                     "labels": {"app": "lotus", "role": "tool-cache"}},
        "spec": spec,
    }
    out, rc = await apply(manifest, timeout=timeout)
    if rc != 0:
        return None
    _CACHE_PVCS[safe] = True
    return safe


def _capture_wrapper(script: str) -> str:
    """Wrap a tool script so stdout/stderr/rc survive kubectl-logs capture.

    The tool's stdout streams RAW and contiguous (no base64 inflation); stderr is
    redirected to a file and re-emitted base64-framed after a separator, and the
    exit code is written last so it survives even if the head of a very large log
    is rotated away by the kubelet.
    """
    return (
        "( " + script + " ) 2>/tmp/lotus.err; rc=$?; "
        "echo ''; echo '" + _ERR_MARK + "'; "
        "base64 /tmp/lotus.err 2>/dev/null || true; "
        "echo \"" + _RC_MARK + "$rc===\""
    )


def _parse_captured(logs: str) -> Tuple[str, str, int]:
    """Reconstruct (stdout, stderr, rc) from raw-stdout framed pod logs."""
    # Only the terminal footer is authoritative. Source-derived output can
    # contain marker-like strings; it must never supply the command's status.
    footer = re.search(r"(?m)^" + re.escape(_RC_MARK) + r"(\d+)===(?:\n)?\Z", logs)
    err_i = logs.rfind("\n" + _ERR_MARK + "\n", 0, footer.start() if footer else len(logs))
    if footer is None or err_i < 0:
        return "", "Kubernetes tool output has an incomplete completion frame", -1
    stdout = logs[:err_i]
    err_start = err_i + len("\n" + _ERR_MARK + "\n")
    err_chunk = logs[err_start:footer.start()]
    try:
        stderr = base64.b64decode("".join(err_chunk.split()), validate=True).decode(errors="replace")
    except (ValueError, binascii.Error):
        return "", "Kubernetes tool output has a malformed stderr completion frame", -1
    return stdout, stderr, int(footer.group(1))


def _tool_job(repo_id: int, job_name: str, image: str, *,
              command: Optional[List[str]] = None, args: Optional[List[str]] = None,
              workdir: str, allow_egress: bool, mem_limit: str, cpu_limit: str,
              mem_request: str, cpu_request: str, writable_paths: List[str],
              env: Optional[Dict[str, str]], timeout: int,
              cache_pvc: Optional[Tuple[str, str]] = None, queue_timeout: int = 0) -> Dict:
    volume_mounts = [
        {"name": "src", "mountPath": "/src", "readOnly": True},
        {"name": "tmp", "mountPath": "/tmp"},
    ]
    volumes = [
        {"name": "src", "persistentVolumeClaim": {"claimName": source_pvc_name(repo_id), "readOnly": True}},
        {"name": "tmp", "emptyDir": {"sizeLimit": "1Gi"}},
    ]
    scratch_override = os.environ.get("LOTUS_K8S_SCRATCH_SIZE")
    for idx, path in enumerate(writable_paths or []):
        vname = f"scratch{idx}"
        volume_mounts.append({"name": vname, "mountPath": path})
        # Full Go package analysis needs both module/build caches and temporary
        # compiler output. A cold large-repository run exceeded 12 GiB before
        # those temporary files cleared. Keep caches private and bounded;
        # smaller explicit operator limits remain authoritative.
        scratch_size = str(scratch_override or ("24Gi" if path == "/go" else "6Gi"))
        volumes.append({"name": vname, "emptyDir": {"sizeLimit": scratch_size}})
    # Optional persistent, cross-audit writable cache (e.g. the shared Go module
    # cache): a named RWO PVC mounted read-write. Unlike the per-audit scratch
    # emptyDirs it survives Job/pod teardown, so module downloads and build
    # artifacts are reused by later harnesses and later audits.
    if cache_pvc:
        claim, mount_path = cache_pvc
        volume_mounts.append({"name": "cache", "mountPath": mount_path})
        volumes.append({"name": "cache", "persistentVolumeClaim": {"claimName": claim}})
    container = {
        "name": "tool",
        "image": image,
        "workingDir": workdir,
        "securityContext": _restricted_container_security(read_only_root=True),
        "resources": {"requests": {"cpu": cpu_request, "memory": mem_request},
                      "limits": {"cpu": cpu_limit, "memory": mem_limit}},
        "volumeMounts": volume_mounts,
    }
    if env:
        container["env"] = [{"name": str(k), "value": str(v)} for k, v in env.items()]
    # A shell wrapper (stream/rc capture) sets ``command``; a distroless tool
    # (e.g. osv-scanner, no /bin/sh) keeps its image ENTRYPOINT and receives
    # ``args``, with the real exit code read from the terminated container.
    if command is not None:
        container["command"] = command
    if args is not None:
        container["args"] = args
    labels = {"role": "tool-job", "lotus.io/repo-id": str(int(repo_id)), "lotus.io/job": job_name}
    if allow_egress:
        # Opt into the additive egress-web NetworkPolicy; without this label the
        # default-deny policy leaves the pod with no network at all.
        labels["lotus.io/egress"] = "web"
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": job_name, "namespace": namespace(), "labels": labels},
        "spec": {
            "backoffLimit": 0,
            # The Job can start before apply's successful response (bounded at
            # 60s). Include that interval plus 30s polling grace so this cluster
            # backstop does not shorten the controller's observed budgets.
            "activeDeadlineSeconds": int(timeout) + int(queue_timeout) + (90 if queue_timeout else 0),
            "ttlSecondsAfterFinished": 120,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": _restricted_pod_security(),
                    "restartPolicy": "Never",
                    "containers": [container],
                    "volumes": volumes,
                },
            },
        },
    }


def _terminated_exit_code(pod: Dict) -> Optional[int]:
    for status in (pod.get("status") or {}).get("containerStatuses") or []:
        term = ((status.get("state") or {}).get("terminated") or {})
        if "exitCode" in term:
            try:
                return int(term.get("exitCode") or 0)
            except (TypeError, ValueError):
                return None
    return None


class KubernetesToolLogsUnavailable(RuntimeError):
    """A complete bounded tool output could not be collected."""


class KubernetesToolCleanupError(RuntimeError):
    """The original tool runtime could not be proved absent."""


async def _read_owned_tool_job(manifest, ownership):
    name = manifest["metadata"]["name"]
    document, rc, raw = await get_json("job", name, timeout=5)
    if rc and "notfound" in str(raw).lower().replace(" ", ""):
        return None
    meta = document.get("metadata") or {}
    if (rc or document.get("kind") != "Job" or not meta.get("uid")
            or meta.get("name") != name or meta.get("namespace") != manifest["metadata"]["namespace"]
            or any((meta.get("labels") or {}).get(key) != value
                   for key, value in manifest["metadata"]["labels"].items())
            or (ownership.get("uid") and meta["uid"] != ownership["uid"])):
        raise KubernetesToolCleanupError("Kubernetes tool Job ownership is unavailable or changed; replacement retained")
    ownership["uid"] = meta["uid"]
    return document


def _remember_owned_tool_pod(manifest, ownership, pod):
    if not pod or (not pod.get("metadata") and not pod.get("status")):
        return
    meta = manifest["metadata"]
    pm = pod.get("metadata") or {}
    parents = [row for row in pm.get("ownerReferences") or []
               if row.get("kind") == "Job" and row.get("controller") is True and row.get("name") == meta["name"]]
    if (not pm.get("uid") or not pm.get("name") or pm.get("namespace") != meta["namespace"]
            or any((pm.get("labels") or {}).get(key) != value for key, value in meta["labels"].items())
            or len(parents) != 1 or not parents[0].get("uid")
            or (ownership.get("uid") and parents[0]["uid"] != ownership["uid"])):
        raise KubernetesToolCleanupError("Kubernetes tool Pod ownership changed; replacement retained")
    known = ownership.setdefault("pods", {})
    if pm["name"] in known and known[pm["name"]] != pm["uid"]:
        raise KubernetesToolCleanupError("Kubernetes tool Pod name was reused; replacement retained")
    if len(known) >= 16 and pm["name"] not in known:
        raise KubernetesToolCleanupError("Kubernetes tool Pod ownership inventory exceeded its bound")
    ownership["uid"] = parents[0]["uid"]
    known[pm["name"]] = pm["uid"]


async def _cleanup_tool_job(manifest, ownership):
    """Reconcile ambiguous creation, then remove only the original UIDs.

    The caller gives this entire operation a deadline. A failed API read or a
    still-live object is a cleanup gap, never evidence that memory was freed.
    """
    from backend.reset_runtime_ownership import delete_k8s_uid
    meta = manifest["metadata"]
    deleted = set()
    while True:
        job = await _read_owned_tool_job(manifest, ownership)
        document, rc, _ = await get_json("pods", selector="lotus.io/tool-owner=" + meta["labels"]["lotus.io/tool-owner"], timeout=5)
        pods = document.get("items")
        if rc or not isinstance(pods, list) or len(pods) > 16:
            raise KubernetesToolCleanupError("Kubernetes tool Pod absence could not be verified")
        # Known UIDs must be checked by name too: a changed/removed label must
        # not make a surviving Pod invisible to the selector's absence check.
        found = {((row.get("metadata") or {}).get("name")) for row in pods}
        for name in ownership.get("pods", {}):
            if name not in found:
                pod, rc, raw = await get_json("pod", name, timeout=5)
                if rc and "notfound" in str(raw).lower().replace(" ", ""):
                    continue
                if rc or not pod:
                    raise KubernetesToolCleanupError("Recorded Kubernetes tool Pod absence could not be verified")
                pods.append(pod)
        selected = []
        for pod in pods:
            _remember_owned_tool_pod(manifest, ownership, pod)
            pm = pod.get("metadata") or {}
            selected.append(("pod", pm["name"], pm["uid"]))
        if job is None and not selected:
            if ownership.get("apply_ambiguous") and not ownership.get("uid"):
                raise KubernetesToolCleanupError("Kubernetes tool creation outcome is ambiguous; no owned UID could be reconciled")
            return
        if job is not None:
            selected.insert(0, ("job", meta["name"], ownership["uid"]))
        for kind, name, uid in selected:
            if (kind, uid) not in deleted:
                await delete_k8s_uid(kind, name, meta["namespace"], uid)
                deleted.add((kind, uid))
        await asyncio.sleep(.2)


async def _drain_tool_operation(task):
    """Cancellation cannot abandon a bounded create/cleanup task or its CLI."""
    cancelled = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            if cancelled is None:
                cancelled = exc
        except Exception:
            break
    if cancelled is not None:
        try:
            task.result()
        except BaseException as exc:
            cancelled.cleanup_gap = "Kubernetes tool operation did not complete: " + type(exc).__name__
        raise cancelled
    return task.result()


async def _kubectl_logs(job_name: str, *, timeout: int = 60, max_bytes: int = 8_000_000) -> str:
    """Collect bounded logs; incomplete output must never become a tool result."""
    from backend.async_process import terminate_and_reap
    args = [k8s_lab.kubectl_binary(), *k8s_lab._context_args(),
            "logs", f"job/{job_name}", "-n", namespace(), "--tail=-1"]
    proc = None
    readers = []
    complete = False
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        async def read(stream, limit):
            result = bytearray()
            while chunk := await stream.read(min(65536, max(1, limit + 1 - len(result)))):
                if len(result) + len(chunk) > limit:
                    raise KubernetesToolLogsUnavailable(f"Kubernetes tool logs exceeded the {limit}-byte output limit; incomplete output discarded")
                result.extend(chunk)
            return result
        readers = [asyncio.create_task(read(proc.stdout, max_bytes)),
                   asyncio.create_task(read(proc.stderr, min(max_bytes, 65536)))]
        async def collect():
            out, err = await asyncio.gather(*readers)
            code = await proc.wait()
            if code:
                raise KubernetesToolLogsUnavailable("Kubernetes tool log collection failed: " + err[-1000:].decode(errors="replace"))
            return out
        out = await asyncio.wait_for(collect(), timeout=timeout)
        complete = True
        return out.decode(errors="replace")
    except asyncio.CancelledError:
        raise
    except asyncio.TimeoutError as exc:
        raise KubernetesToolLogsUnavailable(f"Kubernetes tool log collection timed out after {timeout}s; incomplete output discarded") from exc
    except KubernetesToolLogsUnavailable:
        raise
    except Exception as exc:
        raise KubernetesToolLogsUnavailable("Kubernetes tool log collection failed: " + str(exc)[:500]) from exc
    finally:
        if not complete:
            for reader in readers:
                reader.cancel()
            if readers:
                await asyncio.gather(*readers, return_exceptions=True)
            await terminate_and_reap(proc)


async def run_to_completion(repo_id: int, name: str, image: str, *,
                            script: Optional[str] = None, argv: Optional[List[str]] = None,
                            workdir: str = "/src", timeout: int = 900, queue_timeout: Optional[int] = None,
                            allow_egress: bool = False,
                            mem_limit: str = "4Gi", cpu_limit: str = "2",
                            mem_request: str = "512Mi", cpu_request: str = "500m",
                            writable_paths: Optional[List[str]] = None,
                            env: Optional[Dict[str, str]] = None,
                            cache_pvc: Optional[Tuple[str, str]] = None,
                            send=None, progress_stages: Optional[Dict[str, str]] = None,
                            observation_exit_codes: Tuple[int, ...] = (), diagnostic_sink=None) -> Tuple[str, str, int]:
    """Run a tool to completion in a Job; return (stdout, stderr, rc).

    Two modes mirror the Docker analyzer contract:

    * ``script`` runs via ``sh -c`` with stdout/stderr/rc framed in the logs, so
      JSON-on-stdout analyzers stay clean (shell-capable images).
    * ``argv`` keeps the image ENTRYPOINT (distroless tools like osv-scanner);
      stdout comes from the pod logs and ``rc`` from the terminated container's
      real exit code.

    Infrastructure failures return -1; queue/execution timeouts return 124.
    Queue time has a separate bounded budget and cannot consume execution time.
    """
    if script is None and argv is None:
        return "", "run_to_completion requires either script or argv", -1
    try:
        queue_timeout = _tool_queue_timeout(timeout, queue_timeout)
    except ValueError as exc:
        return "", str(exc), -1
    try:
        await ensure_namespace_governance()
    except KubernetesIsolationUnavailable as exc:
        return "", str(exc), -1
    safe = re.sub(r"[^a-z0-9-]", "-", str(name).lower())[:24].strip("-") or "tool"
    job_name = f"lotus-tool-{safe}-{int(repo_id)}-{uuid.uuid4().hex[:6]}"[:63]
    command = ["sh", "-c", _capture_wrapper(script)] if script is not None else None
    args = list(argv) if (script is None and argv is not None) else None
    manifest = _tool_job(
        repo_id, job_name, image, command=command, args=args,
        workdir=workdir, allow_egress=allow_egress,
        mem_limit=mem_limit, cpu_limit=cpu_limit, mem_request=mem_request,
        cpu_request=cpu_request, writable_paths=writable_paths or [], env=env, timeout=timeout,
        cache_pvc=cache_pvc, queue_timeout=queue_timeout,
    )
    owner = uuid.uuid4().hex
    manifest["metadata"]["labels"]["lotus.io/tool-owner"] = owner
    manifest["spec"]["template"]["metadata"]["labels"]["lotus.io/tool-owner"] = owner
    captured_task = TOOL_TASK.get() or {}
    if captured_task.get("repo_id") == repo_id and type(captured_task.get("scan_job_id")) is int:
        for labels in (manifest["metadata"]["labels"], manifest["spec"]["template"]["metadata"]["labels"]):
            labels["lotus.io/scan-job-id"] = str(captured_task["scan_job_id"])
    from backend import k8s_network_guard
    guard = await k8s_network_guard.prepare(manifest, profile="public" if allow_egress else "isolated")
    manifest = guard.manifest
    ownership = {"uid": None, "apply_ambiguous": True}
    cleanup_task = None
    async def cleanup():
        nonlocal cleanup_task
        if cleanup_task is None:
            cleanup_task = asyncio.create_task(asyncio.wait_for(_cleanup_tool_job(manifest, ownership), timeout=45))
        try:
            await _drain_tool_operation(cleanup_task)
        except asyncio.TimeoutError as exc:
            raise KubernetesToolCleanupError("Kubernetes tool cleanup deadline expired; Job or Pod absence remains unverified") from exc
    diagnostic_job = {}
    typed = None
    try:
        # Apply may create the Job before its response arrives. Keep the CLI
        # owned through cancellation, then reconcile the unique owner label.
        out, rc = await _drain_tool_operation(asyncio.create_task(apply(manifest, timeout=60)))
        if rc != 0:
            return "", f"k8s Job apply failed: {out[-800:]}", -1
        diagnostic_job = await _read_owned_tool_job(manifest, ownership)
        if diagnostic_job is None:
            raise KubernetesToolCleanupError("Applied Kubernetes tool Job has no verifiable immutable identity")
        ownership["apply_ambiguous"] = False
        await guard.release()
        phase, pod = await _wait_pod_phase_for_job(job_name, timeout=timeout, queue_timeout=queue_timeout, repo_id=repo_id,
                                                  send=send or TOOL_PROGRESS.get(),
                                                  progress_stages=progress_stages,
                                                  observation_exit_codes=observation_exit_codes, tool_id=name)
        _remember_owned_tool_pod(manifest, ownership, pod)
        if diagnostic_sink is not None:
            # Read ownership after the bounded wait so diagnosis cannot shorten
            # either queue/execution allowance or the Job deadline backstop.
            candidate = await _read_owned_tool_job(manifest, ownership)
            if candidate is not None:
                diagnostic_job = candidate
            typed = _typed_resource_diagnostic(repo_id, name, image, job_name, diagnostic_job, pod, phase,
                                               mem_request, mem_limit, timeout, queue_timeout)
            if typed is not None:
                diagnostic_sink(typed)
        diagnostic = str(pod.get("_lotus_runtime_diagnostic") or _pod_runtime_status(pod))
        if phase in {"queue_timeout", "timeout"}:
            # Stop the owned runtime before callbacks or potentially slow log
            # collection. A deadline is not permission to keep Java running.
            await cleanup()
            await _publish_runtime_result(repo_id, job_name, pod, send or TOOL_PROGRESS.get(),
                phase="Failed", reason=("Runtime queue budget expired before execution" if phase == "queue_timeout"
                                        else "Analyzer execution budget expired"),
                classification="queue_timeout" if phase == "queue_timeout" else "execution_timeout",
                validating_output=False)
        if phase == "queue_timeout":
            return "", (f"Kubernetes tool Job queue timed out after {queue_timeout}s before execution: {diagnostic}. "
                        "Check available node resources, namespace quota, image availability and volume binding; "
                        "retry after capacity is available or configure LOTUS_K8S_TOOL_QUEUE_TIMEOUT."), 124
        if phase == "timeout":
            return "", f"Kubernetes tool Job timed out after {timeout}s: {diagnostic}; owned runtime removed before log collection", 124
        if phase == "job_failed":
            return "", "Kubernetes tool Job failed before a Pod could execute: " + diagnostic, -1
        try:
            logs = await _kubectl_logs(job_name, timeout=60)
        except KubernetesToolLogsUnavailable as exc:
            # Eviction can remove the container before logs are retrieved.
            # Keep the already-observed Pod failure and termination code;
            # losing logs must not erase its resource/runtime diagnosis.
            code = (_terminated_exit_code(pod) or -1) if phase == "Failed" else -1
            return "", f"{diagnostic}; {exc}", code
        diagnostic = str(pod.get("_lotus_runtime_diagnostic") or _pod_runtime_status(pod))
        if script is not None and _RC_MARK in logs:
            out, err, code = _parse_captured(logs)
            if phase == "Failed" and code == 0:
                return out, err + "\n" + diagnostic, _terminated_exit_code(pod) or 1
            if phase == "Succeeded" and 0 <= code <= 255:
                if typed is not None:
                    diagnostic_sink({**typed,
                        "classification": "completed" if code == 0 else "process_exit",
                        "exit_code": code, "exit_code_scope": "analyzer_process",
                        "wrapper_exit_code": _terminated_exit_code(pod)})
                await _publish_captured_process_exit(repo_id, job_name, pod, code,
                    observation_exit_codes, send or TOOL_PROGRESS.get())
            return out, err, code
        # Direct (argv) mode preserves the entire already-bounded response.
        # Tailing it here destroys the beginning of larger JSON reports (OSV
        # uses exit 1 for findings), even though log collection succeeded.
        # A shell wrapper without its completion frame is incomplete evidence.
        exit_code = _terminated_exit_code(pod)
        if exit_code is None:
            exit_code = 0 if phase == "Succeeded" else (124 if phase == "timeout" else 1)
        if script is not None:
            return "", "Kubernetes tool output is missing its completion frame; " + diagnostic, exit_code or -1
        return logs, diagnostic if exit_code else "", exit_code
    finally:
        original = sys.exc_info()[1]
        try:
            try:
                await cleanup()
            finally:
                await k8s_network_guard.close(guard)
        except asyncio.CancelledError as cancelled:
            if isinstance(original, asyncio.CancelledError):
                if hasattr(cancelled, "cleanup_gap"):
                    original.cleanup_gap = cancelled.cleanup_gap
                raise original
            raise
        except Exception as exc:
            gap = "Owned Kubernetes tool cleanup remains unverified: " + type(exc).__name__
            _LOGGER.warning(gap)
            if original is None:
                failure = KubernetesToolCleanupError(gap)
                failure.cleanup_gap = gap
                if typed is not None:
                    failure.runtime_diagnostic = {**typed, "cleanup_verified": False}
                raise failure from exc
            original.cleanup_gap = gap
            if typed is not None and not hasattr(original, "runtime_diagnostic"):
                original.runtime_diagnostic = {**typed, "cleanup_verified": False}


async def _publish_captured_process_exit(repo_id, job_name, pod, code, observation_codes, send):
    """Distinguish a completed capture wrapper from the analyzer it ran.

    Keep the waiter's measured clocks and producer-bound task identity. A zero
    process exit still requires scanner output validation; it is not coverage.
    Failed Pods and incomplete frames never reach this projection.
    """
    validating = code == 0 or code in observation_codes
    reason = f"Analyzer process exited {code}" + ("; validating scanner output" if validating else "")
    await _publish_runtime_result(repo_id, job_name, pod, send,
        phase="Succeeded" if validating else "Failed", reason=reason,
        exit_code=code, exit_code_scope="analyzer_process",
        wrapper_exit_code=_terminated_exit_code(pod), validating_output=validating)


async def _publish_runtime_result(repo_id, job_name, pod, send, **outcome):
    observed = pod.get("_lotus_runtime_progress")
    if not send or not isinstance(observed, dict) or observed.get("job_name") != job_name:
        return
    detail = {**observed, **outcome}
    try:
        update = send(repo_id, f"Kubernetes {job_name}: {detail['reason']}",
            level="info" if detail["phase"] == "Succeeded" else "warning",
            detail_id=f"{repo_id}-runtime-{job_name}", detail=detail)
        if inspect.isawaitable(update):
            await asyncio.wait_for(update, timeout=5)
    except Exception as exc:
        _LOGGER.warning("Kubernetes analyzer result delivery failed: %s", str(exc)[:200])


def _typed_resource_diagnostic(repo_id, tool_id, image, job_name, job, pod, phase,
                               mem_request, mem_limit, timeout, queue_timeout):
    """Trust exact Kubernetes ownership/status, never process output or exit137 alone."""
    meta = job.get("metadata") or {}
    labels = meta.get("labels") or {}
    if (not meta.get("uid") or meta.get("name") != job_name or meta.get("namespace") != namespace()
            or labels.get("role") != "tool-job" or labels.get("lotus.io/repo-id") != str(repo_id)
            or labels.get("lotus.io/job") != job_name):
        return None
    pm = pod.get("metadata") or {}
    if not pm.get("uid") or pm.get("namespace") != namespace() or not any(
        r.get("kind") == "Job" and r.get("name") == job_name and r.get("uid") == meta["uid"]
        and r.get("controller") is True for r in pm.get("ownerReferences") or []):
        return None
    containers = [c for c in (pod.get("spec") or {}).get("containers") or [] if c.get("name") == "tool"]
    if len(containers) != 1 or containers[0].get("image") != image:
        return None
    resources = containers[0].get("resources") or {}
    try:
        # Kubernetes canonicalizes quantities (4096Mi becomes 4Gi). Verify
        # exact bytes rather than rejecting the controller's own admitted Pod.
        if (_mem_to_bytes(str(resources.get("requests", {}).get("memory") or "")) != _mem_to_bytes(mem_request)
                or _mem_to_bytes(str(resources.get("limits", {}).get("memory") or "")) != _mem_to_bytes(mem_limit)):
            return None
    except (ValueError, TypeError):
        return None
    statuses = [c for c in (pod.get("status") or {}).get("containerStatuses") or [] if c.get("name") == "tool"]
    term = ((statuses[0].get("state") or {}).get("terminated") or {}) if len(statuses) == 1 else {}
    classification = {"queue_timeout": "queue_timeout", "timeout": "execution_timeout"}.get(phase, "process_exit")
    if phase == "Failed" and term.get("reason") == "OOMKilled":
        classification = "oom_killed"
    elif phase == "Failed" and (pod.get("status") or {}).get("reason") == "Evicted":
        classification = "evicted"
    elif phase == "Succeeded":
        classification = "completed"
    return {"schema_version": 1, "provider": "kubernetes", "classification": classification, "ownership_verified": True,
            "repo_id": int(repo_id), "tool_id": tool_id, "configure_tool": tool_id, "namespace": namespace(),
            "job_name": job_name, "job_uid": meta["uid"], "pod_uid": pm["uid"],
            "image": image, "image_id": str(statuses[0].get("imageID") or "") if statuses else "",
            "memory_request": mem_request, "memory_limit": mem_limit,
            "timeout_seconds": timeout, "queue_timeout_seconds": queue_timeout,
            "exit_code": term.get("exitCode") if type(term.get("exitCode")) is int else None}


def _pod_runtime_status(pod: Dict) -> str:
    status = pod.get("status") or {}
    details = []
    if status.get("reason") or status.get("message"):
        # Pod-level reasons (notably Evicted and its volume-pressure message)
        # survive after containerStatuses becomes ContainerStatusUnknown.
        details.append(str(status.get("reason") or "Pod status") + ": " + str(status.get("message") or ""))
    for condition in status.get("conditions") or []:
        if condition.get("status") != "True":
            details.append(str(condition.get("reason") or condition.get("type") or "Pending") + ": " + str(condition.get("message") or ""))
    for container in status.get("containerStatuses") or []:
        state = container.get("state") or {}
        for stage in ("waiting", "terminated"):
            if state.get(stage):
                value = state[stage]
                details.append(str(value.get("reason") or stage) + ": " + str(value.get("message") or ""))
    phase = str(status.get("phase") or "Pending")
    fallback = {"Running": "container running", "Succeeded": "container completed", "Failed": "container failed"}.get(phase, "waiting for a scheduled Pod and container startup")
    return (phase + ": " + "; ".join(details or [fallback]))[:1200]


async def _latest_pod_event(pod: Dict) -> str:
    uid = str((pod.get("metadata") or {}).get("uid") or "")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,253}", uid):
        return ""
    try:
        raw, rc = await k8s_lab._run(["get", "events", "-n", namespace(), "--field-selector", "involvedObject.uid=" + uid,
                                      "-o", "json", "--request-timeout=5s"], timeout=8, max_output=64000)
        events = json.loads(raw).get("items", []) if rc == 0 else []
        if not events:
            return ""
        event = max(events, key=lambda item: str(item.get("lastTimestamp") or item.get("eventTime") or item.get("metadata", {}).get("creationTimestamp") or ""))
        return (str(event.get("reason") or "") + ": " + str(event.get("message") or ""))[:700]
    except (ValueError, TypeError, OSError):
        return ""


async def _read_tool_stage(pod: Dict, stages: Dict[str, str]) -> str:
    """Read an advisory enum; never expose arbitrary source-controlled text.

    The packaged wrapper writes these fixed stage names. A stage is neither
    health evidence nor completion: only the process result and parser can
    establish successful coverage. A missing marker/exec permission is benign.
    """
    pod_name = str(pod.get("metadata", {}).get("name") or "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", pod_name):
        return ""
    raw, code = await k8s_lab._run(
        ["exec", pod_name, "-n", namespace(), "-c", "tool", "--",
         "head", "-c", "64", "/tmp/lotus-tool-stage"], timeout=3, max_output=128,
    )
    key = raw.strip()
    return key if code == 0 and key in stages else ""


def _observation_exit_code(pod: Dict, allowed: Tuple[int, ...]) -> Optional[int]:
    """Recognize a tool's finding exit without hiding runtime failures."""
    status = pod.get("status") or {}
    if status.get("phase") != "Failed" or status.get("reason"):
        return None
    containers = status.get("containerStatuses") or []
    if len(containers) != 1 or status.get("initContainerStatuses"):
        return None
    container = containers[0]
    term = (container.get("state") or {}).get("terminated") or {}
    code = term.get("exitCode")
    if (isinstance(code, int) and code in allowed and code != 0
            and term.get("reason") in {"Completed", "Error"}
            and not term.get("signal") and not container.get("restartCount")):
        return code
    return None


def _tool_queue_timeout(timeout: int, configured: Optional[int] = None) -> int:
    """Bound admission/startup separately from the unchanged execution budget."""
    value = configured if configured is not None else os.environ.get("LOTUS_K8S_TOOL_QUEUE_TIMEOUT")
    if value is None:
        # Three serialized Go analyzers need room for two preceding execution
        # budgets plus startup and scheduling; two budgets leave no margin.
        return max(60, min(7200, 3 * int(timeout)))
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value).strip()):
        raise ValueError("LOTUS_K8S_TOOL_QUEUE_TIMEOUT must be an integer from 1 to 7200 seconds")
    parsed = int(value)
    if not 1 <= parsed <= 7200:
        raise ValueError("LOTUS_K8S_TOOL_QUEUE_TIMEOUT must be an integer from 1 to 7200 seconds")
    return parsed


async def _job_waiting_status(job_name: str, repo_id: int) -> Tuple[str, bool]:
    """Explain absent-Pod admission using only this exact tool Job's events."""
    job, rc, error = await get_json("job", job_name, timeout=10)
    if rc or not isinstance(job, dict):
        return "Waiting for Pod admission; Job status unavailable: " + str(error)[-300:], False
    metadata = job.get("metadata") or {}
    labels = metadata.get("labels") or {}
    if (job.get("kind") != "Job" or metadata.get("name") != job_name
            or metadata.get("namespace") != namespace()
            or labels.get("role") != "tool-job" or labels.get("lotus.io/job") != job_name
            or labels.get("lotus.io/repo-id") != str(int(repo_id))):
        return "Waiting for Pod admission; exact tool Job identity could not be verified", False
    event = await _latest_pod_event(job)  # Events are bound to the observed Job UID.
    for condition in (job.get("status") or {}).get("conditions") or []:
        if condition.get("type") == "Failed" and condition.get("status") == "True":
            reason = str(condition.get("reason") or "Failed") + ": " + str(condition.get("message") or "")
            return (reason + ("; " + event if event else ""))[:1200], True
    return "Waiting for Pod admission" + ("; " + event if event else ""), False


async def _wait_pod_phase_for_job(job_name: str, *, timeout: int, queue_timeout: Optional[int] = None, repo_id: int = 0, send=None,
                                  progress_stages: Optional[Dict[str, str]] = None,
                                  observation_exit_codes: Tuple[int, ...] = (), tool_id: Optional[str] = None) -> Tuple[str, Dict]:
    """Give queued/startup work and running work separate monotonic budgets."""
    queue_timeout = _tool_queue_timeout(timeout, queue_timeout)
    captured_task = TOOL_TASK.get() or {}
    task_identity = {"tool_id": tool_id} if tool_id else {}
    if captured_task.get("repo_id") == repo_id:
        task_identity.update({key: captured_task[key] for key in ("task_name", "task_detail_id", "scan_job_id") if key in captured_task})
    started = asyncio.get_running_loop().time()
    execution_started = None
    selector = f"job-name={job_name}"
    last: Dict = {}
    last_state, last_event, emitted_at = "", "", started - 31
    stage, diagnostic = "", ""
    last_progress = None
    def expired(at):
        result = ""
        if execution_started is None and at - started >= queue_timeout:
            result = "queue_timeout"
        elif execution_started is not None and at - execution_started >= max(5, timeout):
            result = "timeout"
        if result and last_progress is not None:
            last["_lotus_runtime_progress"] = {**last_progress,
                "elapsed_seconds": int(at - started),
                "queue_elapsed_seconds": int((execution_started if execution_started is not None else at) - started),
                "execution_elapsed_seconds": int(at - execution_started) if execution_started is not None else 0}
        return result
    while True:
        now = asyncio.get_running_loop().time()
        if deadline_phase := expired(now):
            return deadline_phase, last
        doc, rc, error = await get_json("pods", selector=selector, timeout=20)
        pods = doc.get("items") if rc == 0 and isinstance(doc, dict) else []
        phase = "Pending"
        for pod in pods or []:
            if not isinstance(pod, dict):
                continue
            last = pod
            phase = str((pod.get("status") or {}).get("phase") or "")
            break
        now = asyncio.get_running_loop().time()
        state = ("Kubernetes Pod read failed: " + str(error)[-500:]) if rc else _pod_runtime_status(last if pods else {})
        # A bounded API call may itself cross a short configured deadline.
        # Do not let its late Running/terminal response bypass that deadline.
        if deadline_phase := expired(now):
            last["_lotus_runtime_diagnostic"] = state + ("; " + last_event if last_event else "")
            return deadline_phase, last
        if phase == "Running" and execution_started is None:
            execution_started = now
        if state != last_state or now - emitted_at >= 30:
            if phase == "Pending":
                if pods:
                    last_event = await _latest_pod_event(last)
                else:
                    last_event, job_failed = await _job_waiting_status(job_name, repo_id)
                    if job_failed:
                        phase = "job_failed"
            else:
                last_event = ""
            if phase == "Running" and progress_stages:
                stage = await _read_tool_stage(last, progress_stages)
            observation_code = _observation_exit_code(last, observation_exit_codes)
            diagnostic = (f"Process exited {observation_code}; validating scanner output"
                          if observation_code is not None else state)
            diagnostic += ("; " + last_event if last_event else "")
            if stage and progress_stages:
                diagnostic += "; " + ("" if phase == "Running" else "Last stage: ") + progress_stages[stage]
            last["_lotus_runtime_diagnostic"] = diagnostic
            if phase not in ("Succeeded", "Failed"):
                if deadline_phase := expired(asyncio.get_running_loop().time()):
                    return deadline_phase, last
            if send:
                try:
                    queue_elapsed = int((execution_started if execution_started is not None else now) - started)
                    execution_elapsed = int(now - execution_started) if execution_started is not None else 0
                    clock = (f"{execution_elapsed}s execution, {queue_elapsed}s queued" if execution_started is not None
                             else f"{queue_elapsed}s queued; execution budget has not started")
                    if phase in ("Succeeded", "Failed") and execution_started is None:
                        clock = f"{int(now - started)}s observed; no running interval was observed"
                    last_progress = {"kind": "runtime_progress", "job_name": job_name,
                                  **task_identity,
                                  "namespace": namespace(), "phase": phase, "reason": diagnostic, "elapsed_seconds": int(now - started),
                                  "budget_seconds": timeout, "queue_budget_seconds": queue_timeout,
                                  "queue_elapsed_seconds": queue_elapsed, "execution_elapsed_seconds": execution_elapsed,
                                  "budget_kind": "execution" if execution_started is not None else "queue",
                                  "stage": stage, "stage_is_advisory": bool(stage),
                                  "exit_code": _terminated_exit_code(last), "validating_output": observation_code is not None}
                    update = send(repo_id, f"Kubernetes {job_name}: {diagnostic} ({clock})", level="warning" if rc or phase == "job_failed" or (phase == "Failed" and observation_code is None) else "info",
                                  detail_id=f"{repo_id}-runtime-{job_name}", detail=last_progress)
                    if inspect.isawaitable(update):
                        await asyncio.wait_for(update, timeout=5)
                except Exception as exc:
                    _LOGGER.warning("Kubernetes tool progress delivery failed: %s", str(exc)[:200])
            last_state, emitted_at = state, now
        # Each API poll replaces the Pod dict, including between heartbeats.
        # Preserve the last UID-scoped event/stage explanation for timeouts.
        last["_lotus_runtime_diagnostic"] = diagnostic
        if last_progress is not None:
            last["_lotus_runtime_progress"] = last_progress
        if phase in ("Succeeded", "Failed", "job_failed"):
            return phase, last
        await asyncio.sleep(1.0)


async def cleanup_source_pvc(repo_id: int) -> None:
    """Delete only the observed source PVC UID, serialized with its upload."""
    from backend.source_volume_ownership import cleanup_owned_source, load_source_receipt
    async with _source_admission(repo_id, 90) as key:
        receipt = load_source_receipt(repo_id)
        if not receipt:
            raise KubernetesSourceUnavailable("Kubernetes source cleanup requires a recorded volume identity")
        try:
            await cleanup_owned_source(receipt, caller_holds_admission=True)
        except RuntimeError as exc:
            raise KubernetesSourceUnavailable(str(exc)) from exc
