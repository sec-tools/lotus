"""In-cluster image builder: registry + kaniko (the k8s replacement for Docker
``build``/``commit``).

The dynamic tools (explorer, fuzzer) build a per-repo image from a generated
Dockerfile and then run it.  On the Docker path this is ``docker build`` +
``docker run``; there is no such verb in Kubernetes, so we:

1. run a small **in-cluster registry** (``registry:2``) backed by a PVC, exposed
   on a stable ``NodePort`` so both build pods and the node's container runtime
   reach it at the *same* ``<nodeIP>:<nodePort>`` reference;
2. build with **kaniko** (userspace image builder -- no Docker daemon, no
   privileged socket) from a context PVC and push to that registry;
3. let the untrusted run Jobs (in the ``lotus`` namespace) pull the pushed tag.

Trust boundary
--------------
kaniko unpacks base-image root filesystems and therefore needs to run as root
with a writable root filesystem and the *default* capability set -- which the
``restricted`` PodSecurity of the ``lotus`` namespace forbids.  The builder and
registry therefore live in a **separate ``lotus-build`` namespace pinned to the
``baseline`` standard**.  This is deliberate defence in depth: the *trusted*
builder (our generated Dockerfile) gets a relaxed-but-unprivileged sandbox,
while the *untrusted* harness run Jobs stay locked down under ``restricted``.

The node's container runtime must be told the registry is plain-HTTP; see
``containerd_hosts_toml`` / the Stage 3b setup notes.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import uuid
import weakref
from copy import deepcopy
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from backend import k8s_lab
from backend.k8s_network_guard import NetworkIsolationUnavailable
from backend.k8s_lab import _run, apply


_REPAIR_EVIDENCE = weakref.WeakKeyDictionary()


class _ExecutorFailure(RuntimeError):
    """Controller-observed terminal state, never a tool-provided message."""
    def __init__(self, phase):
        self.code = "build-timeout" if phase == "timeout" else "executor-failed"
        super().__init__(self.code)


class BuildImageFailure(NetworkIsolationUnavailable):
    """Fixed, bounded diagnostics; never expose arbitrary exception/tool text."""
    STAGES = frozenset(['registry', 'context-volume', 'context-admission', 'context-transfer', 'context-drain', 'build-admission', 'image-build', 'build-cleanup'])
    MESSAGES = {'operation-failed': 'The bounded build operation failed; inspect its controlled stage and owned resource state', 'cleanup-deadline': 'Owned workload did not disappear within the cleanup deadline; inspect termination grace and retry owned cleanup', 'context-in-use': 'Context volume retained because a Pod still references it; drain that owned Pod before cleanup', 'context-ownership': 'Context volume identity changed or is unknown; preserve it and reconcile the recorded owner', 'isolation-denied': 'Required network isolation was not enforced; no repository command was released', 'network-admission-unavailable': 'Network admission or its owned cleanup was unavailable; inspect the exact workload and namespace permissions'}

    MESSAGES.update({"executor-failed": "The isolated image build exited unsuccessfully; open its retained build log for the failing command and error",
                     "build-timeout": "The isolated image build exceeded its deadline; open its retained build log for the last completed command"})
    from backend.k8s_network_guard import WorkloadAdmissionUnavailable as _AdmissionFailure
    MESSAGES.update(_AdmissionFailure.MESSAGES)

    @staticmethod
    def public_diagnostic(error):
        """Reconstruct fixed text; mutable exception attributes grant no trust."""
        def clean(row):
            if (not isinstance(row, dict) or not isinstance(row.get("stage"), str)
                    or not isinstance(row.get("code"), str)
                    or row["stage"] not in BuildImageFailure.STAGES
                    or row["code"] not in BuildImageFailure.MESSAGES):
                return None
            return {"stage": row["stage"], "code": row["code"],
                    "reason": BuildImageFailure.MESSAGES[row["code"]]}
        value = getattr(error, "diagnostic", None)
        primary = clean(value) or {"stage": "image-build", "code": "operation-failed",
                                   "reason": BuildImageFailure.MESSAGES["operation-failed"]}
        rows = value.get("cleanup_errors", []) if isinstance(value, dict) else []
        rows = rows[:4] if isinstance(rows, list) else []
        return {**primary, "cleanup_errors": [r for r in (clean(row) for row in rows) if r is not None]}

    @staticmethod
    def repair_evidence(error, *, source_tree_hash, recipe_sha256):
        """Consume producer-only evidence; public/mutable exception fields confer no authority."""
        if type(error) is not BuildImageFailure:
            return None
        value = _REPAIR_EVIDENCE.pop(error, None)
        if (value is None or value["source_tree_hash"] != source_tree_hash
                or value["recipe_sha256"] != recipe_sha256):
            return None
        return deepcopy(value)

    def __init__(self, stage, error, *, cleanup_errors=()):
        stages = {"registry", "context-volume", "context-admission", "context-transfer",
                  "context-drain", "build-admission", "image-build", "build-cleanup"}
        stage = stage if stage in stages else "image-build"
        if isinstance(error, BuildImageFailure):
            primary = BuildImageFailure.public_diagnostic(error)
            prior_cleanup = primary.pop("cleanup_errors", [])
        else:
            code, reason = self._classify(error)
            primary = {"stage": stage, "code": code, "reason": reason}
            prior_cleanup = []
        cleanup = prior_cleanup + [{"stage": "build-cleanup", "code": self._classify(e)[0],
                                    "reason": self._classify(e)[1]} for e in cleanup_errors]
        self.diagnostic = {**primary, "cleanup_errors": cleanup[:4]}
        super().__init__("Image build " + primary["stage"] + " failed: " + primary["reason"]
                         + ("; owned cleanup remains incomplete" if cleanup else ""))

    @staticmethod
    def _classify(error):
        from backend.k8s_network_guard import WorkloadAdmissionUnavailable
        if isinstance(error, WorkloadAdmissionUnavailable):
            code = getattr(error, "code", "")
            code = code if isinstance(code, str) and code in WorkloadAdmissionUnavailable.MESSAGES else "scheduling-unavailable"
            return code, WorkloadAdmissionUnavailable.MESSAGES[code]
        if isinstance(error, _ExecutorFailure):
            code = error.code if error.code in {"executor-failed", "build-timeout"} else "executor-failed"
            return code, BuildImageFailure.MESSAGES[code]
        if not isinstance(error, NetworkIsolationUnavailable):
            return "operation-failed", BuildImageFailure.MESSAGES["operation-failed"]
        text = str(error)
        if text == "Network cleanup did not verify original UID disappearance" or (
                isinstance(error, NetworkIsolationUnavailable)
                and text.startswith("Network admission cleanup remains incomplete:")
                and "Network cleanup did not verify original UID disappearance" in text):
            return "cleanup-deadline", BuildImageFailure.MESSAGES["cleanup-deadline"]
        if text == "Build context is still referenced by a Pod; volume retained":
            return "context-in-use", BuildImageFailure.MESSAGES["context-in-use"]
        if text == "Build context cleanup refused unknown or replaced PVC identity; volume retained":
            return "context-ownership", BuildImageFailure.MESSAGES["context-ownership"]
        if text == "NetworkPolicy did not enforce the required traffic profile; no repository command was released":
            return "isolation-denied", BuildImageFailure.MESSAGES["isolation-denied"]
        if isinstance(error, NetworkIsolationUnavailable):
            return "network-admission-unavailable", BuildImageFailure.MESSAGES["network-admission-unavailable"]
        return "operation-failed", BuildImageFailure.MESSAGES["operation-failed"]

# Process-local memo so many builds in one audit configure the registry once.
_REGISTRY: Dict[str, object] = {"host": None, "ts": 0.0}
_NODE_IP: Dict[str, str] = {}

# kubectl apply needs get/create/patch; logs and cp additionally need pod
# discovery and their subresources. Keep this contract aligned with the
# administrator-owned Role in k8s/builder/serviceaccount.yaml.
BUILDER_PERMISSIONS = {
    "jobs.batch": ("create", "get", "patch", "delete"),
    "pods": ("create", "get", "list", "patch", "delete"),
    "pods/log": ("get",),
    "pods/exec": ("create", "get"),
    "persistentvolumeclaims": ("create", "get", "patch", "delete"),
    "services": ("create", "get", "patch", "delete"),
    "networkpolicies.networking.k8s.io": ("create", "get", "list", "patch", "delete"),
    "deployments.apps": ("create", "get", "patch", "delete"),
    "replicasets.apps": ("get",),
}


def build_namespace() -> str:
    value = (os.environ.get("LOTUS_K8S_BUILD_NAMESPACE") or "lotus-build").strip()
    return value if re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", value) else "lotus-build"


def registry_nodeport() -> int:
    try:
        port = int(os.environ.get("LOTUS_K8S_REGISTRY_NODEPORT", "30500"))
    except ValueError:
        port = 30500
    return port if 30000 <= port <= 32767 else 30500


def _kaniko_image() -> str:
    return (os.environ.get("LOTUS_K8S_KANIKO_IMAGE")
            or "gcr.io/kaniko-project/executor:v1.23.2").strip()


def _registry_image() -> str:
    return (os.environ.get("LOTUS_K8S_REGISTRY_IMAGE") or "registry:2").strip()


def _registry_size() -> str:
    return (os.environ.get("LOTUS_K8S_REGISTRY_SIZE") or "10Gi").strip()


def _storage_class() -> str:
    return (os.environ.get("LOTUS_K8S_STORAGE_CLASS") or "").strip()


# ---------------------------------------------------------------------------
# Low-level kubectl helpers scoped to an explicit namespace (k8s_lab.get_json
# is hard-wired to the lotus namespace, so the builder reads via _run).
# ---------------------------------------------------------------------------
async def _get_json(kind: str, name: str = "", *, ns: str, selector: str = "",
                    timeout: int = 20) -> Tuple[Dict, int]:
    args = ["get", kind]
    if name:
        args.append(name)
    if selector:
        args.extend(["-l", selector])
    args.extend(["-o", "json", "-n", ns])
    out, rc = await _run(args, timeout=timeout, max_output=None)
    try:
        return json.loads(out), rc
    except Exception:
        return {}, rc


async def node_ip() -> str:
    """Internal IP of a schedulable node (stable for a given kind cluster)."""
    # The supplied Deployment uses spec.hostIP via the downward API. This
    # needs no permission to list cluster-wide Nodes. CLI operators may set
    # the same variable explicitly; discovery remains a kubeconfig fallback.
    configured = (os.environ.get("LOTUS_K8S_NODE_IP") or "").strip()
    if configured:
        try:
            return str(ipaddress.ip_address(configured))
        except ValueError:
            return ""
    if _NODE_IP.get("ip"):
        return _NODE_IP["ip"]
    out, rc = await _run(
        ["get", "nodes", "-o",
         "jsonpath={.items[0].status.addresses[?(@.type=='InternalIP')].address}"],
        timeout=20,
    )
    ip = (out or "").strip().split()[0] if (rc == 0 and out.strip()) else ""
    if ip:
        _NODE_IP["ip"] = ip
    return ip


async def registry_host() -> str:
    """``<nodeIP>:<nodePort>`` -- identical from build pods and the node."""
    ip = await node_ip()
    if not ip:
        return ""
    return f"[{ip}]:{registry_nodeport()}" if ":" in ip else f"{ip}:{registry_nodeport()}"


def image_ref(host: str, repo_id: int, name: str, tag: str) -> str:
    safe = re.sub(r"[^a-z0-9._-]", "-", str(name).lower()).strip("-") or "img"
    return f"{host}/lotus/{int(repo_id)}-{safe}:{tag}"


# ---------------------------------------------------------------------------
# Registry lifecycle
# ---------------------------------------------------------------------------
def _ns_manifest() -> Dict:
    # baseline (not restricted): kaniko + registry:2 run as root with the
    # default capability set, which restricted rejects.
    return {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": build_namespace(), "labels": {
            "app": "lotus", "lotus.io/role": "builder",
            "pod-security.kubernetes.io/enforce": "baseline",
            "pod-security.kubernetes.io/warn": "baseline",
            "pod-security.kubernetes.io/audit": "baseline",
        }},
    }


def _registry_manifests() -> List[Dict]:
    ns = build_namespace()
    labels = {"app": "lotus-registry", "lotus.io/role": "registry"}
    pvc_spec: Dict = {"accessModes": ["ReadWriteOnce"],
                      "resources": {"requests": {"storage": _registry_size()}}}
    if _storage_class():
        pvc_spec["storageClassName"] = _storage_class()
    pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
           "metadata": {"name": "lotus-registry-data", "namespace": ns, "labels": labels},
           "spec": pvc_spec}
    deploy = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "lotus-registry", "namespace": ns, "labels": labels},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": labels},
            "strategy": {"type": "Recreate"},  # single RWO volume
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [{
                        "name": "registry",
                        "image": _registry_image(),
                        "ports": [{"containerPort": 5000, "name": "registry"}],
                        "env": [
                            {"name": "REGISTRY_STORAGE_DELETE_ENABLED", "value": "true"},
                            {"name": "REGISTRY_HTTP_ADDR", "value": ":5000"},
                        ],
                        "resources": {"requests": {"cpu": "100m", "memory": "256Mi"},
                                      "limits": {"cpu": "1", "memory": "1Gi"}},
                        "readinessProbe": {"httpGet": {"path": "/v2/", "port": 5000},
                                           "initialDelaySeconds": 2, "periodSeconds": 3},
                        "volumeMounts": [{"name": "data", "mountPath": "/var/lib/registry"}],
                    }],
                    "volumes": [{"name": "data",
                                 "persistentVolumeClaim": {"claimName": "lotus-registry-data"}}],
                },
            },
        },
    }
    svc = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "lotus-registry", "namespace": ns, "labels": labels},
        "spec": {"type": "NodePort", "selector": labels,
                 "ports": [{"port": 5000, "targetPort": 5000,
                            "nodePort": registry_nodeport(), "protocol": "TCP"}]},
    }
    return [pvc, deploy, svc]


async def _wait_deploy_available(name: str, ns: str, *, timeout: int) -> bool:
    deadline = asyncio.get_running_loop().time() + max(5, timeout)
    while asyncio.get_running_loop().time() < deadline:
        doc, rc = await _get_json("deployment", name, ns=ns, timeout=20)
        if rc == 0 and int(((doc.get("status") or {}).get("availableReplicas")) or 0) >= 1:
            return True
        await asyncio.sleep(2.0)
    return False


async def builder_prerequisites() -> Tuple[bool, str]:
    """Read-only authorization checks before creating any builder resources.

    Builder namespace and RBAC are administrator prerequisites. The running
    controller must never need permission to create namespaces, alter RBAC,
    or administer the cluster just to prepare an image.
    """
    ns = build_namespace()
    limit = asyncio.Semaphore(4)

    async def check(resource: str, verb: str) -> Optional[str]:
        resource_name, _, subresource = resource.partition("/")
        args = ["auth", "can-i", verb, resource_name]
        # TYPE/NAME is a named object to `kubectl auth can-i`, not a
        # subresource. Ask about exec/log explicitly so a pods permission
        # cannot accidentally satisfy its distinct subresource check.
        if subresource:
            args.append(f"--subresource={subresource}")
        args.extend(["-n", ns, "--quiet"])
        async with limit:
            out, rc = await _run(args, timeout=10)
        if rc == 0:
            return None
        return f"{verb} {resource}" + (f" ({out.strip()[-200:]})" if out.strip() else "")

    denied = [value for value in await asyncio.gather(*(
        check(resource, verb)
        for resource, verbs in BUILDER_PERMISSIONS.items()
        for verb in verbs
    )) if value]
    if denied:
        return False, (
            f"builder permissions unavailable in namespace {ns}: {', '.join(denied)}. "
            "An administrator must apply k8s/builder and match its RoleBinding "
            "to the Lotus controller service account; cluster-admin is unnecessary."
        )
    if not await registry_host():
        return False, (
            "builder registry address unavailable; set LOTUS_K8S_NODE_IP to a valid "
            "node IP (the supplied Deployment uses spec.hostIP). Configure the "
            "node runtime's registry trust as described in README.md under target image builds."
        )
    return True, "builder namespace permissions and registry address available"


async def ensure_registry(send=None, repo_id: int = 0, *, timeout: int = 240) -> Optional[str]:
    """Prepare the registry in the administrator-provisioned builder namespace."""
    now = asyncio.get_running_loop().time()
    key = (build_namespace(), tuple(k8s_lab._context_args()), registry_nodeport(),
           os.environ.get("LOTUS_K8S_NODE_IP", ""))
    if (_REGISTRY.get("host") and _REGISTRY.get("key") == key
            and now - float(_REGISTRY["ts"] or 0) < 120):  # type: ignore[arg-type]
        return str(_REGISTRY["host"])
    available, reason = await builder_prerequisites()
    if not available:
        if send:
            await send(repo_id, f"k8s image builder unavailable: {reason}", level="warning")
        return None
    for manifest in _registry_manifests():
        out, rc = await apply(manifest, timeout=60)
        if rc != 0:
            if send:
                await send(repo_id, f"k8s registry apply failed in {build_namespace()}: {out[-400:]}. "
                           "Verify the administrator-applied k8s/builder namespace, RBAC, "
                           "storage class, and registry NodePort.", level="warning")
            return None
    if not await _wait_deploy_available("lotus-registry", build_namespace(), timeout=timeout):
        if send:
            await send(repo_id, "k8s registry did not become ready", level="warning")
        return None
    host = await registry_host()
    if not host:
        return None
    _REGISTRY["host"] = host
    _REGISTRY["ts"] = now
    _REGISTRY["key"] = key
    if send:
        await send(repo_id, f"k8s image registry ready ({host})", level="info")
    return host


# ---------------------------------------------------------------------------
# Build context delivery + kaniko build
# ---------------------------------------------------------------------------
def _ctx_pvc_name(repo_id: int, key: str) -> str:
    return f"lotus-build-{int(repo_id)}-{key}"[:63]


def _ctx_pvc_manifest(pvc: str, repo_id: int) -> Dict:
    spec: Dict = {"accessModes": ["ReadWriteOnce"],
                  "resources": {"requests": {"storage":
                      str(os.environ.get("LOTUS_K8S_BUILD_CTX_SIZE") or "4Gi")}}}
    if _storage_class():
        spec["storageClassName"] = _storage_class()
    return {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": pvc, "namespace": build_namespace(),
                         "labels": {"lotus.io/repo-id": str(int(repo_id)), "role": "build-context"}},
            "spec": spec}


def _ctx_populator_pod(pvc: str, pod_name: str) -> Dict:
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": build_namespace(),
                     "labels": {"role": "build-context-populator"}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "activeDeadlineSeconds": int(os.environ.get("LOTUS_K8S_POPULATE_DEADLINE", "600")),
            # Trusted sleeping transfer worker has no shutdown state to preserve.
            "terminationGracePeriodSeconds": 1,
            "containers": [{
                "name": "pop", "image": str(os.environ.get("LOTUS_K8S_POPULATOR_IMAGE") or "alpine:3.20"),
                "securityContext": {"allowPrivilegeEscalation": False, "privileged": False,
                                    "capabilities": {"drop": ["NET_RAW"]},
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "command": ["sh", "-c", "sleep 600"],
                "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                              "limits": {"cpu": "1", "memory": "512Mi"}},
                "volumeMounts": [{"name": "ctx", "mountPath": "/workspace"}],
            }],
            "volumes": [{"name": "ctx", "persistentVolumeClaim": {"claimName": pvc}}],
        },
    }


async def _wait_pod_phase(pod_name: str, ns: str, phases: Tuple[str, ...], *, timeout: int) -> str:
    deadline = asyncio.get_running_loop().time() + max(3, timeout)
    while asyncio.get_running_loop().time() < deadline:
        doc, rc = await _get_json("pod", pod_name, ns=ns, timeout=20)
        if rc == 0:
            phase = str((doc.get("status") or {}).get("phase") or "")
            if phase in phases:
                return phase
            if phase == "Failed" and "Failed" not in phases:
                return phase
        await asyncio.sleep(1.0)
    return "timeout"


async def _populate_context(pvc: str, context_dir: Path, repo_id: int, *, timeout: int, ownership=None) -> bool:
    ns = build_namespace()
    from backend import k8s_network_guard
    ownership = ownership if ownership is not None else {}
    ownership.update(namespace=ns, name=pvc, owner=uuid.uuid4().hex, uid=None, attempted=True, stage="context-volume")
    volume = _ctx_pvc_manifest(pvc, repo_id)
    volume["metadata"]["labels"]["lotus.io/build-context-owner"] = ownership["owner"]
    # Creation cannot overwrite an existing same-name PVC. Unknown completion
    # remains an explicit cleanup gap rather than authority to delete by name.
    await k8s_network_guard._command(ns, ["create", "-f", "-"], document=volume)
    observed = await k8s_network_guard._read(ns, "PersistentVolumeClaim", pvc)
    metadata = (observed or {}).get("metadata", {})
    if (not metadata.get("uid") or metadata.get("labels", {}).get("lotus.io/build-context-owner") != ownership["owner"]):
        raise k8s_network_guard.NetworkIsolationUnavailable("Build context PVC ownership could not be verified")
    ownership["uid"] = metadata["uid"]
    pod = f"lotus-ctx-pop-{uuid.uuid4().hex[:8]}"
    manifest = _ctx_populator_pod(pvc, pod)
    manifest["metadata"]["labels"]["lotus.io/repo-id"] = str(int(repo_id))
    ownership["stage"] = "context-admission"
    guard = await k8s_network_guard.prepare(manifest, profile="isolated")
    primary_error = None
    try:
        out, rc = await apply(guard.manifest, timeout=60)
        if rc != 0:
            return False
        await guard.release()
        if await _wait_pod_phase(pod, ns, ("Running",), timeout=min(timeout, 180)) != "Running":
            return False
        ownership["stage"] = "context-transfer"
        cp_out, cp_rc = await _run(
            ["cp", f"{str(Path(context_dir))}/.", f"{ns}/{pod}:/workspace", "-c", "pop"], timeout=timeout)
        return cp_rc == 0
    except Exception as exc:
        primary_error = BuildImageFailure(ownership["stage"], exc)
        raise primary_error from exc
    finally:
        # Upload has finished (or failed); drain the exact admitted Pod and
        # controls before reserving resources for the subsequent build guard.
        ownership["stage"] = "context-drain"
        guard.released = False
        try:
            await k8s_network_guard.close(guard)
        except Exception as exc:
            if primary_error is not None:
                raise BuildImageFailure("context-drain", primary_error, cleanup_errors=[exc]) from primary_error
            raise BuildImageFailure("context-drain", exc) from exc


def _kaniko_memory() -> Tuple[str, str]:
    """Reserve schedulable memory while retaining the separately enforced limit."""
    from decimal import Decimal
    def amount(value):
        match = re.fullmatch(r"(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|K|M|G|T)?", value)
        if not match:
            raise ValueError("Kaniko memory must be a positive Kubernetes quantity (for example 768Mi or 4Gi)")
        units = {None: 1, "Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4,
                 "K": 1000, "M": 1000**2, "G": 1000**3, "T": 1000**4}
        return Decimal(match[1]) * units[match[2]]
    request = str(os.environ.get("LOTUS_K8S_KANIKO_REQUEST_MEM") or "768Mi").strip()
    limit = str(os.environ.get("LOTUS_K8S_KANIKO_MEM") or "4Gi").strip()
    if not 0 < amount(request) <= amount(limit):
        raise ValueError("LOTUS_K8S_KANIKO_REQUEST_MEM must be positive and no greater than LOTUS_K8S_KANIKO_MEM")
    return request, limit


def _kaniko_job(job_name: str, pvc: str, destination: str, *,
                dockerfile: str, build_args: Optional[Dict[str, str]],
                timeout: int, return_digest: bool = False) -> Dict:
    ns = build_namespace()
    request_memory, limit_memory = _kaniko_memory()
    args = [
        f"--dockerfile={dockerfile}",
        "--context=dir:///workspace",
        f"--destination={destination}",
        "--insecure", "--skip-tls-verify",
        "--single-snapshot", "--cleanup",
    ]
    if return_digest:
        args.append("--digest-file=/dev/termination-log")
    for k, v in (build_args or {}).items():
        args.append(f"--build-arg={k}={v}")
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": job_name, "namespace": ns,
                     "labels": {"role": "image-build", "lotus.io/job": job_name}},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": int(timeout),
            "ttlSecondsAfterFinished": 180,
            "template": {
                "metadata": {"labels": {"role": "image-build", "lotus.io/job": job_name}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "containers": [{
                        "name": "kaniko",
                        "securityContext": {"allowPrivilegeEscalation": False, "privileged": False,
                                            "capabilities": {"drop": ["NET_RAW"]},
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "image": _kaniko_image(),
                        "args": args,
                        "resources": {"requests": {"cpu": "500m", "memory": request_memory},
                                      "limits": {"cpu": "2", "memory": limit_memory}},
                        "volumeMounts": [{"name": "ctx", "mountPath": "/workspace"}],
                    }],
                    "volumes": [{"name": "ctx", "persistentVolumeClaim": {"claimName": pvc}}],
                },
            },
        },
    }


async def _job_logs(job_name: str, ns: str, *, timeout: int = 60, max_bytes: int = 2_000_000) -> str:
    from backend.async_process import terminate_and_reap
    args = [k8s_lab.kubectl_binary(), *k8s_lab._context_args(),
            "logs", f"job/{job_name}", "-n", ns, "--tail=-1"]
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (out or b"")[:max_bytes].decode(errors="replace")
    except asyncio.CancelledError:
        await terminate_and_reap(proc)
        raise
    except Exception:
        await terminate_and_reap(proc)
        return ""


async def _owned_build_log(job_name: str, ns: str, identity: dict) -> dict:
    """Retain a bounded tail from the admission-owned Pod, before UID cleanup.

    Log text is untrusted evidence kept only in the explicit detail artifact.
    It is never used as a public error classification or runtime proof.
    """
    from backend.async_process import terminate_and_reap
    limit = 128 * 1024
    result = {"type": "image-build-log", "schema_version": 1, "job": job_name,
              "namespace": ns, "capture_limit_bytes": limit, "status": "identity-unavailable"}
    job_uid, pod_uid = identity.get("workload_uid"), identity.get("pod_uid")
    if not isinstance(job_uid, str) or not job_uid or not isinstance(pod_uid, str) or not pod_uid:
        return result

    async def owned_pod():
        job, rc = await _get_json("job", job_name, ns=ns, timeout=10)
        if rc or _build_job_uid(job, job_name, ns) != job_uid:
            return None
        document, rc = await _get_json("pods", ns=ns, selector=f"job-name={job_name}", timeout=10)
        pods = document.get("items") or []
        if rc or len(pods) != 1:
            return None
        pod = pods[0]; meta = pod.get("metadata") or {}
        if (meta.get("uid") != pod_uid or meta.get("namespace") != ns
                or (meta.get("labels") or {}).get("lotus.io/job") != job_name
                or not isinstance(meta.get("name"), str) or not meta["name"]
                or not any(o.get("kind") == "Job" and o.get("name") == job_name
                           and o.get("uid") == job_uid and o.get("controller") is True
                           for o in meta.get("ownerReferences") or [])):
            return None
        containers = [c for c in (pod.get("status") or {}).get("containerStatuses") or []
                      if c.get("name") == "kaniko"]
        if len(containers) != 1 or not containers[0].get("containerID"):
            return None
        terminated = (containers[0].get("state") or {}).get("terminated") or {}
        # Keep only API status scalars, never termination message/tool text.
        termination = {key: terminated.get(key) for key in ("reason", "exitCode", "signal")}
        termination.update(phase=(pod.get("status") or {}).get("phase"),
                           pod_reason=(pod.get("status") or {}).get("reason"))
        return (meta["name"], containers[0]["containerID"], termination)

    proc = None
    readers = []
    try:
        before = await owned_pod()
        if before is None:
            return result
        # The API-side cap avoids downloading a large build log. Independent
        # stream caps also bound a failed or nonconforming CLI's output.
        args = [k8s_lab.kubectl_binary(), *k8s_lab._context_args(), "logs", before[0],
                "-n", ns, "-c", "kaniko", "--tail=-1", f"--limit-bytes={limit + 1}",
                "--request-timeout=15s"]
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE, start_new_session=True)
        async def bounded(stream, cap):
            chunks = []; size = 0
            while True:
                chunk = await stream.read(min(8192, cap + 1 - size))
                if not chunk:
                    return b"".join(chunks)
                size += len(chunk)
                if size > cap:
                    raise OverflowError("bounded build log output")
                chunks.append(chunk)
        readers = [asyncio.create_task(bounded(proc.stdout, limit + 1)),
                   asyncio.create_task(bounded(proc.stderr, 4096))]
        out, _ = await asyncio.wait_for(asyncio.gather(*readers), timeout=20)
        rc = await asyncio.wait_for(proc.wait(), timeout=2)
        if rc:
            result["status"] = "read-failed"
            return result
        if await owned_pod() != before:
            result["status"] = "identity-changed"
            return result
        retained = out[-limit:]
        result.update(status="captured", job_uid=job_uid, pod_uid=pod_uid,
                      pod=before[0], container_id=before[1], termination=before[2], retained_bytes=len(retained),
                      retained_sha256=hashlib.sha256(retained).hexdigest(),
                      truncated=len(out) > limit, text=retained.decode("utf-8", "replace"))
        return result
    except asyncio.CancelledError:
        raise
    except (asyncio.TimeoutError, TimeoutError):
        result["status"] = "read-timeout"
        return result
    except Exception:
        result["status"] = "read-failed"
        return result
    finally:
        for reader in readers:
            if not reader.done(): reader.cancel()
        if readers:
            await asyncio.gather(*readers, return_exceptions=True)
        await terminate_and_reap(proc, process_group=True)


async def _wait_job(job_name: str, ns: str, *, timeout: int) -> str:
    deadline = asyncio.get_running_loop().time() + max(5, timeout)
    while asyncio.get_running_loop().time() < deadline:
        doc, rc = await _get_json("job", job_name, ns=ns, timeout=20)
        st = (doc.get("status") or {}) if rc == 0 else {}
        if int(st.get("succeeded") or 0) >= 1:
            return "Succeeded"
        if int(st.get("failed") or 0) >= 1:
            return "Failed"
        await asyncio.sleep(2.0)
    return "timeout"


async def _wait_image_job(job_name, ns, *, timeout, identity, send, repo_id):
    """Observe bounded owned compiler output; telemetry never grants build success."""
    async def poll():
        previous = None
        while True:
            await asyncio.sleep(15)
            snapshot = await _owned_build_log(job_name, ns, identity)
            if snapshot.get("status") != "captured":
                await send(repo_id, "Live compiler output is unavailable; image completion remains unverified",
                           detail_id=f"{repo_id}-build-progress-{job_name}",
                           detail={"type": "image-build-progress", "status": snapshot.get("status"),
                                   "job": job_name, "namespace": ns})
                return
            fingerprint = snapshot.get("retained_sha256")
            if fingerprint == previous:
                continue
            previous = fingerprint
            from backend.scanners import _redact_scanner_output
            text = _redact_scanner_output(snapshot.get("text", ""))
            await send(repo_id, "Image builder output updated; compilation completion remains unverified",
                       detail_id=f"{repo_id}-build-progress-{job_name}",
                       detail={"type": "image-build-progress", "status": "running",
                               "job": job_name, "namespace": ns,
                               "job_uid": snapshot["job_uid"], "pod_uid": snapshot["pod_uid"],
                               "container_id": snapshot["container_id"], "text": text,
                               "output_truncated": snapshot.get("truncated", False) or len(snapshot.get("text", "")) > 12000,
                               "output_scope": "Latest redacted compiler tail; at most 12000 characters, refreshed no faster than 15 seconds. Not runtime validation."})
    waiter = asyncio.create_task(_wait_job(job_name, ns, timeout=timeout))
    reader = asyncio.create_task(poll()) if send else None
    try:
        if reader is not None:
            # A failed lease/control send is not optional telemetry. Propagate
            # it and drain both children before the caller's owned cleanup.
            await asyncio.wait({waiter, reader}, return_when=asyncio.FIRST_COMPLETED)
            if reader.done() and not reader.cancelled() and reader.exception() is not None:
                raise reader.exception()
        return await waiter
    finally:
        pending = [child for child in (reader, waiter) if child is not None]
        for child in pending:
            if not child.done(): child.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


def _build_job_uid(document: Dict, job_name: str, ns: str) -> str:
    meta = document.get("metadata") or {}
    labels = meta.get("labels") or {}
    if (meta.get("name") != job_name or meta.get("namespace") != ns
            or labels.get("lotus.io/job") != job_name or labels.get("role") != "image-build"):
        return ""
    return str(meta.get("uid") or "")


async def _completed_build_digest(job_name: str, ns: str, job_uid: str) -> Optional[str]:
    """Accept Kaniko's digest only from this completed Job's unique owned Pod."""
    job, rc = await _get_json("job", job_name, ns=ns)
    if rc or not job_uid or _build_job_uid(job, job_name, ns) != job_uid:
        return None
    if int((job.get("status") or {}).get("succeeded") or 0) != 1:
        return None
    document, rc = await _get_json("pods", ns=ns, selector=f"job-name={job_name}")
    pods = document.get("items") or []
    if rc or len(pods) != 1:
        return None
    pod = pods[0]
    meta, status = pod.get("metadata") or {}, pod.get("status") or {}
    if (not meta.get("uid") or meta.get("namespace") != ns or status.get("phase") != "Succeeded"
            or (meta.get("labels") or {}).get("lotus.io/job") != job_name):
        return None
    if not any(owner.get("kind") == "Job" and owner.get("name") == job_name
               and owner.get("uid") == job_uid and owner.get("controller") is True
               for owner in meta.get("ownerReferences") or []):
        return None
    containers = [entry for entry in status.get("containerStatuses") or [] if entry.get("name") == "kaniko"]
    if len(containers) != 1:
        return None
    terminated = (containers[0].get("state") or {}).get("terminated") or {}
    digest = str(terminated.get("message") or "").strip()
    if terminated.get("exitCode") != 0 or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        return None
    return digest


async def _cleanup_build_context(ownership):
    from backend import k8s_network_guard as network
    if not ownership.get("attempted"):
        return
    ns, name = ownership["namespace"], ownership["name"]
    current = await network._read(ns, "PersistentVolumeClaim", name)
    if current is None:
        return
    metadata = current.get("metadata", {})
    if (not ownership.get("uid") or metadata.get("uid") != ownership["uid"]
            or metadata.get("labels", {}).get("lotus.io/build-context-owner") != ownership["owner"]):
        raise network.NetworkIsolationUnavailable("Build context cleanup refused unknown or replaced PVC identity; volume retained")
    pods = await network._read(ns, "Pod")
    if not isinstance(pods, dict) or not isinstance(pods.get("items"), list):
        raise network.NetworkIsolationUnavailable("Build context Pod references could not be inventoried; volume retained")
    if any(volume.get("persistentVolumeClaim", {}).get("claimName") == name
           for pod in pods["items"] for volume in pod.get("spec", {}).get("volumes", [])):
        raise network.NetworkIsolationUnavailable("Build context is still referenced by a Pod; volume retained")
    await network._delete(ns, "PersistentVolumeClaim", name, ownership["uid"])


async def build_image(repo_id: int, name: str, context_dir: Path, *,
                      tag: str = "latest", dockerfile: str = "Dockerfile",
                      build_args: Optional[Dict[str, str]] = None,
                      timeout: int = 1800, send=None, return_digest: bool = False,
                      source_tree_hash: Optional[str] = None) -> Optional[str]:
    """Build ``context_dir`` with kaniko and push to the in-cluster registry.

    Returns the fully-qualified image reference (``<host>/lotus/<id>-<name>:<tag>``)
    the run Jobs should pull. A failed executor raises a fixed typed diagnostic
    after retaining its bounded owned log; setup refusals may return ``None``.
    ``return_digest=True``
    returns an immutable reference attested by the owned Kaniko Pod instead.
    """
    host = await ensure_registry(send=send, repo_id=repo_id, timeout=min(timeout, 300))
    if not host:
        return None
    if not (Path(context_dir) / dockerfile).is_file():
        if send:
            await send(repo_id, f"build context missing {dockerfile}", level="warning")
        return None
    ns = build_namespace()
    pvc = _ctx_pvc_name(repo_id, uuid.uuid4().hex[:6])
    dest = image_ref(host, repo_id, name, tag)
    job = f"lotus-build-{int(repo_id)}-{uuid.uuid4().hex[:6]}"[:63]
    guard = None
    context_ownership = {}
    stage = "registry"
    primary_error = None
    failed_log = None
    executor_failed = False
    # Only the native service caller supplies its already-attested source identity.
    recipe_path = Path(context_dir) / dockerfile
    recipe_hash = None
    if re.fullmatch(r"sha256:[a-f0-9]{64}", source_tree_hash or ""):
        if not recipe_path.is_symlink() and recipe_path.stat().st_size <= 256 * 1024:
            recipe_hash = hashlib.sha256(recipe_path.read_bytes()).hexdigest()
    from backend import k8s_network_guard
    try:
        registry = await k8s_network_guard.registry_binding(ns, host.rsplit(":", 1)[0], registry_nodeport())
        manifest = _kaniko_job(job, pvc, dest, dockerfile=f"/workspace/{dockerfile}",
                               build_args=build_args, timeout=timeout, return_digest=return_digest)
        manifest["metadata"]["labels"]["lotus.io/repo-id"] = str(int(repo_id))
        if not await _populate_context(pvc, Path(context_dir), repo_id, timeout=min(timeout, 600), ownership=context_ownership):
            if send:
                await send(repo_id, "k8s build context upload failed", level="warning")
            return None
        context_ownership.pop("stage", None)
        stage = "build-admission"
        guard = await k8s_network_guard.prepare(manifest, profile="public", registry=registry)
        out, rc = await apply(guard.manifest, timeout=60)
        if rc != 0:
            if send:
                await send(repo_id, f"k8s kaniko apply failed: {out[-400:]}", level="warning")
            return None
        admission_identity = await guard.release()
        job_uid = ""
        if return_digest:
            document, rc = await _get_json("job", job, ns=ns)
            job_uid = _build_job_uid(document, job, ns) if rc == 0 else ""
            if not job_uid:
                if send:
                    await send(repo_id, "k8s build identity unavailable; immutable image cannot be verified", level="warning")
                return None
        stage = "image-build"
        phase = await _wait_image_job(job, ns, timeout=timeout, identity=admission_identity or {}, send=send, repo_id=repo_id)
        if phase != "Succeeded":
            logs = await _owned_build_log(job, ns, admission_identity or {})
            if phase == "Failed":
                failed_log = deepcopy(logs)
            if send:
                await send(repo_id, "Isolated image build exceeded its deadline" if phase == "timeout"
                           else "Isolated image build failed; open the retained build log",
                           level="warning", detail=logs, detail_id=f"{repo_id}-build-log-{job}")
            raise _ExecutorFailure(phase)
        if return_digest:
            digest = await _completed_build_digest(job, ns, job_uid)
            if not digest:
                if send:
                    await send(repo_id, "k8s build completed without an owned immutable image digest", level="warning")
                return None
            dest = dest.rsplit(":", 1)[0] + "@" + digest
        if send:
            await send(repo_id, f"k8s image built + pushed ({dest})", level="info")
        return dest
    except Exception as exc:
        executor_failed = (type(exc) is _ExecutorFailure and exc.code == "executor-failed" and stage == "image-build")
        primary_error = BuildImageFailure(context_ownership.get("stage", stage), exc)
        raise primary_error from exc
    finally:
        async def cleanup():
            if guard is not None:
                guard.released = False
            # A failed exact workload drain preserves the context and its
            # policy. Never override an ownership refusal with name deletion.
            errors = []
            try:
                await k8s_network_guard.close(guard)
            except Exception as exc:
                errors.append(exc)
            # Even if an unrelated control failed cleanup, this independently
            # proves exact PVC ownership and absence of every Pod consumer.
            try:
                await _cleanup_build_context(context_ownership)
            except Exception as exc:
                errors.append(exc)
            if errors:
                raise BuildImageFailure("build-cleanup", primary_error or errors[0],
                                        cleanup_errors=errors if primary_error else errors[1:])
        task = asyncio.create_task(cleanup())
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            raise
        # Reached only after both exact-owned cleanup paths succeeded. A thrown
        # cleanup/cancellation never publishes repair authority. Bind the exact
        # captured log to admission, recipe and source before saving privately.
        if executor_failed and primary_error is not None and recipe_hash and failed_log is not None:
            try:
                recipe_unchanged = (not recipe_path.is_symlink() and recipe_path.stat().st_size <= 256 * 1024
                    and hashlib.sha256(recipe_path.read_bytes()).hexdigest() == recipe_hash)
            except OSError:
                recipe_unchanged = False
            if (recipe_unchanged and context_ownership.get("attempted") is True
                    and context_ownership.get("uid") and context_ownership.get("owner")
                    and context_ownership.get("name") == pvc and context_ownership.get("namespace") == ns
                    and failed_log.get("status") == "captured"
                    and failed_log.get("job") == job and failed_log.get("namespace") == ns
                    and failed_log.get("job_uid") == (admission_identity or {}).get("workload_uid")
                    and failed_log.get("pod_uid") == (admission_identity or {}).get("pod_uid")
                    and failed_log.get("job_uid") and failed_log.get("pod_uid")
                    and failed_log.get("container_id") and failed_log.get("pod")
                    and isinstance(failed_log.get("text"), str)
                    and len(failed_log["text"].encode()) <= 3 * 128 * 1024):
                _REPAIR_EVIDENCE[primary_error] = {
                    "schema_version": 1, "source_tree_hash": source_tree_hash,
                    "recipe_sha256": recipe_hash, "cleanup_verified": True,
                    "failure": {"stage": "image-build", "code": "executor-failed", "cleanup_errors": []},
                    "context_pvc_uid": context_ownership["uid"], "log": failed_log,
                }


async def image_exists(repo_id: int, name: str, tag: str = "latest", *, timeout: int = 90) -> bool:
    """Registry cache probe: is ``lotus/<id>-<name>:<tag>`` already pushed?

    Preserves the Docker path's per-repo image-cache semantics via registry
    tags.  Runs in-cluster (the registry NodePort is not reachable from the API
    host on kind/Docker-Desktop).
    """
    host = _REGISTRY.get("host") or await registry_host()
    if not host:
        return False
    safe = re.sub(r"[^a-z0-9._-]", "-", str(name).lower()).strip("-") or "img"
    repo = f"lotus/{int(repo_id)}-{safe}"
    ns = build_namespace()
    job = f"lotus-imgchk-{int(repo_id)}-{uuid.uuid4().hex[:6]}"[:63]
    url = f"http://{host}/v2/{repo}/tags/list"
    manifest = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": job, "namespace": ns, "labels": {"role": "image-check"}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": int(timeout),
                 "ttlSecondsAfterFinished": 60,
                 "template": {"metadata": {"labels": {"role": "image-check"}}, "spec": {
                     "automountServiceAccountToken": False, "restartPolicy": "Never",
                     "containers": [{"name": "chk", "image": str(os.environ.get("LOTUS_K8S_POPULATOR_IMAGE") or "alpine:3.20"),
                                     "command": ["sh", "-c", f"wget -qO- '{url}' || true"],
                                     "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                                                   "limits": {"cpu": "500m", "memory": "256Mi"}}}],
                 }}},
    }
    try:
        _out, rc = await apply(manifest, timeout=60)
        if rc != 0:
            return False
        if await _wait_job(job, ns, timeout=timeout) != "Succeeded":
            return False
        logs = await _job_logs(job, ns, timeout=30)
        try:
            doc = json.loads(logs.strip().splitlines()[-1]) if logs.strip() else {}
        except Exception:
            return False
        return tag in (doc.get("tags") or [])
    finally:
        await _run(["delete", "job", job, "-n", ns, "--ignore-not-found=true", "--wait=false"],
                   timeout=30)


def containerd_hosts_toml(host: str) -> str:
    """The node ``certs.d`` config that trusts the plain-HTTP registry."""
    return (f'[host."http://{host}"]\n'
            '  capabilities = ["pull", "resolve"]\n'
            '  skip_verify = true\n')


async def cleanup_registry() -> None:
    """Delete registry resources without deleting administrator-owned RBAC."""
    _REGISTRY["host"] = None
    await _run(["delete", "deployment/lotus-registry", "service/lotus-registry",
                "pvc/lotus-registry-data", "-n", build_namespace(),
                "--ignore-not-found=true", "--wait=false"], timeout=60)
