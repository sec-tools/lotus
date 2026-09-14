"""Kubernetes-native disposable lab runner.

This module deliberately uses the ``kubectl`` CLI instead of importing a
cluster client.  The API image stays small, while operators can pin kubectl
and its credentials in the runner image.  Every operation is bounded, uses
JSON manifests (no shell interpolation), and returns enough identity for a
proof receipt: Job UID, Pod UID and the image's resolved digest.

The runner contract is intentionally conservative:

* source must be an HTTPS/SSH Git URL (or a prebuilt immutable image); local
  host paths cannot be mounted into a cluster Job;
* a repository plan supplies the command and optional image;
* the provider waits for a Ready pod, not merely Job creation;
* teardown is idempotent and never deletes resources outside its labels.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from backend.async_process import terminate_and_reap


def kubectl_binary() -> str:
    return (os.environ.get("LOTUS_KUBECTL") or "kubectl").strip() or "kubectl"


def namespace() -> str:
    value = (os.environ.get("LOTUS_K8S_NAMESPACE") or "lotus").strip()
    return value if re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", value) else "lotus"


def _context_args() -> list[str]:
    context = (os.environ.get("LOTUS_K8S_CONTEXT") or "").strip()
    return ["--context", context] if context else []


async def _run(args: list[str], *, input_data: Optional[bytes] = None, timeout: int = 30,
               max_output: Optional[int] = 12000) -> Tuple[str, int]:
    binary = kubectl_binary()
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, *_context_args(), *args,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(input=input_data), timeout=timeout)
        except asyncio.CancelledError:
            await terminate_and_reap(proc)
            raise
        except asyncio.TimeoutError:
            await terminate_and_reap(proc)
            return f"kubectl timed out after {timeout}s", -1
        text = (out or b"").decode(errors="replace")
        stderr = (err or b"").decode(errors="replace")
        combined = text + (f"\n{stderr}" if stderr else "")
        # The default cap keeps control/log commands from flooding memory, but
        # structured readers (``get_json``) MUST opt out: truncating a JSON
        # document to its tail yields invalid JSON and silently drops objects
        # (e.g. a large pod spec whose embedded tool script pushes the doc past
        # the cap), which would make phase/readiness waits hang until timeout.
        if max_output and len(combined) > max_output:
            combined = combined[-max_output:]
        return combined, int(proc.returncode or 0)
    except Exception as exc:
        return f"kubectl execution error: {str(exc)[:500]}", -1


async def cluster_available() -> Tuple[bool, str]:
    """Check that kubectl is present *and* points at a reachable cluster."""
    out, rc = await _run(["version", "--output=json", "--request-timeout=5s"], timeout=10)
    if rc != 0:
        return False, out[-800:]
    return True, out[-800:]


def _valid_source_url(value: str) -> bool:
    parsed = urlparse(str(value or ""))
    # Cluster bootstrap is part of the proof boundary.  Plain HTTP would let
    # a network attacker substitute the source before the tree check (or steal
    # credentials supplied by a dependency helper), so it is never accepted
    # for a Kubernetes replay.  Local Docker remains the explicit break-glass
    # for non-network development targets.
    if parsed.scheme in {"https", "ssh"} and parsed.netloc:
        # Never embed URL userinfo; credentials in clone URLs would be exposed
        # in the Job manifest and Kubernetes audit log.
        return not parsed.username and not parsed.password
    return False


def _allow_unpinned_image() -> bool:
    """Explicit local break-glass for a mutable development image tag."""
    return (os.environ.get("LOTUS_ALLOW_UNPINNED_K8S_IMAGE") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _immutable_image_ref(value: str) -> bool:
    """Require a content-addressed OCI image reference for proof runs."""
    return bool(re.search(r"@sha256:[0-9a-f]{64}$", str(value or "").strip(), re.I))


def _name(repo_id: int) -> str:
    return f"lotus-lab-{int(repo_id)}-{uuid.uuid4().hex[:8]}"


def _load_request(dest: Path) -> Dict[str, Any]:
    for filename in ("lab_request.json", "audit_plan.json"):
        path = Path(dest) / ".lotus" / filename
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                if filename == "audit_plan.json" and isinstance(value.get("k8s_lab"), dict):
                    return {**value, **value["k8s_lab"]}
                return value
        except Exception:
            continue
    return {}


def _command_for(request: Dict[str, Any], app_type: str) -> str:
    install = [str(v).strip() for v in (request.get("install_steps") or []) if str(v).strip()]
    start = str(request.get("start_command") or "").strip()
    if start:
        start = start.replace("${PORT}", str(int(request.get("port") or 3000)))
    elif app_type in {"library", "cli-tool", "unknown"}:
        start = "sleep 3600"
    else:
        start = "python3 -m http.server ${PORT} --bind 0.0.0.0 --directory /workspace".replace(
            "${PORT}", str(int(request.get("port") or 3000))
        )
    # Build/install commands are untrusted repository content.  They execute
    # inside the restricted pod, never through the API shell; join with `&&`
    # so a failed install cannot masquerade as a healthy service.
    return "set -eu; " + ("; ".join(install) + "; " if install else "") + start


def _lab_resources() -> Dict[str, Any]:
    """Resolve saved target-Pod caps without letting a request override them."""
    memory_mb, cpus = 4096, 2.0
    from backend.main import SessionLocal, Settings
    with SessionLocal() as db:
        settings = db.query(Settings).first()
        if settings is not None:
            memory_mb = int(settings.lab_memory_mb)
            cpus = float(settings.lab_cpus)
    if not 256 <= memory_mb <= 1048576 or not 0.25 <= cpus <= 64:
        raise ValueError("Saved lab memory/CPU caps are invalid; correct Settings before launching a lab")
    return {"requests": {"cpu": f"{int(min(cpus, 0.5) * 1000)}m", "memory": f"{min(memory_mb, 512)}Mi"},
            "limits": {"cpu": format(cpus, "g"), "memory": f"{memory_mb}Mi"}}


def build_manifest(repo_id: int, request: Dict[str, Any], app_type: str = "unknown") -> Dict[str, Any]:
    """Build a Job + Service List manifest without shelling out or host mounts."""
    ns = namespace()
    job_name = _name(repo_id)
    service_name = f"{job_name}-svc"
    labels = {"role": "lab-container", "lotus.io/repo-id": str(int(repo_id)), "lotus.io/job": job_name}
    image = str(request.get("image") or os.environ.get("LOTUS_K8S_LAB_IMAGE") or "").strip()
    if not image or any(ch in image for ch in "\r\n"):
        raise ValueError("Kubernetes lab requires LOTUS_K8S_LAB_IMAGE or a request image")
    if not _immutable_image_ref(image) and not _allow_unpinned_image():
        raise ValueError("Kubernetes lab image must be pinned by digest (@sha256:<64 hex>)")
    port = int(request.get("port") or 3000)
    if not 1 <= port <= 65535:
        raise ValueError("invalid Kubernetes lab port")
    image_entrypoint = request.get("use_image_entrypoint") is True
    embedded_source = request.get("source_embedded") is True
    command = None if image_entrypoint else _command_for({**request, "port": port}, app_type)
    source_url = str(request.get("source_url") or request.get("source") or "").strip()
    if embedded_source and (source_url or not image_entrypoint):
        raise ValueError("embedded Kubernetes source requires its built image entrypoint without a second source checkout")
    revision = str(request.get("target_revision") or request.get("revision") or "").strip()
    git_tree = str(request.get("target_tree") or request.get("git_tree") or "").strip()
    branch = str(request.get("effective_branch") or request.get("branch") or "main").strip()
    resources = _lab_resources()
    # Carry immutable target identity in Kubernetes metadata so lab inventory
    # remains useful after an API restart.  Annotations are used instead of
    # labels because Git hashes/revisions are not guaranteed to fit label
    # grammar/length limits.  They are informational recovery metadata; the
    # init container still verifies the tree before the pod becomes Ready.
    target_annotations = {}
    for key, value in (
        ("lotus.io/target-revision", revision),
        ("lotus.io/target-tree", git_tree),
        ("lotus.io/target-tree-hash", str(request.get("target_tree_hash") or "").strip()),
    ):
        text = str(value or "")
        if text and "\n" not in text and "\r" not in text:
            target_annotations[key] = text[:4096]
    init_containers = []
    if source_url:
        if not _valid_source_url(source_url):
            raise ValueError("Kubernetes lab requires a credential-free Git URL; local paths are not cluster-readable")
        # URL/ref are passed as argv to the git image entrypoint script, not
        # interpolated into a host shell.  The command itself is a fixed script.
        clone = ["sh", "-ceu", "git clone --depth 1 --no-tags --branch \"$BRANCH\" -- \"$SOURCE_URL\" /workspace; if [ -n \"$REVISION\" ]; then cd /workspace && git fetch --depth 1 origin \"$REVISION\" && git checkout --detach \"$REVISION\"; fi; if [ -n \"$GIT_TREE\" ]; then cd /workspace && test \"$(git rev-parse HEAD^{tree})\" = \"$GIT_TREE\" || { echo 'target Git tree mismatch'; exit 19; }; fi"]
        init_containers.append({
            "name": "source",
            "image": str(os.environ.get("LOTUS_K8S_GIT_IMAGE") or "alpine/git:2.45.2"),
            "command": clone,
            "env": [
                {"name": "SOURCE_URL", "value": source_url},
                {"name": "BRANCH", "value": branch or "main"},
                {"name": "REVISION", "value": revision},
                {"name": "GIT_TREE", "value": git_tree},
            ],
            "volumeMounts": [{"name": "workspace", "mountPath": "/workspace"}],
            "resources": resources,
            "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
        })
    else:
        # A prebuilt image is a valid cluster contract; source-less jobs are
        # useful for published release images but are explicitly marked in the
        # returned metadata as not source-replayable.
        if not request.get("image") and not os.environ.get("LOTUS_K8S_LAB_IMAGE"):
            raise ValueError("no source URL or prebuilt Kubernetes lab image was supplied")
    pod_spec = {
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
        "initContainers": init_containers,
        "containers": [{
            "name": "lab", "image": image, "imagePullPolicy": str(request.get("image_pull_policy") or "IfNotPresent"),
            "command": ["sh", "-lc", command],
            "ports": [{"name": "http", "containerPort": port, "protocol": "TCP"}],
            "env": [{"name": "PORT", "value": str(port)}],
            "resources": resources,
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": False, "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [{"name": "workspace", "mountPath": "/workspace"}, {"name": "tmp", "mountPath": "/tmp"}],
        }],
        "restartPolicy": "Never",
        "volumes": [{"name": "workspace", "emptyDir": {"sizeLimit": "2Gi"}}, {"name": "tmp", "emptyDir": {"sizeLimit": "512Mi"}}],
    }
    lab_container = pod_spec["containers"][0]
    if image_entrypoint:
        # Preserve the repository image's ENTRYPOINT, CMD and WORKDIR. Replacing
        # them with a generic shell can hide an invalid application launcher.
        lab_container.pop("command", None)
    if embedded_source:
        # No unsolicited mount may hide source baked into a repository image,
        # including apps rooted under /tmp. The image filesystem is writable.
        # Kubernetes omits an empty volumeMounts list on readback. Generate
        # that canonical form so exact admission comparisons remain strict.
        lab_container.pop("volumeMounts", None)
        pod_spec["volumes"] = []
        runtime_user = request.get("runtime_user") or {"uid": 1000, "gid": 1000}
        if (not isinstance(runtime_user, dict)
                or any(type(runtime_user.get(key)) is not int or not 1 <= runtime_user[key] <= 2147483647
                       for key in ("uid", "gid"))):
            raise ValueError("embedded Kubernetes image requires an attested non-root numeric runtime user")
        pod_spec["securityContext"].update(runAsUser=runtime_user["uid"], runAsGroup=runtime_user["gid"])
        runtime_environment = request.get("runtime_environment") or {}
        if (not isinstance(runtime_environment, dict) or len(runtime_environment) > 256
                or any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                       or not isinstance(value, str) or "\x00" in value or len(value) > 32768
                       for key, value in runtime_environment.items())
                or len(json.dumps(runtime_environment).encode()) > 65536):
            raise ValueError("embedded Kubernetes image requires a bounded literal runtime environment")
        environment = {"PORT": str(port), **runtime_environment}
        # Kubelet expands $(VAR) in env.value. Escape dollars so a literal
        # Compose value keeps its meaning without importing controller values.
        lab_container["env"] = [{"name": key, "value": value.replace("$", "$$")} for key, value in environment.items()]
    # Keep this controller-owned identity outside image/Compose environment
    # overrides. Notebook exec validates it before running a user's command.
    from backend.notebook_lab import POD_UID_ENV
    lab_container["env"] = [row for row in lab_container["env"] if row["name"] != POD_UID_ENV]
    lab_container["env"].append({"name": POD_UID_ENV, "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}}})
    if app_type not in {"library", "cli-tool", "unknown"}:
        # Pod Running is not application readiness. Keep bootstrap open until
        # the selected application actually accepts connections at its port.
        lab_container["readinessProbe"] = {
            "tcpSocket": {"port": port}, "periodSeconds": 2,
            "timeoutSeconds": 1, "failureThreshold": 3,
        }
    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": job_name, "namespace": ns, "labels": dict(labels), "annotations": {"lotus.io/repo-id": str(repo_id), **target_annotations}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": int(os.environ.get("LOTUS_K8S_JOB_DEADLINE", "3600")), "ttlSecondsAfterFinished": 300, "template": {"metadata": {"labels": dict(labels), "annotations": target_annotations}, "spec": pod_spec}},
    }
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": service_name, "namespace": ns, "labels": dict(labels)},
        "spec": {"selector": dict(labels), "ports": [{"name": "http", "port": port, "targetPort": port}], "type": "ClusterIP"},
    }
    return {"apiVersion": "v1", "kind": "List", "items": [job, service], "_meta": {"job_name": job_name, "service_name": service_name, "namespace": ns, "port": port, "labels": dict(labels)}}


def bootstrap_network_policy(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Allow only source bootstrap/build egress until the pod is Ready.

    The checked-in lab isolation policy is deny-all egress.  A short-lived,
    per-Job policy is applied before the Job so a Git init-container and locked
    dependency install can complete.  It is deleted immediately after
    readiness; Kubernetes NetworkPolicy rules are additive, so deletion leaves
    the static deny-all policy in force for Phase 2.
    """
    meta = manifest.get("_meta") or {}
    job_name = str(meta.get("job_name") or "")
    labels = dict(meta.get("labels") or {})
    if not job_name or not labels:
        raise ValueError("manifest has no target-bound Job metadata")
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"{job_name}-bootstrap",
            "namespace": str(meta.get("namespace") or namespace()),
            "labels": dict(labels),
        },
        "spec": {
            "podSelector": {"matchLabels": labels},
            "policyTypes": ["Egress"],
            "egress": [
                {"ports": [{"protocol": "UDP", "port": 53}]},
                {"ports": [{"protocol": "TCP", "port": 80}, {"protocol": "TCP", "port": 443}]},
            ],
        },
    }


async def apply(manifest: Dict[str, Any], timeout: int = 60) -> Tuple[str, int]:
    payload = json.dumps({k: v for k, v in manifest.items() if not k.startswith("_")}, sort_keys=True).encode("utf-8")
    return await _run(["apply", "-f", "-"], input_data=payload, timeout=timeout)


async def get_json(kind: str, name: str = "", *, selector: str = "", timeout: int = 30) -> Tuple[Dict[str, Any], int, str]:
    args = ["get", kind]
    if name:
        args.append(name)
    if selector:
        args.extend(["-l", selector])
    args.extend(["-o", "json", "-n", namespace()])
    # Untruncated: a JSON reader cannot tolerate tail-truncation (see ``_run``).
    out, rc = await _run(args, timeout=timeout, max_output=None)
    try:
        value = json.loads(out)
        return (value if isinstance(value, dict) else {}, rc, out)
    except Exception:
        return {}, rc, out


async def wait_ready(job_name: str, *, timeout: int) -> Dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + max(5, timeout)
    selector = f"job-name={job_name}"
    last = ""
    while asyncio.get_running_loop().time() < deadline:
        pod_doc, rc, raw = await get_json("pods", selector=selector, timeout=20)
        last = raw[-1000:]
        pods = pod_doc.get("items") if isinstance(pod_doc, dict) else []
        if isinstance(pods, list):
            for pod in pods:
                if not isinstance(pod, dict):
                    continue
                status = pod.get("status") or {}
                phase = str(status.get("phase") or "")
                conditions = status.get("conditions") or []
                ready = any(isinstance(c, dict) and c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)
                if phase == "Failed":
                    return {"healthy": False, "status": "failed", "reason": "pod failed", "pod": pod, "raw": last}
                if phase == "Running" and ready:
                    return {"healthy": True, "status": "running", "pod": pod, "raw": last}
        job_doc, jrc, jraw = await get_json("job", job_name, timeout=20)
        if jrc == 0 and (job_doc.get("status") or {}).get("failed", 0):
            return {"healthy": False, "status": "failed", "reason": "job failed", "job": job_doc, "raw": jraw[-1000:]}
        await asyncio.sleep(1.5)
    return {"healthy": False, "status": "timeout", "reason": f"pod did not become Ready within {timeout}s", "raw": last}


async def delete(job_name: str, service_name: str = "", *, expected_state: Optional[dict] = None,
                 assert_owner=None) -> Dict[str, Any]:
    """Preflight owned objects, then delete only their immutable Kubernetes UIDs."""
    from backend.reset_runtime_ownership import delete_k8s_uid, _k8s_service_selector_matches, _check_recorded_guard_owner
    result: Dict[str, Any] = {"job": job_name, "service": service_name, "errors": []}
    state = dict(expected_state or {})
    ns = str(state.get("namespace") or namespace())
    async def read(kind, name):
        if not name:
            return None
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", name):
            raise RuntimeError("Invalid Kubernetes cleanup address")
        raw, rc = await _run(["get", kind, name, "-n", ns, "-o", "json", "--ignore-not-found=true"], timeout=15, max_output=None)
        if rc:
            raise RuntimeError("Kubernetes cleanup ownership could not be read: " + raw[-300:])
        if not raw.strip():
            return None
        try:
            doc = json.loads(raw)
            meta = doc["metadata"]
            expected_kind = {"job": "Job", "pod": "Pod", "service": "Service", "networkpolicy": "NetworkPolicy"}[kind]
            if doc.get("kind") != expected_kind or not meta.get("uid") or meta.get("name") != name or meta.get("namespace") != ns:
                raise ValueError()
            return doc
        except (ValueError, KeyError, TypeError):
            raise RuntimeError("Kubernetes cleanup returned incomplete object identity") from None
    try:
        if not job_name or ns != namespace():
            raise RuntimeError("Kubernetes cleanup requires the recorded Job and configured namespace")
        selected = []
        job = await read("job", job_name)
        if job is None and expected_state is None:
            # A retried failed-start cleanup is a no-op when every generated
            # address is absent. Remaining orphan names need recorded ownership.
            service = await read("service", service_name)
            policy = await read("networkpolicy", f"{job_name}-bootstrap")
            if service is None and policy is None:
                return {**result, "ok": True}
            raise RuntimeError("Original Kubernetes Job is absent; remaining resource ownership must be recovered")
        labels = (job or {}).get("metadata", {}).get("labels", {})
        repo = str(state.get("repo_id") or labels.get("lotus.io/repo-id") or "")
        expected_labels = {"role": "lab-container", "lotus.io/repo-id": repo, "lotus.io/job": job_name}
        if not repo.isdigit():
            raise RuntimeError("Kubernetes cleanup has no exact repository ownership")
        job_uid = state.get("job_uid")
        pod_name = str(state.get("pod") or state.get("container") or "")
        pod = await read("pod", pod_name) if expected_state is not None else None
        if expected_state is not None and job and pod is None:
            raise RuntimeError("Original Kubernetes Pod UID is unavailable; owned cleanup is required")
        if pod:
            meta = (pod or {}).get("metadata") or {}
            if not state.get("pod_uid") or meta.get("uid") != state["pod_uid"]:
                raise RuntimeError("Original Kubernetes Pod UID is unavailable; owned cleanup is required")
            if any((meta.get("labels") or {}).get(key) != value for key, value in expected_labels.items()):
                raise RuntimeError("Original Kubernetes Pod ownership labels changed")
            current = next((row for row in (pod.get("status") or {}).get("containerStatuses") or []
                            if row.get("name") == "lab"), {})
            if state.get("container_id") and state["container_id"] != current.get("containerID"):
                raise RuntimeError("Original Kubernetes container instance changed; replacement retained")
            owner = next((row for row in meta.get("ownerReferences") or []
                          if row.get("kind") == "Job" and row.get("controller") is True and row.get("name") == job_name), {})
            owner_uid = owner.get("uid")
            if not owner_uid or (job_uid and owner_uid != job_uid):
                raise RuntimeError("Original Kubernetes Pod has no exact Job owner")
            job_uid = owner_uid
        if job and job_uid and job["metadata"]["uid"] != job_uid:
            raise RuntimeError("Kubernetes Job name was reused; replacement retained")
        receipts = (state.get("cleanup_identity") or {}).get("resources") or []
        recorded_uids = {(row.get("kind"), row.get("name")): row.get("uid") for row in receipts if isinstance(row, dict)}
        if state.get("pod_uid"):
            recorded_uids.setdefault(("pod", pod_name), state["pod_uid"])
        for kind, name in (("job", job_name), ("pod", pod_name), ("service", service_name), ("networkpolicy", f"{job_name}-bootstrap")):
            doc = job if kind == "job" else pod if kind == "pod" else await read(kind, name)
            if not doc:
                continue
            meta = doc["metadata"]
            if any((meta.get("labels") or {}).get(key) != value for key, value in expected_labels.items()):
                raise RuntimeError(f"Kubernetes {kind} does not belong to the recorded lab")
            _check_recorded_guard_owner(doc, kind, state)
            if kind == "service" and not _k8s_service_selector_matches(doc, expected_labels, state):
                raise RuntimeError("Kubernetes Service no longer selects the recorded lab")
            if kind == "job" and state.get("target_tree_hash") and (meta.get("annotations") or {}).get("lotus.io/target-tree-hash") != state["target_tree_hash"]:
                raise RuntimeError("Kubernetes Job source identity changed")
            if (kind, name) in recorded_uids and recorded_uids[(kind, name)] != meta["uid"]:
                raise RuntimeError(f"Kubernetes {kind} UID differs from its cleanup receipt")
            if not job and expected_state is not None and (kind, name) not in recorded_uids:
                raise RuntimeError("Original Job is absent and remaining resource UIDs were not recorded")
            selected.append((kind, name, meta["uid"]))
        for kind, name, uid in selected:
            if assert_owner:
                assert_owner()
            await delete_k8s_uid(kind, name, ns, uid)
        # API acknowledgement may precede finalizers and Pod shutdown. Retain
        # registry state if cleanup cannot be observed complete within the bound.
        deadline = asyncio.get_running_loop().time() + 20
        while selected:
            remaining = []
            for kind, name, uid in selected:
                current = await read(kind, name)
                if current:
                    if current["metadata"]["uid"] != uid:
                        raise RuntimeError("Kubernetes name was reused during deletion; replacement retained")
                    remaining.append((kind, name, uid))
            selected = remaining
            if selected:
                if asyncio.get_running_loop().time() >= deadline:
                    raise RuntimeError("Kubernetes lab deletion is still pending; retry after shutdown/finalizers complete")
                await asyncio.sleep(.25)
    except Exception as exc:
        result["errors"].append(str(exc)[:500])
    result["ok"] = not result["errors"]
    return result


def image_digest(pod: Dict[str, Any]) -> str:
    statuses = (pod.get("status") or {}).get("containerStatuses") or []
    for status in statuses:
        raw = str(status.get("imageID") or "")
        match = re.search(r"sha256:[0-9a-f]{64}", raw, re.I)
        if match:
            return match.group(0).lower()
    return ""
