"""Attested operator-owned Kubernetes identity endpoints with bounded forwarding.

Source annotations are operator assertions. Runtime UIDs/digests establish which
local service was observed, not that its binary is equivalent to audited source.
"""
import asyncio
from contextlib import asynccontextmanager
import json
import ipaddress
import os
import re

from backend.async_process import terminate_and_reap
from backend.deployment_inventory import digest


def _prefix():
    from backend import k8s_lab
    return [k8s_lab.kubectl_binary(), *k8s_lab._context_args(), "--request-timeout=10s"]


async def _read(kind, name, namespace=None):
    from backend.deployment_passive import _command
    args = [*_prefix(), *(["-n", namespace] if namespace else []), "get", kind, name, "-o", "json"]
    output, rc, error = await _command(args, timeout=15, limit=2_000_000)
    if rc:
        raise ValueError("Owned local runtime is unavailable: " + (error or output)[-300:])
    return json.loads(output)


def _assert_source(value, static):
    meta = value.get("metadata") or {}
    labels, annotations = meta.get("labels") or {}, meta.get("annotations") or {}
    expected = {"app.kubernetes.io/managed-by": "lotus", "lotus.io/purpose": "deployment-identity",
                "lotus.io/repo-id": str(static["repo_id"]), "lotus.io/scan-job-id": str(static["scan_job_id"])}
    if not meta.get("uid") or any(labels.get(key) != value for key, value in expected.items()):
        raise ValueError("Local Service/Pod ownership does not match the selected audit")
    if annotations.get("lotus.io/target-tree-hash") != static["target_tree_hash"] or annotations.get("lotus.io/target-revision", "") != static.get("target_revision", ""):
        raise ValueError("Operator source annotations do not match the selected audit revision")


async def attest(namespace, service_name, port, static):
    allowed = {value.strip() for value in os.environ.get("LOTUS_DEPLOYMENT_LOCAL_NAMESPACES", "").split(",") if value.strip()}
    if namespace not in allowed:
        raise ValueError("Namespace is not configured for owned local deployment observations")
    if not all(re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", value) for value in (namespace, service_name)):
        raise ValueError("Invalid local namespace or Service name")
    ns = await _read("namespace", namespace)
    labels = (ns.get("metadata") or {}).get("labels") or {}
    if labels.get("app.kubernetes.io/managed-by") != "lotus" or labels.get("lotus.io/purpose") != "deployment-identity":
        raise ValueError("Local namespace is not owned for deployment identity observations")
    service = await _read("service", service_name, namespace)
    _assert_source(service, static)
    spec = service.get("spec") or {}
    if spec.get("type", "ClusterIP") != "ClusterIP" or not spec.get("selector") or spec.get("externalIPs") or spec.get("clusterIP") in (None, "", "None"):
        raise ValueError("Only a selected, internal ClusterIP Service can be bound")
    selected_ports = [item for item in spec.get("ports", []) if item.get("port") == port and item.get("protocol", "TCP") == "TCP"]
    if len(selected_ports) != 1:
        raise ValueError("Selected TCP port does not belong to the owned Service")
    endpoints = await _read("endpoints", service_name, namespace)
    refs = [address.get("targetRef") or {} for subset in endpoints.get("subsets", []) for address in subset.get("addresses", [])]
    if not refs or len(refs) > 10 or any(ref.get("kind") != "Pod" or ref.get("namespace", namespace) != namespace for ref in refs):
        raise ValueError("Owned Service must have between one and ten Ready Pod endpoints")
    pods = []
    for ref in sorted(refs, key=lambda row: row.get("uid", "")):
        pod = await _read("pod", ref.get("name", ""), namespace)
        _assert_source(pod, static)
        meta, podspec, status = pod["metadata"], pod.get("spec") or {}, pod.get("status") or {}
        if meta["uid"] != ref.get("uid") or any(meta.get("labels", {}).get(key) != value for key, value in spec["selector"].items()):
            raise ValueError("Service endpoints no longer match their selected Pod identities")
        if podspec.get("hostNetwork") or not any(row.get("type") == "Ready" and row.get("status") == "True" for row in status.get("conditions", [])):
            raise ValueError("Owned deployment Pod is not Ready or uses the host network")
        containers = {row["name"]: row for row in podspec.get("containers", [])}
        observed = status.get("containerStatuses") or []
        if not observed or any(not row.get("ready") or not row.get("containerID") or not row.get("imageID") for row in observed):
            raise ValueError("Owned deployment container identities are incomplete")
        if any(not re.search(r"@sha256:[0-9a-f]{64}$", containers.get(row["name"], {}).get("image", "")) for row in observed):
            raise ValueError("Owned deployment images must be pinned by immutable digest")
        target_port = _target_port(selected_ports[0], podspec)
        pods.append({"name": meta["name"], "uid": meta["uid"], "pod_ip": status.get("podIP"),
                     "target_port": target_port, "labels": meta.get("labels", {}), "containers": [
            {**{key: row[key] for key in ("name", "containerID", "imageID")}, "declared_image": containers[row["name"]]["image"]}
            for row in sorted(observed, key=lambda row: row["name"])]})
    return {"schema_version": 1, "provider": "k8s-service", "namespace": namespace, "namespace_uid": ns["metadata"]["uid"],
            "service_name": service_name, "service_uid": service["metadata"]["uid"], "port": port, "pods": pods,
            **{key: static[key] for key in ("repo_id", "scan_job_id", "target_tree_hash", "target_revision")},
            "source_binding": "operator-managed source annotations; binary/source equivalence is unproven"}


@asynccontextmanager
async def endpoint(binding, static):
    current = await attest(binding["namespace"], binding["service_name"], binding["port"], static)
    if digest(current) != digest(binding):
        raise ValueError("Owned local runtime identity changed; bind and capture the selected audit again")
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *_prefix(), "-n", binding["namespace"], "port-forward", "pod/" + current["pods"][0]["name"],
            ":" + str(current["pods"][0]["target_port"]), "--address", "127.0.0.1",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        async def forwarded_port():
            size = 0
            while True:
                line = await process.stdout.readline()
                size += len(line)
                if not line or size > 8192:
                    raise ValueError("Owned local port-forward did not become ready")
                matched = re.search(rb"Forwarding from 127\.0\.0\.1:(\d+) ->", line)
                if matched:
                    return int(matched.group(1))
        port = await asyncio.wait_for(forwarded_port(), timeout=10)
        # Recheck after kubectl selects the named Pod and before callers issue requests.
        if digest(await attest(binding["namespace"], binding["service_name"], binding["port"], static)) != digest(binding):
            raise ValueError("Owned local runtime changed while forwarding was starting")
        local = {**current, "url": "http://127.0.0.1:" + str(port), "identity_bound": True,
                 "container_id": current["pods"][0]["containers"][0]["containerID"],
                 "pod_uid": current["pods"][0]["uid"], "lab_run_id": current["service_uid"]}
        local["transport_binding"] = await _transport_binding(local, current["pods"][0]["name"], current["pods"][0]["target_port"])
        yield local
        after = await attest(binding["namespace"], binding["service_name"], binding["port"], static)
        if process.returncode is not None or digest(after) != digest(binding):
            raise ValueError("Owned local runtime changed during observation; evidence discarded")
    finally:
        await terminate_and_reap(process)


def _target_port(service_port, podspec):
    value = service_port.get("targetPort", service_port["port"])
    if isinstance(value, str):
        ports = {row["containerPort"] for container in podspec.get("containers", [])
                 for row in container.get("ports", []) if row.get("name") == value and row.get("protocol", "TCP") == "TCP"}
        if len(ports) != 1:
            raise ValueError("Owned Service named target port is ambiguous or unavailable")
        value = ports.pop()
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("Owned Service target port is invalid")
    return value


async def _transport_binding(local, pod_name, target_port):
    namespace = local.get("namespace")
    if not namespace or not pod_name or not local.get("pod_uid"):
        raise ValueError("Owned runtime lacks an exact Pod identity")
    pod = await _read("pod", pod_name, namespace)
    meta, spec, status = pod.get("metadata", {}), pod.get("spec", {}), pod.get("status", {})
    if meta.get("uid") != local["pod_uid"] or meta.get("deletionTimestamp") or spec.get("hostNetwork"):
        raise ValueError("Owned runtime Pod identity changed or uses host networking")
    if not any(row.get("type") == "Ready" and row.get("status") == "True" for row in status.get("conditions", [])):
        raise ValueError("Owned runtime Pod is not Ready")
    if local.get("provider") == "k8s-service":
        _assert_source(pod, local)
        allowed = {value.strip() for value in os.environ.get("LOTUS_DEPLOYMENT_LOCAL_NAMESPACES", "").split(",") if value.strip()}
        if namespace not in allowed:
            raise ValueError("Owned deployment namespace is no longer enabled")
    elif local.get("provider") == "k8s-job":
        from backend import k8s_lab
        labels, annotations = meta.get("labels", {}), meta.get("annotations", {})
        if (namespace != k8s_lab.namespace() or labels.get("role") != "lab-container"
                or labels.get("lotus.io/repo-id") != str(local.get("repo_id"))
                or annotations.get("lotus.io/target-tree-hash") != local.get("target_tree_hash")
                or annotations.get("lotus.io/target-revision", "") != local.get("target_revision", "")):
            raise ValueError("Local lab Pod is not bound to this audit source")
    else:
        raise ValueError("Identity transport supports only attested Kubernetes runtimes")
    ip = ipaddress.ip_address(status.get("podIP") or "")
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise ValueError("Owned runtime has an invalid Pod address")
    containers = status.get("containerStatuses", [])
    if not containers or any(not row.get("ready") or not row.get("containerID") or not row.get("imageID") for row in containers):
        raise ValueError("Owned runtime container identities are incomplete")
    if not isinstance(target_port, int) or isinstance(target_port, bool) or not 1 <= target_port <= 65535:
        raise ValueError("Owned runtime target port is invalid")
    return {"namespace": namespace, "pod_name": pod_name, "pod_uid": meta["uid"], "pod_ip": str(ip),
            "target_port": target_port, "pod_labels": meta.get("labels", {}),
            "authority_host": local["service_name"] + "." + namespace + ".svc.cluster.local",
            "authority_port": local["port"],
            "container_statuses": [{key: row.get(key) for key in ("name", "containerID", "imageID", "restartCount")} for row in containers]}


async def validate_transport_binding(local):
    if not isinstance(local, dict) or not local.get("identity_bound"):
        raise ValueError("Private identity destinations require an attested runtime binding")
    binding = local.get("transport_binding") or {}
    current = await _transport_binding(local, binding.get("pod_name"), binding.get("target_port"))
    if digest(current) != digest(binding):
        raise ValueError("Owned runtime changed; observation evidence discarded")
    return current


async def bind_lab_endpoint(local, inspected):
    """Add direct Pod routing to an already audit-bound normal lab attestation."""
    if local.get("provider") != "k8s-job":
        raise ValueError("Docker identity baselines have no destination-isolated transport")
    state = inspected.get("state") or {}
    namespace = state.get("namespace")
    name = state.get("container") or state.get("pod") or inspected.get("container") or inspected.get("pod")
    service = await _read("service", state.get("service_name", ""), namespace)
    from urllib.parse import urlsplit
    port = urlsplit(local["url"]).port or 80
    selected = [row for row in service.get("spec", {}).get("ports", []) if row.get("port") == port and row.get("protocol", "TCP") == "TCP"]
    if len(selected) != 1 or service.get("spec", {}).get("type", "ClusterIP") != "ClusterIP":
        raise ValueError("Local lab Service port is unavailable")
    pod = await _read("pod", name, namespace)
    if any(pod.get("metadata", {}).get("labels", {}).get(k) != v for k, v in service.get("spec", {}).get("selector", {}).items()) or not service.get("spec", {}).get("selector"):
        raise ValueError("Local lab Pod is not selected by its Service")
    endpoints = await _read("endpoints", state.get("service_name", ""), namespace)
    refs = [address.get("targetRef", {}) for subset in endpoints.get("subsets", []) for address in subset.get("addresses", [])]
    if not any(ref.get("uid") == local.get("pod_uid") and ref.get("name") == name and ref.get("namespace", namespace) == namespace for ref in refs):
        raise ValueError("Local lab Service has no endpoint for the attested Pod")
    result = {**local, "namespace": namespace, "service_name": state["service_name"], "port": port}
    result["transport_binding"] = await _transport_binding(result, name, _target_port(selected[0], pod.get("spec", {})))
    return result
