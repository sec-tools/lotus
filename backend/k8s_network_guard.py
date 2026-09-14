"""Fail-closed, same-Pod network admission before repository code executes.

The first init container is trusted, immutable and source-free. It waits for an
explicit release after real socket tests from its own network namespace. Policy
objects and old receipts alone never release a workload. Only private IPv4 Pod
networks are supported by this bounded local implementation.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
import re
import time
import uuid

from backend import k8s_lab

OWNER = "lotus.io/network-owner"
RESOURCE_OWNER = "lotus.io/network-resource-owner"
MANAGED = "lotus.io/network-managed"
INIT = "lotus-network-admission"
PORT = 18080
DENIED_PORT = 18081
MAX_WAIT = 90
PRIVATE = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
           "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
           "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
           "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"]
SECURITY = {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
            "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}
HOLD = """import signal,time,sys
released=False
def release(*args):
 global released
 released=True
signal.signal(signal.SIGUSR1,release)
signal.signal(signal.SIGTERM,lambda *args:sys.exit(78))
end=time.monotonic()+180
while not released and time.monotonic()<end:time.sleep(.1)
sys.exit(0 if released else 78)
"""
SERVER = """import socket,threading,time,signal,sys
signal.signal(signal.SIGTERM,lambda *args:sys.exit(0))
def serve(port):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',port));s.listen(16)
 while True:
  c,a=s.accept();c.close()
for port in (53,80,443,18080,18081):threading.Thread(target=serve,args=(port,),daemon=True).start()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',53))
while True:
 data,addr=s.recvfrom(64);s.sendto(data,addr)
"""
PROBE = """import json,socket,sys,os
spec=json.loads(sys.argv[1])
if os.environ.get('LOTUS_NETWORK_POD_UID')!=spec['pod_uid']:raise ValueError('network probe Pod UID changed')
rows=[]
for endpoint in spec['endpoints']:
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if endpoint.get('protocol')=='UDP' else socket.SOCK_STREAM);s.settimeout(.5)
 try:
  if endpoint.get('protocol')=='UDP':s.sendto(b'lotus-network-control',(endpoint['ip'],endpoint['port']));ok=s.recv(64)==b'lotus-network-control'
  else:s.connect((endpoint['ip'],endpoint['port']));ok=True
 except (TimeoutError,OSError):ok=False
 finally:s.close()
 rows.append(ok)
print(json.dumps(rows))
"""


class NetworkIsolationUnavailable(RuntimeError):
    """No repository command is authorized by an unavailable network boundary."""


class WorkloadAdmissionUnavailable(NetworkIsolationUnavailable):
    """A held workload could not start; this does not establish a CNI failure."""

    MESSAGES = {
        "scheduling-memory": "Kubernetes could not schedule the workload: insufficient unreserved memory. Stop unused labs from Dashboard or add cluster capacity, then retry. Increasing the workload memory limit alone will not free scheduling capacity.",
        "scheduling-cpu": "Kubernetes could not schedule the workload: insufficient unreserved CPU. Stop unused labs, reduce concurrent work, or add cluster capacity, then retry.",
        "scheduling-storage": "Kubernetes could not schedule the workload because its persistent volume is not ready. Check the storage class and volume events, then retry.",
        "scheduling-unavailable": "Kubernetes could not schedule the workload. Check node capacity, placement constraints, and Pod events, then retry.",
        "image-pull-unavailable": "Kubernetes could not pull the trusted admission image. Check node registry connectivity and image availability, then retry.",
    }

    def __init__(self, code):
        self.code = code if isinstance(code, str) and code in self.MESSAGES else "scheduling-unavailable"
        super().__init__(self.MESSAGES[self.code])


def _pending_workload_code(pod):
    """Classify API status using fixed text; never publish raw scheduler messages."""
    status = pod.get("status") or {}
    for row in status.get("conditions") or []:
        if row.get("type") == "PodScheduled" and row.get("status") == "False" and row.get("reason") == "Unschedulable":
            message = str(row.get("message") or "")[:4096]
            if "Insufficient memory" in message:
                return "scheduling-memory"
            if "Insufficient cpu" in message:
                return "scheduling-cpu"
            if "unbound immediate PersistentVolumeClaims" in message:
                return "scheduling-storage"
            return "scheduling-unavailable"
    states = status.get("initContainerStatuses") or []
    if states and states[0].get("name") == INIT:
        reason = ((states[0].get("state") or {}).get("waiting") or {}).get("reason")
        if reason in {"ErrImagePull", "ImagePullBackOff"}:
            return "image-pull-unavailable"
    return ""


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _policy_digest(spec):
    normalized = deepcopy(spec)
    # Kubernetes omits empty optional ingress/egress lists on read-back.
    # No other malformed or unknown shape is discarded by normalization.
    normalized.setdefault("ingress", [])
    normalized.setdefault("egress", [])
    return _digest(normalized)


def _private_v4(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise NetworkIsolationUnavailable("Network admission requires a valid private IPv4 endpoint") from None
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified:
        raise NetworkIsolationUnavailable("This network admission supports private IPv4 Pod networks only; IPv6/public Pod networks are not qualified")
    return str(address)


def _selects(selector, labels):
    if not isinstance(selector, dict) or set(selector) - {"matchLabels", "matchExpressions"}:
        raise NetworkIsolationUnavailable("Unsupported NetworkPolicy selector")
    if not all(labels.get(k) == v for k, v in selector.get("matchLabels", {}).items()):
        return False
    for row in selector.get("matchExpressions", []):
        key, op, values = row.get("key"), row.get("operator"), row.get("values", [])
        if op == "In": match = key in labels and labels[key] in values
        elif op == "NotIn": match = key not in labels or labels[key] not in values
        elif op == "Exists": match = key in labels
        elif op == "DoesNotExist": match = key not in labels
        else: raise NetworkIsolationUnavailable("Unsupported NetworkPolicy selector expression")
        if not match: return False
    return True


def profile_egress(profile, *, registry=None):
    if profile not in {"isolated", "public"}:
        raise NetworkIsolationUnavailable("Unknown network admission profile")
    if registry and profile != "public":
        raise NetworkIsolationUnavailable("Registry egress is only valid for the build profile")
    rules = []
    if profile == "public":
        rules = [
            {"to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": PRIVATE}}],
             "ports": [{"protocol": "TCP", "port": 80}, {"protocol": "TCP", "port": 443}]},
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                      "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
             "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
        ]
    if registry:
        # The registry must be an exact observed, owned Pod, never a user host.
        rules.append({"to": [{"ipBlock": {"cidr": _private_v4(registry["ip"]) + "/32"}}],
                      "ports": [{"protocol": "TCP", "port": 5000}]})
        rules.append({"to": [{"ipBlock": {"cidr": _private_v4(registry["node_ip"]) + "/32"}}],
                      "ports": [{"protocol": "TCP", "port": registry["node_port"]}]})
    return rules


async def registry_binding(namespace, node_ip, node_port):
    """Observe the generated local registry through exact Service/RS/Pod owners."""
    if type(node_port) is not int or not 30000 <= node_port <= 32767:
        raise NetworkIsolationUnavailable("Invalid local registry NodePort")
    node_ip = _private_v4(node_ip)
    service = await _read(namespace, "Service", "lotus-registry")
    deployment = await _read(namespace, "Deployment", "lotus-registry")
    expected_labels = {"app": "lotus-registry", "lotus.io/role": "registry"}
    if (not service or not deployment or service.get("spec", {}).get("selector") != expected_labels
            or service.get("spec", {}).get("type") != "NodePort"
            or deployment.get("spec", {}).get("selector", {}).get("matchLabels") != expected_labels):
        raise NetworkIsolationUnavailable("Local registry Service/deployment ownership is unavailable")
    ports = service["spec"].get("ports", [])
    if len(ports) != 1 or any(ports[0].get(k) != v for k, v in {"port": 5000, "targetPort": 5000, "nodePort": node_port, "protocol": "TCP"}.items()):
        raise NetworkIsolationUnavailable("Local registry Service port binding changed")
    document = await _read(namespace, "Pod", selector="app=lotus-registry")
    pods = (document or {}).get("items", [])
    if len(pods) != 1: raise NetworkIsolationUnavailable("Local registry must have one exact live Pod")
    pod = pods[0]
    meta, spec, status = pod.get("metadata", {}), pod.get("spec", {}), pod.get("status", {})
    if node_ip != _private_v4(status.get("hostIP", "")):
        raise NetworkIsolationUnavailable("Registry NodePort must use the observed registry Pod's node IP")
    refs = [r for r in meta.get("ownerReferences", []) if r.get("kind") == "ReplicaSet" and r.get("controller") is True]
    if len(refs) != 1: raise NetworkIsolationUnavailable("Local registry Pod has no exact ReplicaSet owner")
    rs = await _read(namespace, "ReplicaSet", refs[0]["name"])
    if (not rs or rs.get("metadata", {}).get("uid") != refs[0].get("uid")
            or not any(r.get("kind") == "Deployment" and r.get("controller") is True and r.get("uid") == deployment["metadata"].get("uid") for r in rs["metadata"].get("ownerReferences", []))):
        raise NetworkIsolationUnavailable("Local registry ReplicaSet/deployment ownership changed")
    containers = spec.get("containers", [])
    expected = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    states = status.get("containerStatuses", [])
    if (len(containers) != 1 or len(expected) != 1 or containers[0].get("name") != "registry"
            or containers[0].get("image") != expected[0].get("image") or meta.get("deletionTimestamp")
            or spec.get("hostNetwork") or spec.get("automountServiceAccountToken") is not False
            or len(states) != 1 or states[0].get("ready") is not True
            or not states[0].get("containerID") or not re.search(r"sha256:[0-9a-f]{64}$", states[0].get("imageID", ""))):
        raise NetworkIsolationUnavailable("Local registry immutable container identity is unavailable")
    return {"namespace": namespace, "ip": _private_v4(status.get("podIP", "")),
            "pod_uid": meta["uid"], "pod_name": meta["name"], "container_id": states[0]["containerID"],
            "image_id": states[0]["imageID"], "service_uid": service["metadata"]["uid"],
            "service_spec": _digest(service["spec"]), "deployment_uid": deployment["metadata"]["uid"],
            "replicaset_uid": rs["metadata"]["uid"], "node_ip": node_ip, "node_port": node_port}


def _target(manifest):
    if manifest.get("kind") == "Job":
        return manifest["spec"]["template"]["metadata"], manifest["spec"]["template"]["spec"]
    if manifest.get("kind") == "Pod":
        return manifest["metadata"], manifest["spec"]
    raise NetworkIsolationUnavailable("Network admission requires one Job or Pod")


def validate_workload(manifest):
    metadata, spec = _target(manifest)
    if any(spec.get(k) for k in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace")):
        raise NetworkIsolationUnavailable("Host or shared process namespaces cannot pass network admission")
    if spec.get("automountServiceAccountToken") is not False:
        raise NetworkIsolationUnavailable("Network-admitted workloads must disable service-account tokens")
    if any("hostPath" in v or "projected" in v or "secret" in v for v in spec.get("volumes", [])):
        raise NetworkIsolationUnavailable("Host or credential mounts cannot pass network admission")
    for c in spec.get("initContainers", []) + spec.get("containers", []):
        security = c.get("securityContext") or {}
        if security.get("privileged") or security.get("allowPrivilegeEscalation") is True:
            raise NetworkIsolationUnavailable("Privileged containers cannot pass network admission")
        if any(str(cap).upper().removeprefix("CAP_") in {"NET_ADMIN", "SYS_ADMIN", "NET_RAW"}
               for cap in security.get("capabilities", {}).get("add", [])):
            raise NetworkIsolationUnavailable("Network/host administrator capabilities are forbidden")
        if any(p.get("hostPort") for p in c.get("ports", [])):
            raise NetworkIsolationUnavailable("Host ports cannot pass workload network admission")
        if any("secretKeyRef" in e.get("valueFrom", {}) for e in c.get("env", [])) or any("secretRef" in e for e in c.get("envFrom", [])):
            raise NetworkIsolationUnavailable("Cluster Secret references cannot enter repository workloads")
        if c.get("name") == INIT:
            raise NetworkIsolationUnavailable("Reserved network admission container name")
    if OWNER in metadata.get("labels", {}):
        raise NetworkIsolationUnavailable("Workload already has a network admission owner")


async def _command(namespace, args, *, document=None, timeout=15):
    data = json.dumps(document).encode() if document is not None else None
    text, rc = await k8s_lab._run(["-n", namespace, *args], input_data=data, timeout=timeout, max_output=1_000_000)
    if rc:
        # Do not echo manifests, Secret values or arbitrary kubectl output.
        lower = text.lower()
        reason = ("permission denied; grant the documented namespace-scoped network admission RBAC" if "forbidden" in lower
                  else "timed out; inspect cluster capacity and connectivity" if "timed out" in lower or "timeout" in lower
                  else "resource unavailable; inspect the network admission task and Kubernetes events")
        raise NetworkIsolationUnavailable("Network admission " + " ".join(args[:2]) + " failed: " + reason)
    return text


async def _read(namespace, kind, name="", *, selector=None):
    text = await _command(namespace, ["get", kind, *([name] if name else []), *(["-l", selector] if selector else []), "--ignore-not-found=true", "-o", "json"])
    if not text.strip(): return None
    try:
        doc = json.loads(text)
        if not isinstance(doc, dict): raise ValueError()
        return doc
    except ValueError:
        raise NetworkIsolationUnavailable("Network admission received invalid Kubernetes JSON") from None


async def _create(namespace, document):
    result = json.loads(await _command(namespace, ["create", "-f", "-", "-o", "json"], document=document))
    if not result.get("metadata", {}).get("uid"):
        raise NetworkIsolationUnavailable("Created network resource has no immutable UID")
    return result


async def _delete(namespace, kind, name, uid):
    current = await _read(namespace, kind, name)
    if current is None: return {"original_uid_absent": True, "replacement_preserved": False}
    if current.get("metadata", {}).get("uid") != uid:
        raise NetworkIsolationUnavailable("Network cleanup refuses a replacement resource")
    plural = {"Pod": "pods", "Service": "services", "NetworkPolicy": "networkpolicies", "Job": "jobs", "PersistentVolumeClaim": "persistentvolumeclaims"}[kind]
    api = "networking.k8s.io/v1" if kind == "NetworkPolicy" else "batch/v1" if kind == "Job" else "v1"
    route = ("/api/" if api == "v1" else "/apis/") + api + "/namespaces/" + namespace + "/" + plural + "/" + name
    await _command(namespace, ["delete", "--raw=" + route, "-f", "-"], document={"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}, "propagationPolicy": "Foreground"})
    end = time.monotonic() + 20
    while time.monotonic() < end:
        current = await _read(namespace, kind, name)
        if current is None or current.get("metadata", {}).get("uid") != uid:
            return {"original_uid_absent": True, "replacement_preserved": current is not None}
        await asyncio.sleep(.25)
    raise NetworkIsolationUnavailable("Network cleanup did not verify original UID disappearance")


async def _image():
    value = str(os.environ.get("LOTUS_K8S_NETWORK_GUARD_IMAGE") or "")
    if not value:
        # Resolve the installed trusted controller image from its exact Pod.
        pod_name = os.environ.get("LOTUS_POD_NAME") or os.environ.get("HOSTNAME", "")
        doc = await _read(k8s_lab.namespace(), "Pod", pod_name)
        containers = (doc or {}).get("spec", {}).get("containers", [])
        value = next((c.get("image", "") for c in containers if c.get("name") == "lotus"), "")
        state = next((c for c in (doc or {}).get("status", {}).get("containerStatuses", []) if c.get("name") == "lotus"), {})
        if (not doc or not doc.get("metadata", {}).get("uid") or doc["metadata"].get("deletionTimestamp")
                or doc["metadata"].get("labels", {}).get("app") != "lotus"
                or state.get("ready") is not True or not value or value.rsplit("@", 1)[-1] not in state.get("imageID", "")):
            raise NetworkIsolationUnavailable("Trusted controller image does not match its current live container identity")
    image_pattern = (r"(?:(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?/)?"
                     r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
                     r"(?:/[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)*"
                     r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[a-f0-9]{64}")
    if len(value) > 2048 or not re.fullmatch(image_pattern, value):
        raise NetworkIsolationUnavailable("Configure an immutable trusted Python network-guard image, or use a digest-pinned controller image")
    return value


def _control_pod(name, owner, image):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"lotus.io/network-control": owner, RESOURCE_OWNER: owner}},
            "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never", "activeDeadlineSeconds": 240, "terminationGracePeriodSeconds": 1,
                     "securityContext": {"sysctls": [{"name": "net.ipv4.ip_unprivileged_port_start", "value": "0"}]},
                     "containers": [{"name": "control", "image": image, "command": ["python3", "-u", "-c", SERVER],
                                     "env": [{"name": "LOTUS_NETWORK_POD_UID", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}}}],
                                     "securityContext": SECURITY, "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "250m", "memory": "64Mi"}}}]}}


def _control_job(name, owner, image):
    pod = _control_pod(name, owner, image)
    pod["spec"].pop("activeDeadlineSeconds")
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": pod["metadata"],
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 240, "ttlSecondsAfterFinished": 15,
                     "template": {"metadata": {"labels": pod["metadata"]["labels"]}, "spec": pod["spec"]}}}


class Admission:
    def __init__(self, manifest, profile, image, registry=None):
        self.manifest = deepcopy(manifest)
        validate_workload(self.manifest)
        self.profile, self.image, self.registry = profile, image, registry
        self.namespace = self.manifest.get("metadata", {}).get("namespace") or k8s_lab.namespace()
        self.owner = uuid.uuid4().hex
        self.name = "lotus-net-" + self.owner[:20]
        self.resources = []
        self.control_pods = {}
        self.workload_uid = self.pod_uid = self.pod_name = None
        self.pending_workload_code = ""
        self.released = False
        metadata, spec = _target(self.manifest)
        metadata.setdefault("labels", {})[OWNER] = self.owner
        metadata["labels"][MANAGED] = "true"
        self.manifest["metadata"].setdefault("labels", {})[OWNER] = self.owner
        # Generated legacy web policy is additive; do not select it.
        metadata["labels"].pop("lotus.io/egress", None)
        self.init = {"name": INIT, "image": image, "command": ["python3", "-u", "-c", HOLD],
                     "env": [{"name": "LOTUS_NETWORK_POD_UID", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}}}],
                     "securityContext": deepcopy(SECURITY), "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "250m", "memory": "64Mi"}}}
        spec["initContainers"] = [self.init, *spec.get("initContainers", [])]
        self.labels = metadata["labels"]
        self.policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": self.name, "namespace": self.namespace, "labels": {OWNER: self.owner}},
                       "spec": {"podSelector": {"matchLabels": {OWNER: self.owner}}, "policyTypes": ["Ingress", "Egress"],
                                "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "lotus"}}}], "ports": [{"protocol": "TCP"}]}],
                                "egress": profile_egress(profile, registry=registry)}}

    async def _remember(self, document):
        document["metadata"].setdefault("labels", {})[RESOURCE_OWNER] = self.owner
        for key in ("lotus.io/repo-id", "lotus.io/scan-job-id"):
            if self.manifest["metadata"].get("labels", {}).get(key):
                document["metadata"]["labels"][key] = self.manifest["metadata"]["labels"][key]
        if document["kind"] == "Job":
            document["spec"]["template"]["metadata"]["labels"].update(document["metadata"]["labels"])
        self.resources.append((document["kind"], document["metadata"]["name"], None))
        created = await _create(self.namespace, document)
        self.resources[-1] = (document["kind"], document["metadata"]["name"], created["metadata"]["uid"])
        return created

    async def _policies(self):
        document = await _read(self.namespace, "NetworkPolicy")
        if not isinstance((document or {}).get("items"), list):
            raise NetworkIsolationUnavailable("NetworkPolicy inventory is unavailable")
        own = None
        for row in document["items"]:
            spec = row.get("spec", {})
            if not _selects(spec.get("podSelector", {}), self.labels): continue
            if row.get("metadata", {}).get("name") == self.name:
                own = row
                if row["metadata"].get("uid") != self.policy_uid or _policy_digest(spec) != _policy_digest(self.policy["spec"]):
                    raise NetworkIsolationUnavailable("Owned network profile changed")
                continue
            if spec.get("egress"):
                raise NetworkIsolationUnavailable("Another NetworkPolicy widens this workload's egress; remove the overlapping allow rule before retrying")
            if any(rule not in self.policy["spec"]["ingress"] for rule in spec.get("ingress", [])):
                raise NetworkIsolationUnavailable("Another NetworkPolicy widens this workload's ingress")
        if own is None: raise NetworkIsolationUnavailable("Owned network profile disappeared")

    async def _update_policy(self):
        current = await _read(self.namespace, "NetworkPolicy", self.name)
        if not current or current["metadata"].get("uid") != self.policy_uid:
            raise NetworkIsolationUnavailable("Network profile ownership changed")
        patch = [{"op": "test", "path": "/metadata/uid", "value": self.policy_uid},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
                 {"op": "test", "path": "/spec", "value": current["spec"]},
                 {"op": "replace", "path": "/spec", "value": self.policy["spec"]}]
        if self.policy["metadata"].get("ownerReferences"):
            patch.append({"op": "add", "path": "/metadata/ownerReferences", "value": self.policy["metadata"]["ownerReferences"]})
        await _command(self.namespace, ["patch", "NetworkPolicy", self.name, "--type=json", "-p", json.dumps(patch)])
        await self._policies()

    async def prepare(self):
        # This durable deny-only policy survives per-Job policy GC, so a
        # terminating Pod never becomes non-isolated during resource cleanup.
        baseline = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "lotus-network-default-deny", "namespace": self.namespace},
            "spec": {"podSelector": {"matchLabels": {MANAGED: "true"}},
                     "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}}
        current = await _read(self.namespace, "NetworkPolicy", baseline["metadata"]["name"])
        if current is None:
            try:
                current = await _create(self.namespace, baseline)
            except NetworkIsolationUnavailable:
                # Concurrent admissions may both observe absence. Only an
                # exact successfully re-read deny policy resolves that race.
                current = await _read(self.namespace, "NetworkPolicy", baseline["metadata"]["name"])
                if current is None: raise
        if _policy_digest(current.get("spec", {})) != _policy_digest(baseline["spec"]):
            raise NetworkIsolationUnavailable("Network admission default-deny policy differs; existing policy was preserved")
        # Controls contain only the authored server, never source or secrets.
        sink = await self._remember(_control_job(self.name + "-sink", self.owner, self.image))
        observer = await self._remember(_control_job(self.name + "-observer", self.owner, self.image))
        self.sink_name, self.observer_name = sink["metadata"]["name"], observer["metadata"]["name"]
        self.sink_uid, self.observer_uid = sink["metadata"]["uid"], observer["metadata"]["uid"]
        control_owner = {"apiVersion": "batch/v1", "kind": "Job", "name": self.sink_name, "uid": self.sink_uid}
        self.service = await self._remember({"apiVersion": "v1", "kind": "Service", "metadata": {"name": self.name, "labels": {OWNER: self.owner}, "ownerReferences": [control_owner]},
            "spec": {"selector": {"lotus.io/network-control": self.owner}, "ports": [
                {"name": "http", "port": 80, "targetPort": 80}, {"name": "https", "port": 443, "targetPort": 443},
                {"name": "dns", "port": 53, "targetPort": 53, "protocol": "UDP"}]}})
        self.service_ip = _private_v4(self.service.get("spec", {}).get("clusterIP", ""))
        end = time.monotonic() + MAX_WAIT
        while time.monotonic() < end:
            try:
                self.sink = await self._control(self.sink_name, self.sink_uid)
                await self._control(self.observer_name, self.observer_uid)
                await self._positive()
                break
            except NetworkIsolationUnavailable:
                await asyncio.sleep(.5)
        else: raise NetworkIsolationUnavailable("Trusted network controls did not become reachable")
        self.policy["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": self.sink + "/32"}}], "ports": [{"protocol": "TCP", "port": PORT}]})
        self.policy["metadata"]["ownerReferences"] = [control_owner]
        created = await self._remember(self.policy)
        self.policy_uid = created["metadata"]["uid"]
        await self._policies()

    async def _control(self, name, uid):
        job = await _read(self.namespace, "Job", name)
        if not job or job.get("metadata", {}).get("uid") != uid:
            raise NetworkIsolationUnavailable("Trusted network control Job is unavailable or replaced")
        listing = await _read(self.namespace, "Pod", selector="job-name=" + name)
        pods = [p for p in (listing or {}).get("items", []) if any(o.get("kind") == "Job" and o.get("uid") == uid and o.get("controller") is True for o in p.get("metadata", {}).get("ownerReferences", []))]
        pod = pods[0] if len(pods) == 1 else None
        if (not pod or pod["metadata"].get("deletionTimestamp")
                or pod.get("spec", {}).get("hostNetwork") or pod.get("status", {}).get("phase") != "Running"):
            raise NetworkIsolationUnavailable("Trusted network control is unavailable or replaced")
        identity = (pod["metadata"]["name"], pod["metadata"]["uid"])
        if name in self.control_pods and self.control_pods[name] != identity:
            raise NetworkIsolationUnavailable("Trusted network control Pod was replaced")
        self.control_pods[name] = identity
        expected = _control_pod(name, self.owner, self.image)["spec"]
        actual = pod.get("spec", {})
        containers = actual.get("containers", [])
        if (len(containers) != 1 or actual.get("automountServiceAccountToken") is not False
                or actual.get("volumes") or actual.get("initContainers")
                or any(actual.get(k) for k in ("hostPID", "hostIPC", "shareProcessNamespace"))
                or any(containers[0].get(k) != expected["containers"][0][k] for k in ("image", "command", "securityContext", "env"))
                or set(containers[0]) - set(expected["containers"][0]) - {"imagePullPolicy", "terminationMessagePath", "terminationMessagePolicy"}
                or actual.get("securityContext") != expected.get("securityContext")
                or pod["metadata"].get("labels", {}).get(RESOURCE_OWNER) != self.owner):
            raise NetworkIsolationUnavailable("Trusted network control spec or image changed")
        return _private_v4(pod["status"].get("podIP", ""))

    async def _probe(self, pod, container, endpoints):
        if container == INIT: uid = self.pod_uid
        else: pod, uid = self.control_pods[pod]
        raw = await _command(self.namespace, ["exec", pod, "-c", container, "--", "python3", "-c", PROBE, json.dumps({"pod_uid": uid, "endpoints": endpoints})], timeout=15)
        try: values = json.loads(raw)
        except ValueError: raise NetworkIsolationUnavailable("Malformed network probe output") from None
        if not isinstance(values, list) or len(values) != len(endpoints) or any(type(v) is not bool for v in values):
            raise NetworkIsolationUnavailable("Incomplete network probe results")
        return values

    def _endpoints(self):
        return [{"ip": self.sink, "port": PORT}, {"ip": self.sink, "port": DENIED_PORT},
                {"ip": self.sink, "port": 80}, {"ip": self.sink, "port": 443},
                {"ip": self.sink, "port": 53}, {"ip": self.sink, "port": 53, "protocol": "UDP"},
                {"ip": self.service_ip, "port": 80}, {"ip": self.service_ip, "port": 443},
                {"ip": self.service_ip, "port": 53, "protocol": "UDP"}] + getattr(self, "cluster_endpoints", [])

    async def _positive(self):
        if await self._control(self.sink_name, self.sink_uid) != self.sink:
            raise NetworkIsolationUnavailable("Network sink address changed")
        await self._control(self.observer_name, self.observer_uid)
        service = await _read(self.namespace, "Service", self.name)
        if not service or service["metadata"].get("uid") != self.service["metadata"]["uid"] or service.get("spec") != self.service.get("spec"):
            raise NetworkIsolationUnavailable("Trusted network control Service was replaced or changed")
        if not all(await self._probe(self.observer_name, "control", self._endpoints())):
            raise NetworkIsolationUnavailable("A protected endpoint is unavailable; failed connections cannot establish isolation")

    async def _pod(self):
        self.pending_workload_code = ""
        kind, name = self.manifest["kind"], self.manifest["metadata"]["name"]
        workload = await _read(self.namespace, kind, name)
        if not workload or workload.get("metadata", {}).get("labels", {}).get(OWNER) != self.owner:
            raise NetworkIsolationUnavailable("Original workload ownership is unavailable")
        uid = workload["metadata"]["uid"]
        if self.workload_uid and self.workload_uid != uid: raise NetworkIsolationUnavailable("Workload was replaced")
        self.workload_uid = uid
        if kind == "Pod": pods = [workload]
        else:
            listing = await _read(self.namespace, "Pod", selector=OWNER + "=" + self.owner)
            pods = [p for p in (listing or {}).get("items", []) if p.get("metadata", {}).get("labels", {}).get(OWNER) == self.owner]
        if len(pods) != 1: return None
        pod = pods[0]
        meta, spec = pod.get("metadata", {}), pod.get("spec", {})
        planned_labels = _target(self.manifest)[0]["labels"]
        actual_labels = meta.get("labels", {})
        generated_labels = {"controller-uid", "job-name", "batch.kubernetes.io/controller-uid", "batch.kubernetes.io/job-name"}
        if (any(actual_labels.get(k) != v for k, v in planned_labels.items())
                or set(actual_labels) - set(planned_labels) - generated_labels):
            raise NetworkIsolationUnavailable("Workload network selector labels changed")
        self.labels = actual_labels
        if self.pod_uid and meta.get("uid") != self.pod_uid: raise NetworkIsolationUnavailable("Admission Pod was replaced")
        if kind == "Job" and not any(o.get("kind") == "Job" and o.get("uid") == uid and o.get("controller") is True for o in meta.get("ownerReferences", [])):
            raise NetworkIsolationUnavailable("Admission Pod has no exact Job owner")
        if not spec.get("initContainers") or spec["initContainers"][0].get("command") != self.init["command"] or spec["initContainers"][0].get("image") != self.image:
            raise NetworkIsolationUnavailable("Trusted admission init container changed")
        if spec["initContainers"][0].get("volumeMounts") or spec.get("automountServiceAccountToken") is not False or any(spec.get(k) for k in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace")):
            raise NetworkIsolationUnavailable("Trusted admission container gained source, credentials or host namespaces")
        status = pod.get("status", {})
        self.pending_workload_code = _pending_workload_code(pod)
        if not status.get("podIP"):
            return None
        if status.get("podIPs") and len(status["podIPs"]) != 1:
            raise NetworkIsolationUnavailable("Dual-stack network admission is not supported")
        _private_v4(status.get("podIP", ""))
        for key, value in self.init.items():
            if key not in {"resources"} and spec["initContainers"][0].get(key) != value:
                raise NetworkIsolationUnavailable("Admission init container security or command changed")
        if any("hostPath" in v or "projected" in v or "secret" in v for v in spec.get("volumes", [])):
            raise NetworkIsolationUnavailable("Admission Pod gained host or credential volumes")
        if set(spec["initContainers"][0]) - set(self.init) - {"imagePullPolicy", "terminationMessagePath", "terminationMessagePolicy"}:
            raise NetworkIsolationUnavailable("Admission init container gained an unexpected field")
        checked = deepcopy(pod)
        checked["metadata"]["labels"].pop(OWNER, None)
        checked["spec"]["initContainers"] = checked["spec"]["initContainers"][1:]
        validate_workload(checked)
        expected_spec = _target(self.manifest)[1]
        for group in ("containers", "initContainers"):
            expected_containers, actual_containers = expected_spec.get(group, []), spec.get(group, [])
            if len(expected_containers) != len(actual_containers):
                raise NetworkIsolationUnavailable("Workload containers changed after admission planning")
            for expected_c, actual_c in zip(expected_containers, actual_containers):
                for key in ("name", "image", "command", "args", "workingDir", "volumeMounts", "env", "envFrom", "securityContext"):
                    if expected_c.get(key) != actual_c.get(key):
                        raise NetworkIsolationUnavailable("Workload command, source mounts or security changed before release")
        states = status.get("initContainerStatuses", [])
        if not states or states[0].get("name") != INIT or not states[0].get("state", {}).get("running"):
            if states and states[0].get("state", {}).get("terminated"):
                raise NetworkIsolationUnavailable("Network admission exited before authorization")
            return None
        if any(s.get("state", {}).get("running") or s.get("state", {}).get("terminated") for s in states[1:] + status.get("containerStatuses", [])):
            raise NetworkIsolationUnavailable("A source-bearing container started before network authorization")
        self.pod_uid, self.pod_name = meta["uid"], meta["name"]
        self.cluster_endpoints = [{"ip": _private_v4(os.environ.get("KUBERNETES_SERVICE_HOST", "")), "port": 443}]
        node_port = os.environ.get("LOTUS_K8S_NETWORK_NODE_CONTROL_PORT", "")
        if node_port:
            if not node_port.isdigit() or not 1 <= int(node_port) <= 65535:
                raise NetworkIsolationUnavailable("Invalid explicit node network-control port")
            self.cluster_endpoints.append({"ip": _private_v4(status.get("hostIP", "")), "port": int(node_port)})
        return pod

    async def release(self):
        end = time.monotonic() + MAX_WAIT
        while time.monotonic() < end:
            pod = await self._pod()
            if pod is not None: break
            await asyncio.sleep(.5)
        else:
            if self.pending_workload_code:
                raise WorkloadAdmissionUnavailable(self.pending_workload_code)
            raise NetworkIsolationUnavailable("Workload did not reach its trusted network admission container")
        self.policy["metadata"]["ownerReferences"] = [{"apiVersion": "batch/v1" if self.manifest["kind"] == "Job" else "v1",
            "kind": self.manifest["kind"], "name": self.manifest["metadata"]["name"], "uid": self.workload_uid}]
        for kind, name, uid in self.resources:
            if kind != "Job": continue
            current = await _read(self.namespace, kind, name)
            if not current or current["metadata"].get("uid") != uid:
                raise NetworkIsolationUnavailable("Trusted control owner changed before workload binding")
            patch = [{"op": "test", "path": "/metadata/uid", "value": uid},
                     {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
                     {"op": "add", "path": "/metadata/ownerReferences", "value": self.policy["metadata"]["ownerReferences"]}]
            await _command(self.namespace, ["patch", kind, name, "--type=json", "-p", json.dumps(patch)])
        await self._update_policy()
        await self._settle(self._endpoints()[:2], [True, False])
        self.policy["spec"]["egress"] = profile_egress(self.profile, registry=self.registry)
        await self._update_policy()
        # Fresh sockets after removing the temporary positive exception; no
        # repository process ever ran while that exception was present.
        await self._settle(self._endpoints(), [False] * len(self._endpoints()))
        await self._policies()
        await self._pod()
        if self.registry:
            current = await registry_binding(self.registry["namespace"], self.registry["node_ip"], self.registry["node_port"])
            if current != self.registry:
                raise NetworkIsolationUnavailable("Local registry identity changed during network admission")
            code = "import os,sys,http.client;assert os.environ.get('LOTUS_NETWORK_POD_UID')==sys.argv[1];c=http.client.HTTPConnection(sys.argv[2],int(sys.argv[3]),timeout=2);c.request('GET','/v2/');r=c.getresponse();assert r.status==200 and r.getheader('Docker-Distribution-Api-Version')=='registry/2.0';assert len(r.read(16385))<=16384;c.close()"
            await _command(self.namespace, ["exec", self.pod_name, "-c", INIT, "--", "python3", "-c", code,
                                           self.pod_uid, self.registry["node_ip"], str(self.registry["node_port"])])
            if await registry_binding(self.registry["namespace"], self.registry["node_ip"], self.registry["node_port"]) != self.registry:
                raise NetworkIsolationUnavailable("Local registry changed after its allowed readiness request")
        await _command(self.namespace, ["exec", self.pod_name, "-c", INIT, "--", "python3", "-c",
            "import os,signal,sys;assert os.environ.get('LOTUS_NETWORK_POD_UID')==sys.argv[1],'Admission Pod UID changed';os.kill(1,signal.SIGUSR1)", self.pod_uid])
        self.released = True
        return {"status": "verified", "profile": self.profile, "pod_uid": self.pod_uid,
                "workload_uid": self.workload_uid, "policy_uid": self.policy_uid,
                "policy_sha256": _digest(self.policy["spec"]), "probe_sha256": hashlib.sha256(PROBE.encode()).hexdigest(),
                "node_paths_tested": bool(os.environ.get("LOTUS_K8S_NETWORK_NODE_CONTROL_PORT")),
                "scope": "same-Pod private IPv4 egress and additive-policy admission; not host/kernel or future CNI integrity"}

    async def _settle(self, endpoints, expected):
        async def observe():
            end = time.monotonic() + 8
            while True:
                await self._positive()
                await self._policies()
                if await self._pod() is None:
                    raise NetworkIsolationUnavailable("Trusted init is no longer waiting")
                values = await self._probe(self.pod_name, INIT, endpoints)
                await self._positive()
                await self._policies()
                if values == expected:
                    return
                if time.monotonic() >= end:
                    raise NetworkIsolationUnavailable("NetworkPolicy did not enforce the required traffic profile; no repository command was released")
                await asyncio.sleep(.25)
        try:
            await asyncio.wait_for(observe(), timeout=20)
        except asyncio.TimeoutError:
            raise NetworkIsolationUnavailable("NetworkPolicy enforcement verification exceeded its bounded settling deadline") from None

    async def close(self):
        # An unreleased workload is deleted before its policy; never leave an
        # orphan held init or remove isolation from a possibly running Pod.
        errors, outcomes = [], []
        if not self.released:
            try:
                kind, name = self.manifest["kind"], self.manifest["metadata"]["name"]
                workload = await _read(self.namespace, kind, name)
                if workload:
                    if workload.get("metadata", {}).get("labels", {}).get(OWNER) != self.owner:
                        raise NetworkIsolationUnavailable("Ambiguous workload cleanup; network policy retained")
                    if self.workload_uid and workload["metadata"].get("uid") != self.workload_uid:
                        raise NetworkIsolationUnavailable("Workload cleanup refused a replacement UID; replacement preserved")
                    outcomes.append(await _delete(self.namespace, kind, name, workload["metadata"]["uid"]))
                if self.pod_name and self.pod_uid:
                    outcomes.append(await _delete(self.namespace, "Pod", self.pod_name, self.pod_uid))
            except Exception as exc:
                errors.append(str(exc))
        for kind, name, uid in reversed(self.resources):
            if kind == "NetworkPolicy" and (self.released or errors):
                continue  # Exact Job/Pod owner reference cleans it up later.
            try:
                if uid is None:
                    observed = await _read(self.namespace, kind, name)
                    if observed is None: continue
                    if observed.get("metadata", {}).get("labels", {}).get(RESOURCE_OWNER) != self.owner:
                        raise NetworkIsolationUnavailable("Ambiguous network resource creation; replacement preserved")
                    uid = observed["metadata"]["uid"]
                outcomes.append(await _delete(self.namespace, kind, name, uid))
            except Exception as exc:
                errors.append(str(exc))
        self.cleanup = {"verified": not errors, "resources": outcomes, "errors": errors}
        if errors: raise NetworkIsolationUnavailable("Network admission cleanup remains incomplete: " + "; ".join(errors)[:500])


async def prepare(manifest, *, profile="isolated", registry=None):
    guard = Admission(manifest, profile, await _image(), registry=registry)
    try:
        await guard.prepare()
        return guard
    except BaseException:
        await asyncio.shield(guard.close())
        raise


async def close(guard):
    if guard is None: return
    task = asyncio.create_task(guard.close())
    try: await asyncio.shield(task)
    except asyncio.CancelledError:
        await task
        raise
