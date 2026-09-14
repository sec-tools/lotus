"""Create a separate local kind cluster and prove its NetworkPolicy behavior.

Requires Python 3 with PyYAML, kind, kubectl, and a running local Docker engine
with a Unix socket. Docker hosts kind infrastructure; Lotus runs on Kubernetes.
No existing cluster/CNI or Docker VM capacity is changed. A failed attempt leaves
its private ownership record and infrastructure for inspection, never reuse.
Setup checks configured VM totals, not current workload headroom. Check available
memory/CPU before creation; this command does not resize the Docker VM.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
OWNER = {"app.kubernetes.io/managed-by": "lotus", "lotus.io/purpose": "network-policy-verification"}
_CHECK_NAMES = {
    "positive control reaches sink Pod before policy", "positive control reaches sink Service before policy",
    "positive control reaches Kubernetes API", "positive control receives DNS response",
    "controller reaches lab Pod on application port", "controller reaches lab Service on application port",
    "controller reaches Kubernetes API", "controller cannot reach unrelated sink on port 8080",
    "lab cannot reach sink Pod", "lab cannot reach sink Service", "lab cannot reach sibling lab",
    "lab cannot reach Kubernetes API", "unlabelled observer cannot enter lab",
    "positive control sink still reachable after denials", "lab cannot send DNS queries",
    "actual worker process is nonroot, tokenless, capability-free and seccomp confined",
}
CHECKS = {name: not any(term in name for term in ("cannot reach", "cannot enter", "cannot send")) for name in _CHECK_NAMES}
CHECKS["actual worker process is nonroot, tokenless, capability-free and seccomp confined"] = {
    "uid": 1000, "token": False, "capabilities_empty": True, "no_new_privs": True, "seccomp_filter": True}
SOURCES = ("scripts/bootstrap_kind.py", "k8s/kind-config.yaml", "k8s/verification/setup_cluster.py", "k8s/verification/kind-calico.yaml",
           "k8s/verification/node_capacity.py", "k8s/verification/network_policy_preflight.py", "k8s/networkpolicy.yaml")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def plan(name, directory, image, memory=6, cpus=3, *, root=ROOT, deferred_probe=False):
    if not re.fullmatch(r"lotus-netpol-[a-z0-9][a-z0-9-]{0,35}[a-z0-9]", name):
        raise ValueError("Use a fresh lowercase cluster name beginning lotus-netpol- (maximum 50 characters)")
    if not (deferred_probe and image is None) and not (isinstance(image, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}", image)):
        raise ValueError("--probe-image must name an immutable Python image with its @sha256 digest")
    if type(memory) is not int or not 6 <= memory <= 64 or type(cpus) is not int or not 2 <= cpus <= 32:
        raise ValueError("Choose 6–64 GiB and 2–32 CPUs for the new node; check existing workload headroom separately")
    directory = Path(directory).expanduser()
    if directory.is_symlink() or directory.exists():
        raise ValueError("State directory already exists; inspect its bootstrap.json and ownership.json instead of reusing it")
    directory = directory.resolve()
    try:
        import yaml
    except ImportError as error:
        raise RuntimeError("Install PyYAML in this Python environment before planning or creating the cluster") from error
    config = yaml.safe_load((root / "k8s/kind-config.yaml").read_text())
    reference = yaml.safe_load((root / "k8s/verification/kind-calico.yaml").read_text())
    if config != reference or config.get("networking", {}).get("disableDefaultCNI") is not True or config.get("networking", {}).get("apiServerAddress") != "127.0.0.1" or config.get("nodes") != [{"role": "control-plane"}]:
        raise ValueError("Fresh kind configuration must match the owned Calico fixture without host mounts or port publishing")
    sources = {name: sha(root / name) for name in SOURCES}
    return {"schema_version": 1, "cluster": name, "context": "kind-" + name,
            "directory": str(directory), "kubeconfig": str(directory / "kubeconfig"),
            "probe_image": image, "node_memory_gib": memory, "node_cpus": cpus,
            "pod_network": config["networking"]["podSubnet"], "service_network": config["networking"]["serviceSubnet"],
            "deployment_environment": {"LOTUS_K8S_NETWORK_NODE_CONTROL_PORT": "6443"},
            "deployment_environment_scope": "This owned single-control-plane Kind topology only. Runtime admission must observe a reachable node control before treating its denial as evidence; the setting alone proves nothing.",
            "source_sha256": sources, "state": "planned", "ready": False,
            "scope": "Fresh single-node IPv4 cluster; controller/lab role policies and authored local traffic only. Runtime-specific policies still require their own admission checks.",
            "existing_clusters_modified": False, "docker_vm_capacity_modified": False}


def cluster_identity(value, kube, *, run=None, env=None):
    """Require the actual one-node inventory and IPv4 Pod/Service allocation."""
    run = run or command
    nodes = json.loads(run([*kube, "get", "nodes", "-o", "json"], timeout=10, env=env))["items"]
    if len(nodes) != 1 or nodes[0]["metadata"]["name"] != value["cluster"] + "-control-plane":
        raise RuntimeError("Bootstrap isolation scope requires exactly the one owned node")
    node = nodes[0]
    cidrs = node["spec"].get("podCIDRs")
    if not isinstance(cidrs, list) or len(cidrs) != 1 or node["spec"].get("podCIDR") != cidrs[0]:
        raise RuntimeError("The owned node has unknown or multiple Pod IP families")
    pod_network = ipaddress.ip_network(cidrs[0])
    if pod_network.version != 4 or not pod_network.subnet_of(ipaddress.ip_network(value["pod_network"])):
        raise RuntimeError("The owned node is outside the planned IPv4 Pod network")
    service = json.loads(run([*kube, "get", "service", "kubernetes", "-n", "default", "-o", "json"], timeout=10, env=env))
    spec = service["spec"]
    if spec.get("ipFamilies") != ["IPv4"] or spec.get("clusterIPs") != [spec.get("clusterIP")]:
        raise RuntimeError("The cluster has unknown or multiple Service IP families")
    address = ipaddress.ip_address(spec["clusterIP"])
    if address.version != 4 or address not in ipaddress.ip_network(value["service_network"]):
        raise RuntimeError("The Kubernetes Service is outside the planned IPv4 network")
    system = json.loads(run([*kube, "get", "namespace", "kube-system", "-o", "json"], timeout=10, env=env))
    return {"system_namespace_uid": system["metadata"]["uid"], "node_uid": node["metadata"]["uid"],
            "node_count": 1, "pod_cidr": str(pod_network), "service_uid": service["metadata"]["uid"],
            "service_ip": str(address), "ip_family": "IPv4", "kubeconfig_sha256": sha(value["kubeconfig"])}


def command(argv, *, timeout=30, env=None, data=None, log=None):
    """Bound the entire process group; never pass shell commands or retain pipes."""
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True, env=env)
        try:
            process.communicate(data.encode() if data is not None else None, timeout=timeout)
        except BaseException:
            if log is not None:
                output.seek(0)
                Path(log).write_bytes(output.read(2 * 1024 * 1024))
            # Do not reap the leader before terminating its group: descendants
            # can outlive the leader, and its unreaped PID cannot be reused.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            time.sleep(.2)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                # Darwin can return EPERM for an already empty group. A real
                # surviving process must still fail closed below.
                groups = subprocess.run(["ps", "-axo", "pgid=,stat="], capture_output=True,
                                        text=True, check=True, timeout=2).stdout
                if any(len(parts := line.split()) == 2 and parts[0] == str(process.pid)
                       and not parts[1].startswith("Z") for line in groups.splitlines()):
                    raise RuntimeError("Bootstrap command still has a live process group; cleanup is unconfirmed")
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError("Bootstrap command cleanup remains unconfirmed; inspect owned infrastructure") from error
            if process.stdin is not None:
                process.stdin.close()
            raise
        output.seek(0)
        raw = output.read(2 * 1024 * 1024 + 1)
    if log is not None:
        Path(log).write_bytes(raw[:2 * 1024 * 1024])
    if len(raw) > 2 * 1024 * 1024:
        raise RuntimeError("Bootstrap command output exceeded its bounded record")
    text = raw.decode("utf-8", errors="replace")
    if process.returncode:
        hint = f"; inspect {log}" if log is not None else "; check this prerequisite command directly"
        raise RuntimeError(f"{Path(argv[0]).name} failed (exit {process.returncode})" + hint)
    return text


def save(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with os.fdopen(os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def traffic_passed(report):
    rows = report.get("checks")
    if report.get("status") != "passed" or not isinstance(rows, list):
        return False
    found = {row.get("name"): row for row in rows if isinstance(row, dict)}
    return len(found) == len(rows) and set(CHECKS) <= set(found) and all(
        row.get("passed") is True and row.get("observed") == row.get("expected") for row in found.values()) and all(
        found[name].get("expected") == expected and type(found[name].get("expected")) is type(expected)
        and type(found[name].get("observed")) is type(expected) for name, expected in CHECKS.items())


def cleanup_probes(kube, names, report, *, run=command, env=None):
    """Delete only returned exact namespace UIDs; verify actual disappearance."""
    rows = report.get("retained_namespaces", [])
    known = {row["name"]: row["uid"] for row in rows if isinstance(row, dict) and
             row.get("name") in names and isinstance(row.get("uid"), str) and row["uid"]}
    if len(known) != len(rows):
        raise RuntimeError("Probe cleanup ownership record is malformed")
    for name in names:
        args = [*kube, "get", "namespace", name, "--ignore-not-found", "-o", "json"]
        raw = run(args, timeout=10, env=env)
        if not raw.strip():
            continue
        metadata = json.loads(raw)["metadata"]
        if metadata.get("uid") != known.get(name) or any(metadata.get("labels", {}).get(k) != v for k, v in OWNER.items()):
            raise RuntimeError("Probe namespace ownership changed or creation was uncertain: " + name)
        run([*kube, "delete", "--raw=/api/v1/namespaces/" + name, "-f", "-"], timeout=10, env=env,
            data=json.dumps({"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": known[name]}, "propagationPolicy": "Foreground"}))
        # The authored fixture Pods retain Kubernetes' 30-second termination
        # grace; allow its bounded namespace deletion to finish before refusal.
        deadline = time.monotonic() + 45
        while True:
            raw = run(args, timeout=5, env=env)
            if not raw.strip():
                break
            if json.loads(raw)["metadata"].get("uid") != known[name]:
                raise RuntimeError("Probe namespace was replaced during cleanup: " + name)
            if time.monotonic() >= deadline:
                raise RuntimeError("Probe namespace cleanup is still pending: " + name)
            time.sleep(.25)
    return True


def create(value, *, root=ROOT, run=command, prepare_probe=None, python_executable=None):
    if value.get("probe_image") is None and prepare_probe is None:
        raise ValueError("A deferred probe requires an owned-node image preparation callback")
    python_executable = python_executable or sys.executable
    for binary in ("kind", "kubectl", "docker"):
        if not shutil.which(binary):
            raise RuntimeError(f"Install {binary} before --create; no tools or clusters were changed")
    if importlib.util.find_spec("yaml") is None:
        raise RuntimeError("Install PyYAML in this Python environment before --create")
    endpoint = os.environ.get("DOCKER_HOST") or json.loads(run(
        ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"], timeout=10))
    if not isinstance(endpoint, str) or not endpoint.startswith("unix://"):
        raise RuntimeError("kind bootstrap requires an explicitly local Docker Unix socket; remote engines are not modified")
    env = {**os.environ, "DOCKER_HOST": endpoint, "KIND_EXPERIMENTAL_PROVIDER": "docker"}
    env.pop("DOCKER_CONTEXT", None)
    if value["cluster"] in run(["kind", "get", "clusters"], timeout=15, env=env).split():
        raise RuntimeError("Cluster already exists; refusing to replace its CNI")
    directory = Path(value["directory"])
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)  # Concurrent same-directory attempts cannot queue behind creation.
    receipt = directory / "bootstrap.json"
    value = dict(value, state="creating", docker_endpoint=endpoint, started_at=time.time())
    save(receipt, value)
    report_path = directory / "network-policy.json"
    namespace = "lotus-netpol-" + uuid.uuid4().hex[:16]
    names = [namespace, namespace + "-sink"]
    kube = ["kubectl", "--kubeconfig", value["kubeconfig"], "--context", value["context"]]
    try:
        if any(sha(root / name) != expected for name, expected in value["source_sha256"].items()):
            raise RuntimeError("Bootstrap helpers changed after the plan was captured")
        print("Creating a separate kind cluster with pinned Calico…", flush=True)
        run([python_executable, str(root / "k8s/verification/setup_cluster.py"), "--name", value["cluster"],
             "--directory", str(directory), "--node-memory-gib", str(value["node_memory_gib"]),
             "--node-cpus", str(value["node_cpus"])], timeout=1200, env=env, log=directory / "setup.log")
        ownership = json.loads((directory / "ownership.json").read_text())
        if ownership.get("cluster") != value["cluster"] or ownership.get("context") != value["context"] or ownership.get("kubeconfig") != value["kubeconfig"] or ownership.get("state") != "capacity-aligned":
            raise RuntimeError("Created cluster ownership/readiness record does not match the request")
        def identity():
            return cluster_identity(value, kube, run=run, env=env)
        value.update(state="checking-network", cluster_identity=identity(), probe_namespaces=names)
        if prepare_probe is not None:
            # This hook runs only after this invocation created and identified
            # the new node. The normal traffic gate still runs on the observed
            # immutable application image after preload; no policy waiver.
            prepared = prepare_probe(dict(value, created_by_this_run=True))
            selected_image = prepared.get("image") if isinstance(prepared, dict) else None
            if not isinstance(selected_image, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}", selected_image):
                raise RuntimeError("Owned-node preparation did not return an immutable probe image")
            if identity() != value["cluster_identity"]:
                raise RuntimeError("Cluster identity changed during image preparation")
            value.update(probe_image=selected_image, image_preparation=prepared)
        save(receipt, value)
        print("Measuring positive controls and blocked Pod/Service/API/DNS traffic…", flush=True)
        try:
            run([python_executable, str(root / "k8s/verification/network_policy_preflight.py"), "--kubeconfig", value["kubeconfig"],
                 "--context", value["context"], "--namespace", namespace, "--image", value["probe_image"],
                 "--output", str(report_path), "--keep"], timeout=700, env=env, log=directory / "network-policy.log")
        finally:
            report = json.loads(report_path.read_text()) if report_path.exists() else {}
            value["probe_cleanup_verified"] = cleanup_probes(kube, names, report, run=run, env=env)
            save(receipt, value)
        if not traffic_passed(report) or report.get("context") != value["context"] or report.get("image") != value["probe_image"] or report.get("namespaces") != names:
            raise RuntimeError("Actual NetworkPolicy traffic checks did not pass for this cluster and image")
        if identity() != value["cluster_identity"] or any(sha(root / name) != expected for name, expected in value["source_sha256"].items()):
            raise RuntimeError("Cluster identity or policy source changed during verification")
        value.update(state="ready", ready=True, network_receipt_sha256=sha(report_path), finished_at=time.time())
        save(receipt, value)
        print("NetworkPolicy checks passed. Private kubeconfig: " + value["kubeconfig"], flush=True)
        return value
    except BaseException as error:
        value.update(state="failed", ready=False, error=str(error)[:800], finished_at=time.time())
        save(receipt, value)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog="Plan mode is read-only. --create refuses existing state or clusters. Use a Python image with python available, pinned by digest. The receipt states the exact tested isolation scope.")
    parser.add_argument("--name", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--probe-image", required=True,
                        help="Trusted Python image, pullable by the new cluster and pinned as registry/name@sha256:digest")
    parser.add_argument("--node-memory-gib", type=int, default=6)
    parser.add_argument("--node-cpus", type=int, default=3)
    parser.add_argument("--create", action="store_true", help="Create a new owned cluster, install pinned Calico, and require actual traffic/cleanup checks")
    args = parser.parse_args()
    try:
        value = plan(args.name, args.directory, args.probe_image, args.node_memory_gib, args.node_cpus)
        if args.create:
            create(value)
        else:
            print(json.dumps(value, indent=2))
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
