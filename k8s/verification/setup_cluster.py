"""Create an explicitly owned, bounded kind cluster with enforcing Calico.

Run with verified kind/kubectl binaries on PATH. All kubectl calls use the private
kubeconfig; the user's current context and existing clusters are never changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.request

NODE_IMAGE = "kindest/node:v1.32.2@sha256:f226345927d7e348497136874b6d207e0b32cc52154ad8323129352923a3142f"
CALICO_URL = "https://raw.githubusercontent.com/projectcalico/calico/v3.30.5/manifests/calico.yaml"
CALICO_SHA256 = "55af477d939927a87d2383725e2986bca71497d00913becefabeca3795e9288a"


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def save_ownership(path, record):
    body = json.dumps(record, indent=2) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".ownership-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def created_network(network_id, name, container_id=None):
    if not re.fullmatch(r"[a-f0-9]{64}", network_id):
        raise RuntimeError("Docker network creation did not return an immutable ID; preserve resources for inspection")
    form = '{"Id":{{json .Id}},"Name":{{json .Name}},"Labels":{{json .Labels}},"Containers":{{json .Containers}}}'
    network = json.loads(run(["docker", "network", "inspect", network_id, "--format", form], capture_output=True).stdout)
    labels = {"app.kubernetes.io/managed-by": "lotus", "lotus.io/purpose": "network-policy-verification"}
    if (network.get("Id") != network_id or network.get("Name") != name or network.get("Labels") != labels
            or set(network.get("Containers") or {}) != ({container_id} if container_id else set())):
        raise RuntimeError("Created Docker network identity or membership differs; preserve resources for inspection")
    return network_id


def created_node(name, cluster, network_id):
    form = ('{"Id":{{json .Id}},"Name":{{json .Name}},"Labels":{{json .Config.Labels}},'
            '"Running":{{json .State.Running}},"Networks":{{json .NetworkSettings.Networks}}}')
    node = json.loads(run(["docker", "inspect", name, "--format", form], capture_output=True).stdout)
    labels = node.get("Labels") or {}
    networks = node.get("Networks") or {}
    node_id = node.get("Id", "")
    if (not re.fullmatch(r"[a-f0-9]{64}", node_id) or node.get("Name") != "/" + name
            or node.get("Running") is not True or labels.get("io.x-k8s.kind.cluster") != cluster
            or labels.get("io.x-k8s.kind.role") != "control-plane" or set(networks) != {cluster}
            or networks[cluster].get("NetworkID") != network_id):
        raise RuntimeError("Created Kind node identity or network differs; preserve resources for inspection")
    created_network(network_id, cluster, node_id)
    return node_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--node-memory-gib", type=int, default=6,
                        help="Memory cap for the new node (default 6 GiB; 4 GiB is only a small CNI fixture)")
    parser.add_argument("--node-cpus", type=int, default=3)
    args = parser.parse_args()
    if not re.fullmatch(r"lotus-netpol-[a-z0-9][a-z0-9-]{0,35}[a-z0-9]", args.name):
        parser.error("Owned cluster names must begin lotus-netpol- and contain lowercase DNS-label characters")
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    kubeconfig = directory / "kubeconfig"
    if kubeconfig.exists():
        parser.error("Private kubeconfig already exists; inspect the owned cluster before continuing")
    if args.name in run(["kind", "get", "clusters"], capture_output=True).stdout.split():
        parser.error("Cluster already exists; refusing to modify it")
    if args.name in run(["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True).stdout.splitlines():
        parser.error("Docker network already exists and was preserved. Deleting a Kind cluster may leave "
                     "its custom network behind; choose an unused --name or inspect the old network before removing it")
    info = json.loads(run(["docker", "info", "--format", "{{json .}}"], capture_output=True).stdout)
    engine_id = info.get("ID", "")
    if not isinstance(engine_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_.-]{0,255}", engine_id):
        raise RuntimeError("Docker engine identity is unavailable; no resources were created")
    if args.node_memory_gib < 2 or args.node_cpus < 1:
        parser.error("New node capacity must be at least 2 GiB / 1 CPU")
    if info["MemTotal"] < (args.node_memory_gib + 1) * 1024**3 or info["NCPU"] < args.node_cpus + 1:
        parser.error("Docker requires at least 1 GiB / 1 CPU beyond the requested node cap; inspect capacity before provisioning")
    (directory / "capacity.json").write_text(json.dumps({k: info[k] for k in ["MemTotal", "NCPU", "Architecture", "ServerVersion"]}, indent=2))
    raw = urllib.request.urlopen(CALICO_URL, timeout=45).read()
    if hashlib.sha256(raw).hexdigest() != CALICO_SHA256:
        raise RuntimeError("Pinned upstream Calico manifest checksum mismatch")
    manifest = raw.decode().replace('# - name: CALICO_IPV4POOL_CIDR\n            #   value: "192.168.0.0/16"', '- name: CALICO_IPV4POOL_CIDR\n              value: "192.168.240.0/20"')
    # Calico's default BGP encapsulation is unnecessary on this one-node cluster.
    # The upstream daemon still installs and enforces Kubernetes NetworkPolicy.
    calico = directory / "calico.yaml"
    calico.write_text(manifest)
    network_id = run(["docker", "network", "create", "--label", "app.kubernetes.io/managed-by=lotus", "--label",
                      "lotus.io/purpose=network-policy-verification", args.name], capture_output=True).stdout.strip()
    created_network(network_id, args.name)
    record = {"cluster": args.name, "context": "kind-" + args.name,
        "kubeconfig": str(kubeconfig), "docker_network": args.name, "node": args.name + "-control-plane",
        "docker_network_id": network_id, "docker_engine_id": engine_id,
        "node_image": NODE_IMAGE, "calico_url": CALICO_URL, "calico_sha256": CALICO_SHA256,
        "existing_clusters_modified": False, "state": "network-created"}
    ownership_path = directory / "ownership.json"
    save_ownership(ownership_path, record)
    env = {**os.environ, "KIND_EXPERIMENTAL_DOCKER_NETWORK": args.name}
    run(["kind", "create", "cluster", "--name", args.name, "--image", NODE_IMAGE,
         "--config", str(Path(__file__).with_name("kind-calico.yaml")), "--kubeconfig", str(kubeconfig), "--wait", "0s"], env=env)
    record["docker_container_id"] = created_node(record["node"], args.name, network_id)
    record["state"] = "cluster-created"
    save_ownership(ownership_path, record)
    os.chmod(kubeconfig, 0o600)
    run(["docker", "update", "--memory", f"{args.node_memory_gib}g", "--memory-swap", f"{args.node_memory_gib}g",
         "--cpus", str(args.node_cpus), record["docker_container_id"]])
    kube = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", record["context"]]
    run(kube + ["apply", "-f", str(calico)])
    record["state"] = "cni-applied"
    save_ownership(ownership_path, record)
    # Fresh nodes download Calico images before becoming ready. Share one
    # bounded startup budget across all checks, including slow first downloads.
    deadline = time.monotonic() + 3600
    def wait_ready(parts):
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            raise TimeoutError("Cluster system readiness timed out; inspect setup.log")
        run(kube + parts + [f"--timeout={remaining}s"])
    wait_ready(["-n", "kube-system", "rollout", "status", "daemonset/calico-node"])
    wait_ready(["wait", "--for=condition=Ready", "node/" + record["node"]])
    for ns, deployment in [("kube-system", "calico-kube-controllers"), ("kube-system", "coredns"),
                           ("local-path-storage", "local-path-provisioner")]:
        # These are fresh deployments. A cold CNI download can exhaust their
        # progress deadline before scheduling; require actual availability.
        wait_ready(["-n", ns, "wait", "--for=condition=Available", "deployment/" + deployment])
    for ns in ["kube-system", "local-path-storage"]:
        wait_ready(["-n", ns, "wait", "--for=condition=Ready", "pods", "--all"])
    # A new node cannot become Ready before its CNI exists. After these system
    # prerequisites, align reservations before returning it for audit workloads.
    from node_capacity import align
    record["capacity_alignment"] = align(directory, apply=True)
    record["state"] = "capacity-aligned"
    save_ownership(ownership_path, record)
    print("Created owned cluster with Calico ready and measured node capacity aligned; run isolation smoke tests before audits.")


if __name__ == "__main__":
    main()
