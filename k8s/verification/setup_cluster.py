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
import urllib.request

NODE_IMAGE = "kindest/node:v1.32.2@sha256:f226345927d7e348497136874b6d207e0b32cc52154ad8323129352923a3142f"
CALICO_URL = "https://raw.githubusercontent.com/projectcalico/calico/v3.30.5/manifests/calico.yaml"
CALICO_SHA256 = "55af477d939927a87d2383725e2986bca71497d00913becefabeca3795e9288a"


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


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
    run(["docker", "network", "create", "--label", "app.kubernetes.io/managed-by=lotus", "--label", "lotus.io/purpose=network-policy-verification", args.name])
    record = {"cluster": args.name, "context": "kind-" + args.name,
        "kubeconfig": str(kubeconfig), "docker_network": args.name, "node": args.name + "-control-plane",
        "node_image": NODE_IMAGE, "calico_url": CALICO_URL, "calico_sha256": CALICO_SHA256,
        "existing_clusters_modified": False, "state": "network-created"}
    ownership_path = directory / "ownership.json"
    ownership_path.write_text(json.dumps(record, indent=2))
    env = {**os.environ, "KIND_EXPERIMENTAL_DOCKER_NETWORK": args.name}
    run(["kind", "create", "cluster", "--name", args.name, "--image", NODE_IMAGE,
         "--config", str(Path(__file__).with_name("kind-calico.yaml")), "--kubeconfig", str(kubeconfig), "--wait", "0s"], env=env)
    os.chmod(kubeconfig, 0o600)
    record["state"] = "cluster-created"
    ownership_path.write_text(json.dumps(record, indent=2))
    run(["docker", "update", "--memory", f"{args.node_memory_gib}g", "--memory-swap", f"{args.node_memory_gib}g",
         "--cpus", str(args.node_cpus), args.name + "-control-plane"])
    kube = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", record["context"]]
    run(kube + ["apply", "-f", str(calico)])
    record["state"] = "cni-applied"
    ownership_path.write_text(json.dumps(record, indent=2))
    run(kube + ["-n", "kube-system", "rollout", "status", "daemonset/calico-node", "--timeout=180s"])
    run(kube + ["wait", "--for=condition=Ready", "node/" + record["node"], "--timeout=180s"])
    for ns, deployment in [("kube-system", "calico-kube-controllers"), ("kube-system", "coredns"),
                           ("local-path-storage", "local-path-provisioner")]:
        run(kube + ["-n", ns, "rollout", "status", "deployment/" + deployment, "--timeout=180s"])
    for ns in ["kube-system", "local-path-storage"]:
        run(kube + ["-n", ns, "wait", "--for=condition=Ready", "pods", "--all", "--timeout=180s"])
    # A new node cannot become Ready before its CNI exists. After these system
    # prerequisites, align reservations before returning it for audit workloads.
    from node_capacity import align
    record["capacity_alignment"] = align(directory, apply=True)
    record["state"] = "capacity-aligned"
    ownership_path.write_text(json.dumps(record, indent=2))
    print("Created owned cluster with Calico ready and measured node capacity aligned; run isolation smoke tests before audits.")


if __name__ == "__main__":
    main()
