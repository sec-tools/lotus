"""Remove one recorded installation; never discover ownership from a name alone.

Called under quickstart's installation lock. Host images are deliberately kept.
A failed cleanup retains its journal and private state for a bounded retry.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time
from types import SimpleNamespace

OWNER = "lotus.io/quickstart-owner"
NETWORK_LABELS = {"app.kubernetes.io/managed-by": "lotus", "lotus.io/purpose": "network-policy-verification"}
BASE_NAMESPACES = {"default", "kube-system", "kube-public", "kube-node-lease", "local-path-storage"}
FULL_ID = re.compile(r"[a-f0-9]{64}")
JOURNAL = "installation-cleanup.json"


class CleanupError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise CleanupError(message + "; existing resources and private state were preserved where possible")


def _read(path, optional=False):
    if optional and not path.exists():
        return None
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 2_000_000,
            "Installation metadata is missing, indirect or oversized")
    try:
        value = json.loads(path.read_text())
    except (ValueError, UnicodeError):
        raise CleanupError("Invalid installation metadata; private state was preserved") from None
    require(isinstance(value, dict), "Installation metadata is not an object")
    return value


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _identity(value):
    m = value.get("metadata", {})
    return {"kind": value.get("kind"), "name": m.get("name"), "namespace": m.get("namespace"), "uid": m.get("uid")}


class Cleanup:
    def __init__(self, directory, state, run):
        self.directory, self.state, self.run = directory, state, run
        self.env = None
        self.kube = None

    def call(self, args, *, data=None, timeout=30):
        try:
            value = self.run(args, data=data, timeout=timeout, env=self.env)
        except (RuntimeError, OSError, TimeoutError) as error:
            raise CleanupError("Cleanup command did not complete; retry down after inspecting the retained state") from None
        require(isinstance(value, str) and len(value) <= 8_000_000, "Cleanup command returned an invalid bounded response")
        return value

    def json(self, args):
        try:
            return json.loads(self.call(args))
        except (ValueError, RecursionError):
            raise CleanupError("Cleanup identity response is invalid; resources were preserved") from None

    def get(self, kind, name=None, namespace=None):
        args = self.kube + ["get", kind]
        if name:
            args += [name, "--ignore-not-found"]
        if namespace:
            args += ["-n", namespace]
        raw = self.call(args + ["-o", "json"])
        return json.loads(raw) if raw.strip() else None

    def configure_kube(self, config, context, expected_hash=None):
        path = Path(config)
        require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents))
                and path.is_file() and isinstance(context, str) and context and not context.startswith("-"),
                "Recorded Kubernetes connection is missing or indirect")
        if expected_hash:
            require(_sha(path) == expected_hash, "Recorded kubeconfig changed")
        self.kube = ["kubectl", "--kubeconfig", str(path), "--context", context, "--request-timeout=15s"]

    def docker_plan(self):
        boot = _read(self.directory / "cluster/bootstrap.json", optional=True)
        stage = self.state.get("failed_stage", self.state.get("stage"))
        if boot is None:
            require(stage in {"preparing-python", "preparing-image"} and not (self.directory / "cluster").exists(),
                    "Interrupted cluster creation has no verifiable ownership record")
            return {"mode": "private-state-only"}
        cluster = boot.get("cluster", "")
        require(re.fullmatch(r"lotus-netpol-[a-z0-9][a-z0-9-]{0,35}[a-z0-9]", cluster)
                and boot.get("existing_clusters_modified") is False
                and boot.get("directory") == str(self.directory / "cluster")
                and boot.get("kubeconfig") == str(self.directory / "cluster/kubeconfig")
                and boot.get("context") == "kind-" + cluster, "Bootstrap scope changed")
        image = _read(self.directory / "image/image.json", optional=True) or {}
        endpoint = boot.get("docker_endpoint")
        require(isinstance(endpoint, str) and endpoint.startswith("unix://")
                and (not image.get("docker_endpoint") or image["docker_endpoint"] == endpoint), "Docker endpoint changed")
        self.env = {**os.environ, "DOCKER_HOST": endpoint}
        self.env.pop("DOCKER_CONTEXT", None)
        own = _read(self.directory / "cluster/ownership.json", optional=True) or {}
        node_image = _read(self.directory / "image/node-image.json", optional=True) or {}
        if own:
            require(all(own.get(k) == v for k, v in {"cluster": cluster, "context": boot["context"],
                    "kubeconfig": boot["kubeconfig"], "node": cluster + "-control-plane", "docker_network": cluster,
                    "existing_clusters_modified": False}.items()), "Cluster ownership scope changed")
        recorded = node_image.get("node", {})
        cid = own.get("docker_container_id") or recorded.get("docker_id")
        network = own.get("docker_network_id") or recorded.get("network_id")
        require(not own.get("docker_container_id") or not recorded.get("docker_id") or cid == recorded["docker_id"], "Node receipts disagree")
        require(not own.get("docker_network_id") or not recorded.get("network_id") or network == recorded["network_id"], "Network receipts disagree")
        engine = own.get("docker_engine_id") or image.get("docker_engine_id")
        require(engine and self.json(["docker", "info", "--format", "{{json .ID}}"] ) == engine, "Docker engine identity changed")
        members = self.call(["docker", "ps", "-aq", "--no-trunc", "--filter", "label=io.x-k8s.kind.cluster=" + cluster]).split()
        networks = [json.loads(line) for line in self.call(["docker", "network", "ls", "--no-trunc", "--format", "{{json .}}"]).splitlines() if line.strip()]
        matching = [x for x in networks if x.get("Name") == cluster]
        require((not cid or FULL_ID.fullmatch(cid)) and (not network or FULL_ID.fullmatch(network)), "Recorded Docker IDs are invalid")
        require(not members or (cid and members == [cid]), "Cluster members are unknown or replaced")
        require(not matching or (network and len(matching) == 1 and matching[0].get("ID") == network), "Network is unknown or replaced")
        plan = {"mode": "owned-kind", "cluster": cluster, "container_id": cid, "network_id": network,
                "engine_id": engine, "endpoint": endpoint, "node_image": own.get("node_image"),
                "kubeconfig": boot["kubeconfig"], "context": boot["context"],
                "identity": boot.get("cluster_identity") or node_image.get("cluster_identity")}
        self.check_docker(plan)
        self.check_kubernetes_scope(plan)
        return plan

    def check_docker(self, plan):
        require(self.json(["docker", "info", "--format", "{{json .ID}}"] ) == plan["engine_id"], "Docker engine changed")
        members = self.call(["docker", "ps", "-aq", "--no-trunc", "--filter", "label=io.x-k8s.kind.cluster=" + plan["cluster"]]).split()
        cid = plan["container_id"]
        require(not members or members == [cid], "Owned node was replaced or extra nodes appeared")
        all_ids = self.call(["docker", "ps", "-aq", "--no-trunc"]).split()
        self.node_running = False
        node = None
        if cid and cid in all_ids:
            node = self.json(["docker", "inspect", "--format", '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"image":{{json .Config.Image}},"networks":{{json .NetworkSettings.Networks}},"running":{{json .State.Running}},"mounts":{{json .Mounts}}}', cid])
            self.node_running = node.get("running") is True
            require(members == [cid] and node.get("id") == cid and node.get("name") == "/" + plan["cluster"] + "-control-plane"
                    and node.get("labels", {}).get("io.x-k8s.kind.role") == "control-plane"
                    and node.get("image") == plan["node_image"], "Exact Docker node identity changed")
            require(set(node.get("networks", {})) <= {plan["cluster"]}
                    and all(v.get("NetworkID") == plan["network_id"] for v in node.get("networks", {}).values()), "Node has an unrelated network attachment")
        else:
            require(not members, "Recorded node is absent but a replacement exists")
        networks = [json.loads(line) for line in self.call(["docker", "network", "ls", "--no-trunc", "--format", "{{json .}}"]).splitlines() if line.strip()]
        names = [x for x in networks if x.get("Name") == plan["cluster"]]
        require(not names or (len(names) == 1 and names[0].get("ID") == plan["network_id"]), "Recorded network was replaced")
        network_exists = any(x.get("ID") == plan["network_id"] for x in networks)
        if network_exists:
            net = self.json(["docker", "network", "inspect", plan["network_id"]])[0]
            require(net.get("Id") == plan["network_id"] and net.get("Name") == plan["cluster"] and net.get("Labels") == NETWORK_LABELS
                    and set(net.get("Containers", {})) <= ({cid} if cid else set()), "Network has unknown ownership or attachments")
        self.check_volumes(plan, node, all_ids)
        return bool(cid and cid in all_ids), network_exists

    def check_volumes(self, plan, node, all_ids):
        require(len(all_ids) <= 256, "Too many containers for bounded volume ownership verification")
        if node is not None:
            mounts = node.get("mounts", [])
            expected = [x for x in mounts if x.get("Destination") == "/var"]
            require(len(expected) == 1 and expected[0].get("Type") == "volume" and expected[0].get("Driver") == "local",
                    "Owned node data is not on its expected local Docker volume")
            require(all(x.get("Destination") == "/var" or (x.get("Type") == "bind" and x.get("Destination") == "/lib/modules" and x.get("RW") is False) for x in mounts), "Node has an unexpected host mount")
            name = expected[0].get("Name", "")
            require(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}", name), "Node volume identity is missing")
            if "volume_names" in plan:
                require(plan["volume_names"] == [name], "Node volume changed since cleanup admission")
            else:
                plan["volume_names"] = [name]
        elif "volume_names" not in plan:
            require(not plan.get("container_id"), "Removed node has no saved data-volume cleanup identity")
            plan["volume_names"] = []
        names = set(self.call(["docker", "volume", "ls", "--format", "{{.Name}}"]).splitlines())
        if all_ids and plan["volume_names"]:
            raw = self.call(["docker", "inspect", "--format", '{"id":{{json .Id}},"mounts":{{json .Mounts}}}', *all_ids])
            users = [json.loads(line) for line in raw.splitlines() if line.strip()]
            require({x.get("id") for x in users} == set(all_ids), "Container volume inventory was incomplete")
            require(not any(x["id"] != plan.get("container_id") and any(v.get("Name") in plan["volume_names"] for v in x.get("mounts", [])) for x in users), "Node data volume is shared by another container")
        recorded = plan.setdefault("volumes", {})
        for name in plan["volume_names"]:
            if name not in names:
                require(node is None, "Running node data volume is missing")
                continue
            value = self.json(["docker", "volume", "inspect", name])[0]
            require(value.get("Name") == name and value.get("Driver") == "local" and not value.get("Options"), "Data volume storage changed")
            identity = {k: value.get(k) for k in ("Name", "Driver", "Mountpoint", "CreatedAt")}
            require(identity["Mountpoint"] and identity["CreatedAt"], "Data volume lacks a stable identity")
            if name in recorded:
                require(recorded[name] == identity, "Data volume was replaced")
            else:
                recorded[name] = identity

    def check_kubernetes_scope(self, plan, *, admitted=False):
        exists, _ = self.check_docker(plan)
        if not exists or not plan.get("identity"):
            return
        if not self.node_running:
            require(admitted, "Stopped cluster needs a previously admitted cleanup journal")
            return
        ident = plan["identity"]
        self.configure_kube(plan["kubeconfig"], plan["context"], ident.get("kubeconfig_sha256"))
        require((self.get("namespace", "kube-system") or {}).get("metadata", {}).get("uid") == ident.get("system_namespace_uid"), "Kubernetes cluster was replaced")
        require((self.get("node", plan["cluster"] + "-control-plane") or {}).get("metadata", {}).get("uid") == ident.get("node_uid"), "Kubernetes node was replaced")
        namespaces = [r for r in self.state.get("resources", []) if r.get("kind") == "Namespace"]
        for row in namespaces:
            self.check_resource(row)
        owned = {r["name"] for r in namespaces}
        report = _read(self.directory / "cluster/network-policy.json", optional=True) or {}
        probes = {r["name"]: r["uid"] for r in report.get("retained_namespaces", [])}
        for ns in self.get("namespaces").get("items", []):
            m = ns["metadata"]
            if m["name"] in probes:
                require(m["uid"] == probes[m["name"]], "Probe namespace identity changed")
            else:
                require(m["name"] in BASE_NAMESPACES | owned, "Unrelated namespace exists in the owned Kind cluster")
        rows = self.json(self.kube + ["get", "pods,deployments,daemonsets,statefulsets,replicasets,jobs,cronjobs,pvc,services", "-A", "-o", "json"])["items"]
        bootstrap = {("Deployment", "kube-system", "calico-kube-controllers"), ("Deployment", "kube-system", "coredns"), ("Deployment", "local-path-storage", "local-path-provisioner"), ("DaemonSet", "kube-system", "calico-node"), ("DaemonSet", "kube-system", "kube-proxy")}
        accepted = {(x["kind"], x["metadata"].get("namespace"), x["metadata"]["uid"]) for x in rows if (x["kind"], x["metadata"].get("namespace"), x["metadata"]["name"]) in bootstrap}
        for kind, parents in (("ReplicaSet", {"Deployment"}), ("Pod", {"ReplicaSet", "DaemonSet"})):
            for x in rows:
                m = x["metadata"]
                if x["kind"] == kind and any(o.get("kind") in parents and (o["kind"], m.get("namespace"), o.get("uid")) in accepted and o.get("controller") is True for o in m.get("ownerReferences", [])):
                    accepted.add((kind, m.get("namespace"), m["uid"]))
        for x in rows:
            m = x["metadata"]; ns = m.get("namespace")
            if ns in owned or ns in probes:
                continue
            key = (x["kind"], ns, m["name"])
            service = key in {("Service", "default", "kubernetes"), ("Service", "kube-system", "kube-dns")}
            static = x["kind"] == "Pod" and ns == "kube-system" and m["name"] in {p + "-" + plan["cluster"] + "-control-plane" for p in ("etcd", "kube-apiserver", "kube-controller-manager", "kube-scheduler")} and any(o.get("kind") == "Node" and o.get("uid") == ident["node_uid"] for o in m.get("ownerReferences", []))
            require(service or static or (x["kind"], ns, m["uid"]) in accepted, "Foreign workload or storage exists outside this installation")

    def existing_plan(self):
        state = self.state
        phase = state.get("failed_stage", state.get("stage"))
        if phase == "preparing-python" and not state.get("resources") and not any((self.directory / name).exists() for name in ("network-attempt.json", "network-policy.json", "deployment.json")):
            return {"mode": "private-state-only"}
        require(state.get("cluster_uid") and state.get("kubeconfig_sha256"), "Interrupted existing-cluster setup lacks a bound cluster identity")
        self.configure_kube(state.get("kubeconfig", ""), state.get("context"), state["kubeconfig_sha256"])
        require((self.get("namespace", "kube-system") or {}).get("metadata", {}).get("uid") == state["cluster_uid"], "Existing cluster was replaced")
        rows = state.get("resources", [])
        require(isinstance(rows, list), "Resource ownership records are invalid")
        namespaces = [r for r in rows if r.get("kind") == "Namespace"]
        require(all(r.get("name") in {"lotus", "lotus-build"} and r.get("uid") for r in namespaces)
                and len({r["name"] for r in namespaces}) == len(namespaces), "Namespace ownership is ambiguous")
        roots = namespaces + [r for r in rows if not r.get("namespace") and r.get("kind") != "Namespace"]
        require(all(r.get("kind") in {"Namespace", "ClusterRole", "ClusterRoleBinding"} for r in roots), "Unknown cluster-scoped installation resource")
        manifest = _read(self.directory / "deployment.json", optional=True) or {}
        intended = {(r.get("kind"), r.get("metadata", {}).get("name")) for r in manifest.get("items", []) if r.get("kind") in {"Namespace", "ClusterRole", "ClusterRoleBinding"}}
        known = {(r["kind"], r["name"]): r for r in roots}
        for name in ("lotus", "lotus-build"):
            current = self.get("Namespace", name)
            if current and current.get("metadata", {}).get("labels", {}).get(OWNER) == state["nonce"] and ("Namespace", name) not in known:
                require(("Namespace", name) in intended, "Unrecorded namespace has no matching install intent")
                row = _identity(current); namespaces.append(row); roots.append(row); known[("Namespace", name)] = row
        intent = _read(self.directory / "network-attempt.json", optional=True)
        if intent:
            names = intent.get("namespaces", [])
            require(intent.get("cluster_uid") == state["cluster_uid"] and intent.get("context") == state["context"]
                    and isinstance(names, list) and len(names) == 2 and re.fullmatch(r"lotus-netpol-[a-f0-9]{16}", names[0])
                    and names[1] == names[0] + "-sink", "Network probe intent is not bound to this cluster")
            report = _read(self.directory / "network-policy.json", optional=True) or {}
            identities = {r["name"]: r["uid"] for r in report.get("retained_namespaces", []) if r.get("name") in names}
            from scripts.bootstrap_kind import OWNER as probe_labels
            for name in names:
                current = self.get("Namespace", name)
                if current:
                    require(current["metadata"].get("uid") == identities.get(name) and all(current["metadata"].get("labels", {}).get(k) == v for k, v in probe_labels.items()), "Probe namespace has uncertain ownership")
                    row = _identity(current); row["owner_labels"] = probe_labels; roots.append(row)
        elif (self.directory / "network-policy.json").exists():
            require(not (_read(self.directory / "network-policy.json").get("retained_namespaces")), "Probe cleanup lacks a saved attempt identity")
        for kind in ("ClusterRole", "ClusterRoleBinding"):
            for resource in self.get(kind).get("items", []):
                if resource.get("metadata", {}).get("labels", {}).get(OWNER) != state["nonce"]:
                    continue
                row = _identity(resource); key = (row["kind"], row["name"])
                if key not in known:
                    require(key in intended, "Unrecorded cluster permission has no matching install intent")
                    roots.append(row); known[key] = row
        for row in roots:
            self.check_resource(row)
        plan = {"mode": "existing-kubernetes", "roots": roots, "volumes": [], "claims": [], "cluster_uid": state["cluster_uid"]}
        self.refresh_storage(plan)
        return plan

    def refresh_storage(self, plan):
        claims = {r["uid"]: r for r in plan.get("claims", [])}
        for row in plan["roots"]:
            if row["kind"] == "Namespace" and self.check_resource(row):
                for pvc in self.get("pvc", namespace=row["name"]).get("items", []):
                    identity = _identity(pvc); claims[identity["uid"]] = identity
        plan["claims"] = list(claims.values())
        volumes = {r["uid"]: r for r in plan.get("volumes", [])}
        for pv in self.get("pv").get("items", []):
            if pv.get("spec", {}).get("claimRef", {}).get("uid") in claims:
                require(pv["spec"].get("persistentVolumeReclaimPolicy") == "Delete", "Owned storage uses Retain; administrator must remove its data explicitly")
                identity = _identity(pv); volumes[identity["uid"]] = identity
        plan["volumes"] = list(volumes.values())
        if getattr(self, "checkpoint", None):
            self.checkpoint()

    def check_resource(self, row):
        require(isinstance(row.get("uid"), str) and row["uid"] and isinstance(row.get("name"), str) and row["name"] and "/" not in row["name"], "Invalid owned resource identity")
        current = self.get(row["kind"], row["name"], row.get("namespace"))
        if current:
            require(_identity(current) == {k: row.get(k) for k in ("kind", "name", "namespace", "uid")} and all(current["metadata"].get("labels", {}).get(k) == v for k, v in row.get("owner_labels", {OWNER: self.state["nonce"]}).items()), "Owned resource was replaced or ownership changed")
        return current

    def delete_existing(self, plan):
        require((self.get("namespace", "kube-system") or {}).get("metadata", {}).get("uid") == plan["cluster_uid"], "Existing cluster changed before cleanup")
        routes = {"Namespace": "/api/v1/namespaces/", "ClusterRole": "/apis/rbac.authorization.k8s.io/v1/clusterroles/", "ClusterRoleBinding": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/"}
        self.refresh_storage(plan)
        for row in sorted(plan["roots"], key=lambda r: r["kind"] == "Namespace"):
            if self.check_resource(row):
                self.call(self.kube + ["delete", "--raw=" + routes[row["kind"]] + row["name"], "-f", "-"], data=json.dumps({"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": row["uid"]}, "propagationPolicy": "Foreground"}))
        deadline = time.monotonic() + 180
        while True:
            self.refresh_storage(plan)
            remaining = [r for r in plan["roots"] if self.check_resource(r)]
            for row in plan["volumes"]:
                current = self.get("pv", row["name"])
                if current:
                    require(_identity(current) == row, "Owned volume was replaced during cleanup")
                    remaining.append(row)
            if not remaining:
                self.refresh_storage(plan)
                if not any(self.get("pv", r["name"]) for r in plan["volumes"]):
                    return
            require(time.monotonic() < deadline, "Owned resource deletion is still pending")
            time.sleep(.5)


def down(args, *, run=None):
    """Delete the recorded installation and state; caller holds its sibling lock."""
    from scripts import bootstrap_kind, quickstart
    directory = Path(args.state).expanduser().absolute()
    require(not any(p.is_symlink() for p in (directory, *directory.parents)), "Installation path contains a symlink")
    if not directory.exists():
        print("No saved Lotus installation in this location; no resources were removed.", flush=True)
        return {"removed": False, "already_absent": True}
    require(directory.is_dir() and directory not in {Path('/'), Path.home()} and directory.stat().st_mode & 0o077 == 0,
            "Installation state is not a private directory")
    receipt = directory / "quickstart.json"
    state = _read(receipt)
    require(state.get("schema_version") == 1 and state.get("directory") == str(directory)
            and re.fullmatch(r"[a-f0-9]{32}", state.get("nonce", ""))
            and state.get("mode") in {"owned-kind", "existing-kubernetes"}, "Installation receipt does not bind this directory")
    old_hash, inode = _sha(receipt), directory.stat()
    worker = Cleanup(directory, state, run or quickstart.run)
    journal = _read(directory / JOURNAL, optional=True)
    if journal:
        require(journal.get("schema_version") == 1 and journal.get("nonce") == state["nonce"]
                and journal.get("directory") == str(directory) and journal.get("mode") == state["mode"]
                and isinstance(journal.get("plan"), dict)
                and journal["plan"].get("mode") in {state["mode"], "private-state-only"},
                "Cleanup journal does not match this installation")
        plan = journal["plan"]
        if plan["mode"] == "owned-kind":
            worker.env = {**os.environ, "DOCKER_HOST": plan["endpoint"]};worker.env.pop("DOCKER_CONTEXT", None)
            worker.check_docker(plan)
            worker.check_kubernetes_scope(plan, admitted=True)
        elif plan["mode"] == "existing-kubernetes":
            worker.configure_kube(state["kubeconfig"], state["context"], state["kubeconfig_sha256"])
            require((worker.get("namespace", "kube-system") or {}).get("metadata", {}).get("uid") == plan["cluster_uid"], "Existing cluster changed")
            for row in plan["roots"]:worker.check_resource(row)
    else:
        plan = worker.docker_plan() if state["mode"] == "owned-kind" else worker.existing_plan()
        require(_sha(receipt) == old_hash, "Installation state changed during cleanup admission")
        journal = {"schema_version": 1, "directory": str(directory), "nonce": state["nonce"], "mode": state["mode"], "plan": plan}
        bootstrap_kind.save(directory / JOURNAL, journal)
    worker.checkpoint = lambda: bootstrap_kind.save(directory / JOURNAL, journal)
    state.update(stage="removing", ready=False)
    bootstrap_kind.save(receipt, state)
    print("Removing this installation and its audit data; unrelated installations and host images are preserved.", flush=True)
    if plan["mode"] == "owned-kind":
        exists, _ = worker.check_docker(plan)
        worker.check_kubernetes_scope(plan, admitted=True)
        if exists:
            worker.call(["docker", "stop", "--time", "30", plan["container_id"]], timeout=50)
            worker.check_docker(plan)
            worker.call(["docker", "rm", "--volumes", plan["container_id"]], timeout=60)
        exists, network_exists = worker.check_docker(plan)
        require(not exists, "Owned node still exists")
        for name in plan.get("volume_names", []):
            if name in worker.call(["docker", "volume", "ls", "--format", "{{.Name}}"]).splitlines():
                worker.check_docker(plan)
                worker.call(["docker", "volume", "rm", name], timeout=30)
        require(not set(plan.get("volume_names", [])) & set(worker.call(["docker", "volume", "ls", "--format", "{{.Name}}"]).splitlines()), "Owned data volume still exists")
        if network_exists:
            worker.call(["docker", "network", "rm", plan["network_id"]], timeout=30)
        require(worker.check_docker(plan) == (False, False), "Owned Docker resources still exist")
    elif plan["mode"] == "existing-kubernetes":
        worker.delete_existing(plan)
    require(not directory.is_symlink() and (directory.stat().st_dev, directory.stat().st_ino) == (inode.st_dev, inode.st_ino)
            and _read(receipt) == state and _read(directory / JOURNAL) == journal, "Private state changed before removal")
    require(shutil.rmtree.avoids_symlink_attacks, "Safe private-directory removal is unavailable on this Python")
    shutil.rmtree(directory)
    print("Installation removed. Its private state and audit data are removed; host images and unrelated installations are preserved.", flush=True)
    return {"removed": True, "already_absent": False, "mode": state["mode"], "host_images_preserved": True}
