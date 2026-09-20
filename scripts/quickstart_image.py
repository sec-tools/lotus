"""Prepare an application image for one freshly created, identity-pinned Kind node.

This module is never used for an existing Kubernetes context. Docker operations
use a pinned local Unix socket. No global image/cache cleanup or node restart is
performed. Failed partial imports/configuration remain recorded for inspection.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import uuid

from scripts import bootstrap_kind, prepare_release

DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
IMAGE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}")
FULL_ID = re.compile(r"[a-f0-9]{64}")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def path(value):
    value = Path(value).expanduser().absolute()
    require(not any(p.is_symlink() for p in (value, *value.parents)),
            "Image setup paths must not contain symbolic links")
    return value


def call(run, argv, *, timeout=30, env=None, data=None):
    try:
        result = run(argv, timeout=timeout, env=env, data=data)
    except Exception:
        raise RuntimeError("Image setup prerequisite command failed; inspect the recorded stage") from None
    raw = result.encode() if isinstance(result, str) else result
    require(isinstance(raw, bytes) and len(raw) <= 2 * 1024**2,
            "Image setup command returned an invalid or oversized response")
    return raw


def parsed(raw):
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise RuntimeError("Image setup returned malformed identity metadata") from None


def save(directory, value):
    bootstrap_kind.save(directory / "image.json", value)


def environment(endpoint):
    require(isinstance(endpoint, str) and endpoint.startswith("unix://") and len(endpoint) <= 4096,
            "Image setup requires a local Docker Unix socket")
    env = dict(os.environ, DOCKER_HOST=endpoint, KIND_EXPERIMENTAL_PROVIDER="docker")
    env.pop("DOCKER_CONTEXT", None)
    return env


def inspect_image(run, ref, env):
    value = parsed(call(run, ["docker", "image", "inspect", ref, "--format", "{{json .}}"], env=env))
    require(isinstance(value, dict) and DIGEST.fullmatch(value.get("Id", "")) is not None,
            "Docker did not return an immutable image identity")
    require(value.get("Os") == "linux" and value.get("Architecture") in {"amd64", "arm64"},
            "Quickstart images must target Linux amd64 or arm64")
    layers = value.get("RootFS", {}).get("Layers")
    require(isinstance(layers, list) and all(isinstance(x, str) and DIGEST.fullmatch(x) for x in layers),
            "Docker did not return valid image layers")
    return value


def image_identity(value):
    return {"image_id": value["Id"], "config_sha256": sha(canonical(value["Config"])),
            "layers": value["RootFS"]["Layers"], "os": value["Os"], "architecture": value["Architecture"]}


def verify_export(export, manifest):
    expected = {row["path"]: row for row in manifest["files"]}
    actual = {str(p.relative_to(export)) for p in export.rglob("*") if p.is_file()}
    require(actual == set(expected) | {"SOURCE_MANIFEST.json"}, "Curated image context membership changed")
    for name, row in expected.items():
        p = path(export / name)
        require(p.is_file() and p.stat().st_size == row["bytes"] and sha(p.read_bytes()) == row["sha256"]
                and p.stat().st_mode & 0o777 == row["mode"], "Curated image context changed during setup")
    require(parsed((export / "SOURCE_MANIFEST.json").read_bytes()) == manifest,
            "Curated image manifest changed during setup")


def prepare_image(root, state_dir, image=None, *, run=bootstrap_kind.command):
    """Build only prepare_release's curated files, or pull one explicit digest."""
    require(image is None or isinstance(image, str) and IMAGE.fullmatch(image),
            "An explicit application image must include its immutable repository digest")
    root, directory = path(root), path(state_dir)
    require(not directory.exists(), "Image setup state already exists and was preserved")
    if directory == root or root in directory.parents:
        require(directory != root and directory.relative_to(root).parts[0] in prepare_release.EXCLUDED_PARTS,
                "Private image state must remain outside curated source directories")
    directory.mkdir(parents=True, mode=0o700)
    record = {"schema_version": 1, "state": "checking-engine", "passed": False,
              "directory": str(directory), "helper_sha256": sha(Path(__file__).read_bytes()),
              "started_at": time.time(), "source_export": None, "supplied_image": image}
    save(directory, record)
    try:
        endpoint = os.environ.get("DOCKER_HOST") or parsed(call(run,
            ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"], timeout=15))
        env = environment(endpoint)
        engine = parsed(call(run, ["docker", "info", "--format", "{{json .ID}}"], env=env))
        require(isinstance(engine, str) and 1 <= len(engine) <= 128, "Docker engine identity is unavailable")
        record.update(docker_endpoint=endpoint, docker_engine_id=engine)
        manifest = None
        if image is None:
            record["state"] = "exporting-source"; save(directory, record)
            manifest = prepare_release.inventory(root)
            require(not manifest["blockers"] and not manifest["issues"],
                    "Curated source export has blockers; inspect prepare_release before setup")
            export = directory / "source"
            prepare_release.export_sources(root, export, manifest)
            verify_export(export, manifest)
            tag = "lotus-quickstart:" + uuid.uuid4().hex
            record.update(state="building-image", source_export=str(export),
                          source_manifest_sha256=sha((export / "SOURCE_MANIFEST.json").read_bytes()), transport_ref=tag)
            save(directory, record)
            call(run, ["docker", "build", "--quiet", "--iidfile", str(directory / "image.id"),
                       "--tag", tag, str(export)], timeout=3600, env=env)
            value = inspect_image(run, tag, env)
            require((directory / "image.id").read_text().strip() == value["Id"], "Built image identity changed")
            verify_export(export, manifest)
        else:
            record.update(state="pulling-image"); save(directory, record)
            call(run, ["docker", "pull", "--quiet", image], timeout=1200, env=env)
            value = inspect_image(run, image, env)
            require(repository(image) in {repository(x) for x in value.get("RepoDigests", [])},
                    "Pulled image is not bound to the requested immutable digest")
            tag = "lotus-quickstart:" + uuid.uuid4().hex
            call(run, ["docker", "image", "tag", value["Id"], tag], env=env)
            require(image_identity(inspect_image(run, tag, env)) == image_identity(value),
                    "The prepared local image alias changed")
            record["transport_ref"] = tag
        require(parsed(call(run, ["docker", "info", "--format", "{{json .ID}}"], env=env)) == engine,
                "Docker engine changed during image preparation")
        record.update(image_identity(value), state="image-prepared", passed=True, finished_at=time.time())
        save(directory, record)
        return record
    except BaseException:
        record.update(passed=False, state="failed", failed_stage=record["state"], finished_at=time.time())
        save(directory, record)
        raise


def repository(ref):
    """Normalize Docker's default registry/library spelling without changing a digest."""
    head, separator, digest = ref.partition("@")
    if separator and ":" in head.rsplit("/", 1)[-1]:
        head = head.rsplit(":", 1)[0]
    first = head.split("/", 1)[0]
    if "/" not in head or not ("." in first or ":" in first or first == "localhost"):
        head = "docker.io/" + head
    if head.startswith("docker.io/") and head.count("/") == 1:
        head = "docker.io/library/" + head[len("docker.io/"):]
    return head + (separator + digest if separator else "")


def _leaders_exited(processes):
    # WNOWAIT retains the leader PID, so its process-group ID cannot be reused
    # before descendant cleanup. Darwin Python lacks waitid; ps observes the
    # same unreaped zombie state without consuming its exit status.
    if hasattr(os, "waitid"):
        return all(os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                   is not None for p in processes)
    value = subprocess.run(["ps", "-o", "pid=,stat=", "-p", ",".join(str(p.pid) for p in processes)],
                           capture_output=True, check=True, timeout=3)
    states = {int(parts[0]): parts[1] for line in value.stdout.decode().splitlines()
              if len(parts := line.split()) == 2}
    require(set(states) == {p.pid for p in processes}, "Image stream leader identity is unavailable")
    return all(state.startswith("Z") for state in states.values())


def _process_states():
    if Path("/proc/self/stat").exists():
        rows = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit(): continue
            try: raw = (entry / "stat").read_text()
            except (FileNotFoundError, ProcessLookupError): continue
            fields = raw[raw.rfind(")") + 2:].split()
            require(len(fields) >= 3, "Local process identity could not be read")
            rows.append((int(entry.name), int(fields[2]), fields[0]))
        return rows
    result = subprocess.run(["ps", "-axo", "pid=,pgid=,stat="], capture_output=True, check=True, timeout=3)
    return [(int(p[0]), int(p[1]), p[2]) for line in result.stdout.decode().splitlines()
            if len(p := line.split()) == 3]


def _drain_groups(processes):
    # Always address both groups, including an exited, unreaped leader that
    # left a child. Never use poll()/wait() until group drain has been checked.
    for process in processes:
        try: os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError): pass
    deadline = time.monotonic() + 5
    while processes:
        groups = {p.pid for p in processes}
        live = any(pgid in groups and not state.startswith("Z") for _, pgid, state in _process_states())
        if not live: break
        require(time.monotonic() < deadline, "Image stream local process cleanup remains unconfirmed")
        time.sleep(.1)
    for process in processes:
        process.wait(timeout=3)


def stream_image(source, destination, *, env, timeout=600):
    """Backpressure-bound stream with owned local process-group drain."""
    processes = []
    with tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as output:
        try:
            producer = subprocess.Popen(source, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=errors, env=env, start_new_session=True)
            processes.append(producer)
            consumer = subprocess.Popen(destination, stdin=producer.stdout, stdout=output,
                                        stderr=errors, env=env, start_new_session=True)
            processes.append(consumer); producer.stdout.close()
            deadline = time.monotonic() + timeout
            while not _leaders_exited(processes):
                require(time.monotonic() < deadline, "Image import stream exceeded its deadline")
                time.sleep(.1)
        finally:
            try: _drain_groups(processes)
            finally:
                if processes and processes[0].stdout is not None: processes[0].stdout.close()
        require(all(p.returncode == 0 for p in processes), "Image import stream failed")


def registry_configured(raw):
    # Read only the configured CRI image registry table. A similarly named
    # setting in another plugin cannot authorize the hosts.toml write.
    accepted = {"plugins.io.containerd.grpc.v1.cri.registry", "plugins.io.containerd.cri.v1.images.registry"}
    table = None; found = []
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            table = line[1:-1].replace('"', '').replace("'", '')
        elif table in accepted:
            match = re.fullmatch(r"config_path\s*=\s*['\"]([^'\"]*)['\"]", line)
            if match: found.append(match[1])
    return found == ["/etc/containerd/certs.d"]


def prepare_node(record, bootstrap_value, *, run=bootstrap_kind.command, stream=stream_image):
    """Import and add exact NodeIP:30500 trust only for this fresh bootstrap."""
    value = bootstrap_value
    require(value.get("created_by_this_run") is True and value.get("state") == "checking-network"
            and value.get("existing_clusters_modified") is False,
            "Node image preparation requires this invocation's fresh Kind cluster")
    directory = path(record["directory"])
    require(record.get("passed") is True and record.get("state") == "image-prepared"
            and parsed((directory / "image.json").read_bytes()) == record,
            "Prepared image receipt is missing or changed")
    bootstrap_dir = path(value["directory"]); kubeconfig = path(value["kubeconfig"])
    ownership_path = bootstrap_dir / "ownership.json"
    ownership_raw = ownership_path.read_bytes(); ownership = parsed(ownership_raw)
    cluster = value["cluster"]; name = cluster + "-control-plane"
    require(re.fullmatch(r"lotus-netpol-[a-z0-9][a-z0-9-]{0,35}[a-z0-9]", cluster)
            and value["context"] == "kind-" + cluster and kubeconfig == bootstrap_dir / "kubeconfig",
            "Fresh cluster names or private kubeconfig do not match")
    require(all(ownership.get(k) == v for k, v in {"cluster": cluster, "context": value["context"],
            "kubeconfig": str(kubeconfig), "node": name, "docker_network": cluster,
            "state": "capacity-aligned", "existing_clusters_modified": False}.items()),
            "Fresh cluster ownership receipt does not match")
    require(record["docker_endpoint"] == value.get("docker_endpoint"), "Docker endpoint changed between setup phases")
    env = environment(record["docker_endpoint"])
    kube = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", value["context"], "--request-timeout=10s"]
    receipt = {"schema_version": 1, "passed": False, "state": "checking-node", "started_at": time.time(),
               "image_receipt_sha256": sha((directory / "image.json").read_bytes()),
               "ownership_sha256": sha(ownership_raw), "cluster_identity": value["cluster_identity"]}
    destination = directory / "node-image.json"
    require(not destination.exists(), "Node image preparation already has a receipt; inspect its existing state")
    bootstrap_kind.save(destination, receipt)

    def observe(full_id=None):
        require(path(kubeconfig) == kubeconfig and sha(kubeconfig.read_bytes()) == value["cluster_identity"]["kubeconfig_sha256"]
                and path(ownership_path).read_bytes() == ownership_raw, "Fresh node ownership files changed")
        require(parsed(call(run, ["docker", "info", "--format", "{{json .ID}}"], env=env)) == record["docker_engine_id"],
                "Docker engine identity changed")
        current = bootstrap_kind.cluster_identity(value, kube,
            run=lambda argv, **kw: call(run, argv, **kw).decode(), env=env)
        require(current == value["cluster_identity"], "Kubernetes node identity changed")
        docker = parsed(call(run, ["docker", "inspect", full_id or name, "--format", "{{json .}}"], env=env))
        labels = docker.get("Config", {}).get("Labels", {})
        require(FULL_ID.fullmatch(docker.get("Id", "")) and (full_id is None or docker["Id"] == full_id)
                and docker.get("Name") == "/" + name and docker.get("State", {}).get("Running") is True
                and labels.get("io.x-k8s.kind.cluster") == cluster and labels.get("io.x-k8s.kind.role") == "control-plane",
                "Docker node identity or ownership changed")
        node = parsed(call(run, kube + ["get", "node", name, "-o", "json"], env=env))
        ips = [a["address"] for a in node.get("status", {}).get("addresses", []) if a.get("type") == "InternalIP"]
        require(node.get("metadata", {}).get("uid") == current["node_uid"] and len(ips) == 1,
                "The owned node must have one observed InternalIP")
        require(node.get("status", {}).get("nodeInfo", {}).get("architecture") == record["architecture"],
                "Prepared application image architecture differs from the new node")
        try: address = ipaddress.IPv4Address(ips[0])
        except ipaddress.AddressValueError: raise RuntimeError("Fresh Kind requires an IPv4 node address") from None
        network = docker.get("NetworkSettings", {}).get("Networks", {}).get(cluster, {})
        require(not address.is_loopback and not address.is_unspecified and network.get("IPAddress") == str(address)
                and FULL_ID.fullmatch(network.get("NetworkID", "")), "Node address does not match its owned Docker network")
        return {"docker_id": docker["Id"], "node_uid": current["node_uid"], "node_ip": str(address),
                "network_id": network["NetworkID"]}

    try:
        owner = observe(); receipt["node"] = owner
        node_id = owner["docker_id"]
        def attest():
            require(observe(node_id) == owner, "Fresh node identity changed around a write")
            require(image_identity(inspect_image(run, record["transport_ref"], env)) ==
                    {k: record[k] for k in ("image_id", "config_sha256", "layers", "os", "architecture")},
                    "Prepared Docker image changed before node import")
            require(sha((directory / "image.json").read_bytes()) == receipt["image_receipt_sha256"],
                    "Prepared image receipt changed")
        def execute(args, **kwargs):
            return call(run, ["docker", "exec", node_id, *args], env=env, **kwargs)
        config = execute(["cat", "/etc/containerd/config.toml"])
        require(registry_configured(config),
                "Fresh node containerd registry configuration is unsupported; no daemon changes were made")
        attest(); receipt["state"] = "importing"; bootstrap_kind.save(destination, receipt)
        stream(["docker", "image", "save", record["transport_ref"]],
               ["docker", "exec", "-i", node_id, "ctr", "-n", "k8s.io", "images", "import", "--all-platforms", "--digests", "-"],
               env=env, timeout=600)
        attest()
        source = repository(record["transport_ref"])
        def listing(ref):
            rows = [line.split() for line in execute(["ctr", "-n", "k8s.io", "images", "list"]).decode().splitlines()
                    if line.split() and line.split()[0] == ref]
            require(len(rows) == 1 and len(rows[0]) >= 3 and DIGEST.fullmatch(rows[0][2]),
                    "Imported image reference is missing or ambiguous")
            return rows[0][2]
        target = listing(source)
        def content(digest):
            require(isinstance(digest, str) and DIGEST.fullmatch(digest), "Imported OCI descriptor is invalid")
            raw = execute(["ctr", "-n", "k8s.io", "content", "get", digest])
            require("sha256:" + sha(raw) == digest, "Imported OCI content digest does not match")
            return parsed(raw)
        top = content(target)
        if "manifests" in top:
            platforms = [p for p in top["manifests"] if p.get("platform", {}).get("os") == record["os"]
                         and p.get("platform", {}).get("architecture") == record["architecture"]]
            require(len(platforms) == 1, "Imported image has an ambiguous platform")
            manifest_digest = platforms[0]["digest"]; manifest = content(manifest_digest)
        else:
            manifest_digest, manifest = target, top
        config_digest = manifest["config"]["digest"]; config = content(config_digest)
        require(config.get("os") == record["os"] and config.get("architecture") == record["architecture"]
                and sha(canonical(config.get("config"))) == record["config_sha256"]
                and config.get("rootfs", {}).get("diff_ids") == record["layers"],
                "Imported image configuration or layers do not match the prepared image")
        immutable = source.split("@", 1)[0]
        if ":" in immutable.rsplit("/", 1)[-1]: immutable = immutable.rsplit(":", 1)[0]
        immutable += "@" + target
        if immutable != source:
            attest(); execute(["ctr", "-n", "k8s.io", "images", "tag", source, immutable]); attest()
        require(listing(immutable) == target, "Immutable node image alias changed")
        receipt["state"] = "preparing-registry"; bootstrap_kind.save(destination, receipt)
        # Fresh Kind configures this path but may not create it. Create only
        # the expected directory after checking its parents; never follow links.
        attest()
        execute(["sh", "-ceu", 'for p in /etc /etc/containerd; do test -d "$p"; test ! -L "$p"; done; '
                 'd=/etc/containerd/certs.d; test ! -L "$d"; '
                 'if ! test -e "$d"; then mkdir -m 0755 "$d"; fi; test -d "$d"; test ! -L "$d"'])
        attest()
        authority = owner["node_ip"] + ":30500"
        hosts = 'server = "http://' + authority + '"\n[host."http://' + authority + '"]\n  capabilities = ["pull", "resolve"]\n'
        # Fixed script; the only interpolated shell positional argument is a
        # validated IPv4:30500 authority. Never mutate default/wildcard trust.
        prefix = 'for p in /etc /etc/containerd /etc/containerd/certs.d; do test -d "$p"; test ! -L "$p"; done; d=/etc/containerd/certs.d/$1; test ! -L "$d"; '
        old = execute(["sh", "-ceu", prefix + 'if test -e "$d"; then test -d "$d"; test ! -L "$d/hosts.toml"; test -f "$d/hosts.toml"; cat "$d/hosts.toml"; else printf ABSENT; fi', "sh", authority])
        require(old in (b"ABSENT", hosts.encode()), "Existing registry trust differs and was preserved")
        receipt.update(state="configuring-registry", registry_authority=authority, registry_preexisting=old != b"ABSENT")
        bootstrap_kind.save(destination, receipt)
        if old == b"ABSENT":
            attest()
            call(run, ["docker", "exec", "-i", node_id, "sh", "-ceu", prefix +
                       'umask 077; mkdir "$d"; set -C; cat > "$d/hosts.toml"', "sh", authority], env=env, data=hosts)
            attest()
        require(execute(["sh", "-ceu", prefix + 'test -d "$d"; test ! -L "$d/hosts.toml"; test -f "$d/hosts.toml"; cat "$d/hosts.toml"', "sh", authority]) == hosts.encode(),
                "Registry trust readback did not match the exact node authority")
        attest()
        receipt.update(passed=True, state="node-image-prepared", image=immutable, imported_digest=target,
                       platform_manifest=manifest_digest, config_digest=config_digest, no_host_archive=True,
                       registry_hosts_sha256=sha(hosts.encode()), finished_at=time.time())
        bootstrap_kind.save(destination, receipt)
        return receipt
    except BaseException:
        receipt.update(passed=False, failed_stage=receipt["state"], state="failed-preserved", finished_at=time.time(),
                       limitation="Partial imported images or exact-node trust may remain; no cleanup or readiness is implied")
        bootstrap_kind.save(destination, receipt)
        raise
