#!/usr/bin/env python3
"""Set up, start or remove a saved Lotus installation.

Python 3.9+ and kubectl are required. Local setup also needs kind and a running
local Docker engine. A cold source build downloads pinned dependencies and can
take a substantial time. No provider credentials are requested by this script.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import signal
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts import bootstrap_kind, configure_local, deploy_kubernetes, prepare_release

STATE_NAME = "quickstart.json"
DEFAULT_STATE = Path.home() / ".local/share/lotus/installation"
LEGACY_STATE = ROOT / ".lotus-local/quickstart"
OWNER_KEY = "lotus.io/quickstart-owner"
STAGES = {"checking", "preparing-python", "preparing-image", "creating-cluster", "checking-network",
          "creating-config", "creating-resources", "waiting-controller", "ready", "failed"}


class SetupError(RuntimeError):
    pass


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private_path(value, *, must_exist=False):
    path = Path(value).expanduser().absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise SetupError("A setup path contains a symbolic link; select a direct private path")
    if must_exist and not path.is_file():
        raise SetupError("The selected private file does not exist")
    return path


def lifecycle_command(action, directory):
    command = "./lotus " + action
    if directory != DEFAULT_STATE:
        command += " --state " + shlex.quote(str(directory))
    return command


@contextmanager
def installation_lock(directory):
    """Serialize installation changes; exec releases the startup lock."""
    directory = private_path(directory)
    directory.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    lock = private_path(directory.parent / ("." + directory.name + ".lock"))
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        attributes = os.fstat(descriptor)
        if not stat.S_ISREG(attributes.st_mode) or attributes.st_uid != os.getuid() or attributes.st_mode & 0o077:
            raise SetupError("The installation lock is not a private regular file; it was preserved")
        os.set_inheritable(descriptor, False)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SetupError("Another Lotus setup or removal is running for this installation; wait for it to finish") from None
        yield
    finally:
        os.close(descriptor)


def run(argv, *, timeout=30, data=None, env=None):
    # Reuse the owned process-group timeout/cancellation contract. Raw tool
    # output is never printed or saved here: kubectl may include Secret values.
    return bootstrap_kind.command(argv, timeout=timeout, data=data, env=env)


def kube(args):
    result = ["kubectl", "--context", args.context, "--request-timeout=15s"]
    if args.kubeconfig:
        result += ["--kubeconfig", str(args.kubeconfig)]
    return result


def read(args, *parts):
    raw = run(kube(args) + ["get", *parts, "-o", "json"], timeout=25)
    if not raw.strip():
        return None
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        raise SetupError("Kubernetes returned an invalid bounded identity response") from None
    if not isinstance(value, dict):
        raise SetupError("Kubernetes returned a non-object identity response")
    return value


def cluster_id(args):
    value = read(args, "namespace", "kube-system")
    uid = (value or {}).get("metadata", {}).get("uid")
    if not isinstance(uid, str) or not uid:
        raise SetupError("The selected cluster identity could not be verified")
    return uid


def quantity(value):
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*(B|kB|KB|KiB|MB|MiB|GB|GiB|TB|TiB)\s*", value)
    if not match:
        raise SetupError("Docker memory usage has an unsupported format; inspect engine capacity")
    number, unit = match.groups()
    factors = {"B": 1, "kB": 1000, "KB": 1000, "KiB": 1024, "MB": 1000**2,
               "MiB": 1024**2, "GB": 1000**3, "GiB": 1024**3, "TB": 1000**4, "TiB": 1024**4}
    return int(float(number) * factors[unit])


def local_capacity(args):
    endpoint = os.environ.get("DOCKER_HOST") or json.loads(run(
        ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"], timeout=15))
    if not isinstance(endpoint, str) or not endpoint.startswith("unix://"):
        raise SetupError("Local setup requires a local Docker Unix socket; remote engines are preserved")
    env = {**os.environ, "DOCKER_HOST": endpoint, "KIND_EXPERIMENTAL_PROVIDER": "docker"}
    env.pop("DOCKER_CONTEXT", None)
    info = json.loads(run(["docker", "info", "--format", "{{json .}}"], timeout=20, env=env))
    if args.name in run(["kind", "get", "clusters"], timeout=15, env=env).split():
        raise SetupError("That Kind cluster already exists; choose another --name or use the recorded serve command")
    networks = run(["docker", "network", "ls", "--format", "{{.Name}}"], timeout=15, env=env).splitlines()
    if args.name in networks:
        raise SetupError("Docker network " + args.name + " already exists and was preserved. "
                         "Deleting a Kind cluster can leave its custom network behind. "
                         "Choose an unused --name and a fresh --state directory, or inspect and remove "
                         "the old network only after confirming it is no longer needed. "
                         "See README.md: Interrupted setup")
    memory, cpus = info.get("MemTotal"), info.get("NCPU")
    if type(memory) is not int or type(cpus) is not int:
        raise SetupError("Docker did not return usable memory/CPU capacity")
    usage = run(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}"], timeout=30, env=env)
    used = sum(quantity(line.split("/", 1)[0]) for line in usage.splitlines() if line.strip())
    required = (args.node_memory_gib + 1) * 1024**3
    if memory - used < required or cpus < args.node_cpus + 1:
        raise SetupError("Insufficient current Docker headroom for the new node plus 1 GiB / 1 CPU. "
                         f"Docker has {memory / 1024**3:.1f} GiB total, {used / 1024**3:.1f} GiB used by containers, "
                         f"{max(0, memory - used) / 1024**3:.1f} GiB available and {cpus} CPUs; "
                         f"setup needs {required / 1024**3:.1f} GiB available and {args.node_cpus + 1} CPUs. "
                         "On Docker Desktop open Settings > Resources, increase Memory/CPUs and Apply & restart, "
                         "or stop containers you no longer need. Existing containers were preserved; "
                         "retry ./lotus up --check after adjusting capacity")
    return {"docker_endpoint": endpoint, "memory_total_bytes": memory,
            "observed_container_memory_bytes": used, "required_free_bytes": required, "cpus": cpus}


def check(args):
    if sys.version_info < (3, 9):
        raise SetupError("Use Python 3.9 or newer (set LOTUS_PYTHON to its executable)")
    if os.name != "posix":
        raise SetupError("Use macOS or Linux with a local Unix socket, or a POSIX shell for the existing-cluster path")
    if args.context and (not args.context.strip() or args.context.startswith("-")):
        raise SetupError("Select an explicit nonempty Kubernetes context")
    if args.context and not args.image:
        raise SetupError("Existing Kubernetes requires --image REGISTRY/lotus@sha256:DIGEST; Docker is not used")
    if args.local_preloaded and not args.context:
        raise SetupError("--local-preloaded is only for an explicitly selected existing cluster")
    if args.kubeconfig and not args.context:
        raise SetupError("--kubeconfig requires --context; new Kind uses its own private kubeconfig")
    if not re.fullmatch(r"lotus-netpol-[a-z0-9][a-z0-9-]{0,35}[a-z0-9]", args.name):
        raise SetupError("Use --name lotus-netpol-NAME with lowercase DNS-label characters (maximum 50)")
    if not 6 <= args.node_memory_gib <= 64 or not 2 <= args.node_cpus <= 32:
        raise SetupError("New node capacity must be 6–64 GiB and 2–32 CPUs")
    args.state = private_path(args.state)
    if args.state.exists():
        raise SetupError("Setup state already exists and was preserved. Use " + lifecycle_command("serve", args.state)
                         + " for a completed install")
    args.port = args.port or 8000
    if args.kubeconfig:
        args.kubeconfig = private_path(args.kubeconfig, must_exist=True)
    try:
        configure_local.ensure_port_available(args.port)
    except OSError:
        raise SetupError("The selected local port is occupied; choose --port explicitly. Existing listeners were preserved") from None
    missing = [name for name in (["kubectl"] if args.context else ["kubectl", "kind", "docker"])
               if not shutil.which(name)]
    if missing:
        raise SetupError("Install " + ", ".join(missing) + " and place "
                         + ("it" if len(missing) == 1 else "them")
                         + " on PATH before setup. On macOS run ./lotus deps"
                         + (" --existing-context" if args.context else "")
                         + "; on Linux see README.md: Install dependencies. "
                         "This prerequisite check did not install anything")
    yaml_available = importlib.util.find_spec("yaml") is not None
    if not yaml_available and any(importlib.util.find_spec(name) is None for name in ("venv", "ensurepip")):
        raise SetupError("Python needs venv and ensurepip to install private setup dependencies. "
                         "On Ubuntu/Debian run: sudo apt-get install python3-venv. "
                         "For another Python version, install its matching venv package or set "
                         "LOTUS_PYTHON to a complete Python 3.9+ installation. See README.md: Install dependencies")
    result = {"schema_version": 1, "mode": "existing-kubernetes" if args.context else "owned-kind",
              "state_directory": str(args.state), "context": args.context or "kind-" + args.name,
              "image": args.image, "port": args.port, "read_only": True,
              "python_yaml": "available" if yaml_available else "will install pinned PyYAML in a private venv during up",
              "native_lab_readiness": "Every audit separately checks source, build registry, isolation and target startup",
              "ai_setup": "Open AI Setup in the UI and Save & Test the selected provider and model"}
    if args.context:
        result["cluster_uid"] = cluster_id(args)
        for name in ("lotus", "lotus-build"):
            if read(args, "namespace", name, "--ignore-not-found") is not None:
                raise SetupError("Namespace " + name + " already exists; quickstart will not overwrite an existing installation")
        result["registry_prerequisite"] = "Administrator must configure node-side HTTP registry trust for the registry Pod node IP on port 30500; quickstart does not modify existing nodes"
    else:
        result["capacity"] = local_capacity(args)
        if not args.image:
            inventory = prepare_release.inventory(ROOT)
            if inventory["blockers"]:
                raise SetupError("Curated source export has blockers; run scripts/prepare_release.py to inspect paths without exposing values")
            result["source_files"] = len(inventory["files"])
        result["registry_prerequisite"] = "Configured only on the fresh owned Kind node; no existing node or wildcard trust is changed"
    return result


def ensure_yaml(directory):
    if importlib.util.find_spec("yaml"):
        return sys.executable
    # Install only the existing hash-pinned dependency into a new private venv.
    # Neither global Python nor the full application dependency set is changed.
    lock = (ROOT / "backend/requirements.lock").read_text()
    match = re.search(r"(?m)^PyYAML==6\.0\.3[^\n]*\n(?:[ \t]+--hash=sha256:[a-f0-9]{64}[^\n]*\n)+", lock)
    if not match:
        raise SetupError("The pinned PyYAML stanza is unavailable; inspect backend/requirements.lock")
    requirement = directory / "yaml.requirements.lock"
    requirement.write_text(match.group())
    requirement.chmod(0o600)
    venv = directory / "python"
    run([sys.executable, "-m", "venv", str(venv)], timeout=120)
    executable = str(venv / "bin/python")
    run([executable, "-m", "pip", "--isolated", "install", "--disable-pip-version-check", "--no-input",
         "--no-cache-dir", "--require-hashes", "--only-binary=:all:", "--no-deps", "-r", str(requirement)], timeout=240)
    packages = venv / "lib" / ("python%d.%d" % sys.version_info[:2]) / "site-packages"
    sys.path.insert(0, str(packages))
    importlib.invalidate_caches()
    if not importlib.util.find_spec("yaml"):
        raise SetupError("Private PyYAML installation did not become available; use a supported Python with a published wheel")
    return executable


def save(state, directory):
    bootstrap_kind.save(directory / STATE_NAME, state)


def network_check(args, directory, python):
    owner = cluster_id(args)
    sources = {name: sha(ROOT / name) for name in bootstrap_kind.SOURCES}
    name = "lotus-netpol-" + uuid.uuid4().hex[:16]
    names = [name, name + "-sink"]
    output = directory / "network-policy.json"
    bootstrap_kind.save(directory / "network-attempt.json", {"cluster_uid": owner, "context": args.context,
                        "image": args.image, "namespaces": names})
    command = [python, str(ROOT / "k8s/verification/network_policy_preflight.py"), "--context", args.context,
               "--namespace", name, "--image", args.image, "--output", str(output), "--keep"]
    if args.kubeconfig:
        command += ["--kubeconfig", str(args.kubeconfig)]
    try:
        run(command, timeout=700)
    finally:
        report = json.loads(output.read_text()) if output.exists() else {}
        bootstrap_kind.cleanup_probes(kube(args), names, report, run=run)
    if (cluster_id(args) != owner or sources != {name: sha(ROOT / name) for name in sources}
            or not bootstrap_kind.traffic_passed(report)
            or report.get("context") != args.context or report.get("image") != args.image or report.get("namespaces") != names):
        raise SetupError("Actual network controls did not pass unchanged on the selected cluster")
    return {"cluster_uid": owner, "receipt_sha256": sha(output), "cleanup_verified": True}


def capture_kubeconfig(args):
    """Keep the selected user's existing config unchanged; snapshot one context."""
    if args.kubeconfig:
        return
    raw = run(kube(args) + ["config", "view", "--raw", "--flatten", "--minify", "-o", "json"], timeout=30)
    document = json.loads(raw)
    contexts = document.get("contexts", [])
    if (document.get("kind") != "Config" or len(contexts) != 1 or contexts[0].get("name") != args.context
            or len(document.get("clusters", [])) != 1 or len(document.get("users", [])) > 1):
        raise SetupError("The selected context could not be isolated into a private kubeconfig")
    path = args.state / "kubeconfig"
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as output:
        output.write(raw)
    args.kubeconfig = path


def identity(value):
    meta = value.get("metadata", {})
    if not isinstance(meta.get("uid"), str) or not meta["uid"]:
        raise SetupError("A created resource did not return an exact identity")
    return {"kind": value["kind"], "name": meta["name"], "namespace": meta.get("namespace"), "uid": meta["uid"]}


def same_resource(args, row, nonce):
    parts = [row["kind"], row["name"]]
    if row.get("namespace"):
        parts += ["-n", row["namespace"]]
    current = read(args, *parts)
    if (not current or identity(current) != row or current["metadata"].get("deletionTimestamp")
            or current["metadata"].get("labels", {}).get(OWNER_KEY) != nonce):
        raise SetupError("An owned resource was removed, replaced or changed; it was preserved")
    return current


def deploy(args, state, python):
    directory = args.state
    config = directory / "bootstrap.env"
    configure_local.create_config(config, args.port)
    if state["mode"] == "owned-kind":
        with config.open("a") as output:
            output.write("LOTUS_K8S_NETWORK_NODE_CONTROL_PORT=6443\n")
    state["config_sha256"] = sha(config)
    rendered = directory / "deployment.json"
    command = [python, str(ROOT / "scripts/deploy_kubernetes.py"), "--context", args.context,
               "--image", args.image, "--env-file", str(config), "--render-only", str(rendered)]
    if args.kubeconfig:
        command += ["--kubeconfig", str(args.kubeconfig)]
    if args.local_preloaded or state["mode"] == "owned-kind":
        command += ["--local-preloaded"]
    run(command, timeout=120)
    manifest = json.loads(rendered.read_text())
    for resource in manifest["items"]:
        resource.setdefault("metadata", {}).setdefault("labels", {})[OWNER_KEY] = state["nonce"]
        if resource.get("kind") == "Deployment":
            resource["spec"]["template"].setdefault("metadata", {}).setdefault("labels", {})[OWNER_KEY] = state["nonce"]
    namespaces = [row for row in manifest["items"] if row["kind"] == "Namespace"]
    if {row["metadata"]["name"] for row in namespaces} != {"lotus", "lotus-build"}:
        raise SetupError("Rendered namespaces differ from the reviewed quickstart scope")
    state.update(stage="creating-resources", resources=[])
    save(state, directory)
    # Exclusive create is essential: deploy_kubernetes's normal apply mode is
    # for administrators updating an installation, not this fresh installer.
    for namespace in namespaces:
        created = json.loads(run(kube(args) + ["create", "-f", "-", "-o", "json"],
                                 data=json.dumps(namespace), timeout=30))
        state["resources"].append(identity(created))
        save(state, directory)
    for row in state["resources"]:
        same_resource(args, row, state["nonce"])
    remaining = {"apiVersion": "v1", "kind": "List", "items": [row for row in manifest["items"] if row["kind"] != "Namespace"]}
    rows = deploy_kubernetes.parse_objects(run(kube(args) + ["create", "-f", "-", "-o", "json"], data=json.dumps(remaining), timeout=120))
    if not isinstance(rows, list) or len(rows) != len(remaining["items"]):
        raise SetupError("Resource creation returned incomplete identities; preserve this state for inspection")
    state["resources"].extend(identity(row) for row in rows)
    state["secret_sha256"] = hashlib.sha256(json.dumps(next(row for row in remaining["items"] if row.get("kind") == "Secret"
        and row["metadata"]["name"] == "lotus-bootstrap").get("data", {}), sort_keys=True).encode()).hexdigest()
    state["stage"] = "waiting-controller"
    save(state, directory)
    run(kube(args) + ["rollout", "status", "deployment/lotus", "-n", "lotus", "--timeout=600s"], timeout=620)
    return verify_install(args, state)


def verify_install(args, state):
    if cluster_id(args) != state["cluster_uid"]:
        raise SetupError("The selected cluster was replaced; existing resources were preserved")
    if sha(args.state / "bootstrap.env") != state["config_sha256"]:
        raise SetupError("Private bootstrap values changed; they were not overwritten")
    if args.kubeconfig and sha(args.kubeconfig) != state.get("kubeconfig_sha256"):
        raise SetupError("The recorded kubeconfig changed; select and review the intended installation")
    required = {"Namespace": {"lotus", "lotus-build"}, "Deployment": {"lotus"},
                "Secret": {"lotus-bootstrap"}, "PersistentVolumeClaim": {"lotus-data"}, "Service": {"lotus"}}
    found = {kind: set() for kind in required}
    for row in state["resources"]:
        if row["kind"] in required and row["name"] in required[row["kind"]]:
            current = same_resource(args, row, state["nonce"])
            found[row["kind"]].add(row["name"])
            if row["kind"] == "Deployment":
                deployment_uid = row["uid"]
                containers = current["spec"]["template"]["spec"]["containers"]
                app = [item for item in containers if item.get("name") == "lotus"]
                if len(app) != 1 or app[0].get("image") != state["image"]:
                    raise SetupError("The application image differs from this installation; no deployment was changed")
            if row["kind"] == "Secret" and hashlib.sha256(json.dumps(current.get("data", {}), sort_keys=True).encode()).hexdigest() != state.get("secret_sha256"):
                raise SetupError("The installed bootstrap Secret changed; existing credentials were preserved")
    if found != required:
        raise SetupError("The install receipt lacks required resource identities; automatic resume is unavailable")
    listing = read(args, "pods", "-n", "lotus", "-l", "app=lotus")
    pods = [row for row in listing.get("items", []) if not row.get("metadata", {}).get("deletionTimestamp")
            and row.get("status", {}).get("phase") == "Running"
            and row.get("metadata", {}).get("labels", {}).get(OWNER_KEY) == state["nonce"]
            and any(c.get("type") == "Ready" and c.get("status") == "True" for c in row.get("status", {}).get("conditions", []))]
    if len(pods) != 1:
        raise SetupError("Exactly one ready Lotus controller is required; inspect the selected deployment")
    pod = identity(pods[0])
    app = [row for row in pods[0].get("spec", {}).get("containers", []) if row.get("name") == "lotus"]
    if len(app) != 1 or app[0].get("image") != state["image"]:
        raise SetupError("The ready Pod is not running the recorded immutable application image")
    owners = [row for row in pods[0]["metadata"].get("ownerReferences", []) if row.get("controller") is True and row.get("kind") == "ReplicaSet"]
    if len(owners) != 1:
        raise SetupError("The controller Pod lacks its exact ReplicaSet owner")
    replica = read(args, "replicaset", owners[0]["name"], "-n", "lotus")
    if (replica["metadata"].get("uid") != owners[0].get("uid") or not any(row.get("controller") is True
            and row.get("kind") == "Deployment" and row.get("uid") == deployment_uid
            for row in replica["metadata"].get("ownerReferences", []))):
        raise SetupError("The ready Pod does not belong to the recorded Lotus Deployment")
    for path in ("healthz", "readyz"):
        value = json.loads(run(kube(args) + ["get", "--raw=/api/v1/namespaces/lotus/pods/" + pod["name"] + ":8000/proxy/" + path], timeout=30))
        if path == "healthz" and (value.get("status") != "ok" or value.get("service") != "lotus"):
            raise SetupError("The controller health endpoint did not identify Lotus")
        if path == "readyz" and (value.get("status") != "ready" or value.get("checks", {}).get("database") is not True
                                 or value.get("checks", {}).get("lab_provider") is not True):
            raise SetupError("The controller database/provider readiness checks have not passed")
    after = read(args, "pod", pod["name"], "-n", "lotus")
    if identity(after) != pod or after["metadata"].get("deletionTimestamp"):
        raise SetupError("Controller identity changed during readiness checks; retry the recorded serve command")
    return {"pod": pod, "health": True, "provider_control_plane": True,
            "target_runtime": "Not yet tested; each audit performs fresh build, source and isolation admission"}


def serve(args, state):
    verify_install(args, state)
    configure_local.ensure_port_available(args.port)
    print("Open http://127.0.0.1:%d — configure AI Setup, then Save & Test. Ctrl-C closes only this tunnel." % args.port, flush=True)
    command = [sys.executable, str(ROOT / "scripts/serve_kubernetes.py"), "--context", args.context, "--port", str(args.port),
               "--installation-state", str(args.state), "--installation-nonce", state["nonce"]]
    if args.kubeconfig:
        command += ["--kubeconfig", str(args.kubeconfig)]
    # The foreground helper owns its port-forward child and handles SIGTERM /
    # Ctrl-C with bounded drain. exec avoids a second process owner or PID file.
    os.execv(sys.executable, command)


def up(args):
    args.state = private_path(args.state)
    if args.state.exists():
        state = load_install(args)
        if args.check or args.no_serve:
            readiness = verify_install(args, state)
            summary = {"installed": True, "read_only": True, "context": args.context,
                       "port": args.port, "ready": True, "readiness": readiness}
            print(json.dumps(summary, indent=2), flush=True)
            if not args.check:
                print("Start Lotus: " + lifecycle_command("serve", args.state), flush=True)
            return summary
        print("Using the installed Lotus configuration…", flush=True)
        return serve(args, state)
    summary = check(args)
    if args.check:
        print(json.dumps(summary, indent=2), flush=True)
        return summary
    print("Setting up Lotus…", flush=True)
    args.state.mkdir(parents=True, mode=0o700, exist_ok=False)
    state = {"schema_version": 1, "nonce": uuid.uuid4().hex, "mode": summary["mode"], "stage": "preparing-python",
             "directory": str(args.state), "context": args.context, "image": args.image, "port": args.port, "ready": False}
    save(state, args.state)
    try:
        print("Preparing private setup dependencies…", flush=True)
        python = ensure_yaml(args.state)
        if not args.context:
            from scripts import quickstart_image
            state["stage"] = "preparing-image"; save(state, args.state)
            print("Preparing the application image; a cold source build can take substantial time…", flush=True)
            image_record = quickstart_image.prepare_image(ROOT, args.state / "image", image=args.image)
            local_capacity(args)  # A long image build cannot reserve old headroom.
            state["stage"] = "creating-cluster"; save(state, args.state)
            plan = bootstrap_kind.plan(args.name, args.state / "cluster", None, args.node_memory_gib,
                                       args.node_cpus, deferred_probe=True)
            def prepare(value):
                return quickstart_image.prepare_node(image_record, value)
            created = bootstrap_kind.create(plan, prepare_probe=prepare, python_executable=python)
            args.context, args.kubeconfig, args.image = created["context"], Path(created["kubeconfig"]), created["probe_image"]
            state["network"] = {"receipt_sha256": created["network_receipt_sha256"], "cleanup_verified": created["probe_cleanup_verified"]}
            state["owned_cluster"] = {"cluster": created["cluster"], "directory": created["directory"],
                                      "identity": created["cluster_identity"], "image_preparation": created["image_preparation"]}
        else:
            capture_kubeconfig(args)
            state.update(context=args.context, kubeconfig=str(args.kubeconfig) if args.kubeconfig else None,
                         kubeconfig_sha256=sha(args.kubeconfig) if args.kubeconfig else None,
                         cluster_uid=cluster_id(args), stage="checking-network")
            save(state, args.state)
            print("Checking actual network enforcement in temporary owned namespaces…", flush=True)
            state["network"] = network_check(args, args.state, python)
        state.update(context=args.context, image=args.image, kubeconfig=str(args.kubeconfig) if args.kubeconfig else None,
                     kubeconfig_sha256=sha(args.kubeconfig) if args.kubeconfig else None,
                     cluster_uid=cluster_id(args), stage="creating-config")
        save(state, args.state)
        print("Creating private configuration and a new Lotus installation…", flush=True)
        state["readiness"] = deploy(args, state, python)
        state.update(stage="ready", ready=True)
        save(state, args.state)
    except BaseException as error:
        state.update(failed_stage=state["stage"], stage="failed", ready=False, failure_type=type(error).__name__,
                     recovery="Preserve this directory and owned resources for inspection. Setup never deletes uncertain infrastructure or retries over it.")
        save(state, args.state)
        raise
    print("Controller and network checks passed. Native target builds and startup are checked for each audit.", flush=True)
    print("Setup complete. Start Lotus: " + lifecycle_command("serve", args.state), flush=True)
    return state


def load_install(args):
    args.state = private_path(args.state)
    if not (args.state / STATE_NAME).exists():
        raise SetupError("No completed Lotus installation was found. Run " + lifecycle_command("up", args.state)
                         + ("; if setup was interrupted, inspect it or run " + lifecycle_command("down", args.state)
                            if args.state.exists() else ""))
    path = private_path(args.state / STATE_NAME, must_exist=True)
    if path.stat().st_size > 256 * 1024 or path.stat().st_mode & 0o077:
        raise SetupError("Setup receipt is oversized or not private; it was preserved")
    state = json.loads(path.read_text())
    if (state.get("schema_version") != 1 or state.get("ready") is not True or state.get("stage") != "ready"
            or state.get("directory") != str(args.state) or not re.fullmatch(r"[a-f0-9]{32}", state.get("nonce", ""))):
        raise SetupError("Only a completed installation can start. Setup is incomplete; inspect its logs or run "
                         + lifecycle_command("down", args.state) + " before setting up again")
    for option in ("context", "image"):
        if getattr(args, option, None) and getattr(args, option) != state.get(option):
            raise SetupError("The supplied " + option + " differs from the saved installation; use its saved configuration or a separate --state directory")
    if getattr(args, "kubeconfig", None) and private_path(args.kubeconfig) != Path(state.get("kubeconfig") or ""):
        raise SetupError("The supplied kubeconfig differs from the saved installation")
    if getattr(args, "name", "lotus-netpol-local") != "lotus-netpol-local" and state.get("context") != "kind-" + args.name:
        raise SetupError("The supplied cluster name differs from the saved installation; use a separate --state directory")
    args.context, args.image = state["context"], deploy_kubernetes.validate_image(state["image"])
    args.kubeconfig = Path(state["kubeconfig"]) if state.get("kubeconfig") else None
    args.port = configure_local.validate_port(args.port or state["port"])
    return state


def resume(args):
    return serve(args, load_install(args))


def parser():
    result = argparse.ArgumentParser(prog="./lotus", description=__doc__)
    sub = result.add_subparsers(dest="action")
    install = sub.add_parser("up", help="set up Lotus, or start it using the saved installation")
    install.add_argument("--check", action="store_true", help="read-only prerequisite and capacity check; no installs, builds or resources")
    install.add_argument("--context", help="explicit existing Kubernetes context; requires immutable --image and never uses Docker")
    install.add_argument("--kubeconfig", type=Path)
    install.add_argument("--image", type=deploy_kubernetes.validate_image, help="prebuilt immutable Lotus image; required for existing Kubernetes")
    install.add_argument("--local-preloaded", action="store_true", help="existing cluster only: require application image already present, with pull policy Never")
    install.add_argument("--state", type=Path, help="advanced: override the shared private installation directory")
    install.add_argument("--name", default="lotus-netpol-local", help="fresh local cluster name (default lotus-netpol-local)")
    install.add_argument("--node-memory-gib", type=int, default=6)
    install.add_argument("--node-cpus", type=int, default=3)
    install.add_argument("--port", type=configure_local.validate_port, help="local UI port (default 8000 for a new installation, saved port otherwise)")
    install.add_argument("--no-serve", action="store_true", help="check readiness without opening the UI connection on an existing installation")
    reopen = sub.add_parser("serve", help="start the local UI connection using the saved Lotus installation")
    reopen.add_argument("--state", type=Path, help="advanced: select an older or custom installation")
    reopen.add_argument("--port", type=configure_local.validate_port)
    remove = sub.add_parser("down", help="remove this Lotus installation and its audit data; preserve unrelated resources")
    remove.add_argument("--state", type=Path, help="advanced: remove only the installation at this location")
    return result


def main(argv=None):
    argument_parser = parser()
    args = argument_parser.parse_args(argv)
    if not args.action:
        argument_parser.print_help()
        return 0
    def interrupt(_number, _frame):
        raise KeyboardInterrupt()
    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        # Checkouts share one installation. Keep old checkout-local receipts
        # usable in place: their absolute paths are part of cleanup ownership.
        default_locations = [DEFAULT_STATE, LEGACY_STATE]
        if args.state is None:
            locations = [path for path in default_locations if path.exists() or path.is_symlink()]
            if args.action == "down":
                from scripts import installation_cleanup
                for directory in locations or [DEFAULT_STATE]:
                    if directory.exists() or directory.is_symlink():
                        with installation_lock(directory):
                            installation_cleanup.down(argparse.Namespace(state=directory))
                    else:
                        installation_cleanup.down(argparse.Namespace(state=directory))
                return 0
            if len(locations) > 1:
                raise SetupError("Both shared and older checkout-local installations exist. Run ./lotus down before setting up Lotus again")
            args.state = locations[0] if locations else DEFAULT_STATE
        def dispatch():
            if args.action == "up":
                return up(args)
            if args.action == "serve":
                return resume(args)
            from scripts import installation_cleanup
            return installation_cleanup.down(args)
        if args.action == "up" and args.check:
            dispatch()  # Read-only checks must not create even a lock directory.
        elif not private_path(args.state).exists() and args.action in {"serve", "down"}:
            dispatch()
        else:
            with installation_lock(args.state):
                dispatch()
        return 0
    except KeyboardInterrupt:
        print("Lotus " + args.action + " interrupted. Owned command processes stopped; installation records were kept for retry.", file=sys.stderr)
        return 130
    except (SetupError, ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        # Only our fixed messages are shown. Unexpected/parser/provider output
        # is not safe to echo because it may contain bootstrap Secret values.
        message = str(error) if isinstance(error, (SetupError, RuntimeError)) else type(error).__name__
        print("Lotus " + args.action + " stopped: " + message, file=sys.stderr)
        return 1
    except Exception as error:
        print("Lotus " + args.action + " stopped: invalid setup metadata (" + type(error).__name__ +
              "). Existing resources and private state were preserved for inspection.", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
