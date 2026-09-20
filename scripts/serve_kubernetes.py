#!/usr/bin/env python3
"""Keep the local Lotus UI connected across Kubernetes controller replacements."""
import argparse
import http.client
import json
import os
import re
import signal
import socket
import stat
import subprocess
import threading
import time
from pathlib import Path

if __package__:
    from . import configure_local
else:
    import configure_local

CHECK_INTERVAL = 5.0
CONNECT_GRACE = 30.0
PROBE_TIMEOUT = 2.0
FAILURE_LIMIT = 3
KUBECTL_TIMEOUT = 8.0
RECONNECT_DELAY = 2.0


class DiscoveryError(RuntimeError):
    """A failed Kubernetes read is not evidence that the selected Pod vanished."""


class InstallationError(RuntimeError):
    """The foreground tunnel no longer has its recorded installation binding."""


def _installation_active(args):
    directory = getattr(args, "installation_state", None)
    nonce = getattr(args, "installation_nonce", None)
    if directory is None and nonce is None:
        return True
    if directory is None or not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{32}", nonce):
        raise InstallationError("Installation state and its exact nonce must be supplied together")
    directory = Path(directory).expanduser().absolute()
    path = directory / "quickstart.json"
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise InstallationError("Installation state contains a symbolic link; stopping its tunnel")
    try:
        owner = directory.stat()
        if not stat.S_ISDIR(owner.st_mode) or owner.st_uid != os.getuid() or owner.st_mode & 0o077:
            raise InstallationError("Installation state directory is no longer private to this user")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
                or metadata.st_size > 256 * 1024):
            raise InstallationError("Installation receipt is no longer a bounded private regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise InstallationError("Installation receipt exceeded its size limit")
        try:
            record = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):
            raise InstallationError("Installation receipt is invalid; stopping its tunnel") from None
    finally:
        os.close(fd)
    expected_config = str(Path(args.kubeconfig).expanduser().absolute()) if args.kubeconfig else None
    if (not isinstance(record, dict) or type(record.get("schema_version")) is not int
            or record["schema_version"] != 1 or record.get("directory") != str(directory)
            or record.get("nonce") != nonce or record.get("context") != args.context
            or record.get("kubeconfig") != expected_config):
        raise InstallationError("Installation identity changed; stopping the original tunnel")
    if record.get("stage") == "removing":
        return False
    if record.get("stage") != "ready" or record.get("ready") is not True:
        raise InstallationError("Installation is no longer ready; stopping its tunnel")
    return True


def port_number(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("port must be an integer from 1 to 65535") from None
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("port must be an integer from 1 to 65535")
    return number


def kubectl(args):
    parts = ["kubectl", "--context", args.context]
    if args.kubeconfig:
        parts += ["--kubeconfig", str(args.kubeconfig)]
    return parts + ["--namespace", "lotus"]


def command(args, pod_name):
    if not isinstance(pod_name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]|[a-z0-9]", pod_name):
        raise ValueError("selected Pod name is invalid")
    return kubectl(args) + ["port-forward", "--address", "127.0.0.1",
                            "--pod-running-timeout=30s", "pod/" + pod_name, f"{args.port}:8000"]


def _read(args, *parts):
    try:
        result = subprocess.run(kubectl(args) + ["--request-timeout=5s", "get", *parts, "--output=json"],
                                capture_output=True, text=True, timeout=KUBECTL_TIMEOUT)
        if result.returncode:
            raise DiscoveryError("Kubernetes identity read failed; check the selected context and namespace access")
        return json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise DiscoveryError("Kubernetes identity read is unavailable or timed out") from exc


def discover(args):
    """Read the actual Service selector and select a ready, namespace-bound Pod."""
    service = _read(args, "service/lotus")
    if not isinstance(service, dict):
        raise DiscoveryError("Lotus Service identity is unavailable")
    meta, spec = service.get("metadata"), service.get("spec")
    if not isinstance(meta, dict) or not isinstance(spec, dict):
        raise DiscoveryError("Lotus Service identity is unavailable")
    selector, ports = spec.get("selector"), spec.get("ports")
    if not isinstance(ports, list):
        raise DiscoveryError("Lotus Service ports are unavailable")
    if (meta.get("name") != "lotus" or meta.get("namespace") != "lotus" or not isinstance(meta.get("uid"), str) or not meta["uid"]
            or not isinstance(selector, dict) or selector.get("app") != "lotus"
            or not all(isinstance(key, str) and isinstance(value, str)
                       and re.fullmatch(r"[A-Za-z0-9_.\-/]+", key) and re.fullmatch(r"[A-Za-z0-9_.-]*", value)
                       for key, value in selector.items())
            or not any(port.get("port") == 8000 and port.get("targetPort", 8000) in (8000, "http")
                       for port in ports if isinstance(port, dict))):
        raise DiscoveryError("Lotus Service selector or port does not match this launcher")
    listing = _read(args, "pods", "--selector=" + ",".join(key + "=" + value for key, value in sorted(selector.items())))
    if not isinstance(listing, dict) or not isinstance(listing.get("items"), list):
        raise DiscoveryError("Kubernetes returned an invalid Pod inventory")
    pods, ready = {}, []
    for pod in listing["items"]:
        if not isinstance(pod, dict) or not isinstance(pod.get("metadata"), dict):
            raise DiscoveryError("Kubernetes returned an invalid Pod identity")
        meta, status = pod["metadata"], pod.get("status") or {}
        labels = meta.get("labels") or {}
        if not isinstance(status, dict) or not isinstance(labels, dict):
            raise DiscoveryError("Kubernetes returned invalid Pod readiness or labels")
        conditions = status.get("conditions") or []
        if not isinstance(conditions, list):
            raise DiscoveryError("Kubernetes returned invalid Pod readiness")
        name, uid = meta.get("name"), meta.get("uid")
        if (meta.get("namespace") != "lotus" or not isinstance(name, str) or not isinstance(uid, str) or not uid
                or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]|[a-z0-9]", name)
                or not all(labels.get(key) == value for key, value in selector.items())):
            raise DiscoveryError("Kubernetes Pod inventory differs from the selected Service")
        record = {"name": name, "uid": uid, "created": str(meta.get("creationTimestamp") or ""),
                  "deleting": bool(meta.get("deletionTimestamp"))}
        if uid in pods:
            raise DiscoveryError("Kubernetes returned duplicate Pod identities")
        pods[uid] = record
        if (status.get("phase") == "Running" and not record["deleting"]
                and any(row.get("type") == "Ready" and row.get("status") == "True"
                        for row in conditions if isinstance(row, dict))):
            ready.append(record)
    selected = max(ready, key=lambda row: (row["created"], row["name"], row["uid"])) if ready else None
    return {"service_uid": service["metadata"]["uid"], "pods": pods, "selected": selected}


def health_status(port):
    """Probe transport only, with no proxy environment, redirect or credentials.

    Any HTTP response proves the forward is alive. Auth errors, initialization
    and application failures must not cause reconnection loops or Pod restarts.
    """
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=PROBE_TIMEOUT)
    try:
        connection.request("GET", "/healthz", headers={"Connection": "close"})
        return connection.getresponse().status
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def _available_port(port):
    configure_local.ensure_port_available(port)


def _close_child(child):
    if child is None:
        return
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)


def serve(args, stop=None):
    stop = stop or threading.Event()
    active = None
    handlers = {}

    def shutdown(*_):
        stop.set()
        if active is not None and active.poll() is None:
            active.terminate()

    def installation_active():
        if _installation_active(args):
            return True
        print("Installation removal requested or state removed; closing its UI tunnel.", flush=True)
        stop.set()
        return False

    try:
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGTERM, signal.SIGINT):
                handlers[sig] = signal.signal(sig, shutdown)
        last_notice = None
        while not stop.is_set():
            if not installation_active():
                break
            _available_port(args.port)
            try:
                state = discover(args)
                selected = state["selected"]
                notice = "Waiting for a ready Pod selected by service/lotus."
            except DiscoveryError as exc:
                selected, notice = None, str(exc)
            if selected is None:
                if notice != last_notice:
                    print(notice, flush=True)
                    last_notice = notice
                stop.wait(RECONNECT_DELAY)
                continue
            if stop.is_set() or not installation_active():
                break
            print(f"Connecting Lotus at http://127.0.0.1:{args.port} to context {args.context}, Pod {selected['name']} ({selected['uid']}).", flush=True)
            active = subprocess.Popen(command(args, selected["name"]), stdout=subprocess.DEVNULL)
            started, next_check, failures = time.monotonic(), time.monotonic(), 0
            reason = "Kubernetes connection ended"
            while active.poll() is None and not stop.is_set():
                if not installation_active():
                    break
                now = time.monotonic()
                if now >= next_check:
                    next_check = now + CHECK_INTERVAL
                    try:
                        current = discover(args)
                        replacement = current["selected"]
                        if (current["service_uid"] != state["service_uid"] or selected["uid"] not in current["pods"]
                                or current["pods"][selected["uid"]]["deleting"]
                                or (replacement and replacement["uid"] != selected["uid"])):
                            reason = "Selected Kubernetes Pod changed"
                            break
                    except DiscoveryError:
                        # An unavailable API is not proof of replacement. Keep
                        # the existing forward while checking its local transport.
                        pass
                    if stop.is_set() or not installation_active():
                        break
                    code = health_status(args.port)
                    if code is not None:
                        failures = 0
                    elif time.monotonic() - started >= CONNECT_GRACE:
                        failures += 1
                        if failures >= FAILURE_LIMIT:
                            reason = "Local health transport stopped responding"
                            break
                stop.wait(.25)
            _close_child(active)
            active = None
            if not stop.is_set():
                print(reason + "; reconnecting to the current ready controller Pod.", flush=True)
                stop.wait(RECONNECT_DELAY)
    finally:
        _close_child(active)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--kubeconfig", type=Path)
    parser.add_argument("--port", type=port_number, default=8000)
    parser.add_argument("--installation-state", type=Path, help="private quickstart state directory for this tunnel")
    parser.add_argument("--installation-nonce", help="exact installation nonce; requires --installation-state")
    args = parser.parse_args()
    if not args.context.strip() or args.context.startswith("-"):
        parser.error("select an explicit Kubernetes context")
    if args.kubeconfig and not args.kubeconfig.is_file():
        parser.error("the selected kubeconfig does not exist")
    if ((args.installation_state is None) != (args.installation_nonce is None)
            or (args.installation_nonce is not None and not re.fullmatch(r"[a-f0-9]{32}", args.installation_nonce))):
        parser.error("supply --installation-state and its exact 32-character --installation-nonce together")
    try:
        serve(args)
    except InstallationError as exc:
        parser.exit(1, f"Could not serve Lotus: {exc}.\n")
    except OSError as exc:
        parser.exit(1, f"Could not serve Lotus: {exc.strerror}. Existing listeners were preserved.\n")


if __name__ == "__main__":
    main()
