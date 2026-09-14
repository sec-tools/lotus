"""Authenticated restart ownership for audit source PVCs, never a reuse proof.

Only records in this instance's private data directory are cleanup candidates.
Reading an existing Kubernetes name can confirm a recorded UID, never create
ownership. Incomplete uploads from an unprovably dead owner remain quarantined.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import socket
import stat
import tempfile
import threading

import psutil

_LOCK = threading.RLock()
_MAX_RECORD = 32 * 1024
_MAX_RECORDS = 10000


def _directory():
    from backend.target_snapshots import snapshot_root
    root = snapshot_root() / ".source_volume_ownership"
    if root.is_symlink():
        raise RuntimeError("Source ownership directory must not be a symlink")
    root.mkdir(mode=0o700, exist_ok=True)
    if root.stat().st_mode & 0o077:
        raise RuntimeError("Source ownership directory must have private permissions")
    return root


def _read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > limit:
            raise RuntimeError("Source ownership file is not private bounded regular data")
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise RuntimeError("Source ownership file exceeds its size bound")
        return data


@contextmanager
def _guard():
    with _LOCK:
        root = _directory()
        fd = os.open(root / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            yield root


def _key(root, *, create=False):
    path = root / ".key"
    if create and not path.exists() and not path.is_symlink():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(os.urandom(32)); handle.flush(); os.fsync(handle.fileno())
    try:
        key = _read(path, 32)
    except FileNotFoundError as exc:
        raise RuntimeError("Source ownership signing key is missing; records retained") from exc
    if len(key) != 32:
        raise RuntimeError("Source ownership signing key is invalid; records retained")
    return key


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _scope(repo_id):
    from backend import k8s_lab
    return {"repo_id": int(repo_id), "namespace": k8s_lab.namespace(),
            "context_args": list(k8s_lab._context_args()), "kubeconfig": os.environ.get("KUBECONFIG", "")}


def _filename(scope):
    return hashlib.sha256(_json(scope)).hexdigest() + ".json"


def _validate(receipt):
    if not isinstance(receipt, dict) or receipt.get("schema_version") != 1:
        raise RuntimeError("Unsupported source ownership record")
    if type(receipt.get("repo_id")) is not int or receipt["repo_id"] <= 0 or receipt.get("provider") != "k8s-job":
        raise RuntimeError("Invalid source ownership repository/provider")
    for field in ("name", "namespace", "uid", "owner"):
        if not isinstance(receipt.get(field), str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,252}", receipt[field]):
            raise RuntimeError("Invalid immutable source ownership identity")
    if receipt["name"] != f"lotus-src-{receipt['repo_id']}" or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(receipt.get("source_tree_hash") or "")):
        raise RuntimeError("Invalid source ownership name/tree binding")
    if type(receipt.get("ready")) is not bool or not isinstance(receipt.get("source_path"), str) or not Path(receipt["source_path"]).is_absolute():
        raise RuntimeError("Invalid source ownership upload state")
    scope = receipt.get("scope")
    if not isinstance(scope, dict) or scope.get("repo_id") != receipt["repo_id"] or scope.get("namespace") != receipt["namespace"]:
        raise RuntimeError("Invalid source ownership scope")
    if not isinstance(scope.get("context_args"), list) or any(not isinstance(v, str) for v in scope["context_args"]) or not isinstance(scope.get("kubeconfig"), str):
        raise RuntimeError("Invalid source ownership provider context")
    return receipt


def _load(path, key):
    try:
        envelope = json.loads(_read(path, _MAX_RECORD))
        receipt = _validate(envelope.get("payload"))
        signature = hmac.new(key, b"lotus-source-volume-v1\0" + _json(receipt), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(envelope.get("signature") or ""), signature) or path.name != _filename(receipt["scope"]):
            raise ValueError("signature or scope mismatch")
        return receipt
    except (ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError("Source ownership authentication failed; records retained") from exc


def _uploader():
    return {"hostname": socket.gethostname(), "pid": os.getpid(),
            "process_create_time": psutil.Process().create_time()}


def save_source_receipt(receipt):
    """Persist observed UID before upload; compare owner/UID on later updates."""
    from backend import audit_progress
    value = dict(receipt)
    value.setdefault("schema_version", 1)
    value.setdefault("scope", _scope(value["repo_id"]))
    value.setdefault("uploader", _uploader())
    value.setdefault("scan_job_id", audit_progress.snapshot(value["repo_id"]).get("scan_job_id"))
    value["updated_at"] = datetime.now(timezone.utc).isoformat()
    _validate(value)
    if value["scope"] != _scope(value["repo_id"]):
        raise RuntimeError("Source ownership scope changed before checkpoint")
    with _guard() as root:
        key = _key(root, create=True)
        path = root / _filename(value["scope"])
        if path.exists() or path.is_symlink():
            previous = _load(path, key)
            if any(previous.get(field) != value.get(field) for field in ("uid", "owner", "source_tree_hash", "source_path")):
                raise RuntimeError("Another immutable source owner is already recorded; cleanup required")
            for field in ("uploader", "scan_job_id"):
                value[field] = previous.get(field)
        raw = _json({"payload": value, "signature": hmac.new(key, b"lotus-source-volume-v1\0" + _json(value), hashlib.sha256).hexdigest()})
        if len(raw) > _MAX_RECORD:
            raise RuntimeError("Source ownership record exceeds its bound")
        fd, name = tempfile.mkstemp(prefix="receipt-", dir=root)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw); handle.flush(); os.fsync(handle.fileno())
            os.chmod(name, 0o600); os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    return value


def load_source_receipt(repo_id):
    with _guard() as root:
        path = root / _filename(_scope(repo_id))
        if not path.exists() and not path.is_symlink():
            return None
        return _load(path, _key(root))


def list_source_receipts():
    with _guard() as root:
        paths = []
        for path in root.iterdir():
            if path.suffix == ".json":
                paths.append(path)
                if len(paths) > _MAX_RECORDS:
                    raise RuntimeError("Too many source ownership records; bounded reset preflight refused")
        if not paths:
            return []
        key = _key(root)
        return [_load(path, key) for path in sorted(paths)]


def remove_source_receipt(receipt):
    with _guard() as root:
        scope = receipt.get("scope") or _scope(receipt["repo_id"])
        path = root / _filename(scope)
        if not path.exists() and not path.is_symlink():
            return
        current = _load(path, _key(root))
        if any(current.get(field) != receipt.get(field) for field in ("uid", "owner", "source_tree_hash")):
            raise RuntimeError("Source ownership changed before removal; replacement retained")
        path.unlink()


def _owner_process_state(receipt):
    owner = receipt.get("uploader") or {}
    if owner.get("hostname") != socket.gethostname():
        return "unknown"
    try:
        process = psutil.Process(int(owner["pid"]))
        if process.create_time() != owner["process_create_time"]:
            return "gone"
        return "current" if process.pid == os.getpid() else "live"
    except psutil.NoSuchProcess:
        return "gone"
    except (psutil.Error, KeyError, TypeError, ValueError):
        return "unknown"


def _assert_inactive_owner(receipt, admission_owned):
    from backend.main import SessionLocal, ScanJob, ScanLease
    from backend import k8s_runtime as runtime
    process_state = _owner_process_state(receipt)
    # An admitted caller may retire its own completed source after draining
    # analyzers, but cannot retire another live process's active audit.
    local_teardown = (admission_owned and process_state == "current" and receipt.get("ready")
                      and not runtime._SOURCE_INFLIGHT.get(runtime._source_key(receipt["repo_id"])))
    if local_teardown:
        return
    job_id = receipt.get("scan_job_id")
    if job_id:
        with SessionLocal() as db:
            job = db.get(ScanJob, job_id)
            if job and (job.repo_id != receipt["repo_id"] or job.status in {"queued", "running", "paused", "pending"}):
                raise RuntimeError("Source uploader audit is still active or has conflicting ownership; cleanup refused")
            if db.query(ScanLease).filter(ScanLease.job_id == job_id).first():
                raise RuntimeError("Source uploader audit still holds a lease; cleanup refused")
    elif process_state != "gone":
        raise RuntimeError("Source uploader has no terminal durable audit identity and is not proven gone; cleanup refused")
    if not receipt.get("ready") and process_state != "gone":
        raise RuntimeError("Interrupted source uploader is not proven gone; retain its record and reconcile its controller before cleanup")


async def preflight_source_cleanup(receipt, *, caller_holds_admission=False):
    from backend import k8s_runtime as runtime
    current = load_source_receipt(receipt["repo_id"])
    if not current or any(current.get(field) != receipt.get(field) for field in ("uid", "owner", "source_tree_hash", "scope")):
        raise RuntimeError("Source cleanup requires the exact authenticated durable owner")
    if current["scope"] != _scope(current["repo_id"]):
        raise RuntimeError("Source cleanup provider context differs from its recorded scope")
    admission_owned = bool(caller_holds_admission and runtime.source_admission_owned(current["repo_id"]))
    if caller_holds_admission and not admission_owned:
        raise RuntimeError("Source cleanup admission is not owned by this task")
    if not admission_owned and runtime._SOURCE_INFLIGHT.get(runtime._source_key(current["repo_id"])):
        raise RuntimeError("Source upload is active; cleanup refused")
    _assert_inactive_owner(current, admission_owned)
    document = await runtime._source_read("persistentvolumeclaim", current["name"])
    if document is None:
        return current
    if (document["metadata"]["uid"] != current["uid"]
            or not runtime._source_owned(document, current, role="tool-source", name=current["name"])
            or (document["metadata"].get("annotations") or {}).get("lotus.io/source-tree") != current["source_tree_hash"]):
        raise RuntimeError("Source PVC immutable UID/owner/repository/tree changed; cleanup refused")
    pods, rc, raw = await runtime.get_json("pods", timeout=20)
    if rc or not isinstance(pods, dict) or not isinstance(pods.get("items"), list):
        raise RuntimeError("Source PVC consumers could not be inspected; cleanup refused")
    for pod in pods["items"]:
        if any((volume.get("persistentVolumeClaim") or {}).get("claimName") == current["name"]
               for volume in (pod.get("spec") or {}).get("volumes") or []):
            raise RuntimeError("Source PVC still has a Pod reference; cleanup refused")
    return current


async def cleanup_owned_source(receipt, *, caller_holds_admission=False):
    from backend import k8s_runtime as runtime
    if not caller_holds_admission:
        async with runtime._source_admission(receipt["repo_id"], 30):
            return await cleanup_owned_source(receipt, caller_holds_admission=True)
    current = await preflight_source_cleanup(receipt, caller_holds_admission=True)
    await runtime._delete_source_owned("persistentvolumeclaim", current["name"], current,
                                       role="tool-source", uid=current["uid"])
    deadline = asyncio.get_running_loop().time() + 20
    while True:
        document = await runtime._source_read("persistentvolumeclaim", current["name"])
        if document is None:
            break
        if document["metadata"]["uid"] != current["uid"]:
            raise RuntimeError("Source PVC name was reused during cleanup; replacement retained")
        if asyncio.get_running_loop().time() >= deadline:
            raise RuntimeError("Source PVC deletion is still pending; ownership record retained")
        await asyncio.sleep(.25)
    remove_source_receipt(current)
    runtime._SOURCE_RECEIPTS.pop(runtime._source_key(current["repo_id"]), None)
    runtime._POPULATED.pop(current["repo_id"], None)
