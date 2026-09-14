"""Snapshot-bound, authenticated source indexes and bounded file windows.

Replay/proof verification still uses target_snapshots.load_snapshot. A viewer
instead verifies that the selected file matches a digest captured while the
complete source tree matched the audit. No persisted sidecar is trusted without
authentication; deployments without a stable signing key reverify after restart.
"""
from __future__ import annotations

from array import array
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from functools import wraps
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
import time
from typing import Any, Dict

from backend import proof_receipts, target_snapshots

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_WINDOW_BYTES = 1024 * 1024
MAX_LINES = 1_000_000
MAX_INDEX_BYTES = 32 * 1024 * 1024
_PROCESS_KEY = os.urandom(32)
_LOCK = threading.RLock()
_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="lotus-source-index")
_INDEXES: OrderedDict = OrderedDict()
_FILES: OrderedDict = OrderedDict()
_PENDING: dict = {}
_PROGRESS: dict = {}
_ERRORS: dict = {}
_FILE_GUARDS = tuple(threading.Lock() for _ in range(32))
_MAINTENANCE = threading.Condition(_LOCK)
_OPERATION_LOCAL = threading.local()
_RESETTING = False
_ACTIVE_OPERATIONS = 0
_EXCLUDED = {".git", ".hg", ".svn", ".lotus", ".lotus_harness", "node_modules", "target", "build", "dist", "out",
             "coverage", ".pytest_cache", "__pycache__", ".mypy_cache", ".tox", ".venv", "venv"}
_SYMBOLS = tuple(re.compile(pattern) for pattern in (
    r"^\s*func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\(",
    r"^\s*(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*\(",
    r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_]\w*)\s*\(",
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_]\w*)\s*\(",
    r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_]\w*)\s*=.*=>",
    r"^\s*(?:(?:public|private|protected|internal|static|final|async)\s+)+[\w<>\[\],.?]+\s+(?P<name>[A-Za-z_]\w*)\s*\(",
))


class SourceChanged(ValueError):
    pass


class SourceTooLarge(ValueError):
    pass


class SourceIndexResetBusy(RuntimeError):
    pass


def artifact_operation(function):
    """Track managed source/evaluation work without serializing ordinary readers."""
    @wraps(function)
    def guarded(*args, **kwargs):
        global _ACTIVE_OPERATIONS
        with _MAINTENANCE:
            depth = getattr(_OPERATION_LOCAL, "depth", 0)
            if not depth:
                if _RESETTING:
                    raise SourceChanged("Source indexing is paused for platform reset")
                _ACTIVE_OPERATIONS += 1
            _OPERATION_LOCAL.depth = depth + 1
        try:
            return function(*args, **kwargs)
        finally:
            with _MAINTENANCE:
                _OPERATION_LOCAL.depth -= 1
                if not depth:
                    _ACTIVE_OPERATIONS -= 1
                    _MAINTENANCE.notify_all()
    return guarded


@contextmanager
def reset_indexes(*, timeout=30):
    """Keep source cache admission closed until reset finishes deleting files.

    Wait for in-flight read/index work; never erase source while a background
    writer could publish an index or line cache afterward. A timeout preserves
    the existing records and lets the operator retry after that work drains.
    """
    global _RESETTING
    with _MAINTENANCE:
        if _RESETTING or getattr(_OPERATION_LOCAL, "depth", 0):
            raise SourceIndexResetBusy("Source index maintenance is already active")
        _RESETTING = True
    try:
        deadline = time.monotonic() + max(0.0, float(timeout))
        with _MAINTENANCE:
            while _ACTIVE_OPERATIONS:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SourceIndexResetBusy("Source index work did not quiesce before reset; retry after it finishes")
                _MAINTENANCE.wait(remaining)
            # A caller already admitted before maintenance may have queued a
            # worker while we waited. Cancel queued futures only after it drains.
            for future in list(_PENDING.values()):
                future.cancel()
            for cache in (_INDEXES, _FILES, _PENDING, _PROGRESS, _ERRORS):
                cache.clear()
            from backend import dependency_source_capture
            with dependency_source_capture._METADATA_LOCK:
                dependency_source_capture._METADATA_CACHE.clear()
        yield
    finally:
        with _MAINTENANCE:
            _RESETTING = False
            _MAINTENANCE.notify_all()


def _stamp(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_mode)


def _key():
    return proof_receipts._signing_key() or _PROCESS_KEY


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _signature(payload):
    return hmac.new(_key(), b"lotus-source-index-v1\0" + _canonical(payload), hashlib.sha256).hexdigest()


@artifact_operation
def snapshot_metadata(path_or_key: str, *, expected_tree: str = "", expected_manifest: str = "") -> dict:
    """Check confined manifest identity only; this does not claim content verification."""
    raw = str(path_or_key or "").strip()
    if not raw:
        raise FileNotFoundError("immutable source snapshot is missing")
    root = target_snapshots.snapshot_root()
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / target_snapshots._safe_key(raw)
    candidate = candidate.resolve()
    if candidate.name == "source":
        candidate = candidate.parent
    if candidate == root or root not in candidate.parents:
        raise SourceChanged("snapshot path escapes snapshot root")
    manifest_path, source = candidate / "snapshot.json", candidate / "source"
    if manifest_path.is_symlink() or source.is_symlink() or not manifest_path.is_file() or not source.is_dir():
        raise FileNotFoundError("immutable source snapshot is incomplete")
    if manifest_path.stat().st_size > 65536:
        raise SourceChanged("snapshot manifest exceeds metadata limit")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise SourceChanged("unsupported snapshot schema")
    unsigned = dict(manifest)
    digest = str(unsigned.pop("manifest_hash", ""))
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if digest != "sha256:" + hashlib.sha256(canonical.encode()).hexdigest():
        raise SourceChanged("snapshot manifest hash mismatch")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(manifest.get("tree_hash") or "")) or candidate.name != target_snapshots.snapshot_object_key(manifest):
        raise SourceChanged("snapshot location does not match its content-addressed identity")
    if expected_tree and manifest.get("tree_hash") != expected_tree:
        raise SourceChanged("snapshot tree differs from the selected audit")
    if expected_manifest and digest != expected_manifest:
        raise SourceChanged("snapshot manifest differs from the selected audit")
    return {**manifest, "path": str(candidate), "source_path": str(source)}


def _identity(meta):
    return (meta["path"], meta["tree_hash"], meta["manifest_hash"], _stamp(Path(meta["source_path"]).stat()),
            hashlib.sha256(_key()).hexdigest())


@artifact_operation
def _cache_path(meta):
    directory = Path(meta["path"]).parent / ".source_indexes"
    if directory.is_symlink():
        raise SourceChanged("source index directory must not be a symlink")
    directory.mkdir(mode=0o700, exist_ok=True)
    name = hashlib.sha256((meta["path"] + "\0" + meta["manifest_hash"]).encode()).hexdigest()
    return directory / (name + ".json")


def _remember(key, index):
    with _LOCK:
        _INDEXES[key] = index
        _INDEXES.move_to_end(key)
        while len(_INDEXES) > 8:
            _INDEXES.popitem(last=False)


@artifact_operation
def _load_index(meta, key):
    with _LOCK:
        cached = _INDEXES.get(key)
        if cached is not None:
            _INDEXES.move_to_end(key)
            return cached
    path = _cache_path(meta)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INDEX_BYTES:
        return None
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
        payload = saved["payload"]
        if not hmac.compare_digest(str(saved.get("signature") or ""), _signature(payload)):
            return None
        if payload.get("schema_version") != 1 or payload.get("tree_hash") != meta["tree_hash"] or payload.get("manifest_hash") != meta["manifest_hash"]:
            return None
        if not isinstance(payload.get("files"), dict):
            return None
        _remember(key, payload)
        return payload
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _open_source(root, relative):
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(part in {".", ".."} for part in parts) or "\\" in relative:
        raise SourceChanged("source path is not canonical")
    # openat + O_NOFOLLOW confines every path component, including replacement races.
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parts[:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        result = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        if not stat.S_ISREG(os.fstat(result).st_mode):
            os.close(result)
            raise SourceChanged("source is not a regular file")
        return os.fdopen(result, "rb")
    finally:
        os.close(descriptor)


def _build_index(meta, key, progress=None):
    source = Path(meta["source_path"])
    paths = proof_receipts.source_content_files(source)
    if len(paths) > 100_000:
        raise SourceTooLarge("snapshot exceeds the 100,000 indexed-file viewer limit")
    paths.sort()
    tree, entries, total_bytes = hashlib.sha256(), {}, 0
    for count, path in enumerate(paths, 1):
        relative = path.relative_to(source).as_posix()
        encoded = relative.encode("utf-8")
        tree.update(len(encoded).to_bytes(4, "big")); tree.update(encoded)
        file_hash = hashlib.sha256()
        with _open_source(source, relative) as handle:
            before = _stamp(os.fstat(handle.fileno()))
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                tree.update(chunk); file_hash.update(chunk)
            if before != _stamp(os.fstat(handle.fileno())):
                raise SourceChanged("source changed while index was being prepared")
        entries[relative] = {"sha256": "sha256:" + file_hash.hexdigest(), "bytes": before[2]}
        total_bytes += before[2]
        if count == 1 or count % 100 == 0 or count == len(paths):
            update = {"stage": "verifying-source", "completed": count, "total": len(paths), "bytes": total_bytes}
            with _LOCK:
                _PROGRESS[key] = update
            if progress:
                progress(update)
    if "sha256:" + tree.hexdigest() != meta["tree_hash"]:
        raise SourceChanged("snapshot content hash mismatch")
    metadata = target_snapshots._read_bound_metadata(source, meta)
    payload = {"schema_version": 1, "tree_hash": meta["tree_hash"], "manifest_hash": meta["manifest_hash"],
               "files": entries, "bytes": total_bytes, "aliases": (metadata or {}).get("aliases", {})}
    # A reset or replacement must not let an old background worker recreate artifacts.
    if _identity(snapshot_metadata(meta["path"], expected_tree=meta["tree_hash"], expected_manifest=meta["manifest_hash"])) != key:
        raise SourceChanged("snapshot was replaced during source indexing")
    path = _cache_path(meta)
    raw = _canonical({"payload": payload, "signature": _signature(payload)})
    if len(raw) > MAX_INDEX_BYTES:
        raise SourceTooLarge("source index exceeds the metadata size limit")
    descriptor, temporary = tempfile.mkstemp(prefix=path.stem + "-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    _remember(key, payload)
    return payload


@artifact_operation
def prepare_source_index(snapshot: dict, progress=None) -> dict:
    meta = snapshot_metadata(str(snapshot.get("path") or snapshot.get("source_path") or ""),
                             expected_tree=str(snapshot.get("tree_hash") or ""),
                             expected_manifest=str(snapshot.get("manifest_hash") or ""))
    key = _identity(meta)
    lock_path = _cache_path(meta).with_suffix(".lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "a+b") as lock:
            deadline = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise SourceChanged("another worker is preparing this source index; retry shortly")
                    time.sleep(0.05)
            payload = _load_index(meta, key) or _build_index(meta, key, progress)
    except Exception as exc:
        with _LOCK:
            _ERRORS[key] = (time.monotonic(), str(exc)[:240])
            while len(_ERRORS) > 16:
                _ERRORS.pop(next(iter(_ERRORS)))
        raise
    finally:
        with _LOCK:
            _PENDING.pop(key, None)
            _PROGRESS.pop(key, None)
    return {"status": "ready", "files": len(payload["files"]), "bytes": payload["bytes"], "tree_hash": meta["tree_hash"]}


def _file_offsets(meta, relative, entry, handle):
    with _FILE_GUARDS[hash((meta["path"], relative)) % len(_FILE_GUARDS)]:
        return _build_file_offsets(meta, relative, entry, handle)


def _build_file_offsets(meta, relative, entry, handle):
    stamp = _stamp(os.fstat(handle.fileno()))
    if stamp[2] > MAX_FILE_BYTES:
        raise SourceTooLarge("source file exceeds the 64 MiB viewer limit")
    key = (meta["path"], relative, entry["sha256"], stamp)
    with _LOCK:
        cached = _FILES.get(key)
        if cached is not None:
            _FILES.move_to_end(key)
            return cached
    digest, offsets, symbols, position = hashlib.sha256(), array("Q", [0]), [], 0
    while True:
        line = handle.readline(MAX_WINDOW_BYTES + 1)
        if not line:
            break
        if len(line) > MAX_WINDOW_BYTES:
            raise SourceTooLarge("one source line exceeds the 1 MiB viewer window limit")
        digest.update(line)
        decoded = line.decode("utf-8", errors="replace")
        if not decoded.lstrip().startswith(("//", "#", "/*", "*", "<!--")):
            for pattern in _SYMBOLS:
                match = pattern.search(decoded)
                if match:
                    symbols.append((len(offsets), match.group("name")))
                    break
        position += len(line)
        if line.endswith(b"\n"):
            offsets.append(position)
        if len(offsets) > MAX_LINES:
            raise SourceTooLarge("source file exceeds the one million line viewer limit")
    if "sha256:" + digest.hexdigest() != entry["sha256"] or stamp != _stamp(os.fstat(handle.fileno())):
        raise SourceChanged("source file no longer matches the audited snapshot")
    cached = {"offsets": offsets, "symbols": symbols, "bytes": stamp[2], "stamp": stamp}
    with _LOCK:
        _FILES[key] = cached
        while len(_FILES) > 16 or sum(len(value["offsets"]) * 8 for value in _FILES.values()) > 32 * 1024 * 1024:
            _FILES.popitem(last=False)
    return cached


@artifact_operation
def _source_index(snapshot: dict):
    """Share authenticated preparation and progress across all source readers."""
    meta = snapshot_metadata(str(snapshot.get("path") or snapshot.get("source_path") or ""),
                             expected_tree=str(snapshot.get("tree_hash") or ""),
                             expected_manifest=str(snapshot.get("manifest_hash") or ""))
    key = _identity(meta)
    index = _load_index(meta, key)
    if index is None:
        with _LOCK:
            if key in _ERRORS:
                failed_at, reason = _ERRORS[key]
                if time.monotonic() - failed_at < 2:
                    raise SourceChanged(reason)
                _ERRORS.pop(key, None)
            if key not in _PENDING and len(_PENDING) < 8:
                _PENDING[key] = _EXECUTOR.submit(prepare_source_index, meta)
            progress = dict(_PROGRESS.get(key) or {"stage": "queued", "completed": 0, "total": None})
        return meta, None, {"status": "indexing", "message": "Preparing the immutable source index", "progress": progress, "retry_after": 1}
    return meta, index, None


@artifact_operation
def source_catalog(snapshot: dict, *, query: str = "", offset: int = 0, limit: int = 200) -> dict:
    """Page the complete captured inventory; indexing is distinct from review."""
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 500 or len(query) > 1024:
        raise ValueError("source catalog requires offset>=0, limit 1..500 and query<=1024 characters")
    meta, index, pending = _source_index(snapshot)
    if pending:
        return pending
    names = sorted(name for name in index["files"] if query.casefold() in name.casefold())
    return {"status": "ready", "tree_hash": meta["tree_hash"], "manifest_hash": meta["manifest_hash"],
            "total_files": len(index["files"]), "total_bytes": index["bytes"],
            "matched_files": len(names), "offset": offset, "limit": limit,
            "next_offset": offset + limit if offset + limit < len(names) else None,
            "files": [{"path": name, **index["files"][name]} for name in names[offset:offset + limit]],
            "coverage_basis": "Captured and indexed source; this does not attest analysis or runtime coverage"}


def resolve_source_entry(meta: dict, index: dict, relative: str) -> tuple[str, dict]:
    """Resolve only an authenticated, unchanged alias to its indexed file.

    Callers authenticate ``meta`` and ``index`` before using this helper. The
    alias is checked through confined directory descriptors; its target is
    selected from the signed index, never from the current filesystem link.
    Selected source bytes still require ``indexed_source_window`` verification.
    """
    def canonical(value):
        return (isinstance(value, str) and bool(value) and not value.startswith("/")
                and "\\" not in value and "\x00" not in value
                and all(part not in {"", ".", ".."} for part in value.split("/")))

    if not canonical(relative):
        # An invalid requested name is not a captured file. Preserve the
        # viewer's non-disclosing missing-file contract; only changes to a
        # recorded alias or selected source are integrity conflicts.
        raise FileNotFoundError("source file is not present in the audited source index")
    source_relative = relative
    entry = index["files"].get(relative)
    if entry is None:
        for alias, target in sorted(index.get("aliases", {}).items(), key=lambda row: len(row[0]), reverse=True):
            if relative == alias or relative.startswith(alias + "/"):
                if not canonical(alias) or not canonical(target):
                    raise SourceChanged("source alias index is not canonical")
                source_relative = target + relative[len(alias):]
                parts = alias.split("/")
                descriptor = os.open(meta["source_path"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    for component in parts[:-1]:
                        following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                        os.close(descriptor)
                        descriptor = following
                    expected_link = os.path.relpath(target, os.path.dirname(alias) or ".")
                    if os.readlink(parts[-1], dir_fd=descriptor) != expected_link:
                        raise SourceChanged("source alias no longer matches the audited snapshot")
                except OSError as error:
                    raise SourceChanged("source alias no longer matches the audited snapshot") from error
                finally:
                    os.close(descriptor)
                entry = index["files"].get(source_relative)
                break
    if not isinstance(entry, dict):
        raise FileNotFoundError("source file is not present in the audited source index")
    return source_relative, entry


@artifact_operation
def source_window(snapshot: dict, relative: str, *, start_line: int = 1, line_count: int = 400,
                  expected_sha256: str = "", anchor_line: int = 0) -> dict:
    if isinstance(start_line, bool) or isinstance(line_count, bool) or start_line < 1 or not 1 <= line_count <= 1000:
        raise ValueError("source window requires start_line>=1 and line_count between 1 and 1000")
    meta, index, pending = _source_index(snapshot)
    if pending:
        return pending
    source_relative, entry = resolve_source_entry(meta, index, relative)
    return indexed_source_window(meta, source_relative, entry, start_line=start_line, line_count=line_count,
                                 expected_sha256=expected_sha256, anchor_line=anchor_line, display_relative=relative)


@artifact_operation
def indexed_source_window(meta: dict, source_relative: str, entry: dict, *, start_line: int = 1,
                          line_count: int = 400, expected_sha256: str = "", anchor_line: int = 0,
                          display_relative: str = "") -> dict:
    """Read one file from an already authenticated controller-owned index.

    Callers must authenticate the index and its source root first. The reader
    confines the path and verifies the selected bytes before returning text.
    """
    if type(start_line) is not int or type(line_count) is not int or start_line < 1 or not 1 <= line_count <= 1000:
        raise ValueError("source window requires start_line>=1 and line_count between 1 and 1000")
    relative = display_relative or source_relative
    if expected_sha256 and not hmac.compare_digest(expected_sha256, entry["sha256"]):
        raise SourceChanged("source file identity differs from the open viewer")
    with _open_source(meta["source_path"], source_relative) as handle:
        file_index = _file_offsets(meta, source_relative, entry, handle)
        offsets = file_index["offsets"]
        total = len(offsets)
        if start_line > total:
            return {"status": "ready", "file": relative, "lines": [], "start_line": start_line, "end_line": total,
                    "total_lines": total, "sha256": entry["sha256"], "truncated": False}
        end = min(start_line + line_count - 1, total)
        begin_byte = offsets[start_line - 1]
        end_byte = offsets[end] if end < total else file_index["bytes"]
        if end_byte - begin_byte > MAX_WINDOW_BYTES:
            raise SourceTooLarge("requested source window exceeds 1 MiB; request fewer lines")
        handle.seek(begin_byte)
        data = handle.read(end_byte - begin_byte)
        if len(data) != end_byte - begin_byte or _stamp(os.fstat(handle.fileno())) != file_index["stamp"]:
            raise SourceChanged("source file changed while the window was being read")
    lines = [line.removesuffix("\r") for line in data.decode("utf-8", errors="replace").split("\n")][:end - start_line + 1]
    symbol = {}
    for number, name in file_index["symbols"]:
        if number > anchor_line:
            break
        symbol = {"function": name, "function_line": number}
    return {"status": "ready", "file": relative, "lines": lines, "start_line": start_line, "end_line": end,
            "total_lines": total, "sha256": entry["sha256"], "truncated": False,
            "verification_scope": "selected file authenticated against the audited snapshot index", **symbol}
