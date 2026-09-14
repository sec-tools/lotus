"""Capture exact declared Go dependency source without executing target code.

The original audit snapshot stays immutable. Downloads use the public Go proxy
and its explicit storage CDN only; no package manager, install hook or VCS runs.
Source bytes, Go h1 authentication and completed review remain separate states.
"""
from __future__ import annotations

import base64
from collections import OrderedDict
from copy import deepcopy
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fnmatch
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import tempfile
import threading
import time
from urllib.parse import quote, urljoin, urlsplit
import zipfile

import httpx

# Separate injectable transport boundary: unit/full-audit fixtures deny public
# dependency downloads without replacing unrelated application HTTP clients.
_HTTP_CLIENT = httpx.Client

from backend import proof_receipts, target_snapshots, source_index
from backend.dependency_sources import parse_go_mod, _is_manifest_name

PURPOSE = "lotus-dependency-source-bundle-v1"
MANIFEST_LIMIT = 4 * 1024 * 1024
TOTAL_MANIFEST_LIMIT = 16 * 1024 * 1024
RECEIPT_LIMIT = 32 * 1024 * 1024
_METADATA_CACHE = OrderedDict()
_METADATA_LOCK = threading.Lock()
_METADATA_CACHE_BYTES = 16 * 1024 * 1024


class CaptureError(ValueError):
    pass


@dataclass(frozen=True)
class CaptureLimits:
    concurrency: int = 3
    max_modules: int = 4096
    archive_bytes: int = 128 * 1024 * 1024
    module_bytes: int = 500 * 1024 * 1024
    file_bytes: int = 64 * 1024 * 1024
    file_count: int = 50000
    total_bytes: int = 2 * 1024 * 1024 * 1024
    request_seconds: int = 120
    total_seconds: int = 1800
    compression_ratio: int = 200

    def validate(self):
        if any(type(value) is not int or value < 1 for value in asdict(self).values()):
            raise CaptureError("Source capture limits must be positive integers")
        if self.concurrency > 8 or self.file_count > 65534 or self.max_modules > 10000:
            raise CaptureError("Source capture concurrency or inventory limit exceeds its supported bound")
        if self.archive_bytes > 500 * 1024 * 1024 or self.module_bytes > 500 * 1024 * 1024:
            raise CaptureError("Go module archives and extracted source cannot exceed 500 MiB")


class _Budget:
    def __init__(self, limits, cancel_event):
        self.limits, self.cancel_event = limits, cancel_event
        self.deadline = time.monotonic() + limits.total_seconds
        self.lock, self.used = threading.Lock(), 0

    def check(self):
        if self.cancel_event.is_set():
            raise CaptureError("Dependency source capture cancelled")
        if time.monotonic() > self.deadline:
            raise CaptureError("Dependency source capture exceeded its total time budget")

    def consume(self, size):
        self.check()
        with self.lock:
            if self.used + size > self.limits.total_bytes:
                raise CaptureError("Dependency source capture exceeded its total byte budget")
            self.used += size


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _module_url(module, version):
    if (not isinstance(module, str) or len(module) > 1024
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z0-9.-]+(?:/[A-Za-z0-9._~+-]+)*", module)
            or any(part in {"", ".", ".."} or part.startswith(".") or part.endswith(".") for part in module.split("/"))):
        raise CaptureError("Dependency module path is not a supported public Go module identity")
    if not isinstance(version, str) or len(version) > 256 or not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[A-Za-z0-9.-]+)?(?:\+incompatible)?", version):
        raise CaptureError("Dependency version is not an exact supported Go version")
    escape = lambda value: "".join("!" + char.lower() if "A" <= char <= "Z" else char for char in value)
    return "https://proxy.golang.org/" + quote(escape(module), safe="/!") + "/@v/" + quote(escape(version), safe="!+") + ".zip"


def _allowed_download_url(url, *, initial=False):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment
            or parsed.port not in (None, 443)):
        raise CaptureError("Dependency download URL is outside the allowed HTTPS origin")
    if parsed.hostname == "proxy.golang.org" and not parsed.query:
        return
    if not initial and parsed.hostname == "storage.googleapis.com" and parsed.path.startswith("/proxy-golang-org-prod/"):
        return
    raise CaptureError("Dependency download redirect is outside the official Go proxy/CDN allowlist")


def _download_archive(url, destination, limits, budget):
    """Bounded streaming, explicit redirects and TLS; never inherit proxy auth."""
    _allowed_download_url(url, initial=True)
    deadline = min(budget.deadline, time.monotonic() + limits.request_seconds)
    with _HTTP_CLIENT(follow_redirects=False, trust_env=False, timeout=httpx.Timeout(10)) as client:
        current = url
        for redirects in range(4):
            budget.check()
            _allowed_download_url(current, initial=redirects == 0)
            with client.stream("GET", current, headers={"Accept-Encoding": "identity", "User-Agent": "Lotus-dependency-source-capture/1"}) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    if redirects == 3 or not response.headers.get("location"):
                        raise CaptureError("Dependency download exceeded the redirect budget")
                    current = urljoin(current, response.headers["location"])
                    _allowed_download_url(current)
                    continue
                if response.status_code != 200:
                    raise CaptureError(f"Official Go proxy returned HTTP {response.status_code}")
                if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                    raise CaptureError("Dependency archive uses an unsupported HTTP content encoding")
                length = response.headers.get("content-length")
                if length and (not length.isdigit() or int(length) > limits.archive_bytes):
                    raise CaptureError("Dependency archive exceeds the compressed byte budget")
                size, digest = 0, hashlib.sha256()
                with destination.open("xb") as handle:
                    for chunk in response.iter_raw(chunk_size=65536):
                        budget.check()
                        if time.monotonic() > deadline:
                            raise CaptureError("Dependency download exceeded its request time budget")
                        size += len(chunk)
                        if size > limits.archive_bytes:
                            raise CaptureError("Dependency archive exceeds the compressed byte budget")
                        budget.consume(len(chunk)); digest.update(chunk); handle.write(chunk)
                return {"bytes": size, "sha256": "sha256:" + digest.hexdigest(), "origin": urlsplit(current).hostname}
    raise CaptureError("Dependency download did not return an archive")


def _zip_directory_bound(path, limits):
    """Bound central-directory allocation before ZipFile builds Python objects."""
    size = path.stat().st_size
    if size > limits.archive_bytes:
        raise CaptureError("Dependency archive exceeds the compressed byte budget")
    with path.open("rb") as handle:
        handle.seek(max(0, size - 65557)); tail = handle.read(65557)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise CaptureError("Dependency archive has no bounded ZIP directory")
    end = struct.unpack("<4s4H2LH", tail[offset:offset + 22])
    _, disk, start_disk, disk_count, count, directory_bytes, directory_offset, comment_bytes = end
    if (disk or start_disk or disk_count != count or count == 65535 or count > limits.file_count
            or directory_bytes > 16 * 1024 * 1024 or directory_offset + directory_bytes > size
            or offset + 22 + comment_bytes != len(tail)):
        raise CaptureError("Dependency ZIP directory, ZIP64 or entry count exceeds the supported capture scope")
    return count


def _safe_archive_path(name, prefix, *, root_directory=False):
    if (not name.startswith(prefix) or len(name) > 4096 or "\\" in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        raise CaptureError("Dependency archive entry has an invalid module prefix or path")
    relative = name[len(prefix):].rstrip("/")
    if root_directory and not relative and name == prefix:
        return ""
    parts = relative.split("/")
    if (not relative or any(part in {"", ".", "..", ".git", ".hg", ".svn", ".lotus"}
                           or part.endswith((".", " ")) or ":" in part for part in parts)):
        raise CaptureError("Dependency archive contains an unsafe or reserved source path")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    if any(part.split(".")[0].lower() in reserved for part in parts):
        raise CaptureError("Dependency archive contains a nonportable reserved source path")
    if any(part.lower() == "go.mod" for part in parts) and relative != "go.mod":
        raise CaptureError("Dependency archive contains a nested or mis-cased go.mod")
    return relative


def _extract_archive(path, destination, module, version, limits, budget):
    count = _zip_directory_bound(path, limits)
    prefix = module + "@" + version + "/"
    entries, names, paths, total = [], set(), {}, 0
    with zipfile.ZipFile(path) as archive:
        rows = archive.infolist()
        if len(rows) != count:
            raise CaptureError("Dependency archive entry count differs from its bounded directory")
        for entry in rows:
            budget.check()
            if entry.filename in names or entry.flag_bits & 1 or entry.orig_filename != entry.filename:
                raise CaptureError("Dependency archive has duplicate, truncated or encrypted entries")
            names.add(entry.filename)
            relative = _safe_archive_path(entry.filename, prefix, root_directory=entry.is_dir())
            kind = stat.S_IFMT(entry.external_attr >> 16)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or (kind == stat.S_IFDIR) != entry.is_dir() and kind != 0:
                raise CaptureError("Dependency archive contains a symlink or irregular entry")
            if entry.is_dir() and entry.file_size:
                raise CaptureError("Dependency archive directory contains data")
            parts = relative.split("/") if relative else []
            for index in range(1, len(parts) + 1):
                part = "/".join(parts[:index]); folded = part.casefold()
                directory = index < len(parts) or entry.is_dir()
                previous = paths.get(folded)
                if previous and (previous[0] != part or previous[1] != directory):
                    raise CaptureError("Dependency archive has case-folded or file/directory path collisions")
                paths[folded] = (part, directory)
            total += entry.file_size
            if entry.file_size > limits.file_bytes or total > limits.module_bytes:
                raise CaptureError("Dependency archive exceeds extracted source byte limits")
            if entry.file_size > max(1, entry.compress_size) * limits.compression_ratio:
                raise CaptureError("Dependency archive exceeds the allowed compression ratio")
            entries.append((entry, relative))
        if not entries or not any(not entry.is_dir() for entry, _ in entries):
            raise CaptureError("Dependency archive has no source files")
        destination.mkdir()
        files, summary = [], hashlib.sha256()
        for entry, relative in sorted(entries, key=lambda row: row[0].filename):
            digest, length = hashlib.sha256(), 0
            target = destination / relative
            if not entry.is_dir():
                target.parent.mkdir(parents=True, exist_ok=True)
                output = target.open("xb")
            else:
                output = None
            try:
                with archive.open(entry) as handle:
                    while chunk := handle.read(65536):
                        length += len(chunk)
                        if length > entry.file_size or length > limits.file_bytes:
                            raise CaptureError("Dependency source entry exceeded its recorded length")
                        budget.consume(len(chunk)); digest.update(chunk)
                        if output: output.write(chunk)
                if length != entry.file_size:
                    raise CaptureError("Dependency source entry length is inconsistent")
            finally:
                if output: output.close()
            # Go dirhash.HashZip hashes every ZIP entry by full archive name,
            # including permitted empty directory records, independent of ZIP metadata.
            summary.update((digest.hexdigest() + "  " + entry.filename + "\n").encode("utf-8"))
            if not entry.is_dir():
                files.append({"path": relative, "sha256": "sha256:" + digest.hexdigest(), "bytes": length})
        return "h1:" + base64.b64encode(summary.digest()).decode(), files


def _read_captured(source, names, relative):
    if relative not in names:
        return None
    path = source / relative
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(source):
        raise CaptureError("Dependency declaration is not a confined captured file")
    with path.open("rb") as handle:
        raw = handle.read(MANIFEST_LIMIT + 1)
    if len(raw) > MANIFEST_LIMIT:
        raise CaptureError("Dependency declaration exceeds the 4 MiB parsing budget")
    if _sha(raw) != names[relative]["sha256"]:
        raise CaptureError("Dependency declaration differs from its captured source index")
    return raw


def _go_requests(captured):
    source = Path(captured["source_path"])
    source_index.prepare_source_index(captured)
    _, index, pending = source_index._source_index(captured)
    if pending or index is None:
        raise CaptureError("Dependency capture requires a ready authenticated parent source index")
    names = index["files"]
    requests, gaps, parsed_bytes, omitted = {}, [], 0, 0
    for name in sorted(names):
        basename = PurePosixPath(name).name
        if basename != "go.mod":
            if _is_manifest_name(basename):
                gaps.append({"manifest": name, "reason": "Only exact Go go.mod declarations have an external source capture adapter; other manifests and workspace resolution remain explicit gaps"})
            continue
        try:
            sum_name = str(PurePosixPath(name).parent / "go.sum")
            parse_bytes = names[name]["bytes"] + names.get(sum_name, {}).get("bytes", 0)
            if parsed_bytes + parse_bytes > TOTAL_MANIFEST_LIMIT:
                gaps.append({"manifest": name, "reason": "External dependency capture declaration parsing exceeded 16 MiB; original source remains indexed"})
                continue
            parsed_bytes += parse_bytes
            raw = _read_captured(source, names, name)
            parsed = parse_go_mod(raw.decode("utf-8"))
            gaps.extend({"manifest": name, "reason": reason} for reason in parsed["gaps"])
            sum_raw = _read_captured(source, names, sum_name)
            sums = {}
            for line in (sum_raw.decode("utf-8").splitlines() if sum_raw is not None else []):
                parts = line.split()
                if len(parts) == 3 and re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", parts[2]):
                    sums.setdefault((parts[0], parts[1]), set()).add(parts[2])
                elif parts:
                    gaps.append({"manifest": sum_name, "reason": "Unparsed or unsupported Go checksum entry"})
            for dependency in parsed["dependencies"]:
                module, version = dependency["name"], dependency["version"]
                matches = [item for item in parsed["replacements"] if item["name"] == module and item["version"] in ("", version)]
                if len(matches) > 1:
                    gaps.append({"manifest": name, "name": module, "reason": "Ambiguous replacement requires module graph resolution"});continue
                if matches:
                    replacement = matches[0]
                    if replacement["replacement"].startswith(".") or not replacement["replacement_version"]:
                        gaps.append({"manifest": name, "name": module, "reason": "Local replacement requires captured local source identity"});continue
                    module, version = replacement["replacement"], replacement["replacement_version"]
                try: url = _module_url(module, version)
                except CaptureError as error:
                    gaps.append({"manifest": name, "name": module, "reason": str(error)});continue
                if (module, version) not in requests and len(requests) >= 10000:
                    omitted += 1
                    continue
                row = requests.setdefault((module, version), {"name": module, "version": version, "url": url, "references": [], "expected_h1": set()})
                expected = sums.get((module, version), set())
                row["expected_h1"].update(expected)
                row["references"].append({"manifest": name, "sha256": _sha(raw), "line": dependency["line"],
                    "declared_name": dependency["name"], "declared_version": dependency["version"],
                    "go_sum": sum_name if sum_raw is not None else "", "go_sum_sha256": _sha(sum_raw) if sum_raw is not None else "",
                    "expected_h1": sorted(expected)})
        except (OSError, ValueError, UnicodeError) as error:
            gaps.append({"manifest": name, "reason": str(error)[:300]})
    if omitted:
        gaps.append({"reason": "External source capture exceeded its 10000 unique module preparation bound", "unprepared_declarations": omitted})
    return [{**row, "expected_h1": sorted(row["expected_h1"])} for _, row in sorted(requests.items())], gaps


@source_index.artifact_operation
def verify_capture_bundle(bundle, parent_snapshot, *, verify_files=True):
    """Authenticate metadata and optionally all source bytes before a handoff."""
    bundle = Path(bundle)
    if any(path.is_symlink() for path in (bundle, *bundle.parents)) or not re.fullmatch(r"[a-f0-9]{64}", bundle.name):
        raise CaptureError("Dependency source bundle path is invalid")
    manifest_path = bundle / "manifest.json"
    stamp = manifest_path.stat()
    if manifest_path.is_symlink() or stamp.st_size > RECEIPT_LIMIT:
        raise CaptureError("Dependency source receipt is unsafe or oversized")
    # Metadata-only cache is bounded and invalidates on signing-key rotation,
    # file replacement or byte changes. Selected source bytes are still checked
    # by each window/child reader; no mutable source-file trust is cached here.
    key = (str(bundle), stamp.st_dev, stamp.st_ino, stamp.st_size, stamp.st_mtime_ns, stamp.st_ctime_ns,
           hashlib.sha256(str(proof_receipts._signing_key()).encode()).digest())
    with _METADATA_LOCK:
        cached = _METADATA_CACHE.get(key)
        if cached is not None:
            _METADATA_CACHE.move_to_end(key)
            document, signature, manifest_sha = deepcopy(cached[0]), cached[1], cached[2]
    if cached is None:
        raw = manifest_path.read_bytes(); document = json.loads(raw)
        signature = document.pop("signature", "")
        payload = _canonical(document)
        after = manifest_path.stat()
        if (document.get("schema_version") != 1 or not proof_receipts.verify_blob(payload, signature, purpose=PURPOSE)
                or hashlib.sha256(payload).hexdigest() != bundle.name
                or (stamp.st_dev, stamp.st_ino, stamp.st_size, stamp.st_mtime_ns, stamp.st_ctime_ns) !=
                   (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise CaptureError("Dependency source receipt authentication failed")
        manifest_sha = _sha(raw)
        if len(raw) <= _METADATA_CACHE_BYTES // 4:
            with _METADATA_LOCK:
                _METADATA_CACHE[key] = (deepcopy(document), signature, manifest_sha, len(raw))
                while len(_METADATA_CACHE) > 512 or sum(value[3] for value in _METADATA_CACHE.values()) > _METADATA_CACHE_BYTES:
                    _METADATA_CACHE.popitem(last=False)
    if document.get("parent") != {"tree_hash": parent_snapshot["tree_hash"], "manifest_hash": parent_snapshot["manifest_hash"]}:
        raise CaptureError("Dependency source receipt belongs to a different parent snapshot")
    files = document.get("files")
    if not isinstance(files, list) or not files or len(files) > 65534:
        raise CaptureError("Dependency source receipt inventory is invalid")
    if verify_files:
        source = bundle / "source"
        if source.is_symlink() or not source.is_dir(): raise CaptureError("Dependency source root is unsafe")
        found = {}
        for directory, dirs, names in os.walk(source, followlinks=False):
            if any((Path(directory) / name).is_symlink() for name in dirs + names):
                raise CaptureError("Dependency source tree contains a symlink")
            for name in names:
                path = Path(directory) / name
                with path.open("rb") as handle: digest = "sha256:" + hashlib.file_digest(handle, "sha256").hexdigest()
                found[path.relative_to(source).as_posix()] = {"path": path.relative_to(source).as_posix(), "sha256": digest, "bytes": path.stat().st_size}
        if sorted(found.values(), key=lambda row: row["path"]) != sorted(files, key=lambda row: row["path"]):
            raise CaptureError("Dependency source files differ from their signed inventory")
    return {**document, "signature": signature, "bundle_path": str(bundle), "source_path": str(bundle / "source"), "manifest_sha256": manifest_sha}


def _cached_bundle(request, root, parent):
    key = hashlib.sha256(_canonical({"request": request, "parent": parent})).hexdigest()
    pointer = root / (".request-" + key + ".json")
    if not pointer.exists():
        return pointer, None
    if pointer.is_symlink() or pointer.stat().st_size > 4096:
        raise CaptureError("Dependency source cache index is unsafe")
    document = json.loads(pointer.read_bytes())
    signature = document.pop("signature", "")
    if (document.get("request_hash") != key or not re.fullmatch(r"[a-f0-9]{64}", str(document.get("bundle") or ""))
            or not proof_receipts.verify_blob(_canonical(document), signature, purpose=PURPOSE + "-index")):
        raise CaptureError("Dependency source cache index authentication failed")
    receipt = verify_capture_bundle(root / document["bundle"], parent)
    if (receipt["name"] != request["name"] or receipt["version"] != request["version"]
            or receipt["references"] != request["references"] or receipt["expected_h1"] != request["expected_h1"]):
        raise CaptureError("Dependency source cache differs from the selected declaration")
    return pointer, {**receipt, "reused": True}


def _publish_pointer(pointer, bundle):
    key = pointer.name.removeprefix(".request-").removesuffix(".json")
    document = {"request_hash": key, "bundle": bundle.name}
    encoded = _canonical({**document, "signature": proof_receipts.sign_blob(_canonical(document), purpose=PURPOSE + "-index")})
    fd, temporary = tempfile.mkstemp(prefix=".request-write-", dir=pointer.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, pointer)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def _capture_one(request, root, parent, limits, budget, fetcher):
    budget.check()
    expected = request["expected_h1"]
    if len(expected) > 1: raise CaptureError("Captured Go checksum declarations conflict for this exact module/version")
    pointer, cached = _cached_bundle(request, root, parent)
    if cached is not None:
        return cached
    with tempfile.TemporaryDirectory(prefix=".capture-", dir=root) as temporary:
        stage = Path(temporary); archive = stage / "module.zip"
        download = fetcher(request["url"], archive, limits, budget)
        budget.check()
        observed, files = _extract_archive(archive, stage / "source", request["name"], request["version"], limits, budget)
        if expected and not hmac.compare_digest(expected[0], observed):
            raise CaptureError("Dependency archive h1 does not match the captured go.sum")
        archive.unlink()
        verified = bool(expected) and all(row["expected_h1"] == expected for row in request["references"])
        document = {"schema_version": 1, "parent": parent, "ecosystem": "go", "name": request["name"],
            "version": request["version"], "references": request["references"], "expected_h1": expected,
            "observed_h1": observed, "checksum_status": "verified-go-sum" if verified else "unverified-missing-go-sum",
            "source_status": "captured-external" if verified else "captured-unverified", "review_status": "unverified",
            "download": download, "files": files, "source_files": len(files), "source_bytes": sum(row["bytes"] for row in files),
            "coverage_complete": False, "resolution_status": "declared-versions-only"}
        payload = _canonical(document)
        signature = proof_receipts.sign_blob(payload, purpose=PURPOSE)
        if not signature: raise CaptureError("A stable platform signing key is required for dependency source capture")
        encoded = _canonical({**document, "signature": signature})
        if len(encoded) > RECEIPT_LIMIT: raise CaptureError("Dependency source receipt exceeds its metadata budget")
        (stage / "manifest.json").write_bytes(encoded)
        budget.check()
        destination = root / hashlib.sha256(payload).hexdigest()
        for directory, dirs, names in os.walk(stage):
            for name in names: (Path(directory) / name).chmod(0o444)
        if destination.exists():
            receipt = verify_capture_bundle(destination, parent)
            _publish_pointer(pointer, destination)
            return receipt
        # Atomic publication: no observer sees a partially extracted source.
        try:
            os.rename(stage, destination)
        except OSError as error:
            if error.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                raise
            receipt = verify_capture_bundle(destination, parent)
            _publish_pointer(pointer, destination)
            return receipt
        for directory, dirs, names in os.walk(destination, topdown=False): Path(directory).chmod(0o555)
        receipt = verify_capture_bundle(destination, parent)
        _publish_pointer(pointer, destination)
        return receipt


async def capture_dependency_sources_for_audit(snapshot, output_root, *, enabled, progress=None):
    """Bridge blocking capture to an audit, joining all writers on cancellation.

    Progress is delivered on the audit's event loop, including quiet network
    waits, so lease/pause/cancel controls still run. The pipeline enables this
    only when both Dependency Attack Surface and external capture are selected.
    """
    import asyncio
    if enabled is not True:
        return {"schema_version": 1, "parent": {key: snapshot.get(key) for key in ("tree_hash", "manifest_hash")},
                "status": "disabled", "packages": [], "coverage_complete": False,
                "gaps": [{"reason": "Dependency source capture is not selected in Settings"}]}
    event = threading.Event()
    loop = asyncio.get_running_loop()
    updates = asyncio.Queue()
    worker = asyncio.create_task(asyncio.to_thread(capture_go_dependency_sources, snapshot, output_root,
        cancel_event=event, progress=lambda row: loop.call_soon_threadsafe(updates.put_nowait, row)))
    try:
        while not worker.done() or not updates.empty():
            try:
                update = await asyncio.wait_for(updates.get(), timeout=1)
            except asyncio.TimeoutError:
                update = {"status": "running", "message": "Capturing dependency source; waiting for bounded archive requests"}
            if progress:
                await progress(update)
        return await asyncio.shield(worker)
    finally:
        event.set()
        # Shield the thread's asyncio task, not only its final result. A scan
        # cancellation must not leave a downloader publishing after reset.
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if worker.done() and not worker.cancelled():
            worker.exception()  # retrieve failures even if the progress callback raised


def capture_go_dependency_sources(snapshot, output_root, *, limits=None, progress=None, cancel_event=None, fetcher=None, private_patterns=None):
    """Capture every supported declared Go module, independently of child limits.

    This synchronous boundary is suitable for asyncio.to_thread. Its caller
    must set cancel_event when cancelling that task; active streams check it
    between chunks, and network reads are bounded to ten seconds.
    """
    limits = limits or CaptureLimits()
    limits.validate()
    if not proof_receipts._signing_key():
        raise CaptureError("A stable platform signing key is required for dependency source capture")
    captured = target_snapshots.load_snapshot(str(snapshot.get("path") or ""))
    parent = {"tree_hash": captured["tree_hash"], "manifest_hash": captured["manifest_hash"]}
    if any(snapshot.get(key) != value for key, value in parent.items()):
        raise CaptureError("Dependency capture parent snapshot identity differs")
    source = Path(captured["source_path"])
    root = Path(output_root).expanduser().absolute()
    if root.is_relative_to(source.parent): raise CaptureError("Dependency capture cannot modify the parent snapshot")
    if any(path.is_symlink() for path in [root, *root.parents]):
        raise CaptureError("Dependency capture output traverses a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    requests, gaps = _go_requests(captured)
    event = cancel_event or threading.Event(); budget = _Budget(limits, event)
    patterns = list(private_patterns or []) + [item for item in (os.environ.get("GOPRIVATE", "") + "," + os.environ.get("GONOPROXY", "")).split(",") if item]
    results, pending = {}, {}
    def run(row):
        if any(fnmatch.fnmatchcase(prefix, pattern) for pattern in patterns for prefix in
               ["/".join(row["name"].split("/")[:count]) for count in range(1, len(row["name"].split("/")) + 1)]):
            raise CaptureError("Private dependency source requires an explicitly configured private capture adapter")
        return _capture_one(row, root, parent, limits, budget, fetcher or _download_archive)
    with ThreadPoolExecutor(max_workers=limits.concurrency, thread_name_prefix="lotus-dependency-source") as pool:
        for index, row in enumerate(requests):
            if index >= limits.max_modules:
                results[index] = {"name": row["name"], "version": row["version"], "status": "blocked", "reason": "Declared module count exceeds the capture budget"}
            else: pending[pool.submit(run, row)] = index
        for future in as_completed(pending):
            index = pending[future]; row = requests[index]
            try:
                receipt = future.result()
                results[index] = {"name": row["name"], "version": row["version"], "status": receipt["source_status"],
                    "checksum_status": receipt["checksum_status"], "bundle_path": receipt["bundle_path"],
                    "source_path": receipt["source_path"], "manifest_sha256": receipt["manifest_sha256"],
                    "source_files": receipt["source_files"], "source_bytes": receipt["source_bytes"],
                    "references": row["references"], "review_status": "unverified", "reused": receipt.get("reused", False)}
            except Exception as error:
                results[index] = {"name": row["name"], "version": row["version"], "status": "blocked",
                                  "reason": str(error)[:300] if isinstance(error, CaptureError) else "Dependency capture failed: " + type(error).__name__}
            if progress:
                try:
                    progress({"completed": len(results), "total": len(requests), **results[index]})
                except Exception:
                    if not any(row.get("kind") == "progress-callback" for row in gaps):
                        gaps.append({"kind": "progress-callback", "reason": "Dependency source progress could not be delivered; capture receipts remain available"})
    packages = [results[index] for index in sorted(results)]
    verified = sum(row["status"] == "captured-external" for row in packages)
    unverified = sum(row["status"] == "captured-unverified" for row in packages)
    return {"schema_version": 1, "parent": parent, "status": "not-applicable" if not requests and not gaps else "captured" if verified == len(packages) and packages and not gaps else "partial",
        "packages": packages, "declared_modules": len(requests), "verified_modules": verified,
        "unverified_modules": unverified, "blocked_modules": len(packages) - verified - unverified,
        "gaps": gaps, "limits": asdict(limits), "processed_bytes": budget.used,
        "captured_at": datetime.now(timezone.utc).isoformat(), "coverage_complete": False,
        "resolution_status": "declared-versions-only", "source_scope": "Exact supported Go require/replacement versions in captured go.mod files; this is not a resolved transitive module graph"}
