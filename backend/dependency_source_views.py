"""Exact-audit views of separately captured dependency source bundles.

Virtual paths are catalogued, never translated to arbitrary filesystem paths.
Only bundles registered in this audit's output and authenticated against its
parent snapshot can participate. Capture/checksum/review remain distinct.
"""
from pathlib import Path
import re

from backend import source_index
from backend.dependency_source_capture import CaptureError, verify_capture_bundle

PREFIX = "@dependencies/"


def registered_bundles(snapshot: dict, capture: dict | None, *, verify_files=False, selected_key=""):
    if not capture:
        return
    if (not isinstance(capture, dict) or capture.get("parent") !=
            {key: snapshot.get(key) for key in ("tree_hash", "manifest_hash")}):
        raise CaptureError("Dependency source registration belongs to another audit snapshot")
    rows = capture.get("packages")
    if not isinstance(rows, list) or len(rows) > 10000:
        raise CaptureError("Dependency source registration inventory is invalid")
    seen = set()
    for row in sorted(rows, key=lambda value: (str(value.get("name", "")), str(value.get("version", ""))) if isinstance(value, dict) else ("", "")):
        if not isinstance(row, dict):
            raise CaptureError("Dependency source registration row is invalid")
        if row.get("status") not in {"captured-external", "captured-unverified"}:
            continue
        if selected_key and Path(str(row.get("bundle_path") or "")).name != selected_key:
            continue
        receipt = verify_capture_bundle(row.get("bundle_path") or "", snapshot, verify_files=verify_files)
        if any(row.get(key) != receipt.get(key) for key in ("name", "version", "manifest_sha256")):
            raise CaptureError("Dependency source registration differs from its authenticated receipt")
        if row["status"] != receipt["source_status"]:
            raise CaptureError("Dependency source registration checksum status differs")
        key = Path(receipt["bundle_path"]).name
        if key not in seen:
            seen.add(key)
            yield receipt


def bundle_root(receipt: dict) -> str:
    return PREFIX + Path(receipt["bundle_path"]).name


def bundle_context(receipt: dict) -> dict:
    return {"source_kind": "dependency-bundle", "dependency_name": receipt["name"],
            "dependency_version": receipt["version"], "dependency_bundle": Path(receipt["bundle_path"]).name,
            "dependency_manifest_sha256": receipt["manifest_sha256"], "checksum_status": receipt["checksum_status"],
            "review_status": "unverified", "source_root": bundle_root(receipt)}


def audit_source_catalog(snapshot: dict, capture: dict | None, *, query="", offset=0, limit=200) -> dict:
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 500 or len(query) > 1024:
        raise ValueError("source catalog requires offset>=0, limit 1..500 and query<=1024 characters")
    meta, index, pending = source_index._source_index(snapshot)
    if pending:
        return pending
    files, roots, matched, total, total_bytes = [], [], 0, 0, 0
    needle = query.casefold()

    def include(path, entry, context):
        nonlocal total, total_bytes, matched
        total += 1
        total_bytes += entry["bytes"]
        searchable = path + " " + context.get("dependency_name", "") + " " + context.get("dependency_version", "")
        if needle not in searchable.casefold():
            return
        if offset <= matched < offset + limit:
            files.append({"path": path, "sha256": entry["sha256"], "bytes": entry["bytes"], **context})
        matched += 1

    for name in sorted(index["files"]):
        include(name, index["files"][name], {"source_kind": "immutable-snapshot"})
    for receipt in registered_bundles(snapshot, capture):
        context = bundle_context(receipt)
        roots.append({**context, "files": receipt["source_files"], "bytes": receipt["source_bytes"]})
        for entry in sorted(receipt["files"], key=lambda row: row["path"]):
            virtual = bundle_root(receipt) + "/" + entry["path"]
            if virtual in index["files"]:
                raise source_index.SourceChanged("Repository source collides with a reserved dependency catalog path")
            include(virtual, entry, context)
    return {"status": "ready", "tree_hash": meta["tree_hash"], "manifest_hash": meta["manifest_hash"],
            "total_files": total, "total_bytes": total_bytes, "repository_files": len(index["files"]),
            "dependency_files": total - len(index["files"]), "dependency_roots": roots,
            "matched_files": matched, "offset": offset, "limit": limit,
            "next_offset": offset + limit if offset + limit < matched else None, "files": files,
            "coverage_basis": "Captured source and declared checksums; indexing is not completed review or transitive resolution"}


def dependency_source_window(snapshot: dict, capture: dict | None, relative: str, **kwargs) -> dict:
    _, index, pending = source_index._source_index(snapshot)
    if pending:
        return pending
    if relative in index["files"]:
        return source_index.source_window(snapshot, relative, **kwargs)
    match = re.fullmatch(r"@dependencies/([a-f0-9]{64})/(.+)", relative)
    if not match:
        raise FileNotFoundError("Dependency file is not in this audit's registered source catalog")
    key, name = match.groups()
    for receipt in registered_bundles(snapshot, capture, selected_key=key):
        if Path(receipt["bundle_path"]).name != key:
            continue
        entry = next((row for row in receipt["files"] if row["path"] == name), None)
        if entry is None:
            break
        result = source_index.indexed_source_window(
            {"path": receipt["bundle_path"], "source_path": receipt["source_path"]}, name, entry,
            display_relative=relative, **kwargs)
        return {**result, **bundle_context(receipt),
                "verification_scope": "selected file authenticated against a signed dependency bundle bound to this audit snapshot"}
    raise FileNotFoundError("Dependency file is not in this audit's registered source catalog")
