"""Immutable, content-addressed source snapshots used for audit replay.

The working checkout is intentionally disposable and is cleared when a target
is rescanned.  A proof receipt therefore cannot rely on ``data/repos/<id>``
remaining unchanged.  This module stores a bounded, read-only copy of the
source tree before lab/build side effects and records a manifest that can be
verified before replay.

Snapshots are local by default (``$LOTUS_DATA_DIR/audit_snapshots``).  The
layout is content-addressed and idempotent; an object-store adapter can replace
``snapshot_root`` later without changing the scan/replay contract.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from backend.proof_receipts import content_tree_digest, source_content_files, tracked_source_paths

def _snapshot_limit() -> int:
    """Parse the snapshot quota defensively; a bad env must not stop boot."""
    try:
        value = int(os.environ.get("LOTUS_MAX_SNAPSHOT_BYTES", str(4 * 1024 * 1024 * 1024)))
    except (TypeError, ValueError):
        value = 4 * 1024 * 1024 * 1024
    return max(16 * 1024 * 1024, value)


MAX_SNAPSHOT_BYTES = _snapshot_limit()
MAX_SOURCE_INVENTORY_BYTES = 32 * 1024 * 1024


def _inventory_bytes(files) -> bytes:
    return json.dumps(files, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _write_inventory(root: Path, files: list[str]) -> dict:
    payload = _inventory_bytes(files)
    if len(payload) > MAX_SOURCE_INVENTORY_BYTES or len(files) > 100_000:
        raise ValueError("captured source inventory exceeds its file/metadata budget")
    fd, temporary = tempfile.mkstemp(prefix=".source-files-", dir=root)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.replace(temporary, root / "source-files.json")
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"file": "source-files.json", "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(), "files": len(files)}


def _safe_source_name(name: str) -> Path:
    relative = Path(name)
    if (not name or len(name) > 32768 or relative.is_absolute() or relative.as_posix() != name
            or "\\" in name or any(part in {"..", ".git", ".hg", ".svn", ".lotus"} for part in relative.parts)):
        raise ValueError("snapshot source metadata path is not confined")
    return relative


def _content_targets(names) -> set[str]:
    targets = set(names)
    for name in names:
        targets.update(parent.as_posix() for parent in Path(name).parents if parent.as_posix() != ".")
    return targets


def _read_bound_metadata(source: Path, manifest: dict) -> Optional[dict]:
    descriptor = manifest.get("source_metadata")
    if descriptor is None:
        if manifest.get("source_submodules") is not None or manifest.get("source_capture_status") is not None:
            raise ValueError("snapshot submodules lack captured source metadata")
        return None
    if not isinstance(descriptor, dict) or descriptor.get("file") != "source-metadata.json":
        raise ValueError("snapshot source metadata descriptor is invalid")
    path = source.parent / "source-metadata.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_INVENTORY_BYTES:
        raise ValueError("snapshot source metadata is unavailable or oversized")
    raw = path.read_bytes()
    if "sha256:" + hashlib.sha256(raw).hexdigest() != descriptor.get("sha256"):
        raise ValueError("snapshot source metadata digest mismatch")
    metadata = json.loads(raw)
    if (not isinstance(metadata, dict) or metadata.get("schema_version") != 1
            or not isinstance(metadata.get("files"), dict) or not isinstance(metadata.get("aliases"), dict)
            or len(metadata["files"]) + len(metadata["aliases"]) > 100_000):
        raise ValueError("snapshot source metadata schema or count is invalid")
    for name, mode in metadata["files"].items():
        _safe_source_name(name)
        if type(mode) is not int or not 0 <= mode <= 0o777:
            raise ValueError("snapshot source file mode is invalid")
    content_targets = _content_targets(metadata["files"])
    for name, target in metadata["aliases"].items():
        _safe_source_name(name)
        if not isinstance(target, str):
            raise ValueError("snapshot source alias target is invalid")
        _safe_source_name(target)
        if name in metadata["files"] or target not in content_targets:
            raise ValueError("snapshot source alias does not name captured content")
    submodules = metadata.get("submodules")
    if submodules is not None:
        from backend.submodule_capture import validate_metadata
        if validate_metadata(submodules) != submodules:
            raise ValueError("snapshot submodule metadata is not canonical")
    if manifest.get("source_submodules") != submodules:
        raise ValueError("snapshot submodule projection differs from captured metadata")
    if manifest.get("source_capture_status") != (submodules.get("status") if submodules is not None else None):
        raise ValueError("snapshot capture status differs from captured submodule metadata")
    return metadata


def validate_source_metadata(source: Path, manifest: dict, names=None) -> Optional[dict]:
    """Bind runtime-relevant aliases and executable modes beyond legacy bytes."""
    metadata = _read_bound_metadata(source, manifest)
    if metadata is None:
        return None
    if names is not None and sorted(metadata["files"]) != sorted(names):
        raise ValueError("snapshot source metadata differs from its captured inventory")
    for name, mode in metadata["files"].items():
        path = source / name
        if (path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(source)
                or stat.S_IMODE(path.stat().st_mode) != (0o444 | (mode & 0o111))):
            raise ValueError("snapshot executable mode differs from captured source")
    observed_aliases = {}
    visited = 0
    for directory, dirs, files in os.walk(source, followlinks=False):
        visited += len(dirs) + len(files)
        if visited > 100_000:
            raise ValueError("snapshot source metadata validation exceeds its file limit")
        for name in (*dirs, *files):
            path = Path(directory) / name
            if path.is_symlink():
                expected_target = metadata["aliases"].get(path.relative_to(source).as_posix())
                if expected_target is None:
                    raise ValueError("snapshot contains an uncaptured source alias")
                expected_link = os.path.relpath(source / expected_target, path.parent)
                if os.readlink(path) != expected_link or path.resolve() != (source / expected_target).resolve():
                    raise ValueError("snapshot source alias differs from captured target")
                observed_aliases[path.relative_to(source).as_posix()] = expected_target
    if observed_aliases != metadata["aliases"]:
        raise ValueError("snapshot source alias is missing")
    return metadata


def _require_bound_replay_aliases(source: Path, manifest: dict) -> None:
    if manifest.get("source_metadata") is not None:
        return
    # Legacy regular-file source windows remain readable. Their link targets
    # were never authenticated, so runtime replay requires a fresh capture.
    visited = 0
    for directory, dirs, files in os.walk(source, followlinks=False):
        visited += len(dirs) + len(files)
        if visited > 100_000:
            raise ValueError("legacy snapshot exceeds its source validation limit")
        if any((Path(directory) / name).is_symlink() for name in (*dirs, *files)):
            raise ValueError("legacy snapshot aliases lack captured metadata; recapture the original source before replay")


def source_selection_metadata(source: Path, files: list[Path], *, reject_unsafe: bool = False) -> dict:
    # Snapshot copies retain original modes from their authenticated sidecar;
    # snapshot filesystem modes have deliberately had write bits removed.
    if source.name == "source" and source.parent.parent == snapshot_root():
        manifest_path = source.parent / "snapshot.json"
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text())
            saved = validate_source_metadata(source, manifest, [path.relative_to(source).as_posix() for path in files])
            if saved is not None:
                return saved
            _require_bound_replay_aliases(source, manifest)
    modes = {path.relative_to(source).as_posix(): stat.S_IMODE(path.stat().st_mode) & 0o777 for path in files}
    tracked = tracked_source_paths(source)
    if tracked is None:
        # Local directory enrollments select their safe aliases directly. Git
        # checkouts use only index paths, never newly generated aliases.
        candidates = []
        for directory, dirs, names in os.walk(source, followlinks=False):
            dirs[:] = [name for name in dirs if name not in {".git", ".hg", ".svn", ".lotus", ".lotus_harness", "node_modules", "target", "build", "dist", "out", "coverage", "__pycache__", ".venv", "venv"}]
            candidates.extend((Path(directory) / name).relative_to(source).as_posix() for name in (*dirs, *names))
            if len(candidates) > 100_000:
                raise ValueError("source alias inventory exceeds its file limit")
    else:
        candidates = tracked
    aliases = {}
    content_targets = _content_targets(modes)
    for name in candidates:
        path = source / _safe_source_name(name)
        if not path.is_symlink():
            if reject_unsafe and path.exists() and not path.is_file() and not path.is_dir():
                raise ValueError("source selection contains a special file")
            continue
        resolved = path.resolve()
        if not resolved.is_relative_to(source):
            if reject_unsafe:
                raise ValueError("source selection contains a symlink outside its captured source")
            continue
        target = resolved.relative_to(source).as_posix()
        if target in content_targets:
            aliases[name] = target
    if len(modes) + len(aliases) > 100_000:
        raise ValueError("source metadata exceeds its file limit")
    metadata = {"schema_version": 1, "files": modes, "aliases": aliases}
    from backend.submodule_capture import capture_metadata
    submodules = capture_metadata(source)
    if submodules:
        metadata["submodules"] = submodules
    return metadata


def _metadata_bytes(metadata: dict) -> bytes:
    raw = json.dumps(metadata, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    if len(raw) > MAX_SOURCE_INVENTORY_BYTES:
        raise ValueError("source metadata exceeds its byte limit")
    return raw


def _metadata_descriptor(metadata: dict) -> dict:
    return {"file": "source-metadata.json", "sha256": "sha256:" + hashlib.sha256(_metadata_bytes(metadata)).hexdigest()}


def snapshot_object_key(manifest: dict) -> str:
    tree = str(manifest.get("tree_hash", "")).removeprefix("sha256:")
    descriptor = manifest.get("source_metadata")
    if descriptor is not None:
        if not isinstance(descriptor, dict) or not isinstance(descriptor.get("sha256"), str):
            raise ValueError("snapshot source metadata descriptor is invalid")
        return tree + "-" + descriptor["sha256"].removeprefix("sha256:")
    return tree


def snapshot_files(source: Path, manifest: dict) -> Optional[list[Path]]:
    """Read manifest-bound exact paths; old snapshots keep their legacy policy."""
    selection = manifest.get("source_inventory")
    if selection is None:
        validate_source_metadata(source, manifest)
        return None
    if not isinstance(selection, dict) or selection.get("file") != "source-files.json":
        raise ValueError("snapshot source inventory is invalid")
    path = source.parent / "source-files.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_INVENTORY_BYTES:
        raise ValueError("snapshot source inventory is unavailable or oversized")
    payload = path.read_bytes()
    if "sha256:" + hashlib.sha256(payload).hexdigest() != selection.get("sha256"):
        raise ValueError("snapshot source inventory digest mismatch")
    names = json.loads(payload)
    if (not isinstance(names, list) or len(names) > 100_000 or len(names) != selection.get("files")
            or any(not isinstance(name, str) or not name or len(name) > 32768 for name in names)):
        raise ValueError("snapshot source inventory has invalid paths or count")
    if names != sorted(set(names), key=Path):
        raise ValueError("snapshot source inventory must contain unique sorted paths")
    paths = []
    for name in names:
        relative = Path(name)
        if (relative.is_absolute() or relative.as_posix() != name or "\\" in name
                or any(part in {"..", ".git", ".hg", ".svn", ".lotus"} for part in relative.parts)):
            raise ValueError("snapshot source inventory path is not confined")
        path = source / relative
        if not path.resolve().is_relative_to(source) or path.is_symlink() or not path.is_file():
            raise ValueError("snapshot source inventory file is missing or unsafe")
        paths.append(path)
    validate_source_metadata(source, manifest, names)
    return paths


def managed_snapshot_files(source: Path) -> Optional[list[Path]]:
    """Only controller-managed snapshot paths may change digest selection."""
    base = Path(os.environ.get("LOTUS_DATA_DIR") or Path(__file__).resolve().parent.parent / "data").expanduser().resolve()
    root = base / "audit_snapshots"
    if source.name != "source" or source.parent.parent != root:
        return None
    manifest_path = source.parent / "snapshot.json"
    if not manifest_path.exists():
        return None
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 65536:
        raise ValueError("snapshot manifest is unsafe or oversized")
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("snapshot manifest schema is invalid")
    unsigned = dict(manifest)
    expected = unsigned.pop("manifest_hash", "")
    raw = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if "sha256:" + hashlib.sha256(raw.encode()).hexdigest() != expected:
        raise ValueError("snapshot manifest hash mismatch")
    if source.parent.name != snapshot_object_key(manifest):
        raise ValueError("snapshot object path does not match source identity")
    return snapshot_files(source, manifest)


def copy_source_selection(source: Path, destination: Path, files: list[Path], *, metadata=None) -> None:
    """Copy selected content and manifest-bound safe aliases into writable source."""
    metadata = source_selection_metadata(source, files) if metadata is None else metadata
    destination.mkdir(parents=True, exist_ok=True)
    for path in files:
        relative = path.relative_to(source)
        _safe_source_name(relative.as_posix())
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        os.chmod(target, 0o644 | (metadata["files"][relative.as_posix()] & 0o111))
    for name, resolved in metadata["aliases"].items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(os.path.relpath(destination / resolved, target.parent))


def preserve_checkout_selection(destination: Path, names: list[str], *, metadata: Optional[dict] = None) -> None:
    """Recreate only local tracking metadata for a verified replay/local copy.

    No remotes, history, credentials, templates, hooks or filters are copied
    from the target. This keeps tracked build/dist source distinguishable from
    subsequently generated output for every existing digest/build consumer.
    """
    submodules = (metadata or {}).get("submodules")
    if submodules is not None:
        from backend.submodule_capture import validate_metadata
        submodules = validate_metadata(submodules)
    destination = destination.resolve()
    if (destination / ".git").exists():
        raise ValueError("captured checkout tracking would overwrite existing metadata")
    env = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_TERMINAL_PROMPT": "0"}
    # Keep safe aliases in the index as well as their resolved content paths.
    aliases = [path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_symlink()]
    selected = sorted(set(names + aliases))
    with tempfile.TemporaryDirectory(prefix="lotus-empty-git-template-") as template:
        commands = [
            ["git", "-C", str(destination), "init", "--quiet", "--template=" + template],
            ["git", "--literal-pathspecs", "-C", str(destination), "-c", "core.hooksPath=" + os.devnull,
             "-c", "core.autocrlf=false", "-c", "core.fsmonitor=false", "add", "--force",
             "--pathspec-from-file=-", "--pathspec-file-nul"],
        ]
        for index, command in enumerate(commands):
            if index and not selected:
                continue
            result = subprocess.run(command, input=b"\0".join(name.encode() for name in selected) + b"\0" if index else None,
                                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
            if result.returncode:
                raise ValueError("could not preserve captured source file tracking")
    if submodules is not None:
        from backend.submodule_capture import preserve_metadata
        preserve_metadata(destination, submodules)


def snapshot_root() -> Path:
    root = (os.environ.get("LOTUS_DATA_DIR") or "").strip()
    base = Path(root).expanduser() if root else Path(__file__).resolve().parent.parent / "data"
    path = (base / "audit_snapshots").resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_key(value: str) -> str:
    raw = str(value or "")
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw)[:200] or "unknown"


def _tree_size(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            total += int(path.stat().st_size)
        except OSError:
            continue
        if total > MAX_SNAPSHOT_BYTES:
            break
    return total


def _copy_ignore(directory: str, names: list[str]) -> list[str]:
    # VCS metadata and platform/build output are excluded from the immutable
    # source object; ``content_tree_digest`` uses the same policy.
    excluded = {
        ".git", ".hg", ".svn", ".lotus", ".lotus_harness", "node_modules",
        "target", "build", "dist", "out", "coverage", "__pycache__",
        ".pytest_cache", ".mypy_cache", ".tox", ".venv", "venv",
    }
    return [name for name in names if name in excluded or name.endswith(".pyc")]


def _make_writable(path: Path) -> None:
    """Make a stale snapshot removable without changing its contents."""
    if path.is_symlink():
        return
    try:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    except OSError:
        pass


def _remove_snapshot_tree(path: Path) -> None:
    """Remove an incomplete object, including objects made read-only."""
    if not path.exists() and not path.is_symlink():
        return
    if path.is_dir() and not path.is_symlink():
        for child in sorted(path.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            _make_writable(child)
        _make_writable(path)
        shutil.rmtree(path, ignore_errors=True)
    else:
        _make_writable(path)
        try:
            path.unlink()
        except OSError:
            pass


def _manifest_for_tree(*, repo_id: int, job_id: int, tree_hash: str, revision: str, payload: Path,
                       files: Optional[list[str]] = None, metadata: Optional[dict] = None) -> Dict[str, Any]:
    manifest: Dict[str, Any] = {
        "schema_version": 1,
        "repo_id": int(repo_id),
        "job_id": int(job_id),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tree_hash": tree_hash,
        "target_revision": revision,
        "bytes": _tree_size(payload),
        "source_relpath": "source",
    }
    if files is not None:
        manifest["source_inventory"] = _write_inventory(payload.parent, files)
    if metadata is not None:
        (payload.parent / "source-metadata.json").write_bytes(_metadata_bytes(metadata))
        manifest["source_metadata"] = _metadata_descriptor(metadata)
        if metadata.get("submodules") is not None:
            from backend.submodule_capture import validate_metadata
            manifest["source_submodules"] = validate_metadata(metadata["submodules"])
            manifest["source_capture_status"] = manifest["source_submodules"]["status"]
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    manifest["manifest_hash"] = "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return manifest


def _persist_immutable_manifest(root: Path, manifest: Dict[str, Any]) -> None:
    """Write and lock a manifest after the source tree has been verified."""
    root = Path(root)
    _make_writable(root)
    (root / "snapshot.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    # Make the object immutable to the application user. Parent/root
    # permissions remain writable so retention tooling can remove objects.
    for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_symlink():
            continue
        executable = stat.S_IMODE(path.stat().st_mode) & 0o111
        _make_writable(path)
        try:
            os.chmod(path, 0o555 if path.is_dir() else 0o444 | executable)
        except OSError:
            pass
    try:
        os.chmod(root, 0o555)
    except OSError:
        pass


def _verified_existing(final: Path, observed_hash: str) -> Optional[Dict[str, Any]]:
    """Return a verified object, or ``None`` for a stale/incomplete object."""
    manifest_path = final / "snapshot.json"
    source = final / "source"
    if not final.is_dir() or not manifest_path.is_file() or not source.is_dir():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema_version") != 1 or manifest.get("tree_hash") != observed_hash:
            return None
        if content_tree_digest(source) != observed_hash:
            return None
        unsigned = dict(manifest)
        expected = str(unsigned.pop("manifest_hash") or "")
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if expected != "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest():
            return None
        return {**manifest, "path": str(final), "source_path": str(source)}
    except Exception:
        return None


def create_snapshot(
    source: Path,
    *,
    repo_id: int,
    job_id: int,
    target_identity: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create or reuse a verified source snapshot and return its metadata.

    The copy is first created in a sibling temporary directory, hashed, then
    atomically renamed into its content-addressed location.  A partially
    copied tree is never exposed as replayable.  If the source exceeds the
    configured limit, the operation fails closed with a concrete reason.
    """
    source = Path(source).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"snapshot source is not a directory: {source}")
    selected = source_content_files(source)
    if len(selected) > 100_000:
        raise ValueError("captured source inventory exceeds its file limit")
    names = [path.relative_to(source).as_posix() for path in selected]
    metadata = source_selection_metadata(source, selected)
    size = sum(path.stat().st_size for path in selected)
    if size > MAX_SNAPSHOT_BYTES:
        raise ValueError(f"source tree exceeds snapshot limit ({size} > {MAX_SNAPSHOT_BYTES} bytes)")
    observed_hash = content_tree_digest(source)
    if not observed_hash:
        raise ValueError("source tree digest could not be computed")
    expected_hash = str((target_identity or {}).get("target_tree_hash") or "").strip()
    if expected_hash and expected_hash != observed_hash:
        raise ValueError(
            f"source changed before snapshot (expected {expected_hash}, observed {observed_hash})"
        )
    revision = str((target_identity or {}).get("target_revision") or "").strip()
    key = snapshot_object_key({"tree_hash": observed_hash, "source_metadata": _metadata_descriptor(metadata)})
    final = snapshot_root() / key

    existing = _verified_existing(final, observed_hash)
    if existing:
        return existing
    # A prior process can die after copying ``source/`` but before writing the
    # manifest. If that tree is complete and has the expected digest, finalize
    # it in place instead of attempting to rename over a non-empty directory.
    stale_source = final / "source"
    if stale_source.is_dir():
        try:
            if content_tree_digest(stale_source, files=names) == observed_hash:
                repaired = _manifest_for_tree(
                    repo_id=repo_id, job_id=job_id, tree_hash=observed_hash,
                    revision=revision, payload=stale_source, files=names, metadata=metadata,
                )
                _persist_immutable_manifest(final, repaired)
                existing = _verified_existing(final, observed_hash)
                if existing:
                    return existing
        except Exception:
            pass
    # Any remaining object is incomplete/corrupt. Remove it before the atomic
    # install below; leaving it in place causes ``rename`` to fail with
    # ``Directory not empty`` on macOS and Linux alike.
    if final.exists():
        _remove_snapshot_tree(final)

    tmp = Path(tempfile.mkdtemp(prefix=f"lotus-snapshot-{repo_id}-", dir=str(snapshot_root())))
    try:
        payload = tmp / "source"
        copy_source_selection(source, payload, selected, metadata=metadata)
        copied_hash = content_tree_digest(payload, files=names)
        if (copied_hash != observed_hash or content_tree_digest(source) != observed_hash
                or source_selection_metadata(source, selected) != metadata):
            raise ValueError(f"snapshot digest mismatch (copied {copied_hash}, source {observed_hash})")
        manifest = _manifest_for_tree(
            repo_id=repo_id, job_id=job_id, tree_hash=observed_hash,
            revision=revision, payload=payload, files=names, metadata=metadata,
        )
        _persist_immutable_manifest(tmp, manifest)
        try:
            tmp.rename(final)
        except FileExistsError:
            # Another worker may have won the content-addressed install. Use
            # its verified object; otherwise remove the stale winner and retry
            # once so a crash-left directory cannot strand this snapshot.
            winner = _verified_existing(final, observed_hash)
            if winner:
                _remove_snapshot_tree(tmp)
                return winner
            _remove_snapshot_tree(final)
            try:
                tmp.rename(final)
            except FileExistsError:
                winner = _verified_existing(final, observed_hash)
                if winner:
                    _remove_snapshot_tree(tmp)
                    return winner
                raise
        return {**manifest, "path": str(final), "source_path": str(final / "source")}
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def load_snapshot(path_or_key: str) -> Dict[str, Any]:
    """Resolve and verify a snapshot metadata object without path traversal."""
    raw = str(path_or_key or "").strip()
    if not raw:
        raise FileNotFoundError("snapshot path is empty")
    candidate = Path(raw)
    root = snapshot_root()
    if not candidate.is_absolute():
        candidate = root / _safe_key(raw)
    candidate = candidate.resolve()
    # Transitional manifests sometimes persisted ``source_path`` rather than
    # the object root.  Normalize that form before checking the manifest so a
    # valid snapshot cannot be reported as missing merely because its source
    # subdirectory was stored.  The containment check below still prevents
    # traversal outside the content-addressed root.
    if candidate.name == "source" and candidate.parent.is_dir():
        candidate = candidate.parent
    if candidate != root and root not in candidate.parents:
        raise ValueError("snapshot path escapes snapshot root")
    manifest_path = candidate / "snapshot.json"
    source = candidate / "source"
    if manifest_path.is_symlink() or source.is_symlink() or not manifest_path.is_file() or not source.is_dir():
        raise FileNotFoundError("snapshot object is incomplete")
    if manifest_path.stat().st_size > 65536:
        raise ValueError("snapshot manifest exceeds the metadata size limit")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("unsupported snapshot schema")
    expected = str(manifest.get("manifest_hash") or "")
    unsigned = dict(manifest)
    unsigned.pop("manifest_hash", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if expected != "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest():
        raise ValueError("snapshot manifest hash mismatch")
    if candidate.name != snapshot_object_key(manifest):
        raise ValueError("snapshot object path does not match source identity")
    validate_source_metadata(source, manifest)
    _require_bound_replay_aliases(source, manifest)
    observed = content_tree_digest(source)
    if observed != str(manifest.get("tree_hash") or ""):
        raise ValueError("snapshot content hash mismatch")
    return {**manifest, "path": str(candidate), "source_path": str(source)}
