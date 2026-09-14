"""Platform reset operations backing the Debug page reset buttons.

Two scopes, both of which ALWAYS PRESERVE the platform default skills
(the lotus-core doctrine: methodology / discovery / gating / bug-classes /
packs). Those skill directories ship only on disk in this deployment, so
deleting them would be unrecoverable - they are never touched by any reset.

  * ``full`` - factory reset for a fresh deployment. Wipes ALL database rows
    (audit DATA *and* configuration), learned skills + their revisions +
    the learned pattern DB, skill/pack enable-state, credential/tool-state
    config files, and caller-specified backup archives. Afterwards only the
    default skills remain and a clean default configuration row is recreated -
    i.e. the exact state of a brand-new install.

  * ``data`` - wipes audit DATA (including snapshots, corpora, measurements,
    report/notebook history and backup archives). PRESERVES the
    default skills, the learned skills (+ revisions + pattern DB), and ALL
    configuration (settings, notification settings, credential backup, and
    skill/pack/tool enable-state).

Everything is path- and DB-injectable so the behaviour can be exercised in
tests against a throwaway sandbox without touching real platform data.
"""
from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

FULL = "full"
DATA = "data"
VALID_SCOPES = (FULL, DATA)

# Skill subdirectories that make up the platform default doctrine. These are
# NEVER removed by any reset - preserving them is the core requirement, and
# since this repo ships them only on disk their loss would be unrecoverable.
DEFAULT_SKILL_DIRS = ("methodology", "discovery", "gating", "bug-classes", "packs")
AUDIT_ARTIFACT_SUBDIRS = (
    "repos", "audit_snapshots", "dependency_sources", "e2e_targets", "gateway_targets", "agent_app_targets",
    "discovery_measurements", "eval_snapshots", "fuzz_corpus", "reports", "artifacts", "harness",
    "notebook_runtimes", "replay_runtime", "runtime_resource_receipts", "scanner_tmp",
)

# Learned / compounding knowledge, relative to the skills home. Removed only by
# a full (factory) reset.
LEARNED_ENTRIES = ("learned", ".revisions", "pattern_db.json")

# Skill / pack enable-state files = configuration. Removed only by a full reset.
SKILL_STATE_FILES = ("skills_state.json", "packs_state.json", "external_packs.json")


def _rm(path: Path) -> bool:
    """Remove a file or directory tree. Returns True if something was removed.

    Never raises - a reset must make best-effort progress even if one path is
    locked or already gone.
    """
    try:
        if path.is_symlink():
            path.unlink(missing_ok=True)
            return not path.exists()
        if path.is_dir():
            # Snapshot objects are intentionally read-only so a proof receipt
            # cannot be silently changed.  ``rmtree(ignore_errors=True)``
            # leaves those objects behind on platforms that refuse to unlink
            # read-only files, which would make Reset Platform report a
            # partial success.  Make only the reset target writable and retry
            # failed removals; symlinks are still handled above and are never
            # traversed.
            reset_root = path.absolute()
            resolved_root = reset_root.resolve()

            def _make_writable(candidate):
                candidate = Path(candidate).absolute()
                # Unlinking requires a writable parent directory. Grant access
                # only inside this reset target, never to its parent or to a
                # symlink destination outside the selected artifact tree.
                try:
                    candidate.relative_to(reset_root)
                    candidate.resolve().relative_to(resolved_root)
                    mode = candidate.lstat().st_mode
                    if stat.S_ISLNK(mode):
                        return
                    owner_access = stat.S_IRUSR | stat.S_IWUSR
                    if stat.S_ISDIR(mode):
                        owner_access |= stat.S_IXUSR
                    os.chmod(candidate, stat.S_IMODE(mode) | owner_access, follow_symlinks=False)
                except (OSError, ValueError, NotImplementedError):
                    pass

            def _onerror(function, failed_path, exc_info):  # Python 3.9 API
                _make_writable(Path(failed_path).parent)
                _make_writable(failed_path)
                try:
                    function(failed_path)
                except Exception:
                    pass

            shutil.rmtree(path, onerror=_onerror)
            return not path.exists()
        if path.exists():
            path.unlink(missing_ok=True)
            return not path.exists()
    except Exception:
        pass
    return False


def _remove_and_record(path: Path, summary: Dict[str, Any], *, label: str) -> None:
    """Remove one reset target and distinguish absent from failed cleanup.

    ``shutil.rmtree(..., ignore_errors=True)`` is deliberately best-effort for
    cross-platform operation, but silently ignoring a permission/lock failure
    would let the API report a clean reset while stale audit material remains.
    Record a concrete error whenever a path existed and is still present after
    the removal attempt.
    """
    existed = path.exists() or path.is_symlink()
    removed = _rm(path)
    still_present = path.exists() or path.is_symlink()
    if removed and not still_present:
        summary["paths_removed"].append(str(path))
    elif existed and still_present:
        summary["errors"].append(f"could not remove {label}: {path}")


def _safe_child(root: Path, child: str, *, label: str) -> Optional[Path]:
    """Resolve a reset child while refusing traversal and symlink escapes."""
    if not child or Path(child).name != child or child in {".", ".."}:
        return None
    try:
        root_resolved = root.resolve()
        candidate = (root / child)
        # A symlink is removed as a link, never traversed.  For ordinary paths,
        # require the resolved parent to remain the injected data root.
        if candidate.is_symlink():
            return candidate
        if candidate.resolve().parent != root_resolved:
            return None
        return candidate
    except Exception:
        return None


def _safe_extra_path(path: Path, *, data_dir: Path, skills_dir: Path) -> bool:
    """Reject catastrophic full-reset targets (root/cwd/home/data/skills).

    ``full_reset_paths`` is an explicit internal extension point used for
    configured backup archives.  Keep it injectable for tests while ensuring a
    malformed environment variable can never turn a factory reset into a
    workspace/home/root deletion.
    """
    try:
        resolved = path.resolve()
        protected = {
            Path("/").resolve(),
            Path.cwd().resolve(),
            Path.home().resolve(),
            data_dir.resolve(),
            skills_dir.resolve(),
        }
        # A one-level path such as ``/tmp`` is too broad to be a backup root.
        default_roots = [(skills_dir / name).resolve() for name in DEFAULT_SKILL_DIRS]
        return (len(resolved.parts) >= 3
                and not any(resolved == root or resolved in root.parents for root in protected)
                and not any(resolved == root or root in resolved.parents for root in default_roots))
    except Exception:
        return False


def _clear_tables(session, models: Sequence[Any], summary: Dict[str, Any], *, recreate=()) -> bool:
    pending = {}
    try:
        for model in models:
            name = getattr(model, "__tablename__", str(model))
            n = session.query(model).delete()
            pending[name] = int(n or 0)
        for model in recreate:
            session.add(model())
        session.commit()
    except Exception as e:
        summary["errors"].append(f"database reset rolled back: {e}")
        session.rollback()
        return False
    summary["rows_deleted"].update(pending)
    return True


def perform_reset(
    scope: str,
    *,
    session_factory: Callable[[], Any],
    data_models: Sequence[Any],
    config_models: Sequence[Any],
    data_dir: Path,
    skills_dir: Path,
    credentials_paths: Sequence[Path] = (),
    tool_state_path: Optional[Path] = None,
    # Keep snapshots in the default audit-data set.  Callers may still pass a
    # narrower list for compatibility/ephemeral operations, but a normal
    # reset must not leave source material or replay receipts behind.
    repo_artifact_subdirs: Sequence[str] = AUDIT_ARTIFACT_SUBDIRS,
    audit_reset_paths: Sequence[Path] = (),
    full_reset_paths: Sequence[Path] = (),
    recreate_config_defaults: bool = True,
    log: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Execute a platform reset of the given ``scope``.

    Args:
        scope: ``"full"`` (factory reset) or ``"data"`` (audit data only).
        session_factory: zero-arg callable returning a DB session.
        data_models: ORM classes holding audit DATA (repos, findings, ...).
        config_models: ORM classes holding CONFIGURATION (settings, ...).
        data_dir: platform data directory (holds cloned-repo artifacts).
        skills_dir: platform skills home (holds default + learned skills).
        credentials_paths: credential backup files to delete on a full reset.
        tool_state_path: tool enable-state file to delete on a full reset.
        repo_artifact_subdirs: subdirs of ``data_dir`` that are audit artifacts.
        audit_reset_paths: configured audit/backup roots removed in both scopes.
        full_reset_paths: additional files/directories removed only by a full
            reset (for example, backup archives in a configured external path).
        recreate_config_defaults: after a full wipe, re-add one default row per
            config model so the UI opens on a clean-install baseline.
        log: optional message sink.

    Returns a summary dict describing exactly what was cleared and preserved.
    """
    if scope not in VALID_SCOPES:
        raise ValueError(f"invalid reset scope {scope!r}; expected one of {VALID_SCOPES}")
    data_dir = Path(data_dir)
    skills_dir = Path(skills_dir)
    summary: Dict[str, Any] = {
        "scope": scope,
        "rows_deleted": {},
        "paths_removed": [],
        "preserved": [],
        "errors": [],
    }

    # Validate the complete destructive scope before touching the database.
    # A malformed configured backup/checkout root must not erase audit rows
    # and only then discover that the corresponding files cannot be removed.
    for sub in repo_artifact_subdirs:
        child = _safe_child(data_dir, str(sub), label="repository artifact")
        if child is None or not _safe_extra_path(child, data_dir=data_dir, skills_dir=skills_dir):
            summary["errors"].append(f"refusing unsafe repository artifact path: {sub!r}")
    candidates = [(p, "audit-reset") for p in audit_reset_paths]
    if scope == FULL:
        candidates.extend((p, "full-reset") for p in full_reset_paths)
        candidates.extend((p, "credential") for p in credentials_paths)
        if tool_state_path is not None:
            candidates.append((tool_state_path, "tool-state"))
    for p, label in candidates:
        if not _safe_extra_path(Path(p), data_dir=data_dir, skills_dir=skills_dir):
            summary["errors"].append(f"refusing unsafe {label} path: {p}")
    if summary["errors"]:
        return summary

    # 1) Database rows -------------------------------------------------------
    db = session_factory()
    try:
        models = list(data_models) + (list(config_models) if scope == FULL else [])
        recreate = config_models if scope == FULL and recreate_config_defaults else ()
        if not _clear_tables(db, models, summary, recreate=recreate):
            return summary
    finally:
        try:
            db.close()
        except Exception:
            pass

    # 2) Cloned-repo artifacts (audit DATA - removed in BOTH scopes) ---------
    for sub in repo_artifact_subdirs:
        p = _safe_child(data_dir, str(sub), label="repository artifact")
        if p is None:
            summary["errors"].append(f"refusing unsafe repository artifact path: {sub!r}")
            continue
        _remove_and_record(p, summary, label="repository artifact")

    for extra in audit_reset_paths:
        p = Path(extra)
        if not _safe_extra_path(p, data_dir=data_dir, skills_dir=skills_dir):
            summary["errors"].append(f"refusing unsafe audit-reset path: {p}")
            continue
        _remove_and_record(p, summary, label="audit/backup path")

    # 3) Full-reset-only removals: learned knowledge + config state/files ----
    if scope == FULL:
        for extra in full_reset_paths:
            p = Path(extra)
            if not _safe_extra_path(p, data_dir=data_dir, skills_dir=skills_dir):
                summary["errors"].append(f"refusing unsafe full-reset path: {p}")
                continue
            _remove_and_record(p, summary, label="full-reset path")
        for name in (*LEARNED_ENTRIES, *SKILL_STATE_FILES, "skills_state.json.lock", "packs_state.json.lock"):
            p = skills_dir / name
            _remove_and_record(p, summary, label="learned/configuration path")
        for cred in credentials_paths:
            p = Path(cred)
            if not _safe_extra_path(p, data_dir=data_dir, skills_dir=skills_dir):
                summary["errors"].append(f"refusing unsafe credential path: {p}")
                continue
            _remove_and_record(p, summary, label="credential path")
        if tool_state_path is not None:
            p = Path(tool_state_path)
            if not _safe_extra_path(p, data_dir=data_dir, skills_dir=skills_dir):
                summary["errors"].append(f"refusing unsafe tool-state path: {p}")
            else:
                _remove_and_record(p, summary, label="tool-state path")

    # 4) Record what was intentionally preserved -----------------------------
    for name in DEFAULT_SKILL_DIRS:
        p = skills_dir / name
        if p.exists():
            summary["preserved"].append(str(p))
    if scope == DATA:
        for name in (*LEARNED_ENTRIES, *SKILL_STATE_FILES):
            p = skills_dir / name
            if p.exists():
                summary["preserved"].append(str(p))

    if log:
        try:
            log(
                f"Platform reset ({scope}): cleared "
                f"{sum(summary['rows_deleted'].values())} DB row(s) across "
                f"{len(summary['rows_deleted'])} table(s), removed "
                f"{len(summary['paths_removed'])} path(s), preserved "
                f"{len(summary['preserved'])} skill path(s)."
            )
        except Exception:
            pass
    return summary
