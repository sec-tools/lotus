"""Cross-audit memory: DISPROVE graveyard + retrospective lab hints.

Learned markdown is written at the end of scans. Same-source observations help
review the next audit, but never suppress a fresh lead or supply launch commands.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend import skills as skills_mod

_FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---", re.S)
MAX_LEARNED_ENTRIES = 2000
MAX_LEARNED_FILES = 100
MAX_LEARNED_FILE_BYTES = 64 * 1024
MAX_LEARNED_TOTAL_BYTES = 2 * 1024 * 1024


def _learned_dir() -> Path:
    try:
        return skills_mod.get_learned_dir()
    except Exception:
        return Path(skills_mod.SKILLS_DIR) / "learned"


def _parse_frontmatter(text: str) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    m = _FRONTMATTER.search(text or "")
    if not m:
        return meta
    for line in m.group(1).splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if val.startswith("[") or val.startswith("{"):
            try:
                meta[key] = json.loads(val)
                continue
            except Exception:
                pass
        meta[key] = val
    return meta


def _iter_learned() -> List[Tuple[Path, Dict[str, Any], str]]:
    """Read a bounded advisory sample, without following filesystem links.

    The directory descriptor pins the root across renames. Entry/file budgets
    deliberately make this a sample rather than a claim of exhaustive history.
    """
    d = _learned_dir()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        directory_fd = os.open(d, flags)
    except OSError:
        return []
    out: List[Tuple[Path, Dict[str, Any], str]] = []
    total_bytes = 0
    try:
        candidates = []
        with os.scandir(directory_fd) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_LEARNED_ENTRIES:
                    break
                if not entry.name.endswith(".md"):
                    continue
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode) and info.st_size <= MAX_LEARNED_FILE_BYTES:
                    candidates.append((info.st_mtime_ns, entry.name))
        for _, name in sorted(candidates, reverse=True)[:MAX_LEARNED_FILES]:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                with os.fdopen(fd, "rb") as handle:
                    info = os.fstat(handle.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_LEARNED_FILE_BYTES:
                        continue
                    payload = handle.read(MAX_LEARNED_FILE_BYTES + 1)
                if len(payload) > MAX_LEARNED_FILE_BYTES:
                    continue
                if total_bytes + len(payload) > MAX_LEARNED_TOTAL_BYTES:
                    break
                total_bytes += len(payload)
                text = payload.decode("utf-8")
            except (OSError, UnicodeError):
                continue
            out.append((d / name, _parse_frontmatter(text), text))
    finally:
        os.close(directory_fd)
    return out


def _norm(title: str) -> str:
    s = (title or "").lower()
    s = re.sub(r"^(disprove|skill)[:\s—\-]+", "", s)
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return " ".join(s.split())


def titles_match(a: str, b: str) -> bool:
    """True when two finding titles are the same recycled hypothesis."""
    na, nb = _norm(a), _norm(b)
    if len(na) < 8 or len(nb) < 8:
        return False
    if na == nb or na in nb or nb in na:
        return True
    ta, tb = set(na.split()), set(nb.split())
    if not ta or not tb:
        return False
    return len(ta & tb) / len(ta | tb) >= 0.65


def load_disprove_records(language: Optional[str] = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path, meta, text in _iter_learned():
        qual = str(meta.get("qualification") or "").upper()
        if qual != "DISPROVE" and "DISPROVE" not in (meta.get("title") or "") and "# Skill: DISPROVE" not in text:
            continue
        lang = str(meta.get("language") or "unknown")
        if language and lang not in ("unknown", language) and language not in lang:
            # Still include unscoped DISPROVE; skip only obvious other-language misses
            if lang not in ("", "unknown") and language.split("/")[0] not in lang:
                continue
        title = str(meta.get("title") or path.stem)
        rows.append({
            "title": title,
            "language": lang,
            "source_repo": meta.get("source_repo") or "",
            "verdict": meta.get("verdict") or "DISPROVE",
            "path": str(path),
        })
    return rows


def load_retrospective_hints(language: Optional[str] = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path, meta, text in _iter_learned():
        if str(meta.get("qualification") or "").upper() != "RETROSPECTIVE":
            continue
        lang = str(meta.get("language") or "unknown")
        if language and lang not in ("unknown", "", language) and language not in lang:
            if lang.split("/")[0] != (language or "").split("/")[0]:
                continue
        rows.append({
            "lab_strategy": meta.get("lab_strategy") or "",
            "language": lang,
            "source_repo": str(meta.get("source_repo") or ""),
            "path": str(path),
            "excerpt": text[:2000],
        })
    return rows


def graveyard_entries(
    language: Optional[str] = None,
    repo_source: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Historical disproof annotations; never seed automatic rejection with them."""
    entries: List[Dict[str, Any]] = []
    seen = set()
    repo_l = str(repo_source or "").strip().rstrip("/")
    for rec in load_disprove_records(language):
        title = rec.get("title") or ""
        key = _norm(title)
        if not key or key in seen:
            continue
        src = str(rec.get("source_repo") or "").strip().rstrip("/")
        same_repo = bool(repo_l and src and repo_l == src)
        if not same_repo:
            continue
        seen.add(key)
        entries.append({
            "title": title,
            "graveyard_reason": "prior-audit-disprove",
            "same_repo": same_repo,
            "qualification": "DISPROVE",
            "advisory_only": True,
            "requires_fresh_validation": True,
        })
    return entries


def apply_disprove_memory(
    findings: List[Dict[str, Any]],
    *,
    language: str = "",
    repo_source: str = "",
) -> Tuple[List[Dict[str, Any]], int]:
    """Annotate same-repository history without changing the current verdict.

    Titles and language are not proof identity. A code/configuration change or
    improved observation can overturn an earlier disproof; history never skips
    current validation, even when the title is identical.
    """
    identity = str(repo_source or "").strip().rstrip("/")
    records = [row for row in load_disprove_records(language)
               if identity and str(row.get("source_repo") or "").strip().rstrip("/") == identity]
    if not records:
        return findings, 0
    skipped = 0
    for f in findings:
        if f.get("proven_in_lab") or f.get("poc_result") in ("triggered", "proven", "success"):
            continue
        title = f.get("title") or ""
        hit = next((r for r in records if titles_match(title, r.get("title") or "")), None)
        if not hit:
            continue
        f["historical_disproof"] = {"title": hit.get("title"), "source_repo": identity,
                                   "advisory_only": True, "requires_fresh_validation": True}
        skipped += 1
    return findings, skipped


def overlay_retrospectives(plan: Dict[str, Any], dest: Optional[Path] = None,
                           *, repo_source: str = "") -> Dict[str, Any]:
    """Attach same-source historical strategy as context, never launch commands.

    A matching basename or programming language cannot bind executable history.
    Current repository evidence and the normal planner still choose the runtime.
    """
    from copy import deepcopy
    from backend.prior_audits import source_identity
    out = deepcopy(plan)
    identity = str(repo_source or "").strip().rstrip("/")
    if not identity:
        return out
    matches = [hint for hint in load_retrospective_hints(out.get("language"))
               if str(hint.get("source_repo") or "").strip().rstrip("/") == identity]
    if matches:
        out["historical_plan_context"] = [
            {"source_identity": source_identity(identity),
             "artifact": Path(hint.get("path") or "").name,
             "previous_lab_strategy": str(hint.get("lab_strategy") or "")[:80],
             "requires_current_validation": True}
            for hint in matches[:5]
        ]
        out.setdefault("notes", []).append("Same-source historical strategy available as context; current build and smoke evidence remain required.")
    return out
