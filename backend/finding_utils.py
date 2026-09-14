"""Shared normalization and de-duplication for scanner observations.

The audit battery intentionally runs overlapping detectors.  A single sink may
therefore be emitted by grep, taint, a transferred skill, and a high-severity
pass.  Treating each emission as a separate lead inflates counts and makes the
quality benchmark look worse (or causes an analyst to spend the proof budget on
duplicates).  This module collapses only observations that point at the same
source location and canonical bug class; distinct classes and unknown locations
remain separate.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


_CLASS_ALIASES = {
    "command-injection": "command_injection",
    "command injection": "command_injection",
    "code-injection": "code_injection",
    "code injection": "code_injection",
    "rce": "code_injection",
    "path-traversal": "path_traversal",
    "path traversal": "path_traversal",
    "authz-bypass": "authz_bypass",
    "authorization bypass": "authz_bypass",
}


def canonical_observation_class(observation: Dict[str, Any]) -> str:
    """Return the stable class used when deciding whether two leads overlap."""
    raw = observation.get("canonical_class") or observation.get("class") or observation.get("primitive_type")
    if not raw:
        title = str(observation.get("title") or "").lower()
        if any(token in title for token in ("command injection", "os.system", "popen")):
            raw = "command_injection"
        elif any(token in title for token in ("code injection", "eval", "instance_eval", "rce")):
            raw = "code_injection"
        elif "path traversal" in title or "directory traversal" in title:
            raw = "path_traversal"
        else:
            raw = "unknown"
    value = re.sub(r"[^a-z0-9]+", "_", str(raw).strip().lower()).strip("_")
    return _CLASS_ALIASES.get(value, value or "unknown")


def _relative_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    if not text:
        return ""
    # Absolute paths from the same checkout should still coalesce with the
    # relative paths produced by other detectors.  Keep the suffix because the
    # repository root is not available in every caller.
    try:
        return Path(text).as_posix().lstrip("./")
    except Exception:
        return text.lstrip("./")


def observation_key(observation: Dict[str, Any]) -> Tuple[str, ...]:
    """Build a conservative identity key for an observation.

    Positive file/line locations are preferred.  For line-less output we only
    merge an identical file/class/title, preventing unrelated path-wide leads
    from disappearing.
    """
    from backend.phase2 import is_inventory_summary

    if is_inventory_summary(observation):
        # A map summary may share the first route's location with a real lead.
        # Keep their identities separate without inventing a vulnerability class.
        return ("inventory", str(observation["tool"]), str(observation["inventory_artifact"]),
                str(observation["title"]))
    file_name = _relative_path(observation.get("file"))
    try:
        line = int(observation.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    bug_class = canonical_observation_class(observation)
    if file_name and line > 0:
        return ("location", file_name, str(line), bug_class)
    title = re.sub(r"\s+", " ", str(observation.get("title") or "").strip().lower())
    return ("unlocated", file_name, bug_class, title)


def _rank(observation: Dict[str, Any]) -> Tuple[int, float, int]:
    confidence = str(observation.get("confidence") or "").lower()
    confidence_rank = {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)
    try:
        cvss = float(observation.get("cvss") or 0)
    except (TypeError, ValueError):
        cvss = 0.0
    return confidence_rank, cvss, len(str(observation.get("description") or ""))


def deduplicate_observations(observations: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse overlapping observations while preserving provenance.

    The strongest observation becomes canonical.  Detector names, original
    titles, and evidence are retained in ``observation_sources`` so analysts can
    still see why a lead was surfaced.  Input dictionaries are never mutated.
    """
    from backend.phase2 import is_inventory_summary

    merged: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    order: List[Tuple[str, ...]] = []
    for original in observations:
        if not isinstance(original, dict):
            continue
        observation = copy.deepcopy(original)
        key = observation_key(observation)
        source = {
            "tool": observation.get("tool"),
            "title": observation.get("title"),
            "file": observation.get("file"),
            "line": observation.get("line", 0),
        }
        if key not in merged:
            if not is_inventory_summary(observation):
                observation["canonical_class"] = canonical_observation_class(observation)
            observation["observation_sources"] = [source]
            merged[key] = observation
            order.append(key)
            continue
        current = merged[key]
        sources = current.setdefault("observation_sources", [])
        if source not in sources:
            sources.append(source)
        for field in ("evidence", "evidence_refs", "data_flow"):
            incoming = observation.get(field)
            if incoming and not current.get(field):
                current[field] = incoming
        if _rank(observation) > _rank(current):
            replacement = observation
            replacement["observation_sources"] = sources
            merged[key] = replacement
    return [merged[key] for key in order]


def is_generated_audit_artifact(path: Any) -> bool:
    """Return true for Lotus-generated evidence paths that are out of code scope."""
    text = str(path or "").replace("\\", "/")
    try:
        return ".lotus" in {part.lower() for part in Path(text).parts}
    except Exception:
        return "/.lotus/" in f"/{text.strip('/')}/"
