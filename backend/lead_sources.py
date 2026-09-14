"""Recorded source navigation for scanner leads, including aggregate artifacts.

Location labels are observations, not arbitrary file selectors. Every selected
location still passes the immutable source viewer's content verification.
"""
from pathlib import Path

MAX_LOCATIONS = 500


def safe_relative_file(value):
    raw = str(value or "").strip().replace("\\", "/")
    relative = Path(raw)
    if (not raw or relative.is_absolute() or ".." in relative.parts
            or any(ord(char) < 32 for char in raw) or len(raw) > 4096):
        return ""
    return relative.as_posix()


def _line(value):
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def source_location(lead: dict, root: Path) -> dict:
    """Describe recorded locations without converting artifact labels to files."""
    recorded = lead.get("source_location")
    recorded = recorded if isinstance(recorded, dict) else {}
    if recorded.get("kind") == "aggregate":
        locations = []
        supplied = recorded.get("locations")
        supplied = supplied if isinstance(supplied, list) else []
        for row in supplied[:MAX_LOCATIONS]:
            if not isinstance(row, dict):
                continue
            file = safe_relative_file(row.get("file") or row.get("path"))
            if file:
                locations.append({"file": file, "line": _line(row.get("line")),
                                  "label": str(row.get("label") or file)[:240]})
        total_locations = max(len(supplied), _line(recorded.get("total_locations")))
        return {"kind": "aggregate", "label": str(recorded.get("label") or "Recorded source locations")[:240],
            "reason": str(recorded.get("reason") or "This observation summarizes multiple source locations.")[:500],
            "locations": locations, "total_locations": total_locations,
            "omitted_locations": max(0, total_locations - len(locations))}
    relative = safe_relative_file(recorded.get("path") if recorded.get("kind") == "file" else lead.get("file"))
    if relative:
        candidate = root / relative
        try:
            if candidate.is_file() and candidate.resolve().is_relative_to(root.resolve()):
                return {"kind": "file", "path": relative,
                        "line": _line(recorded.get("line", lead.get("line")))}
        except (OSError, ValueError):
            pass
    # Older attack-surface summaries recorded only the synthetic label
    # 'routes'. Preserve that artifact rather than inventing source locations.
    # A genuine extensionless captured file with this name was handled above.
    if (lead.get("tool") == "attack-surface-map" and lead.get("file") == "routes"
            and str(lead.get("title") or "").startswith("Attack surface:")):
        return {"kind": "aggregate", "label": "Recorded routes and endpoints", "locations": [],
            "total_locations": 0, "omitted_locations": 0,
            "reason": "This historical summary did not record declaration files or lines. Its description remains available; a fresh audit records navigable locations."}
    return {"kind": "unavailable", "locations": [],
            "reason": "This observation has no recorded file in the captured audit source. Review its recorded description and artifacts."}
