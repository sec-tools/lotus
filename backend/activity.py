"""Process-wide activity registry.

Every long-running unit of work (scan phase, Phase-1 tool, Phase-2 task, harness
iteration, lab build, self-test, backup) upserts here so the UI can show *all*
running work with progress and a clickable detail payload — live and after restart
(when the scan job persisted the same records).
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_lock = threading.Lock()
_ITEMS: Dict[str, Dict[str, Any]] = {}
_MAX = 800


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(kind: str, ident: str) -> str:
    return f"{kind}:{ident}"


def upsert(
    *,
    kind: str,
    ident: str,
    name: str,
    state: str,
    phase: str = "",
    summary: str = "",
    detail_id: Optional[str] = None,
    repo_id: Optional[int] = None,
    job_id: Optional[int] = None,
    href: Optional[str] = None,
    terminal_status: Optional[str] = None,
    reason: str = "",
) -> Dict[str, Any]:
    """Insert or update an activity row.

    ``state`` is kept backward compatible (running|ok|failed|skipped|queued),
    while ``terminal_status`` is the stable public lifecycle vocabulary
    (running|completed|failed|skipped).  Persisting both matters after a
    restart: older consumers can still render ``ok`` and newer consumers can
    enforce the hard terminal-task invariant without guessing what ``ok``
    means.  ``reason`` is required by the pipeline for terminal rows and is
    intentionally retained here so activity remains actionable when the
    original SSE event has been dropped.
    """
    key = _id(kind, ident)
    ts = _now()
    with _lock:
        prev = _ITEMS.get(key) or {}
        if prev.get("state") in ("ok", "failed", "skipped") and state == "running":
            return prev
        execution_started = prev.get("state") == "queued" and state == "running"
        lifecycle = terminal_status or ""
        if not lifecycle:
            # A state transition must not inherit the previous ``running``
            # marker. This matters for direct callers that do not know about
            # the newer terminal_status field (and for replayed legacy rows).
            lifecycle = {
                "ok": "completed",
                "queued": "running",
                "running": "running",
                "failed": "failed",
                "skipped": "skipped",
            }.get(state, "running" if state in ("queued", "running") else state)
        rec = {
            "id": key,
            "kind": kind,
            "ident": ident,
            "name": name,
            "state": state,
            "phase": phase or prev.get("phase") or "",
            "summary": (summary or (prev.get("summary") if not execution_started else "") or "")[:400],
            "detail_id": detail_id or prev.get("detail_id"),
            "repo_id": repo_id if repo_id is not None else prev.get("repo_id"),
            "job_id": job_id if job_id is not None else prev.get("job_id"),
            "href": href or prev.get("href"),
            "terminal_status": lifecycle,
            # Direct callers often only have a human-readable terminal
            # summary. Preserve it as the durable reason as well so a
            # restarted UI can explain why the task ended without relying on
            # an SSE event that may already have been evicted.
            "reason": (
                reason
                or (prev.get("reason") if not execution_started else "")
                or (summary if state not in ("running", "queued") else "")
                or ""
            )[:500],
            "started_at": ts if execution_started else (prev.get("started_at") or ts),
            "queued_at": prev.get("queued_at") or (ts if state == "queued" else None),
            "updated_at": ts,
            "ended_at": None,
        }
        if state not in ("running", "queued"):
            rec["ended_at"] = ts
        _ITEMS[key] = rec
        if len(_ITEMS) > _MAX:
            finished = sorted(
                (i for i in _ITEMS.values() if i.get("state") != "running"),
                key=lambda i: i.get("updated_at") or "",
            )
            overflow = len(_ITEMS) - _MAX
            for stale in finished[:overflow]:
                _ITEMS.pop(stale["id"], None)
        return rec


def snapshot() -> Dict[str, Any]:
    with _lock:
        items = list(_ITEMS.values())
    running = [i for i in items if i.get("state") == "running"]
    recent = sorted(items, key=lambda i: i.get("updated_at") or "", reverse=True)[:100]
    return {
        "running": running,
        "recent": recent,
        "running_count": len(running),
        "total_tracked": len(items),
    }


def clear() -> None:
    """Test helper."""
    with _lock:
        _ITEMS.clear()
