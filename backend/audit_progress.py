"""Durable-shaped progress contract for audits.

The scanner still executes in a worker thread, but progress is represented as a
small, JSON-safe state machine rather than inferred from prose in the browser.
This module is intentionally dependency-free so the API, worker and pipeline can
all use it without introducing an import cycle.
"""

from __future__ import annotations

import threading
import time
import os
import json
import math
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Optional

_LOCK = threading.RLock()
_STATE: Dict[int, Dict[str, Any]] = {}

_PHASES = {
    "ingest": ("Phase 0 · Ingest", 0.08),
    "recon": ("Phase 1 · Reconnaissance", 0.32),
    "dynamic": ("Phase 2 · Lab validation", 0.48),
    "gating": ("Phase 3 · Qualification gates", 0.10),
    "complete": ("Complete", 0.02),
}
_PHASE_ORDER = ["ingest", "recon", "dynamic", "gating", "complete"]
_DEFAULT_REMAINING = {"ingest": 30, "recon": 180, "dynamic": 300, "gating": 180}
_AVAILABILITY_TERMINALS = {"blocked", "not-installed"}
_PUBLICATION_STATES = {"preparing_evidence_report", "preparing_diagnostic_report"}


def _task_terminal_state(value: str) -> str:
    return {"ok": "completed", "done": "completed", "partial": "completed",
            "blocked": "skipped", "not-installed": "skipped"}.get(value, value)


def slow_task_threshold_seconds() -> int:
    """Operator-visible warning threshold for a task that is taking a long time.

    This is deliberately a warning, not a timeout: builds, dependency installs,
    and fuzzers can legitimately run for many minutes.  A separate lease
    watchdog remains responsible for declaring a worker lost.
    """
    try:
        return max(30, min(86400, int(os.environ.get("LOTUS_TASK_SLOW_THRESHOLD_SECONDS", "300"))))
    except (TypeError, ValueError):
        return 300


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new(repo_id: int) -> Dict[str, Any]:
    now = _now()
    return {
        "schema_version": 1,
        "repo_id": repo_id,
        "scan_job_id": None,
        "status": "running",
        "phase": "ingest",
        "phase_label": _PHASES["ingest"][0],
        "current_task": None,
        "message": "Audit queued",
        "started_at": now,
        "updated_at": now,
        "elapsed_seconds": 0.0,
        "eta_seconds": None,
        "eta_basis": "insufficient_observations",
        "completion_state": None,
        "progress_pct": 0,
        "tasks": {"total": 0, "completed": 0, "running": 0, "failed": 0, "skipped": 0},
        "bottlenecks": [],
        "resource_pressure": None,
        "leads_total": 0,
        "observations_total": 0,
        "observations_label": "Raw Phase 1 observations (before deduplication; not confirmed findings)",
        "inventory_status": "not_started",
        "recon_tools": [],
        "qualified_leads": 0,
        "confirmed_findings": 0,
        "evidence_status": "incomplete",
        "coverage": {"tools_total": 0, "tools_completed": 0, "tools_failed": 0, "tools_skipped": 0},
        "coverage_map": None,
        "ai_pause": None,
        "task_recovery": None,
        "stream_dropped": 0,
        "task_timeline": [],
        "active_task": None,
        "slow_tasks": [],
        "task_slow_threshold_seconds": slow_task_threshold_seconds(),
        "is_slow": False,
    }


def normalized_tool_coverage(raw: object, tool_results: object = None) -> dict:
    """Return an honest coverage ledger for both new and legacy job blobs.

    Historical jobs often stored only ``total/completed/skipped`` and a
    misleading 100% percentage.  Recompute counts from the immutable per-tool
    records when available, classify not-applicable tools explicitly, and
    expose both the applicable denominator and all-planned denominator without
    mutating the original audit artifact.
    """
    coverage = dict(raw) if isinstance(raw, dict) else {}
    rows = [row for row in (tool_results if isinstance(tool_results, list) else []) if isinstance(row, dict)]
    if rows:
        total = len(rows)
        completed = sum(1 for row in rows if row.get("status") == "completed")
        failed = sum(1 for row in rows if row.get("status") in {"failed", "error"})
        skipped = sum(1 for row in rows if row.get("status") in {"skipped", "not-installed"})
        not_installed = sum(1 for row in rows if row.get("status") == "not-installed")
        not_applicable = sum(
            1 for row in rows
            if row.get("status") == "skipped"
            and "not applicable" in str(row.get("reason") or "").lower()
        )
        coverage.update({
            "total_tools": total,
            "completed": completed,
            "partial": sum(row.get("status") == "partial" for row in rows),
            "failed": failed,
            "skipped": skipped,
            "not_installed": not_installed,
            "not_applicable": not_applicable,
            "applicable_tools": max(total - not_applicable, 0),
            "coverage_pct": round(completed / max(total - not_applicable, 1) * 100, 1),
            "coverage_all_pct": round(completed / max(total, 1) * 100, 1),
            "coverage_basis": "completed / (planned - not_applicable)",
        })
    else:
        # Preserve old values when the detailed ledger is absent, but make the
        # denominator semantics explicit for consumers rendering a warning.
        total = int(coverage.get("total_tools", 0) or 0)
        completed = int(coverage.get("completed", 0) or 0)
        not_applicable = int(coverage.get("not_applicable", 0) or 0)
        coverage.setdefault("applicable_tools", max(total - not_applicable, 0))
        coverage.setdefault("coverage_all_pct", round(completed / max(total, 1) * 100, 1))
        coverage.setdefault("coverage_basis", "completed / (planned - not_applicable)")
    return coverage



def invalidate_status_metadata(repo_id: int, scan_job_id: int) -> bool:
    """Retire the private projection before an active artifact can change."""
    with _LOCK:
        state = _STATE.get(repo_id)
        if not state or state.get("scan_job_id") != scan_job_id:
            return False
        state.pop("_status_metadata", None)
        state.pop("_terminal_status_metadata", None)
        return True


def publish_status_metadata(repo_id: int, scan_job_id: int, output: dict, *,
                            lease_token: str = "", lease_owner: str = "") -> bool:
    """Publish only bounded display fields from an already committed output.

    Callers invalidate before writing and publish after successful commit. This
    is not evidence, and neither the owned artifact nor private lease identity
    is copied into public progress or its durable checkpoint.
    """
    with _LOCK:
        state = _STATE.get(repo_id)
        if not state or state.get("scan_job_id") != scan_job_id:
            return False
        state.pop("_status_metadata", None)
        if state.get("status") != "running" or not isinstance(output, dict):
            return False
        progress = output.get("progress") or {}
        if not isinstance(progress, dict) or any(
            output.get(key) or progress.get(key) or state.get(key)
            for key in ("task_recovery", "audit_recovery", "ai_pause")
        ):
            return False
        # Unknown legacy coverage extensions remain on the durable path.
        raw = output.get("coverage") or {}
        allowed = {"total_tools", "completed", "partial", "failed", "skipped",
                   "not_installed", "not_applicable", "applicable_tools",
                   "coverage_pct", "coverage_all_pct", "coverage_basis"}
        if not isinstance(raw, dict) or set(raw) - allowed:
            return False
        if any(type(value) not in (int, float, str, bool, type(None))
               or isinstance(value, str) and len(value) > 100 for value in raw.values()):
            return False
        try:
            metrics = output.get("discovery_metrics")
            leads = (metrics.get("total_leads")
                     if isinstance(metrics, dict) and metrics.get("total_leads") is not None
                     else output.get("candidate_findings", output.get("leads_total", 0)))
            coverage = normalized_tool_coverage(raw, output.get("tool_results"))
            plan = output.get("audit_plan")
            metadata = {"leads_total": int(leads or 0), "coverage": coverage,
                        "target_snapshot": bool(output.get("target_snapshot") or
                            isinstance(plan, dict) and plan.get("target_snapshot"))}
        except (TypeError, ValueError, OverflowError):
            return False
        state["_status_metadata"] = {"lease_token": str(lease_token or ""),
            "lease_owner": str(lease_owner or ""), "output": metadata}
        return True


def live_status_snapshot(repo_id: int, scan_job_id: int, *, lease_token: str,
                         lease_owner: str):
    """Return an exact live projection; the API must recheck durable ownership."""
    with _LOCK:
        state = _STATE.get(repo_id)
        if (not state or state.get("scan_job_id") != scan_job_id
                or state.get("status") != "running"
                or any(state.get(key) for key in ("task_recovery", "audit_recovery", "ai_pause"))):
            return None
        record = state.get("_status_metadata")
        if (not record or record["lease_token"] != str(lease_token or "")
                or record["lease_owner"] != str(lease_owner or "")):
            return None
        return snapshot(repo_id, include_coverage_map=False), deepcopy(record["output"]), record



def status_metadata_is_current(repo_id: int, scan_job_id: int, marker) -> bool:
    """Close an invalidation/republication race during the API's SQL recheck."""
    with _LOCK:
        state = _STATE.get(repo_id)
        return bool(state and state.get("scan_job_id") == scan_job_id
                    and state.get("status") == "running"
                    and state.get("_status_metadata") is marker
                    and not any(state.get(key) for key in ("task_recovery", "audit_recovery", "ai_pause")))


def _copy_terminal_display(value):
    """Detach at most 512 KiB of ordinary JSON metadata, excluding artifact maps."""
    remaining = [512 * 1024, 32768]
    active = set()

    def copy(item, depth=0):
        remaining[1] -= 1
        if depth > 16 or remaining[1] < 0:
            raise ValueError("Terminal display metadata exceeds its structural bound")
        if isinstance(item, (dict, list)):
            if id(item) in active or len(item) > 1024:
                raise ValueError("Terminal display metadata is cyclic or oversized")
            active.add(id(item))
            remaining[0] -= 2 + (2 if isinstance(item, dict) else 1) * len(item)
            try:
                if isinstance(item, dict):
                    if any(type(key) is not str for key in item):
                        raise ValueError("Terminal display metadata requires string keys")
                    return {copy(key, depth + 1): copy(part, depth + 1) for key, part in item.items()}
                return [copy(part, depth + 1) for part in item]
            finally:
                active.remove(id(item))
        if type(item) not in (str, int, float, bool, type(None)):
            raise ValueError("Terminal display metadata is not JSON")
        if isinstance(item, str) and len(item) > remaining[0]:
            raise ValueError("Terminal display metadata exceeds its text bound")
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("Terminal display metadata is nonfinite")
        remaining[0] -= len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
        if remaining[0] < 0:
            raise ValueError("Terminal display metadata exceeds its byte bound")
        return item

    return copy(value)


def _same_terminal_worker(left, right):
    return (isinstance(left, tuple) and isinstance(right, tuple)
            and len(left) == len(right) == 4
            and all(a is b for a, b in zip(left, right)))


def publish_terminal_status_metadata(repo_id: int, scan_job_id: int, output: dict, *,
                                     lease_token: str, lease_owner: str, worker_marker,
                                     finished_at: datetime) -> bool:
    """Retain a bounded, committed incomplete display while its worker finalizes.

    The publisher owns the successful output commit. Reads independently check
    its original nonempty lease and opaque process-worker identity. Compatible
    later writes retain this last committed view until replacement succeeds.
    """
    def refuse():
        # A committed incompatible replacement must not leave an older display
        # current. A stale publisher cannot evict another process-worker marker.
        with _LOCK:
            state = _STATE.get(repo_id)
            old = state.get("_terminal_status_metadata") if state else None
            if (old and state.get("scan_job_id") == scan_job_id
                    and _same_terminal_worker(old["worker_marker"], worker_marker)
                    and old["lease_token"] == lease_token and old["lease_owner"] == lease_owner):
                state.pop("_terminal_status_metadata", None)
        return False

    if (type(lease_token) is not str or type(lease_owner) is not str
            or not lease_token or not lease_owner or not _same_terminal_worker(worker_marker, worker_marker)
            or not isinstance(finished_at, datetime) or not isinstance(output, dict)):
        return refuse()
    progress = output.get("progress")
    if (not isinstance(progress, dict) or type(progress.get("repo_id")) is not int
            or type(progress.get("scan_job_id")) is not int
            or progress.get("repo_id") != repo_id or progress.get("scan_job_id") != scan_job_id
            or progress.get("status") not in {"completed", "failed", "cancelled", "interrupted"}
            or progress.get("evidence_status") != "incomplete"):
        return refuse()
    fields = {"schema_version", "repo_id", "scan_job_id", "status", "phase", "phase_label",
              "current_task", "message", "started_at", "updated_at", "elapsed_seconds",
              "eta_seconds", "eta_basis", "completion_state", "progress_pct", "tasks", "bottlenecks", "leads_total",
              "observations_total", "observations_label", "inventory_status", "recon_tools",
              "qualified_leads", "confirmed_findings", "evidence_status", "coverage",
              "task_recovery", "audit_recovery", "ai_pause", "stream_dropped", "task_timeline",
              "active_task", "slow_tasks", "task_slow_threshold_seconds", "is_slow", "terminal"}
    try:
        display = {key: progress[key] for key in fields if key in progress}
        mapped, top = progress.get("coverage_map"), output.get("coverage_map")
        for candidate in (mapped, top):
            if isinstance(candidate, dict) and candidate.get("updated_at") is not None:
                stamp = candidate["updated_at"]
                if type(stamp) is not str or len(stamp) > 80:
                    return refuse()
        if isinstance(top, dict) and (not isinstance(mapped, dict)
                or str(top.get("updated_at") or "") >= str(mapped.get("updated_at") or "")):
            mapped = top
        display.update(coverage_map=None, coverage_map_omitted=True,
                       coverage_map_summary=coverage_map_summary(mapped))
        metrics = output.get("discovery_metrics")
        if isinstance(metrics, dict) and metrics.get("total_leads") is not None:
            display["leads_total"] = int(metrics.get("total_leads") or 0)
            display["qualified_leads"] = int(metrics.get("qualified_leads") or 0)
        display = _copy_terminal_display(display)
        completion_state = output.get("completion_state")
        if completion_state is not None and (type(completion_state) is not str or len(completion_state) > 100):
            return refuse()
    except (TypeError, ValueError, OverflowError, RecursionError):
        return refuse()
    with _LOCK:
        state = _STATE.get(repo_id)
        if (not state or state.get("scan_job_id") != scan_job_id
                or state.get("status") != progress["status"]):
            return False
        state["_terminal_status_metadata"] = {
            "lease_token": str(lease_token), "lease_owner": str(lease_owner),
            "worker_marker": worker_marker, "finished_at": finished_at,
            "status": progress["status"], "display": display, "completion_state": completion_state,
        }
    return True


def terminal_status_snapshot(repo_id: int, scan_job_id: int, *, lease_token: str,
                             lease_owner: str, worker_marker):
    """Read the detached committed display; this alone does not authorize a GET."""
    with _LOCK:
        state = _STATE.get(repo_id)
        record = state.get("_terminal_status_metadata") if state else None
        if (not record or not lease_token or not lease_owner or worker_marker is None
                or state.get("scan_job_id") != scan_job_id or state.get("status") != record["status"]
                or record["lease_token"] != lease_token or record["lease_owner"] != lease_owner
                or not _same_terminal_worker(record["worker_marker"], worker_marker)):
            return None
        return deepcopy(record["display"]), record


def terminal_status_metadata_is_current(repo_id: int, scan_job_id: int, marker) -> bool:
    with _LOCK:
        state = _STATE.get(repo_id)
        return bool(state and state.get("scan_job_id") == scan_job_id
                    and state.get("_terminal_status_metadata") is marker
                    and state.get("status") == marker.get("status"))

def start(repo_id: int, message: str = "Audit starting", scan_job_id: Optional[int] = None) -> Dict[str, Any]:
    with _LOCK:
        _STATE[repo_id] = _new(repo_id)
        _STATE[repo_id]["message"] = message
        if scan_job_id is not None:
            _STATE[repo_id]["scan_job_id"] = int(scan_job_id)
        return snapshot(repo_id)


def bind_job(repo_id: int, scan_job_id: int) -> Dict[str, Any]:
    """Bind a live progress snapshot to the durable scan job it represents."""
    with _LOCK:
        state = _STATE.setdefault(repo_id, _new(repo_id))
        state["scan_job_id"] = int(scan_job_id)
        state.pop("_status_metadata", None)
        state.pop("_terminal_status_metadata", None)
        state["updated_at"] = _now()
        return snapshot(repo_id)


def phase(repo_id: int, phase_name: str, message: str = "") -> Dict[str, Any]:
    with _LOCK:
        state = _STATE.setdefault(repo_id, _new(repo_id))
        key = phase_name if phase_name in _PHASES else "recon"
        state["phase"] = key
        state["phase_label"] = _PHASES[key][0]
        state["completion_state"] = None
        if message:
            state["message"] = message[:500]
        state["updated_at"] = _now()
        return snapshot(repo_id)


def plan(repo_id: int, total: int) -> Dict[str, Any]:
    with _LOCK:
        state = _STATE.setdefault(repo_id, _new(repo_id))
        # Keep one cumulative task denominator so Phase 2 cannot make the UI look
        # complete while Phase 1 work is still outstanding.
        # ``total`` is the number of *new* tasks being scheduled at this
        # boundary, not a replacement for prior phases.  Include active work
        # too: planning Phase 2 while a lab task is still running must not
        # create an impossible denominator such as ``47 completed / 47 total``
        # with the lab still in flight.
        observed = sum(state["tasks"].get(k, 0) for k in ("completed", "failed", "skipped", "running"))
        state["tasks"]["total"] = max(
            int(state["tasks"].get("total", 0) or 0),
            observed + max(0, int(total or 0)),
        )
        state["updated_at"] = _now()
        return snapshot(repo_id)


def task(repo_id: int, state_name: str, *, name: str = "", index: Optional[int] = None,
         total: Optional[int] = None, duration_seconds: Optional[float] = None,
         message: str = "", error: str = "", parent_task: Optional[str] = None,
         include_coverage_map: bool = True, configure_setting: Optional[str] = None,
         phase: Optional[str] = None) -> Dict[str, Any]:
    """Record an observed task state and derive a conservative ETA.

    Blocked/uninstalled work is terminal skipped work for accounting, while
    its public availability status remains explicit. Counts are idempotent.
    """
    with _LOCK:
        state = _STATE.setdefault(repo_id, _new(repo_id))
        ledger = state.setdefault("_task_ledger", {})
        key = name or f"task-{index or len(ledger) + 1}"
        now_iso = _now()
        row = ledger.setdefault(key, {"state": "queued", "duration_seconds": None,
                                      "started_at": now_iso, "updated_at": now_iso})
        previous_status = row.get("recorded_status") or (
            "partial" if row.get("state") == "completed" and row.get("scope_complete") is False else row.get("state"))
        previous_availability = (row.get("recorded_status") in _AVAILABILITY_TERMINALS
                                 or row.get("state") in _AVAILABILITY_TERMINALS)
        if state_name in _AVAILABILITY_TERMINALS:
            row["recorded_status"] = state_name
            if message:
                row["reason"] = message[:500]
        elif previous_availability:
            row.pop("recorded_status", None)
            row.pop("reason", None)
            row.pop("terminal_status", None)
            if state_name in {"queued", "running"}:
                row["started_at"] = now_iso
                row["duration_seconds"] = None
                row.pop("ended_at", None)
        next_status = state_name if state_name in _AVAILABILITY_TERMINALS or state_name == "partial" else _task_terminal_state(state_name)
        terminal = _task_terminal_state(state_name) in {"completed", "failed", "skipped"}
        # Keep the producer's explanation beside its task, not only in the
        # audit-wide message. A retry or changed outcome must not inherit an
        # earlier disabled/failure reason when the new event has no details.
        if state_name in {"queued", "running"} or previous_status != next_status or message or error:
            for field in ("reason", "summary", "error"):
                row.pop(field, None)
        if message:
            row["summary"] = message[:500]
        if terminal and (error or message):
            row["reason"] = (error or message)[:500]
            if error:
                row["error"] = error[:500]
                row.setdefault("summary", error[:500])
        if parent_task:
            row["parent_task"] = parent_task
        # Preserve the producer's phase across polling and pause/resume. Task
        # names alone do not identify which phase scheduled the work.
        if isinstance(phase, str) and phase.strip():
            row["phase"] = phase.strip()[:120]
        # A queued notification is not execution. Start the task clock at the
        # first running event so analyzer backpressure is reported honestly.
        if row.get("state") == "queued" and row.get("started_at") and state_name == "running":
            row["started_at"] = now_iso
        row["updated_at"] = now_iso
        row["state"] = _task_terminal_state(state_name)
        if state_name == "partial":
            row["scope_complete"] = False
            if configure_setting == "callgraph_max_files":
                row["configure_setting"] = configure_setting
        elif row["state"] in {"running", "completed"}:
            row.pop("scope_complete", None)
            row.pop("configure_setting", None)
        if duration_seconds is not None:
            row["duration_seconds"] = max(0.0, float(duration_seconds))
        if index is not None:
            row["index"] = int(index)
        if total is not None:
            state["tasks"]["total"] = max(state["tasks"].get("total", 0), int(total))
        if row["state"] in {"completed", "failed", "skipped"}:
            if state_name in _AVAILABILITY_TERMINALS:
                if not row.get("ended_at"):
                    row["ended_at"] = now_iso
            else:
                row["ended_at"] = now_iso
            if row.get("duration_seconds") is None:
                try:
                    started_dt = datetime.fromisoformat(str(row.get("started_at") or now_iso).replace("Z", "+00:00"))
                    ended_dt = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
                    row["duration_seconds"] = round(max(0.0, (ended_dt - started_dt).total_seconds()), 1)
                except (TypeError, ValueError, OverflowError):
                    row["duration_seconds"] = 0.0
        if row["state"] == "running":
            state["current_task"] = {"name": key, "index": index, "total": total}
        elif (state.get("current_task") or {}).get("name") == key:
            state["current_task"] = None
        if message:
            state["message"] = message[:500]
        if error:
            state["bottlenecks"] = [error[:240]] + [b for b in state.get("bottlenecks", []) if b != error[:240]]
            state["bottlenecks"] = state["bottlenecks"][:8]
        counts = {"completed": 0, "running": 0, "failed": 0, "skipped": 0}
        for row in ledger.values():
            if row["state"] in counts:
                counts[row["state"]] += 1
        state["tasks"].update(counts)
        # Some producers discover work lazily (notably third-party analyzer
        # adapters).  A status API must remain truthful even if a producer
        # failed to publish a plan first: no UI may ever render N/0 or more
        # terminal tasks than the announced denominator.
        state["tasks"]["total"] = max(
            int(state["tasks"].get("total", 0) or 0),
            len(ledger),
        )
        state["updated_at"] = _now()
        _derive_progress(state)
        return snapshot(repo_id, include_coverage_map=include_coverage_map)


def tools(repo_id: int, *, total: int, completed: int, failed: int, skipped: int,
          not_installed: int = 0, not_applicable: int = 0,
          queued: int = 0, running: int = 0, partial: int = 0,
          include_coverage_map: bool = True) -> Dict[str, Any]:
    with _LOCK:
        state = _STATE.setdefault(repo_id, _new(repo_id))
        total_i = max(0, int(total))
        completed_i = max(0, int(completed))
        not_applicable_i = max(0, int(not_applicable))
        state["coverage"] = {
            "tools_total": total_i,
            "tools_completed": completed_i,
            "tools_failed": max(0, int(failed)),
            "tools_skipped": max(0, int(skipped)),
            "tools_partial": max(0, int(partial)),
            "tools_not_installed": max(0, int(not_installed)),
            "tools_not_applicable": not_applicable_i,
            "tools_queued": max(0, int(queued)),
            "tools_running": max(0, int(running)),
            "coverage_pct": round(completed_i / max(total_i - not_applicable_i, 1) * 100, 1),
            "coverage_all_pct": round(completed_i / max(total_i, 1) * 100, 1),
        }
        state["updated_at"] = _now()
        _derive_progress(state)
        return snapshot(repo_id, include_coverage_map=include_coverage_map)


def recon_observations(repo_id: int, tool_rows, *, inventory_complete: bool = False,
                       leads_total: Optional[int] = None) -> Dict[str, Any]:
    """Replace observed Phase 1 accounting without implying qualification.

    Producers pass absolute rows, so retries/repeated events cannot add the same
    observations twice. Inventory includes failed/partial and contextual rows;
    only the phase boundary may supply the separately merged lead count.
    """
    rows = [{"id": str(row.get("id") or row.get("name") or ""),
             "name": str(row.get("name") or ""), "status": str(row.get("status") or "queued"),
             "observations": max(0, int(row.get("findings_count") or 0)),
             "reason": str(row.get("reason") or "")[:500]}
            for row in tool_rows if isinstance(row, dict)]
    with _LOCK:
        state = _STATE.setdefault(repo_id, _new(repo_id))
        state["recon_tools"] = rows
        state["observations_total"] = sum(row["observations"] for row in rows)
        terminal = {"completed", "partial", "failed", "error", "skipped", "not-installed", "blocked"}
        state["inventory_status"] = "complete" if inventory_complete and all(row["status"] in terminal for row in rows) else "inventory_in_progress"
        if leads_total is not None:
            state["leads_total"] = max(0, int(leads_total))
        return tools(
            repo_id, total=len(rows), completed=sum(row["status"] == "completed" for row in rows),
            failed=sum(row["status"] in {"failed", "error"} for row in rows),
            skipped=sum(row["status"] in {"skipped", "not-installed", "blocked"} for row in rows),
            partial=sum(row["status"] == "partial" for row in rows),
            not_installed=sum(row["status"] == "not-installed" for row in rows),
            not_applicable=sum(row["status"] == "skipped" and "not applicable" in row["reason"].lower() for row in rows),
            queued=sum(row["status"] == "queued" for row in rows),
            running=sum(row["status"] == "running" for row in rows),
        )


def coverage_map(repo_id: int, mapped: Dict[str, Any], *, include_coverage_map: bool = True) -> Dict[str, Any]:
    """Publish artifact coverage independently from scanner/tool accounting.

    Copy both on write and read: concurrent SSE/API consumers must never be
    able to mutate a worker's coverage obligations or its Phase 3 gate.
    """
    with _LOCK:
        state = _STATE.setdefault(repo_id, _new(repo_id))
        state["coverage_map"] = deepcopy(mapped)
        state["updated_at"] = _now()
        return snapshot(repo_id, include_coverage_map=include_coverage_map)


def message(repo_id: int, text: str, *, bottleneck: str = "", include_coverage_map: bool = True) -> Dict[str, Any]:
    with _LOCK:
        state = _STATE.setdefault(repo_id, _new(repo_id))
        state["message"] = (text or "")[:500]
        if bottleneck:
            state["bottlenecks"] = [bottleneck[:240]] + [b for b in state.get("bottlenecks", []) if b != bottleneck[:240]]
            state["bottlenecks"] = state["bottlenecks"][:8]
        state["updated_at"] = _now()
        _derive_progress(state)
        return snapshot(repo_id, include_coverage_map=include_coverage_map)


def resource_pressure(repo_id: int, evaluation: dict, *, expected_job_id=None) -> bool:
    """Replace this observer's current warning without erasing task failures."""
    with _LOCK:
        state = _STATE.get(repo_id)
        if not state or state.get("scan_job_id") != expected_job_id or state.get("status") != "running":
            return False
        prefixes = ("Resource WARN:", "Resource CRITICAL:", "Critical resource pressure - audit ")
        kept = [value for value in state.get("bottlenecks", [])
                if not str(value).startswith(prefixes)]
        level = evaluation.get("level", "ok")
        state["resource_pressure"] = {"level": level, "message": str(evaluation.get("message") or "")[:500],
                                      "observed_at": _now()}
        if level in {"warn", "critical"}:
            kept.insert(0, f"Resource {level.upper()}: {evaluation.get('message', '')}"[:240])
        state["bottlenecks"] = kept[:8]
        return True


def note_stream_drop(repo_id: int, count: int = 1) -> Dict[str, Any]:
    """Record loss caused by a slow SSE consumer in the durable-shaped state."""
    with _LOCK:
        state = _STATE.setdefault(repo_id, _new(repo_id))
        state["stream_dropped"] = max(0, int(state.get("stream_dropped", 0) or 0) + int(count or 0))
        marker = f"SSE backpressure dropped {state['stream_dropped']} event(s)"
        state["bottlenecks"] = [marker] + [b for b in state.get("bottlenecks", []) if b != marker]
        state["bottlenecks"] = state["bottlenecks"][:8]
        state["updated_at"] = _now()
        return snapshot(repo_id)


def finish(repo_id: int, *, status: str = "completed", leads_total: int = 0,
           qualified_leads: int = 0, confirmed_findings: int = 0,
           evidence_status: str = "incomplete", coverage: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    with _LOCK:
        state = _STATE.setdefault(repo_id, _new(repo_id))
        state["status"] = status
        if status in {"completed", "failed", "cancelled", "interrupted"}:
            state["completion_state"] = None
        state.pop("_status_metadata", None)
        state.pop("_terminal_status_metadata", None)
        state["phase"] = "complete" if status == "completed" else state.get("phase", "recon")
        state["phase_label"] = _PHASES[state["phase"]][0]
        state["leads_total"] = int(leads_total or 0)
        state["qualified_leads"] = int(qualified_leads or 0)
        state["confirmed_findings"] = int(confirmed_findings or 0)
        state["evidence_status"] = evidence_status or "incomplete"
        if coverage:
            state["coverage"].update(coverage)
        state["updated_at"] = _now()
        state["eta_seconds"] = 0
        state["eta_basis"] = "terminal"
        _derive_progress(state)
        if status in ("completed", "failed", "cancelled"):
            state["progress_pct"] = 100 if status == "completed" else state.get("progress_pct", 0)
        return snapshot(repo_id)


def publication_status(repo_id: int, scan_job_id: int, progress: Dict[str, Any]) -> bool:
    """Update publication display fields without copying coverage or task graphs.

    Called after an owned database checkpoint. An older publisher cannot
    replace the display of a newer audit in the same repository.
    """
    with _LOCK:
        state = _STATE.get(repo_id)
        if not state or state.get("scan_job_id") != scan_job_id:
            return False
        for key in ("status", "phase", "phase_label", "message", "current_task",
                    "progress_pct", "eta_seconds", "eta_basis", "completion_state", "evidence_status"):
            if key in progress:
                state[key] = deepcopy(progress[key])
        state["updated_at"] = _now()
        state.pop("_status_metadata", None)
        state.pop("_terminal_status_metadata", None)
        return True


def _derive_progress(state: Dict[str, Any]) -> None:
    now = time.time()
    try:
        started = datetime.fromisoformat(state["started_at"].replace("Z", "+00:00")).timestamp()
        state["elapsed_seconds"] = round(max(0.0, now - started), 1)
    except Exception:
        pass
    phase_key = state.get("phase", "recon")
    if phase_key not in _PHASE_ORDER:
        phase_key = "recon"
        state["phase"] = phase_key
    phase_base = sum(_PHASES[key][1] for key in _PHASE_ORDER[:_PHASE_ORDER.index(phase_key)] if key in _PHASES)
    phase_weight = _PHASES.get(phase_key, ("", 0.3))[1]
    tasks = state.get("tasks", {})
    total = tasks.get("total", 0)
    done = tasks.get("completed", 0) + tasks.get("failed", 0) + tasks.get("skipped", 0)
    within = (done / total) if total else 0.0
    state["progress_pct"] = min(99 if state.get("status") == "running" else 100,
                                 int(round((phase_base + phase_weight * within) * 100)))
    if state.get("status") != "running":
        _project_task_timing(state, now)
        return
    _project_task_timing(state, now)


def lab_setup_active(rows) -> bool:
    """Source-scanner timings do not predict downloads, builds or lab startup."""
    return any(isinstance(row, dict)
               and row.get("name") in {"lab-build", "local-lab-adapter"}
               and row.get("status", row.get("state")) in {"running", "queued"}
               for row in rows or [])


def _project_eta(state: Dict[str, Any]) -> None:
    status = state.get("status")
    if status in {"completed", "failed", "cancelled", "interrupted"}:
        state["eta_seconds"] = 0 if status == "completed" else None
        state["eta_basis"] = status
        return
    if status != "running":
        return
    # Work is registered incrementally. Only the publication checkpoint, never
    # the size of the current task ledger or Phase 3 alone, means finalization.
    completion_state = state.get("completion_state")
    if isinstance(completion_state, str) and completion_state in _PUBLICATION_STATES:
        state.update(eta_seconds=None, eta_basis="finalizing")
        return
    tasks = state.get("tasks") or {}
    total = int(tasks.get("total", 0) or 0)
    done = sum(int(tasks.get(key, 0) or 0) for key in ("completed", "failed", "skipped"))
    remaining = max(0, total - done)
    if total and not remaining:
        state.update(eta_seconds=None, eta_basis="preparing_next_tasks")
        return
    if lab_setup_active(state.get("task_timeline")):
        state.update(eta_seconds=None, eta_basis="lab_setup_in_progress")
        return
    durations = []
    for row in state.get("_task_ledger", {}).values():
        # Disabled/blocked tasks and failed attempts do not predict successful
        # execution. In particular their queue age must not inflate estimates.
        if row.get("state") != "completed":
            continue
        runtime = row.get("runtime_progress")
        # Queue-only observations are not execution samples for later tasks.
        duration = runtime.get("execution_elapsed_seconds") if isinstance(runtime, dict) else row.get("duration_seconds")
        if type(duration) in (int, float) and math.isfinite(duration) and duration > 0:
            durations.append(duration)
    if durations and remaining:
        state["eta_seconds"] = max(1, int(round(sum(durations) / len(durations) * remaining)))
        state["eta_basis"] = "observed_task_durations"
    else:
        state["eta_seconds"] = None
        state["eta_basis"] = "insufficient_observations"


def project_task_runtime(row: Dict[str, Any], *, now: Optional[float] = None,
                         terminal: bool = False, threshold: Optional[int] = None) -> Dict[str, Any]:
    """Project one trusted runtime receipt without mixing queue and execution.

    ``projected_at`` prevents a second API projection from adding the same
    interval twice. Persisted observations remain unchanged; terminal views
    retain their last recorded clocks rather than advancing with wall time.
    """
    result = deepcopy(row)
    raw = result.get("runtime_progress")
    fallback = slow_task_threshold_seconds() if threshold is None else threshold
    result["slow_threshold_seconds"] = fallback
    result["slow_clock_kind"] = "task"
    try:
        result["slow_elapsed_seconds"] = max(0.0, float(result.get("elapsed_seconds") or result.get("duration_seconds") or 0))
    except (TypeError, ValueError, OverflowError):
        result["slow_elapsed_seconds"] = 0.0
    result["is_slow"] = not terminal and result.get("status", result.get("state")) == "running" and result["slow_elapsed_seconds"] >= fallback
    if not isinstance(raw, dict) or raw.get("kind") != "runtime_progress" or raw.get("budget_kind") not in {"queue", "execution"}:
        return result
    import math
    required = ("queue_elapsed_seconds", "execution_elapsed_seconds", "budget_seconds", "queue_budget_seconds")
    if any(type(raw.get(key)) not in (int, float) or not math.isfinite(raw[key]) or raw[key] < 0 for key in required):
        return result
    if raw["budget_seconds"] <= 0 or raw["queue_budget_seconds"] <= 0:
        return result
    if raw.get("phase") not in {"Pending", "Running", "Succeeded", "Failed", "job_failed"}:
        return result
    if (raw["phase"] == "Pending" and raw["budget_kind"] != "queue") or (raw["phase"] == "Running" and raw["budget_kind"] != "execution"):
        return result
    now = time.time() if now is None else now
    runtime = dict(raw)
    lifecycle = str(result.get("status", result.get("state", "")))
    completed = terminal or lifecycle in {"ok", "completed", "failed", "skipped", "blocked", "not-installed"}
    active_phase = runtime.get("phase") in {"Pending", "Running"}
    increment = 0.0
    if not completed and active_phase:
        try:
            anchor = datetime.fromisoformat(str(runtime.get("projected_at") or runtime["observed_at"]).replace("Z", "+00:00")).timestamp()
            increment = max(0.0, now - anchor)
        except (TypeError, ValueError, KeyError, OverflowError):
            pass
    kind = runtime["budget_kind"]
    active_key = "execution_elapsed_seconds" if kind == "execution" else "queue_elapsed_seconds"
    budget_key = "budget_seconds" if kind == "execution" else "queue_budget_seconds"
    runtime[active_key] = round(runtime[active_key] + increment, 1)
    runtime["projected_at"] = datetime.fromtimestamp(now, timezone.utc).isoformat()
    result["runtime_progress"] = runtime
    # Lifecycle remains an observation in recorded_state; a Pending Pod has
    # not executed even if its wrapper coroutine entered the running state.
    if not completed and runtime.get("phase") == "Pending":
        for field in ("status", "state"):
            if result.get(field) == "running":
                result.setdefault("recorded_" + field, result[field])
                result[field] = "queued"
    result["slow_threshold_seconds"] = runtime[budget_key]
    result["slow_clock_kind"] = kind
    result["slow_elapsed_seconds"] = runtime[active_key]
    result["is_slow"] = not completed and active_phase and runtime[active_key] >= runtime[budget_key]
    return result


def runtime_task(repo_id: int, detail: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Attach only a producer-bound receipt to an existing audit task."""
    if not isinstance(detail, dict) or detail.get("kind") != "runtime_progress":
        return False
    job_id, name = detail.get("scan_job_id"), detail.get("task_name")
    if type(job_id) is not int or job_id <= 0 or not isinstance(name, str) or not name:
        return False
    with _LOCK:
        state = _STATE.get(repo_id)
        if not state or state.get("scan_job_id") != job_id or state.get("status") in {"completed", "failed", "cancelled", "interrupted"}:
            return False
        row = (state.get("_task_ledger") or {}).get(name)
        if not row or row.get("state") not in {"running", "queued"}:
            return False
        receipt = deepcopy(detail)
        receipt["observed_at"] = _now()
        receipt.pop("projected_at", None)
        checked = project_task_runtime({"status": "running", "runtime_progress": receipt})
        if checked.get("slow_clock_kind") not in {"queue", "execution"}:
            return False
        row["runtime_progress"] = receipt
        row["updated_at"] = receipt["observed_at"]
        state["updated_at"] = receipt["observed_at"]
        _project_task_timing(state)
        return deepcopy(receipt)


def timing_bottlenecks(existing, slow_tasks, threshold: int) -> list:
    """Replace our generated clock warning without retaining stale queue warnings."""
    suffix = "); open its console or choose Retry, Stop, or Skip"
    kept = [str(value) for value in (existing if isinstance(existing, list) else [])
            if not (("(long-running threshold " in str(value) and str(value).endswith(suffix))
                    or (" reached its " in str(value) and " budget: " in str(value) and str(value).endswith("; open its console for runtime status")))]
    if slow_tasks:
        lead = slow_tasks[0]
        kind = lead.get("slow_clock_kind")
        if kind in {"queue", "execution"}:
            marker = (f"{lead.get('name')} reached its {kind} budget: "
                      f"{int(lead.get('slow_elapsed_seconds', 0))}s of {int(lead.get('slow_threshold_seconds', threshold))}s; open its console for runtime status")
        else:
            marker = (f"{lead.get('name')} has been running for {int(lead.get('elapsed_seconds', 0))}s "
                      f"(long-running threshold {threshold}s){suffix[1:]}")
        kept.insert(0, marker)
    return kept[:8]


def project_runtime_inventory(tool_rows, coverage, timeline):
    """Project orchestration inventory using exact tracked task observations.

    A wrapper occupying an analyzer lane does not mean its Pod is executing.
    Keep the recorded inventory intact and only adjust the public active counts.
    """
    rows = deepcopy(tool_rows) if isinstance(tool_rows, list) else []
    counts = dict(coverage) if isinstance(coverage, dict) else {}
    tasks = {row.get("name"): row for row in timeline if isinstance(row, dict)}
    changed = False
    for row in rows:
        task = tasks.get(row.get("name") or row.get("id"))
        if not task or task.get("slow_clock_kind") not in {"queue", "execution"} or not isinstance(task.get("runtime_progress"), dict):
            continue
        if row.get("status") not in {"queued", "running"} or task.get("status") not in {"queued", "running"}:
            continue
        row["recorded_status"] = row.get("recorded_status", row["status"])
        row["status"] = task["status"]
        row["runtime_progress"] = deepcopy(task["runtime_progress"])
        changed = True
    if changed:
        counts["tools_queued"] = sum(row.get("status") == "queued" for row in rows)
        counts["tools_running"] = sum(row.get("status") == "running" for row in rows)
    return rows, counts


def _project_task_timing(state: Dict[str, Any], now: Optional[float] = None) -> None:
    """Project task clocks into the public progress snapshot.

    The worker can be quiet while a subprocess is running, so this projection
    is recomputed on every API read as well as every task event.  It gives the
    UI an explicit long-running signal without incorrectly failing the task.
    """
    now = time.time() if now is None else now
    threshold = slow_task_threshold_seconds()
    timeline = []
    active = []
    for key, raw in (state.get("_task_ledger") or {}).items():
        row = dict(raw or {})
        row["name"] = key
        row["status"] = row.get("state", "queued")
        started = row.get("started_at")
        elapsed = row.get("duration_seconds")
        if elapsed is None and started:
            try:
                end = now
                if state.get("status") in {"completed", "failed", "cancelled", "interrupted"}:
                    end = datetime.fromisoformat(str(state.get("updated_at") or row.get("updated_at") or started).replace("Z", "+00:00")).timestamp()
                elapsed = max(0.0, end - datetime.fromisoformat(str(started).replace("Z", "+00:00")).timestamp())
            except (TypeError, ValueError, OverflowError):
                elapsed = 0.0
        row["elapsed_seconds"] = round(max(0.0, float(elapsed or 0)), 1)
        row = project_task_runtime(row, now=now,
            terminal=state.get("status") in {"completed", "failed", "cancelled", "interrupted"}, threshold=threshold)
        if row["status"] == "completed" and row.get("scope_complete") is False:
            row.update(status="partial", terminal_status="completed")
        elif row["status"] == "skipped" and row.get("recorded_status") in _AVAILABILITY_TERMINALS:
            row.update(status=row["recorded_status"], terminal_status="skipped")
        row.pop("state", None)
        timeline.append(row)
        if row["status"] in {"running", "queued"} and state.get("status") not in {"completed", "failed", "cancelled", "interrupted"}:
            active.append(row)
    timeline.sort(key=lambda item: (item.get("started_at") or "", item.get("name") or ""))
    # Deferred lab work may have waited longer than every executing analyzer.
    # Its queue age is useful context, but is not an execution bottleneck.
    active.sort(key=lambda item: (item.get("status") == "running", item.get("elapsed_seconds", 0)), reverse=True)
    slow = [row for row in active if row.get("is_slow")]
    state["task_timeline"] = timeline
    state["recon_tools"], state["coverage"] = project_runtime_inventory(state.get("recon_tools"), state.get("coverage"), timeline)
    state["tasks"] = dict(state.get("tasks") or {})
    ledger = state.get("_task_ledger") or {}
    if ledger:
        for terminal in ("completed", "failed", "skipped"):
            state["tasks"][terminal] = sum(_task_terminal_state(row.get("state")) == terminal
                                           for row in ledger.values())
        state["tasks"]["total"] = max(int(state["tasks"].get("total", 0) or 0), len(ledger))
    state["tasks"]["running"] = sum(row["status"] == "running" for row in timeline)
    state["tasks"]["queued"] = sum(row["status"] == "queued" for row in timeline)
    state["active_task"] = dict(active[0]) if active else None
    state["slow_tasks"] = [dict(row) for row in slow]
    state["task_slow_threshold_seconds"] = threshold
    state["is_slow"] = bool(slow)
    state["bottlenecks"] = timing_bottlenecks(state.get("bottlenecks"), slow, threshold)
    _project_eta(state)
    runtime_active = [row for row in active if row.get("slow_clock_kind") in {"queue", "execution"} and isinstance(row.get("runtime_progress"), dict) and row["runtime_progress"].get("phase") in {"Pending", "Running"}]
    if state.get("status") == "running" and runtime_active and (any(row["runtime_progress"]["phase"] == "Pending" for row in runtime_active) or state.get("eta_basis") != "observed_task_durations"):
        state["eta_seconds"] = None
        state["eta_basis"] = "waiting_for_runtime_capacity" if any(row["runtime_progress"]["phase"] == "Pending" for row in runtime_active) else "runtime_execution_in_progress"


def coverage_map_summary(value: object) -> Dict[str, Any]:
    """Bounded recorded metadata, never a substitute for surface evidence."""
    mapped = value if isinstance(value, dict) else {}
    summary = mapped.get("summary") if isinstance(mapped.get("summary"), dict) else {}
    gate = mapped.get("gate") if isinstance(mapped.get("gate"), dict) else {}
    return {
        "available": isinstance(value, dict),
        "updated_at": mapped["updated_at"][:80] if isinstance(mapped.get("updated_at"), str) else None,
        "summary": {key: summary[key] for key in ("total", "covered", "coverage_pct")
                    if type(summary.get(key)) in (int, float)} | {
            section: {key: summary[section][key] for key in keys
                      if type(summary[section].get(key)) is int and summary[section][key] >= 0}
            for section, keys in {
                "planning": ("observations", "classified", "unmapped", "source_review_completed", "runtime_validation_unproven"),
                "execution": ("planned", "settled", "successful", "blocked", "running", "pending"),
            }.items() if isinstance(summary.get(section), dict)},
        "gate": {"complete": gate.get("complete") is True,
                 "phase3_allowed": gate.get("phase3_allowed") is True,
                 "reporting_mode": gate["reporting_mode"][:80] if isinstance(gate.get("reporting_mode"), str) else "",
                 "reason": gate["reason"][:2000] if isinstance(gate.get("reason"), str) else ""},
    }


def snapshot(repo_id: int, *, include_coverage_map: bool = True) -> Dict[str, Any]:
    """Copy progress, optionally excluding the large artifact map.

    Identity checks and activity summaries do not consume map nodes. Copying
    that evidence for each activity row monopolizes the shared progress lock
    and delays source/status requests on larger repositories.
    """
    with _LOCK:
        state = dict(_STATE.get(repo_id) or _new(repo_id))
        _project_task_timing(state)
        # Never expose the private ledger; it is an implementation detail.
        state.pop("_task_ledger", None)
        state.pop("_status_metadata", None)
        state.pop("_terminal_status_metadata", None)
        state["tasks"] = dict(state.get("tasks") or {})
        state["coverage"] = dict(state.get("coverage") or {})
        if include_coverage_map:
            state["coverage_map"] = deepcopy(state.get("coverage_map"))
            state.pop("coverage_map_omitted", None)
            state.pop("coverage_map_summary", None)
        else:
            state["coverage_map_summary"] = coverage_map_summary(state.get("coverage_map"))
            state["coverage_map_omitted"] = True
            state["coverage_map"] = None
        state["recon_tools"] = deepcopy(state.get("recon_tools") or [])
        state["bottlenecks"] = list(state.get("bottlenecks") or [])
        state["task_timeline"] = [dict(row) for row in (state.get("task_timeline") or [])]
        state["slow_tasks"] = [dict(row) for row in (state.get("slow_tasks") or [])]
        return state


def exists(repo_id: int) -> bool:
    """Whether a live or restored progress state exists for this repository.

    ``snapshot`` intentionally returns a JSON-safe default for callers that
    render an empty state, so APIs must use this predicate before treating that
    default as an active audit.
    """
    with _LOCK:
        return repo_id in _STATE


def phase_label(phase_name: str) -> str:
    """Return the stable operator-facing label for a phase key."""
    return _PHASES.get(phase_name, _PHASES["recon"])[0]


def restore(repo_id: int, state: Dict[str, Any], *, restore_task_timeline: bool = False) -> Dict[str, Any]:
    """Restore a persisted terminal/in-progress snapshot after process restart."""
    with _LOCK:
        if not isinstance(state, dict):
            return snapshot(repo_id)
        base = _new(repo_id)
        base.update(deepcopy({k: v for k, v in state.items() if k in base}))
        if restore_task_timeline:
            # A worker publishes its already-projected terminal ledger in one
            # operation; replaying task() N times would recopy the full map N
            # times and replace the recorded task clocks with publication time.
            ledger = {}
            for row in base.get("task_timeline") or []:
                if not isinstance(row, dict) or not row.get("name"):
                    continue
                original = row.get("status") or row.get("state") or "failed"
                restored = {**deepcopy(row), "state": _task_terminal_state(original),
                            "duration_seconds": row.get("duration_seconds", row.get("elapsed_seconds"))}
                if original == "partial":
                    restored["scope_complete"] = False
                elif original in _AVAILABILITY_TERMINALS:
                    restored["recorded_status"] = original
                    # Older snapshots left these clocks open. Use the recorded
                    # terminal update, never the time of this historical read.
                    restored["ended_at"] = row.get("ended_at") or row.get("updated_at") or base.get("updated_at")
                    if row.get("duration_seconds") is None:
                        try:
                            end = datetime.fromisoformat(str(restored["ended_at"]).replace("Z", "+00:00")).timestamp()
                            start = datetime.fromisoformat(str(row["started_at"]).replace("Z", "+00:00")).timestamp()
                            restored["duration_seconds"] = max(0.0, end - start)
                        except (KeyError, TypeError, ValueError, OverflowError):
                            restored["duration_seconds"] = row.get("elapsed_seconds")
                ledger[str(row["name"])] = restored
            base["_task_ledger"] = ledger
            _project_task_timing(base)
        _STATE[repo_id] = base
        return snapshot(repo_id)


def resource_recovery(repo_id: int, scan_job_id: int, recovery: dict, *, status: str, audit_view=None) -> Optional[Dict[str, Any]]:
    """Publish exact-job recovery without replacing the live task ledger."""
    with _LOCK:
        state = _STATE.get(repo_id)
        if (not state or state.get("scan_job_id") != scan_job_id
                or state.get("status") in {"completed", "failed", "cancelled", "interrupted"}):
            return None
        public_recovery = {key: deepcopy(value) for key, value in recovery.items()
                           if key not in {"lease_token", "lease_owner"}}
        state.update(task_recovery=public_recovery, status=status, eta_seconds=None,
                     updated_at=_now())
        if isinstance(audit_view, dict):
            state["audit_recovery"] = deepcopy(audit_view)
        if status == "paused":
            state.update(message="Waiting for audit recovery choice", eta_basis="task_resource_recovery")
        return snapshot(repo_id)


def clear(repo_id: int, *, expected_job_id: Optional[int] = None, terminal_only: bool = False) -> bool:
    """Release a ledger, optionally fencing a completed worker's exact audit."""
    with _LOCK:
        state = _STATE.get(repo_id)
        if expected_job_id is not None and (not state or state.get("scan_job_id") != expected_job_id):
            return False
        if terminal_only and (not state or state.get("status") not in {"completed", "failed", "cancelled", "interrupted"}):
            return False
        _STATE.pop(repo_id, None)
        return True
