import asyncio
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError

from backend.main import (
    Finding,
    NotificationSettings,
    Repo,
    RepoOut,
    ScanJob,
    Settings,
    get_db,
    _PLATFORM_RESET_IN_PROGRESS,
)
from backend.notifications import send_slack
from backend import pipeline
from backend import audit_progress

router = APIRouter()


def _latest_scan_jobs(db, repo_ids=None, *, metadata_only=False) -> dict:
    """Load one latest job per repository without a dashboard N+1 query loop."""
    wanted = set(repo_ids) if repo_ids is not None else None
    if wanted is not None and not wanted:
        return {}
    from sqlalchemy import func
    maxima = db.query(
        ScanJob.repo_id.label("repo_id"),
        func.max(ScanJob.id).label("max_id"),
    ).group_by(ScanJob.repo_id)
    if wanted is not None:
        maxima = maxima.filter(ScanJob.repo_id.in_(wanted))
    maxima = maxima.subquery()
    query = db.query(ScanJob).join(
        maxima,
        (ScanJob.repo_id == maxima.c.repo_id) & (ScanJob.id == maxima.c.max_id),
    )
    if metadata_only:
        from sqlalchemy.orm import load_only
        query = query.options(load_only(ScanJob.id, ScanJob.repo_id, ScanJob.started_at, raiseload=True))
    rows = query.all()
    return {job.repo_id: job for job in rows}


_normalized_tool_coverage = audit_progress.normalized_tool_coverage


def _evidence_complete(job_status: str, output: object) -> bool:
    """Evaluate the terminal evidence contract without trusting a healthy port.

    Older records do not contain the newer completion/coverage fields, so they
    retain the legacy integrity+lab check.  New records must also have the
    pipeline's complete evidence status, an exhausted coverage ledger, and a
    terminal Phase 2 execution receipt.
    """
    if not isinstance(output, dict) or job_status != "completed":
        return False
    integrity = output.get("audit_integrity")
    lab_status = output.get("lab_status")
    if not (isinstance(integrity, dict) and integrity.get("complete") is True
            and isinstance(lab_status, dict) and lab_status.get("healthy") is True):
        return False
    progress = output.get("progress") or {}
    if progress.get("evidence_status") and progress.get("evidence_status") != "complete":
        return False
    if output.get("completion_state") and output.get("completion_state") != "complete":
        return False
    if "coverage_map" in output or ("coverage_map" in progress and progress["coverage_map"] is not None):
        mapped = output.get("coverage_map") or progress.get("coverage_map")
        if not isinstance(mapped, dict):
            return False
        if mapped.get("gate", {}).get("reporting_mode") in {"incomplete_resource_gaps", "incomplete_audit_gaps"}:
            return False
        try:
            # Report permission is distinct from complete evidence. Force the
            # strict validator for this claim even if continuation was selected.
            pipeline._require_phase2_coverage({**output, "coverage_map": mapped, "resource_gap_policy": "strict"})
        except (RuntimeError, TypeError, ValueError, AttributeError):
            return False
    ledger = output.get("coverage_ledger") or {}
    if ledger and ledger.get("honest_exit") is not None and not pipeline._coverage_ledger_complete(ledger):
        return False
    joern = output.get("joern_cpg") or {}
    joern_diag = joern.get("taint_query_diagnostics") if isinstance(joern, dict) else {}
    # New Joern runs carry an explicit image-validation result.  A present tag
    # without a content identity is not a trusted analyzer execution.  Legacy
    # records without this field retain their historical contract so upgrades
    # do not retroactively invalidate already-published reports.
    if isinstance(joern, dict) and "validated" in joern and joern.get("available") and not joern.get("validated"):
        return False
    if isinstance(joern_diag, dict) and (
        int(joern_diag.get("queries_without_output", 0) or 0)
        or int(joern_diag.get("queries_without_valid_flows", 0) or 0)
    ):
        return False
    execution = output.get("phase2_execution") or {}
    # New-format jobs always persist a Phase 2 plan/execution receipt.  Keep
    # the minimal legacy fixture contract backward-compatible when no plan was
    # recorded at all, but never call a job complete when it advertises a plan
    # and omitted its executor accounting.
    if "phase2_plan" in output and not execution:
        return False
    if execution:
        planned = int(execution.get("planned", 0) or 0)
        terminal = int(execution.get("terminal", 0) or 0)
        if not terminal:
            terminal = sum(int(execution.get(k, 0) or 0) for k in ("completed", "failed", "skipped"))
        if planned != terminal or int(execution.get("unresolved", 0) or 0) != 0:
            return False
        # A skipped applicable task is an explicit, honest limitation—not
        # complete evidence.  HTTP-only tasks are legitimately not applicable
        # to a library/CLI target and are tracked separately by Phase 2; those
        # skips do not make an otherwise exhausted run incomplete.
        if int(execution.get("skipped", 0) or 0) > int(execution.get("not_applicable", 0) or 0):
            return False
    return True


def _evidence_complete_for_job(db, job, metadata: object) -> bool:
    """Metadata can reject completeness; only the existing full proof can grant it."""
    if str(job.status or "") != "completed" or not isinstance(metadata, dict):
        return False
    integrity, lab = metadata.get("audit_integrity"), metadata.get("lab_status")
    if not (isinstance(integrity, dict) and integrity.get("complete") is True
            and isinstance(lab, dict) and lab.get("healthy") is True):
        return False
    progress = metadata.get("progress")
    if isinstance(progress, dict) and progress.get("evidence_status") not in (None, "", "complete"):
        return False
    if metadata.get("completion_state") not in (None, "", "complete"):
        return False
    # Do not promote copied green counters into proof. A potentially complete
    # record still undergoes the unchanged coverage graph/receipt validation.
    observed = db.query(ScanJob.output).filter(ScanJob.id == int(job.id),
        ScanJob.repo_id == int(job.repo_id), ScanJob.status == "completed").first()
    if observed is None:
        return False
    try:
        return _evidence_complete("completed", json.loads(observed[0] or "{}"))
    except (ValueError, TypeError, AttributeError):
        return False


class DashboardOut(BaseModel):
    repos: int
    findings: dict
    reports: int
    scan_jobs: dict
    cvss_threshold: float


def _notify(text: str, event_type: str = "scan_complete"):
    """Send notifications if Slack is configured and the event type is enabled.

    event_type: one of 'scan_complete', 'new_finding', 'report_ready', 'lab_failure'
    """
    db = get_db()
    try:
        ns = db.query(NotificationSettings).first()
        if not ns or not ns.slack_enabled or not ns.slack_webhook_url:
            return
        # Check event-specific toggle
        toggle_map = {
            "scan_complete": getattr(ns, "notify_scan_complete", True),
            "new_finding": getattr(ns, "notify_new_finding", True),
            "report_ready": getattr(ns, "notify_report_ready", True),
            "lab_failure": getattr(ns, "notify_lab_failure", False),
        }
        if not toggle_map.get(event_type, True):
            return
        channel = getattr(ns, "slack_channel", None) or None
        send_slack(ns.slack_webhook_url, text, channel=channel)
    finally:
        db.close()


@router.get("/api/dashboard", response_model=DashboardOut)
def dashboard():
    db = get_db()
    try:
        from backend.main import Report, Settings

        s = db.query(Settings).first()
        active_repo_ids = {
            row.id for row in db.query(Repo.id).filter(Repo.status != "archived").all()
        }
        total_repos = len(active_repo_ids)
        # Derive counters through the same receipt-backed authority used by the
        # finding API.  Counting raw ORM flags would resurrect legacy rows that
        # claim ``confirmed`` without a signed lab receipt.  Scope the headline
        # to the latest audit for each repository so stale rows cannot inflate a
        # current dashboard after a repository is rescanned.
        rows = db.query(Finding).all()
        from backend.main import _authoritative_finding_state, _row_belongs_to_current_audit
        latest_jobs = _latest_scan_jobs(db, metadata_only=True)
        current_rows = []
        historical_rows = []
        for row in rows:
            # Archived targets remain available in Findings history, but must
            # not inflate the active Dashboard headline or its current-audit
            # lead/finding counts.
            if row.repo_id not in active_repo_ids:
                historical_rows.append(row)
                continue
            latest = latest_jobs.get(row.repo_id)
            if latest is not None and not _row_belongs_to_current_audit(row, latest):
                historical_rows.append(row)
            else:
                current_rows.append(row)
        current_states = [_authoritative_finding_state(row) for row in current_rows]
        total_findings = len(current_rows)
        unproven = sum(1 for status, _ in current_states if status == "unproven")
        below = sum(1 for status, _ in current_states if status == "below-threshold")
        eligible = sum(1 for _, is_eligible in current_states if is_eligible)
        reports = db.query(Report).count()
        from sqlalchemy import func
        job_counts = dict(db.query(ScanJob.status, func.count(ScanJob.id)).group_by(ScanJob.status).all())
        return {
            "repos": total_repos,
            "findings": {
                "total": total_findings,
                "leads_total": total_findings,
                "unproven": unproven,
                "below_threshold": below,
                "report_eligible": eligible,
                "confirmed": eligible,
                "historical_unscoped": len(historical_rows),
            },
            "reports": reports,
            "scan_jobs": {status: int(job_counts.get(status, 0)) for status in (
                "queued", "running", "paused", "completed", "failed", "cancelled", "interrupted",
            )},
            "cvss_threshold": s.cvss_threshold if s else 7.0,
        }
    finally:
        db.close()


class ScanJobOut(BaseModel):
    audit_depth: Optional[int] = None
    id: int
    repo_id: int
    status: str
    findings_count: int
    output: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    control: Optional[str] = ""
    phase: Optional[str] = "ingest"
    current_task: Optional[str] = ""
    progress_pct: Optional[float] = 0.0
    eta_seconds: Optional[int] = None
    eta_basis: Optional[str] = None
    elapsed_seconds: Optional[float] = 0.0
    active_task: Optional[dict] = None
    slow_tasks: Optional[List[dict]] = None
    task_slow_threshold_seconds: Optional[int] = 300
    is_slow: Optional[bool] = False
    terminal: Optional[bool] = False
    ai_pause: Optional[dict] = None
    task_recovery: Optional[dict] = None
    audit_recovery: Optional[dict] = None
    # Canonical audit counters.  ``findings_count`` is retained for older
    # clients, but these fields are the user-facing contract: raw scanner
    # output is leads; only receipt-backed rows are proven findings.
    leads_total: Optional[int] = 0
    observations_total: int = 0
    observations_label: str = "Raw Phase 1 observations (before deduplication; not confirmed findings)"
    inventory_status: str = "not_started"
    confirmed_findings: Optional[int] = 0
    evidence_status: Optional[str] = "incomplete"
    # Honest Phase-1 tool ledger, exposed on the list endpoint so Dashboard
    # can show what actually ran without opening a detail modal.
    coverage: Optional[dict] = None
    replay_of_job_id: Optional[int] = None
    replay_snapshot_path: Optional[str] = ""
    replay_snapshot_url: Optional[str] = ""
    queue_position: Optional[int] = None
    queue_eta_seconds: Optional[int] = None
    queue_eta_basis: Optional[str] = None
    # List responses are metadata-only; fetch the immutable audit artifact from
    # this stable, job-bound URL when a user opens a run.
    details_url: Optional[str] = None
    metadata_warning: Optional[str] = None

    class Config:
        from_attributes = True


def _scan_task_name(value) -> str:
    """Project the legacy name field without stringifying structured evidence."""
    name = value.get("name") if isinstance(value, dict) else value
    return name if isinstance(name, str) else ""


def _scan_job_progress(job, output, *, include_coverage_map: bool = True, checkpoint=None, allow_live=True):
    """Select only this job's live state, otherwise its latest durable checkpoint."""
    progress = output.get("progress") if isinstance(output, dict) else {}
    progress = progress if isinstance(progress, dict) else {}
    if str(job.status or "") in {"queued", "running", "paused"}:
        try:
            if checkpoint is None:
                checkpoint = json.loads(job.progress_json or "{}")
            if isinstance(checkpoint, dict) and str(checkpoint.get("updated_at") or "") > str(progress.get("updated_at") or ""):
                progress = checkpoint
        except (TypeError, ValueError):
            pass
        if allow_live:
            live = pipeline.audit_progress.snapshot(int(job.repo_id), include_coverage_map=include_coverage_map)
            if live.get("scan_job_id") == int(job.id):
                progress = live
    if not include_coverage_map:
        progress = {key: value for key, value in progress.items() if key != "coverage_map"}
    return progress


def _project_scan_observations(row, progress):
    pause = progress.get("ai_pause")
    row.ai_pause = (deepcopy(pause) if isinstance(pause, dict) and row.status == "paused"
        and pause.get("repo_id") == row.repo_id and pause.get("scan_job_id") == row.id
        and pause.get("resume_required") is True else None)
    recovery = _progress_recovery_for_read(progress, row.repo_id, row)
    row.task_recovery = recovery.get("task_recovery")
    row.audit_recovery = recovery.get("audit_recovery")
    row.observations_total = _progress_int(progress.get("observations_total"))
    row.observations_label = str(progress.get("observations_label") or row.observations_label)
    row.inventory_status = str(progress.get("inventory_status") or "not_started")
    if row.status in {"running", "paused"} and row.inventory_status == "inventory_in_progress" and progress.get("recon_tools"):
        row.coverage = _normalized_tool_coverage(progress.get("coverage"), progress["recon_tools"])


@router.get("/api/scan-workers")
def scan_worker_status():
    """Current bounded dispatcher state, separating execution from waiting."""
    from backend.scan_worker import scheduler_status
    return scheduler_status()


@router.get("/api/scan-jobs", response_model=List[ScanJobOut])
def list_scan_jobs(limit: Optional[int] = None, offset: int = 0, status: Optional[str] = None):
    if status is not None and status not in {"queued", "running", "paused", "completed", "failed", "cancelled", "interrupted"}:
        raise HTTPException(status_code=422, detail="Unknown audit status filter")
    return _scan_job_metadata_rows(limit=limit, offset=offset, status=status)



def _live_scan_status(db, job, columns):
    """Use committed display metadata only while its original worker is live."""
    if job.status != "running" or job.control not in (None, "", "resume"):
        return None, True
    live = audit_progress.live_status_snapshot(int(job.repo_id), int(job.id),
        lease_token=job.lease_token, lease_owner=job.lease_owner)
    if live is None:
        return None, True
    original = (job.repo_id, job.lease_token, job.lease_owner)
    # A pause, terminal commit or replacement may occur while progress is read.
    # Refresh scalar fields only, then retain the normal durable fallback.
    db.refresh(job, attribute_names=list(columns))
    if (job.status != "running" or job.control not in (None, "", "resume")
            or original != (job.repo_id, job.lease_token, job.lease_owner)):
        return None, False
    from backend.main import ScanLease
    now = datetime.utcnow()
    leases = db.query(ScanLease.repo_id).filter(ScanLease.repo_id == job.repo_id,
                                         ScanLease.expires_at > now)
    if job.lease_token:
        if not job.lease_expires_at or job.lease_expires_at <= now:
            return None, False
        if not leases.filter(ScanLease.job_id == job.id,
                             ScanLease.lease_token == job.lease_token,
                             ScanLease.owner == job.lease_owner).first():
            return None, False
    elif job.lease_owner or job.lease_expires_at is not None or leases.first():
        return None, False
    if not audit_progress.status_metadata_is_current(int(job.repo_id), int(job.id), live[2]):
        return None, False
    return live[:2], True

def _scan_job_metadata_rows(*, limit=None, offset=0, job_id=None, status=None):
    from sqlalchemy.orm import load_only
    from backend.audit_metadata import load_audit_metadata, load_progress_checkpoint
    db = get_db()
    try:
        # Listing metadata must not hydrate output first and discard it later.
        # Raiseload makes accidental artifact access fail during development.
        columns = ('id', 'repo_id', 'status', 'findings_count', 'started_at', 'finished_at',
                   'control', 'phase', 'current_task', 'progress_pct', 'eta_seconds',
                   'replay_of_job_id', 'replay_snapshot_path', 'audit_depth')
        owned_columns = (*columns, 'lease_token', 'lease_owner', 'lease_expires_at')
        q = db.query(ScanJob).options(load_only(
            *(getattr(ScanJob, name) for name in owned_columns), raiseload=True,
        )).order_by(ScanJob.started_at.desc(), ScanJob.id.asc())
        if job_id is not None:
            q = q.filter(ScanJob.id == int(job_id))
        if status is not None:
            q = q.filter(ScanJob.status == status)
        if offset:
            q = q.offset(max(offset, 0))
        if limit is not None:
            q = q.limit(min(max(int(limit), 1), 500))
        jobs = q.all()
        from backend.scan_worker import get_scan_control
        from backend.scan_worker import scheduler_status
        from backend.main import _confirmed_findings_for_scan_job
        latest_jobs = _latest_scan_jobs(db, {job.repo_id for job in jobs}, metadata_only=True)
        durable_queue_ids = [
            int(row[0]) for row in
            db.query(ScanJob.id).filter(ScanJob.status == "queued").order_by(ScanJob.id.asc()).all()
        ]
        out = []
        for j in jobs:
            live_status, allow_live = _live_scan_status(db, j, owned_columns)
            # Explicit scalar construction never invokes deferred ORM fields.
            row = ScanJobOut(**{name: getattr(j, name) for name in columns}, output="")
            # Audit output can contain megabytes of logs, source excerpts and
            # tool artifacts.  Never duplicate it into the dashboard/list
            # response (which is polled frequently); the single-job endpoint
            # remains the explicit detail boundary.
            row.output = ""
            row.details_url = f"/api/scan-jobs/{int(j.id)}"
            # ``replay_snapshot_path`` is an internal filesystem location and
            # must never cross a multi-user API boundary.  Keep the legacy
            # field for schema compatibility but expose only the stable,
            # re-verifying resource URL.
            row.replay_snapshot_path = ""
            row.replay_snapshot_url = ""
            ctl = (
                get_scan_control(j.repo_id) or j.control or ""
                if str(j.status or "") in {"queued", "running", "paused"}
                else ""
            )
            try:
                row.control = ctl
            except Exception:
                pass
            if str(j.status or "") == "queued":
                try:
                    queue = scheduler_status(int(j.repo_id))
                except Exception:
                    queue = {}
                position = queue.get("queue_position")
                if position is None:
                    try:
                        position = durable_queue_ids.index(int(j.id)) + 1
                    except ValueError:
                        position = None
                row.queue_position = position
                row.queue_eta_seconds = queue.get("queue_eta_seconds")
                row.queue_eta_basis = queue.get("queue_eta_basis", "insufficient_completed_audits")
            # Do not expose the mutable ScanJob counters as proof.  Recompute
            # the two display counters from the persisted audit artifact and
            # receipt-backed Finding rows, matching /progress and /details.
            metadata_warning = None
            if live_status is not None:
                _progress, output = live_status
            else:
                try:
                    output = load_audit_metadata(db, j)
                except (TypeError, ValueError):
                    output = {}
                    metadata_warning = "Recorded audit metadata is malformed; coverage and evidence completeness could not be established."
                checkpoint = {}
                if str(j.status or "") in {"queued", "running", "paused"}:
                    try:
                        checkpoint = load_progress_checkpoint(db, j)
                    except (TypeError, ValueError):
                        metadata_warning = "Recorded progress metadata is malformed; coverage and evidence completeness could not be established."
                # SQL progress columns are a compatibility cache. Historical
                # jobs retain their authoritative durable progress projection.
                _progress = _scan_job_progress(j, output, include_coverage_map=False, checkpoint=checkpoint, allow_live=allow_live)
            if isinstance(_progress, dict):
                _progress = {**_progress_recovery_for_read(output, j.repo_id, j), **_progress}
                if _progress.get("phase") is not None:
                    row.phase = str(_progress.get("phase") or row.phase or "ingest")
                row.current_task = _scan_task_name(_progress.get("current_task", row.current_task))
                if _progress.get("progress_pct") is not None:
                    row.progress_pct = float(_progress.get("progress_pct") or 0)
                if _progress.get("eta_seconds") is not None:
                    row.eta_seconds = int(_progress.get("eta_seconds") or 0)
                # Project the same authoritative task clocks exposed by the
                # dedicated progress endpoint into Dashboard/Scans polling.
                _progress_view = _project_progress_for_read(int(j.repo_id), _progress, j)
                row.eta_seconds = _progress_view.get("eta_seconds")
                row.eta_basis = _progress_view.get("eta_basis")
                row.elapsed_seconds = _progress_view.get("elapsed_seconds", 0.0)
                row.active_task = _progress_view.get("active_task")
                row.slow_tasks = _progress_view.get("slow_tasks") or []
                row.task_slow_threshold_seconds = _progress_view.get("task_slow_threshold_seconds", 300)
                row.is_slow = bool(_progress_view.get("is_slow"))
                row.terminal = bool(_progress_view.get("terminal"))
            if str(j.status or "").lower() == "completed":
                row.phase = "complete"
                row.progress_pct = 100.0
                row.eta_seconds = None
            if str(j.status or "").lower() in {"failed", "cancelled", "interrupted"}:
                row.eta_seconds = None
            _has_snapshot = bool(getattr(j, "replay_snapshot_path", "")) or bool(
                isinstance(output, dict)
                and (
                    output.get("target_snapshot")
                    or (
                        isinstance(output.get("audit_plan"), dict)
                        and output.get("audit_plan", {}).get("target_snapshot")
                    )
                )
            )
            row.replay_snapshot_url = f"/api/scan-jobs/{int(j.id)}/snapshot" if _has_snapshot else ""
            metrics = output.get("discovery_metrics") if isinstance(output, dict) else None
            leads = (
                metrics.get("total_leads")
                if isinstance(metrics, dict) and metrics.get("total_leads") is not None
                else output.get("candidate_findings", output.get("leads_total", 0))
            )
            # Scope confirmation to this job.  Counting every receipt-backed row
            # for the repository would make an older scan appear to contain
            # findings discovered by a later run.
            confirmed = _confirmed_findings_for_scan_job(
                db, j.repo_id, j, latest_job=latest_jobs.get(j.repo_id)
            )
            row.leads_total = int(leads or 0)
            row.confirmed_findings = confirmed
            row.evidence_status = "complete" if not metadata_warning and _evidence_complete_for_job(db, j, output) else "incomplete"
            raw_coverage = output.get("coverage") if isinstance(output, dict) else {}
            tool_results = output.get("tool_results") if isinstance(output, dict) else []
            row.coverage = _normalized_tool_coverage(raw_coverage, tool_results)
            _project_scan_observations(row, _progress_view)
            if metadata_warning:
                row.metadata_warning = metadata_warning
                row.current_task = metadata_warning
            out.append(row)
        return out
    finally:
        db.close()


class Phase2ApprovalRequest(BaseModel):
    approved: bool = Field(default=True, strict=True)
    revision_prompt: Optional[str] = Field(default=None, max_length=10000)
    excluded_tasks: Optional[List[str]] = Field(default=None, max_length=1000)


@router.post("/api/repos/{repo_id}/phase2-approve")
async def approve_phase2_plan(repo_id: int, payload: Phase2ApprovalRequest, job_id: Optional[int] = None):
    """Approve or revise the Phase 2 plan. Only relevant when plan approval is enabled."""
    if job_id is not None:
        db = get_db()
        try:
            job = _owned_scan_job(db, repo_id, job_id)
            if job.status not in {"queued", "running", "paused"}:
                raise HTTPException(status_code=409, detail="This audit is terminal; approval cannot affect a newer audit")
        finally:
            db.close()
    gate = pipeline.PLAN_APPROVAL_GATES.get(repo_id)
    if not gate:
        return {"status": "no_pending_approval", "repo_id": repo_id}
    pipeline.PLAN_APPROVAL_DATA[repo_id] = {
        "approved": payload.approved,
        "revision_prompt": payload.revision_prompt or "",
        "excluded_tasks": payload.excluded_tasks or [],
    }
    # The gate is an asyncio.Event created and awaited on the scan's WORKER loop. Setting
    # it from this (main) loop would touch futures owned by the worker loop and never wake
    # the scan. Schedule .set() onto the worker loop so the waiter is actually notified.
    wl = pipeline.WORKER_LOOPS.get(repo_id)
    if wl is not None and not wl.is_closed():
        wl.call_soon_threadsafe(gate.set)
    else:
        gate.set()  # no worker loop registered (e.g. same-loop test) - safe to set directly
    return {
        "status": "approved" if payload.approved else "revised",
        "repo_id": repo_id,
        "excluded_count": len(payload.excluded_tasks or []),
    }


def _detail_from_persisted_jobs(detail_id: str, repo_id: Optional[int] = None, job_id: Optional[int] = None):
    """Read a clickable detail locally; historical reads never rehydrate caches."""
    db = get_db()
    try:
        from sqlalchemy.orm import load_only
        from backend.json_projection import read_json_projection, read_json_array_projection, read_json_member_projection
        q = db.query(ScanJob).options(load_only(ScanJob.id, ScanJob.repo_id, ScanJob.status,
            ScanJob.started_at, ScanJob.finished_at, ScanJob.control, raiseload=True)).order_by(ScanJob.started_at.desc())
        if repo_id is None:
            encoded_repo = re.match(r"^(\d+)-", str(detail_id or ""))
            if encoded_repo:
                repo_id = int(encoded_repo.group(1))
        if repo_id is not None:
            q = q.filter(ScanJob.repo_id == repo_id)
        if job_id is not None:
            q = q.filter(ScanJob.id == int(job_id))
        for job in q.limit(25):
            try:
                present, detail = read_json_member_projection(db, ScanJob.output,
                    ScanJob.id == int(job.id), ("details",), detail_id)
            except (TypeError, ValueError):
                continue
            if present:
                # Transitional terminal snapshots may have been written
                # before completion rows carried their persisted ids.  Hydrate
                # those rows from the authoritative database so old audits
                # gain the same Finding/CVSS/source/receipt/reproduction
                # navigation as new runs.
                if isinstance(detail, dict) and detail_id.endswith("-complete"):
                    try:
                        from backend.main import _authoritative_finding_state, _finding_payload, _rows_for_scan_job
                        published = [
                            row for row in _rows_for_scan_job(db, job.repo_id, job)
                            if _authoritative_finding_state(row)[1]
                        ]
                        if published:
                            detail = dict(detail)
                            detail["confirmed"] = [_finding_payload(row, db) for row in published]
                            detail["published_findings"] = list(detail["confirmed"])
                    except Exception:
                        pass
                    if job_id is None and not (detail.get("automatic_report") or {}).get("url") and str(job.status or "").lower() in {"completed", "failed"}:
                        try:
                            from backend.main import ensure_automatic_evidence_report
                            repaired = ensure_automatic_evidence_report(int(job.repo_id), scan_job_id=int(job.id))
                            if repaired and repaired.get("url"):
                                detail = dict(detail)
                                detail["automatic_report"] = repaired
                        except Exception:
                            pass
                return detail
            # A restart may leave a finished timeline row without its old
            # in-memory structured detail. Recover only this audit's recorded
            # task/console; never fabricate scanner observations.
            from backend.tool_detail_checkpoint import recorded_task_console
            fallback = recorded_task_console(db, job, detail_id, _terminalize_task_for_job)
            if fallback is not None:
                return fallback
        return None
    finally:
        db.close()


def _normalize_lead_detail_payload(detail: Any) -> Any:
    """Expose scanner observations as ``leads`` at the API boundary.

    Historical stream snapshots used a ``findings`` key for raw SAST/tool
    output.  The stored blob remains immutable for forensic replay, but a
    response must not teach clients that an unproven row is a Finding.  A
    receipt-backed terminal payload (``confirmed``/``published_findings``)
    is intentionally left untouched.
    """
    if not isinstance(detail, dict):
        return detail
    if isinstance(detail.get("findings"), list) and not (
        isinstance(detail.get("published_findings"), list) or isinstance(detail.get("confirmed"), list)
    ):
        result = dict(detail)
        raw = list(detail.get("findings") or [])
        result.pop("findings", None)
        result["leads"] = [
            {**row, "lead_index": idx}
            if isinstance(row, dict) and "lead_index" not in row
            else row
            for idx, row in enumerate(raw)
        ]
        result["lead_count"] = int(detail.get("lead_count", detail.get("count", len(raw))) or 0)
        result.setdefault("result_type", "leads")
        return result
    return detail


@router.get("/api/stream-detail/{detail_id}")
@router.get("/api/repos/{repo_id}/stream-detail/{detail_id}")
async def get_stream_detail(detail_id: str, repo_id: Optional[int] = None, job_id: Optional[int] = None,
                             scan_job_id: Optional[int] = None):
    """Fetch detail data without blocking the event loop on historical JSON."""
    return await _owned_audit_read(_read_stream_detail, detail_id, repo_id, job_id, scan_job_id)


def _read_stream_detail(detail_id, repo_id=None, job_id=None, scan_job_id=None):
    if scan_job_id is not None:
        if job_id is not None and job_id != scan_job_id:
            raise HTTPException(status_code=422, detail="job_id and scan_job_id must identify the same audit")
        job_id = scan_job_id
    owned_job = None
    if job_id is not None:
        db = get_db()
        try:
            owned_job = _owned_scan_job(db, repo_id, job_id, metadata_only=True)
            repo_id = int(owned_job.repo_id)
        finally:
            db.close()
    if (owned_job is not None and detail_id == f"{repo_id}-handoff-triage-report"):
        from backend.audit_interactions import recorded_report_detail
        with get_db() as db:
            detail = recorded_report_detail(db, owned_job)
        return {"detail_id": detail_id, "content": detail}
    detail = pipeline.STREAM_DETAILS.get(detail_id) if owned_job is None or _job_has_live_artifacts(owned_job) else None
    if detail is None:
        detail = _detail_from_persisted_jobs(detail_id, repo_id, job_id)
    elif isinstance(detail, dict) and detail_id.endswith("-complete"):
        # A legacy process cache may still contain a terminal payload without
        # finding ids. Hydrate this response locally without removing or
        # replacing state that could now belong to an active successor.
        rows = detail.get("confirmed") if isinstance(detail.get("confirmed"), list) else []
        if rows and any(not (isinstance(row, dict) and row.get("id")) for row in rows):
            original = detail
            try:
                loaded = _detail_from_persisted_jobs(detail_id, repo_id, job_id)
                detail = loaded or original
            except Exception:
                detail = original
    # A process-local task-console payload can outlive the terminal ScanJob
    # commit (for example when an optional Phase-2 task was never entered).
    # Apply the same terminal lifecycle normalization used by the task list so
    # clicking its progress bar cannot show a contradictory ``running`` state.
    if isinstance(detail, dict) and detail.get("kind") == "task-console":
        task_match = re.match(r"^(\d+)-(?:task|tool)-(.+)$", str(detail_id or ""))
        if task_match:
            _task_repo_id, _task_name = int(task_match.group(1)), task_match.group(2)
            _db = get_db()
            try:
                from sqlalchemy.orm import load_only
                _task_query = _db.query(ScanJob).options(load_only(ScanJob.id, ScanJob.status,
                    raiseload=True)).filter(ScanJob.repo_id == _task_repo_id)
                if job_id is not None:
                    _task_query = _task_query.filter(ScanJob.id == int(job_id))
                _task_job = _task_query.order_by(ScanJob.id.desc()).first()
                if _task_job and str(_task_job.status or "").lower() in {
                    "completed", "failed", "cancelled", "interrupted"
                }:
                    _normalized = _terminalize_task_for_job({
                        "name": _task_name,
                        "state": detail.get("status") or "running",
                        "terminal_status": detail.get("terminal_status") or "running",
                        "summary": detail.get("reason") or "",
                    }, str(_task_job.status or ""))
                    if _normalized.get("terminal_status") != str(detail.get("terminal_status") or "").lower():
                        detail = dict(detail)
                        detail["status"] = _normalized.get("state")
                        detail["terminal_status"] = _normalized.get("terminal_status")
                        detail["reason"] = _normalized.get("reason")
            finally:
                _db.close()
    if detail is None:
        return {"detail_id": detail_id, "content": None, "error": "Detail not found or expired"}
    if isinstance(detail, dict):
        res = _normalize_lead_detail_payload(dict(detail))
        if "content" not in res:
            res["content"] = dict(res)
        res["detail_id"] = detail_id
        return res
    return {"detail_id": detail_id, "content": detail}



@router.get("/api/repos/{repo_id}/phase2-plan-status")
async def phase2_plan_status(repo_id: int):
    """Check if a scan is waiting for Phase 2 plan approval."""
    gate = pipeline.PLAN_APPROVAL_GATES.get(repo_id)
    if gate and not gate.is_set():
        return {"waiting": True, "repo_id": repo_id}
    return {"waiting": False, "repo_id": repo_id}


@router.get("/api/scan-jobs/{job_id}", response_model=ScanJobOut)
def get_scan_job(job_id: int, include_output: bool = True):
    if not include_output:
        rows = _scan_job_metadata_rows(job_id=job_id, limit=1)
        if not rows:
            raise HTTPException(status_code=404, detail="Scan job not found")
        return rows[0]
    db = get_db()
    try:
        j = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not j:
            raise HTTPException(status_code=404, detail="Scan job not found")
        # Keep the single-job API aligned with the paged list: mutable legacy
        # counters are not proof, so derive leads/confirmed/coverage from the
        # persisted audit artifact and receipt-backed rows here as well.
        row = ScanJobOut.model_validate(j)
        # Queue placement is live scheduler state and must never be copied from
        # a stale database column.  Keep this detail endpoint consistent with
        # both the paged history and repository progress views.
        if str(j.status or "") == "queued":
            from backend.scan_worker import scheduler_status
            try:
                queue = scheduler_status(int(j.repo_id))
            except Exception:
                queue = {}
            position = queue.get("queue_position")
            if position is None:
                durable_ids = [
                    int(value[0]) for value in
                    db.query(ScanJob.id)
                    .filter(ScanJob.status == "queued")
                    .order_by(ScanJob.id.asc())
                    .all()
                ]
                try:
                    position = durable_ids.index(int(j.id)) + 1
                except ValueError:
                    position = None
            row.queue_position = position
            row.queue_eta_seconds = queue.get("queue_eta_seconds")
            row.queue_eta_basis = queue.get(
                "queue_eta_basis", "insufficient_completed_audits"
            )
        try:
            output = json.loads(j.output or "{}")
        except (TypeError, json.JSONDecodeError):
            output = {}
        # The durable progress artifact is authoritative for a single-job
        # view too.  Older completed rows often retain the initial SQL cache
        # values (``phase=ingest``/``progress_pct=0``); exposing those here
        # makes a replay/details click disagree with the dashboard list.
        _progress = _scan_job_progress(j, output)
        if isinstance(_progress, dict):
            if _progress.get("phase") is not None:
                row.phase = str(_progress.get("phase") or row.phase or "ingest")
            row.current_task = _scan_task_name(_progress.get("current_task", row.current_task))
            if _progress.get("progress_pct") is not None:
                row.progress_pct = float(_progress.get("progress_pct") or 0)
            if _progress.get("eta_seconds") is not None:
                row.eta_seconds = int(_progress.get("eta_seconds") or 0)
            view = _project_progress_for_read(int(j.repo_id), _progress, j)
            row.eta_seconds = view.get("eta_seconds")
            row.eta_basis = view.get("eta_basis")
            row.elapsed_seconds = view.get("elapsed_seconds", 0.0)
            row.active_task = view.get("active_task")
            row.slow_tasks = view.get("slow_tasks") or []
            row.task_slow_threshold_seconds = view.get("task_slow_threshold_seconds", 300)
            row.is_slow = bool(view.get("is_slow"))
            row.terminal = bool(view.get("terminal"))
        if str(j.status or "").lower() == "completed":
            row.phase = "complete"
            row.progress_pct = 100.0
            row.eta_seconds = None
        if str(j.status or "").lower() in {"failed", "cancelled", "interrupted"}:
            row.eta_seconds = None
        metrics = output.get("discovery_metrics") if isinstance(output, dict) else None
        leads = (
            metrics.get("total_leads")
            if isinstance(metrics, dict) and metrics.get("total_leads") is not None
            else output.get("candidate_findings", output.get("leads_total", 0))
        )
        latest = _latest_scan_jobs(db, {j.repo_id}, metadata_only=True).get(j.repo_id)
        from backend.main import _authoritative_finding_state, _rows_for_scan_job
        row.leads_total = int(leads or 0)
        row.confirmed_findings = sum(
            1 for finding in _rows_for_scan_job(db, j.repo_id, j, latest_job=latest)
            if _authoritative_finding_state(finding)[1]
        )
        row.evidence_status = "complete" if _evidence_complete(j.status, output) else "incomplete"
        row.coverage = _normalized_tool_coverage(
            output.get("coverage") if isinstance(output, dict) else {},
            output.get("tool_results") if isinstance(output, dict) else [],
        )
        _project_scan_observations(row, view)
        # Keep the explicit detail boundary discoverable from either the
        # paged history row or a direct single-job lookup.  The list endpoint
        # is metadata-only; this URL is the stable, job-bound artifact route.
        row.details_url = f"/api/scan-jobs/{int(j.id)}"
        return row
    finally:
        db.close()


@router.post("/api/scan-jobs/{job_id}/replay")
async def replay_scan_job(job_id: int):
    """Replay an audit from its immutable target snapshot.

    A replay is always a new ScanJob.  It never mutates the historical job or
    silently follows the repository's current branch.  Jobs created before
    snapshot support return a precise 409 explaining why they cannot be
    replayed; callers must re-enroll the target for a fresh run.
    """
    db = get_db()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == int(job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Scan job not found")
        if job.status in {"queued", "running"}:
            raise HTTPException(status_code=409, detail="audit is still running; replay is available after a terminal result")
        repo = db.query(Repo).filter(Repo.id == int(job.repo_id)).first()
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")
        if repo.status == "archived":
            raise HTTPException(status_code=409, detail="Restore the archived repository before replaying an audit")
        from backend.main import require_ai_readiness
        require_ai_readiness(db)
        # A repository can have only one active audit, regardless of whether
        # that audit is a replay of this particular historical job.  Checking
        # only ``replay_of_job_id`` raced the database's one-active-job index
        # whenever a normal scan (or another replay) was already queued.
        active_job = (
            db.query(ScanJob)
            .filter(
                ScanJob.repo_id == int(repo.id),
                ScanJob.status.in_(["queued", "running", "paused"]),
            )
            .order_by(ScanJob.id.desc())
            .first()
        )
        if active_job:
            return {
                "status": "already_running",
                "job_id": int(active_job.id),
                "repo_id": int(repo.id),
                "job_status": str(active_job.status or "queued"),
                "requested_replay_of_job_id": int(job.id),
                "message": "this repository already has an active audit; open that job or retry replay after it is terminal",
            }
        try:
            output = json.loads(job.output or "{}")
        except Exception:
            output = {}
        plan = output.get("audit_plan") if isinstance(output, dict) else {}
        snapshot = output.get("target_snapshot") if isinstance(output, dict) else {}
        if not isinstance(snapshot, dict):
            snapshot = {}
        if not isinstance(plan, dict):
            plan = {}
        # New pipeline outputs put the snapshot under audit_plan; accepting the
        # top-level form keeps the endpoint compatible with transitional jobs.
        snapshot = {**(plan.get("target_snapshot") or {}), **snapshot}
        source_path = str(snapshot.get("source_path") or "").strip()
        snapshot_path = str(snapshot.get("path") or "").strip()
        if not source_path and snapshot_path:
            source_path = str(Path(snapshot_path) / "source")
        identity = output.get("target_identity") if isinstance(output, dict) else {}
        if not isinstance(identity, dict):
            identity = {}
        identity = {
            "target_revision": str(identity.get("target_revision") or plan.get("target_revision") or ""),
            "target_tree_hash": str(identity.get("target_tree_hash") or plan.get("target_tree_hash") or snapshot.get("tree_hash") or ""),
            "target_tree": str(identity.get("target_tree") or plan.get("target_tree") or ""),
        }
        if not source_path:
            raise HTTPException(status_code=409, detail="audit has no immutable source snapshot; re-enroll the target for replay")
        try:
            from backend.target_snapshots import load_snapshot
            # load_snapshot accepts the object root and re-verifies both the
            # manifest and source content hash before any worker is started.
            loaded = load_snapshot(snapshot_path or source_path)
            source_path = str(loaded["source_path"])
            if identity.get("target_tree_hash") and loaded.get("tree_hash") != identity["target_tree_hash"]:
                raise ValueError("snapshot tree hash differs from the historical audit identity")
            identity["target_tree_hash"] = loaded.get("tree_hash") or identity.get("target_tree_hash", "")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=409, detail=f"immutable audit snapshot is unavailable or invalid: {str(exc)[:240]}")
        # Reserve a new job while keeping the original source/branch metadata.
        from backend.audit_depth import admitted_depth
        new_job = ScanJob(
            repo_id=int(repo.id), status="queued", started_at=datetime.utcnow(),
            audit_depth=admitted_depth(db.query(Settings).first(), previous=job, output=output),
            replay_of_job_id=int(job.id), replay_snapshot_path=source_path,
            replay_target_identity_json=json.dumps(identity, sort_keys=True),
        )
        db.add(new_job)
        try:
            db.commit()
        except IntegrityError:
            # A concurrent request may win after the read above.  Resolve the
            # authoritative active row instead of leaking an SQL 500 or
            # claiming that a replay was reserved when it was not.
            db.rollback()
            winner = (
                db.query(ScanJob)
                .filter(
                    ScanJob.repo_id == int(repo.id),
                    ScanJob.status.in_(["queued", "running", "paused"]),
                )
                .order_by(ScanJob.id.desc())
                .first()
            )
            if winner is not None:
                return {
                    "status": "already_running",
                    "job_id": int(winner.id),
                    "repo_id": int(repo.id),
                    "job_status": str(winner.status or "queued"),
                    "requested_replay_of_job_id": int(job.id),
                    "message": "a concurrent request already reserved the active audit",
                }
            raise HTTPException(
                status_code=503,
                detail="Replay admission conflicted but no active job is available; retry safely.",
                headers={"Retry-After": "2"},
            )
        db.refresh(new_job)
        from backend.scan_worker import submit_scan, set_scan_control
        set_scan_control(int(repo.id), "resume")
        try:
            result = submit_scan(
                int(repo.id), get_db, Repo, Finding, ScanJob,
                notify=None,
                cvss_threshold=float((db.query(Settings).first() or Settings()).cvss_threshold or 7.0),
                existing_job_id=int(new_job.id),
                source_override=source_path,
                target_identity_override=identity,
                replay_of_job_id=int(job.id),
            )
        except Exception:
            # The queued row is durable and startup reconciliation can retry it;
            # leave it queued rather than deleting the user's replay request.
            db.close()
            raise
        if isinstance(result, dict) and result.get("status") == "queue_full":
            durable = db.query(ScanJob).filter(ScanJob.id == int(new_job.id)).first()
            if durable is not None and str(durable.status or "") == "queued":
                durable.status = "failed"
                durable.finished_at = datetime.utcnow()
                durable.output = json.dumps({
                    "error": "Replay admission capacity was full; no worker future was created",
                    "terminal_reason": "queue-capacity-rejected",
                    "evidence_status": "incomplete",
                    "worker_started": False,
                    "replay_of_job_id": int(job.id),
                })
                db.commit()
            raise HTTPException(
                status_code=429,
                detail={
                    "message": result.get("message") or "Audit queue is full",
                    "repo_id": int(repo.id),
                    "job_id": int(new_job.id),
                    "scheduler": result,
                },
                headers={"Retry-After": str(result.get("retry_after_seconds") or 5)},
            )
        return {
            **result,
            "job_id": int(new_job.id),
            "replay_of_job_id": int(job.id),
            "target_identity": identity,
            # Never return source/object filesystem paths.  The new job and
            # historical job both have stable verification endpoints instead.
            "snapshot": {
                "tree_hash": snapshot.get("tree_hash") or identity.get("target_tree_hash"),
                "manifest_hash": snapshot.get("manifest_hash") or "",
                "evidence_url": f"/api/scan-jobs/{int(job.id)}/snapshot",
                "replay_url": f"/api/scan-jobs/{int(new_job.id)}/snapshot",
            },
        }
    finally:
        db.close()


@router.get("/api/scan-jobs/{job_id}/snapshot")
def get_scan_snapshot(job_id: int):
    """Return the verified immutable target manifest for a historical audit.

    Paths and mutable checkout details are intentionally omitted.  Consumers
    receive a stable, revision-bound identity plus links to this resource and
    the replay operation; opening it always re-hashes the source object.
    """
    db = get_db()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == int(job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Scan job not found")
        try:
            output = json.loads(job.output or "{}")
        except Exception:
            output = {}
        plan = output.get("audit_plan") if isinstance(output, dict) else {}
        if not isinstance(plan, dict):
            plan = {}
        snapshot = output.get("target_snapshot") if isinstance(output, dict) else {}
        if not isinstance(snapshot, dict):
            snapshot = {}
        snapshot = {**(plan.get("target_snapshot") or {}), **snapshot}
        path = str(snapshot.get("path") or "").strip()
        if not path and snapshot.get("source_path"):
            path = str(Path(str(snapshot.get("source_path"))).parent)
        if not path:
            raise HTTPException(status_code=409, detail="audit has no immutable target snapshot")
        try:
            from backend.target_snapshots import load_snapshot
            manifest = load_snapshot(path)
        except Exception as exc:
            raise HTTPException(status_code=409, detail=f"immutable target snapshot is unavailable or invalid: {str(exc)[:240]}")
        return {
            "job_id": int(job.id),
            "repo_id": int(job.repo_id),
            "status": str(job.status or "unknown"),
            "snapshot": {
                key: manifest.get(key)
                for key in ("schema_version", "repo_id", "job_id", "created_at", "tree_hash", "target_revision", "bytes", "manifest_hash")
            },
            "evidence_url": f"/api/scan-jobs/{int(job.id)}/snapshot",
            "replay_url": f"/api/scan-jobs/{int(job.id)}/replay",
            "verified": True,
        }
    finally:
        db.close()


@router.get("/api/repos/{repo_id}/phase2-plan")
def get_phase2_plan(repo_id: int):
    db = get_db()
    try:
        job = (
            db.query(ScanJob)
            .filter(ScanJob.repo_id == repo_id)
            .order_by(ScanJob.started_at.desc())
            .first()
        )
        if not job or not job.output:
            raise HTTPException(status_code=404, detail="Phase 2 plan not yet available")
        try:
            data = json.loads(job.output)
        except Exception:
            raise HTTPException(status_code=500, detail="Could not parse scan job output")
        plan = data.get("phase2_plan")
        if plan is None:
            raise HTTPException(status_code=404, detail="Phase 2 plan not yet generated")
        return plan
    finally:
        db.close()


@router.get("/api/repos/{repo_id}/intent-model")
def get_intent_model(repo_id: int, scan_job_id: Optional[int] = None, job_id: Optional[int] = None):
    """Read only the selected audit's recorded intent model, with an explicit gap.

    The repo-only live cache has no audit identity and cannot establish provenance.
    SQL selects at most two bounded model fields; unrelated evidence is not decoded.
    """
    from sqlalchemy import LargeBinary, and_, case, cast, func, select
    from backend import json_projection

    if scan_job_id is not None and job_id is not None and scan_job_id != job_id:
        raise HTTPException(status_code=400, detail="Conflicting audit identifiers")
    selected_id = scan_job_id if scan_job_id is not None else job_id
    if selected_id is not None and (type(selected_id) is not int or selected_id <= 0):
        raise HTTPException(status_code=400, detail="Audit identifier must be a positive integer")
    limit = 256 * 1024
    paths = [("intent_model",), ("attack_surface", "intent_model")]

    @json_projection._sqlite_projection_scope
    def recorded(db, predicate):
        dialect, document, source, where = json_projection._prepared_document(db, ScanJob.output, predicate)
        # Inspect validity separately as a scalar, never select the full TEXT.
        valid = (func.json_valid(ScanJob.output) if dialect == "sqlite" else
                 func.pg_input_is_valid(ScanJob.output, "jsonb"))
        _, safe_document = json_projection._document(db, ScanJob.output)
        root_kind = func.json_type(safe_document) if dialect == "sqlite" else func.jsonb_typeof(safe_document)
        valid_row = db.execute(select(valid, func.length(ScanJob.output), root_kind).where(predicate)).first()
        if valid_row is None or not valid_row[1]:
            return "not_recorded", []
        if not valid_row[0] or valid_row[2] != "object":
            return "malformed_output", []
        _, fields = json_projection._fields(db, ScanJob.output, paths, prepared=(dialect, document))
        expressions = []
        for index in range(len(paths)):
            kind, value = fields[index * 2:index * 2 + 2]
            size = func.length(cast(value, LargeBinary)) if dialect == "sqlite" else func.octet_length(value)
            expressions.extend((kind, size, case((size <= limit, value), else_=None)))
        row = db.execute(select(*expressions).select_from(source).where(where)).first()
        if row is None:
            return "not_recorded", []
        result = []
        for index, path in enumerate(paths):
            kind, size, value = row[index * 3:index * 3 + 3]
            if size is not None and size > limit:
                result.append(("oversized", None, ".".join(path)))
            else:
                present, model = json_projection._decode(kind, value, dialect)
                result.append(("present" if present else "absent", model, ".".join(path)))
        return "read", result

    db = get_db()
    try:
        if db.query(Repo.id).filter(Repo.id == repo_id).first() is None:
            raise HTTPException(status_code=404, detail="Repository not found")
        if selected_id is None:
            latest = db.query(ScanJob.id).filter(ScanJob.repo_id == repo_id).order_by(ScanJob.id.desc()).first()
            selected_id = latest[0] if latest else None
        job = _owned_scan_job(db, repo_id, selected_id, metadata_only=True) if selected_id else None
        status = str(job.status) if job is not None else None
        binding = {"repo_id": repo_id, "scan_job_id": selected_id, "job_id": selected_id,
                   "job_status": status, "source": "persisted"}

        def unavailable(code, reason):
            return {**binding, "status": "unavailable", "available": False,
                    "reason_code": code, "reason": reason}

        if job is None:
            return unavailable("no_audit", "No audit has been recorded for this repository.")
        try:
            disposition, candidates = recorded(db, and_(ScanJob.id == selected_id, ScanJob.repo_id == repo_id))
        except (ValueError, TypeError, RecursionError):
            return unavailable("malformed_model", "This audit's recorded gating model could not be decoded.")
        if disposition == "malformed_output":
            return unavailable("malformed_output", "This audit's recorded output is not valid JSON; its gating model is unavailable.")
        for state, model, source_ref in candidates:
            if state == "oversized":
                return unavailable("model_size_limit", "This audit's recorded gating model exceeds the 256 KiB display limit.")
            if state == "absent" or model is None or model == {}:
                continue
            if not isinstance(model, dict) or any(key in model and not isinstance(model[key], list)
                    for key in ("product_intents", "boundaries", "gating_rules", "intended_primitives")):
                return unavailable("malformed_model", "This audit's recorded gating model has an unsupported structure.")
            if not (any(model.get(key) for key in ("product_intents", "boundaries", "gating_rules", "intended_primitives"))
                    or isinstance(model.get("summary"), str) and model["summary"].strip()):
                continue
            return {**model, **binding, "status": "available", "available": True,
                    "reason_code": "recorded", "reason": "Recorded for this audit; inferred boundaries are not proof of security.",
                    "source_ref": source_ref}
        if status in {"queued", "running"}:
            return unavailable("preparing", "No gating model has been recorded yet for this active audit.")
        if status == "paused":
            return unavailable("paused_not_recorded", "This audit is paused and has no recorded gating model.")
        return unavailable("not_recorded", "No gating model was recorded for this " + (status or "unknown-status") + " audit.")
    finally:
        db.close()


def _progress_int(value: object, default: int = 0) -> int:
    """Coerce an untrusted persisted counter without leaking an invalid UI ratio."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _progress_recovery_for_read(source, repo_id, job):
    """Keep public exact-audit recovery notices when polling replaces SSE state."""
    result = {}
    fields = {"schema_version", "repo_id", "scan_job_id", "active", "status", "stage", "checkpoint_id",
              "reason", "initial_policy", "continuation_policy", "continued_at", "completed_at",
              "policy", "state", "continue_allowed", "continue_url", "replay_url", "tasks"}
    for key in ("task_recovery", "audit_recovery"):
        record = source.get(key)
        if (isinstance(record, dict) and job is not None and record.get("repo_id") == repo_id
                and record.get("scan_job_id") == int(job.id)):
            result[key] = {name: deepcopy(value) for name, value in record.items() if name in fields}
    return result


def _ended_audit_task(row: dict, status: str) -> dict:
    """Project unfinished work after the audit ends; never rewrite its evidence."""
    result = dict(row)
    if status in {"completed", "failed", "cancelled", "interrupted"} and result.get("status") in {"running", "queued"}:
        if result.get("reason"):
            result["recorded_reason"] = result.get("recorded_reason", result["reason"])
        result.update(recorded_status=result.get("recorded_status", result["status"]),
                      status="skipped", terminal_status="skipped", scope_complete=False,
                      ended_with_audit=True, is_slow=False)
        result["reason"] = f"Unfinished: audit {status} before this task completed. Its last recorded state is retained."
    return result


def _project_progress_for_read(repo_id: int, raw: object, job=None, *, include_coverage_map: bool = True) -> dict:
    """Build a safe progress response without restoring/mutating process state.

    ``GET /progress`` used to call ``audit_progress.restore`` (and occasionally
    ``clear``) as a side effect.  A dashboard poll could therefore overwrite a
    currently running worker's private task ledger, or erase it after a clock
    parsing hiccup.  Progress snapshots are already JSON-shaped, so project a
    local response copy instead.
    """
    source = raw if isinstance(raw, dict) else {}
    job_status = str(getattr(job, "status", None) or source.get("status") or "running")
    terminal_job = job_status in {"completed", "failed", "cancelled", "interrupted"}
    raw_tasks = source.get("tasks") if isinstance(source.get("tasks"), dict) else {}
    tasks = {
        key: _progress_int(raw_tasks.get(key, 0))
        for key in ("completed", "running", "failed", "skipped")
    }
    observed = sum(tasks.values())
    # A partially persisted task ledger can race the plan denominator.  Never
    # make a client render `N/0` or `N/M` where N > M; preserve the observation
    # and label its plan as incomplete instead.
    tasks["total"] = max(_progress_int(raw_tasks.get("total", 0)), observed)

    phase = str(source.get("phase") or "ingest")
    try:
        progress_pct = float(source.get("progress_pct", 0) or 0)
    except (TypeError, ValueError):
        progress_pct = 0.0
    progress_pct = max(0.0, min(100.0, progress_pct))
    eta_raw = source.get("eta_seconds")
    eta_seconds = None if eta_raw is None else _progress_int(eta_raw)
    # The durable ScanJob clock is authoritative.  Recompute it on every read
    # so a quiet subprocess still has a live timer instead of a frozen value
    # from the last progress event.
    try:
        started_at = getattr(job, "started_at", None) if job is not None else None
        finished_at = getattr(job, "finished_at", None) if job is not None else None
        if started_at:
            end = finished_at or datetime.utcnow()
            elapsed_seconds = max(0.0, float((end - started_at).total_seconds()))
        else:
            elapsed_seconds = max(0.0, float(source.get("elapsed_seconds", 0) or 0))
    except (TypeError, ValueError, AttributeError):
        elapsed_seconds = 0.0
    bottlenecks = source.get("bottlenecks")
    coverage = source.get("coverage")
    current_task = source.get("current_task")
    task_timeline = source.get("task_timeline")
    if not isinstance(task_timeline, list):
        task_timeline = []
    slow_tasks = source.get("slow_tasks")
    if not isinstance(slow_tasks, list):
        slow_tasks = []
    threshold = _progress_int(source.get("task_slow_threshold_seconds", 300), 300)
    # Keep the slow-task flag and durations truthful even if the worker has not
    # emitted an event recently.  Task rows carry their own start timestamps.
    now = datetime.utcnow()
    normalized_tasks = []
    for raw_task in task_timeline:
        if not isinstance(raw_task, dict):
            continue
        row = dict(raw_task)
        try:
            if not terminal_job and str(row.get("status") or "") == "running" and row.get("started_at"):
                started = datetime.fromisoformat(str(row["started_at"]).replace("Z", "+00:00"))
                if started.tzinfo is not None:
                    started = started.replace(tzinfo=None)
                row["elapsed_seconds"] = round(max(0.0, (now - started).total_seconds()), 1)
        except (TypeError, ValueError, OverflowError):
            pass
        row = audit_progress.project_task_runtime(row, now=now.replace(tzinfo=timezone.utc).timestamp(), terminal=terminal_job, threshold=threshold)
        row = _ended_audit_task(row, job_status)
        normalized_tasks.append(row)
    task_timeline = normalized_tasks
    if task_timeline:
        tasks["running"] = sum(row.get("status") == "running" for row in task_timeline)
        tasks["queued"] = sum(row.get("status") == "queued" for row in task_timeline)
    slow_tasks = sorted([row for row in task_timeline if row.get("is_slow")],
                        key=lambda row: float(row.get("elapsed_seconds") or 0), reverse=True)
    active_task = None
    if not terminal_job:
        active = [row for row in task_timeline if row.get("status") in {"running", "queued"}]
        # current_task is a scheduling label, often only {name,index,total}.
        # Use the normalized task clock so a slow-task warning cannot say 0s
        # just because that label omitted timing fields.
        active_task = max(active, key=lambda row: (row.get("status") == "running", float(row.get("elapsed_seconds") or 0)),
                          default=current_task if isinstance(current_task, dict) else None)
    if terminal_job:
        slow_tasks = []
        current_task = None
        # A terminal audit cannot have executing/queued tasks. A partial older
        # checkpoint may have counters without rows, so retain that work as an
        # explicit unfinished count instead of manufacturing successful tasks.
        unfinished = max(_progress_int(raw_tasks.get("unfinished")),
                         _progress_int(raw_tasks.get("running")) + _progress_int(raw_tasks.get("queued")),
                         sum(row.get("ended_with_audit") is True for row in task_timeline))
        tasks.update(running=0, queued=0, unfinished=unfinished)
        tasks["total"] = max(tasks["total"], sum(tasks[key] for key in ("completed", "failed", "skipped", "unfinished")))
    is_slow = bool(slow_tasks)
    recon_tools, coverage = audit_progress.project_runtime_inventory(source.get("recon_tools"), coverage, task_timeline)
    if terminal_job:
        recon_tools = [_ended_audit_task(row, job_status) if isinstance(row, dict) else row for row in recon_tools]
        unfinished_tools = max(_progress_int(coverage.get("tools_unfinished")),
                               _progress_int(coverage.get("tools_running")) + _progress_int(coverage.get("tools_queued")),
                               sum(row.get("ended_with_audit") is True for row in recon_tools if isinstance(row, dict)))
        coverage.update(tools_running=0, tools_queued=0,
                        tools_unfinished=unfinished_tools)
    eta_basis = str(source.get("eta_basis") or "insufficient_observations")
    completion_state = source.get("completion_state")
    completion_state = completion_state if isinstance(completion_state, str) and completion_state in audit_progress._PUBLICATION_STATES else None
    if terminal_job:
        completion_state = None
        eta_basis = "terminal"
        eta_seconds = None
    elif job_status == "paused":
        eta_basis, eta_seconds = "paused", None
    elif job_status == "running" and completion_state:
        eta_basis, eta_seconds = "finalizing", None
    elif eta_basis in {"finalizing", "report_pending"}:
        # Historical progress may have inferred completion from a temporarily
        # exhausted ledger. Correct the read without rewriting its evidence.
        eta_basis, eta_seconds = "preparing_next_tasks", None
    runtime_active = [row for row in task_timeline if row.get("status") in {"queued", "running"}
                      and row.get("slow_clock_kind") in {"queue", "execution"}
                      and isinstance(row.get("runtime_progress"), dict) and row["runtime_progress"].get("phase") in {"Pending", "Running"}]
    if not terminal_job and runtime_active:
        eta_seconds = None
        eta_basis = "waiting_for_runtime_capacity" if any(row["runtime_progress"]["phase"] == "Pending" for row in runtime_active) else "runtime_execution_in_progress"
    if job_status == "running" and not completion_state and audit_progress.lab_setup_active(task_timeline):
        eta_basis, eta_seconds = "lab_setup_in_progress", None
    return {
        "schema_version": _progress_int(source.get("schema_version", 1), 1) or 1,
        "repo_id": int(repo_id),
        "scan_job_id": source.get("scan_job_id"),
        "status": job_status,
        "phase": phase,
        "phase_label": str(source.get("phase_label") or audit_progress.phase_label(phase)),
        "current_task": dict(current_task) if isinstance(current_task, dict) else current_task,
        "message": str(source.get("message") or ""),
        "started_at": source.get("started_at"),
        "updated_at": source.get("updated_at"),
        "elapsed_seconds": round(elapsed_seconds, 1),
        "eta_seconds": eta_seconds,
        "eta_basis": eta_basis,
        "completion_state": completion_state,
        "progress_pct": progress_pct,
        "tasks": tasks,
        "bottlenecks": audit_progress.timing_bottlenecks(bottlenecks, slow_tasks, threshold),
        "leads_total": _progress_int(source.get("leads_total", 0)),
        "observations_total": _progress_int(source.get("observations_total", 0)),
        "observations_label": str(source.get("observations_label") or "Raw Phase 1 observations (before deduplication; not confirmed findings)"),
        "inventory_status": str(source.get("inventory_status") or "not_started"),
        "recon_tools": recon_tools,
        "qualified_leads": _progress_int(source.get("qualified_leads", 0)),
        "confirmed_findings": _progress_int(source.get("confirmed_findings", 0)),
        "evidence_status": str(source.get("evidence_status") or "incomplete"),
        "coverage": dict(coverage) if isinstance(coverage, dict) else {},
        **_progress_recovery_for_read(source, repo_id, job),
        "coverage_map": deepcopy(source.get("coverage_map")) if include_coverage_map and isinstance(source.get("coverage_map"), dict) else None,
        **({"coverage_map_omitted": True, "coverage_map_summary": (
            deepcopy(source["coverage_map_summary"]) if source.get("coverage_map_omitted") is True
            and isinstance(source.get("coverage_map_summary"), dict)
            else audit_progress.coverage_map_summary(source.get("coverage_map")))} if not include_coverage_map else {}),
        "ai_pause": (deepcopy(source["ai_pause"]) if isinstance(source.get("ai_pause"), dict)
            and source["ai_pause"].get("repo_id") == repo_id
            and job is not None and source["ai_pause"].get("scan_job_id") == int(job.id)
            and str(job.status or "") == "paused" else None),
        "stream_dropped": _progress_int(source.get("stream_dropped", 0)),
        "task_timeline": task_timeline,
        "active_task": dict(active_task) if isinstance(active_task, dict) else None,
        "slow_tasks": slow_tasks,
        "task_slow_threshold_seconds": threshold,
        "is_slow": is_slow,
        "terminal": terminal_job,
    }


def _terminal_progress_from_worker(db, job):
    """Read the last committed incomplete display during this worker's cleanup.

    Durable terminal status alone never authorizes a cache read. Both original
    lease rows, the process worker, and the publication marker must still agree.
    """
    if (job.status not in {"completed", "failed", "cancelled", "interrupted"}
            or not job.finished_at or job.control not in (None, "")
            or not job.lease_token or not job.lease_owner):
        return None
    from backend.scan_worker import capture_terminal_read_owner, terminal_read_owner_is_current
    from backend.main import ScanLease, _authoritative_finding_state, _rows_for_scan_job
    from sqlalchemy.orm import aliased
    repo_id, job_id = int(job.repo_id), int(job.id)
    token, owner = job.lease_token, job.lease_owner
    worker = capture_terminal_read_owner(repo_id, job_id, token, owner)
    if worker is None:
        return None
    observed = audit_progress.terminal_status_snapshot(repo_id, job_id,
        lease_token=token, lease_owner=owner, worker_marker=worker)
    if observed is None:
        return None
    progress, marker = observed
    if marker["finished_at"] != job.finished_at or marker["status"] != job.status:
        return None
    restored = _project_progress_for_read(repo_id, progress, job, include_coverage_map=False)
    # Keep confirmation on the original signed-Finding path. Private display
    # counters cannot create proof or promote evidence completeness.
    restored["confirmed_findings"] = sum(
        1 for row in _rows_for_scan_job(db, repo_id, job) if _authoritative_finding_state(row)[1]
    )
    restored.update(status=job.status, terminal=True, evidence_status="incomplete", eta_seconds=None)
    if job.status == "completed":
        restored.update(phase="complete", phase_label=audit_progress.phase_label("complete"), progress_pct=100.0)
    else:
        restored["message"] = f"Audit {job.status}; no complete proof bundle is available"
        if marker["completion_state"] == "coverage_blocked":
            restored.update(phase="dynamic", phase_label=audit_progress.phase_label("dynamic"))
            restored["message"] = str((restored.get("coverage_map_summary") or {}).get("gate", {}).get("reason") or "Phase 2 coverage is incomplete; Phase 3 is locked")
    now = datetime.utcnow()
    live_lease = db.query(ScanLease).filter(ScanLease.repo_id == repo_id, ScanLease.job_id == job_id,
        ScanLease.lease_token == token, ScanLease.owner == owner, ScanLease.expires_at > now).exists()
    successor = aliased(ScanJob)
    active_successor = db.query(successor).filter(successor.repo_id == repo_id, successor.id != job_id,
        successor.status.in_({"queued", "running", "paused"})).exists()
    # This final scalar query also closes races during Finding verification.
    current = db.query(ScanJob.id).filter(ScanJob.id == job_id, ScanJob.repo_id == repo_id,
        ScanJob.status == marker["status"], ScanJob.finished_at == marker["finished_at"],
        ScanJob.control == job.control, ScanJob.lease_token == token, ScanJob.lease_owner == owner,
        ScanJob.lease_expires_at > now, live_lease, ~active_successor).first()
    if (current is None or not terminal_read_owner_is_current(repo_id, job_id, token, owner, worker)
            or not audit_progress.terminal_status_metadata_is_current(repo_id, job_id, marker)):
        return None
    return {"source": "persisted", **restored}


@router.get("/api/repos/{repo_id}/progress")
def get_audit_progress(repo_id: int, job_id: Optional[int] = None, include_coverage_map: bool = True):
    """Return the structured live/replayed audit progress contract.

    Unlike the console stream, this endpoint is safe to poll and does not infer
    completion from elapsed time. ``confirmed_findings`` is proof-gated; zero is
    explicitly not a clean-codebase verdict.
    """
    from sqlalchemy.orm import defer
    from backend.audit_metadata import load_audit_metadata, load_progress_checkpoint
    db = get_db()
    try:
        # Select ownership and lifecycle columns first. Even a live lite poll
        # must not load the large durable artifacts before choosing live state.
        job_query = db.query(ScanJob).options(
            defer(ScanJob.output, raiseload=True),
            defer(ScanJob.progress_json, raiseload=True),
        ).filter(ScanJob.repo_id == repo_id)
        if job_id is not None:
            job_query = job_query.filter(ScanJob.id == int(job_id))
        job = job_query.order_by(ScanJob.started_at.desc()).first()
        if not job:
            detail = "Scan job does not belong to this repository" if job_id is not None else "Repository has no audit"
            raise HTTPException(status_code=404, detail=detail)
        projection_gaps = []

        def _with_queue_state(payload: dict) -> dict:
            """Attach live/durable queue position without mutating audit state."""
            if projection_gaps:
                payload["metadata_warning"] = "Some recorded progress metadata is malformed; evidence completeness could not be established from this read."
                payload["message"] = payload["metadata_warning"]
                payload["evidence_status"] = "incomplete"
            if str(job.status or "") != "queued":
                return payload
            try:
                from backend.scan_worker import scheduler_status
                queue = scheduler_status(repo_id)
            except Exception:
                queue = {}
            position = queue.get("queue_position")
            if position is None:
                # A restart can leave more durable rows than this process may
                # admit at once.  ID is the immutable FIFO key; started_at is
                # deliberately not used because the pipeline rewrites it when
                # execution actually begins.
                try:
                    position = (
                        db.query(ScanJob)
                        .filter(ScanJob.status == "queued", ScanJob.id <= int(job.id))
                        .count()
                    )
                except Exception:
                    position = None
            payload.update({
                "queue_position": position,
                "queue_eta_seconds": queue.get("queue_eta_seconds"),
                "queue_eta_basis": queue.get("queue_eta_basis", "insufficient_completed_audits"),
                "scheduler_scope": queue.get("scheduler_scope", "durable"),
            })
            return payload
        terminal_candidate = (not include_coverage_map
                              and job.status in {"completed", "failed", "cancelled", "interrupted"})
        if terminal_candidate:
            try:
                terminal_display = _terminal_progress_from_worker(db, job)
            except Exception:
                # Unknown, invalid or unavailable private state retains the
                # established durable path and its proof/recovery semantics.
                terminal_display = None
            if terminal_display is not None:
                return _with_queue_state(terminal_display)
            # A terminal candidate may have changed during the ownership
            # checks. Refresh only scalars before its durable fallback, and
            # do not borrow a stale live ledger if it became active again.
            db.refresh(job, attribute_names=["id", "repo_id", "status", "control", "started_at",
                "finished_at", "phase", "current_task", "progress_pct", "eta_seconds",
                "lease_token", "lease_owner", "lease_expires_at"])
        live = pipeline.audit_progress.snapshot(repo_id, include_coverage_map=include_coverage_map)
        if not terminal_candidate and pipeline.audit_progress.exists(repo_id):
            # A process-local snapshot can outlive a job row (tests, restart
            # recovery, or a new scan after a prior terminal run).  Never show
            # stale phase/ETA data for a newer job; the durable row is the source
            # of truth until that scan calls audit_progress.start().
            try:
                # A durable job ID is stronger than timestamps.  The worker
                # intentionally starts its in-memory clock immediately before
                # it writes ``ScanJob.started_at``; comparing the two can be
                # off by milliseconds and was the direct cause of live Dapr
                # progress being discarded on every poll.
                live_job_id = live.get("scan_job_id")
                # A terminal durable job must always win over an in-memory
                # snapshot.  Repository/job integer ids can be recycled in a
                # fresh SQLite test database (and stale process memory can
                # survive a DB restore), so an old completed live ledger must
                # never make a newly-read historical job look active.
                if (
                    str(job.status or "") in {"queued", "running", "paused"}
                    and live_job_id is not None
                    and int(live_job_id) == int(job.id)
                ):
                    return _with_queue_state({"source": "live", **_project_progress_for_read(repo_id, live, job, include_coverage_map=include_coverage_map)})
                if live_job_id is None:
                    # Pre-binding snapshots are only the short setup window
                    # before ``scan_repo`` creates/binds its durable job.  For
                    # an API read, the job row is authoritative and this also
                    # prevents an old unbound snapshot from leaking across a
                    # recycled repository id.
                    pass  # unbound snapshots are ignored until a worker binds them
                else:
                    pass  # stale job binding: ignore it; a read must not erase worker state
            except Exception:
                # A malformed process-local snapshot is not evidence of the
                # current job.  Ignore it and fall back to the durable replay;
                # never let a GET request modify a worker-owned snapshot.
                pass
        if include_coverage_map:
            raw_output, raw_checkpoint = db.query(ScanJob.output, ScanJob.progress_json).filter(
                ScanJob.id == int(job.id)).one()
            try:
                data = json.loads(raw_output or "{}")
            except (ValueError, TypeError):
                data = {}
            try:
                checkpoint = json.loads(raw_checkpoint or "{}")
            except (ValueError, TypeError):
                checkpoint = {}
        else:
            # Project in the database before Python decoding. This preserves
            # the recorded map header while omitting nodes, task evidence and
            # unrelated source excerpts from collapsed historical polling.
            try:
                data = load_audit_metadata(db, job)
            except (ValueError, TypeError):
                data = {}
                projection_gaps.append("audit artifact")
            try:
                checkpoint = load_progress_checkpoint(db, job)
            except (ValueError, TypeError):
                checkpoint = {}
                projection_gaps.append("progress checkpoint")
        if not isinstance(data, dict):
            data = {}
        persisted = data.get("progress") or {}
        if not isinstance(persisted, dict):
            persisted = {}

        def _complete_evidence():
            return (_evidence_complete(job.status, data) if include_coverage_map
                    else _evidence_complete_for_job(db, job, data))
        if isinstance(checkpoint, dict) and checkpoint and (
            not persisted or (
                job.status in {"running", "queued", "paused"}
                and str(checkpoint.get("updated_at") or "") >= str(persisted.get("updated_at") or "")
            )
        ):
            persisted = checkpoint
        if persisted:
            # The full output may be newer than its last progress checkpoint.
            # Preserve job-bound coverage on restart without restoring live state.
            if isinstance(data.get("coverage_map"), dict) and (
                not isinstance(persisted.get("coverage_map"), dict)
                or str(data["coverage_map"].get("updated_at") or "") >= str(persisted["coverage_map"].get("updated_at") or "")
            ):
                persisted = {**persisted, "coverage_map": data["coverage_map"]}
            restored = _project_progress_for_read(repo_id, persisted, job, include_coverage_map=include_coverage_map)
            restored["scan_job_id"] = int(job.id)
            # Do not trust a JSON progress snapshot for proof counts.  It is a
            # replay artifact, not an authority source, and older snapshots may
            # predate signed receipts.
            from backend.main import _authoritative_finding_state, _rows_for_scan_job
            _repo_rows = _rows_for_scan_job(db, repo_id, job)
            restored["confirmed_findings"] = sum(
                1 for row in _repo_rows if _authoritative_finding_state(row)[1]
            )
            _metrics = data.get("discovery_metrics") if isinstance(data, dict) else None
            if isinstance(_metrics, dict) and _metrics.get("total_leads") is not None:
                restored["leads_total"] = int(_metrics.get("total_leads") or 0)
                restored["qualified_leads"] = int(_metrics.get("qualified_leads") or 0)
            if job.status == "completed":
                restored["status"] = "completed"
                restored["terminal"] = True
                restored["phase"] = "complete"
                restored["phase_label"] = pipeline.audit_progress.phase_label("complete")
                restored["progress_pct"] = 100.0
                restored["evidence_status"] = "complete" if _complete_evidence() else "incomplete"
            if job.status in ("failed", "interrupted", "cancelled"):
                restored["status"] = job.status
                restored["terminal"] = True
                restored["evidence_status"] = "incomplete"
                restored["message"] = f"Audit {job.status}; no complete proof bundle is available"
                if data.get("completion_state") == "coverage_blocked":
                    restored["phase"] = "dynamic"
                    restored["phase_label"] = pipeline.audit_progress.phase_label("dynamic")
                    restored["message"] = str(((restored.get("coverage_map") or restored.get("coverage_map_summary") or {}).get("gate") or {}).get("reason") or "Phase 2 coverage is incomplete; Phase 3 is locked")
            if job.status in ("completed", "failed", "interrupted", "cancelled"):
                restored["eta_seconds"] = None
            return _with_queue_state({"source": "persisted", **restored})
        # A terminal job status is not itself proof completeness. Older jobs may
        # predate the signed receipt/progress contract; only advertise complete
        # evidence when the persisted integrity record and healthy lab both say
        # so. Otherwise the operator must review the degraded audit explicitly.
        evidence_complete = _complete_evidence()
        # ``leads_total`` was introduced after older jobs had already been
        # persisted. Prefer the discovery ledger's total (the number of raw
        # observations examined) over the post-filter ``leads_total`` field so
        # replayed audits do not make it look as though only the survivors
        # were analyzed. Keep the candidate fallback for very old records.
        _metrics = data.get("discovery_metrics") if isinstance(data, dict) else None
        _lead_total = (
            (_metrics or {}).get("total_leads")
            if isinstance(_metrics, dict) and (_metrics or {}).get("total_leads") is not None
            else data.get("candidate_findings", data.get("leads_total", 0))
        )
        # Legacy jobs often persisted only ``findings_count``.  That column is
        # not evidence; derive the displayed confirmation count from the
        # current receipt-backed rows, exactly as the findings/dashboard APIs
        # do.  A completed job without receipts therefore remains 0 confirmed.
        from backend.main import _authoritative_finding_state, _rows_for_scan_job
        _repo_rows = _rows_for_scan_job(db, repo_id, job)
        _confirmed = sum(1 for row in _repo_rows if _authoritative_finding_state(row)[1])
        _legacy_phase = "complete" if job.status == "completed" else getattr(job, "phase", "ingest")
        _legacy_progress = 100.0 if job.status == "completed" else float(getattr(job, "progress_pct", 0.0) or 0.0)
        return _with_queue_state({
            "source": "job", "schema_version": 1, "repo_id": repo_id, "scan_job_id": int(job.id),
            "status": job.status, "phase": _legacy_phase,
            "phase_label": pipeline.audit_progress.phase_label(_legacy_phase),
            "current_task": getattr(job, "current_task", ""),
            "progress_pct": _legacy_progress,
            "eta_seconds": getattr(job, "eta_seconds", None) if job.status in {"queued", "running", "paused"} else None,
            "elapsed_seconds": ((datetime.utcnow() - job.started_at).total_seconds() if job.started_at and not job.finished_at else
                                ((job.finished_at - job.started_at).total_seconds() if job.started_at and job.finished_at else 0)),
            "message": ("Audit is queued" if job.status == "queued" else
                        "Legacy audit record loaded; structured progress was not persisted"),
            "evidence_status": "complete" if evidence_complete else "incomplete",
            "tasks": {"total": 0, "completed": 0, "running": 0, "failed": 0, "skipped": 0},
            "bottlenecks": [],
            "leads_total": int(_lead_total or 0),
            "qualified_leads": int((_metrics or {}).get("qualified_leads", 0) or 0),
            "confirmed_findings": _confirmed,
            "coverage": _normalized_tool_coverage(
                data.get("coverage") if isinstance(data.get("coverage"), dict) else {},
                data.get("tool_results", []),
            ),
            "coverage_map": deepcopy(data.get("coverage_map")) if include_coverage_map and isinstance(data.get("coverage_map"), dict) else None,
            **({"coverage_map_omitted": True, "coverage_map_summary": audit_progress.coverage_map_summary(data.get("coverage_map"))}
               if not include_coverage_map else {}),
            "task_timeline": [],
            "active_task": None,
            "slow_tasks": [],
            "task_slow_threshold_seconds": audit_progress.slow_task_threshold_seconds(),
            "is_slow": False,
            "terminal": job.status in {"completed", "failed", "cancelled", "interrupted"},
        })
    finally:
        db.close()


class ScanStartRequest(BaseModel):
    audit_depth: Optional[int] = Field(default=None, ge=1, le=5, strict=True)


@router.post("/api/repos/{repo_id}/scan")
async def trigger_scan(repo_id: int, payload: Optional[ScanStartRequest] = None):
    # Reserve the short scan-admission critical section against the reset
    # lock. Checking only the Event left a narrow race where a request could
    # commit ``queued`` after reset had begun draining workers.
    from backend.main import _PLATFORM_RESET_LOCK
    if not _PLATFORM_RESET_LOCK.acquire(blocking=False):
        raise HTTPException(
            status_code=503,
            detail="platform reset in progress; retry this scan when it completes",
            headers={"Retry-After": "2"},
        )
    try:
        if _PLATFORM_RESET_IN_PROGRESS.is_set():
            raise HTTPException(
                status_code=503,
                detail="platform reset in progress; retry this scan when it completes",
                headers={"Retry-After": "2"},
            )
        db = get_db()
        try:
            r = db.query(Repo).filter(Repo.id == repo_id).first()
            if not r:
                raise HTTPException(status_code=404, detail="Repo not found")
            if r.status == "archived":
                raise HTTPException(status_code=409, detail="Restore the archived repository before scanning")
            settings = db.query(Settings).first()
            from backend.main import require_ai_readiness
            require_ai_readiness(db)
            cvss_threshold = settings.cvss_threshold if settings else 7.0
            # Never turn an already-running (or deliberately paused) audit
            # back into ``queued`` just because a user double-clicked Scan.
            # The response includes the exact existing job so callers can bind
            # their live UI without guessing from a later list request.
            active_job = (
                db.query(ScanJob)
                .filter(
                    ScanJob.repo_id == repo_id,
                    ScanJob.status.in_(("queued", "running", "paused")),
                )
                .order_by(ScanJob.id.desc())
                .first()
            )
            from backend.scan_worker import is_scan_running, set_scan_control, submit_scan
            if active_job is not None:
                if str(active_job.status or "") in {"running", "paused"} or is_scan_running(repo_id):
                    return {
                        "repo_id": repo_id,
                        "status": "already_running",
                        "job_id": int(active_job.id),
                        "job_status": str(active_job.status or "queued"),
                    }
                # A durable queued row can outlive a process restart.  Reuse it
                # rather than creating a second active job for the same repo.
                result = submit_scan(
                    repo_id, get_db, Repo, Finding, ScanJob, _notify, cvss_threshold,
                    existing_job_id=int(active_job.id),
                )
                if result.get("status") == "queue_full":
                    # This row was admitted durably before this request.  Keep
                    # it queued for the completion-triggered dispatcher pump;
                    # capacity rejection applies only to creating *new* work.
                    return {
                        **result,
                        "repo_id": int(repo_id),
                        "status": "queued",
                        "job_id": int(active_job.id),
                        "job_status": "queued",
                        "deferred": True,
                    }
                if result.get("status") == "already_running":
                    result = {
                        **result,
                        "job_id": int(active_job.id),
                        "job_status": str(active_job.status or "queued"),
                    }
                return result

            # Reserve status + ScanJob together.  This route is also used by
            # API clients that enrolled through the legacy endpoint, so it
            # must uphold the same no-phantom-queue invariant as Start.
            prior_status = str(r.status or "pending")
            from backend.audit_depth import admitted_depth
            new_job = ScanJob(repo_id=int(repo_id), status="queued", started_at=datetime.utcnow(),
                              audit_depth=admitted_depth(settings, payload.audit_depth if payload else None))
            db.add(new_job)
            r.status = "queued"
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                winner = (
                    db.query(ScanJob)
                    .filter(
                        ScanJob.repo_id == repo_id,
                        ScanJob.status.in_(("queued", "running", "paused")),
                    )
                    .order_by(ScanJob.id.desc())
                    .first()
                )
                if winner is not None:
                    return {
                        "repo_id": repo_id,
                        "status": "already_running",
                        "job_id": int(winner.id),
                        "job_status": str(winner.status or "queued"),
                    }
                raise HTTPException(
                    status_code=503,
                    detail="Scan admission conflicted but no active job is available; retry safely.",
                    headers={"Retry-After": "1"},
                )
            db.refresh(new_job)
            # A fresh scan clears any stale control flag (e.g. a prior cancel/pause).
            try:
                set_scan_control(repo_id, "resume")
                result = submit_scan(
                    repo_id, get_db, Repo, Finding, ScanJob, _notify, cvss_threshold,
                    existing_job_id=int(new_job.id),
                )
            except Exception as exc:
                # The reservation is durable evidence of the failed start, but
                # it must become terminal before the repository returns to its
                # prior state.  Never leave a queue row without a runnable
                # worker or a restart-recovery explanation.
                queued = db.query(ScanJob).filter(ScanJob.id == int(new_job.id)).first()
                if queued is not None and str(queued.status or "") == "queued":
                    queued.status = "failed"
                    queued.finished_at = datetime.utcnow()
                    queued.output = json.dumps({
                        "error": f"Audit worker dispatch failed before start: {str(exc)[:300]}",
                        "terminal_reason": "worker-dispatch-failed",
                        "evidence_status": "incomplete",
                        "worker_started": False,
                    })
                r.status = prior_status
                db.commit()
                raise HTTPException(
                    status_code=503,
                    detail={
                        "message": "Audit reservation was saved, but worker dispatch failed",
                        "repo_id": int(repo_id),
                        "job_id": int(new_job.id),
                        "reason": str(exc)[:300],
                    },
                    headers={"Retry-After": "1"},
                ) from exc
            if not isinstance(result, dict) or result.get("status") not in {"queued", "already_running"}:
                queued = db.query(ScanJob).filter(ScanJob.id == int(new_job.id)).first()
                if queued is not None and str(queued.status or "") == "queued":
                    queued.status = "failed"
                    queued.finished_at = datetime.utcnow()
                    queued.output = json.dumps({
                        "error": (
                            "Audit admission capacity was full; no worker future was created"
                            if isinstance(result, dict) and result.get("status") == "queue_full"
                            else "Audit worker returned no valid binding for the reserved job"
                        ),
                        "terminal_reason": (
                            "queue-capacity-rejected"
                            if isinstance(result, dict) and result.get("status") == "queue_full"
                            else "worker-binding-invalid"
                        ),
                        "evidence_status": "incomplete",
                        "worker_started": False,
                    })
                    r.status = prior_status
                    db.commit()
                if isinstance(result, dict) and result.get("status") == "queue_full":
                    raise HTTPException(
                        status_code=429,
                        detail={
                            "message": result.get("message") or "Audit queue is full",
                            "repo_id": int(repo_id),
                            "job_id": int(new_job.id),
                            "scheduler": result,
                        },
                        headers={"Retry-After": str(result.get("retry_after_seconds") or 5)},
                    )
                raise HTTPException(status_code=503, detail="Audit job was reserved but could not be bound to a worker.")
            if result.get("status") == "already_running":
                result = {
                    **result,
                    "repo_id": int(repo_id),
                    "job_id": int(new_job.id),
                    "job_status": str(new_job.status or "queued"),
                }
            return result
        finally:
            db.close()
    finally:
        _PLATFORM_RESET_LOCK.release()


class SkipTaskIn(BaseModel):
    task: str


@router.post("/api/repos/{repo_id}/scan/{action}")
async def control_scan(repo_id: int, action: str, job_id: Optional[int] = None,
                       payload: Optional[SkipTaskIn] = None):
    """Stop (pause), resume, or cancel a running/queued audit.

    - stop/pause: the scan halts at the next phase checkpoint and can be resumed.
    - resume: continue a paused scan.
    - cancel: prevent new work and drain owned processes/labs; retain captured
      source and mark cancelled only after cleanup is verified.
    - skip: handled by the job-bound task endpoint and only applies before a task starts.
    """
    from backend.scan_worker import set_scan_control, is_scan_running, get_scan_control
    # Kept behind this generic route for compatibility with older clients; the
    # dedicated endpoint below documents the same operation explicitly.
    if action == "skip":
        if payload is None:
            raise HTTPException(status_code=400, detail="task is required")
        return await skip_scan_task(repo_id, payload, job_id)
    norm = {"stop": "pause", "pause": "pause", "resume": "resume", "cancel": "cancel"}.get(action)
    if norm is None:
        raise HTTPException(status_code=400, detail=f"Unknown action '{action}'")
    if job_id is not None or norm == "resume":
        from sqlalchemy.orm import load_only
        db = get_db()
        try:
            selected = (_owned_scan_job(db, repo_id, job_id, metadata_only=True) if job_id is not None else
                        db.query(ScanJob).options(load_only(ScanJob.id, ScanJob.repo_id,
                            ScanJob.status, ScanJob.control, raiseload=True)).filter(ScanJob.repo_id == int(repo_id),
                            ScanJob.status.in_(["queued", "running", "paused"])).order_by(ScanJob.id.desc()).first())
            if selected is not None and str(selected.status or "") not in {"queued", "running", "paused"}:
                raise HTTPException(status_code=409, detail="This audit is terminal; controls cannot affect a newer audit")
            if norm == "resume":
                from backend.main import require_ai_readiness
                from backend.ai_readiness import readiness
                require_ai_readiness(db)
                if selected is not None:
                    # Bind legacy repo-only Resume to the row actually checked;
                    # a newer audit must not inherit this admission decision.
                    job_id = int(selected.id)
                    saved_progress = db.query(ScanJob.progress_json).filter(
                        ScanJob.id == job_id, ScanJob.repo_id == int(repo_id)).scalar()
                    try:
                        progress = json.loads(saved_progress or "{}")
                    except (TypeError, ValueError):
                        progress = {}
                    pause = progress.get("ai_pause") if isinstance(progress, dict) else None
                    settings = db.query(Settings).first()
                    if (isinstance(pause, dict) and pause.get("role") == "judge"
                            and type(pause.get("repo_id")) is int and pause["repo_id"] == int(repo_id)
                            and type(pause.get("scan_job_id")) is int and pause["scan_job_id"] == job_id
                            and (selected.status == "paused" or selected.control == "pause")
                            and getattr(settings, "ai_judge_enabled", False)):
                        state = readiness(settings, role="judge")
                        if not state["ready"]:
                            raise HTTPException(status_code=409, detail={"code": "ai_not_ready",
                                "message": state["reason"], "action": "settings", "role": "judge",
                                "readiness": state})
        finally:
            db.close()

    async def apply_control(value):
        try:
            result = (set_scan_control(repo_id, value) if job_id is None else
                      set_scan_control(repo_id, value, expected_job_id=int(job_id)))
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if value == "cancel" and result.get("control") != "cancelled":
            from backend.audit_cancellation import finish_unowned_cancellation
            selected_id = job_id
            if selected_id is None:
                with get_db() as selected_db:
                    selected_row = selected_db.query(ScanJob).filter(
                        ScanJob.repo_id == int(repo_id), ScanJob.status.in_(["queued", "running", "paused"]),
                        ScanJob.control == "cancel",
                    ).order_by(ScanJob.id.desc()).first()
                    selected_id = selected_row.id if selected_row else None
            if selected_id is not None:
                result = await finish_unowned_cancellation(repo_id, selected_id) or result
        if value == "cancel":
            gate = pipeline.PLAN_APPROVAL_GATES.get(repo_id)
            if gate is not None:
                pipeline.PLAN_APPROVAL_DATA[repo_id] = {"approved": False, "cancelled": True}
                worker_loop = pipeline.WORKER_LOOPS.get(repo_id)
                if worker_loop is not None and not worker_loop.is_closed():
                    worker_loop.call_soon_threadsafe(gate.set)
                else:
                    gate.set()
        return result
    if not is_scan_running(repo_id):
        # A different API replica (or a process restart) may own the durable
        # queued/paused job even though this process has no local worker map.
        # Read that row before declaring the operation a no-op, and re-dispatch
        # a paused job when this replica is the first one back on its feet.
        db = get_db()
        try:
            query = db.query(ScanJob).filter(
                ScanJob.repo_id == int(repo_id), ScanJob.status.in_(["queued", "running", "paused"])
            )
            if job_id is not None:
                query = query.filter(ScanJob.id == int(job_id))
            job = query.order_by(ScanJob.id.desc()).first()
            if job is None:
                if norm != "cancel":
                    return {"repo_id": repo_id, "control": get_scan_control(repo_id) or "idle",
                            "running": False, "message": "No active scan for this repo"}
                # There is no durable job to cancel; preserve the old idempotent
                # response instead of manufacturing a control record.
                return {"repo_id": repo_id, "control": "idle", "running": False,
                        "message": "No active scan for this repo"}
            threshold = float((db.query(Settings).first() or Settings()).cvss_threshold or 7.0)
            if norm == "resume" and (
                str(getattr(job, "status", "")) == "paused"
                or str(getattr(job, "control", "")) == "pause"
            ):
                from backend.scan_worker import _live_lease_job_id
                if _live_lease_job_id(get_db, int(repo_id)) == int(job.id):
                    result = await apply_control("resume")
                    return {**result, "job_id": int(job.id), "running": True, "control": "running"}
                # Queue first, then clear the durable pause marker.  If another
                # replica still owns the lease, submit_scan returns
                # ``already_running`` and the resume signal still reaches that
                # worker through the database row.
                from backend.scan_worker import submit_scan
                result = submit_scan(
                    int(repo_id), get_db, Repo, Finding, ScanJob,
                    notify=None, cvss_threshold=threshold,
                    existing_job_id=int(job.id),
                )
                if isinstance(result, dict) and result.get("status") == "queue_full":
                    # The paused/queued row remains durable.  Keep its control
                    # state intact so the response cannot claim a resume that
                    # has no worker behind it.
                    return {
                        **result,
                        "repo_id": int(repo_id),
                        "job_id": int(job.id),
                        "control": "pause" if str(job.status or "") == "paused" else "queued",
                        "running": False,
                    }
                await apply_control("resume")
                return result
            return await apply_control(norm)
        finally:
            db.close()
    return await apply_control(norm)


@router.post("/api/repos/{repo_id}/scan/skip")
async def skip_scan_task(repo_id: int, payload: SkipTaskIn, job_id: Optional[int] = None):
    """Skip one queued analyzer at its next admission boundary.

    Skipping a running subprocess is rejected rather than pretending it did not
    execute.  The request is bound to the selected ScanJob and is consumed once
    by the worker, producing a durable ``skipped`` task with an explicit reason.
    """
    if job_id is None:
        raise HTTPException(status_code=400, detail="job_id is required to skip a task safely")
    task_name = str(payload.task or "").strip()
    if not task_name:
        raise HTTPException(status_code=400, detail="task is required")
    db = get_db()
    try:
        selected = _owned_scan_job(db, repo_id, job_id)
        if str(selected.status or "") not in {"queued", "running", "paused"}:
            raise HTTPException(status_code=409, detail="This audit is terminal; its tasks cannot be changed")
        rows = pipeline.SCAN_TASKS.get(int(repo_id)) or []
        row = next((item for item in rows if str(item.get("name") or "") == task_name), None)
        if row is None:
            raise HTTPException(status_code=404, detail="Task is not present in the selected audit timeline")
        if str(row.get("state") or "") == "running":
            raise HTTPException(status_code=409, detail="Task is already running; stop or wait for it before skipping")
        if str(row.get("state") or "") in {"ok", "failed", "skipped"}:
            return {"repo_id": int(repo_id), "job_id": int(selected.id), "task": task_name,
                    "status": "already_terminal", "task_status": row.get("terminal_status") or row.get("state")}
        reason = "skipped by operator before analyzer execution"
        pipeline.request_task_skip(int(repo_id), task_name)
        pipeline.record_task(int(repo_id), task_name, str(row.get("phase") or "Phase 1 · Recon"),
                             "skipped", summary=reason, detail_id=row.get("detail_id"))
        return {"repo_id": int(repo_id), "job_id": int(selected.id), "task": task_name,
                "status": "skip_requested", "task_status": "skipped", "reason": reason}
    finally:
        db.close()


@router.post("/api/scan-jobs/{job_id}/retry")
async def retry_scan_job(job_id: int):
    """Retry a scan, or request a safe stop when its worker is still active.

    A terminal job is replayed from its immutable snapshot.  An active job is
    cancelled first; this avoids two workers mutating the same repository and
    tells the UI exactly why a new replay is not created yet.
    """
    db = get_db()
    try:
        job = _owned_scan_job(db, None, job_id)
        if str(job.status or "") in {"queued", "running", "paused"}:
            from backend.scan_worker import set_scan_control
            try:
                result = set_scan_control(int(job.repo_id), "cancel", expected_job_id=int(job.id))
                if result.get("control") != "cancelled":
                    from backend.audit_cancellation import finish_unowned_cancellation
                    result = await finish_unowned_cancellation(job.repo_id, job.id) or result
            except RuntimeError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            return {"status": "stop_requested", "repo_id": int(job.repo_id), "job_id": int(job.id),
                    "message": "The active audit is being stopped; replay it after the terminal state is recorded.",
                    "control": result.get("control", "cancel") if isinstance(result, dict) else "cancel"}
    finally:
        db.close()
    # Reuse the immutable-snapshot replay implementation for terminal jobs.
    return await replay_scan_job(job_id)


class TaskRetryRequest(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    configuration_revision: str = Field(min_length=1, max_length=128)


class AuditContinueRequest(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    checkpoint_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


@router.get("/api/scan-jobs/{job_id}/recovery")
async def audit_recovery_options(job_id: int):
    from backend.task_recovery import audit_projection
    db = get_db()
    try:
        return audit_projection(_owned_scan_job(db, None, job_id))
    finally:
        db.close()


@router.post("/api/scan-jobs/{job_id}/continue-with-gaps")
async def continue_audit_with_gaps(job_id: int, payload: AuditContinueRequest):
    from backend.main import _PLATFORM_RESET_LOCK
    from backend.task_recovery import request_continue, existing_continue_response
    from backend.ai_readiness import readiness
    if not _PLATFORM_RESET_LOCK.acquire(blocking=False):
        raise HTTPException(409, "Platform reset is in progress")
    db = None
    try:
        db = get_db()
        if _PLATFORM_RESET_IN_PROGRESS.is_set():
            raise HTTPException(409, "Platform reset is in progress")
        job = _owned_scan_job(db, None, job_id)
        previous = existing_continue_response(job, payload)
        if previous:
            return previous
        if not readiness(db.query(Settings).first()).get("ready"):
            raise HTTPException(409, "Configure and test AI before continuing this audit")
        return request_continue(db, job, payload)
    finally:
        if db is not None:
            db.close()
        _PLATFORM_RESET_LOCK.release()


@router.get("/api/scan-jobs/{job_id}/tasks/{task_name}/recovery")
async def task_recovery_options(job_id: int, task_name: str):
    from backend.resource_continuation import TASK_TO_TOOL
    from backend.task_recovery import current_policy, projection
    if task_name not in TASK_TO_TOOL:
        raise HTTPException(404, "This task has no resource recovery adapter")
    db = get_db()
    try:
        job = _owned_scan_job(db, None, job_id)
        settings = db.query(Settings).first()
        policy = await current_policy(settings)
        db.refresh(job)
        return projection(job, task_name, policy)
    finally:
        db.close()


@router.post("/api/scan-jobs/{job_id}/tasks/{task_name}/retry")
async def retry_audit_task(job_id: int, task_name: str, payload: TaskRetryRequest):
    from backend.resource_continuation import TASK_TO_TOOL
    from backend.task_recovery import current_policy, request_retry
    if task_name not in TASK_TO_TOOL:
        raise HTTPException(404, "This task has no resource recovery adapter")
    db = get_db()
    try:
        if _PLATFORM_RESET_IN_PROGRESS.is_set():
            raise HTTPException(409, "Platform reset is in progress")
        job = _owned_scan_job(db, None, job_id)
        settings = db.query(Settings).first()
        from backend.ai_readiness import readiness
        if not readiness(settings).get("ready"):
            raise HTTPException(409, "Configure and test AI before resuming this audit")
        from backend.analyzer_resources import snapshot_policy
        def selected_configuration(value):
            return next((row for row in snapshot_policy(value)["tools"]
                         if row["id"] == TASK_TO_TOOL[task_name]), None)
        admitted_configuration = selected_configuration(settings)
        policy = await current_policy(settings)
        # Capacity discovery can await Kubernetes. Recheck mutable admission
        # inputs afterwards, retaining the original job/lease for retry CAS.
        from backend.main import _PLATFORM_RESET_LOCK
        if not _PLATFORM_RESET_LOCK.acquire(blocking=False):
            raise HTTPException(409, "Platform reset is in progress")
        try:
            if _PLATFORM_RESET_IN_PROGRESS.is_set():
                raise HTTPException(409, "Platform reset is in progress")
            if settings is not None:
                db.refresh(settings)
            if not readiness(settings).get("ready"):
                raise HTTPException(409, "Configure and test AI before resuming this audit")
            if selected_configuration(settings) != admitted_configuration:
                raise HTTPException(409, "Configuration changed; refresh task recovery before retrying")
            return request_retry(db, job, task_name, payload, policy)
        finally:
            _PLATFORM_RESET_LOCK.release()
    finally:
        db.close()


@router.get("/api/repos/{repo_id}/scan/control")
async def scan_control_state(repo_id: int, job_id: Optional[int] = None):
    from backend.scan_worker import is_scan_running, get_scan_control
    if job_id is not None:
        db = get_db()
        try:
            job = _owned_scan_job(db, repo_id, job_id, metadata_only=True)
            active = str(job.status or "") in {"queued", "running", "paused"}
            return {"repo_id": repo_id, "scan_job_id": int(job.id), "running": active and is_scan_running(repo_id),
                    "control": (str(job.control or "") or str(job.status or "")) if active else "idle"}
        finally:
            db.close()
    running = is_scan_running(repo_id)
    return {"repo_id": repo_id, "running": running,
            "control": get_scan_control(repo_id) or ("running" if running else "idle")}


def _get_or_reconstruct_logs(repo_id: int) -> List[dict]:
    """Return live logs or a request-local durable replay, without cache writes."""
    history = pipeline.STREAM_HISTORY.get(repo_id)

    # CRITICAL: if a scan is actively running (queued/running in this process), stream the
    # LIVE in-memory history as-is and never fall through to DB reconstruction. The
    # reconstruction path always appends a synthetic terminal {"level":"complete"} entry
    # (it exists to replay FINISHED audits). During the first seconds of a scan the live
    # history has few entries, so without this guard the SSE replay would emit that fake
    # 'complete', the browser would close the stream, and the UI would show
    # "Stream disconnected - scan may still be running" moments after start.
    try:
        from backend import scan_worker
        if scan_worker.is_scan_running(repo_id):
            return pipeline.normalize_visible_audit_logs(history or [])
    except Exception:
        pass

    db = get_db()
    logs = []
    try:
        from sqlalchemy.orm import load_only
        repo = db.query(Repo).filter(Repo.id == repo_id).first()
        job = db.query(ScanJob).options(load_only(ScanJob.id, ScanJob.repo_id, ScanJob.status,
            ScanJob.started_at, ScanJob.finished_at, raiseload=True)).filter(
            ScanJob.repo_id == repo_id).order_by(ScanJob.id.desc()).first()
        # A worker in another process may be active without a local registry.
        # Its durable checkpoint is not a finished audit to reconstruct.
        if job and str(job.status or "") in {"queued", "running", "paused"}:
            return _bound_job_logs(job, db)
        data = {}
        if job:
            from backend.json_projection import read_json_projection, read_json_array_projection
            try:
                data = read_json_projection(db, ScanJob.output, ScanJob.id == int(job.id), [
                    *((field,) for field in ('logs', 'candidate_findings', 'leads_total', 'evidence_status',
                        'duration_seconds', 'language', 'app_type', 'audit_depth', 'dependency_count',
                        'high_risk_dependencies', 'tainted_dependencies', 'cli_entry_flags', 'coverage')),
                    ('discovery_metrics', 'total_leads'), ('joern_cpg', 'cpg_generated'),
                    ('joern_cpg', 'findings_count'), ('high_yield', 'pass_counts'),
                    ('lab_status', 'container_name'), ('lab_status', 'image'),
                    *(('ai_gating_log', field) for field in ('candidates_analyzed', 'confirmed', 'rejected', 'provider', 'model')),
                ])
                if not data.get('logs'):
                    data['tool_results'] = read_json_array_projection(db, ScanJob.output,
                        ScanJob.id == int(job.id), ('tool_results',), [(field,) for field in (
                            'name', 'status', 'duration_ms', 'lead_count', 'findings_count', 'reason')])
            except (TypeError, ValueError):
                data = {}
        repo_name = repo.source if repo else f"Repo #{repo_id}"
        branch_name = repo.branch if repo else "main"

        t0 = job.started_at.isoformat() if job and job.started_at else datetime.utcnow().isoformat()
        t_end = job.finished_at.isoformat() if job and job.finished_at else datetime.utcnow().isoformat()

        # If job.output contains raw persisted logs, use them directly
        if job and data:
            try:
                if isinstance(data, dict):
                    if data.get("logs") and len(data["logs"]) > 0:
                        persisted_logs = pipeline.normalize_visible_audit_logs(data["logs"])
                        # Older completed jobs persisted the pre-terminal
                        # snapshot and therefore have no completion marker.
                        # Synthesize one from durable counters so SSE replay
                        # terminates and the operator receives an honest
                        # terminal interpretation after a restart.
                        if job.status in {"completed", "failed", "cancelled", "interrupted"} and not any(
                            row.get("level") == "complete" for row in persisted_logs
                        ):
                            _metrics = data.get("discovery_metrics") if isinstance(data, dict) else None
                            _leads = (
                                (_metrics or {}).get("total_leads")
                                if isinstance(_metrics, dict) and (_metrics or {}).get("total_leads") is not None
                                else data.get("candidate_findings", data.get("leads_total", 0))
                            )
                            # Never reconstruct a terminal proof count from the
                            # mutable ScanJob.output blob.  Older snapshots can
                            # contain a stale or fabricated ``confirmed_findings``
                            # counter; the receipt-backed Finding rows are the
                            # only authority, just as they are for /details.
                            try:
                                from backend.main import _authoritative_finding_state, _rows_for_scan_job
                                _confirmed = sum(
                                    1 for _row in _rows_for_scan_job(db, repo_id, job)
                                    if _authoritative_finding_state(_row)[1]
                                )
                            except Exception:
                                _confirmed = 0
                            _evidence = data.get("evidence_status", "incomplete") if isinstance(data, dict) else "incomplete"
                            _duration = data.get("duration_seconds", 0) if isinstance(data, dict) else 0
                            persisted_logs.append({
                                "time": t_end,
                                "level": "complete",
                                "message": (
                                    f"Audit replay complete: {_leads or 0} leads analyzed, "
                                    f"{_confirmed or 0} Findings proven in local lab "
                                    f"({_confirmed or 0} confirmed findings); status={job.status}, "
                                    f"evidence={_evidence}, duration={float(_duration or 0):.1f}s"
                                ),
                                "detail_id": f"{repo_id}-complete-replay",
                            })
                        return persisted_logs
            except Exception:
                pass

        # Otherwise, reconstruct high-fidelity chronological audit log
        logs.append({"time": t0, "level": "info", "message": f"Audit initialized for {repo_name} (branch: {branch_name})"})

        if job and data:
            try:
                if isinstance(data, dict):
                    lang = data.get("language", "unknown")
                    app_type = data.get("app_type", "unknown")
                    depth = data.get("audit_depth")
                    # Legacy jobs may store a scalar; absent evidence is not L3.
                    audit_depth = depth.get("level") if isinstance(depth, dict) else depth
                    depth_label = f"Level {audit_depth}" if type(audit_depth) is int and 1 <= audit_depth <= 5 else "not recorded"

                    logs.append({"time": t0, "level": "info", "message": f"Detected language/framework: {lang} ({app_type}) - Audit Depth: {depth_label}"})

                    # Attack surface details
                    dep_count = data.get("dependency_count", 0)
                    high_risk_deps = data.get("high_risk_dependencies", [])
                    tainted_deps = data.get("tainted_dependencies", [])
                    cli_flags = data.get("cli_entry_flags", [])
                    if dep_count > 0 or high_risk_deps or tainted_deps or cli_flags:
                        dep_msg = f"Target attack surface: {dep_count} dependencies mapped"
                        if high_risk_deps:
                            dep_msg += f", {len(high_risk_deps)} high-risk packages"
                        if tainted_deps:
                            dep_msg += f", {len(tainted_deps)} tainted callpaths"
                        if cli_flags:
                            dep_msg += f", {len(cli_flags)} CLI entrypoints"
                        logs.append({"time": t0, "level": "info", "message": dep_msg})

                    # Phase 1 Parallel Tools
                    tool_results = data.get("tool_results", [])
                    if tool_results:
                        logs.append({"time": t0, "level": "info", "message": f"Phase 1: Executing {len(tool_results)} static & dynamic reconnaissance tools in parallel..."})
                        for t in tool_results:
                            t_name = t.get("name", "tool")
                            status = t.get("status", "completed")
                            dur = t.get("duration_ms", 0)
                            cnt = t.get("lead_count", t.get("findings_count", 0))
                            detail_id = f"{repo_id}-tool-{t_name}"
                            if status == "completed":
                                logs.append({
                                    "time": t0,
                                    "level": "success" if cnt > 0 else "info",
                                    "message": f"✓ {t_name} completed in {dur}ms ({cnt} leads observed)",
                                    "detail_id": detail_id,
                                })
                            elif status in ("failed", "error"):
                                logs.append({
                                    "time": t0,
                                    "level": "error",
                                    "message": f"✗ {t_name} failed ({dur}ms): {t.get('reason') or 'execution error'}",
                                    "detail_id": detail_id,
                                })
                            else:
                                logs.append({
                                    "time": t0,
                                    "level": "warning",
                                    "message": f"⚠ {t_name} status: {status} ({dur}ms)",
                                    "detail_id": detail_id,
                                })

                    # Phase 1 Code Intelligence & CPG
                    if data.get("joern_cpg"):
                        jc = data["joern_cpg"]
                        cpg_ok = jc.get("cpg_generated", False)
                        cpg_cnt = jc.get("findings_count", 0)
                        logs.append({
                            "time": t0,
                            "level": "success" if cpg_ok else "warning",
                            "message": f"Joern Code Property Graph AST: generated={cpg_ok}, semantic leads={cpg_cnt}",
                        })

                    # Multi-pass high yield battery
                    hy = data.get("high_yield")
                    if isinstance(hy, dict) and hy.get("pass_counts"):
                        pc = hy["pass_counts"]
                        logs.append({
                            "time": t0,
                            "level": "info",
                            "message": f"Multi-pass Battery: sink-first={pc.get('sink-first',0)}, sibling-variants={pc.get('sibling-variant',0)}, guard-alternates={pc.get('guard-alternate-path',0)}, pattern-transfer={pc.get('pattern-transfer',0)}",
                        })

                    # Coverage stats
                    cov = _normalized_tool_coverage(data.get("coverage", {}), tool_results)
                    if cov:
                        logs.append({
                            "time": t0,
                            "level": "info",
                            "message": f"Phase 1 tool coverage: {cov.get('coverage_pct', 100)}% ({cov.get('completed', 0)} completed, {cov.get('failed', 0)} failed)",
                        })

                    # Phase 2 AI & Lab container execution
                    lab_st = data.get("lab_status") or {}
                    if lab_st:
                        logs.append({
                            "time": t0,
                            "level": "info",
                            "message": f"Phase 2: Local Lab container active (pod: {lab_st.get('container_name', 'lotus-lab')}, image: {lab_st.get('image', 'standard')})",
                        })

                    # AI Gating Log
                    aig = data.get("ai_gating_log") or {}
                    if aig:
                        c_analyzed = aig.get("candidates_analyzed", 0)
                        c_conf = aig.get("confirmed", 0)
                        c_rej = aig.get("rejected", 0)
                        logs.append({
                            "time": t0,
                            # AI acceptance is a triage result, not proof.  In
                            # particular, old job blobs may contain a non-zero
                            # model count even though no signed receipt exists.
                            "level": "info",
                            "message": f"AI Gating ({aig.get('provider','ai')}/{aig.get('model','default')}): "
                                       f"{c_conf}/{c_analyzed} leads accepted for proof review, "
                                       f"{c_rej} leads rejected (signed lab receipt still required)",
                            "detail_id": f"{repo_id}-ai-gating",
                        })
            except Exception:
                pass

        # Results section.  Keep legacy rows addressable, but do not mix rows
        # from an earlier unscoped audit into the current audit's user-facing
        # timeline.  The source table remains immutable for forensics.
        findings = db.query(Finding).filter(Finding.repo_id == repo_id).order_by(Finding.cvss.desc()).all()
        from backend.main import _authoritative_finding_state, _row_belongs_to_current_audit
        latest_job = (
            db.query(ScanJob).options(load_only(ScanJob.id, ScanJob.repo_id,
                ScanJob.started_at, raiseload=True)).filter(ScanJob.repo_id == repo_id)
            .order_by(ScanJob.id.desc()).first()
        )
        current_findings = [f for f in findings if _row_belongs_to_current_audit(f, latest_job)]
        if findings:
            confirmed_count = 0
            for f in current_findings:
                status, eligible = _authoritative_finding_state(f)
                confirmed_count += int(eligible)
                lvl = "success" if eligible else "warning" if status == "confirmed" else "info"
                label = "Finding" if eligible else "Lead"
                logs.append({
                    "time": t0,
                    "level": lvl,
                    "message": f"{label}: {f.title} (CVSS {f.cvss}) - {status} (Report Eligible: {eligible})",
                    "detail_id": f"{repo_id}-finding-{f.id}",
                })
            logs.insert(
                next((i for i, row in enumerate(logs) if row.get("message", "").startswith("Audit pipeline finished")), len(logs)),
                {
                    "time": t0,
                    "level": "info",
                    "message": (
                        f"Persisted audit results ({len(current_findings)} leads; "
                        f"{confirmed_count} proof-gated findings; historical rows excluded from current scope):"
                    ),
                },
            )

        duration_sec = 0
        if job and data:
            try:
                duration_sec = data.get("duration_seconds", 0)
            except Exception:
                pass
        dur_str = f" in {duration_sec:.1f}s" if duration_sec else ""
        logs.append({
            "time": t_end,
            "level": "complete",
            "message": f"Audit pipeline finished for {repo_name} (Status: {job.status if job else 'completed'}{dur_str})",
            "detail_id": f"{repo_id}-complete",
        })

        return logs
    finally:
        db.close()


def _owned_scan_job(db, repo_id: Optional[int], job_id: int, *, metadata_only=False):
    query = db.query(ScanJob).filter(ScanJob.id == int(job_id))
    if metadata_only:
        from sqlalchemy.orm import load_only
        query = query.options(load_only(ScanJob.id, ScanJob.repo_id, ScanJob.status,
            ScanJob.started_at, ScanJob.finished_at, ScanJob.control, raiseload=True))
    if repo_id is not None:
        query = query.filter(ScanJob.repo_id == int(repo_id))
    job = query.first()
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job does not belong to this repository")
    return job


def _job_has_live_artifacts(job) -> bool:
    if str(job.status or "") not in {"queued", "running", "paused"}:
        return False
    live = pipeline.audit_progress.snapshot(int(job.repo_id), include_coverage_map=False)
    return live.get("scan_job_id") == int(job.id)


def _bound_job_logs(job, db=None) -> List[dict]:
    if _job_has_live_artifacts(job):
        return pipeline.normalize_visible_audit_logs(pipeline.STREAM_HISTORY.get(int(job.repo_id)) or [])
    try:
        if db is not None:
            from backend.json_projection import read_json_projection
            data = read_json_projection(db, ScanJob.output, ScanJob.id == int(job.id), [('logs',)])
        else:
            data = json.loads(job.output or "{}")
    except (TypeError, ValueError):
        data = {}
    logs = pipeline.normalize_visible_audit_logs(data.get("logs") or []) if isinstance(data, dict) else []
    if str(job.status or "") in {"completed", "failed", "cancelled", "interrupted"} and not any(
        row.get("level") == "complete" for row in logs
    ):
        logs.append({
            "level": "complete", "time": job.finished_at.isoformat() if job.finished_at else "",
            "message": f"Audit {int(job.id)} {job.status}; inspect its evidence report for coverage and proof status",
            "scan_job_id": int(job.id),
        })
    return logs


async def _owned_audit_read(operation, *args):
    """Keep SQLite projection admission and reads off the event loop.

    The worker owns its database session. A disconnected caller cannot leave
    that session or its memory reservation running without being awaited.
    """
    work = asyncio.create_task(asyncio.to_thread(operation, *args))
    try:
        return await asyncio.shield(work)
    except asyncio.CancelledError:
        while not work.done():
            try:
                await asyncio.shield(work)
            except asyncio.CancelledError:
                continue
            except BaseException:
                break
        if work.done():
            try:
                work.result()
            except BaseException:
                pass
        raise


@router.get("/api/repos/{repo_id}/logs")
async def get_repo_logs(repo_id: int, job_id: Optional[int] = None):
    return await _owned_audit_read(_read_repo_logs, repo_id, job_id)


def _read_repo_logs(repo_id, job_id):
    """Retrieve full in-memory log history for an audit/repository."""
    if job_id is not None:
        db = get_db()
        try:
            return _bound_job_logs(_owned_scan_job(db, repo_id, job_id, metadata_only=True), db)
        finally:
            db.close()
    return _get_or_reconstruct_logs(repo_id)


@router.get("/api/repos/{repo_id}/tasks")
async def get_repo_tasks(repo_id: int, job_id: Optional[int] = None):
    """Structured task timeline for the current/last audit: every task with phase, state
    (running/ok/failed/skipped), timing, and clickable detail_id. Serves the live in-memory
    registry during a scan and the persisted copy (from the job output) afterwards, so the
    same timeline renders identically live and after a restart."""
    return await _owned_audit_read(_read_repo_tasks, repo_id, job_id)


def _read_repo_tasks(repo_id, job_id):
    from sqlalchemy.orm import load_only
    if job_id is not None:
        db = get_db()
        try:
            selected = _owned_scan_job(db, repo_id, job_id, metadata_only=True)
            use_live = _job_has_live_artifacts(selected)
            if use_live:
                raw_tasks = pipeline.SCAN_TASKS.get(repo_id)
            else:
                from backend.json_projection import read_json_projection
                try:
                    output = read_json_projection(db, ScanJob.output, ScanJob.id == int(selected.id), [('tasks',)])
                except (TypeError, ValueError):
                    output = {}
                raw_tasks = output.get('tasks', [])
            tasks = []
            for raw in raw_tasks or []:
                task = _terminalize_task_for_job(raw if isinstance(raw, dict) else {"name": str(raw)}, str(selected.status or ""))
                if not task.get("detail_id"):
                    task["detail_id"] = f"{repo_id}-task-{task.get('name') or 'task'}"
                tasks.append(task)
            return {"repo_id": repo_id, "scan_job_id": int(selected.id), "source": "live" if use_live else "persisted", "tasks": tasks}
        finally:
            db.close()
    live = pipeline.SCAN_TASKS.get(repo_id)
    # Read the durable job status even when an in-process task registry exists;
    # after a terminal commit, stale process-local ``running`` rows must be
    # rendered as explicit skipped work rather than an endless spinner.
    db = get_db()
    try:
        latest_job = (
            db.query(ScanJob).options(load_only(ScanJob.id, ScanJob.status, raiseload=True)).filter(ScanJob.repo_id == repo_id)
            .order_by(ScanJob.started_at.desc()).first()
        )
        job_status = str(latest_job.status or "") if latest_job else ""
    finally:
        db.close()
    if live:
        # Rehydrated legacy rows can still lack the feature's detail id and
        # explicit terminal spelling.  Normalize the response without
        # mutating the immutable in-memory replay blob; stream-detail will
        # synthesize the matching console from the persisted log if needed.
        tasks = []
        for raw in live:
            task = _terminalize_task_for_job(raw if isinstance(raw, dict) else {"name": str(raw)}, job_status)
            name = str(task.get("name") or "task")
            # ``setdefault`` does not replace a legacy explicit ``null``;
            # normalize both missing and null ids so every visible task has a
            # deterministic, clickable console target after a restart.
            if not task.get("detail_id"):
                task["detail_id"] = f"{repo_id}-task-{name}"
            tasks.append(task)
        return {"repo_id": repo_id, "source": "live", "tasks": tasks}
    # Fall back to the latest scan job's persisted tasks.
    db = get_db()
    try:
        job = (
            db.query(ScanJob).options(load_only(ScanJob.id, ScanJob.status, raiseload=True)).filter(ScanJob.repo_id == repo_id)
            .order_by(ScanJob.started_at.desc()).first()
        )
        job_status = str(job.status or "") if job else job_status
        tasks = []
        if job:
            try:
                from backend.json_projection import read_json_projection
                tasks = read_json_projection(db, ScanJob.output, ScanJob.id == int(job.id), [('tasks',)]).get('tasks', []) or []
            except Exception:
                tasks = []
        # Give pre-feature task rows a deterministic detail id.  The stream
        # detail endpoint synthesizes their console from the same persisted
        # audit log, so the progress UI remains fully clickable across replay.
        tasks = [_terminalize_task_for_job(task, job_status) for task in tasks]
        for task in tasks:
            if isinstance(task, dict) and not task.get("detail_id") and task.get("name"):
                task["detail_id"] = f"{repo_id}-task-{task['name']}"
        return {"repo_id": repo_id, "source": "persisted", "tasks": tasks}
    finally:
        db.close()


class LabExecIn(BaseModel):
    command: str
    timeout: Optional[int] = 30


class LabKeepIn(BaseModel):
    keep: bool = True


@router.get("/api/repos/{repo_id}/lab")
async def repo_lab_inspect(repo_id: int):
    """Live look-in on the isolated lab for this audit (container, URL, health)."""
    from backend.lab import inspect_lab
    return await inspect_lab(repo_id)


@router.get("/api/labs")
async def list_local_labs():
    """List every known local lab pod/container, including post-restart K8s pods."""
    from backend.lab import list_labs
    return await list_labs()


@router.get("/api/repos/{repo_id}/lab/logs")
async def repo_lab_logs(repo_id: int, tail: int = 200):
    from backend.lab import lab_logs
    return await lab_logs(repo_id, tail=tail)


@router.post("/api/repos/{repo_id}/lab/exec")
async def repo_lab_exec(repo_id: int, payload: LabExecIn):
    from backend.lab import exec_in_lab
    cmd = (payload.command or "").strip()
    if not cmd:
        raise HTTPException(status_code=400, detail="command is required")
    if len(cmd) > 4000:
        raise HTTPException(status_code=400, detail="command too long")
    timeout = max(1, min(int(payload.timeout or 30), 120))
    # ``exec_in_lab`` records the exact provider command, including the
    # container/pod identity, exactly once.  Recording a second synthetic
    # command here used to lose that identity (and produced duplicate task
    # rows), making a displayed transcript impossible to bind to a runtime.
    return await exec_in_lab(repo_id, cmd, timeout=timeout)


@router.post("/api/repos/{repo_id}/lab/keep")
def repo_lab_keep(repo_id: int, payload: LabKeepIn = LabKeepIn()):
    from backend.lab import set_keep_lab
    return set_keep_lab(repo_id, payload.keep)


@router.post("/api/repos/{repo_id}/lab/teardown")
async def repo_lab_teardown(repo_id: int, force: bool = False):
    """Explicitly stop and remove a disposable lab from the UI/API.

    Teardown is idempotent and provider-aware (Docker or Kubernetes).  The
    optional force flag is required to remove a lab that the operator marked
    ``keep`` for interactive reproduction.
    """
    from backend.lab import teardown_lab, inspect_lab, get_lab_state
    expected = get_lab_state(repo_id)
    before = await inspect_lab(repo_id)
    try:
        await teardown_lab(repo_id, force=bool(force), expected_state=expected)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(409, str(exc)) from None
    after = await inspect_lab(repo_id)
    return {
        "repo_id": int(repo_id),
        "requested": True,
        "force": bool(force),
        "before": before,
        "after": after,
        "removed": not bool(after.get("running")) and not after.get("container") and not after.get("pod"),
    }


_ACTIVITY_TASK_FIELDS = [
    (name,) for name in (
        "name", "label", "detail_id", "state", "terminal_status", "reason", "phase", "summary",
        "started_at", "queued_at", "ended_at", "duration_seconds", "slow_threshold_seconds",
        "slow_clock_kind", "slow_elapsed_seconds", "is_slow",
    )
] + [
    ("runtime_progress", name) for name in (
        "kind", "job_name", "task_id", "tool_id", "repo_id", "scan_job_id", "namespace",
        "pod_name", "pod_uid", "image", "phase", "reason", "elapsed_seconds", "budget_seconds",
        "queue_budget_seconds", "queue_elapsed_seconds", "execution_elapsed_seconds", "budget_kind",
        "stage", "stage_is_advisory", "exit_code", "validating_output", "observed_at", "projected_at",
    )
]
_ACTIVITY_TEXT_LIMITS = {
    ("summary",): 500, ("reason",): 500, ("phase",): 200,
    ("runtime_progress",): 500, ("runtime_progress", "reason"): 500,
    ("runtime_progress", "stage"): 200,
}
_ACTIVITY_PROGRESS_FIELDS = [
    ("progress", name) for name in ("progress_pct", "eta_seconds", "bottlenecks", "evidence_status")
]


def _rows_from_job_output(job, *, projected_output: Optional[dict] = None) -> List[dict]:
    """Format a small stored task projection without reading its audit artifacts.

    The legacy object-only calling form remains for callers already holding an
    authored snapshot. HTTP activity reads always supply a SQL projection and
    select no ScanJob.output/progress_json ORM attributes.
    """
    if projected_output is None:
        try:
            blob = json.loads(job.output or "") or {}
        except Exception:
            return []
    else:
        blob = projected_output
    if not isinstance(blob, dict) or not isinstance(blob.get("tasks", []), list):
        return []
    rows = []
    persisted_progress = blob.get("progress") if isinstance(blob.get("progress"), dict) else {}
    for t in blob.get("tasks") or []:
        if not isinstance(t, dict):
            continue
        t = _terminalize_task_for_job(t, str(getattr(job, "status", "") or ""))
        name = t.get("name") or t.get("label") or "task"
        did = t.get("detail_id")
        state = t.get("state") or "ok"
        # ``state=ok`` is a legacy UI spelling.  Hydrated activity rows must
        # still expose the hard lifecycle contract so a restart cannot turn a
        # completed/failed/skipped task into an ambiguous status.  Unknown or
        # missing values remain explicitly unresolved instead of being treated
        # as successful work.
        terminal_status = str(t.get("terminal_status") or "").strip().lower()
        if terminal_status not in {"completed", "failed", "skipped", "running"}:
            terminal_status = {
                "ok": "completed",
                "completed": "completed",
                "failed": "failed",
                "skipped": "skipped",
                "not-installed": "skipped",
                "running": "running",
            }.get(str(state).strip().lower(), "unresolved")
        reason = str(t.get("reason") or "")[:500]
        # A terminal ScanJob is authoritative even when a crash/timeout left
        # the last in-memory task marked ``running``.  Report that work as
        # skipped with a reason, preserving the raw persisted task for replay.
        if str(getattr(job, "status", "") or "").strip().lower() in {
            "completed", "failed", "cancelled", "interrupted"
        } and terminal_status not in {"completed", "failed", "skipped"}:
            state = "skipped"
            terminal_status = "skipped"
            reason = reason or (
                f"not executed: audit became {str(getattr(job, 'status', '') or '').lower()} "
                f"before {name} completed"
            )[:500]
        if terminal_status in {"completed", "failed", "skipped"} and not reason:
            # Legacy snapshots did not always store a separate reason.  The
            # summary is the only honest fallback; never synthesize a green
            # reason for an unresolved task.
            reason = str(t.get("summary") or terminal_status)[:500]
        rows.append({
            "id": f"scan-task:{job.repo_id}:{job.id}:{name}",
            "kind": "scan-task",
            "ident": f"{job.repo_id}:{job.id}:{name}",
            "name": name,
            "state": state,
            "terminal_status": terminal_status,
            "reason": reason,
            "phase": t.get("phase") or "",
            "summary": (t.get("summary") or "")[:400],
            "detail_id": did or f"{job.repo_id}-task-{name}",
            "repo_id": job.repo_id,
            "href": f"/api/stream-detail/{did or f'{job.repo_id}-task-{name}'}?job_id={job.id}&repo_id={job.repo_id}",
            "job_id": job.id,
            "started_at": t.get("started_at"),
            "queued_at": t.get("queued_at"),
            "ended_at": t.get("ended_at"),
            "duration_seconds": t.get("duration_seconds"),
            "slow_threshold_seconds": t.get("slow_threshold_seconds"),
            "slow_clock_kind": t.get("slow_clock_kind"),
            "slow_elapsed_seconds": t.get("slow_elapsed_seconds"),
            "is_slow": bool(t.get("is_slow")),
            "runtime_progress": deepcopy(t.get("runtime_progress")) if isinstance(t.get("runtime_progress"), dict) else None,
            "progress_pct": persisted_progress.get("progress_pct"),
            "eta_seconds": persisted_progress.get("eta_seconds"),
            "bottlenecks": persisted_progress.get("bottlenecks") or [],
            "evidence_status": persisted_progress.get("evidence_status", "incomplete"),
        })
    return rows


def _attach_progress(row: dict, *, cache: Optional[dict] = None) -> dict:
    """Decorate an activity row with the durable-shaped audit progress view."""
    repo_id = row.get("repo_id")
    if repo_id is None:
        return row
    try:
        repo_id = int(repo_id)
        if not audit_progress.exists(repo_id):
            return row
        if cache is not None and repo_id in cache:
            progress = cache[repo_id]
        else:
            progress = audit_progress.snapshot(repo_id, include_coverage_map=False)
            if cache is not None:
                cache[repo_id] = progress
        job_id = row.get("job_id") or row.get("scan_job_id")
        if job_id is not None and progress.get("scan_job_id") != int(job_id):
            return row
        if row.get("kind") == "scan-task" and job_id is not None:
            task = next((task for task in progress.get("task_timeline", [])
                         if task.get("name") == row.get("name")), None)
            if task and isinstance(task.get("runtime_progress"), dict):
                row["runtime_progress"] = deepcopy(task["runtime_progress"])
                row = audit_progress.project_task_runtime(row, terminal=progress.get("status") in {"completed", "failed", "cancelled", "interrupted"})
        for key in (
            "phase", "phase_label", "current_task", "progress_pct", "eta_seconds",
            "eta_basis", "elapsed_seconds", "bottlenecks", "evidence_status",
            "leads_total", "qualified_leads", "confirmed_findings", "coverage",
        ):
            if key in progress:
                row[key] = progress[key]
    except Exception:
        pass
    return row


def _normalize_activity_row(row: dict) -> dict:
    """Apply lifecycle terminology and stable console links to activity rows."""
    result = dict(row or {})
    try:
        result["summary"] = pipeline.normalize_visible_audit_message(result.get("summary") or "")
        result["reason"] = pipeline.normalize_visible_audit_message(result.get("reason") or "")
    except Exception:
        pass
    if result.get("kind") == "scan-task" and result.get("repo_id") is not None:
        name = str(result.get("name") or "task")
        result.setdefault("detail_id", f"{result['repo_id']}-task-{name}")
        result.setdefault("href", f"/api/stream-detail/{result['detail_id']}")
    return result


def _terminalize_task_for_job(task: dict, job_status: str) -> dict:
    """Return a display-safe task row with a hard terminal lifecycle.

    A process can be interrupted between the last task update and the
    ScanJob commit.  If the durable job is already terminal, exposing a stale
    ``running`` row leaves the UI claiming work is still in flight forever.
    Keep the persisted blob immutable, but make the API replay explicit:
    unfinished work was skipped because the audit ended before it ran.
    """
    row = dict(task) if isinstance(task, dict) else {"name": str(task)}
    status = str(job_status or "").strip().lower()
    terminal_job = status in {"completed", "failed", "cancelled", "interrupted"}
    state = str(row.get("state") or "").strip().lower()
    terminal = str(row.get("terminal_status") or "").strip().lower()
    terminal_values = {"completed", "failed", "skipped", "running"}
    if terminal not in terminal_values:
        terminal = {
            "ok": "completed", "completed": "completed", "failed": "failed",
            "skipped": "skipped", "not-installed": "skipped", "running": "running",
        }.get(state, "unresolved")
    if terminal_job and terminal not in {"completed", "failed", "skipped"}:
        task_name = str(row.get("label") or row.get("name") or "task")
        row["state"] = "skipped"
        row["terminal_status"] = "skipped"
        row["reason"] = (
            str(row.get("reason") or "").strip()
            or f"not executed: audit became {status} before {task_name} completed"
        )[:500]
    else:
        row["terminal_status"] = terminal
        if terminal in {"completed", "failed", "skipped"} and not str(row.get("reason") or "").strip():
            row["reason"] = str(row.get("summary") or terminal)[:500]
    # Older task rows incorrectly stamped queue notifications as ended.
    # An active row cannot have an end time; clear only the response copy.
    if not terminal_job and state in {"queued", "running"}:
        row["ended_at"] = None
        if row.get("started_at"):
            row.pop("duration_seconds", None)
    # Preserve a stable task clock for Dashboard/Tasks consumers.  Live rows
    # are refreshed by /progress, while this endpoint still exposes the last
    # known elapsed value after a restart.
    try:
        started = row.get("started_at")
        ended = row.get("ended_at")
        if row.get("duration_seconds") is None and started:
            start_dt = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(str(ended).replace("Z", "+00:00")) if ended else (start_dt if terminal_job else datetime.utcnow().replace(tzinfo=start_dt.tzinfo))
            row["duration_seconds"] = round(max(0.0, (end_dt - start_dt).total_seconds()), 1)
        row = audit_progress.project_task_runtime(row, terminal=terminal_job)
    except (TypeError, ValueError, OverflowError):
        row.setdefault("duration_seconds", 0.0)
    return row


@router.get("/api/activity")
def get_activity():
    """Global clickable activity: live registry plus persisted job timelines.

    After restart, bounded task projections retain clickable history without
    loading complete audit source/evidence maps into the controller heap.
    """
    from backend import activity as _activity
    snap = _activity.snapshot()
    # One snapshot per repository/request keeps every row consistent and avoids
    # repeatedly copying its task ledger while holding the worker's lock.
    progress_cache = {}
    db = get_db()
    try:
        # SQL scalar rows cannot lazy-load either of the large JSON columns.
        columns = (ScanJob.id, ScanJob.repo_id, ScanJob.status, ScanJob.started_at)
        running_jobs = (
            db.query(*columns)
            .filter(ScanJob.status.in_(("queued", "running")))
            .order_by(ScanJob.started_at.desc())
            .limit(50)
            .all()
        )
        recent_jobs = (
            db.query(*columns)
            .order_by(ScanJob.started_at.desc())
            .limit(12)
            .all()
        )
        jobs = [
            _attach_progress({
                "id": j.id,
                "job_id": j.id,
                "repo_id": j.repo_id,
                "status": j.status,
                "started_at": j.started_at.isoformat() if j.started_at else None,
                "href": f"/api/scan-jobs/{j.id}/details",
            }, cache=progress_cache)
            for j in running_jobs
        ]
        live_ids = {r.get("id") for r in (snap.get("running") or []) + (snap.get("recent") or [])}
        persisted = []
        remaining = max(0, 120 - len(snap.get("recent") or []))
        from backend.json_projection import read_json_array_projection, read_json_projection
        for j in recent_jobs:
            if len(persisted) >= remaining:
                break
            try:
                header = read_json_projection(db, ScanJob.output, ScanJob.id == j.id,
                                              _ACTIVITY_PROGRESS_FIELDS)
                offset = 0
                while len(persisted) < remaining:
                    tasks = read_json_array_projection(
                        db, ScanJob.output, ScanJob.id == j.id, ("tasks",), _ACTIVITY_TASK_FIELDS,
                        limit=120, offset=offset, string_limits=_ACTIVITY_TEXT_LIMITS,
                        object_paths=(("runtime_progress",),),
                    )
                    if not tasks:
                        break
                    offset += len(tasks)
                    for row in _rows_from_job_output(j, projected_output={**header, "tasks": tasks}):
                        if row["id"] in live_ids:
                            continue
                        live_ids.add(row["id"])
                        persisted.append(_attach_progress(row, cache=progress_cache))
                        if len(persisted) >= remaining:
                            break
                    if len(tasks) < 120:
                        break
            except (ValueError, TypeError):
                # Invalid historical metadata must not hydrate arbitrary
                # artifacts or prevent other jobs' activity from rendering.
                continue
    finally:
        db.close()
    recent = [_normalize_activity_row(_attach_progress(dict(row), cache=progress_cache)) for row in (snap.get("recent") or [])] + [_normalize_activity_row(row) for row in persisted]
    running = [_normalize_activity_row(_attach_progress(dict(row), cache=progress_cache)) for row in (snap.get("running") or [])]
    return {
        **snap,
        "running": running,
        "recent": recent[:120],
        "running_count": len(running),
        "scan_jobs": jobs,
    }


@router.get("/api/deploy-info")
def get_deploy_info():
    """Active deploy profile, database class, and auth posture (no secrets)."""
    from backend.deploy_profile import inspect_runtime
    return inspect_runtime()


async def _next_legacy_stream_message(queue: asyncio.Queue, *, timeout: float = 15.0):
    """Wake every pre-admission viewer when its queue is durably retired."""
    retirement = queue._lotus_retirement_event
    message_wait = asyncio.create_task(queue.get(), name="lotus-legacy-stream-message")
    retirement_wait = asyncio.create_task(retirement.wait(), name="lotus-legacy-stream-retirement")
    waits = (message_wait, retirement_wait)
    try:
        done, _ = await asyncio.wait(waits, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        # Queue draining can race an awakened getter. Retirement is a
        # broadcast, so all viewers receive the small exact-audit closure.
        if retirement.is_set():
            return dict(queue._lotus_retirement_message), True
        if message_wait not in done:
            raise asyncio.TimeoutError
        return message_wait.result(), False
    finally:
        for pending in waits:
            if not pending.done():
                pending.cancel()
        await asyncio.gather(*waits, return_exceptions=True)


def _read_bound_stream_snapshot(repo_id, job_id):
    with get_db() as db:
        job = _owned_scan_job(db, repo_id, int(job_id), metadata_only=True)
        return job, _bound_job_logs(job, db)


@router.get("/api/repos/{repo_id}/stream")
async def stream_repo(repo_id: int, job_id: Optional[int] = None):
    """Real-time SSE stream with historical replay and live updates.

    ``job_id`` is optional for older log viewers.  Start supplies it so a
    freshly enrolled audit cannot silently attach to a different repository
    run if the page is restored or another scan is queued later.
    """
    db = get_db()
    try:
        if job_id is not None:
            _owned_scan_job(db, repo_id, job_id, metadata_only=True)
        else:
            latest = db.query(ScanJob.id).filter(ScanJob.repo_id == int(repo_id)).order_by(ScanJob.id.desc()).first()
            if latest is not None:
                job_id = int(latest[0])
    finally:
        db.close()
    if job_id is not None:
        # Each viewer owns a cursor into the audit log. A shared asyncio.Queue
        # is a work queue, not a broadcast channel: two browsers used to steal
        # alternate console events from one another. Durable job binding also
        # prevents a historical SSE connection from following a newer scan.
        async def bound_events():
            seen = {}
            idle_polls = 0
            try:
                while idle_polls < 1800:
                    job, logs = await _owned_audit_read(_read_bound_stream_snapshot, repo_id, int(job_id))
                    terminal = str(job.status or "") in {"completed", "failed", "cancelled", "interrupted"}
                    # Check the exact live job again after the threaded read;
                    # a replacement worker owns a different wakeup queue.
                    queue = pipeline.STREAM_QUEUES.get(repo_id) if _job_has_live_artifacts(job) else None
                    if queue is not None:
                        while not queue.empty():
                            try:
                                queue.get_nowait()
                            except asyncio.QueueEmpty:
                                break
                    occurrences = {}
                    emitted = False
                    for msg in logs:
                        marker = json.dumps(msg, sort_keys=True, default=str)
                        occurrences[marker] = occurrences.get(marker, 0) + 1
                        if occurrences[marker] <= seen.get(marker, 0):
                            continue
                        seen[marker] = occurrences[marker]
                        emitted = True
                        yield f"data: {json.dumps(msg)}\n\n"
                    if terminal:
                        return
                    idle_polls = 0 if emitted else idle_polls + 1
                    if idle_polls and idle_polls % 30 == 0:
                        yield f"data: {json.dumps({'level': 'heartbeat', 'time': datetime.utcnow().isoformat(), 'scan_job_id': int(job_id)})}\n\n"
                    await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                return
            except HTTPException:
                yield f"data: {json.dumps({'level': 'complete', 'message': 'Selected audit is no longer available', 'scan_job_id': int(job_id)})}\n\n"

        return StreamingResponse(bound_events(), media_type="text/event-stream")
    # Reuse existing queue (may have buffered messages) or create new one
    if repo_id in pipeline.STREAM_QUEUES:
        queue = pipeline.STREAM_QUEUES[repo_id]
    else:
        queue = asyncio.Queue(maxsize=pipeline.STREAM_QUEUE_MAX)
        pipeline.STREAM_QUEUES[repo_id] = queue
    # This endpoint runs on the main loop and owns/reads the queue; record that ownership
    # so worker-thread _send() bridges enqueues onto this loop safely.
    try:
        pipeline.register_stream_loop(repo_id, asyncio.get_running_loop())
    except Exception:
        pass

    async def event_generator():
        try:
            if queue._lotus_retirement_event.is_set():
                yield f"data: {json.dumps(dict(queue._lotus_retirement_message))}\n\n"
                return
            # De-dup guard: _send writes each message to BOTH STREAM_HISTORY (replayed
            # below) and the live queue (drained below). Those sources overlap, so without
            # tracking what we've already emitted the client would see duplicate log lines
            # (badly so on a late connect/reconnect). We key on id(msg): _send enqueues the
            # exact same dict object it appended to history, and history dicts are retained
            # (never GC'd), so identity is stable and unique - distinct messages can never
            # be wrongly suppressed and none are lost.
            seen_ids = set()

            # First send all historical messages from STREAM_HISTORY (or reconstructed).
            # If the audit already finished, its terminal 'complete' event is in history  -
            # replay up to it and close, so a finished scan doesn't hold the connection open.
            # Snapshot the list so appends made mid-replay flow through the queue path only.
            history = _get_or_reconstruct_logs(repo_id)
            for msg in list(history):
                seen_ids.add(id(msg))
                yield f"data: {json.dumps(msg)}\n\n"
                if isinstance(msg, dict) and msg.get("level") == "complete":
                    return

            # Drain any queued messages that might not be in history yet
            while not queue.empty():
                msg = queue.get_nowait()
                if id(msg) in seen_ids:  # already replayed from history
                    continue
                seen_ids.add(id(msg))
                yield f"data: {json.dumps(msg)}\n\n"
                if isinstance(msg, dict) and msg.get("level") == "complete":
                    return

            # Then wait for new real-time messages with heartbeat keepalives
            idle_count = 0
            max_idle = 60  # 60 * 15s = 15 minutes max idle
            while idle_count < max_idle:
                try:
                    msg, retired = await _next_legacy_stream_message(queue)
                    if retired:
                        yield f"data: {json.dumps(msg)}\n\n"
                        return
                    idle_count = 0  # Reset on real message
                    if id(msg) in seen_ids:  # narrow race: replayed AND queued
                        continue
                    seen_ids.add(id(msg))
                    yield f"data: {json.dumps(msg)}\n\n"
                    # Check for terminal messages
                    if isinstance(msg, dict) and msg.get("level") == "complete":
                        return
                except asyncio.TimeoutError:
                    idle_count += 1
                    # Keepalive as a real SSE *data* event (not a bare comment) so the
                    # browser's onmessage fires and can refresh its liveness timer. A
                    # comment heartbeat kept the TCP connection open but left the client
                    # thinking no message had arrived, so a long quiet phase (e.g. a
                    # C/C++ lab image build) was misread as "scan stopped".
                    yield f"data: {json.dumps({'level': 'heartbeat', 'time': datetime.utcnow().isoformat()})}\n\n"
            yield f"data: {json.dumps({'time': datetime.utcnow().isoformat(), 'level': 'info', 'message': 'Stream ended after 15 minutes idle'})}\n\n"
        except asyncio.CancelledError:
            pass

    return StreamingResponse(event_generator(), media_type="text/event-stream")


class CustomToolIn(BaseModel):
    name: str
    command: str


@router.post("/api/repos/{repo_id}/inject-tool")
async def inject_tool(repo_id: int, tool: CustomToolIn, job_id: Optional[int] = None):
    """Inject a custom tool into the current or next scan for this repo.
    
    If a scan is currently running (in recon phase), it will be picked up
    on the next custom_tools check. If queued before scan start, it will
    be included in Phase 1 recon.
    """
    db = get_db()
    try:
        r = db.query(Repo).filter(Repo.id == repo_id).first()
        if not r:
            raise HTTPException(status_code=404, detail="Repo not found")
        if job_id is not None:
            job = _owned_scan_job(db, repo_id, job_id)
            if str(job.status or "") not in {"queued", "running", "paused"}:
                raise HTTPException(status_code=409, detail="This audit is terminal; tools cannot be injected into a newer audit")
        else:
            job = db.query(ScanJob).filter(
                ScanJob.repo_id == int(repo_id), ScanJob.status.in_(["queued", "running", "paused"]),
            ).order_by(ScanJob.id.desc()).first()
            if job is None:
                raise HTTPException(status_code=409, detail="Start an audit before injecting a tool")
            job_id = int(job.id)
    finally:
        db.close()
    name, command = str(tool.name or "").strip(), str(tool.command or "").strip()
    if not name or len(name) > 200 or not command or len(command) > 4000:
        raise HTTPException(status_code=422, detail="Tool name (1–200 characters) and command (1–4000 characters) are required")
    try:
        pipeline.queue_custom_tool(repo_id, int(job_id), name, command)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except OverflowError as exc:
        raise HTTPException(status_code=429, detail=str(exc), headers={"Retry-After": "5"}) from exc
    # Notify the stream if active
    if repo_id in pipeline.STREAM_QUEUES:
        message = {
            "time": datetime.utcnow().isoformat(),
            "level": "info",
            "message": f"Custom tool queued: {name} ({command})",
        }
        pipeline.STREAM_HISTORY.setdefault(repo_id, []).append(message)
        pipeline.enqueue_stream_message(repo_id, pipeline.STREAM_QUEUES[repo_id], message)
    return {"status": "queued", "tool": name, "repo_id": repo_id, "scan_job_id": job_id}


@router.get("/api/scan-jobs/{job_id}/details")
def get_scan_details(job_id: int):
    """Get detailed scan job info including per-tool results, timing, and coverage metrics."""
    db = get_db()
    try:
        j = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not j:
            raise HTTPException(status_code=404, detail="Scan job not found")
        # Repair the secondary evidence deliverable on read for historical
        # terminal jobs produced before automatic-report publication existed.
        # The helper is idempotent by scan-job identity, so this does not create
        # duplicates and makes the UI's report link reliable after upgrades.
        repaired_report = None
        if str(j.status or "").lower() in {"completed", "failed"}:
            try:
                raw_probe = json.loads(j.output or "{}") if j.output else {}
                has_report = isinstance(raw_probe, dict) and bool(
                    (raw_probe.get("automatic_report") or {}).get("url")
                )
                is_latest = not db.query(ScanJob).filter(
                    ScanJob.repo_id == j.repo_id, ScanJob.id > j.id
                ).first()
                if not has_report and is_latest:
                    from backend.main import ensure_automatic_evidence_report
                    repaired_report = ensure_automatic_evidence_report(int(j.repo_id), scan_job_id=int(j.id))
                    if repaired_report and repaired_report.get("url"):
                        raw_probe["automatic_report"] = repaired_report
                        j.output = json.dumps(raw_probe, default=str)
                        db.commit()
            except Exception:
                # Details remain readable even when report repair is blocked;
                # the evidence status below will continue to expose the gap.
                # A locked write mid-audit must be rolled back so the rest of
                # this read request does not fail with PendingRollbackError.
                try:
                    db.rollback()
                except Exception:
                    pass
                repaired_report = None
        result = {
            "id": j.id,
            "repo_id": j.repo_id,
            "status": j.status,
            "control": (getattr(j, "control", "") or "") if str(j.status or "") in {"queued", "running", "paused"} else "",
            # ``findings_count`` is a legacy storage field.  The canonical
            # operator vocabulary is leads plus receipt-backed confirmed
            # findings; keep the old key only for older SDK clients.
            "findings_count": j.findings_count,
            "lead_count": 0,
            "result_type": "leads",
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "finished_at": j.finished_at.isoformat() if j.finished_at else None,
            "duration_seconds": (j.finished_at - j.started_at).total_seconds() if j.finished_at and j.started_at else None,
            "replay_of_job_id": getattr(j, "replay_of_job_id", None),
            "replay_snapshot_path": "",
            "replay_snapshot_url": f"/api/scan-jobs/{int(j.id)}/snapshot" if getattr(j, "replay_snapshot_path", "") else "",
        }
        if j.output:
            try:
                output = json.loads(j.output)
                result["tool_results"] = output.get("tool_results", [])
                for _tool in result["tool_results"]:
                    if isinstance(_tool, dict):
                        _tool.setdefault("lead_count", _tool.get("findings_count", 0))
                        _tool.setdefault("result_type", "leads")
                        if _tool.get("status") in {"completed", "failed", "skipped", "not-installed"} and not _tool.get("reason"):
                            _tool["reason"] = str(_tool.get("error") or _tool.get("status"))
                result["coverage"] = _normalized_tool_coverage(
                    output.get("coverage", {}), output.get("tool_results", [])
                )
                result["tool_execution_invariant"] = output.get("tool_execution_invariant", {})
                result["timing"] = output.get("timing", {})
                result["language"] = output.get("language", "unknown")
                result["gates"] = output.get("gates", {})
                result["phase2_plan"] = output.get("phase2_plan", {})
                result["phase2_execution"] = output.get("phase2_execution", {})
                result["automatic_report"] = output.get("automatic_report", {})
                if repaired_report and repaired_report.get("url"):
                    result["automatic_report"] = repaired_report
                result["completion_state"] = output.get("completion_state", "")
                result["requested_branch"] = output.get("requested_branch", "")
                result["effective_branch"] = output.get("effective_branch", "")
                result["target_identity"] = output.get("target_identity", {})
                _raw_snapshot = output.get("target_snapshot") or (output.get("audit_plan") or {}).get("target_snapshot", {})
                # Never leak server filesystem paths through a multi-user
                # details response; replay resolves them internally and the
                # snapshot endpoint exposes only the verified manifest.
                result["target_snapshot"] = (
                    {k: v for k, v in _raw_snapshot.items() if k not in {"path", "source_path"}}
                    if isinstance(_raw_snapshot, dict) else {}
                )
                if isinstance(result["target_snapshot"], dict) and result["target_snapshot"]:
                    result["target_snapshot"] = {
                        **result["target_snapshot"],
                        "evidence_url": f"/api/scan-jobs/{int(j.id)}/snapshot",
                        "replay_url": f"/api/scan-jobs/{int(j.id)}/replay",
                    }
                result["audit_integrity"] = output.get("audit_integrity", {})
                result["joern_cpg"] = output.get("joern_cpg", {})
                result["lab_smoke"] = output.get("lab_smoke", {})
                result["library_harness"] = output.get("library_harness", {})
                result["phase2_dynamic_probe"] = output.get("phase2_dynamic_probe", {})
                # ``ScanJob.output`` is an artifact, not an authority source.
                # Older jobs (and tampered/replayed blobs) can contain a
                # fabricated ``confirmed_findings`` counter.  Recompute the
                # displayed proof count from receipt-backed rows exactly as
                # /api/findings, /progress, and /audit-summary do.  Keep the
                # legacy field names for client compatibility, but make their
                # semantics authoritative.
                from backend.main import _authoritative_finding_state, _rows_for_scan_job
                _repo_rows = _rows_for_scan_job(db, j.repo_id, j)
                _published_rows = [
                    row for row in _repo_rows if _authoritative_finding_state(row)[1]
                ]
                result["confirmed_findings"] = len(_published_rows)
                # Full receipt-backed payloads make the terminal result
                # actionable after a restart: every published Finding has an
                # id, CVSS explanation, revision-bound source, proof receipt,
                # report links, and the notebook/reproduction deep link.
                from backend.main import _finding_payload
                result["published_findings"] = [
                    _finding_payload(row, db) for row in _published_rows
                ]
                result["confirmed"] = result["published_findings"]
                _metrics = output.get("discovery_metrics")
                _lead_total = (
                    (_metrics or {}).get("total_leads")
                    if isinstance(_metrics, dict) and (_metrics or {}).get("total_leads") is not None
                    else output.get("candidate_findings", output.get("leads_total", 0))
                )
                result["candidate_findings"] = int(_lead_total or 0)
                result["leads_total"] = int(_lead_total or 0)
                result["lead_count"] = result["leads_total"]
                result["qualified_leads"] = int(((_metrics or {}).get("qualified_leads", 0) if isinstance(_metrics, dict) else 0) or 0)
                result["evidence_status"] = "complete" if _evidence_complete(j.status, output) else "incomplete"
                result["owasp_coverage"] = output.get("owasp_coverage")
                result["ai_gating_log"] = output.get("ai_gating_log")
                result["lab_status"] = output.get("lab_status")
                result["error"] = output.get("error")
                result["traceback"] = output.get("traceback")
                result["discovery_metrics"] = output.get("discovery_metrics")
                result["coverage_ledger"] = output.get("coverage_ledger")
                result["coverage_map"] = output.get("coverage_map") or (output.get("progress") or {}).get("coverage_map")
                result["high_yield"] = output.get("high_yield")
                # Completion-dialog inputs: the persisted task timeline (each
                # with a stream-detail id/href for per-task results) and the
                # learned-skill provenance (how/why learned, before/after,
                # phase-3 generalization proof).
                result["tasks"] = output.get("tasks", [])
                result["skill_compound"] = output.get("skill_compound", {})
                result["progress"] = output.get("progress") or {}
            except json.JSONDecodeError:
                result["error"] = "Could not parse job output"
        # Reuse the same job-bound read contract as Start's live/replay poll.
        # Never fall back to another scan's in-memory map for this repository.
        result["progress"] = get_audit_progress(int(j.repo_id), job_id=int(j.id))
        result["coverage_map"] = result["progress"].get("coverage_map")
        return result
    finally:
        db.close()


@router.get("/api/scan-jobs/{job_id}/learned-skills/{skill_index}/source")
def get_learned_skill_source(job_id: int, skill_index: int):
    """Return the full markdown of a skill this audit learned/strengthened.

    Index-addressed against the job's persisted ``skill_compound.skills`` list
    and confined to the platform skills home so a client cannot read arbitrary
    server files through a crafted path.
    """
    db = get_db()
    try:
        j = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not j:
            raise HTTPException(status_code=404, detail="Scan job not found")
        try:
            output = json.loads(j.output or "{}") if j.output else {}
        except Exception:
            output = {}
        skills = ((output.get("skill_compound") or {}).get("skills")) or []
        if skill_index < 0 or skill_index >= len(skills):
            raise HTTPException(status_code=404, detail="learned skill not found for this audit")
        entry = skills[skill_index] or {}
        path = str(entry.get("path") or "")
        try:
            from backend.skills import get_platform_home
            home = Path(get_platform_home()).resolve()
            resolved = Path(path).resolve()
            resolved.relative_to(home)  # raises if outside the skills home
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=409, detail="skill file is outside the skills home")
        if not resolved.is_file():
            raise HTTPException(status_code=404, detail="skill file is not present on disk")
        if resolved.stat().st_size > 1024 * 1024:
            raise HTTPException(status_code=413, detail="skill file is too large to display")
        return {
            "name": entry.get("name") or resolved.stem,
            "kind": entry.get("kind") or "learned",
            "path_display": resolved.name,
            "content": resolved.read_text(encoding="utf-8", errors="replace"),
        }
    finally:
        db.close()


async def monitor_loop():
    """Single continuous-coverage loop: git-based new-commit detection.

    Replaces the old time-based rescan (which re-ran every 5 minutes even with
    no new commits) and is the only background poller started from lifespan.
    """
    from backend.pipeline import check_continuous_repos
    while True:
        await asyncio.sleep(60)
        try:
            await check_continuous_repos(Repo, Finding, ScanJob, notify=_notify)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            from backend.main import log_console
            log_console(f"Continuous coverage monitor failed ({type(exc).__name__}); next poll will retry", level="warn")
