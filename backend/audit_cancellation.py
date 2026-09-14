"""Explicit cancellation after the audit owner is gone.

A cancelled job is never replayed to obtain a worker. Runtime cleanup is scoped
only to the selected row and attested immutable IDs. Source snapshots, mutable
source caches and signed source-volume receipts are retained for review or the
normal separately guarded maintenance path.
"""
import asyncio
from datetime import datetime
import json
import logging
import threading

logger = logging.getLogger("lotus.audit_cancellation")
_ACTIVE = {"queued", "running", "paused"}
_cleanup_threads = {}
_cleanup_lock = threading.Lock()


def _doc(value):
    if isinstance(value, dict):
        return value
    try:
        value = json.loads(value or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _runtime_record(job):
    raw = job.runtime_cleanup_json
    if raw and raw not in ("{}", "null") and not _doc(raw):
        raise RuntimeError("Recorded runtime cleanup identity is unreadable; ownership recovery is required")
    raw = _doc(raw) or _doc(_doc(job.output).get("lab_status"))
    state = {**_doc(raw.get("state")), **raw}
    return state if (state.get("healthy") or state.get("cleanup_identity") or any(state.get(key) for key in (
        "container", "pod", "job_name", "net_name", "service_name", "container_id", "network_id",
    ))) else {}


def _local_owner(repo_id):
    """Called with scan_worker._scan_lock held; uncertainty retains ownership."""
    from backend import scan_worker as sw
    if repo_id in sw._worker_tasks:
        return True
    future = sw._scan_futures.get(repo_id)
    if future is not None and not future.done():
        # A queued future can be conclusively withdrawn before lease acquisition.
        if str(sw._active_scans.get(repo_id) or "") == "queued" and future.cancel():
            sw._scan_futures.pop(repo_id, None)
            sw._active_scans.pop(repo_id, None)
            sw._scan_started_monotonic.pop(repo_id, None)
        else:
            return True
    return repo_id in sw._active_scans


def _row_fence(db, job):
    from backend.main import ScanJob, Repo
    if db.query(Repo).filter(Repo.id == job.repo_id).with_for_update().first() is None:
        return False
    if str(job.status or "") not in _ACTIVE or str(job.control or "") != "cancel":
        return False
    return bool(db.query(ScanJob).filter(
        ScanJob.id == job.id, ScanJob.repo_id == job.repo_id,
        ScanJob.status == job.status, ScanJob.control == "cancel",
    ).update({"control": "cancel"}, synchronize_session=False))


def _owner_absent(db, job, token=None):
    from backend.main import ScanLease
    now = datetime.utcnow()
    lease = db.query(ScanLease).filter(ScanLease.repo_id == job.repo_id).with_for_update().first()
    if token:
        return bool(lease and lease.job_id == job.id and lease.lease_token == token
                    and lease.expires_at and lease.expires_at > now and job.lease_token == token)
    if lease and lease.expires_at and lease.expires_at > now:
        return False
    # A surviving row-level heartbeat is also evidence of ownership, even if
    # a damaged/legacy database is missing its corresponding ScanLease row.
    if job.lease_owner and job.lease_expires_at and job.lease_expires_at > now:
        return False
    return True


def _terminalize(db, job, *, runtime_cleaned=False, retain_lease=False):
    from backend.main import ScanJob, ScanLease, Repo
    output = _doc(job.output)
    progress = _doc(job.progress_json) or _doc(output.get("progress"))
    tasks = _doc(progress.get("tasks"))
    observed_work = (int(job.attempt or 0) > 0 or output.get("worker_started") is True
                     or str(progress.get("phase") or "") not in {"", "queue", "queued", "ingest"}
                     or any(tasks.get(key) for key in ("completed", "running", "failed")))
    # Enrollment/queue metadata is not evidence that a worker started.
    before_start = job.status == "queued" and not observed_work
    message = ("Audit cancelled before a worker started" if before_start else
               "Audit cancelled after its worker exited; recorded artifacts and source caches were preserved")
    progress.update({"schema_version": 1, "repo_id": job.repo_id, "scan_job_id": job.id,
                     "status": "cancelled", "message": message, "eta_seconds": 0,
                     "evidence_status": "incomplete"})
    output.update({"terminal_reason": "cancelled-before-start" if before_start else "cancelled-unowned-audit",
                   "evidence_status": "incomplete", "progress": progress,
                   "cancellation": {"status": "complete", "runtime_cleanup": "verified" if runtime_cleaned else "no-recorded-runtime",
                                    "source_artifacts": "retained", "message": message}})
    if before_start:
        output["worker_started"] = False
    job.status, job.control, job.finished_at = "cancelled", "", datetime.utcnow()
    job.output, job.progress_json, job.eta_seconds = json.dumps(output), json.dumps(progress), 0
    if not retain_lease:
        job.lease_token, job.lease_owner, job.lease_expires_at, job.heartbeat_at = "", "", None, None
        db.query(ScanLease).filter(ScanLease.repo_id == job.repo_id, ScanLease.job_id == job.id).delete(synchronize_session=False)
    newest = db.query(ScanJob.id).filter(ScanJob.repo_id == job.repo_id).order_by(ScanJob.id.desc()).first()
    if newest and newest[0] == job.id:
        db.query(Repo).filter(Repo.id == job.repo_id).update({"status": "cancelled"}, synchronize_session=False)
    db.commit()


def finish_without_runtime(repo_id, job_id=None, *, db_factory=None):
    """Synchronous exact-row transition, only when there is nothing to inspect."""
    from backend import scan_worker as sw
    from backend.main import SessionLocal, ScanJob
    db_factory = db_factory or SessionLocal
    repo_id = int(repo_id)
    with sw._scan_lock:
        if _local_owner(repo_id):
            return None
        with db_factory() as db:
            query = db.query(ScanJob).filter(ScanJob.repo_id == repo_id, ScanJob.status.in_(_ACTIVE))
            if job_id is not None:
                query = query.filter(ScanJob.id == int(job_id))
            job = query.order_by(ScanJob.id.desc()).first()
            if not job or not _row_fence(db, job) or not _owner_absent(db, job):
                db.rollback()
                return None
            try:
                runtime = _runtime_record(job)
            except RuntimeError:
                db.rollback()
                return None
            if runtime:
                db.rollback()
                return None
            selected_id = job.id
            _terminalize(db, job)
            sw._control.pop(repo_id, None)
            return selected_id


def _pending(db_factory, repo_id, job_id, token, message):
    from backend.main import ScanJob
    with db_factory() as db:
        job = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.repo_id == repo_id).first()
        if not job or not _row_fence(db, job) or not _owner_absent(db, job, token):
            db.rollback()
            return
        output = _doc(job.output)
        progress = _doc(job.progress_json) or _doc(output.get("progress"))
        progress.update({"schema_version": 1, "repo_id": repo_id, "scan_job_id": job_id,
                         "status": "cancelling", "message": message, "eta_seconds": None})
        output.update({"progress": progress, "cancellation": {"status": "cleanup_pending",
                      "message": message, "source_artifacts": "retained"}})
        job.output, job.progress_json = json.dumps(output), json.dumps(progress)
        db.commit()


def _drained_worker_owner(repo_id, expected):
    """Exact registered root whose loop and every owned child have been closed."""
    from backend import scan_worker as sw
    if expected is None or sw._worker_tasks.get(repo_id) is not expected:
        return False
    try:
        loop, task, _job_id = expected
        return loop.is_closed() and task.done() and not asyncio.all_tasks(loop)
    except (TypeError, ValueError, AttributeError):
        return False


async def finish_drained_worker_cancellation(repo_id, job_id, token, worker, *, db_factory=None):
    """Continue the original lease after subprocess/task drain; no ownership gap."""
    if not token or not _drained_worker_owner(int(repo_id), worker) or worker[2] != int(job_id):
        raise RuntimeError("Cancellation requires the exact drained audit worker and its lease")
    return await finish_unowned_cancellation(repo_id, job_id, db_factory=db_factory,
                                             _drained_worker=worker, _lease_token=token)


async def finish_unowned_cancellation(repo_id, job_id, *, db_factory=None,
                                     _drained_worker=None, _lease_token=None):
    """Drain only this audit's attested runtime under a renewable maintenance lease."""
    from backend import scan_worker as sw, reset_runtime_ownership as ownership
    from backend.main import SessionLocal, ScanJob
    db_factory = db_factory or SessionLocal
    repo_id, job_id = int(repo_id), int(job_id)
    if _drained_worker is None:
        done = finish_without_runtime(repo_id, job_id, db_factory=db_factory)
        if done:
            return {"repo_id": repo_id, "job_id": done, "control": "cancelled", "running": False}
    with sw._scan_lock:
        if _drained_worker is None:
            if _local_owner(repo_id):
                return None
        elif not _drained_worker_owner(repo_id, _drained_worker) or _drained_worker[2] != job_id:
            return None
        with db_factory() as db:
            job = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.repo_id == repo_id).first()
            if not job or not _row_fence(db, job) or not _owner_absent(db, job, _lease_token):
                db.rollback()
                return None
            db.rollback()
        token = _lease_token if _drained_worker is not None else sw._acquire_lease(
            db_factory, ScanJob, job_id, repo_id, cancellation=True)
    if not token:
        return None  # Database failure is never evidence that ownership is absent.
    heartbeat = sw._LeaseHeartbeat(db_factory, repo_id, job_id, token)
    heartbeat.start()

    def assert_owner():
        if heartbeat.lost or sw._heartbeat_lease(db_factory, repo_id, job_id, token) is not True:
            raise RuntimeError("Cancellation maintenance lease was lost; remaining runtime was retained")

    try:
        _pending(db_factory, repo_id, job_id, token, "Cancelling unowned audit: verifying its recorded runtime identities")
        with db_factory() as db:
            job = db.get(ScanJob, job_id)
            runtime = _runtime_record(job)
            expected_runtime = job.runtime_cleanup_json
            expected_lab = _doc(job.output).get("lab_status")
            records = ownership._records(db, {}, repo_id=repo_id, scan_job_id=job_id)
            if runtime and not records:
                raise RuntimeError("Recorded runtime has no complete inspection address; ownership recovery is required")
            plan = await ownership.plan_cleanup(db, {}, repo_id=repo_id, scan_job_id=job_id,
                                                include_source_volumes=False)
        assert_owner()
        await ownership.apply_cleanup(plan, {}, assert_owner=assert_owner)
        with sw._scan_lock:
            if ((_drained_worker is None and _local_owner(repo_id))
                    or (_drained_worker is not None and not _drained_worker_owner(repo_id, _drained_worker))):
                raise RuntimeError("A local worker appeared during cleanup; cancellation remains pending")
            with db_factory() as db:
                job = db.get(ScanJob, job_id)
                if not job or not _row_fence(db, job) or not _owner_absent(db, job, token):
                    raise RuntimeError("Audit ownership changed during cleanup; terminal transition refused")
                if job.runtime_cleanup_json != expected_runtime or _doc(job.output).get("lab_status") != expected_lab:
                    raise RuntimeError("Audit runtime record changed during cleanup; terminal transition refused")
                _terminalize(db, job, runtime_cleaned=True, retain_lease=_drained_worker is not None)
                sw._control.pop(repo_id, None)
        return {"repo_id": repo_id, "job_id": job_id, "control": "cancelled", "running": False}
    except (Exception, asyncio.CancelledError) as exc:
        message = "Cancellation cleanup pending: " + (str(exc)[:500] or "cleanup request interrupted; retry Cancel")
        _pending(db_factory, repo_id, job_id, token, message)
        return {"repo_id": repo_id, "job_id": job_id, "control": "cancel", "running": False,
                "cleanup_pending": True, "message": message}
    finally:
        heartbeat.stop()
        if _drained_worker is None:
            sw._release_lease(db_factory, ScanJob, repo_id, job_id, token)


def schedule_runtime_cleanup(repo_id, job_id, *, db_factory=None):
    """Recovery runs cleanup only, on a separate loop; never starts the audit."""
    key = (int(repo_id), int(job_id))
    def run():
        try:
            asyncio.run(finish_unowned_cancellation(*key, db_factory=db_factory))
        except Exception:
            logger.exception("Unowned audit cancellation remains pending for audit %s", key[1])
        finally:
            with _cleanup_lock:
                _cleanup_threads.pop(key, None)
    with _cleanup_lock:
        if key in _cleanup_threads:
            return
        thread = threading.Thread(target=run, name=f"lotus-cancel-{job_id}", daemon=True)
        _cleanup_threads[key] = thread
        thread.start()
