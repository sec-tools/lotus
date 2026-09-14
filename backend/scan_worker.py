"""
Scan worker pool  - runs scan_repo in dedicated threads so the API stays responsive.

Architecture:
  - Each scan gets its own thread with a fresh asyncio event loop
  - Progress messages are bridged from the worker thread to the main event loop
    via call_soon_threadsafe → asyncio.Queue (STREAM_QUEUES)
  - Concurrency limited by LOTUS_MAX_CONCURRENT_SCANS (default 3)
  - The API server (uvicorn) event loop is NEVER blocked by scan I/O

Why threads, not processes:
  - scan_repo uses SQLAlchemy sessions (not picklable across processes)
  - Docker client shares host socket (simpler in-process)
  - STREAM_QUEUES are in-process asyncio.Queues (no IPC needed)
  - Each thread gets its own asyncio event loop  - fully isolated from uvicorn's
"""

from __future__ import annotations

import asyncio
import contextvars
import errno
import json
import logging
import os
import threading
import socket
import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.terminal_json import ObjectView

logger = logging.getLogger("lotus.scan_worker")

MAX_CONCURRENT_SCANS = int(os.environ.get("LOTUS_MAX_CONCURRENT_SCANS", "3"))


def _configured_queue_limit(max_running: int) -> int:
    """Read the bounded local waiting-room limit without accepting nonsense.

    ``ThreadPoolExecutor`` has an unbounded internal queue.  That is a poor
    admission boundary for an audit platform: a burst of repositories can
    reserve memory and make each audit's expected start time unknowable.  The
    dispatcher therefore bounds *admitted but not yet running* scans before a
    future enters that internal queue.  Operators can choose zero for a pure
    reject-when-busy policy; the conservative local default keeps a small
    visible FIFO waiting room.
    """
    raw = os.environ.get("LOTUS_MAX_QUEUED_SCANS", "").strip()
    if raw:
        try:
            return max(0, min(100, int(raw)))
        except (TypeError, ValueError):
            logger.warning("Ignoring invalid LOTUS_MAX_QUEUED_SCANS=%r", raw)
    return max(3, min(100, max(1, int(max_running)) * 3))

_executor: Optional[ThreadPoolExecutor] = None
# ``_active_scans`` contains both executor-queued and running jobs.  The value
# is deliberately a lifecycle state rather than an opaque thread name so the
# API can distinguish capacity from current execution.  Unknown legacy test
# values are treated as running by ``scheduler_status``.
_active_scans: Dict[int, str] = {}
_scan_futures: Dict[int, Any] = {}
# Exact owning root Task; loop callbacks have no asyncio.current_task().
_worker_tasks: Dict[int, Tuple[Any, Any, Optional[int]]] = {}
_scan_lock = threading.Lock()
_scan_started_monotonic: Dict[int, float] = {}
_recent_scan_durations: List[float] = []
_RECENT_DURATION_SAMPLE_CAP = 40

# Last valid context is used only to drain *already durable* queued rows after
# a worker completes.  New HTTP requests still go through ``submit_scan`` and
# the same bounded admission check.  Keeping this in the worker module avoids
# an API->worker->API cycle and makes restart recovery follow the same path.
_scheduler_context: Optional[Tuple[Callable, type, type, type, Optional[Callable], float]] = None
_scheduler_drain_lock = threading.Lock()
_scheduler_stopping = threading.Event()
_scheduler_main_loop: Optional[asyncio.AbstractEventLoop] = None

# Cooperative scan control: repo_id -> "pause" | "cancel". Honored at every progress
# checkpoint (each _send), so scans stop/resume/cancel at phase boundaries.
_control: Dict[int, str] = {}
_cancel_acknowledged = contextvars.ContextVar("lotus_cancel_acknowledged", default=False)
LEASE_TTL_SECONDS = max(60, int(os.environ.get("LOTUS_SCAN_LEASE_TTL_SECONDS", "900")))


def _lease_heartbeat_interval_seconds(ttl_seconds: int = LEASE_TTL_SECONDS) -> float:
    """Return a conservative, bounded independent lease-heartbeat interval.

    A scan can spend many minutes inside a single build, package manager, or
    analyzer subprocess without emitting a pipeline progress event.  Heartbeats
    therefore cannot be coupled to ``pipeline._send``.  Operators may lower the
    interval for a constrained lab via ``LOTUS_SCAN_LEASE_HEARTBEAT_SECONDS``;
    production defaults to at most one minute and at least three renewals before
    a normal lease would expire.
    """
    configured = os.environ.get("LOTUS_SCAN_LEASE_HEARTBEAT_SECONDS", "").strip()
    if configured:
        try:
            return max(1.0, min(float(ttl_seconds) / 2.0, float(configured)))
        except (TypeError, ValueError):
            logger.warning("Ignoring invalid LOTUS_SCAN_LEASE_HEARTBEAT_SECONDS=%r", configured)
    return max(5.0, min(60.0, float(ttl_seconds) / 3.0))


class _LeaseHeartbeat:
    """Renew a durable scan lease while the worker is silent.

    The worker loop intentionally does not own this heartbeat: a long-running
    synchronous subprocess prevents that loop from reaching ``_send``.  This
    tiny daemon uses fresh database sessions, records a *definitive* lease loss
    for the worker to observe at its next safe checkpoint, and tolerates a
    transient database lock until the last known-good lease could actually
    expire.  It never raises on the heartbeat thread.
    """

    def __init__(
        self,
        db_factory: Callable,
        repo_id: int,
        job_id: Optional[int],
        token: str,
        *,
        ttl_seconds: int = LEASE_TTL_SECONDS,
        interval_seconds: Optional[float] = None,
    ) -> None:
        self.db_factory = db_factory
        self.repo_id = int(repo_id)
        self.job_id = job_id
        self.token = token
        self.ttl_seconds = max(1.0, float(ttl_seconds))
        self.interval_seconds = (
            max(0.01, float(interval_seconds))
            if interval_seconds is not None
            else _lease_heartbeat_interval_seconds(int(self.ttl_seconds))
        )
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._lock = threading.Lock()
        self._reason = ""
        self._last_success = time.monotonic()
        self._attempts = 0
        self._thread: Optional[threading.Thread] = None

    @property
    def lost(self) -> bool:
        return self._lost.is_set()

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason

    @property
    def attempts(self) -> int:
        with self._lock:
            return self._attempts

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name=f"lotus-lease-{self.repo_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread and thread is not threading.current_thread():
            # A bounded join keeps shutdown responsive while making it
            # impossible for a late heartbeat to race lease release in the
            # normal case.
            thread.join(timeout=max(1.0, min(5.0, self.interval_seconds + 0.5)))

    def _mark_lost(self, reason: str) -> None:
        with self._lock:
            if not self._reason:
                self._reason = reason
        self._lost.set()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            verdict = _heartbeat_lease(self.db_factory, self.repo_id, self.job_id, self.token)
            with self._lock:
                self._attempts += 1
            if verdict is True:
                self._last_success = time.monotonic()
                continue
            if verdict is False:
                self._mark_lost(f"Durable scan lease lost for repository {self.repo_id}")
                return

            # ``None`` means the datastore was temporarily unavailable (for
            # example a SQLite busy lock), not that another worker owns the
            # scan.  Failing immediately would turn a recoverable hiccup into
            # a false interruption.  Once our last known-valid lease has had a
            # full TTL to expire, fail closed instead of continuing unowned.
            if time.monotonic() - self._last_success >= self.ttl_seconds:
                self._mark_lost(
                    f"Could not renew durable scan lease for repository {self.repo_id} before it expired"
                )
                return
            logger.warning(
                "Transient lease-heartbeat failure for repository %s; retrying before lease expiry",
                self.repo_id,
            )


class ScanCancelled(BaseException):
    """Cooperative-cancellation signal.

    Subclasses BaseException (not Exception) on purpose: scan_repo wraps individual
    phases in `except Exception`, so a normal exception would be swallowed and the scan
    would keep running. BaseException propagates cleanly to the worker top-level, while
    scan_repo's own `finally` still runs (lab teardown), then the worker performs the
    rest of the cancel cleanup (artifacts, status).
    """


class LeaseLost(BaseException):
    """The durable repository lease was lost; worker must stop safely."""


def _acquire_lease(db_factory: Callable, scan_job_cls: type, job_id: int, repo_id: int, *, cancellation: bool = False) -> Optional[str]:
    """Acquire the per-repository lease, atomically where the datastore supports it.

    A database failure returns ``None`` for backwards-compatible test harnesses and
    explicitly non-durable local operation; a conflicting live lease returns an empty
    string so callers can report ``already_running`` rather than running concurrently.
    """
    try:
        from backend.main import ScanLease, Repo
        db = db_factory()
        token = uuid.uuid4().hex
        now = datetime.utcnow()
        expires = now + timedelta(seconds=LEASE_TTL_SECONDS)
        owner = _new_lease_owner()
        try:
            # Serialize claims across different historical jobs of one repo.
            # PostgreSQL locks this row; SQLite serializes the following write.
            if db.query(Repo).filter(Repo.id == int(repo_id)).with_for_update().first() is None:
                db.rollback()
                return ""
            job = db.query(scan_job_cls).filter(
                scan_job_cls.id == int(job_id), scan_job_cls.repo_id == int(repo_id),
            ).first() if job_id else None
            if job_id:
                if job is None or str(job.status or "") not in {"queued", "running", "paused"}:
                    db.rollback()
                    return ""
                if (str(job.control or "") == "cancel") != cancellation:
                    db.rollback()
                    return ""
                # Acquire a write fence on the job before inspecting the
                # lease. A concurrent queued-cancel uses the same row, so it
                # either wins before execution or becomes a cooperative
                # request after this lease claim commits.
                from sqlalchemy import or_
                control_allowed = (scan_job_cls.control == "cancel" if cancellation else
                                   or_(scan_job_cls.control != "cancel", scan_job_cls.control.is_(None)))
                updated = db.query(scan_job_cls).filter(
                    scan_job_cls.id == int(job_id), scan_job_cls.repo_id == int(repo_id),
                    scan_job_cls.status.in_(["queued", "running", "paused"]),
                    control_allowed,
                ).update({"status": scan_job_cls.status}, synchronize_session=False)
                if not updated:
                    db.rollback()
                    return ""
                # Pause/resume may commit between the initial read and this
                # write fence. Keep that current state, then refresh ownership
                # under the fence before inspecting or creating a lease.
                db.refresh(job, attribute_names=[
                    "id", "repo_id", "status", "control",
                    "lease_owner", "lease_expires_at", "attempt",
                ])
            lease = db.query(ScanLease).filter(ScanLease.repo_id == repo_id).with_for_update().first()
            # A live lease is authoritative even when it references the same
            # durable job id.  Re-dispatching that job from another replica
            # must not replace the current token and steal work from its real
            # owner; startup reconciliation will only retry it once the owner
            # is known dead or the lease expires.
            if lease and lease.expires_at and lease.expires_at > now:
                db.rollback()
                return ""
            if cancellation and job and job.lease_owner and job.lease_expires_at and job.lease_expires_at > now:
                db.rollback()
                return ""
            if lease:
                lease.job_id, lease.lease_token, lease.owner = job_id, token, owner
                lease.acquired_at, lease.heartbeat_at, lease.expires_at = now, now, expires
            else:
                db.add(ScanLease(repo_id=repo_id, job_id=job_id, lease_token=token, owner=owner,
                                 acquired_at=now, heartbeat_at=now, expires_at=expires))
            if job is not None:
                job.lease_token, job.lease_owner, job.lease_expires_at, job.heartbeat_at = token, owner, expires, now
                if not cancellation:
                    job.attempt = int(getattr(job, "attempt", 0) or 0) + 1
            db.commit()
            return token
        except Exception as exc:
            db.rollback()
            # IntegrityError means another process won the race. Other DB failures
            # are treated as a non-durable local run; scan_repo will still be guarded
            # by the in-process reservation.
            return "" if exc.__class__.__name__ == "IntegrityError" else None
        finally:
            db.close()
    except Exception:
        return None


def _release_lease(db_factory: Callable, scan_job_cls: type, repo_id: int, job_id: Optional[int], token: Optional[str]) -> None:
    if not token:
        return
    try:
        from backend.main import ScanLease
        db = db_factory()
        try:
            lease = db.query(ScanLease).filter(ScanLease.repo_id == repo_id, ScanLease.lease_token == token).first()
            if lease:
                db.delete(lease)
            if job_id:
                job = db.query(scan_job_cls).filter(scan_job_cls.id == job_id).first()
                if job and getattr(job, "lease_token", "") == token:
                    job.lease_token = ""
                    job.lease_owner = ""
                    job.lease_expires_at = None
                    job.heartbeat_at = None
            db.commit()
        finally:
            db.close()
    except Exception:
        logger.warning("Could not release scan lease for repo %s", repo_id, exc_info=True)


def _worker_terminal_rows(db, repo_cls, scan_job_cls, repo_id, job_id, token):
    """Fence terminal writes against a new owner's repository lease claim."""
    from backend.main import ScanLease
    if not job_id:
        return None, None
    fenced = db.query(repo_cls).filter(repo_cls.id == int(repo_id)).update(
        {"status": repo_cls.status}, synchronize_session=False,
    )
    if not fenced:
        return None, None
    now = datetime.utcnow()
    lease = db.query(ScanLease).filter(
        ScanLease.repo_id == int(repo_id), ScanLease.expires_at > now,
    ).first()
    if lease and (lease.job_id != job_id or lease.lease_token != token):
        return None, None
    job = db.query(scan_job_cls).filter(
        scan_job_cls.id == int(job_id), scan_job_cls.repo_id == int(repo_id),
    ).first()
    if (job is not None and job.lease_token != (token or "")
            and job.lease_owner and job.lease_expires_at and job.lease_expires_at > now):
        return None, None
    # An expired/removed lease can be terminalized if no replacement owner
    # exists. A live replacement's status, evidence and controls stay intact.
    return job, db.query(repo_cls).filter(repo_cls.id == int(repo_id)).first()


def _record_worker_failure_report(db_factory, repo_cls, scan_job_cls, repo_id, job_id, token):
    """Create a secondary failed-audit deliverable only while still its owner."""
    from backend.main import ScanLease, ensure_automatic_evidence_report
    if not token or not job_id:
        return None

    def owned(db):
        return db.query(ScanLease).filter(
            ScanLease.repo_id == int(repo_id), ScanLease.job_id == int(job_id),
            ScanLease.lease_token == token, ScanLease.expires_at > datetime.utcnow(),
        ).first() is not None

    with db_factory() as db:
        job = db.query(scan_job_cls).filter(
            scan_job_cls.id == int(job_id), scan_job_cls.repo_id == int(repo_id),
            scan_job_cls.status == "failed", scan_job_cls.lease_token == token,
        ).first()
        if job is None or not owned(db):
            return None
    try:
        result = ensure_automatic_evidence_report(repo_id, scan_job_id=int(job_id))
        if not isinstance(result, dict) or (not result.get("id") and not result.get("error")):
            result = {"id": None, "created": False, "url": "", "error": "Automatic failure evidence report unavailable"}
    except Exception as exc:
        result = {"id": None, "created": False, "url": "", "error": str(exc)[:500]}
    with db_factory() as db:
        job, _repo = _worker_terminal_rows(db, repo_cls, scan_job_cls, repo_id, job_id, token)
        if job is None or job.status != "failed" or job.lease_token != token or not owned(db):
            db.rollback()
            return None
        output = _load_job_output(job.output)
        output["automatic_report"] = result
        job.output = json.dumps(output)
        db.commit()
    return result


def _heartbeat_lease(db_factory: Callable, repo_id: int, job_id: Optional[int], token: str) -> Optional[bool]:
    """Renew a lease.

    ``False`` means ownership was conclusively lost; ``None`` means that the
    database could not be queried/updated and callers should retry until the
    last known-good expiry.  Keeping those states distinct is important for
    SQLite and short transient outages: a lock is not evidence that another
    worker owns the audit.
    """
    try:
        from backend.main import ScanLease, ScanJob
        db = db_factory()
        try:
            now = datetime.utcnow()
            lease = db.query(ScanLease).filter(ScanLease.repo_id == repo_id, ScanLease.lease_token == token).first()
            if not lease or (lease.expires_at and lease.expires_at <= now):
                db.rollback()
                return False
            lease.heartbeat_at, lease.expires_at = now, now + timedelta(seconds=LEASE_TTL_SECONDS)
            if job_id:
                job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
                if job and getattr(job, "lease_token", "") == token:
                    job.heartbeat_at, job.lease_expires_at = now, lease.expires_at
            db.commit()
            return True
        finally:
            db.close()
    except Exception:
        logger.debug("Lease heartbeat database operation failed for repo %s", repo_id, exc_info=True)
        return None


def _persist_scan_control(repo_id: int, action: str, expected_job_id: Optional[int] = None) -> Optional[bool]:
    """Persist an operator control request for the current queued/running job.

    The worker-local map remains the low-latency path, but the database row is
    the cross-process source of truth.  This helper is deliberately best-effort
    for the explicit single-user/test mode; shared profiles fail closed at
    enqueue time if their durable job cannot be written.
    """
    try:
        from backend.main import SessionLocal, ScanJob, ScanLease
        db = SessionLocal()
        try:
            # Use a conditional UPDATE after selecting the latest row:
            # a terminal worker commit racing a button click must win without
            # allowing a late pause request to resurrect a completed job.
            value = action if action in ("pause", "cancel") else ""
            current = (
                db.query(ScanJob)
                .filter(
                    ScanJob.repo_id == int(repo_id),
                    ScanJob.status.in_(["queued", "running", "paused"]),
                )
                .order_by(ScanJob.id.desc())
                .first()
            )
            if expected_job_id is not None and (current is None or int(current.id) != int(expected_job_id)):
                return False
            if current is not None:
                if str(current.control or "") == "cancel" and action != "cancel":
                    return False  # Cancellation is monotonic; retry a terminal audit explicitly.
                old_status = str(current.status or "")
                values = {"control": value}
                if action == "resume" and old_status == "paused":
                    live_owner = db.query(ScanLease).filter(
                        ScanLease.repo_id == int(repo_id), ScanLease.job_id == int(current.id),
                        ScanLease.expires_at > datetime.utcnow(),
                    ).first()
                    values["status"] = "running" if live_owner is not None else "queued"
                updated = db.query(ScanJob).filter(
                    ScanJob.id == int(current.id), ScanJob.status == old_status,
                ).update(values, synchronize_session=False)
                db.commit()
                return bool(updated)
            return False
        finally:
            db.close()
    except Exception:
        logger.debug("Could not persist scan control for repo %s", repo_id, exc_info=True)
        return None


def _durable_scan_control(repo_id: int) -> Optional[str]:
    """Return authoritative control, including an empty (resumed) value.

    ``None`` means there is no durable active job or the database cannot be
    read. Only that case may fall back to the process-local control cache.
    """
    try:
        from backend.main import SessionLocal, ScanJob
        db = SessionLocal()
        try:
            job = (
                db.query(ScanJob.control)
                .filter(ScanJob.repo_id == int(repo_id), ScanJob.status.in_(["queued", "running", "paused"]))
                .order_by(ScanJob.id.desc())
                .first()
            )
            return str(job[0] or "") if job else None
        finally:
            db.close()
    except Exception:
        return None


def _read_persisted_scan_control(repo_id: int) -> str:
    return _durable_scan_control(repo_id) or ""


def _clear_persisted_scan_control(repo_id: int, job_id: Optional[int] = None) -> None:
    """Clear a control flag only for the terminal job this worker owned."""
    try:
        from backend.main import SessionLocal, ScanJob
        db = SessionLocal()
        try:
            query = db.query(ScanJob).filter(ScanJob.repo_id == int(repo_id))
            if job_id is not None:
                query = query.filter(ScanJob.id == int(job_id))
            job = query.order_by(ScanJob.id.desc()).first()
            if job is not None and str(job.status or "") not in {"queued", "running", "paused"}:
                job.control = ""
                db.commit()
        finally:
            db.close()
    except Exception:
        logger.debug("Could not clear scan control for repo %s", repo_id, exc_info=True)


def _force_cancel_worker_task(repo_id: int, expected_job_id: Optional[int] = None) -> bool:
    """Cancel the captured root Task on its own loop, fenced to the exact audit."""
    repo_id = int(repo_id)
    with _scan_lock:
        owner = _worker_tasks.get(repo_id)
    if owner is None:
        return False
    loop, task, job_id = owner
    if loop.is_closed() or (expected_job_id is not None and job_id != int(expected_job_id)):
        return False

    def _cancel_captured() -> None:
        with _scan_lock:
            still_owner = _worker_tasks.get(repo_id) is owner
        if still_owner and not task.done() and not task.cancelling():
            # Repeated HTTP cancellations must not interrupt the root task's
            # finally blocks while it is already draining owned resources.
            task.cancel()

    try:
        loop.call_soon_threadsafe(_cancel_captured)
        return True
    except RuntimeError:
        return False


def set_scan_control(repo_id: int, action: str, *, expected_job_id: Optional[int] = None) -> Dict[str, Any]:
    """action: 'pause' | 'resume' | 'cancel'. Returns the resulting control state."""
    applied = _persist_scan_control(repo_id, action, expected_job_id)
    if expected_job_id is not None and not applied:
        raise RuntimeError("Audit control could not be applied to the selected active job; refresh and retry")
    if applied is False and action != "cancel" and _durable_scan_control(repo_id) == "cancel":
        raise RuntimeError("This audit is cancelling; wait for terminal cleanup before starting an explicit replay")
    if action == "resume":
        _control.pop(repo_id, None)
    elif action in ("pause", "cancel"):
        _control[repo_id] = action
    if action == "cancel":
        if applied:
            from backend.dependency_audit import cancel_dependency_children
            cancel_dependency_children(repo_id, expected_job_id)
        cancelled_job_id = _cancel_unstarted_queued_job(repo_id, expected_job_id)
        if cancelled_job_id is not None:
            _control.pop(repo_id, None)
            with _scan_lock:
                future = _scan_futures.get(int(repo_id))
            if future is not None and future.cancel():
                _finish_scheduler_entry(repo_id)
            return {"repo_id": repo_id, "job_id": cancelled_job_id, "control": "cancelled", "running": False}
        # A running worker is not cancellable via ThreadPoolExecutor.cancel().
        # Inject a CancelledError into its event loop so any awaiting subprocess
        # gets reaped and the pipeline unwinds cleanly.
        if is_scan_running(repo_id):
            _force_cancel_worker_task(repo_id, expected_job_id)
    state = _control.get(repo_id) or ("running" if is_scan_running(repo_id) else "idle")
    return {"repo_id": repo_id, "control": state, "running": is_scan_running(repo_id)}


def _cancel_unstarted_queued_job(repo_id: int, expected_job_id: Optional[int] = None) -> Optional[int]:
    """Close an unowned cancellation without runtime I/O; preserve all artifacts.

    The historical name is retained for callers. Running/paused orphan rows
    are equally cancellable once local ownership and durable leases are absent.
    Recorded runtime cleanup is handled by the asynchronous control route.
    """
    from backend.audit_cancellation import finish_without_runtime
    return finish_without_runtime(repo_id, expected_job_id)


def get_scan_control(repo_id: int) -> Optional[str]:
    durable = _durable_scan_control(repo_id)
    if durable is not None:
        return durable or None
    return _control.get(repo_id)


async def _honor_control(repo_id: int) -> None:
    """Block while paused; raise ScanCancelled if cancellation was requested."""
    # The durable empty value is a resume issued by another API process;
    # an old local pause must never mask it indefinitely.
    st = get_scan_control(repo_id)
    while st == "pause":
        await asyncio.sleep(0.4)
        st = get_scan_control(repo_id)
    if st == "cancel":
        # Consume the flag so the teardown/complete _send in scan_repo's finally does
        # not re-raise while we are already unwinding.
        _control.pop(repo_id, None)
        if _cancel_acknowledged.get():
            return
        _cancel_acknowledged.set(True)
        raise ScanCancelled()


def resolve_max_concurrent_scans() -> int:
    """Resolve the concurrent-scan limit from Settings, adapting to the host.

    Precedence: explicit user value in Settings (>0) > adaptive recommendation
    (when ``adaptive_resources`` is on) > the ``LOTUS_MAX_CONCURRENT_SCANS`` env
    default. Bounded to [1, 20] to match the API validation. Best-effort: any
    failure falls back to the env constant so scheduling never breaks.
    """
    try:
        from backend.main import SessionLocal, Settings
        db = SessionLocal()
        try:
            s = db.query(Settings).first()
        finally:
            db.close()
        if s is not None:
            user_val = int(getattr(s, "max_concurrent_scans", 0) or 0)
            if user_val > 0 and not getattr(s, "adaptive_resources", True):
                return max(1, min(20, user_val))
            if getattr(s, "adaptive_resources", True):
                try:
                    from backend import resource_monitor as rm
                    rec = int(rm.recommended_resources().get("max_concurrent_scans", user_val or MAX_CONCURRENT_SCANS))
                    # An explicit user value still caps the adaptive recommendation.
                    return max(1, min(20, min(rec, user_val) if user_val > 0 else rec))
                except Exception:
                    pass
            if user_val > 0:
                return max(1, min(20, user_val))
    except Exception:
        pass
    return max(1, MAX_CONCURRENT_SCANS)


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    _scheduler_stopping.clear()
    # Double-checked locking: the fast path avoids the lock once initialized, while the
    # lock prevents two concurrent first-callers from creating (and leaking) two pools.
    if _executor is None:
        with _scan_lock:
            if _executor is None:
                _executor = ThreadPoolExecutor(
                    max_workers=resolve_max_concurrent_scans(),
                    thread_name_prefix="lotus-scan",
                )
    return _executor


def _effective_worker_limit() -> int:
    """Return the actual pool size, not a later Settings recommendation.

    A ``ThreadPoolExecutor`` does not resize after construction.  Reporting a
    fresh Settings value while dispatching through an older pool made the UI
    promise slots that did not exist.  Prefer the instantiated pool's bound;
    otherwise use the value that a first pool would receive.
    """
    executor = _executor
    try:
        if executor is not None:
            return max(1, int(getattr(executor, "_max_workers")))
    except (TypeError, ValueError, AttributeError):
        pass
    return max(1, int(resolve_max_concurrent_scans()))


def _scheduler_status_locked(max_running: int, repo_id: Optional[int] = None) -> Dict[str, Any]:
    """Produce a lock-held scheduler snapshot with truthful queue semantics."""
    max_running = max(1, int(max_running))
    max_queued = _configured_queue_limit(max_running)
    states = dict(_active_scans)
    queued_ids = [
        int(rid) for rid, state in states.items()
        if str(state or "").lower() in {"queued", "admitting"}
    ]
    # Pre-existing tests and integrations historically stored arbitrary thread
    # names in this map.  Such values mean active execution, never an invisible
    # queue entry.
    running_ids = [
        int(rid) for rid, state in states.items()
        if str(state or "").lower() not in {"queued", "admitting"}
    ]
    position: Optional[int] = None
    if repo_id is not None:
        state = str(states.get(int(repo_id), "")).lower()
        if state in {"queued", "admitting"}:
            try:
                position = queued_ids.index(int(repo_id)) + 1
            except ValueError:
                position = None
        elif int(repo_id) in running_ids:
            position = 0

    free_running_slots = max(0, max_running - len(running_ids))
    eta_seconds: Optional[int] = None
    eta_basis = "insufficient_completed_audits"
    if position and position <= free_running_slots:
        # This position fits a currently free worker. The estimate concerns
        # dispatcher wait only, not later startup/runtime admission delays.
        eta_seconds = 0
        eta_basis = "available_worker_slot"
    elif position and _recent_scan_durations:
        try:
            median_seconds = max(1.0, float(statistics.median(_recent_scan_durations)))
            # Free workers consume the front of the queue immediately. The
            # remaining waves use completed duration as a conservative proxy,
            # not a measurement of active workers' remaining time or a promise.
            waves = (int(position) - free_running_slots + max_running - 1) // max_running
            eta_seconds = int(round(median_seconds * max(1, waves)))
            eta_basis = "completed_audit_duration_median"
        except (statistics.StatisticsError, TypeError, ValueError):
            pass

    admitted = len(states)
    total_capacity = max_running + max_queued
    return {
        "scheduler_scope": "process-local",
        "running_scans": len(running_ids),
        "queued_scans": len(queued_ids),
        "active_scans": admitted,
        "max_concurrent": max_running,
        "max_queued": max_queued,
        "admission_capacity": total_capacity,
        "available_running_slots": free_running_slots,
        "available_queue_slots": max(0, max_queued - len(queued_ids)),
        "available_slots": max(0, total_capacity - admitted),
        "running_repos": running_ids,
        "queued_repos": queued_ids,
        "queue_position": position,
        "queue_eta_seconds": eta_seconds,
        "queue_eta_basis": eta_basis,
    }


def scheduler_status(repo_id: Optional[int] = None) -> Dict[str, Any]:
    """Public, read-only local dispatcher state for API/progress consumers."""
    max_running = _effective_worker_limit()
    with _scan_lock:
        return _scheduler_status_locked(max_running, repo_id)


def _remember_scheduler_context(
    db_factory: Callable,
    repo_cls: type,
    finding_cls: type,
    scan_job_cls: type,
    notify: Optional[Callable],
    cvss_threshold: float,
) -> None:
    """Save enough stable wiring to drain durable overflow after a completion."""
    global _scheduler_context
    _scheduler_context = (db_factory, repo_cls, finding_cls, scan_job_cls, notify, float(cvss_threshold))


def _push_to_main_stream(
    main_loop: asyncio.AbstractEventLoop,
    repo_id: int,
    message: str,
    level: str = "info",
    detail_id: Optional[str] = None,
    scan_job_id: Optional[int] = None,
):
    """Thread-safe push of a progress message to the main event loop's SSE queue."""
    from backend.pipeline import STREAM_QUEUES, STREAM_HISTORY, enqueue_stream_message
    msg: Dict[str, Any] = {
        "time": datetime.utcnow().isoformat(),
        "level": level,
        "message": message,
    }
    if detail_id:
        msg["detail_id"] = detail_id
    if scan_job_id is not None:
        msg["scan_job_id"] = int(scan_job_id)

    # Append to STREAM_HISTORY for durable start-to-finish log replay
    if repo_id not in STREAM_HISTORY:
        STREAM_HISTORY[repo_id] = []
    STREAM_HISTORY[repo_id].append(msg)
    if len(STREAM_HISTORY[repo_id]) > 10000:
        STREAM_HISTORY[repo_id] = STREAM_HISTORY[repo_id][-8000:]

    q = STREAM_QUEUES.get(repo_id)
    if not q or main_loop.is_closed():
        return
    lease_token = None
    try:
        main_loop.call_soon_threadsafe(enqueue_stream_message, repo_id, q, msg)
    except RuntimeError:
        pass  # main loop closed between check and call


def _load_job_output(raw: Any) -> Dict[str, Any]:
    """Read a historical output blob without ever discarding opaque evidence."""
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str) and raw.strip():
        try:
            decoded = json.loads(raw)
            if isinstance(decoded, dict):
                return dict(decoded)
        except Exception:
            # Older or externally written rows can contain plain text.  Keep
            # it visible under a namespaced field instead of replacing it with
            # a tiny lease error and erasing the operator's evidence.
            return {"legacy_output": raw}
    return {}


def _merge_live_artifacts(repo_id: int, output: Dict[str, Any], *, artifacts=None) -> Dict[str, Any]:
    """Merge the current in-memory audit timeline into an existing job blob.

    Lease loss frequently occurs after substantial work but before the normal
    end-of-pipeline persistence.  ``capture_scan_artifacts`` gives us that
    partial work; this helper only overwrites a persisted collection when the
    live collection actually contains data, and merges detail payloads so old
    revision-bound evidence remains reachable.
    """
    try:
        from backend.pipeline import capture_scan_artifacts
        if artifacts is None:
            artifacts = capture_scan_artifacts(repo_id)
    except Exception:
        logger.warning("Could not capture partial artifacts for repository %s", repo_id, exc_info=True)
        return output

    live_tasks = artifacts.get("tasks")
    if isinstance(live_tasks, list) and live_tasks:
        prior_tasks = output.get("tasks") if isinstance(output.get("tasks"), list) else []
        # A task name is the pipeline's stable timeline key.  Keep older
        # entries absent from the live snapshot, while a newer live row wins
        # for the same task (for example, its terminal state/reason).
        merged_by_name = {
            str(row.get("name") or f"prior-{idx}"): row
            for idx, row in enumerate(prior_tasks) if isinstance(row, dict)
        }
        prior_order = [str(row.get("name") or f"prior-{idx}") for idx, row in enumerate(prior_tasks) if isinstance(row, dict)]
        for idx, row in enumerate(live_tasks):
            if not isinstance(row, dict):
                continue
            key = str(row.get("name") or f"live-{idx}")
            if key not in merged_by_name:
                prior_order.append(key)
            merged_by_name[key] = row
        output["tasks"] = [merged_by_name[key] for key in prior_order if key in merged_by_name]

    live_logs = artifacts.get("logs")
    if isinstance(live_logs, list) and live_logs:
        prior_logs = output.get("logs") if isinstance(output.get("logs"), list) else []
        merged_logs = []
        seen_logs = set()
        for row in [*prior_logs, *live_logs]:
            if not isinstance(row, dict):
                continue
            marker = (
                str(row.get("time") or ""), str(row.get("level") or ""),
                str(row.get("message") or ""), str(row.get("detail_id") or ""),
            )
            if marker not in seen_logs:
                seen_logs.add(marker)
                merged_logs.append(row)
        output["logs"] = merged_logs
    details = artifacts.get("details")
    if isinstance(details, dict) and details:
        prior = output.get("details") if isinstance(output.get("details"), dict) else {}
        output["details"] = {**prior, **details}
    return output


def _terminal_progress(repo_id: int, status: str) -> Dict[str, Any]:
    """Close stale timeline rows and return a durable incomplete progress snapshot."""
    try:
        from backend import audit_progress
        from backend.pipeline import finalize_open_tasks
        finalize_open_tasks(repo_id, reason=f"audit {status} before this task reported completion")
        return audit_progress.finish(repo_id, status=status, evidence_status="incomplete")
    except Exception:
        logger.warning("Could not finalize progress for repository %s", repo_id, exc_info=True)
        return {}


def _project_worker_terminal(repo_id, job, status):
    """Build terminal evidence without changing progress, tasks or activity."""
    from backend import audit_progress
    live = audit_progress.snapshot(repo_id)
    output = _load_job_output(job.output)
    if live.get("scan_job_id") in {None, int(job.id)}:
        output = _merge_live_artifacts(repo_id, output)
        progress = live
    else:
        progress = _load_job_output(job.progress_json)
    output, progress = deepcopy(output), deepcopy(progress)
    now = datetime.utcnow().isoformat()
    reason = f"audit {status} before this task reported completion"

    def terminal_row(raw, *, timeline=False):
        row = dict(raw)
        observed = row.get("status") if timeline else row.get("terminal_status") or row.get("state")
        if observed not in {"completed", "ok", "failed", "skipped"}:
            row.update(state="failed", terminal_status="failed", ended_at=now,
                       reason=reason, summary=f"{reason}: {row.get('name') or 'task'}")
            if timeline:
                row["status"] = "failed"
        if timeline or "is_slow" in row:
            row["is_slow"] = False
        return row

    output["tasks"] = [terminal_row(row) for row in output.get("tasks") or [] if isinstance(row, dict)]
    timeline = progress.get("task_timeline") or [
        {**row, "status": {"ok": "completed"}.get(row.get("state"), row.get("state"))}
        for row in output["tasks"]
    ]
    progress["task_timeline"] = [terminal_row(row, timeline=True) for row in timeline if isinstance(row, dict)]
    counts = {name: sum(row.get("status") == name for row in progress["task_timeline"])
              for name in ("completed", "running", "failed", "skipped")}
    progress["tasks"] = {**counts, "total": max(int((progress.get("tasks") or {}).get("total") or 0), sum(counts.values()))}
    progress.update(repo_id=int(repo_id), scan_job_id=int(job.id), status=status, evidence_status="incomplete",
                    updated_at=now, eta_seconds=0, eta_basis="terminal", current_task=None, active_task=None,
                    slow_tasks=[], is_slow=False)
    output["progress"] = progress
    return progress, output


def _publish_worker_terminal(db_factory, repo_cls, scan_job_cls, repo_id, job_id, token, status, main_loop, messages):
    """Publish only the committed terminal state still owned by this worker."""
    from backend import activity, audit_progress, pipeline
    with db_factory() as db:
        job, _repo = _worker_terminal_rows(db, repo_cls, scan_job_cls, repo_id, job_id, token)
        live = audit_progress.snapshot(repo_id, include_coverage_map=False)
        if job is None or job.status != status or live.get("scan_job_id") not in {None, int(job_id)}:
            db.rollback()
            return False
        output = _load_job_output(job.output)
        progress = output.get("progress") or _load_job_output(job.progress_json)
        tasks = deepcopy(output.get("tasks") or [])
        prior_tasks = {(row.get("name"), row.get("scan_job_id")): row
                       for row in pipeline.SCAN_TASKS.get(repo_id) or [] if isinstance(row, dict)}
        pipeline.SCAN_TASKS[repo_id] = tasks
        for task in tasks:
            if not isinstance(task, dict):
                continue
            previous = prior_tasks.get((task.get("name"), task.get("scan_job_id"))) or {}
            if previous.get("terminal_status") in {"completed", "failed", "skipped"}:
                continue
            name = str(task.get("name") or "task")
            ident = f"{repo_id}:{task.get('scan_job_id')}:{name}" if task.get("scan_job_id") is not None else f"{repo_id}:{name}"
            activity.upsert(kind="scan-task", ident=ident, name=task.get("label") or name,
                            state=task.get("state") or "failed", phase=task.get("phase") or "",
                            summary=task.get("summary") or "", detail_id=task.get("detail_id"),
                            repo_id=repo_id, job_id=task.get("scan_job_id"),
                            terminal_status=task.get("terminal_status"), reason=task.get("reason") or "")
        audit_progress.restore(repo_id, progress, restore_task_timeline=True)
        if main_loop and not main_loop.is_closed():
            for message, level in messages:
                _push_to_main_stream(main_loop, repo_id, message, level, scan_job_id=job_id)
        # All writes above are process-local. The repository fence is held
        # through publication; no nested database session/commit is opened.
        db.rollback()
    return True


def _apply_progress_to_job(job: Any, progress: Dict[str, Any]) -> None:
    """Write the structured progress snapshot to a ScanJob-like object safely."""
    if not progress:
        return
    try:
        job.progress_json = json.dumps(progress)
        job.phase = str(progress.get("phase") or getattr(job, "phase", "") or "")
        current = progress.get("current_task") or {}
        job.current_task = (
            str(current.get("name") or "") if isinstance(current, dict) else str(current or "")
        )
        job.progress_pct = float(progress.get("progress_pct", 0) or 0)
        job.eta_seconds = progress.get("eta_seconds")
    except Exception:
        logger.debug("Could not attach terminal progress to job", exc_info=True)


def _unstarted_progress_view(output, raw_checkpoint, repo_id, job_id):
    """Choose this row's existing checkpoint without decoding its heavy map.

    Match the active-job read rule: newer checkpoint wins over output.progress.
    Missing legacy IDs are accepted only because both inputs came from this
    exact row; explicit conflicting IDs refuse the write, never borrow state.
    """
    checkpoint = ObjectView(raw_checkpoint or "{}")
    persisted = output.child("progress")
    candidates = [view for view in (persisted, checkpoint) if view and view._fields]
    for view in candidates:
        for key, expected in (("repo_id", repo_id), ("scan_job_id", job_id)):
            value = view.get(key, max_chars=64)
            if value is not None and (type(value) is not int or value != expected):
                raise ValueError("Durable progress identity mismatch")
    if not candidates:
        return None
    if persisted is None or not persisted._fields:
        return checkpoint
    if checkpoint._fields and str(checkpoint.get("updated_at", "", max_chars=1024) or "") >= str(
            persisted.get("updated_at", "", max_chars=1024) or ""):
        return checkpoint
    return persisted

def _persist_unstarted_job_terminal(repo_id, db_factory, repo_cls, scan_job_cls,
                                    job_id, *, status, reason, update_repo=False):
    """Terminalize this failed attempt without erasing prior execution history."""
    if job_id is None:
        return
    try:
        from backend.main import ScanLease
        db = db_factory()
        try:
            job = db.query(scan_job_cls).filter(scan_job_cls.id == job_id,
                scan_job_cls.repo_id == repo_id).first()
            if job is None or str(job.status or "") not in {"queued", "running", "paused"}:
                return
            # A same-job owner may have appeared after the caller's lease
            # observation but before this read. Never adopt that owner's
            # fresh token merely because a later equality CAS would match.
            now = datetime.utcnow()
            if ((job.lease_token or job.lease_owner) and job.lease_expires_at
                    and job.lease_expires_at > now):
                return
            live_owner = db.query(ScanLease).filter(ScanLease.repo_id == repo_id,
                ScanLease.expires_at > now)
            if not update_repo:
                live_owner = live_owner.filter(ScanLease.job_id == job_id)
            if live_owner.first() is not None:
                return
            output = ObjectView(job.output or "{}")
            prior = _unstarted_progress_view(output, job.progress_json, repo_id, job_id)
            now = datetime.utcnow()
            terminal = {"repo_id": int(repo_id), "scan_job_id": int(job_id),
                "status": status, "message": reason, "updated_at": now.isoformat(),
                "eta_seconds": 0, "eta_basis": "terminal", "terminal": True,
                "current_task": None, "active_task": None, "slow_tasks": [],
                "is_slow": False, "evidence_status": "incomplete"}
            if prior is None:
                prior = ObjectView('{"schema_version":1,"phase":"ingest",'
                    '"phase_label":"Queue","progress_pct":0,"tasks":'
                    '{"total":0,"completed":0,"running":0,"failed":0,"skipped":0}}')
            # Preserve task rows/counts, observations, map, recovery fields and
            # unknown evidence as raw spans. The API projects terminal clocks;
            # a dispatch failure is not evidence that earlier tasks failed.
            previous_reasons = prior.get("bottlenecks", [], max_chars=16384)
            if not isinstance(previous_reasons, list):
                previous_reasons = []
            terminal["bottlenecks"] = [reason[:240]] + [item for item in previous_reasons
                if isinstance(item, str) and item != reason[:240]][:7]
            progress = prior.patch(terminal)
            changes = {"error": reason, "terminal_reason": reason,
                "evidence_status": "incomplete", "interrupted_at": now.isoformat(),
                "worker_started": False, "progress": progress}
            # Keep exactly the row observed above. A concurrent lifecycle,
            # owner, control or artifact write wins over this losing attempt.
            query = db.query(scan_job_cls).filter(scan_job_cls.id == job_id,
                scan_job_cls.repo_id == repo_id, scan_job_cls.status == job.status,
                scan_job_cls.control == job.control, scan_job_cls.finished_at == job.finished_at,
                scan_job_cls.lease_token == job.lease_token,
                scan_job_cls.lease_owner == job.lease_owner,
                scan_job_cls.lease_expires_at == job.lease_expires_at,
                scan_job_cls.output == job.output, scan_job_cls.progress_json == job.progress_json)
            live_owner = db.query(ScanLease).filter(ScanLease.repo_id == repo_id,
                ScanLease.expires_at > datetime.utcnow())
            if not update_repo:
                live_owner = live_owner.filter(ScanLease.job_id == job_id)
            query = query.filter(~live_owner.exists())
            values = {"status": status, "finished_at": now,
                "output": output.patch(changes).dumps(), "progress_json": progress.dumps(),
                "phase": prior.get("phase", job.phase, max_chars=1024) or "",
                "progress_pct": prior.get("progress_pct", job.progress_pct, max_chars=128) or 0,
                "current_task": "", "eta_seconds": 0}
            if query.update(values, synchronize_session=False) != 1:
                db.rollback()
                return
            if update_repo:
                db.query(repo_cls).filter(repo_cls.id == repo_id).update(
                    {"status": status}, synchronize_session=False)
            db.commit()
        finally:
            db.close()
    except Exception:
        logger.warning("Could not persist unstarted terminal state for repo %s", repo_id,
                       exc_info=True)


def _shared_profile_requires_durable_lease() -> bool:
    """Whether a scan may proceed without a durable lease in this deployment."""
    try:
        from backend.deploy_profile import allow_unsafe, current_profile
        return current_profile() in ("team", "enterprise") and not allow_unsafe()
    except Exception:
        # Failing closed is appropriate only when the deployment profile itself
        # is available.  Preserve the existing single-user/test fallback if it
        # cannot be read during early startup.
        return False


def _live_lease_job_id(db_factory: Callable, repo_id: int) -> Optional[int]:
    """Return the current durable owner for a repository, if it is still live."""
    try:
        from backend.main import ScanLease
        db = db_factory()
        try:
            lease = (
                db.query(ScanLease)
                .filter(ScanLease.repo_id == int(repo_id), ScanLease.expires_at > datetime.utcnow())
                .first()
            )
            return int(lease.job_id) if lease is not None else None
        finally:
            db.close()
    except Exception:
        return None


def _mark_worker_started(repo_id: int) -> None:
    """Move an admitted executor future from visible queue to running state."""
    with _scan_lock:
        if int(repo_id) in _active_scans:
            _active_scans[int(repo_id)] = "running"
            _scan_started_monotonic[int(repo_id)] = time.monotonic()


def _finish_scheduler_entry(repo_id: int) -> None:
    """Release one admitted slot and asynchronously offer it to durable backlog."""
    duration: Optional[float] = None
    with _scan_lock:
        started = _scan_started_monotonic.pop(int(repo_id), None)
        if started is not None:
            duration = max(0.0, time.monotonic() - started)
        _active_scans.pop(int(repo_id), None)
        _scan_futures.pop(int(repo_id), None)
        if duration is not None:
            _recent_scan_durations.append(duration)
            if len(_recent_scan_durations) > _RECENT_DURATION_SAMPLE_CAP:
                del _recent_scan_durations[:-_RECENT_DURATION_SAMPLE_CAP]
    # A legacy/startup backlog may contain more jobs than the bounded local
    # executor admitted initially.  Drain in a separate daemon so worker
    # teardown never blocks on SQLite or a remote control-plane database.
    try:
        _request_durable_backlog_drain()
    except Exception:
        logger.debug("Could not request durable queue drain", exc_info=True)


_WORKER_DRAIN_NOTICE_SECONDS = 15.0


def _close_worker_loop(loop: asyncio.AbstractEventLoop) -> bool:
    """Cancel and drain worker-owned tasks before retiring their event loop.

    A failed parent coroutine does not cancel independently created tasks.
    Closing its loop immediately strands their subprocess pipes and prevents
    their finally blocks from running, even when those helpers handle normal
    cancellation correctly.
    """
    drained = False
    async def drain() -> None:
        nonlocal drained
        current = asyncio.current_task()
        tasks = [task for task in asyncio.all_tasks() if task is not current and not task.done()]
        if not getattr(loop, "_lotus_cleanup_started", False):
            for task in tasks:
                task.cancel()
            loop._lotus_cleanup_started = True
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=_WORKER_DRAIN_NOTICE_SECONDS)
            if done:
                await asyncio.gather(*done, return_exceptions=True)
            if pending:
                logger.warning("Worker cleanup is still draining %s task(s); ownership retained", len(pending))
                return
        await asyncio.wait_for(loop.shutdown_asyncgens(), timeout=5)
        drained = not any(task is not current and not task.done() for task in asyncio.all_tasks())

    try:
        loop.run_until_complete(drain())
    except Exception:
        logger.warning("Worker loop cleanup failed", exc_info=True)
    finally:
        if drained:
            loop.close()
    return drained


def _make_progress_persistor(db_factory, scan_job_cls, repo_id, job_id, lease_token):
    """Fence telemetry to its original worker, including delayed drop callbacks.

    A progress update does not own job lifecycle transitions. It may reflect
    an already committed pause/terminal state, but cannot reopen that state or
    adopt a replacement lease. Missing original identity disables persistence.
    """
    from backend.main import ScanLease
    token = lease_token or ""
    owner = None
    lock = threading.RLock()
    retired = False
    last_write = 0.0
    last_drop = 0
    last_coverage = None
    try:
        if type(job_id) is int and job_id > 0 and type(repo_id) is int and repo_id > 0:
            with db_factory() as db:
                job = db.query(scan_job_cls).filter(scan_job_cls.id == job_id,
                    scan_job_cls.repo_id == repo_id, scan_job_cls.lease_token == token).first()
                if job is not None:
                    candidate = str(job.lease_owner or "")
                    if (token and candidate and job.lease_expires_at and job.lease_expires_at > datetime.utcnow()
                            or not token and not candidate and job.lease_expires_at is None):
                        owner = candidate
    except Exception:
        logger.debug("Could not capture original progress owner for repo %s", repo_id, exc_info=True)

    def persist(state):
        nonlocal last_write, last_drop, last_coverage
        with lock:
            if (retired or owner is None or not isinstance(state, dict)
                    or type(state.get("repo_id")) is not int or state["repo_id"] != repo_id
                    or type(state.get("scan_job_id")) is not int or state["scan_job_id"] != job_id
                    or state.get("coverage_map_omitted") is True):
                return False
            try:
                dropped = int(state.get("stream_dropped", 0) or 0)
                mapped = state.get("coverage_map") or {}
                if isinstance(mapped, dict) and mapped.get("repo_id", repo_id) != repo_id:
                    return False
                coverage_revision = mapped.get("updated_at") if isinstance(mapped, dict) else None
                drop_changed = dropped > last_drop
                coverage_changed = bool(coverage_revision) and coverage_revision != last_coverage
                if time.monotonic() - last_write < 2 and state.get("status") == "running" and not drop_changed and not coverage_changed:
                    return False
                with db_factory() as db:
                    job = db.query(scan_job_cls).filter(scan_job_cls.id == job_id,
                        scan_job_cls.repo_id == repo_id).first()
                    if job is None or job.lease_token != token or str(job.lease_owner or "") != owner:
                        return False
                    status, control = str(job.status or ""), str(job.control or "")
                    incoming = state.get("status")
                    terminal = {"completed", "failed", "cancelled", "interrupted"}
                    if status in terminal:
                        if incoming != status or control not in ({"", "cancel"} if status == "cancelled" else {""}):
                            return False
                    elif status in {"queued", "running", "paused"}:
                        if control == "cancel" or control not in {"", "pause", "resume"}:
                            return False
                        paused = status == "paused" or control == "pause"
                        if incoming != ("paused" if paused else status):
                            return False
                    else:
                        return False
                    previous = _load_job_output(job.progress_json)
                    if (dropped < int(previous.get("stream_dropped", 0) or 0)
                            or (isinstance(state.get("updated_at"), str) and isinstance(previous.get("updated_at"), str)
                                and state["updated_at"] < previous["updated_at"])):
                        return False
                    now = datetime.utcnow()
                    query = db.query(scan_job_cls).filter(scan_job_cls.id == job_id,
                        scan_job_cls.repo_id == repo_id, scan_job_cls.lease_token == token,
                        scan_job_cls.lease_owner == job.lease_owner, scan_job_cls.lease_expires_at == job.lease_expires_at,
                        scan_job_cls.status == job.status, scan_job_cls.control == job.control,
                        scan_job_cls.progress_json == job.progress_json)
                    if token:
                        if not job.lease_expires_at or job.lease_expires_at <= now:
                            return False
                        lease_exists = db.query(ScanLease).filter(ScanLease.repo_id == repo_id,
                            ScanLease.job_id == job_id, ScanLease.lease_token == token,
                            ScanLease.owner == owner, ScanLease.expires_at > now).exists()
                        query = query.filter(scan_job_cls.lease_expires_at > now, lease_exists)
                    else:
                        if job.lease_expires_at is not None:
                            return False
                        live_lease = db.query(ScanLease).filter(ScanLease.repo_id == repo_id,
                            ScanLease.expires_at > now).exists()
                        query = query.filter(~live_lease)
                    current = state.get("current_task") or {}
                    changed = query.update({"progress_json": json.dumps(state), "phase": state.get("phase", ""),
                        "current_task": current.get("name", "") if isinstance(current, dict) else str(current),
                        "progress_pct": float(state.get("progress_pct", 0) or 0),
                        "eta_seconds": state.get("eta_seconds")}, synchronize_session=False)
                    if changed != 1:
                        db.rollback()
                        return False
                    db.commit()
                # Failed/CAS-rejected writes must not consume a coverage/drop
                # transition or throttle the next valid persistence attempt.
                last_write, last_drop = time.monotonic(), max(last_drop, dropped)
                if coverage_changed:
                    last_coverage = coverage_revision
                return True
            except Exception:
                logger.debug("Progress persistence unavailable for repo %s", repo_id, exc_info=True)
                return False

    def close():
        nonlocal retired
        with lock:
            retired = True
    persist.close = close
    persist.original_owner = owner
    persist.original_token = token
    return persist


def capture_terminal_read_owner(repo_id, job_id, token, owner):
    """Capture this process's original worker and transport, not a restored row.

    The API must separately validate the durable job and unexpired lease. A
    completed task can still own its reservation while terminal writes drain.
    """
    from backend import pipeline
    if (type(repo_id) is not int or repo_id <= 0 or type(job_id) is not int or job_id <= 0
            or not isinstance(token, str) or not token or not isinstance(owner, str) or not owner):
        return None
    with _scan_lock:
        worker = _worker_tasks.get(repo_id)
        queue = pipeline.STREAM_QUEUES.get(repo_id)
        loop = pipeline.STREAM_QUEUE_LOOPS.get(repo_id)
        persistor = pipeline.PROGRESS_PERSISTORS.get(repo_id)
        if (not isinstance(worker, tuple) or len(worker) != 3 or worker[2] != job_id
                or repo_id not in _active_scans or queue is None or loop is None or persistor is None
                or pipeline.WORKER_LOOPS.get(repo_id) is not worker[0]
                or getattr(persistor, "original_token", None) != token
                or getattr(persistor, "original_owner", None) != owner):
            return None
        return worker, queue, loop, persistor


def terminal_read_owner_is_current(repo_id, job_id, token, owner, marker):
    """Refuse cached display data after any worker or transport replacement."""
    if not isinstance(marker, tuple) or len(marker) != 4:
        return False
    current = capture_terminal_read_owner(repo_id, job_id, token, owner)
    return current is not None and all(left is right for left, right in zip(current, marker))


def _persist_terminal_cache_artifacts(db_factory, scan_job_cls, repo_id, job_id,
                                     token, original_owner, state, artifacts) -> bool:
    """Commit a drained worker's last telemetry without changing its outcome.

    The caller still owns the local worker/reservation. A terminal lease may
    have expired or been cleared by the original interruption handler, but a
    different lease (even expired) never authorizes these writes.
    """
    from backend.main import Report, ScanLease
    from backend.terminal_json import ObjectView
    from sqlalchemy.orm import load_only
    terminal = {"completed", "failed", "cancelled", "interrupted"}
    if (original_owner is None or type(job_id) is not int or job_id <= 0
            or not isinstance(state, dict) or type(state.get("repo_id")) is not int or state.get("repo_id") != repo_id
            or type(state.get("scan_job_id")) is not int or state.get("scan_job_id") != job_id or state.get("status") not in terminal
            or state.get("coverage_map_omitted") is True):
        return False
    try:
        with db_factory() as db:
            fields = ("id", "repo_id", "status", "control", "finished_at", "lease_token",
                      "lease_owner", "lease_expires_at", "output", "progress_json")
            job = db.query(scan_job_cls).options(load_only(
                *(getattr(scan_job_cls, name) for name in fields), raiseload=True,
            )).filter(scan_job_cls.id == job_id,
                                               scan_job_cls.repo_id == repo_id).first()
            if (job is None or job.status != state["status"] or not job.finished_at
                    or str(job.control or "") not in ({"", "cancel"} if job.status == "cancelled" else {""})):
                return False
            # Keep the original TEXT for the exact CAS, but do not rebuild
            # its source/coverage/evidence graph just to merge telemetry.
            # Invalid legacy documents keep their cache and original bytes.
            output = ObjectView(job.output or "{}")
            original = job.lease_token == (token or "") and str(job.lease_owner or "") == original_owner
            cleared_interruption = (bool(token) and job.status == "interrupted" and output.get("lease_lost", max_chars=32) is True
                                    and not job.lease_token and not job.lease_owner and job.lease_expires_at is None)
            if not original and not cleared_interruption:
                return False
            lease = db.query(ScanLease).filter(ScanLease.repo_id == repo_id).first()
            if lease is not None and (lease.job_id != job_id or lease.lease_token != (token or "")
                                      or lease.owner != original_owner):
                return False
            if not token and (job.lease_expires_at is not None or lease is not None):
                return False
            report = output.get("automatic_report", max_chars=16384)
            if job.status in {"completed", "failed"}:
                if not isinstance(report, dict):
                    return False
                if report.get("id"):
                    if (type(report["id"]) is not int or db.query(Report.id).filter(
                            Report.id == report["id"], Report.repo_id == repo_id,
                            Report.manifest_hash != "").first() is None):
                        return False
                elif not report.get("error"):
                    return False
            prior = ObjectView(job.progress_json or "{}")
            prior_updated = prior.get("updated_at", max_chars=1024)
            if (int(state.get("stream_dropped", 0) or 0) < int(prior.get("stream_dropped", 0, max_chars=128) or 0)
                    or (prior.truthy("coverage_map") and not state.get("coverage_map"))
                    or (isinstance(state.get("updated_at"), str) and isinstance(prior_updated, str)
                        and state["updated_at"] < prior_updated)):
                return False
            mapped = state.get("coverage_map")
            if isinstance(mapped, dict) and mapped.get("repo_id", repo_id) != repo_id:
                return False
            # Logs and task rows need identity-based merging. Large detail
            # values are overlaid by key directly into the same output stream;
            # old keys and explicit nulls remain intact without graph copies.
            telemetry = {key: output.get(key) for key in ("tasks", "logs")
                         if isinstance(artifacts.get(key), list) and artifacts[key]}
            merged = _merge_live_artifacts(repo_id, telemetry,
                artifacts={key: value for key, value in artifacts.items() if key != "details"})
            details = artifacts.get("details")
            if isinstance(details, dict) and details:
                merged["details"] = (output.child("details") or ObjectView("{}")).patch(details)
            merged["progress"] = state
            # Every predicate is from this fresh read; a concurrent report
            # update, Stop, ownership change, or successor admission wins.
            query = db.query(scan_job_cls).filter(scan_job_cls.id == job_id,
                scan_job_cls.repo_id == repo_id, scan_job_cls.status == job.status,
                scan_job_cls.control == job.control, scan_job_cls.finished_at == job.finished_at,
                scan_job_cls.lease_token == job.lease_token, scan_job_cls.lease_owner == job.lease_owner,
                scan_job_cls.lease_expires_at == job.lease_expires_at,
                scan_job_cls.output == job.output, scan_job_cls.progress_json == job.progress_json)
            if lease is None:
                query = query.filter(~db.query(ScanLease).filter(ScanLease.repo_id == repo_id).exists())
            else:
                query = query.filter(db.query(ScanLease).filter(ScanLease.repo_id == repo_id,
                    ScanLease.job_id == job_id, ScanLease.lease_token == lease.lease_token,
                    ScanLease.owner == lease.owner, ScanLease.expires_at == lease.expires_at).exists())
            from sqlalchemy.orm import aliased
            successor = aliased(scan_job_cls)
            query = query.filter(~db.query(successor).filter(successor.repo_id == repo_id,
                successor.id != job_id, successor.status.in_({"queued", "running", "paused"})).exists())
            current = state.get("current_task") or {}
            changed = query.update({"output": output.patch(merged).dumps(), "progress_json": json.dumps(state),
                "phase": state.get("phase", ""),
                "current_task": current.get("name", "") if isinstance(current, dict) else str(current),
                "progress_pct": float(state.get("progress_pct", 0) or 0), "eta_seconds": state.get("eta_seconds")},
                synchronize_session=False)
            if changed != 1:
                db.rollback()
                return False
            db.commit()
            return True
    except Exception:
        logger.warning("Terminal cache artifacts retained for repository %s: persistence unavailable", repo_id,
                       exc_info=True)
        return False


def _retire_terminal_scan_cache(db_factory, scan_job_cls, repo_id, job_id, token,
                                worker_owner, queue, main_loop, persistor, *, timeout=3.0) -> bool:
    """Flush callbacks, persist off the API loop, then release exact caches.

    The original worker entry and admission reservation remain installed
    throughout. Expired rendezvous callbacks are inert; failure keeps caches.
    """
    from backend import audit_progress, pipeline
    if worker_owner is None or main_loop is None or main_loop.is_closed() or not main_loop.is_running():
        return False

    def owned():
        return (_worker_tasks.get(repo_id) is worker_owner and repo_id in _active_scans
                and pipeline.STREAM_QUEUES.get(repo_id) is queue
                and pipeline.STREAM_QUEUE_LOOPS.get(repo_id) is main_loop)

    def rendezvous(action):
        done = threading.Event()
        gate = threading.Lock()
        waiting = [True]
        result = [False]
        def callback():
            with gate:
                if not waiting[0]:
                    return
                try:
                    with _scan_lock:
                        if owned():
                            result[0] = action()
                finally:
                    waiting[0] = False
                    done.set()
        try:
            main_loop.call_soon_threadsafe(callback)
        except RuntimeError:
            return False
        if not done.wait(timeout):
            with gate:
                waiting[0] = False
            return False
        return result[0]

    # FIFO with every enqueue from the now-drained worker. Stop the progress
    # callback after its final drop receipt, before the fresh terminal CAS.
    if not rendezvous(lambda: (persistor.close(), True)[1]):
        return False
    with _scan_lock:
        if not owned():
            return False
    state = audit_progress.snapshot(repo_id)
    artifacts = pipeline.capture_scan_artifacts(repo_id, include_coverage_map=False)
    if not _persist_terminal_cache_artifacts(db_factory, scan_job_cls, repo_id, job_id,
                                            token, persistor.original_owner, state, artifacts):
        return False
    return rendezvous(lambda: pipeline.release_scan_caches(repo_id, expected_job_id=job_id, expected_queue=queue))


def _run_scan_in_thread(
    repo_id: int,
    db_factory: Callable,
    repo_cls: type,
    finding_cls: type,
    scan_job_cls: type,
    notify: Optional[Callable] = None,
    cvss_threshold: float = 7.0,
    main_loop: Optional[asyncio.AbstractEventLoop] = None,
    job_id: Optional[int] = None,
    lease_token: Optional[str] = None,
    source_override: Optional[str] = None,
    target_identity_override: Optional[Dict[str, Any]] = None,
):
    """Run scan_repo in a dedicated thread with its own event loop.

    The worker's own _send() pushes to the main loop's SSE queue so
    the browser receives real-time updates while the scan runs.
    """
    from backend import pipeline
    from backend.pipeline import STREAM_QUEUES, STREAM_DETAILS, STREAM_HISTORY

    worker_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(worker_loop)
    lease_heartbeat: Optional[_LeaseHeartbeat] = None
    _mark_worker_started(repo_id)

    # A ThreadPoolExecutor may hold an admitted job for minutes while all scan
    # workers are busy.  Claiming a short-lived lease at HTTP enqueue time made
    # that queue delay indistinguishable from a dead worker: the lease expired
    # before this thread ever began useful work.  Claim here, immediately
    # before the pipeline starts.  Local reservations still prevent duplicate
    # submits in this process; an inter-process race is resolved here without
    # running duplicate labs or scanners.
    if job_id is not None and not lease_token:
        claimed = _acquire_lease(db_factory, scan_job_cls, job_id, repo_id)
        if claimed == "":
            owner_job_id = _live_lease_job_id(db_factory, repo_id)
            same_durable_job = owner_job_id is not None and int(owner_job_id) == int(job_id)
            reason = (
                "This process did not start a duplicate worker because another worker already holds "
                "the durable repository lease for this audit. No scanner or lab work was duplicated."
                if same_durable_job else
                "This queued audit did not start because another worker already holds "
                "the durable repository lease. No scanner or lab work was duplicated."
            )
            if not same_durable_job:
                _persist_unstarted_job_terminal(
                    repo_id, db_factory, repo_cls, scan_job_cls, job_id,
                    status="interrupted", reason=reason,
                )
            if main_loop and not main_loop.is_closed():
                _push_to_main_stream(main_loop, repo_id, reason, "warning")
                if not same_durable_job:
                    _push_to_main_stream(main_loop, repo_id, "Audit queue entry closed", "complete")
            worker_loop.close()
            _finish_scheduler_entry(repo_id)
            _control.pop(repo_id, None)
            return
        if claimed is None and _shared_profile_requires_durable_lease():
            reason = "Durable scan lease could not be acquired; shared deployment refused an unowned audit."
            _persist_unstarted_job_terminal(
                repo_id, db_factory, repo_cls, scan_job_cls, job_id,
                status="failed", reason=reason,
            )
            if main_loop and not main_loop.is_closed():
                _push_to_main_stream(main_loop, repo_id, reason, "error")
                _push_to_main_stream(main_loop, repo_id, "Audit queue entry closed", "complete")
            worker_loop.close()
            _finish_scheduler_entry(repo_id)
            _control.pop(repo_id, None)
            return
        lease_token = claimed or None

    if lease_token:
        lease_heartbeat = _LeaseHeartbeat(db_factory, repo_id, job_id, lease_token)
        lease_heartbeat.start()

    # The SSE queue for this repo was created on the MAIN loop (submit_scan), and
    # pipeline.register_stream_loop() recorded that ownership. pipeline._send is now
    # inherently loop-safe: when called from this worker loop it bridges enqueues onto
    # the main loop via call_soon_threadsafe. No module-global monkeypatch (which raced
    # across concurrent scans and could revert _send to a non-bridged version mid-scan).
    #
    # Register this worker loop so main-loop code (e.g. the phase2-approve endpoint) can
    # safely schedule callbacks onto it, and install the cooperative-control hook once so
    # _send honors pause/cancel on the worker path.
    pipeline.WORKER_LOOPS[repo_id] = worker_loop
    pipeline.set_send_control_hook(_honor_control)
    def _lease_check() -> None:
        if not lease_heartbeat:
            return
        if lease_heartbeat.lost:
            raise LeaseLost(lease_heartbeat.reason or f"Durable scan lease lost for repository {repo_id}")
    pipeline.set_lease_check(repo_id, _lease_check)
    _persist_progress = _make_progress_persistor(db_factory, scan_job_cls, repo_id, job_id, lease_token)
    pipeline.set_progress_persistor(repo_id, _persist_progress)
    _worker_queue = STREAM_QUEUES.get(repo_id)

    try:
        _scan_options = {"job_id": job_id}
        # Keep compatibility with lightweight/test pipeline adapters that
        # implement the pre-replay call signature.  Replay callers always pass
        # these values and therefore retain the immutable binding.
        if source_override is not None:
            _scan_options["source_override"] = source_override
        if target_identity_override is not None:
            _scan_options["target_identity_override"] = target_identity_override
        root_task = worker_loop.create_task(
            pipeline.scan_repo(
                repo_id, db_factory, repo_cls, finding_cls, scan_job_cls,
                notify, cvss_threshold, **_scan_options,
            )
        )
        owner = (worker_loop, root_task, job_id)
        with _scan_lock:
            _worker_tasks[int(repo_id)] = owner
        # A cancellation can be persisted while the executor is starting this
        # task. Do not lose that request between admission and registration.
        if _control.get(int(repo_id)) == "cancel":
            root_task.cancel()
        worker_loop.run_until_complete(root_task)
    except (ScanCancelled, asyncio.CancelledError):
        logger.info(f"Scan {repo_id} cancelled by user; cleaning up")
        _cancel_requested = True
        _cleanup_cancelled_scan(repo_id, db_factory, repo_cls, scan_job_cls, job_id, main_loop, lease_token)
    except LeaseLost as e:
        logger.error("Scan %s stopped: %s", repo_id, e)
        persisted = False
        try:
            db = db_factory()
            try:
                job, repo = _worker_terminal_rows(db, repo_cls, scan_job_cls, repo_id, job_id, lease_token)
                if job and job.status in {"queued", "running", "paused"}:
                    # Do not replace a multi-megabyte evidence bundle with an
                    # 86-byte error.  Preserve every persisted key, then merge
                    # the current task/log/detail snapshot captured before the
                    # worker releases its resources.
                    progress, output = _project_worker_terminal(repo_id, job, "interrupted")
                    output.update({
                        "error": str(e),
                        "terminal_reason": str(e),
                        "evidence_status": "incomplete",
                        "interrupted_at": datetime.utcnow().isoformat(),
                        "lease_lost": True,
                    })
                    if progress:
                        output["progress"] = progress
                    job.status = "interrupted"
                    job.finished_at = datetime.utcnow()
                    job.output = json.dumps(output)
                    _apply_progress_to_job(job, progress)
                    if lease_token and getattr(job, "lease_token", "") == lease_token:
                        job.lease_token = ""
                        job.lease_owner = ""
                        job.lease_expires_at = None
                        job.heartbeat_at = None
                    if repo:
                        repo.status = "interrupted"
                db.commit()
                persisted = job is not None and job.status == "interrupted"
            finally:
                db.close()
        except Exception:
            logger.warning("Could not persist lease-loss state for repo %s", repo_id, exc_info=True)
        if persisted:
            try:
                _publish_worker_terminal(db_factory, repo_cls, scan_job_cls, repo_id, job_id, lease_token,
                    "interrupted", main_loop, [(f"Scan stopped safely: {e}", "error"),
                    ("Audit interrupted; partial evidence preserved", "complete")])
            except Exception:
                logger.exception("Could not publish committed interruption for repository %s", repo_id)
    except Exception as e:
        logger.error(f"Scan {repo_id} failed in worker thread: {e}", exc_info=True)
        # Pipeline adapters and setup code can fail outside scan_repo's own
        # persistence guard. Close the durable job before closing its stream;
        # otherwise the UI and unique-active-job index are stranded forever.
        persisted = False
        messages = []
        try:
            db = db_factory()
            try:
                job, repo = _worker_terminal_rows(db, repo_cls, scan_job_cls, repo_id, job_id, lease_token)
                if job is not None and str(job.status or "") in {"queued", "running", "paused"}:
                    progress, output = _project_worker_terminal(repo_id, job, "failed")
                    output.update({
                        "error": str(e)[:2000],
                        "terminal_reason": "worker-execution-failed",
                        "evidence_status": "incomplete",
                        "progress": progress,
                    })
                    job.status = "failed"
                    job.finished_at = datetime.utcnow()
                    job.output = json.dumps(output)
                    _apply_progress_to_job(job, progress)
                    if repo is not None:
                        repo.status = "failed"
                db.commit()
                persisted = job is not None and job.status == "failed"
            finally:
                db.close()
        except Exception:
            logger.exception("Could not persist worker failure for repository %s", repo_id)
        if persisted:
            try:
                report = _record_worker_failure_report(
                    db_factory, repo_cls, scan_job_cls, repo_id, job_id, lease_token,
                )
                if report and report.get("error"):
                    messages.append((f"Automatic failure evidence report unavailable: {report['error']}", "warning"))
            except Exception:
                logger.exception("Could not preserve automatic report status for repository %s", repo_id)
                messages.append(("Automatic failure evidence report status could not be saved", "warning"))
            try:
                _publish_worker_terminal(db_factory, repo_cls, scan_job_cls, repo_id, job_id, lease_token,
                    "failed", main_loop, [*messages, (f"Scan failed: {e}", "error"),
                    ("Audit failed; partial evidence preserved", "complete")])
            except Exception:
                logger.exception("Could not publish committed failure for repository %s", repo_id)
    finally:
        # Keep the lease and worker context until owned child tasks have
        # received cancellation and completed their subprocess cleanup.
        _owner = locals().get("owner")
        _cancel_requested_here = bool(locals().get("_cancel_requested"))
        def finish_drained_worker(_worker_drained):
            if _cancel_requested_here and _worker_drained and lease_token and _owner:
                try:
                    from backend.audit_cancellation import finish_drained_worker_cancellation
                    result = asyncio.run(finish_drained_worker_cancellation(repo_id, job_id, lease_token,
                        _owner, db_factory=db_factory))
                    if result and result.get("control") == "cancelled":
                        _terminal_progress(repo_id, "cancelled")
                        if main_loop and not main_loop.is_closed():
                            _push_to_main_stream(main_loop, repo_id,
                                "Audit cancelled; owned tasks stopped and runtime cleanup verified. Evidence retained.", "complete")
                    elif main_loop and not main_loop.is_closed():
                        _push_to_main_stream(main_loop, repo_id,
                            (result or {}).get("message") or "Cancellation cleanup pending; retry Cancel to verify remaining runtime.", "warning")
                except Exception:
                    logger.exception("Cancellation remains pending for audit %s after worker drain", job_id)
            try:
                if _worker_drained:
                    _retire_terminal_scan_cache(db_factory, scan_job_cls, repo_id, job_id, lease_token,
                        _owner, _worker_queue, main_loop, _persist_progress)
            except Exception:
                logger.warning("Terminal caches retained for repository %s: release unavailable", repo_id, exc_info=True)
            with _scan_lock:
                owns_local_entry = _worker_tasks.get(int(repo_id)) is _owner
                if owns_local_entry:
                    _worker_tasks.pop(int(repo_id), None)
                    _control.pop(repo_id, None)
            if lease_heartbeat is not None:
                lease_heartbeat.stop()
            if pipeline.WORKER_LOOPS.get(repo_id) is worker_loop:
                pipeline.WORKER_LOOPS.pop(repo_id, None)
            if pipeline.LEASE_CHECKS.get(repo_id) is _lease_check:
                pipeline.set_lease_check(repo_id, None)
            _persist_progress.close()
            if pipeline.PROGRESS_PERSISTORS.get(repo_id) is _persist_progress:
                pipeline.set_progress_persistor(repo_id, None)
            _release_lease(db_factory, scan_job_cls, repo_id, job_id, lease_token)
            _clear_persisted_scan_control(repo_id, job_id)
            if owns_local_entry:
                _finish_scheduler_entry(repo_id)

        _worker_drained = _close_worker_loop(worker_loop)
        if not _worker_drained and not worker_loop.is_closed():
            # A native thread or subprocess cleanup can outlive cancellation.
            # Keep its loop, heartbeat, exact owner and admission reservation;
            # neither reset nor another audit may take its resources yet.
            message = "Cancellation cleanup is still running; audit ownership is retained until its tasks stop"
            try:
                with db_factory() as db:
                    job, _repo = _worker_terminal_rows(db, repo_cls, scan_job_cls, repo_id, job_id, lease_token)
                    if job is not None:
                        progress = _load_job_output(job.progress_json)
                        progress.update({"status": "cancelling" if _cancel_requested_here else "cleanup_pending",
                                         "message": message, "eta_seconds": None})
                        job.progress_json = json.dumps(progress)
                        db.commit()
            except Exception:
                logger.exception("Could not save pending task-drain status for audit %s", job_id)
            if main_loop and not main_loop.is_closed():
                _push_to_main_stream(main_loop, repo_id, message, "warning")
            def continue_cleanup():
                asyncio.set_event_loop(worker_loop)
                try:
                    while not _close_worker_loop(worker_loop):
                        time.sleep(.25)
                    finish_drained_worker(True)
                except Exception:
                    # Unknown cleanup cannot transfer ownership. A process
                    # restart followed by normal incarnation recovery is safe.
                    logger.exception("Audit %s task cleanup requires process recovery; ownership retained", job_id)
            threading.Thread(target=continue_cleanup, name=f"lotus-drain-{job_id}", daemon=True).start()
        else:
            finish_drained_worker(_worker_drained)


def _cleanup_cancelled_scan(repo_id, db_factory, repo_cls, scan_job_cls, job_id, main_loop, lease_token=None):
    """Persist cancellation intent before draining; never claim cleanup succeeded."""
    try:
        with db_factory() as db:
            job, _repo = _worker_terminal_rows(db, repo_cls, scan_job_cls, repo_id, job_id, lease_token)
            if job is None or job.status not in {"queued", "running", "paused"}:
                db.rollback()
                return False
            output = _merge_live_artifacts(repo_id, _load_job_output(job.output))
            progress = _load_job_output(job.progress_json) or output.get("progress") or {}
            message = "Cancelling audit: stopping owned tasks and verifying local runtime cleanup"
            progress.update({"schema_version": 1, "repo_id": repo_id, "scan_job_id": job_id,
                             "status": "cancelling", "message": message, "eta_seconds": None})
            output.update({"evidence_status": "incomplete", "progress": progress,
                           "cancellation": {"status": "cleanup_pending", "message": message,
                                            "source_artifacts": "retained"}})
            job.control, job.output, job.progress_json = "cancel", json.dumps(output), json.dumps(progress)
            db.commit()
    except Exception:
        logger.exception("Could not checkpoint cancellation for audit %s; ownership retained until worker cleanup", job_id)
        return False
    if main_loop and not main_loop.is_closed():
        _push_to_main_stream(main_loop, repo_id, message, "warning")
    return True


class ReplayBindingInvalid(RuntimeError):
    """A persisted replay cannot run until its immutable binding is repaired."""
    retired = False


def _retire_invalid_queued_replay(db_factory, repo_cls, scan_job_cls, repo_id, job_id, error):
    """Reject permanent binding errors without touching admitted/running work."""
    with db_factory() as db:
        job, repo = _worker_terminal_rows(db, repo_cls, scan_job_cls, repo_id, job_id, None)
        if job is None or job.status != "queued":
            db.rollback()
            return False
        output = _load_job_output(job.output)
        output.update({"error": str(error), "terminal_reason": "invalid-replay-source-binding",
                       "evidence_status": "incomplete", "worker_started": False})
        retired = db.query(scan_job_cls).filter(
            scan_job_cls.id == int(job_id), scan_job_cls.repo_id == int(repo_id),
            scan_job_cls.status == "queued", scan_job_cls.control == job.control,
            scan_job_cls.lease_token == job.lease_token,
        ).update({"status": "failed", "finished_at": datetime.utcnow(), "output": json.dumps(output)},
                 synchronize_session=False)
        if not retired:
            db.rollback()
            return False
        if repo is not None:
            repo.status = "failed"
        db.commit()
        return True


def _restore_submission_source(
    db_factory: Callable, scan_job_cls: type, repo_id: int, job_id: int,
    source_override: Optional[str], target_identity_override: Optional[Dict[str, Any]],
    replay_of_job_id: Optional[int],
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Restore a durable source binding before admitting any executor work."""
    db = db_factory()
    try:
        job = db.query(scan_job_cls).filter(
            scan_job_cls.id == int(job_id), scan_job_cls.repo_id == int(repo_id),
        ).first()
        if job is None:
            raise RuntimeError("Reserved audit source binding is no longer available")
        path = str(getattr(job, "replay_snapshot_path", "") or "").strip()
        raw = getattr(job, "replay_target_identity_json", "") or "{}"
        try:
            identity = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise ReplayBindingInvalid("Persisted audit source identity is malformed; dispatch refused") from exc
        if not isinstance(identity, dict):
            raise ReplayBindingInvalid("Persisted audit source identity must be an object; dispatch refused")
        if getattr(job, "replay_of_job_id", None) is not None or replay_of_job_id is not None:
            if not path or not isinstance(identity.get("target_tree_hash"), str) or not identity["target_tree_hash"].strip():
                raise ReplayBindingInvalid("Immutable replay requires its persisted snapshot path and tree identity; dispatch refused")
            # The stored replay binding is authoritative across restarts and
            # duplicate submissions. Never substitute the moving repo source.
            return path, identity
        return source_override if source_override is not None else path or None, (
            target_identity_override if target_identity_override is not None else identity or None
        )
    finally:
        db.close()


def submit_scan(
    repo_id: int,
    db_factory: Callable,
    repo_cls: type,
    finding_cls: type,
    scan_job_cls: type,
    notify: Optional[Callable] = None,
    cvss_threshold: float = 7.0,
    existing_job_id: Optional[int] = None,
    source_override: Optional[str] = None,
    target_identity_override: Optional[Dict[str, Any]] = None,
    replay_of_job_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Submit a scan to the worker pool. Returns immediately  - non-blocking.

    Durable queue: a ScanJob row is persisted with status 'queued' at enqueue time (unless
    ``existing_job_id`` is re-dispatching one after a restart), so the enqueue survives a
    crash/restart and can be reconciled. The scan runs in a background thread; progress is
    streamed via SSE.
    """
    # Platform resets establish a closed admission window before draining
    # workers.  Check it here as well as in the HTTP middleware because scans
    # can be submitted by continuous-coverage schedulers or SDK callers that
    # bypass HTTP entirely.
    try:
        from backend.main import _PLATFORM_RESET_IN_PROGRESS
        from backend import reset_queue
        if _PLATFORM_RESET_IN_PROGRESS.is_set() or reset_queue.pending():
            return {
                "repo_id": repo_id,
                "status": "resetting",
                "message": "platform reset in progress; retry after it completes",
            }
    except Exception:
        # Import cycles during very early startup should not prevent normal
        # scans; the HTTP-level guard still protects API requests.
        pass

    # Every producer, including continuous scans and direct SDK submission,
    # must pass the same saved-model verification gate before reserving work.
    from backend.main import Settings
    from backend.ai_readiness import require_ready
    readiness_db = db_factory()
    try:
        settings = readiness_db.query(Settings).first()
        require_ready(settings)
        from backend.audit_depth import admitted_depth
        submission_depth = admitted_depth(settings)
    finally:
        readiness_db.close()
    # ``shutdown()`` closes the current executor as part of an application
    # restart.  The next accepted submission owns creation of the fresh pool;
    # clear this process-local gate before admission so recovery/test doubles
    # cannot strand durable queued rows behind a stale stopping bit.
    _scheduler_stopping.clear()
    from backend.pipeline import STREAM_QUEUES

    # SSE queues belong to the API loop.  Resolve that owner before reserving
    # capacity so a caller without any usable loop cannot leave a phantom
    # admission behind.  Normal FastAPI, startup-recovery, and continuous
    # coverage calls all execute on the application loop.
    try:
        submission_loop = asyncio.get_running_loop()
    except RuntimeError:
        try:
            submission_loop = asyncio.get_event_loop()
        except RuntimeError as exc:
            if _shared_profile_requires_durable_lease():
                raise RuntimeError(
                    "durable scan job could not be created: scan submission requires an application event loop"
                ) from exc
            raise RuntimeError("scan submission requires an application event loop") from exc
    if submission_loop.is_closed():
        if _shared_profile_requires_durable_lease():
            raise RuntimeError(
                "durable scan job could not be created: scan submission event loop is closed"
            )
        raise RuntimeError("scan submission event loop is closed")

    # Atomically check-and-reserve both the per-repository identity and one
    # bounded scheduler slot.  ThreadPoolExecutor's private queue is unbounded;
    # admitting into it directly made bursts consume arbitrary memory and hid
    # when work could actually start.
    worker_limit = _effective_worker_limit()
    with _scan_lock:
        # Reset may be queued while readiness/database checks above finish.
        # Recheck at the atomic reservation boundary so it cannot miss a late
        # worker that passed the initial maintenance check.
        from backend import reset_queue
        if _PLATFORM_RESET_IN_PROGRESS.is_set() or reset_queue.pending():
            return {"repo_id": repo_id, "status": "resetting",
                    "message": "platform reset queued; no audit worker was admitted"}
        if repo_id in _active_scans:
            # Callers that already reserved a durable job (notably atomic
            # enrollment and restart recovery) must still receive its exact
            # identity when a same-process worker won the race to dispatch.
            # Omitting it made a healthy audit look like an admission failure.
            return {
                "repo_id": repo_id,
                "status": "already_running",
                "job_id": int(existing_job_id) if existing_job_id is not None else None,
            }
        capacity = _scheduler_status_locked(worker_limit, repo_id)
        if int(capacity["active_scans"]) >= int(capacity["admission_capacity"]):
            return {
                **capacity,
                "repo_id": int(repo_id),
                "status": "queue_full",
                "job_id": int(existing_job_id) if existing_job_id is not None else None,
                "retry_after_seconds": 5,
                "message": (
                    "Audit admission is temporarily full; no executor future was created. "
                    "Retry after a running audit completes."
                ),
            }
        _active_scans[repo_id] = "admitting"

    lease_token = None
    try:
        # Persist the queued job (durable) unless we're re-dispatching an existing one.
        job_id = existing_job_id
        existing_active_state = ""
        if job_id is None:
            try:
                _db = db_factory()
                try:
                    # Reuse a previously admitted *queued* job rather than
                    # manufacturing another row every time a browser retries.
                    # If it has already become running/paused, let its owner
                    # continue; a fresh lease must not be stolen at enqueue.
                    _active = (
                        _db.query(scan_job_cls)
                        .filter(
                            scan_job_cls.repo_id == int(repo_id),
                            scan_job_cls.status.in_(["queued", "running", "paused"]),
                        )
                        .order_by(scan_job_cls.id.desc())
                        .first()
                    )
                    if _active is not None:
                        job_id = int(_active.id)
                        existing_active_state = str(getattr(_active, "status", "") or "")
                    else:
                        _job = scan_job_cls(repo_id=repo_id, status="queued", started_at=datetime.utcnow(), audit_depth=submission_depth)
                        if replay_of_job_id is not None:
                            _job.replay_of_job_id = int(replay_of_job_id)
                        if source_override:
                            _job.replay_snapshot_path = str(source_override)
                        if target_identity_override:
                            _job.replay_target_identity_json = json.dumps(target_identity_override, sort_keys=True)
                        _db.add(_job)
                        _db.commit()
                        _db.refresh(_job)
                        job_id = _job.id
                finally:
                    _db.close()
            except Exception as exc:
                # A network/shared deployment must never run an untracked scan:
                # without a durable job there is no lease, progress replay, or
                # audit trail to prevent duplicate proof work. Keep the
                # untracked fallback only for explicitly single-user local
                # harnesses and unit tests.
                from backend.deploy_profile import allow_unsafe, current_profile
                if current_profile() in ("team", "enterprise") and not allow_unsafe():
                    raise RuntimeError(f"durable scan job could not be created: {exc}") from exc
                logger.warning("Durable scan job unavailable for local run: %s", exc)
                job_id = None  # scan_repo may create a best-effort local row
        else:
            # A caller that claims it has already reserved a job must prove it
            # belongs to this repository and is still active.  Otherwise a
            # stale/mistyped id could dispatch an untracked scan or attach a
            # fresh run to historical evidence.
            _db = db_factory()
            try:
                _existing = (
                    _db.query(scan_job_cls)
                    .filter(
                        scan_job_cls.id == int(job_id),
                        scan_job_cls.repo_id == int(repo_id),
                    )
                    .first()
                )
                if _existing is None:
                    raise RuntimeError(
                        f"durable scan job {job_id} is not reserved for repository {repo_id}"
                    )
                if str(getattr(_existing, "status", "") or "") not in ("queued", "running", "paused"):
                    raise RuntimeError(
                        f"durable scan job {job_id} is not active "
                        f"(status={getattr(_existing, 'status', '')!s})"
                    )
            finally:
                _db.close()

        if job_id is not None:
            with db_factory() as cancel_db:
                cancel_row = cancel_db.query(scan_job_cls).filter(scan_job_cls.id == int(job_id)).first()
                if cancel_row is not None and str(cancel_row.control or "") == "cancel":
                    with _scan_lock:
                        _active_scans.pop(repo_id, None)
                    return {"repo_id": repo_id, "job_id": int(job_id), "status": "cancelling",
                            "message": "Cancellation is pending; this audit will not be restarted"}

        if existing_active_state in ("running", "paused"):
            with _scan_lock:
                _active_scans.pop(repo_id, None)
            return {"repo_id": repo_id, "status": "already_running", "job_id": job_id}

        _remember_scheduler_context(
            db_factory, repo_cls, finding_cls, scan_job_cls, notify, cvss_threshold,
        )

        # Startup reconciliation re-dispatches an existing row.  Restore its
        # replay binding before launching so a restart cannot silently switch
        # an immutable replay back to the moving branch.
        if job_id is not None:
            source_override, target_identity_override = _restore_submission_source(
                db_factory, scan_job_cls, repo_id, job_id,
                source_override, target_identity_override, replay_of_job_id,
            )

        # Do not acquire the expiring repository lease yet.  An executor queue
        # can be legitimately backlogged longer than a lease TTL; the worker
        # claims it immediately before it starts ``scan_repo`` instead.  If two
        # replicas dispatch the same queued row, that start-time claim lets one
        # run and closes the duplicate without duplicate scanner/lab work.

        # Create SSE queue on the MAIN event loop BEFORE launching worker thread.
        # The worker pushes messages here via call_soon_threadsafe.
        # The SSE handler reads from here on the main loop.
        if repo_id not in STREAM_QUEUES:
            from backend.pipeline import STREAM_QUEUE_MAX
            STREAM_QUEUES[repo_id] = asyncio.Queue(maxsize=STREAM_QUEUE_MAX)
        else:
            # A completed run can leave a terminal event buffered when nobody was
            # connected.  Drain it before dispatching a new run; durable history
            # is kept on ScanJob.output and must not be replayed as live work.
            _queue = STREAM_QUEUES[repo_id]
            while True:
                try:
                    _queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

        main_loop = submission_loop
        if main_loop.is_running():
            global _scheduler_main_loop
            _scheduler_main_loop = main_loop

        # Record the loop that OWNS this queue so pipeline._send bridges worker-thread
        # enqueues onto it via call_soon_threadsafe (never mutating the queue cross-loop).
        from backend import pipeline as _pipeline
        _pipeline.register_stream_loop(repo_id, main_loop)

        with _scan_lock:
            # Keep insertion order as the process-local FIFO order exposed by
            # ``queue_position``.  The worker changes this exact entry to
            # ``running`` as soon as its executor slot begins.
            if repo_id not in _active_scans:
                raise RuntimeError("scan admission reservation disappeared before dispatch")
            _active_scans[repo_id] = "queued"
        submitted_future = _get_executor().submit(
            _run_scan_in_thread,
            repo_id, db_factory, repo_cls, finding_cls, scan_job_cls,
            notify, cvss_threshold, main_loop, job_id,
            None,
            source_override,
            target_identity_override,
        )
        with _scan_lock:
            # A tiny audit can finish before submit() returns its Future.
            # Never recreate a reservation which the worker already released.
            if repo_id in _active_scans and callable(getattr(submitted_future, "cancel", None)):
                _scan_futures[int(repo_id)] = submitted_future
    except Exception as exc:
        # Dispatch failed before the worker took ownership - release the reservation so
        # the repo isn't permanently stuck as "already_running".
        if isinstance(exc, ReplayBindingInvalid) and job_id is not None:
            try:
                exc.retired = _retire_invalid_queued_replay(db_factory, repo_cls, scan_job_cls, repo_id, job_id, exc)
            except Exception:
                logger.exception("Could not persist invalid replay rejection for repository %s", repo_id)
        with _scan_lock:
            _active_scans.pop(repo_id, None)
        _release_lease(db_factory, scan_job_cls, repo_id, job_id if 'job_id' in locals() else None, lease_token)
        raise

    queue_state = scheduler_status(repo_id)
    return {
        **queue_state,
        "repo_id": repo_id,
        "status": "queued",
        "job_id": job_id,
    }


def _drain_durable_backlog(
    context: Tuple[Callable, type, type, type, Optional[Callable], float]
) -> None:
    """Fill newly available local slots from the oldest durable queued rows.

    A previous release could have persisted more queued rows than the current
    bounded waiting room, and a crash can happen after the database commit but
    before executor dispatch.  Those rows remain the source of truth.  This
    pump runs after each completion and on startup, skips jobs with a live
    lease on another process, and routes every admission through
    ``submit_scan`` so the same cap and duplicate protection apply.
    """
    db_factory, repo_cls, finding_cls, scan_job_cls, notify, cvss_threshold = context
    try:
        while not _scheduler_stopping.is_set():
            if scheduler_status().get("available_slots", 0) <= 0:
                return
            db = db_factory()
            try:
                live_job_ids = set()
                try:
                    from backend.main import ScanLease
                    now = datetime.utcnow()
                    live_job_ids = {
                        int(row.job_id) for row in db.query(ScanLease).filter(ScanLease.expires_at > now).all()
                    }
                except Exception:
                    # Failing to inspect leases must not make the dispatcher
                    # steal work.  ``submit_scan`` still has a start-time
                    # fenced lease claim, so continue conservatively.
                    live_job_ids = set()
                rows = (
                    db.query(scan_job_cls)
                    .filter(scan_job_cls.status == "queued")
                    .order_by(scan_job_cls.id.asc())
                    .limit(200)
                    .all()
                )
                candidates = [
                    (int(row.id), int(row.repo_id))
                    for row in rows
                    if int(row.id) not in live_job_ids and str(row.control or "") not in {"cancel", "pause"}
                ]
            finally:
                db.close()

            progressed = False
            for job_id, repo_id in candidates:
                if is_scan_running(repo_id):
                    continue
                try:
                    result = _submit_durable_from_drain(
                        repo_id, job_id, db_factory, repo_cls, finding_cls,
                        scan_job_cls, notify, cvss_threshold,
                    )
                except ReplayBindingInvalid as exc:
                    # A permanently rejected replay must not strand later
                    # valid audits, even when it occupied the oldest batch.
                    progressed = progressed or exc.retired
                    continue
                state = str((result or {}).get("status") or "")
                if state == "queued":
                    progressed = True
                    break
                if state in {"queue_full", "resetting"}:
                    return
            if not progressed:
                return
    except Exception:
        logger.debug("Durable queue drain failed; queued rows remain recoverable", exc_info=True)
    finally:
        try:
            _scheduler_drain_lock.release()
        except RuntimeError:
            pass


def _submit_durable_from_drain(
    repo_id: int,
    job_id: int,
    db_factory: Callable,
    repo_cls: type,
    finding_cls: type,
    scan_job_cls: type,
    notify: Optional[Callable],
    cvss_threshold: float,
) -> Dict[str, Any]:
    """Marshal a completion-triggered dispatch back onto the SSE owner loop."""
    loop = _scheduler_main_loop
    if loop is None or loop.is_closed() or not loop.is_running():
        return {
            "status": "deferred",
            "repo_id": int(repo_id),
            "job_id": int(job_id),
            "message": "application event loop is unavailable; durable job remains queued",
        }
    finished = threading.Event()
    outcome: Dict[str, Any] = {}

    def _dispatch() -> None:
        try:
            outcome["result"] = submit_scan(
                repo_id, db_factory, repo_cls, finding_cls, scan_job_cls,
                notify, cvss_threshold, existing_job_id=job_id,
            )
        except Exception as exc:
            outcome["error"] = exc
        finally:
            finished.set()

    try:
        loop.call_soon_threadsafe(_dispatch)
    except RuntimeError:
        return {"status": "deferred", "repo_id": int(repo_id), "job_id": int(job_id)}
    if not finished.wait(timeout=15.0):
        return {
            "status": "deferred",
            "repo_id": int(repo_id),
            "job_id": int(job_id),
            "message": "application loop did not accept durable dispatch before timeout",
        }
    if "error" in outcome:
        raise outcome["error"]
    result = outcome.get("result")
    return result if isinstance(result, dict) else {"status": "deferred"}


def _request_durable_backlog_drain() -> bool:
    """Start at most one non-blocking durable queue pump."""
    context = _scheduler_context
    if context is None or _scheduler_stopping.is_set():
        return False
    if not _scheduler_drain_lock.acquire(blocking=False):
        return False
    try:
        thread = threading.Thread(
            target=_drain_durable_backlog,
            args=(context,),
            name="lotus-durable-queue",
            daemon=True,
        )
        thread.start()
        return True
    except Exception:
        _scheduler_drain_lock.release()
        raise


def _process_identity(pid: int) -> Optional[Dict[str, Any]]:
    """Read Linux process incarnation; unavailable evidence never retires a lease.

    Read stat twice around the boot metadata so PID replacement during this
    observation cannot combine one process's start time with another's identity.
    The parenthesized comm field may itself contain spaces or parentheses.
    """
    from pathlib import Path
    try:
        stat_path = Path(f"/proc/{pid}/stat")
        def start_ticks():
            raw = stat_path.read_text()
            prefix, _, fields = raw.rpartition(") ")
            if not prefix.startswith(f"{pid} ("):
                raise ValueError("Unexpected process stat identity")
            return int(fields.split()[19])  # Linux stat field 22; fields begin at 3.
        started = start_ticks()
        boot = str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))
        boot_time = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines()
                         if line.startswith("btime "))
        ticks_per_second = int(os.sysconf("SC_CLK_TCK"))
        if started <= 0 or ticks_per_second <= 0 or boot_time <= 0 or start_ticks() != started:
            return None
        return {"boot_id": boot, "start_ticks": started,
                "started_at": datetime.fromtimestamp(boot_time + started / ticks_per_second, timezone.utc)}
    except (OSError, ValueError, IndexError, StopIteration, OverflowError):
        return None


def _new_lease_owner() -> str:
    owner = f"{socket.gethostname()}:{os.getpid()}:{threading.current_thread().name}"
    identity = _process_identity(os.getpid())
    if identity:
        owner += f"|lotus-v2={identity['boot_id']}/{identity['start_ticks']}"
    return owner


def _lease_owner_is_definitively_dead(owner: Any, heartbeat_at: Optional[datetime] = None) -> bool:
    """Retire only a missing PID or a proven different local process incarnation.

    Cross-host ownership and unavailable process metadata remain unknown. New
    leases bind boot ID and Linux process start ticks. Legacy leases may be
    recovered when their last heartbeat predates the current PID's creation by
    more than five seconds, accommodating timestamp precision/clock jitter.
    """
    try:
        host, pid_text, thread = str(owner or "").rsplit(":", 2)
        pid = int(pid_text)
    except (TypeError, ValueError):
        return False
    if host != socket.gethostname() or pid <= 0 or not thread:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    except OSError as exc:
        return getattr(exc, "errno", None) == errno.ESRCH
    identity = _process_identity(pid)
    if not identity:
        return False
    if "|lotus-v2=" in thread:
        try:
            boot, ticks = thread.rsplit("|lotus-v2=", 1)[1].split("/")
            boot, ticks = str(uuid.UUID(boot)), int(ticks)
            if ticks <= 0:
                return False
        except (TypeError, ValueError):
            return False
        return boot != identity["boot_id"] or ticks != identity["start_ticks"]
    if not isinstance(heartbeat_at, datetime):
        return False
    heartbeat = heartbeat_at.replace(tzinfo=timezone.utc) if heartbeat_at.tzinfo is None else heartbeat_at
    return heartbeat < identity["started_at"] - timedelta(seconds=5)


def _annotate_recovered_interruption(job: Any, reason: str, now: datetime) -> None:
    """Mark a crash-recovered job incomplete without replacing prior evidence."""
    output = _load_job_output(getattr(job, "output", ""))
    output["evidence_status"] = "incomplete"
    output["recovery"] = {
        "status": "interrupted",
        "reason": reason,
        "recovered_at": now.isoformat(),
    }
    try:
        progress = json.loads(getattr(job, "progress_json", "") or "{}")
    except Exception:
        progress = {}
    if isinstance(progress, dict) and progress:
        mapped = progress.get("coverage_map") or output.get("coverage_map")
        if isinstance(mapped, dict):
            from backend.coverage_mapper import update_coverage_map
            mapped = update_coverage_map(mapped, finalized=True)
            progress["coverage_map"] = mapped
            output["coverage_map"] = mapped
        progress.update({
            "status": "interrupted",
            "message": reason,
            "eta_seconds": 0,
            "evidence_status": "incomplete",
        })
        output["progress"] = progress
        _apply_progress_to_job(job, progress)
    job.output = json.dumps(output)


def _recover_repository(db_factory: Callable, repo_cls: type, scan_job_cls: type,
                        repo_id: int) -> Dict[str, Any]:
    """Reconcile one owner under the same repository fence as lease claims."""
    from backend.main import ScanLease
    result: Dict[str, Any] = {"interrupted": 0, "active_leases": 0, "cancellations": []}
    with _scan_lock:
        if repo_id in _active_scans:
            return result
    db = db_factory()
    try:
        # Claims lock the repository before the job/lease. A no-op UPDATE also
        # establishes this fence on SQLite, where FOR UPDATE is ignored. Read
        # ownership only after acquiring it, so a newly claimed worker cannot
        # be interrupted using an earlier recovery snapshot.
        fenced = db.query(repo_cls).filter(repo_cls.id == repo_id).update(
            {"status": repo_cls.status}, synchronize_session=False,
        )
        if not fenced:
            db.rollback()
            return result
        with _scan_lock:
            if repo_id in _active_scans:
                db.rollback()
                return result
        now = datetime.utcnow()
        repo = db.query(repo_cls).filter(repo_cls.id == repo_id).first()
        lease = db.query(ScanLease).filter(ScanLease.repo_id == repo_id).first()
        if lease is not None:
            expired = not lease.expires_at or lease.expires_at <= now
            dead_owner = not expired and _lease_owner_is_definitively_dead(lease.owner, heartbeat_at=lease.heartbeat_at)
            if not expired and not dead_owner:
                result["active_leases"] = 1
                db.rollback()
                return result
            # Heartbeats do not need the repository fence. Compare the exact
            # observed token and expiry so a concurrent renewal wins safely.
            retired = db.query(ScanLease).filter(
                ScanLease.repo_id == repo_id,
                ScanLease.lease_token == lease.lease_token,
                ScanLease.owner == lease.owner,
                ScanLease.expires_at == lease.expires_at,
            ).delete(synchronize_session=False)
            if not retired:
                db.rollback()
                return result
            mirrored = db.query(scan_job_cls).filter(
                scan_job_cls.id == lease.job_id, scan_job_cls.repo_id == repo_id,
            ).first()
            if (mirrored is not None and mirrored.lease_token == lease.lease_token
                    and mirrored.lease_owner == lease.owner
                    and (dead_owner or not mirrored.lease_expires_at or mirrored.lease_expires_at <= now)):
                mirrored.lease_token, mirrored.lease_owner = "", ""
                mirrored.lease_expires_at, mirrored.heartbeat_at = None, None
            db.flush()
        jobs = db.query(scan_job_cls).filter(
            scan_job_cls.repo_id == repo_id,
            scan_job_cls.status.in_(["queued", "running", "paused"]),
        ).all()
        retain_repo = False
        recovered_pause = False
        for job in jobs:
            # Retain a conflicting, still-valid mirrored owner as well. This
            # is conservative when old/partially migrated data is inconsistent.
            if job.lease_owner and job.lease_expires_at and job.lease_expires_at > now:
                retain_repo = True
                continue
            if str(job.control or "") == "cancel":
                result["cancellations"].append((job.id, repo_id))
                retain_repo = True
                continue
            if str(job.control or "") == "pause":
                # Restore resumable state without removing the user's pause.
                # Startup and backlog recovery must not dispatch a paused
                # worker or change its start time. Resume is an explicit action.
                job.status = "paused"
                recovered_pause = True
            elif job.status == "queued":
                retain_repo = True
                continue
            else:
                job.status = "interrupted"
                job.finished_at = now
                _annotate_recovered_interruption(
                    job,
                    "Audit worker lease expired or its owner stopped; partial artifacts were preserved. Retry explicitly to continue.",
                    now,
                )
                result["interrupted"] += 1
            job.lease_token, job.lease_owner = "", ""
            job.lease_expires_at, job.heartbeat_at = None, None
        if not retain_repo and repo.status in {"cloning", "lab", "recon", "scanning"}:
            repo.status = "paused" if recovered_pause else "interrupted"
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def reconcile_on_startup(db_factory: Callable, repo_cls: type, finding_cls: type,
                         scan_job_cls: type, notify: Optional[Callable] = None,
                         cvss_threshold: float = 7.0, *, resume_queued: bool = True) -> Dict[str, int]:
    """Recover dead workers; only the startup pass also resumes durable queues.

    Unexpired owners are retained even when this process has no local worker.
    Periodic passes revisit them after expiry without starting another audit.
    Paused work remains paused during both startup and periodic recovery.
    """
    result = {"interrupted": 0, "requeued": 0, "active_leases": 0, "cancelled": 0, "cleanup_pending": 0}
    try:
        from backend.main import ScanLease
        db = db_factory()
        try:
            repo_ids = {int(row[0]) for row in db.query(ScanLease.repo_id).all()}
            repo_ids.update(int(row[0]) for row in db.query(scan_job_cls.repo_id).filter(
                scan_job_cls.status.in_(["running", "paused"]),
            ).all())
            repo_ids.update(int(row[0]) for row in db.query(scan_job_cls.repo_id).filter(
                scan_job_cls.status == "queued", scan_job_cls.control.in_(["cancel", "pause"]),
            ).all())
            repo_ids.update(int(row[0]) for row in db.query(repo_cls.id).filter(
                repo_cls.status.in_(["cloning", "lab", "recon", "scanning"]),
            ).all())
        finally:
            db.close()
        cancellation_ids = []
        for rid in sorted(repo_ids):
            try:
                recovered = _recover_repository(db_factory, repo_cls, scan_job_cls, rid)
                result["interrupted"] += recovered["interrupted"]
                result["active_leases"] += recovered["active_leases"]
                cancellation_ids.extend(recovered["cancellations"])
            except Exception as exc:
                logger.warning("Scan recovery for repository %s could not complete (%s); retained state will be retried", rid, type(exc).__name__)
        from backend.audit_cancellation import finish_without_runtime, schedule_runtime_cleanup
        for job_id, rid in cancellation_ids:
            if finish_without_runtime(rid, job_id, db_factory=db_factory):
                result["cancelled"] += 1
            else:
                schedule_runtime_cleanup(rid, job_id, db_factory=db_factory)
                result["cleanup_pending"] += 1
        if resume_queued:
            db = db_factory()
            try:
                # A job can still be queued between its lease claim and the
                # first pipeline checkpoint. Never dispatch its current owner.
                leased_ids = {int(row[0]) for row in db.query(ScanLease.job_id).all()}
                queued_ids = [(j.id, j.repo_id) for j in db.query(scan_job_cls).filter(
                    scan_job_cls.status == "queued",
                ).all() if j.id not in leased_ids and str(j.control or "") not in {"cancel", "pause"}
                    and not (j.lease_owner and j.lease_expires_at and j.lease_expires_at > datetime.utcnow())]
            finally:
                db.close()
            for job_id, rid in queued_ids:
                try:
                    dispatched = submit_scan(rid, db_factory, repo_cls, finding_cls, scan_job_cls,
                                             notify, cvss_threshold, existing_job_id=job_id)
                    if isinstance(dispatched, dict) and dispatched.get("status") == "queued":
                        result["requeued"] += 1
                except Exception:
                    continue
    except Exception as exc:
        logger.warning("Scan queue recovery could not complete (%s); retained state will be retried", type(exc).__name__)
    return result


async def monitor_recovery(db_factory: Callable, repo_cls: type, finding_cls: type,
                           scan_job_cls: type, *, interval_seconds: float = 30.0) -> None:
    """Recheck owners retained at startup after their leases can expire.

    A container restart can reuse a PID, and a rolling restart can observe a
    different host's still-valid lease. A single startup pass cannot declare
    either owner dead. Later passes preserve live/renewed owners and partial
    evidence, but never dispatch queued work or restart a paid audit.
    """
    while True:
        await asyncio.sleep(interval_seconds)
        result = await asyncio.to_thread(
            reconcile_on_startup, db_factory, repo_cls, finding_cls, scan_job_cls,
            resume_queued=False,
        )
        if result.get("interrupted"):
            logger.warning("Recovered %s interrupted audit worker(s); partial evidence preserved, explicit retry required", result["interrupted"])


def active_scan_count() -> int:
    """Number of locally admitted scans (running plus bounded waiting)."""
    with _scan_lock:
        return len(_active_scans)


def running_scan_count() -> int:
    """Number of executor workers that have actually begun an audit."""
    return int(scheduler_status().get("running_scans", 0) or 0)


def is_scan_running(repo_id: int) -> bool:
    with _scan_lock:
        return repo_id in _active_scans


def shutdown():
    global _executor, _scheduler_context, _scheduler_main_loop
    _scheduler_stopping.set()
    if _executor:
        _executor.shutdown(wait=False, cancel_futures=True)
        _executor = None
    # Futures cancelled while still in ThreadPoolExecutor's private queue will
    # never enter ``_run_scan_in_thread`` and therefore cannot clear their own
    # reservations.  Leave their durable ScanJob rows queued for next-start
    # reconciliation, but release the process-local accounting immediately.
    with _scan_lock:
        for repo_id, state in list(_active_scans.items()):
            if str(state or "").lower() in {"queued", "admitting"}:
                _active_scans.pop(repo_id, None)
                _scan_started_monotonic.pop(repo_id, None)
                _scan_futures.pop(repo_id, None)
    _scheduler_context = None
    _scheduler_main_loop = None
