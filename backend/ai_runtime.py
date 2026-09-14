"""Pause an exact active audit when its required model becomes unavailable."""
from __future__ import annotations

import asyncio
from concurrent.futures import Future, TimeoutError as FutureTimeout
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import hashlib
import uuid
from time import monotonic
from threading import Event

from backend.ai_gateway import AIResult, AIStatus, AITask
from backend.ai_readiness import (
    AIRequiredError, fingerprint, invalidate, readiness, receipts, role_settings,
)


@dataclass
class AuditAIContext:
    repo_id: int
    job_id: int
    db_factory: object
    loop: object
    active: bool = True
    pause_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    calls: list = field(default_factory=list)
    lease_identity: tuple | None = None


_AUDIT: ContextVar[AuditAIContext | None] = ContextVar("lotus_audit_ai", default=None)


def bind_audit(repo_id, job_id, db_factory):
    from backend.main import ScanJob
    context = AuditAIContext(repo_id, job_id, db_factory, asyncio.get_running_loop())
    db = db_factory()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.repo_id == repo_id).first()
        if job is not None:
            context.lease_identity = (job.lease_token, job.lease_owner)
    finally:
        db.close()
    return _AUDIT.set(context)


def unbind_audit(token):
    context = _AUDIT.get()
    if context is not None:
        context.active = False
    _AUDIT.reset(token)


def audit_provenance():
    context = _AUDIT.get()
    return list(context.calls) if context is not None else []


def active_audit_context():
    context = _AUDIT.get()
    return context if context is not None and context.active else None


def _require_role_task(role, task):
    """Keep the secondary model out of planning, building and other work."""
    if role not in {"primary", "judge"}:
        raise ValueError("Unknown AI role")
    if task == AITask.MODEL_VERIFICATION:
        if _AUDIT.get() is not None:
            raise ValueError("Model verification is only available outside an audit through Settings")
        return
    if role == "judge" and task != AITask.INDEPENDENT_REVIEW:
        raise ValueError("The secondary model is reserved for findings and scoring review during triage")


def _role_readiness(settings, role):
    return readiness(settings) if role == "primary" else readiness(settings, role=role)


def _resume_role_ready(settings, role):
    state = _role_readiness(settings, role)
    # Disabling the optional findings reviewer is an explicit way to skip it.
    # Keep the platform restart barrier and the existing explicit-resume gate.
    return state["ready"] or (role == "judge" and not getattr(settings, "ai_judge_enabled", False)
                              and not state.get("restart_required", False))


async def request_model(prompt, *, role="primary", task=AITask.LAB_BUILD, timeout=120):
    """Adapter-facing model request using the current verified audit role.

    Strict adapter consumers validate LAB_BUILD's typed output quality before
    parsing. The secondary ("judge") role is reserved for findings review
    during triage; all other audit tasks are refused. Cancellation
    drains the owned bounded transport before returning.
    """
    _require_role_task(role, task)
    context = active_audit_context()
    if context is None:
        raise AIRequiredError("Model requests require an active, exact-audit context")
    settings = _load(context)
    selected = role_settings(settings, role)
    if role == "judge" and not getattr(settings, "ai_judge_enabled", False):
        return None
    from backend.main import call_ai_result
    from backend.ai_gateway import independent_review_transport
    from threading import Event
    options = {}
    stop = Event()
    with independent_review_transport(stop):
        work = asyncio.create_task(asyncio.to_thread(call_ai_result, prompt, selected, timeout=timeout, task=task, **options))
        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError:
            stop.set()
            while not work.done():
                try:
                    await asyncio.shield(work)
                except asyncio.CancelledError:
                    continue
                except BaseException:
                    break
            if work.done() and not work.cancelled():
                try:
                    work.result()
                except BaseException:
                    pass
            raise
        except AIRequiredError:
            if role == "judge" and not getattr(_load(context), "ai_judge_enabled", False):
                return None
            raise


def _load(context):
    from backend.main import Settings
    db = context.db_factory()
    try:
        settings = db.query(Settings).first()
        if settings is not None:
            db.expunge(settings)
        return settings
    finally:
        db.close()


def _await_on_audit(context, coroutine, *, stop_event=None):
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None
    if current_loop is context.loop:
        coroutine.close()
        raise AIRequiredError("Required AI calls must run off the audit event loop so Settings recovery remains responsive")
    # Cancelling run_coroutine_threadsafe's proxy future acknowledges too early:
    # the real task can still be unwinding. Complete this proxy only after the
    # owned task (including its async finally blocks) has actually finished.
    future, cancel_requested, owned = Future(), Event(), {}
    def start():
        task = context.loop.create_task(coroutine)
        owned["task"] = task
        def completed(task):
            try:
                future.set_result(task.result())
            except BaseException as error:
                future.set_exception(error)
        task.add_done_callback(completed)
        if cancel_requested.is_set():
            task.cancel()
    def cancel():
        task = owned.get("task")
        if task is not None:
            task.cancel()
    try:
        context.loop.call_soon_threadsafe(start)
    except RuntimeError:
        coroutine.close()
        raise asyncio.CancelledError()
    while context.active and not context.loop.is_closed():
        if stop_event is not None and stop_event.is_set():
            break
        try:
            return future.result(timeout=.1 if stop_event is not None else 1)
        except FutureTimeout:
            if future.done():
                # FutureTimeout aliases built-in TimeoutError on Python 3.11+.
                # A completed child's own error is not a polling timeout.
                return future.result()
            continue
    cancel_requested.set()
    if not context.loop.is_closed():
        context.loop.call_soon_threadsafe(cancel)
    while not future.done() and context.loop.is_running():
        try:
            future.result(timeout=.1)
        except FutureTimeout:
            continue
        except BaseException:
            break
    raise asyncio.CancelledError()


async def _wait_for_review_control(context):
    """Honor Stop between model calls, fenced to the originally admitted audit."""
    while context.active:
        db = context.db_factory()
        try:
            job = _owned_ai_job(db, context, metadata_only=True)
            if job.control != "pause":
                return
        finally:
            db.close()
        await asyncio.sleep(.1)
    raise asyncio.CancelledError()


def _original_lease(context):
    from backend.scan_worker import ScanCancelled
    identity = context.lease_identity
    if identity is None:
        raise ScanCancelled()
    # The scan pipeline captures its admitted lease from the original job row
    # before any awaited work. Prefer it if binding raced a replacement owner.
    if hasattr(context, "recovery_lease_token"):
        admitted = (context.recovery_lease_token, context.recovery_lease_owner)
        if tuple(value or "" for value in identity) != admitted:
            return admitted
    return identity


def _owned_ai_job(db, context, *, metadata_only=False):
    from backend.main import ScanJob
    from backend.scan_worker import ScanCancelled
    query = db.query(ScanJob)
    if metadata_only:
        from sqlalchemy.orm import load_only
        query = query.options(load_only(ScanJob.id, ScanJob.repo_id, ScanJob.status, ScanJob.control,
            ScanJob.lease_token, ScanJob.lease_owner, ScanJob.lease_expires_at, raiseload=True))
    job = query.filter(ScanJob.id == context.job_id, ScanJob.repo_id == context.repo_id).first()
    identity = _original_lease(context)
    if (not context.active or job is None or job.status not in {"queued", "running", "paused"}
            or job.control == "cancel" or (job.lease_token, job.lease_owner) != identity):
        raise ScanCancelled()
    if any(identity):
        expiry = job.lease_expires_at
        if not all(identity) or not isinstance(expiry, datetime):
            raise ScanCancelled()
        expiry = expiry.replace(tzinfo=timezone.utc) if expiry.tzinfo is None else expiry.astimezone(timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            raise ScanCancelled()
    return job


def _change_ai_state(context, transform, *, precondition=None):
    """Merge fresh artifacts and fence the original worker plus every control."""
    from backend.main import Repo, ScanJob
    from backend import audit_progress
    from backend.scan_worker import ScanCancelled
    for _ in range(8):
        db = context.db_factory()
        try:
            if precondition is not None:
                header = _owned_ai_job(db, context, metadata_only=True)
                if not precondition(header):
                    return None
                # The decision can race an operator control or replacement.
                # Reload every owned field before transforming the full
                # artifact; never promote the metadata observation to a write.
                db.expire(header)
            job = _owned_ai_job(db, context)
            original = (job.output, job.progress_json, job.status, job.control)
            change = transform(job)
            if change is None:
                return None
            values, repo_status, progress = change
            identity = _original_lease(context)
            query = db.query(ScanJob).filter(ScanJob.id == context.job_id, ScanJob.repo_id == context.repo_id,
                ScanJob.output == original[0], ScanJob.progress_json == original[1],
                ScanJob.status == original[2], ScanJob.control == original[3],
                ScanJob.lease_token == identity[0], ScanJob.lease_owner == identity[1])
            if any(identity):
                query = query.filter(ScanJob.lease_expires_at > datetime.utcnow())
            # A pending pause/resume must not expose pre-recovery metadata via
            # the live status shortcut, even if this CAS later loses a race.
            audit_progress.invalidate_status_metadata(context.repo_id, context.job_id)
            if query.update(values, synchronize_session=False) != 1:
                db.rollback()
                continue
            db.query(Repo).filter(Repo.id == context.repo_id).update({Repo.status: repo_status}, synchronize_session=False)
            db.commit()
            return progress
        finally:
            db.close()
    raise ScanCancelled()


def _ai_progress(context, job):
    from backend import audit_progress
    progress = audit_progress.snapshot(context.repo_id)
    if progress.get("scan_job_id") not in (None, context.job_id):
        try:
            progress = json.loads(job.progress_json or "{}")
        except (TypeError, ValueError):
            progress = {}
    progress["scan_job_id"] = context.job_id
    return progress


async def pause_for_ai(context, role, message, *, quality_diagnostic=None,
                       quality_kind="plan_quality", retry_message=None, failure_diagnostic=None):
    """Persist a fenced pause and retry only after verified explicit resume."""
    from backend.main import ScanJob
    from backend import audit_progress, pipeline
    from backend.scan_worker import ScanCancelled

    if quality_kind not in {"plan_quality", "review_quality", "triage_quality"}:
        raise ValueError("Unsupported AI quality checkpoint")
    retry_message = retry_message or (
        "Audit plan retry explicitly requested" if quality_diagnostic is not None
        else "AI configuration verified; retrying the interrupted AI task")

    async with context.pause_lock:
        state = _role_readiness(_load(context), role)
        notice = {"repo_id": context.repo_id, "scan_job_id": context.job_id,
            "pause_id": str(uuid.uuid4()), "paused_at": datetime.now(timezone.utc).isoformat(),
            "role": role, "status": "blocked", "message": message,
            "action": "settings", "resume_required": True, "readiness": state}
        if quality_diagnostic is not None:
            notice.update(kind=quality_kind, configuration_required=False, action="resume",
                          diagnostic=quality_diagnostic)
        if failure_diagnostic is not None:
            notice["failure_diagnostic"] = dict(failure_diagnostic)
        def pause(job):
            if quality_diagnostic is None and state["ready"] and job.control != "pause":
                return None
            progress = _ai_progress(context, job)
            progress.update(status="paused", message=message, ai_pause=notice, updated_at=notice["paused_at"])
            output = json.loads(job.output or "{}")
            output.update(ai_pause=notice, ai_model_runs=list(context.calls))
            return ({ScanJob.status: "paused", ScanJob.control: "pause", ScanJob.current_task: message[:500],
                     ScanJob.progress_json: json.dumps(progress), ScanJob.output: json.dumps(output)}, "paused", progress)
        progress = _change_ai_state(context, pause)
        if progress is None:
            return
        audit_progress.restore(context.repo_id, progress, restore_task_timeline=True)
        await pipeline._send(context.repo_id, message, level="warning",
            detail_id=f"{context.repo_id}-ai-readiness", detail={"type": "ai_readiness", **notice},
            event_type="ai_readiness", notify=True, skip_control_check=True)

        while context.active:
            def resume_ready(job):
                return job.control != "pause" and _resume_role_ready(_load(context), role)

            def resume(job):
                if job.control == "pause" or not _resume_role_ready(_load(context), role):
                    return None
                output = json.loads(job.output or "{}")
                output.pop("ai_pause", None)
                progress = _ai_progress(context, job)
                progress.update(status="running", ai_pause=None, updated_at=datetime.now(timezone.utc).isoformat(),
                                message=retry_message)
                return ({ScanJob.status: "running", ScanJob.output: json.dumps(output),
                         ScanJob.progress_json: json.dumps(progress)}, "scanning", progress)
            progress = _change_ai_state(context, resume, precondition=resume_ready)
            if progress is not None:
                audit_progress.restore(context.repo_id, progress, restore_task_timeline=True)
                break
            await asyncio.sleep(0.4)
        if not context.active:
            raise ScanCancelled()
        await pipeline._send(context.repo_id, retry_message,
                             detail_id=f"{context.repo_id}-ai-readiness",
                             detail={"type": "ai_readiness", "status": "ready", "resume_required": False},
                             event_type="ai_readiness")


async def pause_for_plan_quality(error):
    """Require an explicit retry without revoking a working model receipt."""
    from backend.audit_planner import AuditPlanQualityError
    if not isinstance(error, AuditPlanQualityError):
        raise TypeError("An audit-plan validation failure is required")
    context = active_audit_context()
    if context is None:
        raise AIRequiredError("Audit-plan recovery requires an active exact-audit context")
    diagnostic = error.diagnostic
    message = (f"Audit paused: the model answered, but the plan was rejected at {diagnostic['path']}: "
               f"{diagnostic['reason']}. Both bounded attempts failed validation. "
               "The provider verification is unchanged. Resume to request a new plan, or optionally change the model in Settings.")
    await pause_for_ai(context, "primary", message, quality_diagnostic=diagnostic)


async def pause_for_review_quality(error):
    """Keep model verification while a rejected independent review awaits retry."""
    from backend.ai_judge import IndependentReviewQualityError
    if not isinstance(error, IndependentReviewQualityError):
        raise TypeError("An independent-review validation failure is required")
    context = active_audit_context()
    if context is None:
        raise AIRequiredError("Independent-review recovery requires an active exact-audit context")
    diagnostic = error.diagnostic
    message = (f"Audit paused: the independent model answered, but its review was rejected at {diagnostic['path']}: "
               f"{diagnostic['reason']}. The bounded review attempts ended without a valid review. "
               "Provider verification is unchanged. Resume to retry the independent review, or optionally change its model in Settings.")
    await pause_for_ai(context, "judge", message, quality_diagnostic=diagnostic,
                       quality_kind="review_quality",
                       retry_message="Independent review retry explicitly requested")


async def pause_for_triage_quality(error):
    from backend.lead_triage import LeadTriageQualityError
    if not isinstance(error, LeadTriageQualityError):
        raise TypeError("Expected a lead triage quality failure")
    context = active_audit_context()
    if context is None:
        raise error
    diagnostic = error.diagnostic
    await pause_for_ai(context, "primary",
        f"Audit paused: primary lead review was rejected at {diagnostic['path']}: {diagnostic['reason']}",
        quality_diagnostic=diagnostic, quality_kind="triage_quality",
        retry_message="Primary lead review retry explicitly requested")


async def ensure_audit_ready():
    context = _AUDIT.get()
    if context is None:
        raise AIRequiredError("Audit AI context is missing")
    while context.active:
        settings = _load(context)
        state = readiness(settings)
        if state["ready"]:
            return settings
        await pause_for_ai(context, "primary", "Audit paused: " + state["reason"] + ". Open Settings, verify the model, then resume this audit.")
    raise asyncio.CancelledError()


def _invalidate_call(context, role, before, tested_at, message):
    from backend.main import ScanJob, Settings
    from backend.scan_worker import ScanCancelled
    # Acquire a no-op original-owner write fence in the same transaction as
    # invalidation. A delayed completion cannot revoke model readiness after
    # another worker has acquired the audit or cancellation has committed.
    for _ in range(8):
        db = context.db_factory()
        try:
            job = _owned_ai_job(db, context)
            identity = _original_lease(context)
            query = db.query(ScanJob).filter(ScanJob.id == context.job_id, ScanJob.repo_id == context.repo_id,
                ScanJob.status == job.status, ScanJob.control == job.control,
                ScanJob.lease_token == identity[0], ScanJob.lease_owner == identity[1])
            if any(identity):
                query = query.filter(ScanJob.lease_expires_at > datetime.utcnow())
            if query.update({ScanJob.id: ScanJob.id}, synchronize_session=False) != 1:
                db.rollback()
                continue
            # The job fence protects worker ownership. Lock the Settings row
            # as well on databases with row locks so a concurrent verification
            # cannot be lost between reading and invalidating its receipt.
            settings = db.query(Settings).with_for_update().first()
            if settings is None:
                return True
            changed = invalidate(settings, role, expected_configuration=before,
                                 expected_tested_at=tested_at, reason=message)
            if changed:
                db.commit()
            return changed
        finally:
            db.close()
    raise ScanCancelled()


async def pause_for_invalid_response(role, message, *, response=None):
    context = _AUDIT.get()
    if context is None:
        raise AIRequiredError(message)
    db = context.db_factory()
    try:
        _owned_ai_job(db, context)
    finally:
        db.close()
    # Bind parser failures to the same receipt used for the actual completion.
    # A delayed malformed response cannot revoke a newer verification or an
    # explicitly selected replacement role. This private attribute is omitted
    # from model metadata and all persisted/public call provenance.
    binding = getattr(response, "_lotus_verification", None)
    if isinstance(binding, dict) and binding.get("role") == role:
        if not _invalidate_call(context, role, binding.get("configuration"),
                                binding.get("tested_at"), message):
            return
    elif _role_readiness(_load(context), role)["ready"]:
        raise AIRequiredError("Required AI operation failed without a bound model response; no current verification was invalidated")
    await pause_for_ai(context, role, message)


def invoke_with_recovery(invoke, supplied_settings, *, prompt="", task=None, timeout=None):
    role = getattr(supplied_settings, "_lotus_ai_role", "primary")
    _require_role_task(role, task)
    context = _AUDIT.get()
    if context is None:
        return invoke(supplied_settings)
    plan = role == "primary" and task == AITask.AUDIT_PLAN
    build = task == AITask.LAB_BUILD
    review = plan or build or (role == "judge" and task == AITask.INDEPENDENT_REVIEW) or (role == "primary" and task == AITask.LEAD_TRIAGE)
    from backend.ai_gateway import independent_review_stop_event
    stop_event = independent_review_stop_event() if review else None
    started, paused_seconds = monotonic(), 0.0

    def wait(coroutine):
        nonlocal paused_seconds
        before_wait = monotonic()
        try:
            return _await_on_audit(context, coroutine, stop_event=stop_event)
        finally:
            if review:
                paused_seconds += monotonic() - before_wait

    while context.active:
        if stop_event is not None and stop_event.is_set():
            raise asyncio.CancelledError()
        from backend.main import ScanJob
        from backend.scan_worker import ScanCancelled
        db = context.db_factory()
        try:
            from sqlalchemy.orm import load_only
            job = db.query(ScanJob).options(load_only(ScanJob.id, ScanJob.control, ScanJob.status, raiseload=True)).filter(
                ScanJob.id == context.job_id, ScanJob.repo_id == context.repo_id).first()
            if job is None or job.control == "cancel" or job.status in {"cancelled", "interrupted"}:
                raise ScanCancelled()
            # Automatic report enrichment runs after the durable terminal
            # commit. Its typed result must not resurrect a completed audit.
            if job.status in {"completed", "failed"}:
                return invoke(supplied_settings)
        finally:
            db.close()
        db = context.db_factory()
        try:
            paused = _owned_ai_job(db, context, metadata_only=True).control == "pause"
        finally:
            db.close()
        if review and paused:
            wait(_wait_for_review_control(context))
            continue
        settings = _load(context)
        if role == "judge" and not getattr(settings, "ai_judge_enabled", False):
            raise AIRequiredError("Independent evaluator was explicitly disabled during recovery")
        state = _role_readiness(settings, role)
        if not state["ready"]:
            wait(pause_for_ai(context, role,
                "Audit paused: " + state["reason"] + ". Open Settings, verify the model, then resume this audit."))
            continue
        selected = role_settings(settings, role)
        if review and timeout is not None:
            remaining = float(timeout) - (monotonic() - started - paused_seconds)
            if remaining <= 0:
                from backend.ai_judge import IndependentReviewQualityError
                from backend.lead_triage import LeadTriageQualityError
                from backend.audit_planner import AuditPlanQualityError
                if build:
                    from backend.lab_adapters import AdapterUnavailable
                    raise AdapterUnavailable("The active local adapter request budget ended during recovery; runtime remains unverified")
                error_type = AuditPlanQualityError if plan else LeadTriageQualityError if task == AITask.LEAD_TRIAGE else IndependentReviewQualityError
                label = "audit plan" if plan else "primary lead review" if task == AITask.LEAD_TRIAGE else "independent review"
                raise error_type({"path": "$", "reason": f"The active {label} request budget ended during recovery",
                    "attempts": [], "timeout_seconds": float(timeout)})
            selected._lotus_review_timeout = remaining
        before = fingerprint(settings, role)
        tested_at = receipts(settings).get(role, {}).get("tested_at")
        try:
            result = invoke(selected)
        except Exception:
            # Typed provider results carry availability failures. A Python
            # implementation failure must not revoke working credentials.
            raise
        db = context.db_factory()
        try:
            _owned_ai_job(db, context, metadata_only=True)
        finally:
            db.close()
        status = str(getattr(result.status, "value", result.status))
        record = {"role": role, "provider": selected.ai_provider, "model": selected.ai_model,
            "verified_at": tested_at, "status": status, "completed_at": datetime.now(timezone.utc).isoformat(),
            "task": str(getattr(task, "value", task) or ""),
            "prompt_sha256": hashlib.sha256(str(prompt).encode()).hexdigest(),
            "response_sha256": hashlib.sha256(str(result.text or "").encode()).hexdigest()}
        failure = (result.meta or {}).get("provider_failure")
        if isinstance(failure, dict):
            # Gateway diagnostics are controller-owned scalar classifications;
            # never persist arbitrary exception text or provider payload fields.
            kind = failure.get("kind")
            bounded_failure = {"schema_version": 1,
                "kind": kind if kind in {"timeout", "http_status", "transport", "provider_response"} else "provider_response",
                "retryable": failure.get("retryable") is True}
            code = failure.get("status_code")
            if type(code) is int and 100 <= code <= 599:
                bounded_failure["status_code"] = code
            failure = bounded_failure
            record["provider_failure"] = dict(failure)
        quality = (result.meta or {}).get("response_quality")
        if isinstance(quality, dict):
            record["response_quality"] = {key: quality.get(key) is True for key in
                ("empty", "truncated", "invalid_provider_payload", "response_body_rejected")}
        context.calls.append(record)
        result._lotus_verification = {"role": role, "configuration": before, "tested_at": tested_at}
        if review:
            result._lotus_pause_seconds = paused_seconds
        # A successful but empty structured review is an output-quality
        # failure, not evidence that the credentials stopped working. Its
        # strict consumer owns bounded repair and cannot accept an empty review.
        review_quality_response = review
        if (result.status == AIStatus.OK and (str(result.text or "").strip() or review_quality_response)
                and not (result.meta or {}).get("mock") and not (result.meta or {}).get("simulated")):
            result.meta.update(lotus_provider=selected.ai_provider, lotus_model=selected.ai_model,
                               lotus_role=role, verified_at=tested_at)
            return result
        display_role = "independent evaluator" if role == "judge" else "primary model"
        message = (f"Audit paused: the {display_role} returned {status}. Check Settings and verify the model, "
                   "or explicitly select a verified secondary model as primary, then resume this audit.")
        if isinstance(failure, dict):
            category = failure.get("kind") or "provider response"
            code = failure.get("status_code")
            message += f" Request diagnosis: {category}" + (f" (HTTP {code})" if type(code) is int else "") + "."
        if _invalidate_call(context, role, before, tested_at, message):
            wait(pause_for_ai(context, role, message, **({"failure_diagnostic": failure} if isinstance(failure, dict) else {})))
    raise asyncio.CancelledError()
