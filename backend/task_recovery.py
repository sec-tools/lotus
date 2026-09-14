"""Durable, explicit retries at the owning worker's settled recon boundary."""
import asyncio
from copy import deepcopy
from datetime import datetime, timezone
import json
import math
import uuid

from backend.resource_continuation import resource_failure, task_failure, TASK_TO_TOOL
from backend import audit_progress


def recovery_failure(row):
    """Select recovery work without turning a deliberate exclusion into a fault.

    Reporting still uses task_failure directly: excluded tools remain evidence
    gaps. Inspect the recorded decision, never today's capability settings, so
    disabling a tool after it failed cannot erase that failure.
    """
    failure = task_failure(row)
    if not failure or resource_failure(row):
        return failure
    status = str(row.get("status") or "").lower().replace("_", "-")
    if status not in {"skipped", "disabled", "blocked"} or row.get("error") or row.get("runtime_diagnostic"):
        return failure
    policy = row.get("resource_policy")
    if policy is not None and not isinstance(policy, dict):
        return failure
    if isinstance(policy, dict) and policy:
        state = policy.get("state")
        admission = policy.get("admission_state", state)
        tool = TASK_TO_TOOL.get(failure["task_name"])
        if (not policy.get("diagnostic") and tool and row.get("configure_tool") == tool
                and policy.get("tool_id", policy.get("id")) == tool
                and state in {"user_disabled", "capability_disabled", "resource_blocked"}
                and admission in {"user_disabled", "capability_disabled"}):
            return None
        # Conflicting/malformed admission metadata must not hide a resource or
        # configuration error behind a legacy selection message.
        if state != "ready" or policy.get("diagnostic"):
            return failure
    if status == "blocked":
        return failure
    if (status == "disabled" or row.get("intentional_disabled") is True
            or row.get("classification") == "not_selected"):
        return None
    reason = row.get("reason")
    if not isinstance(reason, str):
        return failure
    if reason in {
        "disabled by capabilities configuration", "disabled in capabilities configuration",
        "static_analysis_enabled disabled in Settings", "dependency_audit_enabled disabled in Settings",
        "callgraph_enabled disabled in Settings", "dynamic_path_exploration_enabled disabled in Settings",
        "skipped by operator before analyzer execution",
        "audit depth L1 Quick: core tools only", "audit depth L1 Fast: core tools only",
        "audit depth L2 Standard: core+structural tools only",
    }:
        return None
    if ((failure["task_name"] == "dynamic-path-exploration" and reason == "opt-in disabled")
            or (failure["task_name"] == "joern-cpg" and reason == "LOTUS_DISABLE_JOERN=1")):
        return None
    return failure


def _now():
    return datetime.now(timezone.utc).isoformat()


def _object(raw):
    try:
        value = json.loads(raw or "{}") if isinstance(raw, (str, type(None))) else raw
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def _recovery_detail_metadata(original, *, task_name, repo_id, scan_job_id):
    """Retain selected recorded diagnostics without merging an analyzer payload.

    The recovery card replaces the original clickable tool detail. Its controls
    remain controller-owned; these detached fields are display data only. Reject
    oversized or malformed metadata as a whole instead of truncating a receipt
    into an apparently complete one. Durable original_result remains unchanged.
    """
    fields = ("runtime_diagnostic", "resource_policy", "resource_envelope")
    omitted = []
    result = {}
    remaining = 64 * 1024
    nodes = 1024

    def bound_identity(value):
        return all(key not in value or (type(value[key]) is int and value[key] == expected)
                   for key, expected in (("repo_id", repo_id), ("scan_job_id", scan_job_id)))

    def copy_json(value, depth=0):
        nonlocal remaining, nodes
        nodes -= 1
        if nodes < 0 or depth > 8:
            raise ValueError("metadata structure limit")
        if value is None or type(value) is bool:
            copied = value
        elif type(value) is int and value.bit_length() <= 64:
            copied = value
        elif type(value) is float and math.isfinite(value):
            copied = value
        elif type(value) is str and len(value) <= 4096:
            copied = value
        elif type(value) in (list, tuple) and len(value) <= 32:
            remaining -= 2 + len(value)
            if remaining < 0:
                raise ValueError("metadata byte limit")
            return [copy_json(item, depth + 1) for item in value]
        elif type(value) is dict and len(value) <= 64:
            copied = {}
            remaining -= 2 + 2 * len(value)
            if remaining < 0:
                raise ValueError("metadata byte limit")
            for key, item in value.items():
                if (type(key) is not str or len(key) > 128 or any(part in key.lower()
                        for part in ("password", "secret", "credential", "authorization", "api_key", "environment", "token"))):
                    raise ValueError("metadata key unavailable")
                copied[copy_json(key, depth + 1)] = copy_json(item, depth + 1)
            return copied
        else:
            raise ValueError("metadata value unavailable")
        remaining -= len(json.dumps(copied, ensure_ascii=True, allow_nan=False))
        if remaining < 0:
            raise ValueError("metadata byte limit")
        return copied

    if (not isinstance(original, dict) or original.get("name") != task_name
            or original.get("task_name", task_name) != task_name or not bound_identity(original)):
        omitted.append("original_result")
    else:
        for key in ("lead_count", "findings_count"):
            value = original.get(key)
            if type(value) is int and 0 <= value <= 2**63 - 1:
                result[key] = value
        if "lead_count" in result:
            result.update(count=result["lead_count"], result_type="leads")
        for key in fields:
            if key not in original:
                continue
            value = original[key]
            diagnostic = value if key == "runtime_diagnostic" else value.get("diagnostic") if type(value) is dict else None
            valid = type(value) is dict and bound_identity(value)
            if isinstance(diagnostic, dict):
                valid = valid and bound_identity(diagnostic) and diagnostic.get(
                    "tool_id", TASK_TO_TOOL.get(task_name)) == TASK_TO_TOOL.get(task_name)
            budget = remaining, nodes
            try:
                if not valid:
                    raise ValueError("metadata identity mismatch")
                copied = copy_json(value)
                if remaining < 0:
                    raise ValueError("metadata byte limit")
                result[key] = copied
            except ValueError:
                remaining, nodes = budget
                omitted.append(key)
    if omitted:
        result["detail_metadata_omitted"] = omitted
        result["detail_metadata_reason"] = (
            "Some recorded diagnostic metadata is unavailable in this bounded card; "
            "the original audit artifacts are retained.")
    return result


async def current_policy(settings):
    from backend.analyzer_resources import assess_policy, snapshot_policy
    return await assess_policy(snapshot_policy(settings))


def _lease_live(job):
    expiry = getattr(job, "lease_expires_at", None)
    if not isinstance(expiry, datetime):
        return False
    expiry = expiry.replace(tzinfo=timezone.utc) if expiry.tzinfo is None else expiry.astimezone(timezone.utc)
    return bool(getattr(job, "lease_token", "") and getattr(job, "lease_owner", "")
                and expiry > datetime.now(timezone.utc))


def _bound_record(job, record):
    return (record.get("schema_version") == 1 and record.get("scan_job_id") == job.id
            and record.get("repo_id") == job.repo_id
            and record.get("lease_token") == getattr(job, "lease_token", None)
            and record.get("lease_owner") == getattr(job, "lease_owner", None)
            and bool(record.get("target_tree_hash")))


def projection(job, task_name, policy):
    output = _object(job.output)
    recovery = _object(output.get("task_recovery"))
    saved = _object(_object(recovery.get("tasks")).get(task_name))
    tool = TASK_TO_TOOL.get(task_name)
    selected = next((row for row in policy.get("tools", []) if row.get("id") == tool), {})
    live = (str(job.status) in {"running", "paused"} and recovery.get("active") is True
            and _lease_live(job) and _bound_record(job, recovery))
    state = saved.get("state", "unavailable") if live else "terminal" if str(job.status) in {
        "completed", "failed", "cancelled", "interrupted"} else "unavailable"
    ready = selected.get("state") == "ready"
    reason = (saved.get("reason") or "This task has no active recovery checkpoint")
    if not live:
        if state == "terminal":
            reason = "This audit has finished; replay it to collect new results"
        elif str(job.status) in {"running", "paused"}:
            closed = (recovery.get("active") is False and _bound_record(job, recovery)
                      and _lease_live(job) and (recovery.get("continued_at") or recovery.get("completed_at")))
            if closed:
                state = "checkpoint_closed"
                stage = {"recon": "Phase 1", "phase2": "Phase 2"}.get(recovery.get("stage"), "earlier")
                reason = (f"This audit has moved beyond its {stage} recovery checkpoint. "
                          "In-place retry is closed; the recorded task outcome remains unchanged. "
                          "Replay becomes available after the audit finishes.")
            else:
                reason = ("This audit is still active, but this task has no current recovery checkpoint. "
                          "Replay becomes available after the audit finishes.")
        else:
            reason = "This audit has not reached an active task recovery checkpoint"
    allowed = bool(live and str(job.status) == "paused" and job.control == "pause"
                   and state in {"waiting", "failed"} and ready and tool
                   and saved.get("retry_supported", True) is True
                   and isinstance(selected.get("configuration_revision"), str) and selected["configuration_revision"])
    return {"schema_version": 1, "scan_job_id": int(job.id), "repo_id": int(job.repo_id),
            "task_name": task_name, "configure_tool": tool, "classification": saved.get("classification"),
            "state": state, "reason": reason, "retry_allowed": allowed,
            "configuration_revision": selected.get("configuration_revision"),
            "readiness": {"state": selected.get("state", "unavailable"),
                          "reason": selected.get("reason") or "Resource configuration is unavailable"},
            "attempts": deepcopy(saved.get("attempts") or []),
            "retry_url": f"/api/scan-jobs/{int(job.id)}/tasks/{task_name}/retry",
            "replay_url": f"/api/scan-jobs/{int(job.id)}/replay" if state == "terminal" else None}


def audit_projection(job):
    """Public, secret-free projection of the original worker's exact checkpoint."""
    record = _object(_object(job.output).get("task_recovery"))
    live = (job.status in {"running", "paused"} and record.get("active") is True
            and _lease_live(job) and _bound_record(job, record))
    pending = any(attempt.get("state") in {"requested", "running"}
                  for task in _object(record.get("tasks")).values() if isinstance(task, dict)
                  for attempt in task.get("attempts", []) if isinstance(attempt, dict))
    waiting = live and job.status == "paused" and job.control == "pause" and not pending
    terminal = job.status in {"completed", "failed", "cancelled", "interrupted"}
    return {"schema_version": 1, "repo_id": int(job.repo_id), "scan_job_id": int(job.id),
            "checkpoint_id": record.get("checkpoint_id"), "stage": record.get("stage"),
            "state": "waiting" if waiting else "running" if live else "terminal" if terminal else "unavailable",
            "continue_allowed": bool(waiting and record.get("checkpoint_id")),
            "policy": record.get("continuation_policy") or record.get("initial_policy") or "strict",
            "continued_at": record.get("continued_at"),
            "tasks": [{key: deepcopy(task.get(key)) for key in ("task_name", "configure_tool", "classification",
                "reason", "state", "retry_supported")} for task in _object(record.get("tasks")).values()
                if isinstance(task, dict)],
            "continue_url": f"/api/scan-jobs/{int(job.id)}/continue-with-gaps",
            "replay_url": f"/api/scan-jobs/{int(job.id)}/replay" if terminal else None,
            "reason": ("Independent work has settled. Reconfigure and retry supported tasks, or continue with disclosed gaps."
                       if waiting else "Continuing never marks missing coverage complete or bypasses finding proof gates.")}


def existing_continue_response(job, request):
    """An uncertain acknowledged action remains queryable after its worker ends."""
    from fastapi import HTTPException
    record = _object(_object(job.output).get("task_recovery"))
    for decision in record.get("continuation_decisions", []):
        if decision.get("idempotency_key") == request.idempotency_key:
            if decision.get("checkpoint_id") != request.checkpoint_id:
                raise HTTPException(409, "Idempotency key belongs to another checkpoint")
            return {"status": "already_continued", "schema_version": 1, "repo_id": int(job.repo_id),
                    "scan_job_id": int(job.id), "checkpoint_id": request.checkpoint_id}
    return None


def request_continue(db, job, request):
    """Persist one audit-bound choice; no current Settings change is implied."""
    from fastapi import HTTPException
    previous = existing_continue_response(job, request)
    if previous:
        return previous
    model = type(job)
    original = job.output
    output = _object(original)
    record = _object(output.get("task_recovery"))
    view = audit_projection(job)
    if not view["continue_allowed"] or request.checkpoint_id != view["checkpoint_id"]:
        raise HTTPException(409, detail={"message": "Audit checkpoint changed; refresh recovery", "recovery": view})
    now = _now()
    record.setdefault("continuation_decisions", []).append({"idempotency_key": request.idempotency_key,
        "checkpoint_id": request.checkpoint_id, "policy": "continue_with_gaps", "requested_at": now})
    record.update(continuation_policy="continue_with_gaps", continued_at=now)
    audit_progress.invalidate_status_metadata(int(job.repo_id), int(job.id))
    changed = db.query(model).filter(model.id == job.id, model.repo_id == job.repo_id,
        model.output == original, model.status == "paused", model.control == "pause",
        model.lease_token == job.lease_token, model.lease_owner == job.lease_owner,
        model.lease_expires_at > datetime.utcnow()).update({model.output: json.dumps(output),
            model.control: "", model.status: "running"}, synchronize_session=False)
    if changed != 1:
        db.rollback()
        raise HTTPException(409, "Audit state changed; refresh recovery")
    db.commit()
    return {"status": "continued", "schema_version": 1, "repo_id": int(job.repo_id),
            "scan_job_id": int(job.id), "checkpoint_id": request.checkpoint_id}


def request_retry(db, job, task_name, request, policy):
    """CAS admission prevents two API processes from queuing competing attempts."""
    from fastapi import HTTPException
    model = type(job)
    original = job.output
    output = _object(original)
    recovery = _object(output.get("task_recovery"))
    for name, saved in _object(recovery.get("tasks")).items():
        for attempt in saved.get("attempts") or []:
            if attempt.get("idempotency_key") == request.idempotency_key:
                if name != task_name or attempt.get("configuration_revision") != request.configuration_revision:
                    raise HTTPException(409, "Idempotency key already belongs to another task/configuration")
                return {"status": "already_requested", "scan_job_id": int(job.id), "repo_id": int(job.repo_id),
                        "task_name": task_name, "attempt_id": attempt["attempt_id"]}
    current = projection(job, task_name, policy)
    if not current["retry_allowed"]:
        raise HTTPException(409, detail={"message": "Task retry is not currently admissible", "recovery": current})
    if request.configuration_revision != current["configuration_revision"]:
        raise HTTPException(409, "Configuration changed; refresh task recovery before retrying")
    attempt = {"attempt_id": str(uuid.uuid4()), "idempotency_key": request.idempotency_key,
               "configuration_revision": request.configuration_revision,
               "resource_policy": deepcopy(policy), "requested_at": _now(), "state": "requested"}
    selected = recovery["tasks"][task_name]
    selected.setdefault("attempts", []).append(attempt)
    selected["state"] = "requested"
    audit_progress.invalidate_status_metadata(int(job.repo_id), int(job.id))
    changed = db.query(model).filter(model.id == job.id, model.repo_id == job.repo_id,
        model.output == original, model.status == "paused", model.control == "pause",
        model.lease_token == job.lease_token, model.lease_owner == job.lease_owner,
        model.lease_expires_at > datetime.utcnow()).update(
            {model.output: json.dumps(output), model.control: "", model.status: "running"}, synchronize_session=False)
    if changed != 1:
        db.rollback()
        raise HTTPException(409, "Audit state changed; refresh task recovery")
    db.commit()
    return {"status": "retry_requested", "scan_job_id": int(job.id), "repo_id": int(job.repo_id),
            "task_name": task_name, "attempt_id": attempt["attempt_id"]}


def _owned_job(db, context, lease):
    from backend.main import ScanJob
    from backend.scan_worker import ScanCancelled
    job = db.query(ScanJob).filter(ScanJob.id == context.job_id, ScanJob.repo_id == context.repo_id).first()
    if (job is None or job.status not in {"running", "paused"} or job.control == "cancel"
            or not _lease_live(job) or (job.lease_token, job.lease_owner) != lease):
        raise ScanCancelled()
    return job


def _change_checkpoint(context, lease, transform):
    """Merge one change into fresh output and fence controls plus lease ownership.

    A concurrent heartbeat may extend expiry. A replacement owner, expired
    lease, pause/cancel, or changed artifact forces a fresh read before mutation.
    Transformations operate on the latest record, never a stale whole output.
    """
    from backend.main import Repo, ScanJob
    from backend.scan_worker import ScanCancelled
    for _ in range(8):
        db = context.db_factory()
        try:
            job = _owned_job(db, context, lease)
            original, status, control = job.output, job.status, job.control
            output = _object(original)
            record = deepcopy(_object(output.get("task_recovery")))
            changes = transform(record, job, db)
            if changes is None:
                return None
            output["task_recovery"] = record
            values = {ScanJob.output: json.dumps(output), **changes}
            audit_progress.invalidate_status_metadata(context.repo_id, context.job_id)
            changed = db.query(ScanJob).filter(
                ScanJob.id == context.job_id, ScanJob.repo_id == context.repo_id,
                ScanJob.output == original, ScanJob.status == status, ScanJob.control == control,
                ScanJob.lease_token == lease[0], ScanJob.lease_owner == lease[1],
                ScanJob.lease_expires_at > datetime.utcnow(),
            ).update(values, synchronize_session=False)
            if not changed:
                db.rollback()
                continue
            if ScanJob.status in changes:
                db.query(Repo).filter(Repo.id == context.repo_id).update(
                    {Repo.status: "paused" if changes[ScanJob.status] == "paused" else "recon"},
                    synchronize_session=False)
            db.commit()
            return record
        finally:
            db.close()
    raise ScanCancelled()


def merge_worker_output(context, fields):
    """Commit a phase checkpoint without replacing newer recovery artifacts."""
    from backend.main import ScanJob
    lease = (context.recovery_lease_token, context.recovery_lease_owner)
    committed_output = None
    def merge(record, job, db):
        nonlocal committed_output
        output = _object(job.output)
        output.update(deepcopy(fields))
        committed_output = output
        return {ScanJob.output: json.dumps(output, default=str)}
    result = _change_checkpoint(context, lease, merge)
    if result is not None and committed_output is not None:
        audit_progress.publish_status_metadata(context.repo_id, context.job_id, committed_output,
                                               lease_token=lease[0], lease_owner=lease[1])


async def recover_at_checkpoint(rows, runners, findings, dest, *, send, stage="recon", target_tree_hash=None):
    """Retry only an explicit request in the original live worker and source."""
    from backend.ai_runtime import active_audit_context
    from backend import audit_progress, pipeline, analyzer_resources
    from backend.main import ScanJob, Settings
    from backend.scan_worker import ScanCancelled
    from backend.proof_receipts import content_tree_digest
    context = active_audit_context()
    resource_context = analyzer_resources.AUDIT_CONTEXT.get() or {}
    failures = {failure["task_name"]: failure for row in rows if (failure := recovery_failure(row))}
    if context is None or not failures:
        return {}
    expected_tree = target_tree_hash or (resource_context.get("target_identity") or {}).get("target_tree_hash")
    lease = (getattr(context, "recovery_lease_token", ""), getattr(context, "recovery_lease_owner", ""))
    if not expected_tree or not all(lease):
        return {}

    def validate(record, job):
        if not _bound_record(job, record) or record.get("target_tree_hash") != expected_tree:
            raise ScanCancelled()

    def initialize(record, job, db):
        if record:
            validate(record, job)
            if record.get("active") is not True or record.get("stage", "recon") != stage:
                record.setdefault("checkpoints", []).append({key: deepcopy(record.get(key)) for key in
                    ("checkpoint_id", "stage", "tasks", "continued_at", "completed_at")})
                record.update(active=True, tasks={}, checkpoint_id=str(uuid.uuid4()))
                for key in ("continued_at", "completed_at", "pause_observed"):
                    record.pop(key, None)
        else:
            record.update(schema_version=1, active=True, scan_job_id=context.job_id,
                          repo_id=context.repo_id, target_tree_hash=expected_tree,
                          lease_token=lease[0], lease_owner=lease[1], tasks={})
        record.setdefault("initial_policy", getattr(context, "recovery_gap_policy", "strict"))
        record.setdefault("checkpoint_id", str(uuid.uuid4()))
        record["stage"] = stage
        if job.status == "paused" or job.control == "pause":
            record["pause_observed"] = True
        for name, failure in failures.items():
            original = next(row for row in rows if row.get("name") == name)
            task = record["tasks"].setdefault(name, {**failure, "state": "waiting", "attempts": []})
            task["retry_supported"] = name in runners and name in TASK_TO_TOOL
            task.setdefault("original_result", deepcopy(original))
        return {}

    record = _change_checkpoint(context, lease, initialize)

    def publish(value):
        # Reload the committed record: a newer explicit action may already have
        # changed it. Progress never replaces the task ledger or DB controls.
        db = context.db_factory()
        try:
            job = _owned_job(db, context, lease)
            current = deepcopy(_object(_object(job.output).get("task_recovery")))
            validate(current, job)
            state = audit_progress.resource_recovery(context.repo_id, context.job_id, current,
                status=job.status, audit_view=audit_projection(job))
            if state is None:
                return
            changed = db.query(ScanJob).filter(
                ScanJob.id == context.job_id, ScanJob.repo_id == context.repo_id,
                ScanJob.output == job.output, ScanJob.status == job.status, ScanJob.control == job.control,
                ScanJob.lease_token == lease[0], ScanJob.lease_owner == lease[1],
                ScanJob.lease_expires_at > datetime.utcnow(),
            ).update({ScanJob.progress_json: json.dumps(state), ScanJob.eta_seconds: None}, synchronize_session=False)
            if changed:
                db.commit()
            else:
                db.rollback()
        finally:
            db.close()

    try:
        for name, failure in failures.items():
            original = _object(_object(record.get("tasks")).get(name)).get("original_result")
            metadata = _recovery_detail_metadata(original, task_name=name,
                repo_id=context.repo_id, scan_job_id=context.job_id)
            partial_scope = (failure.get("classification") == "scope_limit"
                and isinstance(original, dict) and original.get("status") == "partial"
                and original.get("terminal_status") == "completed"
                and original.get("scope_complete") is False and not original.get("error"))
            summary = (f"{name} finished with partial scope. Recorded results remain available; unexamined areas remain coverage gaps."
                       if partial_scope else f"{name} did not complete. Review its saved results and recovery options, or finish the audit with gaps.")
            await send(context.repo_id, summary,
                       level="warning", detail_id=f"{context.repo_id}-tool-{name}",
                       detail={**metadata, "type": "task_recovery", "tool": name, "status": "partial" if partial_scope else "failed",
                               **{key: failure.get(key) for key in ("task_name", "configure_tool", "classification", "reason")},
                               "scan_job_id": context.job_id, "repo_id": context.repo_id,
                               "retry_supported": name in runners and name in TASK_TO_TOOL,
                               "recovery_url": f"/api/scan-jobs/{context.job_id}/recovery"},
                       event_type="task_recovery", notify=True, skip_control_check=True)
        while context.active:
            db = context.db_factory()
            try:
                job = _owned_job(db, context, lease)
                record = deepcopy(_object(_object(job.output).get("task_recovery")))
                validate(record, job)
                pending = [(name, attempt) for name, task in record["tasks"].items()
                           for attempt in task.get("attempts", []) if attempt.get("state") == "requested"]
                paused = job.control == "pause" or job.status == "paused"
            finally:
                db.close()
            if pending and not paused:
                name, attempt = pending[0]
                if content_tree_digest(dest) != expected_tree:
                    raise RuntimeError("Captured source changed before task retry; refusing to execute")
                attempt_id = attempt["attempt_id"]
                def claim(current, job, db):
                    validate(current, job)
                    if job.control == "pause" or job.status != "running":
                        return None
                    selected = next((item for item in current["tasks"][name]["attempts"]
                                     if item.get("attempt_id") == attempt_id and item.get("state") == "requested"), None)
                    if selected is None:
                        return None
                    selected.update(state="running", started_at=_now())
                    current["tasks"][name]["state"] = "running"
                    return {}
                claimed = _change_checkpoint(context, lease, claim)
                if claimed is None:
                    continue
                attempt = next(item for item in claimed["tasks"][name]["attempts"] if item["attempt_id"] == attempt_id)
                publish(claimed)
                try:
                    with analyzer_resources.audit_context(attempt["resource_policy"], repo_id=context.repo_id,
                            scan_job_id=context.job_id, target_identity=resource_context["target_identity"]):
                        result = await runners[name]()
                except BaseException as error:
                    def failed(current, job, db):
                        validate(current, job)
                        item = next(item for item in current["tasks"][name]["attempts"] if item["attempt_id"] == attempt_id)
                        item.update(state="interrupted", finished_at=_now(), error=type(error).__name__)
                        current["tasks"][name]["state"] = "failed"
                        return {}
                    try:
                        _change_checkpoint(context, lease, failed)
                    except ScanCancelled:
                        pass
                    raise
                if isinstance(result, list):
                    findings.extend(result)
                latest = next(row for row in reversed(rows) if row.get("name") == name)
                def finished(current, job, db):
                    validate(current, job)
                    item = next(item for item in current["tasks"][name]["attempts"] if item["attempt_id"] == attempt_id)
                    item.update(state="completed" if latest.get("status") == "completed" else "failed",
                                finished_at=_now(), result=deepcopy(latest))
                    current["tasks"][name].update(state=item["state"], reason=latest.get("reason"))
                    if all(task["state"] == "completed" for task in current["tasks"].values()):
                        current.update(active=False, completed_at=_now())
                        return {}  # A newer Stop remains paused, even on success.
                    return {ScanJob.status: "paused", ScanJob.control: "pause",
                            ScanJob.current_task: "Waiting for task resource recovery"}
                record = _change_checkpoint(context, lease, finished)
                publish(record)
                if record.get("completed_at"):
                    return record
                continue

            def settle(current, job, db):
                validate(current, job)
                pending_now = any(attempt.get("state") == "requested" for task in current["tasks"].values()
                                  for attempt in task.get("attempts", []))
                settings = db.query(Settings).first()
                continuation_policy = (getattr(settings, "resource_gap_policy", "strict")
                                       if current.get("pause_observed") is True else current.get("initial_policy", "strict"))
                # Only an audit-bound action can override its captured policy.
                # Preserve the legacy narrow policy's Settings+Resume workflow.
                if current.get("continuation_policy") == "continue_with_gaps":
                    continuation_policy = "continue_with_gaps"
                elif current.get("initial_policy") == "continue_with_gaps":
                    continuation_policy = "continue_with_gaps"
                elif continuation_policy == "continue_with_gaps":
                    continuation_policy = current.get("initial_policy", "strict")
                if (not pending_now and job.control != "pause" and job.status == "running"
                        and continuation_policy in {"report_incomplete", "continue_with_gaps"}):
                    current.update(active=False, continuation_policy=continuation_policy, continued_at=_now())
                    return {}
                if job.control == "pause" or job.status == "paused":
                    if current.get("pause_observed") is not True:
                        current["pause_observed"] = True
                        return {}
                    return None
                if pending_now:
                    return None
                current["pause_observed"] = True
                return {ScanJob.status: "paused", ScanJob.control: "pause",
                        ScanJob.current_task: "Waiting for audit recovery choice"}
            changed = _change_checkpoint(context, lease, settle)
            if changed is not None:
                record = changed
                publish(record)
                if record.get("active") is False and record.get("continued_at"):
                    return record
            check = pipeline.LEASE_CHECKS.get(context.repo_id)
            if check:
                outcome = check()
                if asyncio.iscoroutine(outcome):
                    await outcome
            await asyncio.sleep(0.4)
        raise ScanCancelled()
    finally:
        def deactivate(current, job, db):
            validate(current, job)
            current["active"] = False
            return {}
        try:
            _change_checkpoint(context, lease, deactivate)
        except ScanCancelled:
            pass
