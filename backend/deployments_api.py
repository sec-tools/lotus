"""API for deployment identity, host inventory, and safe recon observations.

This router is intentionally a separate bounded workflow from the audit/finding
pipeline.  It never reads or writes ``Finding`` rows.  Every response carries
``result_type=deployment-observation`` so clients cannot accidentally present an
identity match as a vulnerability.
"""

from __future__ import annotations

import asyncio
import json
import hashlib
import os
import re
import socket
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel, Field, StrictBool, StrictInt, StrictStr
from sqlalchemy import text

from backend.main import (
    Deployment,
    DeploymentCreate,
    DeploymentDiscoverRequest,
    DeploymentReconRun,
    DeploymentTarget,
    DeploymentTargetsCreate,
    DeploymentVerifyRequest,
    Repo,
    ScanJob,
    SessionLocal,
    get_db,
)
from backend.deployment_recon import (
    build_profile,
    build_static_signature,
    discover_public_subdomains,
    normalize_host,
    validate_domain,
    verify_host,
)
from backend import deployment_inventory as inventory
from backend import deployment_request_plan as request_plans

router = APIRouter()
_RUN_TASKS: Dict[int, asyncio.Task] = {}
_OWNER = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex}"
_LEASE_SECONDS = 600
_VERIFY_BUDGET_SECONDS = 120


class TargetSpec(BaseModel):
    id: Optional[StrictInt] = Field(default=None, ge=1)
    kind: StrictStr = Field(default="host", pattern="^(host|domain)$")
    value: StrictStr = Field(min_length=1, max_length=255)
    scheme: StrictStr = Field(default="https", pattern="^(http|https)$")
    port: Optional[StrictInt] = Field(default=None, ge=1, le=65535)
    enabled: StrictBool = True


class TargetInventory(BaseModel):
    targets: List[TargetSpec] = Field(default_factory=list, max_length=200)
    expected_revision: Optional[StrictStr] = Field(default=None, max_length=100)


class TargetReview(BaseModel):
    status: StrictStr = Field(pattern="^(unreviewed|confirmed|rejected)$")
    note: StrictStr = Field(default="", max_length=4000)
    reviewer: StrictStr = Field(default="operator", min_length=1, max_length=120)
    expected_revision: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class LocalRuntimeSpec(BaseModel):
    namespace: StrictStr = Field(min_length=1, max_length=63)
    service_name: StrictStr = Field(min_length=1, max_length=63)
    port: StrictInt = Field(ge=1, le=65535)


class RequestPlanSelection(BaseModel):
    model_config = {"extra": "forbid"}
    expected_plan_hash: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    requests: List[Dict[str, Any]] = Field(max_length=9)


class RequestPlanExecution(BaseModel):
    model_config = {"extra": "forbid"}
    expected_plan_hash: Optional[StrictStr] = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")


class LocalLabExecution(RequestPlanExecution):
    test_local: StrictBool = False
    expected_runtime_hash: Optional[StrictStr] = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")


def _plan_for(db, deployment):
    """Rebuild the candidate authority from the selected immutable audit.

    Old profiles may be read without a migration, but their previous dynamic
    observations are never accepted as evidence for this new request policy.
    """
    repo = db.get(Repo, deployment.repo_id)
    job = db.get(ScanJob, deployment.scan_job_id) if deployment.scan_job_id else None
    if not repo or not job or job.repo_id != repo.id:
        raise HTTPException(409, "Selected audit source is unavailable")
    static = build_static_signature(repo, job)
    fresh = request_plans.make_plan(static, _json(job.output, {}))
    saved = _json(deployment.fingerprint_json, {}).get("request_plan")
    if isinstance(saved, dict) and saved.get("catalog_hash") == fresh.get("catalog_hash"):
        try:
            return request_plans.validate_plan(saved, static)
        except ValueError:
            pass
    return fresh


def _execution_plan(db, deployment, expected_hash):
    plan = _plan_for(db, deployment)
    if not expected_hash or expected_hash != plan["plan_hash"]:
        raise HTTPException(409, "Review the current request plan before running identity checks")
    if not plan["requests"]:
        raise HTTPException(409, "No source-supported identity requests are selected; review the request plan")
    return plan


def _baseline_current(deployment, plan):
    profile = _json(deployment.fingerprint_json, {})
    return bool(profile.get("dynamic_signature", {}).get("successful")
                and profile.get("request_plan", {}).get("plan_hash") == plan["plan_hash"]
                and profile.get("baseline_provenance", {}).get("request_plan_hash") == plan["plan_hash"])


def _digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _target_snapshot(target):
    return {"id": target.id, "kind": target.kind, "value": target.value,
            "scheme": target.scheme, "port": target.port, "enabled": bool(target.enabled)}


def _inventory_revision(targets):
    return _digest([_target_snapshot(row) for row in sorted(targets, key=lambda row: row.id)])


def _invalidate_profile(db, deployment, reason):
    profile = _json(deployment.fingerprint_json, {})
    profile.pop("dynamic_signature", None)
    profile.pop("baseline_provenance", None)
    profile.update(dynamic_status="unavailable", reason=reason, confidence=0, confidence_label="unavailable")
    profile["fingerprint_hash"] = _digest({key: value for key, value in profile.items() if key != "fingerprint_hash"})
    deployment.fingerprint_json = json.dumps(profile)
    deployment.fingerprint_hash = profile["fingerprint_hash"]
    deployment.dynamic_signature_json = "{}"
    deployment.status, deployment.confidence, deployment.confidence_label = "baseline-unavailable", 0, "unavailable"
    for target in db.query(DeploymentTarget).filter_by(deployment_id=deployment.id):
        inventory.invalidate_target(target, reason)


@contextmanager
def _mutation(deployment_id):
    from backend.main import _PLATFORM_RESET_LOCK
    if not _PLATFORM_RESET_LOCK.acquire(blocking=False):
        raise HTTPException(503, "Another admission/reset is in progress; retry")
    db = SessionLocal()
    try:
        if db.bind.dialect.name == "sqlite":
            db.execute(text("BEGIN IMMEDIATE"))
        deployment = db.query(Deployment).filter_by(id=deployment_id).with_for_update().first()
        if not deployment:
            raise HTTPException(404, "deployment not found")
        yield db, deployment
    finally:
        db.close()
        _PLATFORM_RESET_LOCK.release()


def _audit_reason(job, static):
    if job.status not in {"completed", "failed", "cancelled", "interrupted"}:
        return "Wait for the selected audit to reach a terminal state"
    if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", static.get("target_tree_hash", "")):
        return "Selected audit lacks a durable target tree identity; run a new audit"
    return ""


def _owned_run(db, run_id):
    db.rollback()  # discard the stale read transaction held across an await
    if db.bind.dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))
    run = db.query(DeploymentReconRun).filter_by(id=run_id).with_for_update().first()
    if not run or run.status not in {"queued", "running"} or run.lease_owner != _OWNER or not run.lease_expires_at or run.lease_expires_at <= datetime.utcnow():
        raise asyncio.CancelledError("Identity operation no longer owns its durable run")
    return run


async def _bound_local_lab(repo, job):
    from backend import lab
    static = build_static_signature(repo, job)
    inspected = await lab.inspect_lab(repo.id)
    state = inspected.get("state") or {}
    if not inspected.get("running") or inspected.get("provider") not in {"docker", "k8s-job"}:
        return None, "No running isolated local lab is available"
    if state.get("target_tree_hash") != static["target_tree_hash"] or (static.get("target_revision") and state.get("target_revision") != static["target_revision"]):
        return None, "The active lab belongs to a different target revision"
    with SessionLocal() as db:
        latest = _latest_job(db, repo.id)
        latest_id = latest.id if latest else None
    output = _json(job.output, {})
    expected = output.get("lab_status") or {}
    expected_run = expected.get("lab_run_id") or (expected.get("state") or {}).get("lab_run_id")
    if latest_id != job.id and (not expected_run or expected_run != state.get("lab_run_id")):
        return None, "Selected historical audit has no matching active lab run"
    attested = await (lab._k8s_attestation(repo.id) if inspected["provider"] == "k8s-job" else lab._docker_attestation(repo.id))
    if not all(attested.get(key) for key in ("container_id", "image_digest", "network_id", "lab_run_id")) or attested.get("target_tree_hash") != static["target_tree_hash"]:
        return None, "Selected audit runtime identity could not be attested"
    url = inspected.get("url") or ""
    host = urlsplit(url).hostname or ""
    if inspected["provider"] == "docker" and host not in {"localhost", "127.0.0.1", "::1"}:
        return None, "Docker baseline is not a local published endpoint"
    if inspected["provider"] == "docker" and (not inspected.get("port") or urlsplit(url).port != int(inspected["port"])):
        return None, "Docker baseline port differs from the attested local lab endpoint"
    if inspected["provider"] == "k8s-job":
        service, namespace = state.get("service_name"), state.get("namespace")
        if not service or not namespace or host not in {f"{service}.{namespace}", f"{service}.{namespace}.svc", f"{service}.{namespace}.svc.cluster.local"}:
            return None, "Baseline endpoint is not the selected Kubernetes lab service"
    local_lab = {**attested, "identity_bound": True, "repo_id": repo.id, "scan_job_id": job.id,
                 "target_tree_hash": static["target_tree_hash"], "target_revision": static["target_revision"],
                 "provider": inspected["provider"], "url": url}
    from backend.deployment_local import bind_lab_endpoint
    try:
        return await bind_lab_endpoint(local_lab, inspected), ""
    except ValueError as exc:
        return None, str(exc)


def _reserve_run(db, deployment, operation, inputs):
    static = _json(deployment.static_signature_json, {})
    scope = {"repo_id": deployment.repo_id, "scan_job_id": deployment.scan_job_id,
             "target_revision": static.get("target_revision"), "target_tree_hash": static.get("target_tree_hash"),
             "fingerprint_hash": deployment.fingerprint_hash, **inputs}
    request_hash = _digest(scope)
    active = db.query(DeploymentReconRun).filter(DeploymentReconRun.deployment_id == deployment.id, DeploymentReconRun.status.in_(["queued", "running"])).first()
    if active:
        if active.operation == operation and _json(active.scope_json, {}).get("request_hash") == request_hash:
            return active, True
        raise HTTPException(409, {"message": "Another identity operation is active; complete or cancel it before changing scope", "run": _run_out(active)})
    scope["request_hash"] = request_hash
    run = DeploymentReconRun(deployment_id=deployment.id, operation=operation, status="queued", scope_json=json.dumps(scope),
                             domains_json=json.dumps(inputs.get("domains") or []), lease_owner=_OWNER,
                             heartbeat_at=datetime.utcnow(), lease_expires_at=datetime.utcnow() + timedelta(seconds=_LEASE_SECONDS),
                             progress_json=json.dumps({"stage": "queued", "message": "Identity observation queued", "completed": 0, "total": 0}))
    db.add(run)
    db.commit()
    db.refresh(run)
    return run, False


async def _owned_operation(run_id, operation):
    task = asyncio.current_task()
    entered = False

    async def heartbeat():
        while True:
            await asyncio.sleep(10)
            with SessionLocal() as db:
                count = db.query(DeploymentReconRun).filter(DeploymentReconRun.id == run_id, DeploymentReconRun.lease_owner == _OWNER, DeploymentReconRun.status.in_(["queued", "running"])).update({"heartbeat_at": datetime.utcnow(), "lease_expires_at": datetime.utcnow() + timedelta(seconds=_LEASE_SECONDS)}, synchronize_session=False)
                db.commit()
            if not count:
                task.cancel()
                return

    renewal = asyncio.create_task(heartbeat())
    try:
        with SessionLocal() as db:
            run = _owned_run(db, run_id)
            run.progress_json = json.dumps({"stage": "running", "message": "Running isolated identity observation", "completed": 0, "total": 0})
            db.commit()
        entered = True
        await operation
    except asyncio.CancelledError:
        with SessionLocal() as db:
            run = db.query(DeploymentReconRun).filter_by(id=run_id, lease_owner=_OWNER).first()
            if run and run.status in {"queued", "running"}:
                run.status, run.error = "interrupted", "Observation worker interrupted; retry explicitly"
                run.finished_at = datetime.utcnow()
                db.commit()
        raise
    finally:
        if not entered:
            operation.close()
        renewal.cancel()
        await asyncio.gather(renewal, return_exceptions=True)
        with SessionLocal() as db:
            run = db.query(DeploymentReconRun).filter_by(id=run_id, lease_owner=_OWNER).first()
            if run and run.status not in {"queued", "running"}:
                run.lease_expires_at = None
                progress = _json(run.progress_json, {})
                progress.update(stage=run.status, message=run.error or "Identity observation finished")
                run.progress_json = json.dumps(progress)
                db.commit()
        if _RUN_TASKS.get(run_id) is task:
            _RUN_TASKS.pop(run_id, None)


def _dispatch(run, operation):
    wrapper = _owned_operation(run.id, operation)
    try:
        _RUN_TASKS[run.id] = asyncio.create_task(wrapper)
    except Exception:
        wrapper.close()
        operation.close()
        with SessionLocal() as db:
            db.query(DeploymentReconRun).filter_by(id=run.id, lease_owner=_OWNER).update({"status": "failed", "error": "Could not dispatch identity worker", "finished_at": datetime.utcnow(), "lease_expires_at": None}, synchronize_session=False)
            db.commit()
        raise


def recover_orphaned_runs() -> int:
    """Terminalize process-local deployment jobs lost across an API restart.

    The observations are intentionally retryable, so a restart must never
    leave a run stuck in ``queued``/``running`` forever or imply that it
    completed.  The next explicit Refresh/Discover/Verify creates a new run.
    """
    db = SessionLocal()
    count = 0
    try:
        rows = db.query(DeploymentReconRun).filter(DeploymentReconRun.status.in_(["queued", "running"])).all()
        from backend.scan_worker import _lease_owner_is_definitively_dead
        for run in rows:
            if run.lease_owner and run.lease_expires_at and run.lease_expires_at > datetime.utcnow() and not _lease_owner_is_definitively_dead(run.lease_owner, heartbeat_at=run.heartbeat_at):
                continue
            reason = "deployment observation interrupted by API restart; retry explicitly"
            # A concurrently renewed lease wins over a stale recovery read.
            count += db.query(DeploymentReconRun).filter_by(id=run.id, status=run.status, lease_owner=run.lease_owner,
                                                           lease_expires_at=run.lease_expires_at).update({
                "status": "interrupted", "error": reason, "finished_at": datetime.utcnow(), "lease_expires_at": None,
                "progress_json": json.dumps({"stage": "interrupted", "message": reason}),
            }, synchronize_session=False)
        if count:
            db.commit()
        return count
    finally:
        db.close()


def _json(value: Any, fallback: Any):
    try:
        parsed = json.loads(value or "")
        return parsed if isinstance(parsed, type(fallback)) else fallback
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def _latest_job(db, repo_id: int, requested: Optional[int] = None) -> Optional[ScanJob]:
    if requested is not None:
        job = db.query(ScanJob).filter(ScanJob.id == requested, ScanJob.repo_id == repo_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="audit job not found for repository")
        return job
    return db.query(ScanJob).filter(ScanJob.repo_id == repo_id).order_by(ScanJob.id.desc()).first()


def _target_url(target: DeploymentTarget) -> str:
    host = str(target.value or "")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{int(target.port)}" if target.port else ""
    return f"{target.scheme or 'https'}://{host}{port}"


def _run_out(run: DeploymentReconRun) -> Dict[str, Any]:
    scope = _json(run.scope_json, {})
    return {
        "id": int(run.id),
        "operation_id": int(run.id),
        **{key: scope.get(key) for key in ("repo_id", "scan_job_id", "target_revision", "target_tree_hash")},
        "scope": {key: value for key, value in scope.items() if key != "profile"},
        "progress": _json(run.progress_json, {}),
        "heartbeat_at": run.heartbeat_at.isoformat() if run.heartbeat_at else None,
        "deployment_id": int(run.deployment_id),
        "operation": run.operation,
        "status": run.status,
        "domains": _json(run.domains_json, []),
        "results": _json(run.results_json, {}),
        "error": run.error or "",
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "result_type": "deployment-observation",
        "findings_created": 0,
    }


def _deployment_out(db, deployment: Deployment) -> Dict[str, Any]:
    repo = db.query(Repo).filter(Repo.id == deployment.repo_id).first()
    job = db.query(ScanJob).filter(ScanJob.id == deployment.scan_job_id).first() if deployment.scan_job_id else None
    targets = db.query(DeploymentTarget).filter(DeploymentTarget.deployment_id == deployment.id).order_by(DeploymentTarget.id.asc()).all()
    runs = db.query(DeploymentReconRun).filter(DeploymentReconRun.deployment_id == deployment.id).order_by(DeploymentReconRun.id.desc()).all()
    fingerprint = _json(deployment.fingerprint_json, {})
    plan = _plan_for(db, deployment)
    return {
        "id": int(deployment.id),
        "name": deployment.name or (repo.source.rsplit("/", 1)[-1] if repo else f"Deployment {deployment.id}"),
        "status": deployment.status,
        "repo_id": int(deployment.repo_id),
        "scan_job_id": int(deployment.scan_job_id) if deployment.scan_job_id else None,
        "repo": {"source": repo.source, "branch": repo.branch, "status": repo.status} if repo else None,
        "audit": {"status": job.status, "started_at": job.started_at.isoformat() if job and job.started_at else None, "finished_at": job.finished_at.isoformat() if job and job.finished_at else None} if job else None,
        "network_service": bool(deployment.network_service),
        "fingerprint": fingerprint,
        "request_plan": plan,
        "request_candidates": plan.get("catalog", []),
        "baseline_current": _baseline_current(deployment, plan),
        "fingerprint_hash": deployment.fingerprint_hash,
        "static_signature": _json(deployment.static_signature_json, {}),
        "dynamic_signature": _json(deployment.dynamic_signature_json, {}),
        "confidence": float(deployment.confidence or 0),
        "confidence_label": deployment.confidence_label or "unavailable",
        "confidence_basis": "identity-evidence-heuristic",
        "calibrated_probability": False,
        "inventory_revision": _inventory_revision(targets),
        "summary": inventory.summarize(targets, runs, deployment.fingerprint_hash),
        "local_runtime": _json(deployment.local_runtime_json, {}),
        "last_verified_at": deployment.last_verified_at.isoformat() if deployment.last_verified_at else None,
        "targets": [
            {"id": int(t.id), "kind": t.kind, "value": t.value, "scheme": t.scheme, "port": t.port,
             "source": t.source, "enabled": bool(t.enabled), "status": t.status,
             "confidence": float(t.confidence or 0), "confidence_label": t.confidence_label or "unavailable",
             "match": _json(t.match_json, {}), "url": _target_url(t),
             "provenance": _json(t.provenance_json, {}),
             **inventory.target_assessment(t, deployment.fingerprint_hash),
             "local_binding": _json(t.local_binding_json, {}),
             "last_checked_at": t.last_checked_at.isoformat() if t.last_checked_at else None}
            for t in targets
        ],
        "runs": [_run_out(r) for r in runs[:20]],
        "result_type": "deployment-observation",
        "findings_created": 0,
    }


async def _run_recon(run_id: int, deployment_id: int, domains: List[str]) -> None:
    db = SessionLocal()
    run = None
    try:
        run = _owned_run(db, run_id)
        deployment = db.query(Deployment).filter(Deployment.id == deployment_id).first()
        if not run or not deployment:
            return
        run.status = "running"
        run.started_at = datetime.utcnow()
        db.commit()
        result = await discover_public_subdomains(domains, run_id=run_id)
        run = _owned_run(db, run_id)
        hosts = result.get("hosts") if isinstance(result, dict) else []
        added = 0
        for item in hosts if isinstance(hosts, list) else []:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host") or "").strip().lower().rstrip(".")
            try:
                host, scheme, port = normalize_host(host, "https", None)
            except ValueError:
                continue
            if not any(host == domain or host.endswith("." + domain) for domain in domains):
                continue
            exists = db.query(DeploymentTarget).filter(
                DeploymentTarget.deployment_id == deployment_id,
                DeploymentTarget.kind == "host",
                DeploymentTarget.value == host,
                DeploymentTarget.scheme == scheme,
                DeploymentTarget.port == port,
            ).first()
            if not exists:
                exists = DeploymentTarget(deployment_id=deployment_id, kind="host", value=host, scheme=scheme, port=port, source="recon")
                db.add(exists)
                added += 1
            provenance = _json(exists.provenance_json, {})
            provenance.update(sources=sorted(set(provenance.get("sources") or []) | set(item.get("sources") or [])),
                              domains=domains, run_id=run_id, last_seen=datetime.utcnow().isoformat(),
                              first_seen=provenance.get("first_seen") or datetime.utcnow().isoformat())
            exists.provenance_json = json.dumps(provenance)
        result["hosts_added"] = added
        result["findings_created"] = 0
        run.results_json = json.dumps(result, sort_keys=True)
        run.status = result.get("status") if result.get("status") in {"blocked", "failed", "partial"} else "completed"
        run.error = result.get("reason") or ("Some public sources failed; inspect source results" if run.status == "partial" else "")
        run.finished_at = datetime.utcnow()
        db.commit()
    except Exception as exc:
        db.rollback()
        run = db.query(DeploymentReconRun).filter(DeploymentReconRun.id == run_id).first()
        if run and run.lease_owner == _OWNER and run.status in {"queued", "running"}:
            run.status = "failed"
            run.error = str(exc)[:1000]
            run.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


async def _run_verify(run_id: int, deployment_id: int, target_ids: List[int]) -> None:
    db = SessionLocal()
    run = None
    try:
        run = _owned_run(db, run_id)
        deployment = db.query(Deployment).filter(Deployment.id == deployment_id).first()
        if not run or not deployment:
            return
        run.status = "running"
        run.started_at = datetime.utcnow()
        db.commit()
        scope = _json(run.scope_json, {})
        profile = scope.get("profile") or {}
        plan = _execution_plan(db, deployment, (scope.get("request_plan") or {}).get("plan_hash"))
        if (scope.get("fingerprint_hash") != deployment.fingerprint_hash
                or profile.get("request_plan") != plan):
            raise ValueError("Identity inputs changed after the request plan was reviewed")
        query = db.query(DeploymentTarget).filter(DeploymentTarget.deployment_id == deployment_id, DeploymentTarget.enabled.is_(True), DeploymentTarget.kind == "host")
        if target_ids:
            query = query.filter(DeploymentTarget.id.in_(target_ids))
        snapshots = scope.get("targets") or [_target_snapshot(row) for row in query.order_by(DeploymentTarget.id.asc()).all()]
        results = {"checked": 0, "matches": 0, "no_matches": 0, "inconclusive": 0, "errors": 0, "deferred": 0,
                   "request_plan_hash": plan["plan_hash"], "findings_created": 0, "observations": []}
        deadline = asyncio.get_running_loop().time() + _VERIFY_BUDGET_SECONDS
        from types import SimpleNamespace
        for index, snapshot in enumerate(snapshots):
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                results["deferred"] = len(snapshots) - index
                results["observations"].extend({"target_id": row["id"], "status": "deferred",
                    "reason": "Operation time budget reached; select these hosts to retry"} for row in snapshots[index:])
                break
            local_binding = (scope.get("local_bindings") or {}).get(str(snapshot["id"]))
            async def observe():
                if local_binding:
                    from backend.deployment_local import endpoint
                    try:
                        async with endpoint(local_binding, profile["static_signature"]) as local:
                            return await verify_host(local["url"], profile, owned_local=local)
                    except ValueError as exc:
                        return {"status": "stale", "confidence": 0, "confidence_label": "unavailable", "reason": str(exc)}
                return await verify_host(_target_url(SimpleNamespace(**snapshot)), profile)
            try:
                observation = await asyncio.wait_for(observe(), timeout=remaining)
            except asyncio.TimeoutError:
                observation = {"status": "error", "confidence": 0, "confidence_label": "unavailable",
                               "reason": "Operation time budget reached; select this host to retry"}
            run = _owned_run(db, run_id)
            target = db.query(DeploymentTarget).filter_by(id=snapshot["id"], deployment_id=deployment_id).with_for_update().first()
            if not target or _target_snapshot(target) != snapshot:
                results["observations"].append({"target_id": snapshot["id"], "status": "stale-input"})
                run.results_json = json.dumps(results)
                db.commit()
                continue
            if local_binding and observation.get("status") == "stale":
                _invalidate_profile(db, deployment, observation.get("reason") or "Owned local runtime changed")
            old_evidence = inventory.evidence_hash(target, deployment.fingerprint_hash)
            target.status = observation.get("status") or "error"
            target.confidence = float(observation.get("confidence") or 0)
            target.confidence_label = str(observation.get("confidence_label") or "unavailable")
            target.match_json = json.dumps(observation, sort_keys=True)
            target.last_checked_at = datetime.utcnow()
            if inventory.evidence_hash(target, deployment.fingerprint_hash) != old_evidence:
                inventory.invalidate_review(target, "Identity evidence changed after manual review")
            results["checked"] += 1
            if target.status == "match":
                results["matches"] += 1
            elif target.status == "no-match":
                results["no_matches"] += 1
            elif target.status == "inconclusive":
                results["inconclusive"] += 1
            else:
                results["errors"] += 1
            results["observations"].append({"target_id": target.id, "status": target.status, "confidence": target.confidence, "confidence_label": target.confidence_label})
            run.progress_json = json.dumps({"stage": "verifying", "message": "Comparing benign identity metadata", "completed": len(results["observations"]), "total": len(snapshots)})
            run.results_json = json.dumps(results)
            db.commit()
        run = _owned_run(db, run_id)
        run.results_json = json.dumps(results, sort_keys=True)
        run.status = "partial" if results["errors"] or results["deferred"] else "completed"
        if results["deferred"]:
            run.error = "Operation time budget reached; completed observations retained and remaining hosts can be retried"
        run.finished_at = datetime.utcnow()
        deployment.last_verified_at = datetime.utcnow()
        db.commit()
    except Exception as exc:
        db.rollback()
        run = db.query(DeploymentReconRun).filter(DeploymentReconRun.id == run_id).first()
        if run and run.lease_owner == _OWNER and run.status in {"queued", "running"}:
            run.status = "failed"
            run.error = str(exc)[:1000]
            run.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


async def _run_profile_refresh(run_id: int, deployment_id: int) -> None:
    """Re-capture the harmless local-lab baseline for an existing profile."""
    db = SessionLocal()
    run = None
    try:
        run = _owned_run(db, run_id)
        deployment = db.query(Deployment).filter(Deployment.id == deployment_id).first()
        if not run or not deployment:
            return
        repo = db.query(Repo).filter(Repo.id == deployment.repo_id).first()
        job = db.query(ScanJob).filter(ScanJob.id == deployment.scan_job_id).first() if deployment.scan_job_id else None
        if not repo or not job or job.repo_id != repo.id:
            raise RuntimeError("deployment audit source is no longer available")
        run.status = "running"
        run.started_at = datetime.utcnow()
        db.commit()
        scope = _json(run.scope_json, {})
        plan = _execution_plan(db, deployment, (scope.get("request_plan") or {}).get("plan_hash"))
        binding = _json(deployment.local_runtime_json, {})
        test_local = scope.get("test_local") is True
        preview = None
        verification = None
        if test_local:
            from backend.deployment_local_test import resolve_preview
            _, preview = await resolve_preview(repo, job, binding)
            if not preview["ready"] or preview["runtime_hash"] != scope.get("expected_runtime_hash"):
                raise RuntimeError("Selected local runtime changed or is unavailable; preview it again before testing")

        async def capture_and_compare(local_lab):
            nonlocal verification
            current = _owned_run(db, run_id)
            current.progress_json = json.dumps({"stage": "baseline-capture", "completed": 0, "total": 2 if test_local else 1})
            db.commit()
            profile = await build_profile(repo, job, local_lab=local_lab, request_plan=plan)
            if test_local and local_lab and profile.get("dynamic_status") == "captured":
                # Both passes use the same attested destination transport. No
                # user URL, redirect, body/header or exploit input is introduced.
                current = _owned_run(db, run_id)
                _execution_plan(db, deployment, plan["plan_hash"])
                current.progress_json = json.dumps({"stage": "local-verification", "completed": 1, "total": 2})
                db.commit()
                verification = await verify_host(local_lab["url"], profile, owned_local=local_lab)
            return profile

        if binding:
            from backend.deployment_local import endpoint
            async with endpoint(binding, build_static_signature(repo, job)) as local_lab:
                profile = await capture_and_compare(local_lab)
            reason = ""
        else:
            local_lab, reason = await _bound_local_lab(repo, job)
            if test_local:
                from backend.deployment_local_test import runtime_hash
                if not local_lab or runtime_hash(local_lab) != preview["runtime_hash"]:
                    raise RuntimeError("Selected local runtime changed before testing")
            profile = await capture_and_compare(local_lab)
        if local_lab and not binding:
            current_lab, _ = await _bound_local_lab(repo, job)
            changed = not current_lab or any(current_lab.get(key) != local_lab.get(key) for key in ("container_id", "lab_run_id", "target_tree_hash", "url"))
            if test_local and current_lab:
                from backend.deployment_local_test import runtime_hash
                changed = changed or runtime_hash(current_lab) != preview["runtime_hash"]
            if changed:
                profile.pop("dynamic_signature", None)
                profile.pop("baseline_provenance", None)
                profile.update(dynamic_status="unavailable", confidence=0.0, confidence_label="unavailable")
                reason = "Local lab changed during baseline capture; retry against the selected audit"
                if test_local:
                    raise RuntimeError(reason)
        if profile["static_signature"]["target_tree_hash"] != scope.get("target_tree_hash"):
            raise RuntimeError("Selected audit target identity changed")
        if reason:
            profile["reason"] = reason
        from backend.deployment_recon import _hash
        profile["fingerprint_hash"] = _hash({key: value for key, value in profile.items() if key != "fingerprint_hash"})
        run = _owned_run(db, run_id)
        deployment = db.query(Deployment).filter_by(id=deployment_id).with_for_update().first()
        deployment.network_service = bool(profile.get("network_service"))
        deployment.status = "ready" if profile.get("dynamic_status") == "captured" else "baseline-unavailable" if deployment.network_service else "unsupported"
        deployment.fingerprint_json = json.dumps(profile, sort_keys=True)
        deployment.fingerprint_hash = str(profile.get("fingerprint_hash") or "")
        deployment.static_signature_json = json.dumps(profile.get("static_signature") or {}, sort_keys=True)
        deployment.dynamic_signature_json = json.dumps(profile.get("dynamic_signature") or {}, sort_keys=True)
        deployment.confidence = float(profile.get("confidence") or 0)
        deployment.confidence_label = str(profile.get("confidence_label") or "unavailable")
        deployment.updated_at = datetime.utcnow()
        for target in db.query(DeploymentTarget).filter_by(deployment_id=deployment_id):
            inventory.invalidate_target(target, "Selected-audit baseline was refreshed")
        results = {"dynamic_status": profile.get("dynamic_status"), "reason": profile.get("reason"),
                   "confidence": profile.get("confidence"), "confidence_label": profile.get("confidence_label"),
                   "fingerprint_hash": profile.get("fingerprint_hash"), "findings_created": 0}
        if test_local:
            results["local_test"] = {"schema_version": 1, "runtime": preview, "fingerprint": profile,
                "verification": verification or {"status": "unverified", "reason": "No successful baseline response was captured",
                    "confidence": 0.0, "revision_verified": False, "findings_created": 0},
                "request_plan_hash": plan["plan_hash"], "result_type": "deployment-observation",
                "revision_verified": False, "calibrated_probability": False, "findings_created": 0}
        run.results_json = json.dumps(results, sort_keys=True)
        run.status = "completed"
        run.finished_at = datetime.utcnow()
        db.commit()
    except Exception as exc:
        db.rollback()
        run = db.query(DeploymentReconRun).filter(DeploymentReconRun.id == run_id).first()
        if run and run.lease_owner == _OWNER and run.status in {"queued", "running"}:
            current_deployment = db.query(Deployment).filter_by(id=deployment_id).first()
            if current_deployment:
                _invalidate_profile(db, current_deployment, "Baseline capture failed: " + str(exc)[:500])
            run.status = "failed"
            run.error = str(exc)[:1000]
            run.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


@router.get("/api/deployments/audits")
def deployment_audits():
    with SessionLocal() as db:
        rows = []
        for job, repo in db.query(ScanJob, Repo).join(Repo, Repo.id == ScanJob.repo_id).filter(Repo.status != "archived").order_by(ScanJob.id.desc()).limit(500).all():
            static = build_static_signature(repo, job)
            reason = _audit_reason(job, static)
            deployment = db.query(Deployment).filter_by(repo_id=repo.id, scan_job_id=job.id).first()
            summary = inventory.summarize()
            if deployment:
                summary = inventory.summarize(db.query(DeploymentTarget).filter_by(deployment_id=deployment.id).all(),
                                              db.query(DeploymentReconRun).filter_by(deployment_id=deployment.id).all(), deployment.fingerprint_hash)
            rows.append({"repo_id": repo.id, "source": repo.source, "branch": repo.branch, "repo_status": repo.status,
                         "scan_job_id": job.id, "scan_status": job.status,
                         "target_revision": static["target_revision"], "target_tree_hash": static["target_tree_hash"],
                         "network_service": static["network_service"], "selectable": not bool(reason), "reason": reason,
                         "deployment_id": deployment.id if deployment else None, "summary": summary,
                         "result_type": "deployment-observation"})
        return {"audits": rows, "result_type": "deployment-observation", "findings_created": 0}


@router.get("/api/deployments")
def list_deployments():
    recover_orphaned_runs()
    with SessionLocal() as db:
        rows = db.query(Deployment).order_by(Deployment.updated_at.desc(), Deployment.id.desc()).all()
        return {"deployments": [_deployment_out(db, row) for row in rows], "result_type": "deployment-observation", "findings_created": 0}


@router.post("/api/deployments")
async def create_deployment(body: DeploymentCreate):
    from backend.main import _PLATFORM_RESET_LOCK
    if not _PLATFORM_RESET_LOCK.acquire(blocking=False):
        raise HTTPException(503, "Another admission/reset is in progress; retry")
    db = SessionLocal()
    try:
        if db.bind.dialect.name == "sqlite":
            db.execute(text("BEGIN IMMEDIATE"))
        repo = db.query(Repo).filter_by(id=body.repo_id).with_for_update().first()
        if not repo:
            raise HTTPException(404, "repository not found")
        if repo.status == "archived":
            raise HTTPException(409, "Restore the repository before creating a deployment profile")
        job = _latest_job(db, repo.id, body.scan_job_id)
        if not job:
            raise HTTPException(409, "select an audit before creating a deployment profile")
        static = build_static_signature(repo, job)
        reason = _audit_reason(job, static)
        if reason:
            raise HTTPException(409, reason)
        deployment = db.query(Deployment).filter_by(repo_id=repo.id, scan_job_id=job.id).first()
        if not deployment:
            # Static construction does no I/O. Baseline capture is a separate,
            # visible durable operation so progress/cancellation stay available.
            profile = await build_profile(repo, job)
            deployment = Deployment(repo_id=repo.id, scan_job_id=job.id,
                                    name=body.name or repo.source.rstrip("/").rsplit("/", 1)[-1],
                                    status="baseline-unavailable" if profile["network_service"] else "unsupported",
                                    network_service=profile["network_service"], fingerprint_json=json.dumps(profile),
                                    fingerprint_hash=profile["fingerprint_hash"], static_signature_json=json.dumps(static),
                                    dynamic_signature_json="{}", confidence=0, confidence_label="unavailable")
            db.add(deployment)
        elif body.name:
            deployment.name = body.name
        deployment.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(deployment)
        return _deployment_out(db, deployment)
    finally:
        db.close()
        _PLATFORM_RESET_LOCK.release()


@router.get("/api/deployments/{deployment_id}")
def get_deployment(deployment_id: int):
    recover_orphaned_runs()
    with SessionLocal() as db:
        deployment = db.get(Deployment, deployment_id)
        if not deployment:
            raise HTTPException(404, "deployment not found")
        return _deployment_out(db, deployment)


@router.get("/api/deployments/{deployment_id}/request-plan")
def get_request_plan(deployment_id: int):
    with SessionLocal() as db:
        deployment = db.get(Deployment, deployment_id)
        if not deployment:
            raise HTTPException(404, "deployment not found")
        plan = _plan_for(db, deployment)
        return {"plan": plan, "candidates": plan.get("catalog", []), "baseline_current": _baseline_current(deployment, plan),
                "result_type": "deployment-observation", "findings_created": 0}


@router.put("/api/deployments/{deployment_id}/request-plan")
def save_request_plan(deployment_id: int, body: RequestPlanSelection):
    recover_orphaned_runs()
    with _mutation(deployment_id) as (db, deployment):
        if db.query(DeploymentReconRun).filter(DeploymentReconRun.deployment_id == deployment_id,
                                               DeploymentReconRun.status.in_(["queued", "running"])).first():
            raise HTTPException(409, "Wait for the active observation to finish or cancel it before editing requests")
        current = _plan_for(db, deployment)
        if body.expected_plan_hash != current["plan_hash"]:
            raise HTTPException(409, "Request plan changed; reload before saving")
        try:
            plan = request_plans.select_requests(current, body.requests)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        profile = _json(deployment.fingerprint_json, {})
        if profile.get("request_plan") != plan:
            # Even a legacy profile with the same paths needs a fresh baseline:
            # the old sender did not enforce this plan or its isolation policy.
            profile["request_plan"] = plan
            profile["requests"] = plan["requests"]
            deployment.fingerprint_json = json.dumps(profile, sort_keys=True)
            _invalidate_profile(db, deployment, "Request plan changed; capture a fresh local baseline")
            deployment.updated_at = datetime.utcnow()
            db.commit()
        return {"plan": plan, "candidates": plan.get("catalog", []), "baseline_current": _baseline_current(deployment, plan),
                "result_type": "deployment-observation", "findings_created": 0}


def _normalize_spec(spec):
    if spec.kind == "domain":
        return validate_domain(spec.value), "https", None
    return normalize_host(spec.value, spec.scheme, spec.port)


def _save_inventory(deployment_id, body):
    normalized = []
    errors = []
    for index, spec in enumerate(body.targets):
        try:
            normalized.append((spec, _normalize_spec(spec)))
        except ValueError as exc:
            errors.append({"index": index, "value": spec.value, "error": str(exc)})
    if errors:
        raise HTTPException(422, {"message": "No inventory changes saved; correct invalid targets", "errors": errors})
    with _mutation(deployment_id) as (db, deployment):
        targets = db.query(DeploymentTarget).filter_by(deployment_id=deployment_id).order_by(DeploymentTarget.id).all()
        if body.expected_revision is not None and body.expected_revision != _inventory_revision(targets):
            raise HTTPException(409, "Inventory changed; reload before saving")
        by_id = {target.id: target for target in targets}
        seen_ids = set()
        for spec, (value, scheme, port) in normalized:
            target = by_id.get(spec.id) if spec.id is not None else None
            if spec.id is not None and (target is None or spec.id in seen_ids):
                raise HTTPException(422, "Target ID is missing, duplicated or belongs to a different deployment")
            if spec.id is not None:
                seen_ids.add(spec.id)
            exact = next((row for row in targets if (row.kind, row.value, row.scheme, row.port) == (spec.kind, value, scheme, port)), None)
            if target is not None and exact is not None and target.id != exact.id:
                raise HTTPException(409, "Another saved target already has that address")
            target = target or exact
            if target is None:
                target = DeploymentTarget(deployment_id=deployment_id, source="manual", kind=spec.kind, value=value, scheme=scheme, port=port, enabled=spec.enabled)
                db.add(target)
                targets.append(target)
            changed = (target.kind, target.value, target.scheme, target.port, bool(target.enabled)) != (spec.kind, value, scheme, port, spec.enabled)
            if _json(target.local_binding_json, {}) and (target.kind, target.value, target.scheme, target.port) != (spec.kind, value, scheme, port):
                raise HTTPException(409, "An owned local runtime address cannot be edited; remove it and bind another runtime")
            if changed:
                inventory.invalidate_target(target, "Saved target configuration changed")
            if (target.kind, target.value) != (spec.kind, value):
                target.provenance_json = "{}"
                target.source = "manual"
            target.kind, target.value, target.scheme, target.port, target.enabled = spec.kind, value, scheme, port, spec.enabled
        deployment.updated_at = datetime.utcnow()
        db.commit()
        result = _deployment_out(db, deployment)
        result.update(targets_saved=len(normalized), targets_added=len(result["targets"]) - len(by_id), validation_errors=[])
        return result


@router.post("/api/deployments/{deployment_id}/targets")
def add_targets(deployment_id: int, body: TargetInventory):
    return _save_inventory(deployment_id, body)


@router.put("/api/deployments/{deployment_id}/targets")
def save_targets(deployment_id: int, body: TargetInventory):
    """Atomic upsert; omitted rows are retained and DELETE is explicit."""
    return _save_inventory(deployment_id, body)


@router.put("/api/deployments/{deployment_id}/targets/{target_id}")
def edit_target(deployment_id: int, target_id: int, body: TargetSpec):
    if body.id not in (None, target_id):
        raise HTTPException(422, "Target ID conflicts with request path")
    return _save_inventory(deployment_id, TargetInventory(targets=[body.model_copy(update={"id": target_id})]))


@router.delete("/api/deployments/{deployment_id}/targets/{target_id}")
def delete_target(deployment_id: int, target_id: int):
    with _mutation(deployment_id) as (db, deployment):
        target = db.query(DeploymentTarget).filter_by(id=target_id, deployment_id=deployment_id).first()
        if not target:
            raise HTTPException(404, "deployment target not found")
        db.delete(target)
        deployment.updated_at = datetime.utcnow()
        db.commit()
        return {"status": "deleted", "target_id": target_id, "result_type": "deployment-observation", "findings_created": 0}


@router.put("/api/deployments/{deployment_id}/targets/{target_id}/review")
def review_target(deployment_id: int, target_id: int, body: TargetReview):
    with _mutation(deployment_id) as (db, deployment):
        target = db.query(DeploymentTarget).filter_by(id=target_id, deployment_id=deployment_id).with_for_update().first()
        if not target or target.kind != "host":
            raise HTTPException(404, "Host target not found in this selected audit")
        current = inventory.review_out(target, deployment.fingerprint_hash)
        if current["revision"] != body.expected_revision:
            raise HTTPException(409, "Target evidence or review changed; reload before reviewing")
        previous = _json(target.review_json, {})
        history = list(previous.get("history") or [])[-19:]
        if previous:
            history.append({key: value for key, value in previous.items() if key != "history"})
        target.review_json = json.dumps({"status": body.status, "note": body.note, "reviewer": body.reviewer,
            "reviewed_at": datetime.utcnow().isoformat(), "evidence_hash": current["evidence_hash"],
            "repo_id": deployment.repo_id, "scan_job_id": deployment.scan_job_id,
            "target_id": target.id, "history": history, "reviewer_identity": "operator-supplied label"})
        deployment.updated_at = datetime.utcnow()
        db.commit()
        return _deployment_out(db, deployment)


@router.post("/api/deployments/{deployment_id}/local-runtime")
async def bind_local_runtime(deployment_id: int, body: LocalRuntimeSpec):
    from backend.deployment_local import attest
    with SessionLocal() as db:
        deployment = db.get(Deployment, deployment_id)
        if not deployment:
            raise HTTPException(404, "deployment not found")
        static = _json(deployment.static_signature_json, {})
    try:
        binding = await attest(body.namespace, body.service_name, body.port, static)
    except (ValueError, TimeoutError) as exc:
        raise HTTPException(409, str(exc))
    with _mutation(deployment_id) as (db, deployment):
        if db.query(DeploymentReconRun).filter(DeploymentReconRun.deployment_id == deployment_id,
                                              DeploymentReconRun.status.in_(["queued", "running"])).first():
            raise HTTPException(409, "Complete or cancel the active identity operation before binding a runtime")
        if _json(deployment.static_signature_json, {}) != static:
            raise HTTPException(409, "Selected audit identity changed while binding local runtime")
        if _digest(_json(deployment.local_runtime_json, {})) != _digest(binding):
            _invalidate_profile(db, deployment, "Owned local runtime binding changed; capture its baseline explicitly")
            deployment.local_runtime_json = json.dumps(binding)
        host = body.service_name + "." + body.namespace + ".svc.cluster.local"
        _, _, saved_port = normalize_host(host, "http", body.port)
        target = db.query(DeploymentTarget).filter_by(deployment_id=deployment_id, kind="host", value=host, scheme="http", port=saved_port).first()
        if target is None:
            target = DeploymentTarget(deployment_id=deployment_id, kind="host", value=host, scheme="http", port=saved_port,
                                      source="local-runtime", enabled=True)
            db.add(target)
        if _digest(_json(target.local_binding_json, {})) != _digest(binding):
            inventory.invalidate_target(target, "Owned local runtime identity changed")
            target.local_binding_json = json.dumps(binding)
        deployment.updated_at = datetime.utcnow()
        db.commit()
        return _deployment_out(db, deployment)


class IdentityDiscoverRequest(BaseModel):
    domains: List[StrictStr] = Field(default_factory=list, max_length=50)


class IdentityVerifyRequest(RequestPlanExecution):
    target_ids: List[StrictInt] = Field(default_factory=list, max_length=200)
    mode: StrictStr = Field(default="public", pattern="^(public|owned-local-runtime)$")


@router.post("/api/deployments/{deployment_id}/discover")
async def discover_targets(deployment_id: int, body: IdentityDiscoverRequest):
    recover_orphaned_runs()
    try:
        supplied = sorted({validate_domain(value) for value in body.domains})
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    with _mutation(deployment_id) as (db, deployment):
        domains = supplied or [target.value for target in db.query(DeploymentTarget).filter_by(deployment_id=deployment_id, kind="domain", enabled=True).all()]
        if not domains or len(domains) > 50:
            raise HTTPException(422, "Save or supply between 1 and 50 enabled public domains")
        for domain in supplied:
            if not db.query(DeploymentTarget).filter_by(deployment_id=deployment_id, kind="domain", value=domain).first():
                db.add(DeploymentTarget(deployment_id=deployment_id, kind="domain", value=domain, scheme="https", source="manual", enabled=True))
        run, deduplicated = _reserve_run(db, deployment, "discover", {"domains": sorted(set(domains))})
        payload = {"run": _run_out(run), "deduplicated": deduplicated, "validation_errors": []}
        if not deduplicated:
            _dispatch(run, _run_recon(run.id, deployment_id, domains))
        return payload


@router.post("/api/deployments/{deployment_id}/verify")
async def verify_targets(deployment_id: int, body: IdentityVerifyRequest):
    recover_orphaned_runs()
    with _mutation(deployment_id) as (db, deployment):
        plan = _execution_plan(db, deployment, body.expected_plan_hash)
        targets = db.query(DeploymentTarget).filter_by(deployment_id=deployment_id, kind="host", enabled=True).order_by(DeploymentTarget.id).all()
        targets = [target for target in targets if bool(_json(target.local_binding_json, {})) == (body.mode == "owned-local-runtime")]
        if body.target_ids:
            requested = set(body.target_ids)
            targets = [target for target in targets if target.id in requested]
            if {target.id for target in targets} != requested:
                raise HTTPException(422, "Selected host IDs must be enabled hosts of this deployment and observation mode")
        if not targets:
            raise HTTPException(422, "Save at least one enabled host before verifying identity")
        if len(targets) > 200:
            raise HTTPException(422, "Select no more than 200 hosts for one identity operation")
        profile = _json(deployment.fingerprint_json, {})
        if not profile.get("baseline_provenance") or not profile.get("dynamic_signature"):
            raise HTTPException(409, "Capture a local-lab baseline for the selected audit before verifying hosts")
        if (profile.get("request_plan", {}).get("plan_hash") != plan["plan_hash"]
                or profile["baseline_provenance"].get("request_plan_hash") != plan["plan_hash"]):
            raise HTTPException(409, "Request plan changed; capture a fresh local baseline before verifying hosts")
        snapshots = [_target_snapshot(target) for target in targets[:200]]
        run, deduplicated = _reserve_run(db, deployment, "fingerprint", {"targets": snapshots, "profile": profile, "mode": body.mode, "request_plan": plan,
            "local_bindings": {str(target.id): _json(target.local_binding_json, {}) for target in targets if _json(target.local_binding_json, {})}})
        payload = {"run": _run_out(run), "deduplicated": deduplicated}
        if not deduplicated:
            _dispatch(run, _run_verify(run.id, deployment_id, [target["id"] for target in snapshots]))
        return payload



@router.get("/api/deployments/{deployment_id}/local-lab-preview")
async def preview_local_lab(deployment_id: int):
    from backend.deployment_local_test import resolve_preview
    with SessionLocal() as db:
        deployment = db.get(Deployment, deployment_id)
        if not deployment:
            raise HTTPException(404, "deployment not found")
        plan = _plan_for(db, deployment)
        repo = db.get(Repo, deployment.repo_id)
        job = db.get(ScanJob, deployment.scan_job_id)
        binding = _json(deployment.local_runtime_json, {})
        identity = {"deployment_id": deployment.id, "repo_id": repo.id, "scan_job_id": job.id,
                    "plan_hash": plan["plan_hash"], "request_count": len(plan["requests"])}
        if not plan["requests"]:
            preview = {"ready": False, "url": None, "runtime_hash": None,
                       "reason": "No source-supported identity requests are selected; review the plan"}
        else:
            try:
                _, preview = await resolve_preview(repo, job, binding)
            except (ValueError, RuntimeError, TimeoutError):
                preview = {"ready": False, "url": None, "runtime_hash": None,
                           "reason": "The selected local runtime could not be attested; restore or rebind it before testing"}
        return {**identity, **preview, "read_only": True, "requests_sent": 0}


@router.post("/api/deployments/{deployment_id}/fingerprint")
async def refresh_fingerprint(deployment_id: int, body: Optional[LocalLabExecution] = Body(default=None)):
    recover_orphaned_runs()
    with _mutation(deployment_id) as (db, deployment):
        plan = _execution_plan(db, deployment, body.expected_plan_hash if body else None)
        test_local = bool(body and body.test_local)
        if test_local and not body.expected_runtime_hash:
            raise HTTPException(409, "Preview the selected local runtime before testing")
        inputs = {"request_plan": plan}
        if test_local:
            inputs.update(test_local=True, expected_runtime_hash=body.expected_runtime_hash)
        run, deduplicated = _reserve_run(db, deployment, "fingerprint-baseline", inputs)
        payload = {"run": _run_out(run), "deduplicated": deduplicated}
        if not deduplicated:
            _dispatch(run, _run_profile_refresh(run.id, deployment_id))
        return payload


@router.get("/api/deployment-runs/{run_id}")
def get_deployment_run(run_id: int):
    recover_orphaned_runs()
    with SessionLocal() as db:
        run = db.get(DeploymentReconRun, run_id)
        if not run:
            raise HTTPException(404, "deployment run not found")
        return _run_out(run)


@router.post("/api/deployment-runs/{run_id}/cancel")
async def cancel_deployment_run(run_id: int):
    with SessionLocal() as db:
        run = db.get(DeploymentReconRun, run_id)
        if not run:
            raise HTTPException(404, "deployment run not found")
        deployment_id = run.deployment_id
    with _mutation(deployment_id) as (db, deployment):
        run = db.query(DeploymentReconRun).filter_by(id=run_id).with_for_update().first()
        if run.status in {"queued", "running"}:
            run.status, run.error = "cancelled", "Cancelled by operator; retained completed observations"
            run.finished_at, run.lease_expires_at = datetime.utcnow(), None
            run.progress_json = json.dumps({"stage": "cancelled", "message": run.error})
            db.commit()
        payload = {"run": _run_out(run)}
    task = _RUN_TASKS.get(run_id)
    if task and not task.done():
        task.cancel()
    return payload
