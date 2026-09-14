"""Owned publication checkpoint writes without reloading the full audit graph."""
from __future__ import annotations

import asyncio
from datetime import datetime
import json


async def commit_publication_state(db, job_cls, repo_cls, *, repo_id, job_id,
                                   token, owner, values, progress, repo_status,
                                   pause_message='Paused before report completion', task_progress=None):
    """Honor durable controls and keep a replacement owner's data untouched.

    Publication may outlive an API pause/cancel request. Read only scalar owner
    fields after the callback; no saved ORM row is authority across publication.
    The caller supplies its already retained, frozen evidence for the write.
    """
    from backend import audit_progress, pipeline
    from backend.scan_worker import ScanCancelled
    from backend.main import ScanLease
    fields = ('id', 'repo_id', 'status', 'control', 'finished_at',
              'lease_token', 'lease_owner', 'lease_expires_at')
    preparing = values.get(job_cls.status) == 'running'
    preparation_committed = False
    conflicts = 0
    def reject():
        db.rollback()
        raise ScanCancelled()
    while True:
        # The first checkpoint shares the analysis transaction: flushed lead
        # rows are not committed yet. Rolling it back here silently loses them.
        # Scalar SQL reads bypass the identity map without expiring or flushing
        # pending application objects. The owned checkpoint commits them all.
        with db.no_autoflush:
            row = db.query(*(getattr(job_cls, name) for name in fields)).filter(
                job_cls.id == job_id, job_cls.repo_id == repo_id).first()
        if (row is None or row.status not in {'running', 'paused'}
                or (row.lease_token, row.lease_owner) != (token, owner)
                or row.control not in {'', 'pause'} or row.finished_at is not None
                or (token and (row.lease_expires_at is None
                               or row.lease_expires_at <= datetime.utcnow()))):
            reject()
        now = datetime.utcnow()
        with db.no_autoflush:
            lease = db.query(ScanLease.job_id, ScanLease.lease_token, ScanLease.owner,
                ScanLease.expires_at).filter(ScanLease.repo_id == repo_id).first()
        if (token and (lease is None or lease.job_id != job_id or lease.lease_token != token
                      or lease.owner != owner or lease.expires_at is None or lease.expires_at <= now)
                or not token and lease is not None and lease.expires_at and lease.expires_at > now):
            reject()
        query = db.query(job_cls).filter(
            job_cls.id == job_id, job_cls.repo_id == repo_id,
            job_cls.status == row.status, job_cls.control == row.control,
            job_cls.finished_at.is_(None), job_cls.lease_token == token,
            job_cls.lease_owner == owner,
        )
        if token:
            query = query.filter(job_cls.lease_expires_at > datetime.utcnow(),
                db.query(ScanLease).filter(ScanLease.repo_id == repo_id, ScanLease.job_id == job_id,
                    ScanLease.lease_token == token, ScanLease.owner == owner,
                    ScanLease.expires_at > datetime.utcnow()).exists())
        else:
            query = query.filter(~db.query(ScanLease).filter(ScanLease.repo_id == repo_id,
                ScanLease.expires_at > datetime.utcnow()).exists())
        if row.control == 'pause' or row.status == 'paused':
            paused = dict(progress, status='paused',
                          current_task={'name': pause_message},
                          message=pause_message, eta_seconds=None, eta_basis='paused')
            if job_cls.output in values:
                paused.update(phase='gating', phase_label='Phase 3 · Report publication', progress_pct=99)
            # Flushed evidence still owns a write transaction even if the row
            # was already paused. Commit it once before waiting for a Resume
            # writer; db.new/dirty cannot identify already-flushed changes.
            if row.status != 'paused' or (preparing and not preparation_committed):
                paused_values = dict(values) if preparing else {}
                paused_values.update({job_cls.status: 'paused',
                    job_cls.progress_json: json.dumps(paused, default=str) if preparing and job_cls.progress_json in values
                        else progress_transition(db, job_cls.progress_json, paused),
                    job_cls.current_task: pause_message,
                    job_cls.eta_seconds: None})
                if query.update(paused_values, synchronize_session=False) != 1:
                    if not preparing:
                        db.rollback()
                    conflicts += 1
                    if conflicts >= 8:
                        reject()
                    continue
                db.query(repo_cls).filter(repo_cls.id == repo_id).update({repo_cls.status: 'paused'})
                db.commit()
                preparation_committed = True
                audit_progress.publication_status(repo_id, job_id, paused)
            check = pipeline.LEASE_CHECKS.get(repo_id)
            if check is not None:
                result = check()
                if asyncio.iscoroutine(result):
                    await result
            await asyncio.sleep(.1)
            continue
        if values.get(job_cls.status) == 'completed':
            values = {**values, job_cls.finished_at: datetime.utcnow(),
                      job_cls.progress_json: progress_transition(db, job_cls.progress_json, progress, task_progress)}
        elif preparation_committed and job_cls.progress_json not in values:
            # The early evidence checkpoint has no replacement graph. Resume
            # only its display fields so the durable job and progress agree.
            progress = dict(progress, status='running', current_task=progress.get('current_task'),
                            message=progress.get('message', ''), eta_seconds=progress.get('eta_seconds'),
                            eta_basis=progress.get('eta_basis'))
            task = progress.get('current_task')
            values = {**values,
                job_cls.progress_json: progress_transition(db, job_cls.progress_json, progress),
                job_cls.current_task: str(task.get('name') or '') if isinstance(task, dict) else str(task or ''),
                job_cls.eta_seconds: progress.get('eta_seconds')}
        if query.update(values, synchronize_session=False) != 1:
            # A zero-row CAS is not a failed SQL transaction. A concurrent
            # pause may have changed control after the scalar read. Keep
            # pending evidence while re-reading; invalid ownership/control
            # or exhausted retries still roll it back through reject().
            if not preparing:
                db.rollback()
            conflicts += 1
            if conflicts >= 8:
                reject()
            continue
        db.query(repo_cls).filter(repo_cls.id == repo_id).update({repo_cls.status: repo_status})
        db.commit()
        audit_progress.publication_status(repo_id, job_id, progress)
        return values.get(job_cls.finished_at)


def progress_transition(db, column, progress, task_progress=None):
    """Patch lifecycle fields in SQL, preserving later telemetry without a read.

    Explicit JSON null stays null; this deliberately does not use merge-patch,
    which would delete null-valued fields. Only task telemetry that changed in
    this publisher's live ledger is supplied; the coverage graph is untouched.
    """
    from sqlalchemy import cast, func, literal, Text
    updates = {key: progress[key] for key in ("status", "phase", "phase_label", "message",
        "current_task", "progress_pct", "eta_seconds", "eta_basis", "completion_state", "evidence_status") if key in progress}
    if task_progress:
        allowed = {'tasks', 'task_timeline', 'active_task', 'slow_tasks'}
        if set(task_progress) - allowed:
            raise ValueError('Unexpected publication task telemetry')
        updates.update(task_progress)
    dialect = db.get_bind().dialect.name
    if dialect == 'sqlite':
        arguments = [func.coalesce(column, '{}')]
        for key, value in updates.items():
            arguments.extend(['$.' + key, func.json(json.dumps(value, default=str))])
        return func.json_set(*arguments)
    if dialect == 'postgresql':
        from sqlalchemy.dialects.postgresql import JSONB
        return cast(cast(func.coalesce(column, '{}'), JSONB).op('||')(
            cast(literal(json.dumps(updates, default=str)), JSONB)), Text)
    raise RuntimeError('Publication progress updates require SQLite or PostgreSQL')
