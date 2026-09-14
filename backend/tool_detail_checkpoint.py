"""Small, lease-fenced scanner detail checkpoints, independent of full report assembly."""
from __future__ import annotations

import asyncio
from contextlib import nullcontext
from datetime import datetime
import json
import logging
import re

from sqlalchemy import Text, case, cast, func, literal, select

LOG = logging.getLogger(__name__)
MAX_DETAIL_BYTES = 512 * 1024
_TERMINAL = {'ok', 'completed', 'failed', 'skipped', 'blocked', 'not-installed', 'partial', 'limited'}
_DETAIL_ID = re.compile(r'([1-9][0-9]*)-tool-([A-Za-z0-9_.:-]{1,160})\Z')


def bounded_detail(detail):
    """Bound the persisted UI projection; raw scanner artifacts remain separate."""
    remaining = MAX_DETAIL_BYTES - 4096
    clipped = False

    def visit(value, depth=0):
        nonlocal remaining, clipped
        if remaining < 128 or depth > 8:
            clipped = True
            return None
        if isinstance(value, str):
            encoded = value.encode('utf-8')
            cap = min(16000, remaining // 2)
            if len(encoded) > cap:
                value = encoded[:cap].decode('utf-8', errors='ignore')
                clipped = True
            remaining -= len(value.encode('utf-8')) * 2 + 8
            return value
        if value is None or isinstance(value, (bool, int, float)):
            remaining -= 32
            return value
        if isinstance(value, dict):
            out = {}
            for index, (key, item) in enumerate(value.items()):
                if index >= 80 or remaining < 128:
                    clipped = True
                    break
                if isinstance(key, str) and len(key) <= 120:
                    remaining -= len(key) * 2 + 8
                    out[key] = visit(item, depth + 1)
            return out
        if isinstance(value, list):
            out = []
            for item in value[:200]:
                if remaining < 128:
                    clipped = True
                    break
                out.append(visit(item, depth + 1))
            clipped |= len(out) != len(value)
            return out
        clipped = True
        return None

    result = visit(detail)
    if clipped:
        result['detail_truncated'] = True
        result['detail_notice'] = 'Bounded saved task detail; consult the recorded scanner artifact for complete output.'
    raw = json.dumps(result, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    if len(raw.encode('utf-8')) > MAX_DETAIL_BYTES:
        raise ValueError('Task detail exceeds its bounded checkpoint')
    return raw


def write_checkpoint(context, detail_id, detail):
    """Atomically patch one member without selecting/decoding the audit output."""
    from backend.main import ScanJob, ScanLease
    from backend.json_projection import _SQLITE_PROJECTION_LOCK
    match = _DETAIL_ID.fullmatch(str(detail_id or ''))
    identity = getattr(context, 'lease_identity', None)
    if (not match or not getattr(context, 'active', False) or int(match[1]) != context.repo_id
            or not identity or len(identity) != 2 or not isinstance(detail, dict)
            or detail.get('tool') != match[2]
            or str(detail.get('terminal_status') or detail.get('status') or '').lower() not in _TERMINAL):
        return False
    token, owner = identity
    if bool(token) != bool(owner):
        return False
    raw = bounded_detail(detail)
    with context.db_factory() as db:
        dialect = db.get_bind().dialect.name
        # Serialize JSON1 readers/writers so concurrent completions cannot each
        # allocate a parsed copy of the same audit document.
        with _SQLITE_PROJECTION_LOCK if dialect == 'sqlite' else nullcontext():
            now = datetime.utcnow()
            query = db.query(ScanJob).filter(
                ScanJob.id == context.job_id, ScanJob.repo_id == context.repo_id,
                ScanJob.lease_token == (token or ''), ScanJob.lease_owner == (owner or ''),
                ScanJob.status.in_(['running', 'paused']), ScanJob.control.in_(['', 'pause', 'resume']))
            if token:
                live = db.query(ScanLease).filter(ScanLease.repo_id == context.repo_id,
                    ScanLease.job_id == context.job_id, ScanLease.lease_token == token,
                    ScanLease.owner == owner, ScanLease.expires_at > now).exists()
                query = query.filter(ScanJob.lease_expires_at > now, live)
            else:
                live = db.query(ScanLease).filter(ScanLease.repo_id == context.repo_id,
                    ScanLease.expires_at > now).exists()
                query = query.filter(ScanJob.lease_expires_at.is_(None), ~live)
            if dialect == 'sqlite':
                # Only known controller-authored detail IDs enter the JSON path.
                document = func.coalesce(func.nullif(ScanJob.output, ''), '{}')
                query = query.filter(func.json_valid(document),
                    func.json_type(document, '$') == 'object',
                    func.coalesce(func.json_type(document, '$.details'), 'object') == 'object')
                patched = func.json_set(document, '$.details.' + json.dumps(detail_id), func.json(raw))
            elif dialect == 'postgresql':
                from sqlalchemy.dialects.postgresql import JSONB, array
                document = cast(func.coalesce(func.nullif(ScanJob.output, ''), '{}'), JSONB)
                query = query.filter(func.jsonb_typeof(document) == 'object',
                    func.coalesce(func.jsonb_typeof(document['details']), 'object') == 'object')
                document = document.op('||')(func.jsonb_build_object('details',
                    func.coalesce(document['details'], cast(literal('{}'), JSONB))))
                patched = cast(func.jsonb_set(document, array(['details', detail_id]), cast(literal(raw), JSONB), True), Text)
            else:
                return False
            changed = query.update({'output': patched}, synchronize_session=False)
            if changed != 1:
                db.rollback()
                return False
            db.commit()
            return True


async def checkpoint_tool_detail(repo_id, detail_id, detail):
    from backend.ai_runtime import active_audit_context
    context = active_audit_context()
    if context is None or context.repo_id != repo_id:
        return None
    match = _DETAIL_ID.fullmatch(str(detail_id or ''))
    if not match or not isinstance(detail, dict) or str(detail.get('terminal_status') or detail.get('status') or '').lower() not in _TERMINAL:
        return None
    # Serialize inside the worker too; source snippets and console text can be
    # large. Await completion before announcing a durable terminal detail.
    task = asyncio.create_task(asyncio.to_thread(write_checkpoint, context, detail_id, detail))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        try:
            await task
        except Exception:
            LOG.warning('Task detail checkpoint failed during cancellation', exc_info=True)
        raise
    except Exception:
        LOG.warning('Task detail checkpoint unavailable for audit %s task %s', context.job_id, detail_id, exc_info=True)
        return False


def recorded_task_console(db, job, detail_id, terminalize):
    """Bounded historical fallback. A saved state is not saved lead evidence."""
    from backend.main import ScanJob
    from backend.json_projection import read_json_array_projection, _SQLITE_PROJECTION_LOCK
    match = re.fullmatch(r'([1-9][0-9]*)-(?:task|tool)-(.{1,160})', str(detail_id or ''))
    if not match or int(match[1]) != job.repo_id:
        return None
    name = match[2]
    fields = [(x,) for x in ('name', 'state', 'status', 'terminal_status', 'summary', 'reason', 'phase', 'detail_id')]
    task = None
    # Current progress is checkpointed throughout Phase 1; output.tasks is the
    # legacy final snapshot. Each projection is bounded and never reads maps.
    for column, path in ((ScanJob.progress_json, ('task_timeline',)), (ScanJob.output, ('tasks',))):
        for offset in range(0, 2400, 120):
            try:
                rows = read_json_array_projection(db, column, ScanJob.id == job.id, path, fields,
                    limit=120, offset=offset, string_limits={field: 2000 for field in fields})
            except (TypeError, ValueError):
                break
            task = next((row for row in rows if row.get('name') == name
                         and row.get('detail_id') in (None, '', detail_id)), None)
            if task or len(rows) < 120:
                break
        if task:
            break
    if task is None:
        return None
    task['state'] = task.get('state') or task.get('status') or 'unknown'
    task = terminalize(task, str(job.status or ''))
    logs = []
    try:
        dialect = db.get_bind().dialect.name
        with _SQLITE_PROJECTION_LOCK if dialect == 'sqlite' else nullcontext():
            if dialect == 'sqlite':
                count_expr = func.json_array_length(ScanJob.output, '$.logs')
            else:
                from backend.json_projection import _document
                _, document = _document(db, ScanJob.output)
                from sqlalchemy.dialects.postgresql import JSONB
                logs_member = document['logs']
                count_expr = func.jsonb_array_length(case(
                    (func.jsonb_typeof(logs_member) == 'array', logs_member),
                    else_=cast(literal('[]'), JSONB)))
            count = db.execute(select(count_expr).where(ScanJob.id == job.id)).scalar() or 0
            rows = read_json_array_projection(db, ScanJob.output, ScanJob.id == job.id, ('logs',),
                [('level',), ('message',), ('time',), ('detail_id',)], limit=200, offset=max(0, count - 200),
                string_limits={('level',): 20, ('message',): 4000, ('time',): 80, ('detail_id',): 200})
        # Explicit IDs take precedence; a different tool's explicit ID never
        # leaks into this console merely because it mentions the task name.
        pattern = re.compile(r'(?<![A-Za-z0-9_.:-])' + re.escape(name) + r'(?![A-Za-z0-9_.:-])', re.I)
        logs = [row for row in rows if row.get('detail_id') == detail_id or
                (not row.get('detail_id') and pattern.search(str(row.get('message') or '')))]
    except (TypeError, ValueError):
        pass
    state = str(task.get('state') or 'unknown')
    terminal = str(task.get('terminal_status') or '').lower()
    if terminal not in {'completed', 'failed', 'skipped', 'running'}:
        terminal = {'ok': 'completed', 'completed': 'completed', 'failed': 'failed', 'skipped': 'skipped',
            'not-installed': 'skipped', 'running': 'running'}.get(state.lower(), 'unresolved')
    return {'kind': 'task-console', 'result_type': 'task-console', 'task': name,
        'phase': task.get('phase') or '', 'status': state, 'terminal_status': terminal,
        'reason': task.get('reason') or task.get('summary') or '', 'console': logs,
        'console_text': '\n'.join(f"[{row.get('level', 'info')}] {row.get('message', '')}" for row in logs),
        'structured_detail_available': False,
        'detail_notice': 'Structured scanner detail was not checkpointed for this audit. This view contains only its recorded task state and available console lines.',
        'console_scope': 'matching-task-lines-from-last-200-audit-events'}
