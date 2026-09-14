"""One durable, priority platform reset intent; existing cleanup remains authoritative."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import time
import uuid

import fcntl

PENDING = {'queued', 'cancelling', 'waiting', 'resetting'}
MAX_WAIT_SECONDS = 20 * 60
_THREAD_LOCK = threading.Lock()
_THREAD = None


def _path():
    from backend.main import _data_dir
    return Path(_data_dir()) / 'platform-reset-intent.json'


@contextmanager
def _file_lock(name, *, wait=True):
    path = _path().with_name(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        os.close(fd)


def read(operation_id=None):
    path = _path()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as handle:
        raw = handle.read(65537)
    if len(raw) > 65536:
        raise ValueError('Saved reset intent exceeds its size limit')
    value = json.loads(raw)
    if (not isinstance(value, dict) or value.get('schema_version') != 1
            or value.get('scope') not in {'data', 'full'}
            or value.get('status') not in PENDING | {'completed', 'failed'}
            or not isinstance(value.get('operation_id'), str)):
        raise ValueError('Saved reset intent is invalid; maintenance remains closed')
    if operation_id is not None and value['operation_id'] != operation_id:
        return None
    return value


def pending():
    try:
        value = read()
        return bool(value and value['status'] in PENDING)
    except Exception:
        # Corrupt intent cannot silently reopen admission during destructive work.
        return True


def _write(value):
    path = _path(); path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
    if len(raw) > 65536:
        raise ValueError('Reset status exceeds its size limit')
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        temp.unlink(missing_ok=True)


def enqueue(scope):
    if scope not in {'data', 'full'}:
        raise ValueError('Unknown reset scope')
    with _file_lock('platform-reset-intent.lock'):
        previous = read()
        if previous and previous['status'] in PENDING:
            if previous['scope'] != scope:
                raise ValueError('A different reset scope is already queued; wait for it to settle')
            value = previous
        else:
            now = time.time()
            value = {'schema_version': 1, 'operation_id': uuid.uuid4().hex, 'scope': scope,
                'status': 'queued', 'requested_at': datetime.now(timezone.utc).isoformat(),
                'deadline_epoch': now + MAX_WAIT_SECONDS, 'updated_at': now, 'attempt': 0,
                'message': 'Reset queued with priority. New work is blocked; cancelling active audits.',
                'data_deleted': False}
            _write(value)
    ensure_running()
    return value


def _update(operation_id, **fields):
    with _file_lock('platform-reset-intent.lock'):
        current = read(operation_id)
        if current is None or current['status'] not in PENDING:
            return None
        current.update(fields, updated_at=time.time())
        _write(current)
        return current


def _cancel_and_reconcile():
    from backend import main, scan_worker
    with main.SessionLocal() as db:
        rows = db.query(main.ScanJob.id, main.ScanJob.repo_id).filter(
            main.ScanJob.status.in_(['queued', 'running', 'paused'])).all()
    for job_id, repo_id in rows:
        try:
            scan_worker.set_scan_control(repo_id, 'cancel', expected_job_id=job_id)
        except RuntimeError:
            # An owner may have settled between the scalar inventory and CAS.
            # The next exact runtime/lease check still controls deletion.
            pass
    scan_worker.reconcile_on_startup(main.SessionLocal, main.Repo, main.Finding, main.ScanJob,
                                    resume_queued=False)
    return len(rows)


def _summary(value):
    summary = {'scope': value.get('scope'), 'rows_deleted': dict(value.get('rows_deleted') or {}),
        'paths_removed': [str(p)[:300] for p in (value.get('paths_removed') or [])[:80]],
        'preserved': [str(p)[:300] for p in (value.get('preserved') or [])[:40]],
        'errors': [str(e)[:500] for e in (value.get('errors') or [])[:20]]}
    runtime = value.get('runtime_cleanup')
    images = runtime.get('images') if isinstance(runtime, dict) else None
    if isinstance(images, dict):
        summary['runtime_cleanup'] = {'images': {
            'provider': str(images.get('provider') or '')[:40],
            'removed_count': len(images.get('removed') or []),
            'retained_count': len(images.get('retained') or []),
            'retained_reasons': list(dict.fromkeys(str(row.get('reason') or '')[:160]
                for row in (images.get('retained') or []) if isinstance(row, dict)))[:20],
            'errors': [str(error)[:300] for error in (images.get('errors') or [])[:10]],
            'physical_bytes_reclaimed': None,
            'node_cache_cleanup': str(images.get('node_cache_cleanup') or '')[:80],
            'registry_cache_cleanup': str(images.get('registry_cache_cleanup') or '')[:80],
        }}
    return summary


def _run():
    from backend import main
    # The OS releases this lock on controller death. Another process can
    # resume the same intent but cannot overlap its destructive execution.
    with _file_lock('platform-reset-worker.lock', wait=False) as acquired:
        if not acquired:
            return
        value = read()
        if not value or value['status'] not in PENDING:
            return
        operation_id = value['operation_id']
        # A crash after deletion began has an uncertain outcome. Do not apply
        # destructive work again automatically without a new explicit request.
        if value['status'] == 'resetting':
            _update(operation_id, status='failed', message='Controller stopped during reset. Review the retained status and explicitly retry.', retryable=True)
            return
        while value and value['status'] in PENDING:
            if time.time() >= value['deadline_epoch']:
                _update(operation_id, status='failed', message='Reset could not safely drain all owners within 20 minutes. No reset deletion was started; inspect the blocking owner and retry.', retryable=True)
                return
            try:
                _update(operation_id, status='cancelling', message='Cancelling audits and checking exact runtime owners.', attempt=int(value.get('attempt', 0))+1)
                count = _cancel_and_reconcile()
                _update(operation_id, status='waiting', active_audits=count,
                    message='Waiting for audit cancellation and owned runtime cleanup. New work remains blocked.')
                # Existing implementation owns the in-process reset lock, drain,
                # complete runtime attestation and deletion order. Mark actual
                # deletion separately at its final pre-delete boundary.
                result = main._run_platform_reset(value['scope'])
                summary = _summary(result)
                errors = summary['errors']
                deleted = bool(summary['paths_removed']) or any(int(v or 0) > 0 for v in summary['rows_deleted'].values())
                if not errors:
                    if value['scope'] == 'full':
                        main.engine.dispose()
                    _update(operation_id, status='completed', message='Platform reset complete.',
                        summary=summary, data_deleted=deleted, retryable=False)
                    return
                transient = not deleted and all(any(term in error.lower() for term in (
                    'quiesce', 'drain scan workers', 'another platform reset is already in progress')) for error in errors)
                if not transient:
                    _update(operation_id, status='failed', message=errors[0], summary=summary,
                        data_deleted=deleted, retryable=True)
                    return
                _update(operation_id, status='waiting', message=errors[0] + ' Reset remains queued; checking again shortly.', summary=summary)
            except Exception as exc:
                _update(operation_id, status='failed', message='Reset coordination stopped: ' + str(exc)[:400], retryable=True)
                return
            time.sleep(2)
            value = read(operation_id)


def mark_deleting():
    """Called only after the existing owner/cleanup gates all passed."""
    value = read()
    if value and value['status'] in PENDING:
        _update(value['operation_id'], status='resetting', data_deleted=None,
                message='Owned work stopped. Clearing the selected audit data and artifacts.')


def ensure_running():
    global _THREAD
    if not pending():
        return
    with _THREAD_LOCK:
        if _THREAD is not None and _THREAD.is_alive():
            return
        _THREAD = threading.Thread(target=_run, name='lotus-platform-reset', daemon=True)
        _THREAD.start()
