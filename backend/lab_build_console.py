"""Exact-audit lab setup console projection; no runtime or proof authority."""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy

_CAPTURE = ContextVar('lotus_lab_build_console', default=None)
_FIELDS = ('repo_id', 'scan_job_id', 'console', 'console_text', 'console_scope', 'compiler_output')


@contextmanager
def capture_build_console(repo_id, job_id):
    from backend.ai_runtime import active_audit_context
    context = active_audit_context()
    valid = (context is not None and type(job_id) is int and job_id > 0
             and context.repo_id == repo_id and context.job_id == job_id)
    token = _CAPTURE.set((context, repo_id, job_id) if valid else None)
    try:
        yield
    finally:
        _CAPTURE.reset(token)


def preserve_build_console(previous, target, repo_id, job_id):
    if (isinstance(previous, dict) and previous.get('repo_id') == repo_id
            and type(job_id) is int and previous.get('scan_job_id') == job_id):
        for field in _FIELDS:
            if field in previous:
                target[field] = deepcopy(previous[field])


def record_build_event(repo_id, message, detail, details, tasks):
    """Called only after the ordinary send ownership/control fence succeeded."""
    from backend.ai_runtime import active_audit_context
    from backend.scanners import _redact_scanner_output
    captured = _CAPTURE.get()
    if captured is None:
        return
    context, expected_repo, job_id = captured
    if (repo_id != expected_repo or active_audit_context() is not context
            or context.repo_id != repo_id or context.job_id != job_id):
        return
    task = next((row for row in tasks.get(repo_id, []) if row.get('name') == 'lab-build'
                 and row.get('scan_job_id') == job_id and row.get('state') in ('queued', 'running')), None)
    if task is None:
        return
    did = f'{repo_id}-task-lab-build'
    current = {'kind': 'task-console', 'result_type': 'task-console', 'task': 'lab-build', 'phase': 'Lab',
               'status': task['state'], 'terminal_status': 'running', 'reason': task.get('summary', ''),
               'repo_id': repo_id, 'scan_job_id': job_id, 'console': []}
    preserve_build_console(details.get(did), current, repo_id, job_id)
    row = {key: message[key] for key in ('time', 'level', 'detail_id') if key in message}
    row['message'] = _redact_scanner_output(message.get('message', ''))[:1000]
    current['reason'] = row['message']
    rows = current['console']
    if not rows or any(rows[-1].get(key) != row.get(key) for key in ('message', 'level', 'detail_id')):
        rows.append(row)
    current['console'] = rows[-80:]
    if isinstance(detail, dict) and detail.get('type') in ('image-build-progress', 'image-build-log'):
        output = {key: detail[key] for key in ('status', 'job', 'namespace', 'job_uid', 'pod_uid', 'container_id',
                    'output_scope', 'output_truncated') if key in detail}
        # Keep the original structured build artifact at its own detail ID.
        # The parent task receives only the same bounded redacted display tail.
        if isinstance(detail.get('text'), str):
            output['text'] = _redact_scanner_output(detail['text'])
            output['output_truncated'] = bool(detail.get('truncated') or detail.get('output_truncated') or len(detail['text']) > 12000)
        current['compiler_output'] = output
    current['console_scope'] = 'Exact-audit lab setup messages (last 80) and latest bounded compiler tail; not a full build transcript or runtime proof'
    current['console_text'] = '\n'.join(f"[{r.get('level', 'info')}] {r['message']}" for r in current['console'])
    compiler = current.get('compiler_output', {})
    if compiler.get('text'):
        current['console_text'] += '\n\n--- Latest redacted compiler output ---\n' + compiler['text']
    details[did] = current
