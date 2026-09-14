"""Small stored audit projections for list and collapsed progress reads."""
from backend.json_projection import read_json_array_projection, read_json_projection

_MAP_FIELDS = [('updated_at',), ('summary',), ('gate', 'complete'), ('gate', 'phase3_allowed'),
               ('gate', 'reporting_mode'), ('gate', 'reason')]
_MAP_PATHS = [('coverage_map',), ('progress', 'coverage_map')]
_METADATA_PATHS = [('progress',), ('discovery_metrics',), ('candidate_findings',), ('leads_total',),
                   ('coverage',), ('completion_state',), ('audit_integrity','complete'), ('lab_status','healthy'),
                   ('task_recovery',), ('audit_recovery',),
                   ('target_snapshot',), ('audit_plan','target_snapshot')]


def _scan_job_model():
    from backend.main import ScanJob
    return ScanJob


def _map_fields(prefixes):
    return [prefix + parts for prefix in prefixes for parts in _MAP_FIELDS]


def _project_audit_metadata(db, job):
    """No full output/map is returned to the Python heap for metadata reads."""
    model = _scan_job_model()
    result = read_json_projection(db, model.output, model.id == int(job.id),
        [*_METADATA_PATHS, *_map_fields(_MAP_PATHS)],
        omit_paths=[('progress','coverage_map')], object_paths=_MAP_PATHS)
    result['tool_results'] = read_json_array_projection(db, model.output, model.id == int(job.id),
                                                       ('tool_results',), [('status',), ('reason',)])
    if isinstance(result.get('progress'), dict):
        result['progress'].pop('coverage_map_omitted', None)
        result['progress'].pop('coverage_map_summary', None)
    return result


def load_audit_metadata(db, job):
    from backend.audit_metadata_cache import read_through
    from backend.json_projection import _sqlite_projection_scope

    @_sqlite_projection_scope
    def read(db):
        return read_through(db, int(job.id), lambda: _project_audit_metadata(db, job))
    return read(db)


def load_progress_checkpoint(db, job):
    """Keep all public task/queue/recovery fields; replace only the heavy map."""
    model = _scan_job_model()
    # The progress contract is fixed; an allowlist avoids copying arbitrary
    # source/model payloads from malformed legacy checkpoint documents.
    fields = ['schema_version','repo_id','scan_job_id','status','phase','phase_label','current_task','message',
              'started_at','updated_at','elapsed_seconds','eta_seconds','eta_basis','progress_pct','tasks',
              'bottlenecks','leads_total','observations_total','observations_label','inventory_status','recon_tools',
              'qualified_leads','confirmed_findings','evidence_status','coverage','task_recovery','audit_recovery',
              'ai_pause','stream_dropped','task_timeline','active_task','slow_tasks','task_slow_threshold_seconds',
              'is_slow','terminal']
    return read_json_projection(db, model.progress_json, model.id == int(job.id),
        [*((name,) for name in fields), *_map_fields([('coverage_map',)])], object_paths=[('coverage_map',)])
