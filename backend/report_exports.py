"""Owned, bounded exports of immutable publications and exact recorded evidence."""
import hashlib
import json
import tempfile
import zipfile

from fastapi import HTTPException
from starlette.responses import StreamingResponse
from sqlalchemy import LargeBinary, cast, func
from sqlalchemy.orm import load_only

from backend.terminal_json import ObjectView

ARCHIVE_LIMIT = 256 * 1024 * 1024
OUTPUT_LIMIT = 128 * 1024 * 1024
PUBLICATION_LIMIT = 64 * 1024 * 1024
RECORD_FIELD_LIMIT = 1024 * 1024
CHUNK = 65536
# Artifact records only. Never export Settings, captured credentials/environment,
# filesystem paths, a current checkout, or another audit's mutable runtime state.
JOB_ARTIFACT_FIELDS = (
    'details', 'tasks', 'logs', 'progress', 'coverage_map', 'phase2_plan',
    'phase2_execution', 'primary_triage', 'poc_chains', 'failed_pocs',
    'fix_verification', 'lab_status', 'lab_network_finalization',
    'scanner_diagnostics', 'coverage_gaps', 'tools_run', 'discovery_metrics',
)


class OwnedExportResponse(StreamingResponse):
    def __init__(self, stream, *, media_type, filename):
        self.export_stream = stream
        def chunks():
            while data := stream.read(CHUNK):
                yield data
        super().__init__(chunks(), media_type=media_type,
            headers={'Content-Disposition': f'attachment; filename="{filename}"'})

    def close_export(self):
        self.export_stream.close()

    async def __call__(self, scope, receive, send):
        try:
            return await super().__call__(scope, receive, send)
        finally:
            self.close_export()


class _CappedFile:
    def __init__(self, stream, limit):
        self.stream, self.limit = stream, limit

    def write(self, data):
        if self.stream.tell() + len(data) > self.limit:
            raise HTTPException(413, 'Report evidence exceeds the export byte limit')
        return self.stream.write(data)

    def __getattr__(self, name):
        return getattr(self.stream, name)


def _text_chunks(value, start=0, end=None):
    end = len(value) if end is None else end
    for offset in range(start, end, CHUNK):
        yield value[offset:min(offset + CHUNK, end)].encode('utf-8')


def _json_chunks(value):
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, default=str, allow_nan=False)
    for fragment in encoder.iterencode(value):
        yield from _text_chunks(fragment)


def _publication(db, m, report_id):
    sizes = db.query(m.Report.id, func.length(cast(m.Report.manifest_json, LargeBinary)),
        func.length(cast(m.Report.published_markdown, LargeBinary))).filter(m.Report.id == report_id).first()
    if sizes is None:
        raise HTTPException(404, 'Report not found')
    if any((size or 0) > PUBLICATION_LIMIT for size in sizes[1:]):
        raise HTTPException(413, 'Report publication exceeds the export byte limit')
    report = db.query(m.Report).options(load_only(
        m.Report.id, m.Report.repo_id, m.Report.published_markdown,
        m.Report.manifest_json, m.Report.manifest_hash, raiseload=True,
    )).filter(m.Report.id == report_id).one()
    manifest = m._load_report_manifest(report)
    if not manifest:
        raise HTTPException(409, 'report publication snapshot is unavailable or tampered')
    return report, manifest


def _build_export(m, report_id, bundle):
    stream = tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode='w+b')
    db = None
    try:
        db = m.get_db()
        # SQLite's legacy transaction mode does not start a read snapshot for
        # SELECT alone. Keep the exact job and paginated notebook pages stable.
        if db.get_bind().dialect.name == 'sqlite':
            db.connection().exec_driver_sql('BEGIN')
        report, manifest = _publication(db, m, report_id)
        markdown = report.published_markdown or ''
        if not bundle:
            if not markdown:
                raise HTTPException(409, 'Published Markdown snapshot is unavailable; editable draft was not substituted')
            target = _CappedFile(stream, PUBLICATION_LIMIT)
            for chunk in _text_chunks(markdown):
                target.write(chunk)
            stream.seek(0)
            return OwnedExportResponse(stream, media_type='text/markdown; charset=utf-8',
                                       filename=f'lotus-report-{report_id}.md')
        evidence = manifest.get('evidence') if isinstance(manifest.get('evidence'), dict) else {}
        job_id = evidence.get('scan_job_id')
        if job_id is not None and (type(job_id) is not int or job_id <= 0):
            raise HTTPException(409, 'Report audit binding is invalid')
        context = m._report_notebook_context(report, manifest)
        binding = context.get('binding') if isinstance(context.get('binding'), dict) else {}
        if (binding.get('repo_id') is not None and binding['repo_id'] != report.repo_id
                or binding.get('scan_job_id') is not None and binding['scan_job_id'] != job_id):
            raise HTTPException(409, 'Report notebook binding does not match its publication')
        index = {'schema_version': 1, 'report_id': report_id, 'repo_id': report.repo_id,
            'scan_job_id': job_id, 'context_hash': context.get('context_hash'),
            'publication_verification': ('keyed_signature' if report.manifest_hash.strip().lower().startswith('hmac-sha256:')
                                         else 'legacy_empty_digest'),
            'scope': 'Report evidence ZIP; retained records, not all source or runtime artifacts',
            'files': [], 'missing': [], 'missing_artifact_fields': [],
            'notebook_records': 0, 'notebook_field_omissions': 0,
            'omissions': ['Current checkout and complete source trees',
                'Settings, provider credentials, environment and raw notebook runtime provenance',
                'Runtime images, filesystem artifacts and unrecorded console output',
                'Other reports/audits and task fields outside the declared artifact allowlist'],
            'job_artifact_fields': list(JOB_ARTIFACT_FIELDS), 'archive_limit_bytes': ARCHIVE_LIMIT,
            'notebook_field_limit_characters': RECORD_FIELD_LIMIT}
        with zipfile.ZipFile(_CappedFile(stream, ARCHIVE_LIMIT), 'w', compression=zipfile.ZIP_STORED) as archive:
            def put(name, chunks):
                digest, size = hashlib.sha256(), 0
                with archive.open(name, 'w', force_zip64=True) as entry:
                    for chunk in chunks:
                        entry.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                index['files'].append({'path': name, 'bytes': size, 'sha256': digest.hexdigest()})

            if markdown:
                put('report.md', _text_chunks(markdown))
            else:
                index['missing'].append('Published Markdown snapshot is unavailable; editable draft was not substituted')
            put('publication/manifest.json', _text_chunks(report.manifest_json))
            put('publication/integrity.json', _json_chunks({'manifest_hash': report.manifest_hash,
                'signature_purpose': 'lotus-report-manifest',
                'note': 'This signature covers manifest.json only. Published Markdown and supplemental observations have separate export hashes; they are not newly signed by this export.'}))
            put('notebook/context.json', _json_chunks(context))
            from backend.report_architecture import recorded_report_source_artifacts
            source = recorded_report_source_artifacts(context)
            put('source/recorded-declarations.json', _json_chunks(source))
            if source.get('status') != 'recorded':
                index['missing'].append('Source declarations were not recorded in this publication')
            job = None
            if job_id is not None and report.repo_id is not None:
                job = db.query(m.ScanJob.id, m.ScanJob.repo_id, m.ScanJob.status,
                    m.ScanJob.started_at, m.ScanJob.finished_at,
                    func.length(cast(m.ScanJob.output, LargeBinary)).label('output_bytes')) .filter(
                        m.ScanJob.id == job_id, m.ScanJob.repo_id == report.repo_id).first()
            if job is None:
                index['missing'].append('Original exact audit row is unavailable; no other job was substituted')
            elif (job.output_bytes or 0) > OUTPUT_LIMIT:
                index['missing'].append('Retained audit output exceeds the 128MiB input limit; task artifacts omitted')
            else:
                put('audit/metadata.json', _json_chunks({'id': job.id, 'repo_id': job.repo_id,
                    'status': job.status, 'started_at': job.started_at, 'finished_at': job.finished_at,
                    'scope': 'Retained audit row at export time; supplemental to immutable publication'}))
                raw = db.query(m.ScanJob.output).filter(m.ScanJob.id == job_id,
                    m.ScanJob.repo_id == report.repo_id).scalar() or '{}'
                try:
                    view = ObjectView(raw)
                except ValueError:
                    index['missing'].append('Retained audit output is malformed; task artifacts omitted')
                else:
                    for key in JOB_ARTIFACT_FIELDS:
                        field = view._last.get(key)
                        if field is not None:
                            put(f'audit/{key}.json', _text_chunks(raw, field.start, field.end))
                        else:
                            index['missing_artifact_fields'].append(key)
                    del view
                del raw
            # Stream every exactly bound execution in keyset pages; never use
            # the notebook UI's first-50 history cap as an archival limit.
            notebook_base = db.query(m.NotebookExecution).filter(m.NotebookExecution.report_id == report_id)
            if job_id is not None and report.repo_id is not None and context.get('context_hash'):
                matching = notebook_base.filter(m.NotebookExecution.repo_id == report.repo_id,
                    m.NotebookExecution.scan_job_id == job_id,
                    m.NotebookExecution.context_hash == context['context_hash'])
                excluded = notebook_base.count() - matching.count()
                if excluded:
                    index['missing'].append(f'{excluded} notebook records have a different or missing binding and were excluded')
                def execution_chunks():
                    after = 0
                    while True:
                        page = matching.with_entities(m.NotebookExecution.id, m.NotebookExecution.finding_id,
                            m.NotebookExecution.cell_id, m.NotebookExecution.language, m.NotebookExecution.mode,
                            m.NotebookExecution.status, m.NotebookExecution.code_hash,
                            m.NotebookExecution.started_at, m.NotebookExecution.finished_at,
                            func.substr(m.NotebookExecution.code, 1, RECORD_FIELD_LIMIT + 1).label('code'),
                            func.substr(m.NotebookExecution.result_json, 1, RECORD_FIELD_LIMIT + 1).label('result_json'),
                        ).filter(m.NotebookExecution.id > after).order_by(m.NotebookExecution.id).limit(16).all()
                        if not page:
                            break
                        for row in page:
                            record = dict(row._mapping)
                            record['evidence_scope'] = 'recorded_observation_not_proof'
                            omitted = []
                            for key in ('code', 'result_json'):
                                if len(record[key] or '') > RECORD_FIELD_LIMIT:
                                    record[key] = None
                                    omitted.append(key)
                                    index['notebook_field_omissions'] += 1
                            record['omitted_fields'] = omitted
                            index['notebook_records'] += 1
                            yield from _json_chunks(record)
                            yield b'\n'
                        after = page[-1].id
                put('notebook/executions.ndjson', execution_chunks())
            else:
                index['missing'].append('Exact notebook execution binding is unavailable; no executions substituted')
            put('README.txt', _text_chunks(
                'Report evidence ZIP\nThe published report and publication manifest are immutable. '
                'Audit task records and notebook executions are separately recorded observations at export time, '
                'not new verified findings. See export-manifest.json for hashes, limits and omissions. '
                'This bundle is not a complete source tree or runtime backup. No lab is launched by exporting.\n'))
            put('export-manifest.json', _json_chunks(index))
        stream.seek(0)
        return OwnedExportResponse(stream, media_type='application/zip',
                                   filename=f'lotus-report-{report_id}-evidence.zip')
    except BaseException:
        stream.close()
        raise
    finally:
        try:
            if db is not None:
                db.close()
        except BaseException:
            stream.close()
            raise


async def export_report(report_id, *, bundle):
    from backend import main
    from backend.api import _owned_audit_read
    owned = []
    def build():
        response = _build_export(main, report_id, bundle)
        owned.append(response)
        return response
    async with main._report_render_lock():
        try:
            return await _owned_audit_read(build)
        except BaseException:
            # _owned_audit_read drains its worker before raising cancellation.
            # Close its result even when ASGI never receives the response.
            for response in owned:
                response.close_export()
            raise
