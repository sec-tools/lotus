"""Request-scoped Findings reads: bounded enumeration, unchanged proof authority."""
from __future__ import annotations
from contextlib import contextmanager
from sqlalchemy import cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from backend.json_projection import _sqlite_projection_scope
from sqlalchemy.orm import load_only


@contextmanager
def finding_read_snapshot(db):
    """Keep audit selection, proof filters and page payloads on one DB snapshot."""
    if db.get_bind().dialect.name == 'postgresql':
        connection = db.connection(execution_options={'isolation_level': 'REPEATABLE READ'})
    else:
        connection = db.connection()
    with connection.begin_nested():
        yield


class _NonemptyObject(dict):
    """Retain a projected object's truthiness without adding fictional fields."""
    def __bool__(self):
        return True


@_sqlite_projection_scope
def _read_output(db, repo_id, job_id):
    from backend.main import ScanJob
    from backend.json_projection import read_json_projection, _prepared_document, _member
    identity = ('target_revision', 'revision', 'target_tree_hash', 'tree_hash')
    snapshot = ('path', 'source_path', 'manifest_hash', 'target_revision', 'revision', 'tree_hash')
    paths = [('target_identity', name) for name in identity]
    for parent in (('target_snapshot',), ('audit_plan', 'target_snapshot')):
        paths.extend((*parent, name) for name in snapshot)
    predicate = (ScanJob.id == job_id) & (ScanJob.repo_id == repo_id)
    output = read_json_projection(db, ScanJob.output, predicate, paths,
        object_paths=[('target_identity',), ('target_snapshot',), ('audit_plan',), ('audit_plan', 'target_snapshot')])
    for field in ('target_identity', 'target_snapshot'):
        canonical = output.get(field)
        if not isinstance(canonical, dict) or canonical:
            continue
        # Unknown canonical fields still affect legacy identity/snapshot
        # precedence. Read only existence, inside this same read snapshot.
        dialect, document, source, scope = _prepared_document(db, ScanJob.output, predicate)
        if dialect == 'sqlite':
            members = func.json_each(document, '$.' + field).table_valued('key')
            nonempty = select(literal(1)).select_from(members).exists()
        else:
            nonempty = _member(document, (field,)) != cast(literal('{}'), JSONB)
        if db.execute(select(nonempty).select_from(source).where(scope)).scalar():
            output[field] = _NonemptyObject()
    return output


class FindingReadContext:
    """Cache only within one synchronous request; never trust cached proof across requests."""
    def __init__(self, db, *, latest_jobs=None):
        self.db = db
        self.latest = latest_jobs
        self.repos = {}
        self.outputs = {}
        self.receipts = {}
        self.states = {}
        self.report_links = None

    def repo(self, repo_id):
        from backend.main import Repo
        if repo_id not in self.repos:
            self.repos[repo_id] = self.db.query(Repo).filter(Repo.id == repo_id).first()
        return self.repos[repo_id]

    def latest_job(self, repo_id):
        from backend.api import _latest_scan_jobs
        if self.latest is None:
            self.latest = {}
        if repo_id not in self.latest:
            self.latest[repo_id] = _latest_scan_jobs(self.db, [repo_id], metadata_only=True).get(repo_id)
        return self.latest[repo_id]

    def output(self, repo_id, job_id):
        key = (repo_id, job_id)
        if key not in self.outputs:
            try:
                self.outputs[key] = _read_output(self.db, repo_id, job_id)
            except (ValueError, TypeError):
                self.outputs[key] = {}
        return self.outputs[key]

    def identity(self, finding):
        def load(job_id):
            value = self.output(finding.repo_id, job_id).get('target_identity')
            return value if isinstance(value, dict) else {}
        return load

    def receipt_valid(self, finding):
        from backend import main
        if finding.id not in self.receipts:
            self.receipts[finding.id] = main._finding_receipt_valid(finding, _identity_loader=self.identity(finding))
        return self.receipts[finding.id]

    def state(self, finding):
        from backend import main
        if finding.id not in self.states:
            self.states[finding.id] = main._authoritative_finding_state(finding, _identity_loader=self.identity(finding))
            if self.states[finding.id][1]:
                self.receipts[finding.id] = True
        return self.states[finding.id]

    def reports_for(self, findings):
        self.report_links = finding_report_ids(self.db, {int(row.id) for row in findings})


def finding_report_ids(db, finding_ids):
    """Select candidate IDs cheaply, then verify each matching publication once.

    Projections are never publication authority. Current row eligibility is not
    used here: an immutable historical report remains navigable after triage or
    row edits. Headers and one manifest at a time avoid retaining all reports.
    """
    from backend import main
    from backend.json_projection import read_json_array_projection
    result = {int(value): [] for value in finding_ids}
    if not result:
        return result
    before = None
    while True:
        query = db.query(main.Report.id)
        if before is not None:
            query = query.filter(main.Report.id < before)
        headers = query.order_by(main.Report.id.desc()).limit(64).all()
        if not headers:
            break
        before = headers[-1].id
        for header in headers:
            try:
                candidates = read_json_array_projection(db, main.Report.manifest_json,
                    main.Report.id == header.id, ('findings',), [('id',), ('report_eligible',)])
                possible = set()
                for row in candidates:
                    if row.get('report_eligible'):
                        try:
                            value = int(row.get('id') or 0)
                        except (TypeError, ValueError, OverflowError):
                            continue
                        if value in result:
                            possible.add(value)
                if not possible:
                    continue
            except (TypeError, ValueError):
                continue
            report = db.query(main.Report).options(load_only(main.Report.id,
                main.Report.manifest_json, main.Report.manifest_hash, raiseload=True)).filter(main.Report.id == header.id).first()
            if report is None:
                continue
            manifest = None
            try:
                manifest = main._load_report_manifest(report)
                matched = set()
                for row in manifest.get('findings') or []:
                    if not isinstance(row, dict) or not row.get('report_eligible'):
                        continue
                    try:
                        value = int(row.get('id') or 0)
                    except (TypeError, ValueError, OverflowError):
                        continue
                    if value in result:
                        matched.add(value)
                for value in matched:
                    result[value].append(int(report.id))
            finally:
                db.expunge(report)
                report = manifest = None
    return result


def select_findings(db, context, *, repo_id=None, status=None, report_eligible=None,
                    triage=None, limit=None, offset=0, include_history=False):
    """Enumerate small headers and apply audit/proof filters before pagination."""
    from backend import main
    from backend.api import _latest_scan_jobs
    if type(offset) is not int or offset < 0 or (limit is not None and (type(limit) is not int or limit < 0)):
        raise main.HTTPException(422, 'limit and offset must be nonnegative integers')
    if limit == 0:
        return []
    latest = _latest_scan_jobs(db, [repo_id] if repo_id is not None else None, metadata_only=True)
    context.latest = latest
    fields = (main.Finding.id, main.Finding.repo_id, main.Finding.scan_job_id,
              main.Finding.created_at, main.Finding.status, main.Finding.report_eligible,
              main.Finding.cvss)
    query = db.query(*fields)
    if repo_id is not None:
        query = query.filter(main.Finding.repo_id == repo_id)
    if triage is not None:
        query = query.filter(main.Finding.triage == triage)
    if not include_history:
        # Exact legacy timestamp/grace and missing-job semantics are checked
        # below; this inexpensive prefilter only eliminates known old job IDs.
        query = query.filter(or_(main.Finding.scan_job_id.is_(None),
                                 main.Finding.scan_job_id.in_([job.id for job in latest.values()])))
    query = query.order_by(main.Finding.cvss.desc(), main.Finding.created_at.desc(), main.Finding.id.desc())
    selected, accepted, page_offset = [], 0, 0
    done = False
    while not done:
        headers = query.limit(128).offset(page_offset).all()
        if not headers:
            break
        page_offset += len(headers)
        for header in headers:
            if not include_history and not main._row_belongs_to_current_audit(header, latest.get(header.repo_id)):
                continue
            # Unfiltered offsets need no proof work. Only normalized filters
            # require verification before pagination; selected payloads always
            # go through the authoritative validator.
            if status is not None or report_eligible is not None:
                raw_status = str(header.status or 'unproven')
                if header.report_eligible or raw_status in {'confirmed', 'report-eligible'}:
                    row = db.query(main.Finding).filter(main.Finding.id == header.id).first()
                    if row is None:
                        continue
                    try:
                        state, eligible = context.state(row)
                    finally:
                        db.expunge(row)
                        row = None
                else:
                    state, eligible = raw_status, False
                if status is not None and state != status:
                    continue
                if report_eligible is not None and eligible != bool(report_eligible):
                    continue
            accepted += 1
            if accepted <= offset:
                continue
            selected.append(header.id)
            if limit is not None and len(selected) >= limit:
                done = True
                break
    rows = []
    for start in range(0, len(selected), 128):
        ids = selected[start:start + 128]
        by_id = {row.id: row for row in db.query(main.Finding).filter(main.Finding.id.in_(ids)).all()}
        rows.extend(by_id[key] for key in ids if key in by_id)
    return rows
