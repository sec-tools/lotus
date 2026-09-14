"""UI ↔ API contract: every control in the vanilla frontend maps to a live route
and a defined JS handler, and every route the UI calls behaves as labeled.
"""
from __future__ import annotations

import json
import io
import re
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent.parent
FRONTEND = ROOT / "frontend" / "index.html"

from backend.main import app, SessionLocal, AuditDecision, ScanJob, Finding, ensure_automatic_evidence_report

client = TestClient(app)

# Route/navigation tests enroll authored targets under the same admission
# contract as Start. Readiness rejection has its own dedicated test suite.
pytestmark = pytest.mark.usefixtures("verified_audit_ai")


def _frontend() -> str:
    return FRONTEND.read_text(encoding="utf-8")


def _route_keys():
    keys = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        if not path:
            continue
        for m in methods:
            if m in ("HEAD", "OPTIONS"):
                continue
            keys.add((m, path))
    return keys


def _normalize_ui_path(raw: str) -> str:
    p = raw.split("?")[0]
    p = re.sub(r"\$\{[^}]+\}", "{id}", p)
    p = re.sub(r"' \+ [^+]+ \+ '", "{id}", p)
    p = re.sub(r'" \+ [^+]+ \+ "', "{id}", p)
    return p


def test_every_onclick_handler_is_defined():
    html = _frontend()
    script = html.split("<script>", 1)[1]
    handlers = set(re.findall(r"""onclick\s*=\s*['"]([A-Za-z_][A-Za-z0-9_]*)""", html))
    skip = {"event", "this", "window", "document", "console"}
    missing = []
    for name in sorted(handlers - skip):
        if (
            f"function {name}" not in script
            and f"async function {name}" not in script
            and f"{name} =" not in script
        ):
            missing.append(name)
    assert missing == [], f"onclick handlers with no function: {missing}"


def test_ui_api_literals_exist_on_server():
    html = _frontend()
    literals = set(re.findall(r"""['"`](/api/[^'"`\s]+)['"`]""", html))
    literals |= set(re.findall(r"""API \+ '(/api/[^']+)'""", html))
    routes = _route_keys()
    route_paths = {p for _, p in routes}

    missing = []
    for lit in sorted(literals):
        path = _normalize_ui_path(lit).rstrip("/")
        if not path.startswith("/api/"):
            continue
        # Dynamic: /api/repos/ + id  → prefix /api/repos/
        if any(path == rp or rp.startswith(path.rstrip("{id}")) for rp in route_paths):
            continue
        # Parameterized FastAPI paths
        matched = False
        for rp in route_paths:
            tmpl = re.sub(r"\{[^}]+\}", "{id}", rp)
            if path == tmpl or path.rstrip("/") == tmpl.rstrip("/"):
                matched = True
                break
            # prefix match for concatenations like /api/repos/
            if path.count("/") >= 2 and rp.startswith(path):
                matched = True
                break
        if not matched and "{" not in path:
            # allow download-style paths that FastAPI serves
            if path in route_paths:
                matched = True
        if not matched:
            # last chance: any route with same static prefix
            static = path.split("{")[0]
            if any(rp.startswith(static) or static.startswith(rp.split("{")[0]) for rp in route_paths):
                matched = True
        if not matched:
            missing.append(path)
    assert missing == [], f"Frontend calls API paths with no backend route: {missing}"


def test_core_tabs_present():
    html = _frontend()
    for tab in (
        "enroll", "dashboard", "repos", "scans", "findings", "reports",
        "harness", "settings", "capabilities", "debug",
    ):
        assert f'data-tab="{tab}"' in html, f"missing tab {tab}"
        assert f"id='{tab}'" in html or f'id="{tab}"' in html, f"missing section {tab}"


def test_primary_navigation_is_small_and_routes_legacy_views_to_dashboard():
    html = _frontend()
    nav = html.split('<nav>', 1)[1].split('</nav>', 1)[0]
    # Audits/Scans are no longer rendered as nav buttons; their route names are
    # retained only for compatibility links and canonicalize to Dashboard.
    assert 'data-tab="enroll">Start' in nav
    assert 'data-tab="dashboard">Dashboard' in nav
    assert 'data-tab="deployments">Deployments' in nav
    assert 'data-tab="findings">Findings' in nav
    assert 'data-tab="harness">Auto' in nav
    assert 'data-tab="info">Docs' not in nav
    assert len(re.findall(r'<button class="tab(?: active)?" data-tab="(?!repos|scans)[^"]+"', nav)) == 9
    assert 'data-tab="repos"' in nav and 'data-tab="scans"' in nav
    assert 'legacy-tab' not in nav
    assert "repos: 'dashboard'" in html and "scans: 'dashboard'" in html
    assert "id='dashboard-repos-list'" in html
    assert "id='dashboard-scans-list'" in html
    assert "loadRepos('dashboard-repos-list', !_dashboardReposExpanded)" in html
    assert "loadScans('dashboard-scans-list', !_dashboardScansExpanded)" in html


def test_auto_and_platform_reset_controls_are_explicit_and_api_backed():
    html = _frontend()
    assert '>Auto<' in html
    assert 'Continuous coverage' in html
    assert 'toggleContinuousCoverage' in html
    assert "/api/repos/' + repoId + '/continuous-config" in html
    assert 'Reset Platform' in html and 'Full Reset Platform' in html
    assert 'function resetPlatformData()' in html
    assert 'function resetPlatformFull()' in html
    assert "'/api/debug/reset/data'" in html and "'/api/debug/reset/full'" in html
    assert "prompt('Type ' + required + ' to confirm:'" in html


def test_labeled_buttons_exist():
    html = _frontend()
    for label in (
        "Add & Scan", "Generate Report", "Backup Database", "Download Backup",
        "Reset Database", "Run Tests", "Refresh Stats", "Connect recorded lab",
        "▶ Repro", "Build Harness", "Deploy to Lab Pod", "Refresh skill index",
        "Enable All Tools", "Disable All Tools", "Test Slack", "Saved artifacts ZIP",
        "Submit answer", "fixes", "Stop test lab",
    ):
        assert label in html, f"missing labeled control: {label}"


def test_repro_runs_inline_and_poc_panel_cells():
    html = _frontend()
    assert "async function runAllNotebookCells" in html
    runnable = html[html.index("function _reportRunnableCells"):html.index("function _syncReportRunAll")]
    assert '#report-body .notebook-cell' in runnable
    assert '#report-poc-cells > div[id^="rpoc-"]' in runnable
    assert 'code.value.trim()' in runnable
    assert "isolated lab pod" in html.lower()
    start = html.index("async function runAllNotebookCells")
    body = html[start:html.index("// ---- Interactive lab shell", start)]
    assert "cells=_reportRunnableCells(),inline=cells.inline,poc=cells.added" in body
    assert "runInlineNotebookCell" in body
    assert "runReportPocCell" in body
    assert "currentReportId !== notebookId" in body


def test_scan_details_make_tool_and_native_target_artifacts_clickable():
    html = _frontend()
    start = html.index("// Tool Results Table")
    body = html[start:start + 7000]
    assert "_showDetailViewer" in body
    assert "toolDetailId" in body
    assert "Native package targets" in body


def test_phase1_lead_detail_has_recorded_locations_and_cvss_without_repro_controls():
    """Scanner observations expose recorded source and scoring, never Lead Repro."""
    html = _frontend()
    start = html.index("// Object with leads array")
    body = html[start:start + 7000]
    assert "CVSS estimate" in body
    assert "showLeadCvss" in body
    assert "_renderLeadLocation" in body
    assert "<th>Location</th>" in body
    assert "_reproLead" not in html
    assert "<th>Reproduce</th>" not in body
    assert "function _renderRecordedSourceLocation" in html
    assert "View recorded locations" in html
    assert "Exact console output" in body
    assert "This score helps prioritize review; it does not confirm a vulnerability." in html
    assert "proof pending" in html


def test_task_timeline_progress_bars_open_exact_console_for_every_task():
    html = _frontend()
    start = html.index("async function _renderTaskTimeline")
    body = html[start:start + 9000]
    assert "Overall task progress" in body
    assert "task-progress-button" in body
    assert "exact console output" in body
    assert "terminal" in body


def test_legacy_numeric_findings_are_normalized_to_leads_before_display():
    from backend.pipeline import normalize_visible_audit_message
    assert normalize_visible_audit_message("✓ high-yield-discovery completed (10 findings)") == "✓ high-yield-discovery completed (10 leads observed)"
    assert "2 Findings proven in local lab" in normalize_visible_audit_message("2 Findings proven in local lab")


def test_stream_lead_navigation_and_repro_never_promote_to_finding():
    repo = _repo("https://example.com/stream-lead-contract")
    detail_id = f"{repo['id']}-tool-high-yield-discovery"
    payload = {
        "tool": "high-yield-discovery", "result_type": "leads", "lead_count": 1,
        "leads": [{"lead_index": 0, "title": "Unsafe join", "file": "src/app.py", "line": 9,
                   "cvss": 8.1, "description": "untrusted path reaches join", "confidence": "high"}],
    }
    db = SessionLocal()
    try:
        job = ScanJob(repo_id=repo["id"], status="completed", output=json.dumps({"details": {detail_id: payload}}))
        db.add(job)
        db.commit()
    finally:
        db.close()
    cvss = client.get(f"/api/stream-detail/{detail_id}/leads/0/cvss")
    assert cvss.status_code == 200
    assert cvss.json()["lifecycle"] == "lead"
    assert cvss.json()["proof_status"] == "unproven"
    repro = client.post(f"/api/stream-detail/{detail_id}/leads/0/repro", json={})
    assert repro.status_code == 200
    assert repro.json()["lifecycle"] == "lead"
    assert repro.json()["proof_status"] == "unproven"
    assert repro.json()["repro_status"] == "not_ready"


def test_stream_lead_source_is_revision_bound_to_immutable_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("LOTUS_DATA_DIR", str(tmp_path / "lotus-data"))
    source = tmp_path / "checkout"
    (source / "src").mkdir(parents=True)
    (source / "src" / "app.py").write_text("dangerous = input()\n", encoding="utf-8")
    from backend.target_snapshots import create_snapshot
    snap = create_snapshot(source, repo_id=999, job_id=1, target_identity={"target_revision": "abc123"})
    repo = _repo("https://example.com/stream-lead-source-contract")
    detail_id = f"{repo['id']}-tool-semgrep"
    payload = {"tool": "semgrep", "result_type": "leads", "lead_count": 1,
               "leads": [{"lead_index": 0, "title": "Input reaches sink", "file": "src/app.py", "line": 1, "cvss": 7.5}]}
    db = SessionLocal()
    try:
        job = ScanJob(repo_id=repo["id"], status="completed", output=json.dumps({
            "details": {detail_id: payload},
            "target_snapshot": {"path": snap["path"], "source_path": snap["source_path"], "tree_hash": snap["tree_hash"]},
            "target_identity": {"target_revision": "abc123", "target_tree_hash": snap["tree_hash"]},
        }))
        db.add(job)
        db.commit()
    finally:
        db.close()
    meta = client.get(f"/api/stream-detail/{detail_id}/leads/0/source?meta=1")
    assert meta.status_code == 200
    assert meta.json()["revision_bound"] is True
    assert meta.json()["target_revision"] == "abc123"
    text = client.get(f"/api/stream-detail/{detail_id}/leads/0/source")
    assert text.status_code == 200
    assert "dangerous = input()" in text.text
    assert text.headers.get("x-lotus-revision-bound") == "true"


def test_stream_lead_source_repairs_legacy_failed_snapshot(tmp_path, monkeypatch):
    """Existing leads remain navigable when only a complete pre-manifest copy exists."""
    monkeypatch.setenv("LOTUS_DATA_DIR", str(tmp_path / "lotus-data"))
    source = tmp_path / "checkout"
    (source / "pkg").mkdir(parents=True)
    (source / "pkg" / "server.go").write_text(
        "package pkg\n\nfunc Vulnerable() {}\n", encoding="utf-8"
    )
    from backend.proof_receipts import content_tree_digest
    from backend.target_snapshots import snapshot_root
    expected_tree = content_tree_digest(source)
    # Author the historical tree-only object layout. New snapshots bind an
    # additional source metadata hash and are a different recovery contract.
    object_root = snapshot_root() / expected_tree.removeprefix("sha256:")
    (object_root / "source" / "pkg").mkdir(parents=True)
    (object_root / "source" / "pkg" / "server.go").write_bytes((source / "pkg" / "server.go").read_bytes())

    repo = _repo("https://example.com/stream-lead-legacy-source")
    detail_id = f"{repo['id']}-tool-semgrep"
    payload = {"tool": "semgrep", "result_type": "leads", "lead_count": 1,
               "leads": [{"lead_index": 0, "title": "Unsafe server", "file": "pkg/server.go", "line": 3, "cvss": 7.5}]}
    db = SessionLocal()
    try:
        job = ScanJob(repo_id=repo["id"], status="completed", output=json.dumps({
            "details": {detail_id: payload},
            "target_snapshot": {"status": "failed", "reason": "manifest write interrupted"},
            "target_identity": {"target_revision": "rev-legacy", "target_tree_hash": expected_tree},
        }))
        db.add(job)
        db.commit()
    finally:
        db.close()

    meta = client.get(f"/api/stream-detail/{detail_id}/leads/0/source?meta=1")
    assert meta.status_code == 200, meta.text
    assert meta.json()["revision_bound"] is True
    assert meta.json()["target_revision"] == "rev-legacy"
    assert meta.json()["function"] == "Vulnerable"
    assert meta.json()["function_line"] == 3
    text = client.get(f"/api/stream-detail/{detail_id}/leads/0/source")
    assert text.status_code == 200
    assert "func Vulnerable()" in text.text
    assert text.headers.get("x-lotus-revision-bound") == "true"


def test_lead_source_viewer_renders_function_context_and_line_markers():
    html = _frontend()
    start = html.index("function _sourceAcceptPage")
    end = html.index("let _findingsLoadVersion", start)
    body = html[start:end]
    assert "functionLine" in body
    assert "meta.function" in body
    assert "enclosing function" in body
    assert "isFunction" in body
    assert "code.textContent" in body
    assert "_sourceGoTo" in body
    assert "source-scroll" in body
    assert "view.meta[key]" in body  # every page keeps its original audit/file identity
    assert "source.detail" not in body  # pages are typed JSON, never a full-text wrapper
    assert ".modal-overlay" in html
    assert "z-index: 10001" in html


def test_findings_and_scans_are_paged():
    html = _frontend()
    assert "/api/findings?limit=" in html
    assert "function findingsPage" in html
    assert "function scansPage" in html
    assert "SCANS_PAGE" in html
    listed = client.get("/api/findings?limit=2&offset=0")
    assert listed.status_code == 200
    assert isinstance(listed.json(), list)
    assert len(listed.json()) <= 2
    jobs = client.get("/api/scan-jobs?limit=2")
    assert jobs.status_code == 200
    assert isinstance(jobs.json(), list)
    assert len(jobs.json()) <= 2


def test_scan_job_list_exposes_progress_and_tool_coverage_ledger():
    repo = _repo()
    db = SessionLocal()
    try:
        from backend.main import ScanJob
        job = ScanJob(
            repo_id=repo["id"], status="running",
            output=json.dumps({
                "tool_results": [
                    {"name": "sast", "status": "completed"},
                    {"name": "dast", "status": "failed"},
                    {"name": "osv", "status": "skipped", "reason": "not applicable"},
                ],
                "progress": {"phase": "dynamic", "progress_pct": 42, "eta_seconds": 75},
            }),
        )
        db.add(job)
        db.commit()
    finally:
        db.close()
    payload = client.get("/api/scan-jobs").json()
    row = next(item for item in payload if item["repo_id"] == repo["id"])
    assert row["coverage"]["total_tools"] == 3
    assert row["coverage"]["failed"] == 1
    assert row["coverage"]["not_applicable"] == 1
    assert row["progress_pct"] == 42.0
    assert row["phase"] == "dynamic"
    detail = client.get(f"/api/scan-jobs/{row['id']}").json()
    assert detail["coverage"]["failed"] == 1
    assert detail["leads_total"] == 0


def test_new_terminal_audit_with_unexhausted_ledger_is_incomplete():
    from backend.api import _evidence_complete
    base = {
        "audit_integrity": {"complete": True},
        "lab_status": {"healthy": True},
        "progress": {"evidence_status": "complete"},
        "completion_state": "complete",
    }
    assert _evidence_complete("completed", base)
    base["coverage_ledger"] = {"honest_exit": "IN_PROGRESS"}
    assert not _evidence_complete("completed", base)
    base["coverage_ledger"] = {"honest_exit": "COMPLETE"}
    base["phase2_execution"] = {"planned": 3, "completed": 1, "failed": 0, "skipped": 2}
    assert not _evidence_complete("completed", base)


def test_scan_ui_labels_unproven_counts_as_leads():
    html = _frontend()
    scan_rows = html.split("function renderScans(", 1)[1].split("async function scanRowControl(", 1)[0]
    assert "const leadCount = j.leads_total ?? j.findings_count" in scan_rows
    assert "const provenCount = j.confirmed_findings ?? 0" in scan_rows
    assert "${escapeHtml(String(leadCount))} leads · ${escapeHtml(String(provenCount))} confirmed" in scan_rows
    assert "Results incomplete" in scan_rows
    assert "AI review results" in html
    assert "Select a task to inspect its output" in html
    assert "Leads analyzed" in html
    assert "Confirmed findings:" in html
    assert "Number.isSafeInteger(d.confirmed_findings)" in html
    assert "Leads rejected" in html
    assert "d.evidence_status !== 'complete'" in html
    assert "Saved results" in html
    assert "Phase 2 was not executed because its lab/proof prerequisites were unavailable." in html
    assert "Phase 2: Not executed" in html
    assert "hasP2ExecutionReceipt" in html
    assert "p2NotExecuted" in html
    assert "provider attempts" in html


def test_finding_navigation_uses_authenticated_source_viewer_and_cvss_dialog():
    html = _frontend()
    # Existing three-argument callers remain valid; audit artifact links add an
    # optional expected scope, which the shared source viewer verifies.
    assert "function _showFileViewer(findingId, filePath, lineNum, expectedScope = null)" in html
    assert "repoId:expectedScope?.repoId || 0,jobId:expectedScope?.jobId || 0" in html
    assert "/api/findings/' + encodeURIComponent(findingId) + '/source" in html
    assert "function showFindingCvss(id)" in html
    assert "File preview is available in the Findings tab" not in html


def test_report_markdown_renderer_preserves_safe_clickable_links():
    html = _frontend()
    assert "function mdInline(s)" in html
    assert "LOTUSLINK" in html
    assert "https:\\/\\/" in html
    assert "javascript:" in html  # documented/rejected by the safe allow-list comment


def test_dynamic_click_targets_use_js_safe_encoding():
    html = _frontend()
    # Raw HTML entity escaping is not enough inside an inline JS handler: the
    # browser decodes entities before compiling the expression.  These user- or
    # repository-controlled values must flow through the JSON/HTML-safe helper.
    assert 'showAuditLog(${r.id}, "${escapeHtml(r.source)}")' not in html
    assert 'openAuditChat(${r.id}, "${escapeHtml(r.source)}")' not in html
    assert 'onclick="_showFileViewer(\\\'' not in html
    assert 'function jsString(value)' in html


def test_fixes_button_renders_ranked_options_not_raw_json():
    html = _frontend()
    start = html.index("async function showFindingFixes")
    body = html[start:start + 2800]
    assert "JSON.stringify" not in body
    assert "renderMarkdown" in body
    assert "Suggested Fixes" in body


# ---------------------------------------------------------------------------
# Functional: each UI-backed endpoint does what the label promises
# ---------------------------------------------------------------------------


def _repo(source="https://example.com/lotus-ui-contract"):
    r = client.post("/api/repos", json={"source": source, "branch": "main"})
    assert r.status_code == 200
    return r.json()


def test_health_and_retired_docs():
    assert client.get("/healthz").json()["status"] == "ok"
    ready = client.get("/readyz")
    assert ready.status_code == 200
    info = client.get("/api/info")
    assert info.status_code == 404


def test_dashboard_and_settings_roundtrip():
    d = client.get("/api/dashboard")
    assert d.status_code == 200
    body = d.json()
    assert "repos" in body and "findings" in body and "scan_jobs" in body
    s = client.get("/api/settings")
    assert s.status_code == 200
    r = client.post("/api/settings", json={"cvss_threshold": 7.5})
    assert r.status_code == 200
    assert r.json()["cvss_threshold"] == 7.5


def test_dashboard_headlines_exclude_archived_targets():
    active = _repo()
    archived = _repo("https://example.com/lotus-archived")
    assert client.delete(f"/api/repos/{archived['id']}").status_code == 200
    body = client.get("/api/dashboard").json()
    assert body["repos"] == 1
    assert active["id"] != archived["id"]


def test_repo_lifecycle_archive_restore_delete():
    repo = _repo()
    rid = repo["id"]
    assert client.get("/api/repos").status_code == 200
    assert client.get(f"/api/repos/{rid}").json()["id"] == rid
    assert client.delete(f"/api/repos/{rid}").status_code == 200
    archived = client.get("/api/repos/archived").json()
    assert any(r["id"] == rid for r in archived)
    assert client.post(f"/api/repos/{rid}/unarchive").status_code == 200
    assert client.delete(f"/api/repos/{rid}").status_code == 200
    assert client.delete(f"/api/repos/{rid}/permanent").status_code == 200
    leftover = client.get("/api/repos/archived").json()
    assert all(r["id"] != rid for r in leftover)


def test_continuous_config_and_scan_control():
    repo = _repo()
    rid = repo["id"]
    r = client.put(f"/api/repos/{rid}/continuous-config", json={
        "mode": "continuous", "focus_areas": ["rce"], "max_tokens": 1000,
        "max_hours": 0.5, "max_findings": 2, "auto_harness": False,
    })
    assert r.status_code == 200
    assert r.json()["mode"] == "continuous"
    idle = client.post(f"/api/repos/{rid}/scan/pause")
    assert idle.status_code == 200
    assert idle.json().get("running") is False
    ctl = client.get(f"/api/repos/{rid}/scan/control")
    assert ctl.status_code == 200
    jobs = client.get("/api/scan-jobs")
    assert jobs.status_code == 200
    tasks = client.get(f"/api/repos/{rid}/tasks")
    assert tasks.status_code == 200
    logs = client.get(f"/api/repos/{rid}/logs")
    assert logs.status_code == 200


def test_findings_view_validate_triage_ticket_fixes():
    repo = _repo()
    f = client.post("/api/findings", json={
        "repo_id": repo["id"], "title": "UI contract finding",
        "cvss": 8.1, "description": "user input reaches sink",
    })
    assert f.status_code == 201
    fid = f.json()["id"]
    assert client.get(f"/api/findings/{fid}").status_code == 200
    val = client.post(f"/api/findings/{fid}/validate", json={"context": ""})
    assert val.status_code == 200
    assert val.json()["lifecycle"] == "lead"
    assert val.json()["proof_status"] == "unproven"
    assert val.json()["proof_confidence"] == "unproven"
    assert val.json()["confidence"] in ("high", "medium", "low", "unverified")
    tri = client.post(f"/api/findings/{fid}/triage", json={"action": "accept"})
    assert tri.status_code == 200
    cvss = client.get(f"/api/findings/{fid}/cvss")
    assert cvss.status_code == 200
    assert cvss.json()["lifecycle"] == "lead"
    assert cvss.json()["proof_status"] == "unproven"
    assert cvss.json()["confidence"] != "certain"
    assert cvss.json()["proof_confidence"] == "unproven"
    ticket = client.post(f"/api/findings/{fid}/ticket", json={"target": "payload"})
    assert ticket.status_code == 200
    assert "ticket" in ticket.json()
    fixes = client.get(f"/api/findings/{fid}/fixes")
    assert fixes.status_code == 200


def test_finding_api_exposes_unambiguous_lead_lifecycle_and_confidence():
    """An unproven row is a Lead, while proof confidence is never implied."""
    repo = _repo("https://example.com/lifecycle-contract")
    created = client.post("/api/findings", json={
        "repo_id": repo["id"], "title": "Lifecycle lead",
        "cvss": 8.4, "description": "tool=semgrep | confidence=high | file=src/app.py:17 | untrusted input reaches sink",
    })
    assert created.status_code == 201
    row = client.get(f"/api/findings/{created.json()['id']}").json()
    assert row["lifecycle"] == "lead"
    assert row["proof_status"] == "unproven"
    assert row["confidence"] == "high"
    assert row["report_eligible"] is False


def test_terminal_details_return_ids_and_navigation_for_published_findings(monkeypatch):
    """The completion detail must remain clickable after a process restart."""
    repo = _repo("https://example.com/published-detail-contract")
    db = SessionLocal()
    try:
        job = ScanJob(repo_id=repo["id"], status="completed", findings_count=1,
                      output=json.dumps({"candidate_findings": 1, "confirmed_findings": 1,
                                         "automatic_report": {"id": 9001, "url": "/?report=9001#reports"},
                                         "progress": {"evidence_status": "complete"}}))
        db.add(job)
        db.commit()
        finding = Finding(repo_id=repo["id"], scan_job_id=job.id,
                          title="Published detail finding", cvss=8.2,
                          description="tool=dynamic | confidence=verified | file=src/app.py:17",
                          status="report-eligible", report_eligible=True)
        db.add(finding)
        db.commit()
        job_id, finding_id = job.id, finding.id
    finally:
        db.close()

    # This fixture models the trusted receipt validator; the route still uses
    # its normal authoritative-row filtering and payload construction.
    import backend.main as main_module
    monkeypatch.setattr(main_module, "_finding_receipt_valid", lambda _row, **_kwargs: True)
    detail = client.get(f"/api/scan-jobs/{job_id}/details")
    assert detail.status_code == 200
    body = detail.json()
    assert body["confirmed_findings"] == 1
    assert body["published_findings"][0]["id"] == finding_id
    assert body["published_findings"][0]["lifecycle"] == "finding"
    assert body["published_findings"][0]["confidence"] == "attested"
    assert body["published_findings"][0]["proof_confidence"] == "attested"

    html = _frontend()
    assert "_renderPublishedFindings" in html
    assert "_renderReportFindingNavigation" in html
    assert "Open the Finding notebook and run the local lab PoC" in html


def test_single_scan_job_view_normalizes_completed_progress():
    """Clicking a completed job must not regress to the legacy 0% ingest cache."""
    repo = _repo("https://example.com/single-job-progress-contract")
    db = SessionLocal()
    try:
        job = ScanJob(
            repo_id=repo["id"],
            status="completed",
            output=json.dumps({"progress": {"phase": "coverage", "progress_pct": 42.0, "eta_seconds": 17}}),
        )
        db.add(job)
        db.commit()
        job_id = job.id
    finally:
        db.close()

    response = client.get(f"/api/scan-jobs/{job_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["phase"] == "complete"
    assert body["progress_pct"] == 100.0
    assert body["eta_seconds"] is None


def test_terminal_job_never_exposes_stale_running_tasks():
    """Every planned task ends completed/failed/skipped with an operator reason."""
    repo = _repo("https://example.com/terminal-task-invariant")
    db = SessionLocal()
    try:
        job = ScanJob(
            repo_id=repo["id"],
            status="completed",
            output=json.dumps({"tasks": [
                {"name": "phase2-plan", "state": "running", "summary": "Generating plan"},
                {"name": "lead-analysis", "state": "ok", "summary": "done"},
            ]}),
        )
        db.add(job)
        db.commit()
    finally:
        db.close()

    response = client.get(f"/api/repos/{repo['id']}/tasks")
    assert response.status_code == 200
    rows = response.json()["tasks"]
    assert len(rows) == 2
    assert all(row["terminal_status"] in {"completed", "failed", "skipped"} for row in rows)
    stale = next(row for row in rows if row["name"] == "phase2-plan")
    assert stale["state"] == "skipped"
    assert "not executed" in stale["reason"]


def test_live_task_null_detail_id_gets_clickable_console_target():
    """Legacy live rows with an explicit null id still receive a stable link."""
    import backend.pipeline as pipeline

    repo = _repo("https://example.com/null-detail-task-contract")
    pipeline.SCAN_TASKS[repo["id"]] = [{
        "name": "clone", "state": "ok", "terminal_status": "completed",
        "detail_id": None,
    }]
    try:
        response = client.get(f"/api/repos/{repo['id']}/tasks")
        assert response.status_code == 200
        row = response.json()["tasks"][0]
        assert row["detail_id"] == f"{repo['id']}-task-clone"
    finally:
        pipeline.SCAN_TASKS.pop(repo["id"], None)


def test_task_console_click_matches_terminalized_task_state():
    """A stale process-local console cannot contradict the task timeline."""
    import backend.pipeline as pipeline

    repo = _repo("https://example.com/terminal-console-contract")
    detail_id = f"{repo['id']}-task-phase2-plan"
    db = SessionLocal()
    try:
        db.add(ScanJob(repo_id=repo["id"], status="completed", output=json.dumps({
            "tasks": [{"name": "phase2-plan", "state": "running"}],
        })))
        db.commit()
    finally:
        db.close()
    pipeline.STREAM_DETAILS[detail_id] = {
        "kind": "task-console", "task": "phase2-plan", "status": "running",
        "terminal_status": "running", "console_text": "planner stopped",
    }
    try:
        response = client.get(f"/api/stream-detail/{detail_id}")
        assert response.status_code == 200
        content = response.json()["content"]
        assert content["status"] == "skipped"
        assert content["terminal_status"] == "skipped"
        assert "not executed" in content["reason"]
    finally:
        pipeline.STREAM_DETAILS.pop(detail_id, None)


def test_terminal_details_repair_missing_automatic_report():
    """Opening an old completed audit repairs its zero/non-zero report link."""
    repo = _repo("https://example.com/report-repair-contract")
    db = SessionLocal()
    try:
        job = ScanJob(repo_id=repo["id"], status="completed", findings_count=0,
                      output=json.dumps({"candidate_findings": 0,
                                         "progress": {"evidence_status": "incomplete"}}))
        db.add(job)
        db.commit()
        job_id = job.id
    finally:
        db.close()
    detail = client.get(f"/api/scan-jobs/{job_id}/details")
    assert detail.status_code == 200
    repaired = detail.json().get("automatic_report") or {}
    assert repaired.get("id")
    assert repaired.get("url") == f"/?report={repaired['id']}#reports"


def test_replayed_completion_detail_hydrates_legacy_rows(monkeypatch):
    """A cold/replayed stream repairs old completion rows before rendering."""
    repo = _repo("https://example.com/replayed-completion-contract")
    detail_id = f"{repo['id']}-complete"
    db = SessionLocal()
    try:
        job = ScanJob(repo_id=repo["id"], status="completed",
                      output=json.dumps({"details": {detail_id: {
                          "total_leads": 3,
                          "confirmed": [{"title": "Legacy published row", "cvss": 8.0, "file": "src/app.py", "line": 4}],
                          "automatic_report": {"id": 1, "url": "/?report=1#reports"},
                      }}}))
        db.add(job)
        db.commit()
        finding = Finding(repo_id=repo["id"], scan_job_id=job.id,
                          title="Legacy published row", cvss=8.0,
                          description="tool=dynamic | file=src/app.py:4",
                          status="report-eligible", report_eligible=True)
        db.add(finding)
        db.commit()
        finding_id = finding.id
    finally:
        db.close()
    import backend.main as main_module
    monkeypatch.setattr(main_module, "_finding_receipt_valid", lambda _row, **_kwargs: True)
    response = client.get(f"/api/stream-detail/{detail_id}")
    assert response.status_code == 200
    content = response.json()["content"]
    assert content["confirmed"][0]["id"] == finding_id
    assert content["confirmed"][0]["lifecycle"] == "finding"


def test_reports_generate_pdf_markdown_and_lab_status():
    repo = _repo()
    client.post("/api/findings", json={
        "repo_id": repo["id"], "title": "Eligible-looking",
        "cvss": 9.0, "description": "n/a",
    })
    rep = client.post("/api/reports", json={"repo_id": repo["id"]})
    assert rep.status_code == 200
    rid = rep.json()["id"]
    got = client.get(f"/api/reports/{rid}")
    assert got.status_code == 200
    markdown = client.get(f"/api/reports/{rid}/markdown")
    assert markdown.status_code == 200
    assert "attachment" in markdown.headers.get("content-disposition", "").lower()
    assert markdown.headers["content-type"].startswith("text/markdown")
    pdf = client.get(f"/api/reports/{rid}/pdf")
    assert pdf.status_code == 200
    ls = client.get(f"/api/reports/{rid}/poc/lab-status")
    assert ls.status_code == 200
    assert "running" in ls.json()
    # An unbound publication may not execute or stop a repository's current lab.
    poc = client.post(f"/api/reports/{rid}/poc/run", json={
        "code": "echo lotus-lab", "language": "bash", "mode": "lab",
    })
    assert poc.status_code == 409
    assert "audit" in poc.json()["detail"].lower()
    stopped = client.post(f"/api/reports/{rid}/poc/stop-lab")
    assert stopped.status_code == 409
    missing = client.post("/api/reports/9999/poc/stop-lab")
    assert missing.status_code == 404




def test_zero_finding_report_contains_immutable_evidence_ledger_and_is_idempotent():
    repo = _repo("https://example.com/zero-evidence")
    db = SessionLocal()
    try:
        job = ScanJob(
            repo_id=repo["id"], status="completed", findings_count=0,
            output=json.dumps({
                "app_type": "library",
                "requested_branch": "main", "effective_branch": "master",
                "target_identity": {"target_revision": "abc", "target_tree_hash": "tree"},
                "tool_results": [
                    {"name": "npm-audit", "status": "completed"},
                    {"name": "semgrep", "status": "not-installed", "reason": "binary unavailable"},
                ],
                "coverage": {"total_tools": 2, "completed": 1, "failed": 0, "skipped": 1},
                "phase2_plan": {"task_count": 2, "tasks": [{"category": "library-harness"}]},
                "phase2_execution": {"planned": 2, "executed": 1, "completed": 1, "failed": 0,
                                      "skipped": 1, "terminal": 2, "unresolved": 0},
                "coverage_ledger": {"honest_exit": "IN_PROGRESS", "exhaustion_pct": 50,
                                     "tools_missing": ["semgrep"]},
                "lab_status": {"healthy": True, "status": "healthy", "url": ""},
                "lab_smoke": {"ran": True, "ok": True},
                "progress": {"evidence_status": "incomplete"},
                "completion_state": "completed_with_gaps",
                "discovery_metrics": {"total_leads": 4},
            }),
        )
        db.add(job)
        db.commit()
        job_id = job.id
    finally:
        db.close()

    first = ensure_automatic_evidence_report(repo["id"])
    assert first["created"] is True
    second = ensure_automatic_evidence_report(repo["id"])
    assert second["created"] is False
    assert second["id"] == first["id"]

    got = client.get(f"/api/reports/{first['id']}")
    assert got.status_code == 200
    body = got.json()
    assert body["manifest_verified"] is True
    assert body["findings_count"] == 0
    assert body["evidence"]["scan_job_id"] == job_id
    assert body["evidence"]["evidence_status"] == "incomplete"
    # The report is itself a clickable, signed artifact even when no findings
    # are confirmed.  The self-link is finalized after the DB allocates the
    # report id and must survive manifest verification.
    assert body["evidence"]["automatic_report"] == {
        "id": first["id"],
        "created": True,
        "url": f"/?report={first['id']}#reports",
    }
    assert f"/?report={first['id']}#reports" in body["markdown"]
    assert f"[open report](/?report={first['id']}#reports)" in body["markdown"]
    assert "Audit results, coverage, and limitations" in body["markdown"]
    assert "Lead lifecycle:" in body["markdown"]
    assert "not installed" in body["markdown"].lower()
    assert client.get(f"/api/reports/{first['id']}/findings").json() == []


def test_failed_terminal_job_also_gets_incomplete_evidence_report():
    repo = _repo("https://example.com/failed-evidence")
    db = SessionLocal()
    try:
        job = ScanJob(
            repo_id=repo["id"], status="failed", findings_count=0,
            output=json.dumps({
                "error": "lab build failed",
                "progress": {"evidence_status": "incomplete"},
                "completion_state": "failed",
            }),
        )
        db.add(job)
        db.commit()
    finally:
        db.close()

    report = ensure_automatic_evidence_report(repo["id"])
    assert report and report["created"] is True
    body = client.get(f"/api/reports/{report['id']}").json()
    assert body["findings_count"] == 0
    assert body["evidence_status"] == "incomplete"
    assert "lab was not healthy/usable" in "\n".join(body["evidence"]["gaps"])


def test_report_flattens_nested_native_audit_target_outcomes():
    repo = _repo("https://example.com/monorepo-evidence")
    db = SessionLocal()
    try:
        db.add(ScanJob(
            repo_id=repo["id"], status="completed", findings_count=0,
            output=json.dumps({
                "app_type": "api-service",
                "target_identity": {"target_revision": "rev", "target_tree_hash": "tree"},
                "tool_results": [{
                    "name": "native-package-audits", "status": "completed",
                    "target_results": [{
                        "language": "python", "root": "services/api",
                        "status": "not-installed", "reason": "pip-audit missing",
                        "findings_count": 0,
                    }],
                }],
                "coverage": {"total_tools": 1, "completed": 1},
                "phase2_execution": {"planned": 0, "completed": 0, "failed": 0,
                                      "skipped": 0, "terminal": 0, "unresolved": 0},
                "lab_status": {"healthy": True, "status": "healthy"},
                "lab_smoke": {"ran": True, "ok": True},
                "coverage_ledger": {"honest_exit": "COMPLETE"},
                "progress": {"evidence_status": "complete"},
                "completion_state": "complete",
            }),
        ))
        db.commit()
    finally:
        db.close()

    report = ensure_automatic_evidence_report(repo["id"])
    body = client.get(f"/api/reports/{report['id']}").json()
    targets = body["evidence"]["tools"]["target_results"]
    assert targets and targets[0]["root"] == "services/api"
    assert "Native package-audit targets" in body["markdown"]


def test_decisions_answer_updates_status():
    db = SessionLocal()
    try:
        d = AuditDecision(repo_id=1, question="Which PHP version?", status="pending",
                          options=json.dumps(["8.1", "8.2"]))
        db.add(d)
        db.commit()
        did = d.id
    finally:
        db.close()
    listed = client.get("/api/decisions")
    assert listed.status_code == 200
    assert any(x["id"] == did for x in listed.json())
    ans = client.post(f"/api/decisions/{did}/answer", json={"answer": "8.2"})
    assert ans.status_code == 200
    assert ans.json()["status"] == "answered"
    count = client.get("/api/decisions/count")
    assert count.status_code == 200
    assert "pending" in count.json()


def test_capabilities_skills_tools_and_packs():
    caps = client.get("/api/capabilities")
    assert caps.status_code == 200
    tools = client.get("/api/capabilities/tools")
    assert tools.status_code == 200
    packs = client.get("/api/skill-packs")
    assert packs.status_code == 200
    assert "packs" in packs.json()
    skills = client.get("/api/skills")
    assert skills.status_code == 200
    reindex = client.post("/api/capabilities/reindex")
    assert reindex.status_code == 200
    reload = client.post("/api/skill-packs/reload")
    assert reload.status_code == 200
    depth = client.get("/api/audit-depth/levels")
    assert depth.status_code == 200
    assert "levels" in depth.json()
    docs = client.get("/api/docs/spec")
    assert docs.status_code == 200


def test_harness_build_and_stop():
    repo = _repo()
    created = client.post("/api/harness", json={
        "repo_id": repo["id"], "focus_areas": ["rce"], "max_tokens": 1000,
        "max_hours": 0.1, "max_findings": 1,
    })
    assert created.status_code == 200
    hid = created.json()["id"]
    listed = client.get("/api/harness")
    assert any(h["id"] == hid for h in listed.json())
    stopped = client.post(f"/api/harness/{hid}/stop")
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "stopped"


def test_debug_stats_console_run_tests_backup_download():
    stats = client.get("/api/debug/stats")
    assert stats.status_code == 200
    assert "docker_running" in stats.json()
    console = client.get("/api/console")
    assert console.status_code == 200
    tests = client.post("/api/debug/run-tests")
    assert tests.status_code == 200
    body = tests.json()
    assert "details" in body
    names = [d["name"] for d in body["details"]]
    assert "lab-pod-pytest" in names
    bak = client.post("/api/db/backup")
    assert bak.status_code == 200
    listed = client.get("/api/db/backups")
    assert listed.status_code == 200
    dl = client.get("/api/db/backup/download")
    assert dl.status_code == 200
    z = client.get("/api/debug/download-data")
    assert z.status_code == 200
    assert z.headers.get("content-type", "").startswith("application/zip")
    assert z.content[:2] == b"PK"


def test_fast_data_export_is_bounded_but_retains_snapshot_metadata(monkeypatch, tmp_path):
    """The default export must not walk full replay trees for minutes."""
    snap = tmp_path / "audit_snapshots" / "abc"
    (snap / "source").mkdir(parents=True)
    (snap / "snapshot.json").write_text('{"tree_hash":"sha256:test"}', encoding="utf-8")
    (snap / "source" / "app.py").write_text("print('ok')", encoding="utf-8")
    (tmp_path / "skills").mkdir()
    (tmp_path / "skills" / "rule.md").write_text("rule", encoding="utf-8")
    outside = tmp_path.parent / "export-secret.txt"
    outside.write_text("must not be exported", encoding="utf-8")
    (tmp_path / "skills" / "linked-secret.txt").symlink_to(outside)
    monkeypatch.setattr("backend.main._data_dir", lambda: tmp_path)

    response = client.get("/api/debug/download-data")
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("_export_manifest.json"))
        assert "audit_snapshot_metadata/abc.json" in names
        assert "audit_snapshots/abc/source/app.py" not in names
        assert "audit_snapshots" in manifest["omitted_directories"]
        assert "skills/linked-secret.txt" not in names

    full = client.get("/api/debug/download-data?include_snapshots=true")
    assert full.status_code == 200
    with zipfile.ZipFile(io.BytesIO(full.content)) as archive:
        assert "audit_snapshots/abc/source/app.py" in set(archive.namelist())
