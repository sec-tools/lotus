"""Regression tests for the operational endpoints added for production readiness.

These back Kubernetes probes and enterprise observability, so their contracts must
stay stable:
  - GET /healthz  -> liveness (never touches the DB/Docker; cannot restart-loop)
  - GET /readyz   -> readiness (DB connectivity + lab-provider visibility)
  - GET /metrics  -> Prometheus text-format counters/gauges
  - GET /api/repos/{id}/tasks -> structured audit task timeline (live or persisted)

They use the real get_db against the conftest-managed database (no module-level
dependency_overrides, which historically leaked across modules).
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from backend.main import app, SessionLocal, Repo

client = TestClient(app)


def test_healthz_is_liveness_only():
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "lotus"
    assert "version" in body


def test_readyz_reports_db_and_lab_checks():
    r = client.get("/readyz")
    # conftest keeps the DB reachable, so readiness should be positive here.
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] is True
    # lab_provider is reported but never fails readiness (candidate-only mode is valid).
    assert "lab_provider" in body["checks"]


def test_metrics_prometheus_text_format():
    # Exercise the request path first so the middleware counter has a value to emit.
    client.get("/healthz")
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    text = r.text
    assert "lotus_http_requests_total" in text
    assert "# TYPE lotus_http_requests_total counter" in text
    # Live gauges derived from the DB should be present too.
    assert "lotus_repos" in text
    assert "lotus_findings" in text


def test_repo_tasks_timeline_shape_for_new_repo():
    db = SessionLocal()
    try:
        repo = Repo(source="/tmp/ops-test-repo", branch="main",
                    mode="one-time", status="queued")
        db.add(repo)
        db.commit()
        db.refresh(repo)
        repo_id = repo.id
    finally:
        db.close()

    r = client.get(f"/api/repos/{repo_id}/tasks")
    assert r.status_code == 200
    body = r.json()
    assert body["repo_id"] == repo_id
    assert body["source"] in ("live", "persisted")
    # A brand-new repo has no recorded tasks yet, but the shape must be a list.
    assert isinstance(body["tasks"], list)
