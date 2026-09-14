import os
import tempfile
import time

import pytest

os.environ.setdefault("LOTUS_NO_SEED", "1")
# Unit tests stay host-hermetic: do not spawn lotus-selftest pods, and keep the
# AST sandbox available so report-notebook unit tests can still exercise it.
# Production (Debug → Run Tests, report ▶ Run) does not set these flags.
os.environ.setdefault("LOTUS_SELFTEST_SKIP_POD", "1")
os.environ.setdefault("LOTUS_ALLOW_HOST_SANDBOX", "1")

# Test isolation: scans run in background worker threads. SQLite ":memory:" uses a single
# shared connection (StaticPool) that cannot survive concurrent access from those threads,
# producing order-dependent "no such table" flakiness. Always force a per-process FILE
# database unless an explicit opt-in is supplied. Previously an externally supplied
# DATABASE_URL (including the operator's active data/lotus.db) was honored and the
# autouse reset fixture could delete real audit data.
_use_external_db = os.environ.get("LOTUS_TEST_USE_DATABASE_URL", "").strip().lower() in {
    "1", "true", "yes", "on",
}
if not _use_external_db:
    _tmp = os.path.join(tempfile.gettempdir(), f"lotus_test_{os.getpid()}.db")
    for _suffix in ("", "-wal", "-shm"):
        try:
            if os.path.exists(_tmp + _suffix):
                os.remove(_tmp + _suffix)
        except OSError:
            pass
    os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}"
    # Keep destructive reset/backup tests hermetic even when a developer has
    # not opted into an external datastore.  LOTUS_DATA_DIR is intentionally
    # left untouched because several fixture suites exercise the checked-in
    # default skills and absolute e2e targets; the reset implementation itself
    # still accepts an injected data root for those tests.
    _test_backup_dir = os.path.join(tempfile.gettempdir(), f"lotus_test_{os.getpid()}_backups")
    os.makedirs(_test_backup_dir, exist_ok=True)
    os.environ.setdefault("LOTUS_BACKUP_DIR", _test_backup_dir)
    _test_credentials_path = os.path.join(tempfile.gettempdir(), f"lotus_test_{os.getpid()}_credentials.json")
    os.environ.setdefault("LOTUS_CREDENTIALS_PATH", _test_credentials_path)

# Capture the process-level test baseline once.  Module-scoped fixtures are
# allowed to configure a safety mode for their own tests, but that setup runs
# outside the function-scoped isolation fixture.  Restoring the values seen at
# collection time prevents a module such as the real-target e2e suite from
# leaking ``LOTUS_DISABLE_LAB=1`` into later mocked lab-discovery tests.
_TEST_ENV_BASELINE = {
    key: os.environ.get(key)
    for key in (
        "DATABASE_URL", "LOTUS_DISABLE_LAB", "LOTUS_REQUIRE_LAB_PROOF",
        "LOTUS_LAB_PROVIDER", "LOTUS_NO_SEED", "LOTUS_DEPLOY_PROFILE",
        "LOTUS_AUTH_TOKEN", "LOTUS_PROOF_SIGNING_KEY",
        "LOTUS_BACKUP_DIR", "LOTUS_CREDENTIALS_PATH",
    )
}


# Modules that manage their own DB lifecycle (session/module-scoped clients, real e2e
# audits with persistent cross-test state or long real scans) opt OUT of per-test reset.
_NO_ISOLATION_MODULES = {
    "test_platform_verification",
    "test_e2e_full_audit",
    "test_e2e_targets",
    "test_e2e_harness_audit",
    "test_chef_audit_e2e",
    "test_mlrun_audit_e2e",
    "test_microci_audit_e2e",
    "run_spree_e2e",
}


@pytest.fixture
def verified_audit_ai(monkeypatch):
    """Opt-in authored model transport for tests of unrelated audit workflows.

    Tests exercise the production readiness gate using a real configuration-
    bound receipt, while all completions stay inside this process. Tests of
    missing AI configuration deliberately do not request this fixture.
    The returned helper re-verifies after a test intentionally changes models.
    """
    from backend.main import SessionLocal, Settings
    from backend.ai_gateway import AIResult, AIStatus, AITask
    from backend.ai_readiness import record_verification

    def verify_current():
        db = SessionLocal()
        try:
            settings = db.query(Settings).first()
            if settings is None:
                settings = Settings()
                db.add(settings)
                db.flush()
            if settings.ai_provider in (None, "", "none") or (
                    settings.ai_provider not in {"ollama", "lmstudio"} and not settings.ai_api_key):
                settings.ai_provider = "ollama"
                settings.ai_model = "lotus-authored-test-model"
                settings.ai_base_url = "http://127.0.0.1:11434"
            settings.ai_judge_enabled = False
            record_verification(settings, "primary", AIResult(AIStatus.OK, text="OK"))
            db.commit()
        finally:
            db.close()

    def completion(prompt, settings, timeout=120, *, task=None, **kwargs):
        text = ('{"install_steps":[],"start_command":"","smoke_test":"","extra_packages":[],"audit_focus":[],"phase2_tasks":[],"notes":[]}'
                if task == AITask.AUDIT_PLAN else '[]')
        return AIResult(AIStatus.OK, text=text, meta={"authored_test_fixture": True})

    monkeypatch.setattr("backend.main._dispatch_ai_result", completion)
    verify_current()
    return verify_current


@pytest.fixture(autouse=True)
def _deny_dependency_source_public_transport(monkeypatch):
    """Go declarations in authored audits must never trigger public downloads.

    Capture transport tests override this exact factory with MockTransport;
    source integration tests provide authored in-memory archive fetchers.
    This does not change unrelated app HTTP clients or feature settings.
    """
    from backend import dependency_source_capture
    def denied(*args, **kwargs):
        raise dependency_source_capture.CaptureError("Public dependency download denied by the hermetic test transport; provide an authored fetcher")
    monkeypatch.setattr(dependency_source_capture, "_HTTP_CLIENT", denied)


@pytest.fixture(autouse=True)
def _restore_process_environment():
    """Prevent one audit fixture from changing the next test's safety mode.

    End-to-end fixtures intentionally toggle lab/database settings for their
    own run.  Those mutations must not leak into later tests (for example,
    leaving ``LOTUS_DISABLE_LAB=1`` makes mocked lab-discovery tests exercise a
    different code path).  Restoring the small set of process-wide controls is
    also safer for developers who invoke pytest with deployment environment
    variables present.
    """
    keys = (
        "DATABASE_URL", "LOTUS_DISABLE_LAB", "LOTUS_REQUIRE_LAB_PROOF",
        "LOTUS_LAB_PROVIDER", "LOTUS_NO_SEED", "LOTUS_DEPLOY_PROFILE",
        "LOTUS_AUTH_TOKEN", "LOTUS_PROOF_SIGNING_KEY",
        "LOTUS_BACKUP_DIR", "LOTUS_CREDENTIALS_PATH",
    )
    try:
        yield
    finally:
        for key, value in _TEST_ENV_BASELINE.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.fixture(autouse=True)
def _isolate_db(request, _restore_process_environment):
    """Per-test DB isolation: give every test a pristine schema and clean in-memory state.

    Fixes cross-test contamination that surfaced when the whole suite runs in one process:
      - the singleton `settings`/`notification_settings` rows accumulating another suite's
        mutations (breaking default-value assertions), and
      - a background worker-pool scan from one test still writing when a later test drops
        tables via /api/db/reset ("no such table").

    Strategy: drain any active scans (bounded), drop+recreate all tables, ensure a default
    settings row, and clear the SSE/scan in-memory registries  - before each test. Heavy
    e2e modules that own their DB lifecycle are exempted.
    """
    mod = ""
    try:
        mod = request.node.module.__name__.split(".")[-1]
    except Exception:
        mod = ""
    if mod in _NO_ISOLATION_MODULES:
        yield
        return

    # 1) Drain background scans so a worker thread can't race a later test that drops/
    #    rewrites tables (e.g. /api/db/reset). Bounded so a hung scan can't wedge the suite.
    try:
        from backend import scan_worker as _sw
        _deadline = time.time() + 20
        while _sw.active_scan_count() > 0 and time.time() < _deadline:
            time.sleep(0.1)
        with _sw._scan_lock:
            _sw._active_scans.clear()
    except Exception:
        pass

    # 2) Per-test data isolation WITHOUT dropping the schema. We ensure the tables exist
    #    (create_all is idempotent) and clear all rows, then re-seed the singleton
    #    settings/notification rows to defaults. Crucially we do NOT drop_all: several
    #    modules have their own autouse clean_db fixtures that DELETE from tables, and a
    #    global drop between fixture-setup ordering left those tables missing ("no such
    #    table"). Delete-based reset keeps tables present, isolates data, AND fixes the
    #    singleton-settings accumulation that broke default-value assertions.
    try:
        from backend.main import (
            Base, engine, SessionLocal, Settings, NotificationSettings,
            Repo, Finding, Report, ScanJob, ScanLease, HarnessRun, AuditDecision, NotebookExecution, NotebookRuntime,
            Deployment, DeploymentTarget, DeploymentReconRun,
            _PLATFORM_RESTART_REQUIRED,
        )
        # Each isolated test starts a fresh application configuration lifetime.
        # Successful imports intentionally keep writes locked until restart.
        _PLATFORM_RESTART_REQUIRED.clear()
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            for _m in (NotebookRuntime, NotebookExecution, Finding, ScanLease, ScanJob, Report, HarnessRun, AuditDecision,
                       DeploymentReconRun, DeploymentTarget, Deployment, Repo,
                       Settings, NotificationSettings):
                try:
                    db.query(_m).delete()
                except Exception:
                    db.rollback()
            db.add(Settings())
            db.add(NotificationSettings())
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    # 3) Clear in-memory SSE/scan registries so streams/details don't leak across tests.
    try:
        from backend import pipeline as _p
        _p.STREAM_QUEUES.clear()
        _p.STREAM_DETAILS.clear()
        _p.STREAM_HISTORY.clear()
        _p.SCAN_TASKS.clear()
        # Database rows are recreated above, so their integer IDs can be
        # reused. A previous test's job-bound progress/coverage must not be
        # mistaken for the new run just because both jobs were assigned ID 1.
        from backend import audit_progress as _progress
        with _progress._LOCK:
            _progress._STATE.clear()
    except Exception:
        pass

    yield
