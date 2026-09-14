"""Lotus Python SDK - LotusClient.

A synchronous, repository-local client for a subset of the Lotus REST API.

Usage:
    from backend.sdk import LotusClient

    # Supply token=... when API authentication is enabled.
    with LotusClient("http://127.0.0.1:8000") as client:
        for job in client.list_scan_jobs(limit=20):
            print(job.id, job.status, job.evidence_status)

Source/progress reads select an exact audit. Recovery actions are explicit and
retain server-side readiness, source, ownership, and idempotency checks.
"""
from __future__ import annotations

import json
import math
import os
import tempfile
import time
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urlencode

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

try:
    import requests as _requests_lib
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from backend.sdk.exceptions import (
    LotusAPIError,
    LotusConnectionError,
    LotusNotFoundError,
    LotusTimeoutError,
    LotusValidationError,
)
from backend.sdk.models import (
    AuditDecision,
    Dashboard,
    Finding,
    HarnessRun,
    Repo,
    Report,
    ScanJob,
    Settings,
    Skill,
    SystemStats,
)


class LotusClient:
    """Python client for the Lotus Security Platform API.

    Args:
        base_url: Base URL of the Lotus server (default: http://127.0.0.1:8000)
        api_key: Optional legacy X-API-Key credential
        token: Optional bearer token (LOTUS_AUTH_TOKEN)
        timeout: Request timeout in seconds (default: 30)
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        api_key: Optional[str] = None,
        timeout: float = 30,
        *,
        token: Optional[str] = None,
    ):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite positive number")
        if token and api_key and token != api_key:
            raise ValueError("token and api_key must not contain different credentials")
        self.base_url = base_url.rstrip("/")
        self.api_key = token or api_key
        self._scan_jobs: Dict[int, int] = {}
        self.timeout = timeout
        self._headers: Dict[str, str] = {"Content-Type": "application/json"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
        elif api_key:
            self._headers["X-API-Key"] = api_key

        # Prefer httpx, fall back to requests, fall back to urllib
        if _HAS_HTTPX:
            self._http = httpx.Client(
                base_url=self.base_url,
                headers=self._headers,
                timeout=timeout,
            )
            self._impl = "httpx"
        elif _HAS_REQUESTS:
            self._impl = "requests"
        else:
            self._impl = "urllib"

    def close(self) -> None:
        """Release pooled transport connections; safe to call repeatedly."""
        if self._impl == "httpx":
            self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        json_body: Optional[dict] = None,
        params: Optional[dict] = None,
        *,
        raw: bool = False,
    ) -> Any:
        """Make an HTTP request and return parsed JSON."""
        url = f"{self.base_url}{path}"

        try:
            if self._impl == "httpx":
                resp = self._http.request(method, path, json=json_body, params=params)
                status = resp.status_code
                content = resp.content
                body = content.decode("utf-8", errors="replace")
            elif self._impl == "requests":
                resp = _requests_lib.request(
                    method,
                    url,
                    json=json_body,
                    params=params,
                    headers=self._headers,
                    timeout=self.timeout,
                )
                status = resp.status_code
                content = resp.content
                body = content.decode("utf-8", errors="replace")
            else:
                import urllib.request
                import urllib.error

                if params:
                    query = urlencode({k: v for k, v in params.items() if v is not None}, doseq=True)
                    if query:
                        url += ("&" if "?" in url else "?") + query
                data = json.dumps(json_body).encode() if json_body is not None else None
                req = urllib.request.Request(url, data=data, headers=self._headers, method=method)
                try:
                    with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                        status = resp.status
                        content = resp.read()
                        body = content.decode("utf-8", errors="replace")
                except urllib.error.HTTPError as e:
                    status = e.code
                    content = e.read()
                    body = content.decode("utf-8", errors="replace")
        except Exception as e:
            if isinstance(e, TimeoutError) or "timeout" in type(e).__name__.lower() or "timeout" in str(e).lower() or "timed out" in str(e).lower():
                raise LotusTimeoutError(f"Request timed out: {method} {path}")
            raise LotusConnectionError(f"Cannot connect to {self.base_url}: {e}")

        if status == 404:
            raise LotusNotFoundError(f"Not found: {path}", status_code=status, response_body=body)
        elif status == 422:
            raise LotusValidationError(
                f"Validation error: {body[:500]}", status_code=status, response_body=body
            )
        elif status >= 400:
            raise LotusAPIError(
                f"API error {status}: {body[:500]}", status_code=status, response_body=body
            )

        if raw:
            return content

        if not body or body.strip() == "":
            return {}

        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"raw": body}

    def _get(self, path: str, params: Optional[dict] = None) -> Any:
        return self._request("GET", path, params=params)

    def _post(self, path: str, json_body: Optional[dict] = None) -> Any:
        return self._request("POST", path, json_body=json_body)

    def _delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    def _put(self, path: str, json_body: Optional[dict] = None) -> Any:
        return self._request("PUT", path, json_body=json_body)

    # ----- Repos -----

    def list_repos(self) -> List[Repo]:
        """List all active repositories."""
        data = self._get("/api/repos")
        return [Repo(**r) for r in data]

    def add_repo(
        self,
        source: str,
        branch: str = "main",
        mode: str = "one-time",
        focus_areas: Optional[List[str]] = None,
        max_tokens: int = 50000,
        max_hours: float = 1.0,
        max_findings: int = 5,
        auto_harness: bool = False,
    ) -> Repo:
        """Add a repository for scanning with optional autonomous continuous coverage settings."""
        payload: dict = {"source": source, "branch": branch}
        if mode != "one-time":
            payload["mode"] = mode
        if focus_areas:
            payload["focus_areas"] = focus_areas
        if max_tokens != 50000:
            payload["max_tokens"] = max_tokens
        if max_hours != 1.0:
            payload["max_hours"] = max_hours
        if max_findings != 5:
            payload["max_findings"] = max_findings
        if auto_harness:
            payload["auto_harness"] = auto_harness
        data = self._post("/api/repos", payload)
        return Repo(**data)


    def update_continuous_config(
        self,
        repo_id: int,
        mode: Optional[str] = None,
        focus_areas: Optional[List[str]] = None,
        max_tokens: Optional[int] = None,
        max_hours: Optional[float] = None,
        max_findings: Optional[int] = None,
        auto_harness: Optional[bool] = None,
    ) -> Repo:
        """Update only supplied policy fields; explicit []/False clear those options."""
        payload = {key: value for key, value in {
            "mode": mode, "focus_areas": focus_areas, "max_tokens": max_tokens,
            "max_hours": max_hours, "max_findings": max_findings,
            "auto_harness": auto_harness,
        }.items() if value is not None}
        return Repo(**self._put(f"/api/repos/{repo_id}/continuous-config", payload))

    def get_repo(self, repo_id: int) -> Repo:
        """Get a specific repository."""
        data = self._get(f"/api/repos/{repo_id}")
        return Repo(**data)

    def delete_repo(self, repo_id: int) -> bool:
        """Soft-delete (archive) a repository."""
        self._delete(f"/api/repos/{repo_id}")
        return True

    def delete_repo_permanent(self, repo_id: int) -> bool:
        """Permanently delete a repository and all its data."""
        self._delete(f"/api/repos/{repo_id}/permanent")
        return True

    @staticmethod
    def _audit_depth(value: Optional[int]) -> None:
        if value is not None and (type(value) is not int or not 1 <= value <= 5):
            raise ValueError("audit_depth must be an integer from 1 to 5")

    def list_repo_branches(self, source: str) -> dict:
        """Discover public HTTPS Git branches without enrolling or cloning.

        The server enforces URL/DNS policy, credential isolation and bounded
        Git lifetime/output. SSH enrollment still requires a chosen branch.
        """
        if not isinstance(source, str) or not source.strip() or len(source) > 512:
            raise ValueError("source must be a nonempty Git URL of at most 512 characters")
        return self._post("/api/repos/branches", {"source": source})

    def enroll_and_scan(
        self, source: str, branch: str = "main", *, audit_depth: Optional[int] = None,
        mode: str = "one-time", focus_areas: Optional[List[str]] = None,
        max_tokens: int = 50000, max_hours: float = 1.0, max_findings: int = 5,
        auto_harness: bool = False,
    ) -> dict:
        """Atomically enroll and reserve an exact audit; retain its ID for waiting.

        Omitted depth captures Settings' default. A retry attaches to the
        existing active audit and preserves that audit's original depth.
        """
        self._audit_depth(audit_depth)
        payload = {"source": source, "branch": branch, "mode": mode,
                   "focus_areas": focus_areas or [], "max_tokens": max_tokens,
                   "max_hours": max_hours, "max_findings": max_findings,
                   "auto_harness": auto_harness}
        if audit_depth is not None:
            payload["audit_depth"] = audit_depth
        result = self._post("/api/repos/enroll-and-scan", payload)
        repo = result.get("repo") if isinstance(result, dict) else None
        scan = result.get("scan") if isinstance(result, dict) else None
        rid = repo.get("id") if isinstance(repo, dict) else None
        jid = scan.get("job_id") if isinstance(scan, dict) else None
        if (type(rid) is not int or rid <= 0 or type(jid) is not int or jid <= 0
                or type(scan.get("repo_id")) is not int or scan["repo_id"] != rid
                or result.get("accepted") is not True):
            raise LotusAPIError("Enrollment response has no exact accepted repository/audit binding")
        self._scan_jobs[rid] = jid
        return result

    def scan_repo(self, repo_id: int, *, audit_depth: Optional[int] = None) -> dict:
        """Trigger an audit; optionally override depth without changing Settings."""
        self._positive_id(repo_id, "repo_id")
        self._audit_depth(audit_depth)
        result = (self._post(f"/api/repos/{repo_id}/scan") if audit_depth is None else
                  self._post(f"/api/repos/{repo_id}/scan", {"audit_depth": audit_depth}))
        job_id = result.get("job_id", result.get("scan_job_id"))
        if isinstance(job_id, int) and not isinstance(job_id, bool) and job_id > 0:
            self._scan_jobs[repo_id] = job_id
        return result

    def get_scan_status(self, job_id: int) -> ScanJob:
        """Read exact-job metadata without downloading its full audit output.

        Use ``get_scan_details`` when the full recorded artifacts are needed.
        Progress, incomplete-evidence state, and recovery notices are retained.
        """
        self._positive_id(job_id, "job_id")
        data = self._get(f"/api/scan-jobs/{job_id}", params={"include_output": "false"})
        return self._scan_metadata(data)

    def get_audit_summary(self, repo_id: int) -> dict:
        """Get structured summary of the most recent audit for a repo."""
        return self._get(f"/api/repos/{repo_id}/audit-summary")

    def audit_chat(
        self,
        repo_id: int,
        message: str,
        action: str = "general",
    ) -> dict:
        """Chat with AI about an audit (intel, steering, Phase 2 modifications).

        Actions: general, query-intel, add-intel, modify-phase2, restart-phase2
        """
        return self._post(f"/api/repos/{repo_id}/audit-chat", {
            "message": message,
            "action": action,
        })

    def restart_phase2(
        self,
        repo_id: int,
        guidance: str = "",
        focus_areas: Optional[List[str]] = None,
    ) -> dict:
        """Re-trigger Phase 2 analysis with user-supplied guidance."""
        result = self._post(f"/api/repos/{repo_id}/restart-phase2", {
            "guidance": guidance,
            "focus_areas": focus_areas or [],
        })
        selected = result.get("job_id", result.get("scan_job_id"))
        if isinstance(selected, int) and not isinstance(selected, bool) and selected > 0:
            self._scan_jobs[repo_id] = selected
        else:
            self._scan_jobs.pop(repo_id, None)
        return result

    # ----- Findings -----

    def list_findings(self, repo_id: Optional[int] = None, min_cvss: Optional[float] = None) -> List[Finding]:
        """List all findings, optionally filtered."""
        data = self._get("/api/findings")
        findings = [Finding(**f) for f in data]
        if repo_id is not None:
            findings = [f for f in findings if f.repo_id == repo_id]
        if min_cvss is not None:
            findings = [f for f in findings if f.cvss >= min_cvss]
        return findings

    def get_finding(self, finding_id: int) -> Finding:
        """Get a specific finding."""
        data = self._get(f"/api/findings/{finding_id}")
        return Finding(**data)

    def create_finding(self, repo_id: int, title: str, cvss: float = 0.0, description: str = "") -> Finding:
        """Manually create a finding."""
        data = self._post("/api/findings", {
            "repo_id": repo_id,
            "title": title,
            "cvss": cvss,
            "description": description,
        })
        return Finding(**data)

    def validate_finding(self, finding_id: int) -> dict:
        """Run a finding through proof gates."""
        return self._post(f"/api/findings/{finding_id}/validate")

    def get_finding_fixes(self, finding_id: int) -> dict:
        """Get ranked remediation suggestions for a finding."""
        return self._get(f"/api/findings/{finding_id}/fixes")

    def get_finding_cvss(self, finding_id: int) -> dict:
        """Return the persisted CVSS vector/metrics and any score limitations."""
        return self._get(f"/api/findings/{finding_id}/cvss")

    def get_finding_source(self, finding_id: int, *, meta: bool = False):
        """Fetch source metadata (or the enrolled source text) for a finding."""
        return self._get(f"/api/findings/{finding_id}/source", params={"meta": int(meta)})

    def get_finding_reports(self, finding_id: int) -> List[dict]:
        """Return immutable report notebook/export links containing a finding."""
        return self._get(f"/api/findings/{finding_id}/reports")

    # ----- Reports -----

    def list_reports(self) -> List[Report]:
        """List all generated reports."""
        data = self._get("/api/reports")
        return [Report(**r) for r in data]

    def create_report(self, repo_id: int) -> Report:
        """Generate a new report from report-eligible findings."""
        data = self._post("/api/reports", {"repo_id": repo_id})
        return Report(**data)

    def get_report(self, report_id: int) -> dict:
        """Get report markdown content."""
        return self._get(f"/api/reports/{report_id}")


    def export_pdf(self, report_id: int, output_path: str) -> str:
        """Download report as PDF.

        Returns the output file path.
        """
        content = self._request("GET", f"/api/reports/{report_id}/pdf", raw=True)
        if not content.startswith(b"%PDF-"):
            raise LotusAPIError("Report export did not return a PDF; destination was preserved")
        destination = os.path.abspath(os.fspath(output_path))
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=os.path.dirname(destination), delete=False) as stream:
                temporary = stream.name
                stream.write(content)
            os.replace(temporary, destination)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
        return output_path

    # -- Report Review --

    def update_report(self, report_id: int, markdown: str) -> dict:
        """Update report markdown content."""
        return self._request("PUT", f"/api/reports/{report_id}", {"markdown": markdown})

    def get_report_findings(self, report_id: int) -> List[dict]:
        """Get findings associated with a report's repository."""
        return self._get(f"/api/reports/{report_id}/findings")

    def report_chat(
        self,
        report_id: int,
        message: str,
        action: str = "general",
        section: str = "",
        target_language: str = "",
    ) -> dict:
        """Chat with AI assistant about a report.

        Actions: general, rewrite, translate-poc, explain, summarize, test-version
        """
        body: Dict[str, Any] = {"message": message, "action": action}
        if section:
            body["section"] = section
        if target_language:
            body["target_language"] = target_language
        return self._request("POST", f"/api/reports/{report_id}/chat", body)

    def run_poc(
        self,
        report_id: int,
        code: str,
        language: str = "python",
        mode: str = "sandbox",
    ) -> dict:
        """Execute PoC code in sandbox or lab environment."""
        return self._request("POST", f"/api/reports/{report_id}/poc/run", {
            "code": code,
            "language": language,
            "mode": mode,
        })

    def launch_lab(self, report_id: int) -> dict:
        """Launch a lab container for a report's repository."""
        return self._request("POST", f"/api/reports/{report_id}/poc/launch-lab", {})

    def get_lab_status(self, report_id: int) -> dict:
        """Check lab container status for a report."""
        return self._get(f"/api/reports/{report_id}/poc/lab-status")

    def stop_lab(self, report_id: int) -> dict:
        """Stop the isolated lab pod registered for this report (no glob-delete)."""
        return self._request("POST", f"/api/reports/{report_id}/poc/stop-lab", {})

    # ----- Harness -----

    def list_harness_runs(self) -> List[HarnessRun]:
        """List all harness runs."""
        data = self._get("/api/harness")
        return [HarnessRun(**h) for h in data]

    def create_harness_run(
        self,
        repo_id: int,
        focus_areas: Optional[List[str]] = None,
        max_tokens: int = 50000,
        max_hours: float = 1.0,
        max_findings: int = 5,
    ) -> dict:
        """Create a new AI harness run."""
        body = {
            "repo_id": repo_id,
            "max_tokens": max_tokens,
            "max_hours": max_hours,
            "max_findings": max_findings,
        }
        if focus_areas:
            body["focus_areas"] = focus_areas
        return self._post("/api/harness", body)

    def deploy_harness(self, run_id: int) -> dict:
        """Start a harness run."""
        return self._post(f"/api/harness/{run_id}/deploy")

    def stop_harness(self, run_id: int) -> dict:
        """Stop a running harness."""
        return self._post(f"/api/harness/{run_id}/stop")

    # ----- Settings -----

    def get_settings(self) -> Settings:
        """Get current platform settings."""
        data = self._get("/api/settings")
        return Settings(**data)

    def update_settings(self, **kwargs) -> Settings:
        """Update platform settings.

        Pass any settings field as a keyword argument.
        Example: client.update_settings(cvss_threshold=8.0, audit_depth=3)
        """
        data = self._post("/api/settings", kwargs)
        return Settings(**data)

    # ----- Skills -----

    def list_skills(self) -> List[Skill]:
        """List all available skills."""
        data = self._get("/api/skills")
        return [Skill(**s) for s in data.get("skills", [])]

    # ----- Decisions -----

    def list_decisions(self, status: str = "pending") -> List[AuditDecision]:
        """List audit decisions."""
        data = self._get("/api/decisions", params={"status": status})
        return [AuditDecision(**d) for d in data]

    def answer_decision(self, decision_id: int, answer: str) -> dict:
        """Answer an audit decision."""
        return self._post(f"/api/decisions/{decision_id}/answer", {"answer": answer})

    def pending_decision_count(self) -> int:
        """Get count of pending audit decisions."""
        data = self._get("/api/decisions/count")
        return data.get("pending", 0)

    # ----- Dashboard & Stats -----

    def dashboard(self) -> Dashboard:
        """Get dashboard summary."""
        data = self._get("/api/dashboard")
        # The server groups counters; retain compatibility with older flat responses.
        for group, prefix in (("findings", "findings_"), ("scan_jobs", "scan_jobs_")):
            for key, value in (data.get(group) or {}).items():
                data.setdefault(prefix + key, value)
        return Dashboard(**data)

    def stats(self) -> dict:
        """Get system statistics."""
        return self._get("/api/debug/stats")

    # ----- Scan Jobs -----

    @staticmethod
    def _positive_id(value: int, name: str) -> None:
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer")

    @staticmethod
    def _page(limit: int, offset: int) -> None:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("limit must be an integer from 1 to 500")
        if type(offset) is not int or offset < 0:
            raise ValueError("offset must be a nonnegative integer")

    @staticmethod
    def _scan_metadata(data: dict) -> ScanJob:
        # Older servers may ignore include_output. Never retain that unrelated
        # body in the metadata model; explicit detail reads remain available.
        return ScanJob(**{key: value for key, value in data.items() if key != "output"})

    def list_scan_jobs(self, *, limit: int = 100, offset: int = 0,
                       status: Optional[str] = None) -> List[ScanJob]:
        """Read one metadata page, newest first (default 100; maximum 500).

        Advance ``offset`` explicitly to inspect older runs. This method does
        not automatically download the complete audit history.
        """
        self._page(limit, offset)
        if status is not None and (not isinstance(status, str) or status not in {
                "queued", "running", "paused", "completed", "failed", "cancelled", "interrupted"}):
            raise ValueError("Unknown audit status filter")
        params = {"limit": limit, "offset": offset}
        if status is not None:
            params["status"] = status
        data = self._get("/api/scan-jobs", params=params)
        return [self._scan_metadata(j) for j in data]

    def get_audit_progress(self, repo_id: int, *, job_id: int,
                           include_coverage_map: bool = False) -> dict:
        """Read exact-audit progress; lightweight map summaries are the default.

        Omitted coverage is marked by the server and is not an empty map. Pass
        ``include_coverage_map=True`` to explicitly read the full map.
        """
        self._positive_id(repo_id, "repo_id")
        self._positive_id(job_id, "job_id")
        if type(include_coverage_map) is not bool:
            raise ValueError("include_coverage_map must be a boolean")
        return self._get(f"/api/repos/{repo_id}/progress", params={
            "job_id": job_id, "include_coverage_map": "true" if include_coverage_map else "false"})

    def get_audit_sources(self, job_id: int, *, query: str = "", offset: int = 0,
                          limit: int = 200) -> dict:
        """Read a captured-source catalog page, including registered dependencies.

        A returned ``status='indexing'`` means preparation is still underway;
        it is not a completed empty inventory.
        """
        self._positive_id(job_id, "job_id")
        self._page(limit, offset)
        return self._get(f"/api/scan-jobs/{job_id}/sources", params={
            "query": query, "offset": offset, "limit": limit})

    def get_dependency_sources(self, job_id: int, *, offset: int = 0,
                               limit: int = 100) -> dict:
        """Read one page of declared/captured dependency source inventory."""
        self._positive_id(job_id, "job_id")
        self._page(limit, offset)
        return self._get(f"/api/scan-jobs/{job_id}/dependency-sources", params={
            "offset": offset, "limit": limit})

    def get_audit_source(self, job_id: int, file: str, *, start_line: int = 1,
                         line_count: int = 400, file_sha256: str = "") -> dict:
        """Read an authenticated source window, optionally pinned to a file hash.

        Preserve returned source/job/bundle identity when paging. Changed or
        unavailable evidence raises the API's error; it never switches audits.
        """
        self._positive_id(job_id, "job_id")
        self._positive_id(start_line, "start_line")
        if type(line_count) is not int or not 1 <= line_count <= 1000:
            raise ValueError("line_count must be an integer from 1 to 1000")
        return self._get(f"/api/scan-jobs/{job_id}/source", params={
            "file": file, "start_line": start_line, "line_count": line_count, "file_sha256": file_sha256})

    def get_audit_recovery(self, job_id: int) -> dict:
        """Read current exact-job completion options without taking an action."""
        self._positive_id(job_id, "job_id")
        return self._get(f"/api/scan-jobs/{job_id}/recovery")

    def continue_audit_with_gaps(self, job_id: int, *, checkpoint_id: str,
                                  idempotency_key: str) -> dict:
        """Explicitly continue an eligible checkpoint with unresolved gaps.

        Reuse the same key for an uncertain request. The server owns eligibility
        and source/lease checks; no automatic retry or settings change occurs.
        """
        self._positive_id(job_id, "job_id")
        return self._post(f"/api/scan-jobs/{job_id}/continue-with-gaps", {
            "checkpoint_id": checkpoint_id, "idempotency_key": idempotency_key})

    @staticmethod
    def _task_segment(task_name: str) -> str:
        from urllib.parse import quote
        if (not isinstance(task_name, str) or not task_name or len(task_name) > 128
                or any(char in task_name for char in ("/", "\\", "\x00"))
                or task_name in {".", ".."}):
            raise ValueError("task_name must be a nonempty single path segment")
        return quote(task_name, safe="")

    def get_task_recovery(self, job_id: int, task_name: str) -> dict:
        """Read a supported task's retry options and configuration revision."""
        self._positive_id(job_id, "job_id")
        task = self._task_segment(task_name)
        return self._get(f"/api/scan-jobs/{job_id}/tasks/{task}/recovery")

    def retry_audit_task(self, job_id: int, task_name: str, *,
                         configuration_revision: str, idempotency_key: str) -> dict:
        """Request one eligible task retry using its observed configuration.

        Reuse the key if the response is uncertain. A changed configuration,
        closed checkpoint, stale lease, or unavailable source remains an error.
        """
        self._positive_id(job_id, "job_id")
        task = self._task_segment(task_name)
        return self._post(f"/api/scan-jobs/{job_id}/tasks/{task}/retry", {
            "configuration_revision": configuration_revision, "idempotency_key": idempotency_key})

    def get_scan_details(self, job_id: int) -> dict:
        """Get detailed scan job information."""
        return self._get(f"/api/scan-jobs/{job_id}/details")

    # ----- Console -----

    def get_console_logs(self) -> List[str]:
        """Get current console log lines."""
        data = self._get("/api/console")
        return data.get("lines", [])

    # ----- Database Management -----

    def backup_db(self) -> dict:
        """Create a database backup."""
        return self._post("/api/db/backup")

    def reset_db(self) -> dict:
        """Reset the database (preserves AI settings)."""
        return self._post("/api/db/reset")

    # ----- Utilities -----

    def wait_for_scan(self, repo_id: int, poll_interval: float = 5, timeout: float = 600,
                      *, job_id: Optional[int] = None) -> str:
        """Wait for the exact scan accepted by ``scan_repo`` and return its final status.

        ``job_id`` explicitly selects a run after reconnecting. Without a known
        job, legacy callers poll repository status. Failed/cancelled outcomes
        are returned as such; they are never reported as successful scans.
        """
        if any(not math.isfinite(value) or value <= 0 for value in (poll_interval, timeout)):
            raise ValueError("poll_interval and timeout must be finite positive numbers")
        selected_job = job_id if job_id is not None else self._scan_jobs.get(repo_id)
        if selected_job is not None and (not isinstance(selected_job, int) or isinstance(selected_job, bool) or selected_job <= 0):
            raise ValueError("job_id must be a positive integer")
        terminal = {"idle", "error", "completed", "scanned", "failed", "cancelled", "canceled", "interrupted", "archived"}
        deadline = time.monotonic() + timeout
        while True:
            if selected_job is not None:
                job = self.get_scan_status(selected_job)
                if job.repo_id != repo_id:
                    raise LotusValidationError("Selected scan job belongs to a different repository")
                status = job.status
            else:
                status = self.get_repo(repo_id).status
            if status in terminal:
                return status
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LotusTimeoutError(f"Scan for repo {repo_id} did not complete within {timeout}s")
            time.sleep(min(poll_interval, remaining))

    def health_check(self) -> bool:
        """Check if the Lotus server is reachable."""
        try:
            self._get("/healthz")
            return True
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"LotusClient(base_url={self.base_url!r}, impl={self._impl!r})"
