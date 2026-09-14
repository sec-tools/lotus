"""Lotus SDK data models.

Typed Pydantic models matching the Lotus REST API responses.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict


class Repo(BaseModel):
    id: int
    source: str
    branch: str = "main"
    mode: str = "one-time"
    status: str = "pending"
    created_at: Optional[str] = None


class Finding(BaseModel):
    id: int
    repo_id: int
    title: str
    cvss: float = 0.0
    status: str = "unproven"
    report_eligible: bool = False
    description: str = ""
    ai_response: str = ""
    created_at: Optional[str] = None
    file: str = ""
    line: Optional[int] = None
    source_url: str = ""
    source_api_url: str = ""
    evidence_scope: str = "unknown"
    report_ids: List[int] = Field(default_factory=list)
    target_revision: str = ""


class Report(BaseModel):
    id: int
    repo_id: Optional[int] = None
    created_at: Optional[str] = None
    markdown: str = ""
    title: Optional[str] = None
    target: Optional[str] = None
    findings_count: Optional[int] = 0
    critical_count: Optional[int] = 0
    high_count: Optional[int] = 0


class ScanJob(BaseModel):
    # Keep new metadata available across server upgrades. Status reads exclude
    # the full output artifact before constructing this model.
    model_config = ConfigDict(extra="allow")
    id: int
    repo_id: int
    status: str = "pending"
    audit_depth: Optional[int] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    tool_results: Optional[str] = None
    phase: Optional[str] = None
    current_task: Optional[str] = None
    progress_pct: Optional[float] = None
    eta_seconds: Optional[int] = None
    evidence_complete: bool = False
    evidence_status: Optional[str] = None
    completion_state: Optional[str] = None
    task_recovery: Optional[Dict[str, Any]] = None
    audit_recovery: Optional[Dict[str, Any]] = None
    coverage_map_summary: Optional[Dict[str, Any]] = None


class HarnessRun(BaseModel):
    id: int
    repo_id: int
    status: str = "pending"
    focus_areas: List[str] = Field(default_factory=list)
    max_tokens: int = 50000
    max_hours: float = 1.0
    max_findings: int = 5
    tokens_used: int = 0
    findings_count: int = 0
    iterations: int = 0
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    created_at: Optional[str] = None


class Settings(BaseModel):
    # Keep new server settings available to clients across rolling upgrades.
    model_config = ConfigDict(extra="allow")
    cvss_threshold: float = 7.0
    default_lab_image: str = "ubuntu:26.04"
    validation_mode: str = "manual"
    ai_provider: str = "devin"
    ai_model: str = ""
    ai_session_mode: str = "batch"
    ai_api_key: str = ""
    ai_base_url: str = ""
    harness_api_key: str = ""
    lab_url: str = ""
    skills_dir: str = ""
    audit_depth: int = 3
    phase2_max_iterations: int = 3
    callgraph_max_files: int = 200
    slack_enabled: bool = False
    slack_webhook_url: str = ""
    slack_channel: str = ""
    api_keys: Dict[str, Any] = Field(default_factory=dict)
    notify_scan_complete: bool = True
    notify_new_finding: bool = True
    notify_report_ready: bool = True
    notify_lab_failure: bool = False
    available_models: Dict[str, list] = Field(default_factory=dict)
    fuzzing_enabled: bool = False
    crash_triage_enabled: bool = True
    phase2_approval_required: bool = False
    static_analysis_enabled: bool = True
    dependency_audit_enabled: bool = True
    callgraph_enabled: bool = True
    dynamic_fuzzing_enabled: bool = False
    dynamic_path_exploration_enabled: bool = True
    phase2_dynamic_testing_enabled: bool = True
    lab_validation_enabled: bool = True
    reuse_prior_audit_artifacts: bool = False
    skills_count: int = 0


class Dashboard(BaseModel):
    repos: int = 0
    findings_total: int = 0
    findings_unproven: int = 0
    findings_below_threshold: int = 0
    findings_report_eligible: int = 0
    reports: int = 0
    scan_jobs_queued: int = 0
    scan_jobs_running: int = 0
    scan_jobs_completed: int = 0
    scan_jobs_paused: int = 0
    scan_jobs_failed: int = 0
    scan_jobs_cancelled: int = 0
    scan_jobs_interrupted: int = 0
    cvss_threshold: float = 7.0


class Skill(BaseModel):
    filename: str = ""
    title: str = ""
    category: str = ""
    pack: str = ""


class AuditDecision(BaseModel):
    id: int
    repo_id: int
    scan_job_id: Optional[int] = None
    category: str = ""
    question: str = ""
    options: List[str] = Field(default_factory=list)
    context: str = ""
    status: str = "pending"
    answer: Optional[str] = None
    auto_answer: Optional[str] = None
    created_at: Optional[str] = None


class SystemStats(BaseModel):
    repos: int = 0
    findings: Dict[str, int] = Field(default_factory=dict)
    disk: Dict[str, Any] = Field(default_factory=dict)
    cpu: float = 0.0
    ram: Dict[str, Any] = Field(default_factory=dict)
