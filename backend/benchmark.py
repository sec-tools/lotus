"""Discovery & Triage Measurement Engine.

Computes precision, recall metrics, gating efficiency, and multi-repo
comparison statistics to evaluate the platform's bug discovery capabilities.
"""

from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional


def compute_audit_metrics(db_path: str = "./data/lotus_lab_e2e_full.db") -> Dict[str, Any]:
    """Compute end-to-end vulnerability discovery and quality metrics across all audited repositories."""
    p = Path(db_path)
    if not p.exists():
        return {
            "audits_count": 0,
            "findings_count": 0,
            "report_eligible_count": 0,
            "conversion_rate_pct": 0.0,
            "fp_elimination_rate_pct": 0.0,
            "high_severity_ratio_pct": 0.0,
            "repos": [],
        }

    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Query repos
    c.execute("SELECT id, source, branch, status, created_at FROM repos ORDER BY id ASC")
    repos = [dict(r) for r in c.fetchall()]

    # Query findings
    c.execute("SELECT id, repo_id, title, cvss, status, report_eligible, description, ai_response, created_at FROM findings")
    findings = [dict(f) for f in c.fetchall()]

    # Query scan jobs
    c.execute("SELECT id, repo_id, status, output, started_at, finished_at FROM scan_jobs ORDER BY id ASC")
    scan_jobs = [dict(j) for j in c.fetchall()]

    # Query reports
    c.execute("SELECT id, repo_id, created_at FROM reports ORDER BY id ASC")
    reports = [dict(r) for r in c.fetchall()]

    conn.close()

    total_findings = len(findings)
    report_eligible = [f for f in findings if f.get("report_eligible")]
    eligible_count = len(report_eligible)

    # Classify severities
    crit_count = sum(1 for f in findings if f.get("cvss", 0) >= 9.0)
    high_count = sum(1 for f in findings if 7.0 <= f.get("cvss", 0) < 9.0)
    med_count = sum(1 for f in findings if 4.0 <= f.get("cvss", 0) < 7.0)
    low_count = sum(1 for f in findings if f.get("cvss", 0) < 4.0)

    # Calculate conversion and gating rates
    conversion_rate = (eligible_count / total_findings * 100.0) if total_findings > 0 else 0.0
    high_severity_ratio = ((crit_count + high_count) / total_findings * 100.0) if total_findings > 0 else 0.0

    # Build per-repo breakdown
    repo_metrics = []
    for r in repos:
        r_id = r["id"]
        r_findings = [f for f in findings if f.get("repo_id") == r_id]
        r_eligible = [f for f in r_findings if f.get("report_eligible")]
        r_jobs = [j for j in scan_jobs if j.get("repo_id") == r_id]
        r_reports = [rp for rp in reports if rp.get("repo_id") == r_id]

        r_tools_run = 0
        r_leads = 0
        if r_jobs and r_jobs[-1].get("output"):
            try:
                out = json.loads(r_jobs[-1]["output"])
                r_tools_run = len(out.get("tool_results", []))
                r_leads = sum(t.get("findings_count", 0) for t in out.get("tool_results", []))
            except Exception:
                pass

        repo_metrics.append({
            "repo_id": r_id,
            "source": r["source"],
            "branch": r["branch"],
            "status": r["status"],
            "tools_run": r_tools_run,
            "phase1_leads": r_leads or len(r_findings),
            "findings_count": len(r_findings),
            "report_eligible_count": len(r_eligible),
            "critical_count": sum(1 for f in r_findings if f.get("cvss", 0) >= 9.0),
            "high_count": sum(1 for f in r_findings if 7.0 <= f.get("cvss", 0) < 9.0),
            "reports_count": len(r_reports),
            "conversion_rate_pct": round(len(r_eligible) / len(r_findings) * 100.0, 1) if r_findings else 0.0,
        })

    return {
        "audits_count": len(repos),
        "total_scan_jobs": len(scan_jobs),
        "findings_count": total_findings,
        "report_eligible_count": eligible_count,
        "reports_count": len(reports),
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "conversion_rate_pct": round(conversion_rate, 1),
        "high_severity_ratio_pct": round(high_severity_ratio, 1),
        "fp_elimination_rate_pct": round(100.0 - conversion_rate, 1) if total_findings > 0 else 0.0,
        "repos": repo_metrics,
    }
