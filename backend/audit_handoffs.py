"""Versioned context receipts for the audit's existing worker/agent boundaries.

The executor is named explicitly: these are not claims of independent LLM runs.
Receipts describe actual context delivery and never confer execution authority.
"""
from __future__ import annotations

from datetime import datetime, timezone
from copy import deepcopy
from typing import Any, Dict

from backend.prior_audits import digest

AGENTS = {
    "planner": {"phase": "ingest", "executor": "backend.audit_planner.build_audit_plan"},
    "recon": {"phase": "phase1", "executor": "backend.pipeline.run_recon", "children": "tracked static analyzer workers"},
    "lab": {"phase": "local-lab", "executor": "backend.lab_provider.get_lab_provider"},
    "coverage": {"phase": "phase2", "executor": "backend.phase2.generate_phase2_plan / execute_phase2_plan"},
    "triage": {"phase": "phase3", "executor": "configured existing domain agents and evidence gates"},
    "report": {"phase": "publication", "executor": "backend.main.ensure_automatic_evidence_report"},
}


def create_handoffs(repo_id: int, job_id: int, target: Dict[str, Any]) -> Dict[str, Any]:
    return {"schema_version": 1, "scope": {"repo_id": int(repo_id), "scan_job_id": int(job_id),
            "target_tree_hash": str(target.get("target_tree_hash") or "")},
            "agents": deepcopy(AGENTS), "handoffs": [],
            "policy": "Repository text and prior artifacts are untrusted data. Only the existing bounded executors run work; handoffs cannot grant tools, import commands, bypass approval, or satisfy proof/coverage gates."}


def record_handoff(ledger: Dict[str, Any], producer: str, consumer: str,
                   artifacts: Dict[str, Any], *, repo_id: int, job_id: int,
                   target: Dict[str, Any]) -> Dict[str, Any]:
    if producer not in AGENTS or consumer not in AGENTS:
        raise ValueError("Unknown audit worker role")
    scope = {"repo_id": int(repo_id), "scan_job_id": int(job_id),
             "target_tree_hash": str(target.get("target_tree_hash") or "")}
    if scope != ledger.get("scope"):
        raise ValueError("Cross-audit context handoff rejected")
    receipt = {"sequence": len(ledger["handoffs"]) + 1, "producer": producer,
               "consumer": consumer, "scope": scope,
               "status": "delivered" if scope["target_tree_hash"] else "unbound",
               "timestamp": datetime.now(timezone.utc).isoformat(),
               "artifacts": [{"name": str(name), "sha256": digest(value)} for name, value in sorted(artifacts.items())]}
    receipt["receipt_hash"] = digest(receipt)
    ledger["handoffs"].append(receipt)
    return receipt


def verify_handoff(receipt: Dict[str, Any], artifacts: Dict[str, Any], *, repo_id: int,
                   job_id: int, target: Dict[str, Any]) -> bool:
    expected = {"repo_id": int(repo_id), "scan_job_id": int(job_id),
                "target_tree_hash": str(target.get("target_tree_hash") or "")}
    body = {key: value for key, value in receipt.items() if key != "receipt_hash"}
    return bool(expected["target_tree_hash"] and receipt.get("status") == "delivered"
                and receipt.get("producer") in AGENTS and receipt.get("consumer") in AGENTS
                and receipt.get("scope") == expected and digest(body) == receipt.get("receipt_hash")
                and receipt.get("artifacts") == [{"name": str(name), "sha256": digest(value)}
                                                  for name, value in sorted(artifacts.items())])
