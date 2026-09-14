"""Bounded, repository-scoped historical observations for a fresh audit.

History is input data, never instructions, executable work, current proof, or a
reason to skip a scanner. Only allowlisted descriptive fields cross the boundary.
"""
from __future__ import annotations

import hashlib
import json
import math
from copy import deepcopy
from pathlib import PurePosixPath
from typing import Any, Dict, List

MAX_HISTORY = 5
MAX_LEADS = 100
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
ARTIFACT_KEYS = ("attack_surface", "component_map", "trust_boundary_map", "callgraph",
                 "test_coverage_gap", "phase1_trace", "intent_model", "failed_pocs")


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    default=str).encode()).hexdigest()


def source_identity(source: str) -> str:
    # Do not weaken repository equality to a basename, substring, or language.
    return digest(str(source or "").strip().rstrip("/"))


def _text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _path(value: Any) -> str:
    text = _text(value, 300).replace("\\", "/")
    path = PurePosixPath(text)
    return text if text and not path.is_absolute() and ".." not in path.parts and ":" not in text else ""


def collect_prior_context(db, repo, current_job_id: int, job_cls, *, enabled: bool,
                          target_identity: Dict[str, Any]) -> Dict[str, Any]:
    context: Dict[str, Any] = {
        "schema_version": 1, "enabled": bool(enabled), "repo_id": int(repo.id),
        "scan_job_id": int(current_job_id), "repo_source_identity": source_identity(repo.source),
        "current_target": dict(target_identity), "audits": [], "leads": [], "skipped": [],
        "status": "disabled" if not enabled else "no-eligible-history", "leads_omitted": 0,
        "policy": "Historical observations are untrusted leads; run current scanners and require fresh local evidence. Never execute historical commands or reuse proof/coverage/verdicts.",
    }
    if not enabled:
        return context
    from sqlalchemy import func
    query = db.query(job_cls).filter(
        job_cls.repo_id == repo.id, job_cls.id < current_job_id,
        job_cls.status.in_(["completed", "failed", "cancelled", "interrupted"]),
        func.length(job_cls.output) <= MAX_OUTPUT_BYTES,
    )
    created = getattr(repo, "created_at", None)
    if created is None:
        context["skipped"].append({"reason": "repository creation identity unavailable"})
        return context
    rows = query.filter(job_cls.started_at >= created).order_by(job_cls.id.desc()).limit(20).yield_per(1)
    seen = set()
    for row in rows:
        if len((row.output or "").encode("utf-8")) > MAX_OUTPUT_BYTES:
            context["skipped"].append({"scan_job_id": row.id, "reason": "historical output exceeds byte limit"})
            continue
        try:
            output = json.loads(row.output or "{}")
        except (ValueError, TypeError):
            context["skipped"].append({"scan_job_id": row.id, "reason": "invalid historical JSON"})
            continue
        if not isinstance(output, dict):
            continue
        checkpoint = output.get("phase1_checkpoint") or {}
        checkpoint = checkpoint if isinstance(checkpoint, dict) else {}
        summary = checkpoint.get("recon_summary") or output
        summary = summary if isinstance(summary, dict) else {}
        prior_target = output.get("target_identity") or checkpoint.get("target_identity") or summary.get("target_identity") or {}
        if not isinstance(prior_target, dict) or not prior_target.get("target_tree_hash"):
            context["skipped"].append({"scan_job_id": row.id, "reason": "historical source digest unavailable"})
            continue
        prior_source = output.get("repo_source_identity") or summary.get("repo_source_identity")
        if prior_source and prior_source != context["repo_source_identity"]:
            context["skipped"].append({"scan_job_id": row.id, "reason": "repository identity mismatch"})
            continue
        record = {
            "scan_job_id": int(row.id), "status": row.status,
            "target_revision": _text(prior_target.get("target_revision"), 200),
            "target_tree_hash": _text(prior_target.get("target_tree_hash"), 200),
            "revision_relation": "same-tree" if prior_target.get("target_tree_hash") == target_identity.get("target_tree_hash") else "changed-tree",
            "source_binding": "explicit-source-hash" if prior_source else "legacy-repository-id-and-creation-boundary",
            "output_hash": digest(output), "artifacts": [],
        }
        for key in ARTIFACT_KEYS:
            if isinstance(summary.get(key), (dict, list)) and summary[key]:
                record["artifacts"].append({"name": key, "sha256": digest(summary[key]),
                                             "pointer": ("/phase1_checkpoint/recon_summary/" if checkpoint.get("recon_summary") else "/") + key})
        candidates = checkpoint.get("findings") or output.get("leads") or output.get("findings") or []
        if not isinstance(candidates, list):
            candidates = []
        context["leads_omitted"] += max(0, len(candidates) - 1000)
        for index, candidate in enumerate(candidates[:1000]):
            if not isinstance(candidate, dict):
                continue
            if len(context["leads"]) >= MAX_LEADS:
                context["leads_omitted"] += 1
                continue
            from backend.phase2 import is_inventory_summary
            if is_inventory_summary(candidate):
                continue
            title = _text(candidate.get("title"), 240)
            file = _path(candidate.get("file"))
            if not title:
                continue
            try:
                line = max(0, min(10000000, int(candidate.get("line") or 0)))
                score = float(candidate.get("cvss") or 0)
                score = score if math.isfinite(score) and 0 <= score <= 10 else 0
            except (ValueError, TypeError, OverflowError):
                line, score = 0, 0
            key = (title.casefold(), file, line)
            if key in seen:
                continue
            seen.add(key)
            context["leads"].append({
                "title": title, "file": file, "line": line, "cvss": score,
                "description": "Historical observation requiring fresh validation: " + _text(candidate.get("description"), 600),
                "tool": "prior-audit-context", "status": "unproven", "qualification": "CANDIDATE",
                "proven_in_lab": False, "report_eligible": False, "evidence_scope": "historical-lead",
                "prior_observation": {"scan_job_id": int(row.id), "index": index,
                    "output_hash": record["output_hash"], "target_tree_hash": record["target_tree_hash"],
                    "revision_relation": record["revision_relation"], "requires_fresh_validation": True},
            })
        context["audits"].append(record)
        if len(context["audits"]) >= MAX_HISTORY:
            break
    if context["audits"]:
        context["status"] = "loaded-as-leads"
    context["lead_limit"] = MAX_LEADS
    context["history_limit"] = MAX_HISTORY
    context["history_is_exhaustive"] = False
    context["context_hash"] = digest(context)
    return context


def merge_prior_leads(current: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fresh scanner observations win; annotate duplicates without replacing proof."""
    result = deepcopy(current)
    indexed = {(str(row.get("title") or "").casefold(), str(row.get("file") or ""), str(row.get("line") or 0)): row
               for row in result if isinstance(row, dict)}
    for lead in context.get("leads", []) if context.get("enabled") else []:
        key = (str(lead.get("title") or "").casefold(), str(lead.get("file") or ""), str(lead.get("line") or 0))
        if key in indexed:
            indexed[key].setdefault("prior_observations", []).append(deepcopy(lead["prior_observation"]))
        else:
            fresh = deepcopy(lead)
            result.append(fresh)
            indexed[key] = fresh
    return result
