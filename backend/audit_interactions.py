"""Bounded, read-only console navigation from the current audit's recorded data.

These descriptors do not authorize execution or confer proof. Existing detail,
source, skill and report readers retain their authentication/identity checks.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

MAX_ITEMS = 100
MAX_DETAIL_BYTES = 256 * 1024


def _text(value, limit=800):
    return value[:limit] if isinstance(value, str) else ""


def _id(value):
    return type(value) is int and value > 0


def _base(repo_id, scan_job_id, kind, status, summary):
    if not _id(repo_id) or not _id(scan_job_id):
        raise ValueError("Console interactions require an exact repository and audit")
    return {"type": "audit-interactions", "schema_version": 1, "repo_id": repo_id,
        "scan_job_id": scan_job_id, "kind": kind, "status": status,
        "summary": summary, "items": [], "actions": [], "leads": [],
        "evidence_role": "recorded-display-only"}


def _detail_id(repo_id, value):
    if (not isinstance(value, str) or not value.startswith(f"{repo_id}-") or len(value) > 200
            or any(ord(c) < 32 for c in value)):
        raise ValueError("Detail identity does not belong to this repository")
    return value


def _source(card, detail_id, lead):
    from backend.lead_sources import safe_relative_file
    path = lead.get("file") or lead.get("source_file")
    if not isinstance(path, str) or len(path) > 1024 or "://" in path or not safe_relative_file(path):
        return []
    line = lead.get("line", lead.get("source_line", 0))
    line = line if type(line) is int and 0 <= line <= 2**31 - 1 else 0
    index = len(card["leads"])
    card["leads"].append({"title": _text(lead.get("title"), 300), "file": path, "line": line,
        "description": _text(lead.get("description")), "evidence_scope": "recorded interpretation"})
    return [{"type": "source", "detail_id": detail_id, "lead_index": index,
             "file": path, "line": line, "label": "Open recorded source"}]


def _finish(card, recorded_count):
    # Items are display rows, not database entity identities. Keep their actual
    # recorded indexes; omission never renumbers a source action or an audit ID.
    card["recorded_count"] = recorded_count
    while True:
        card["omitted_count"] = max(0, recorded_count - len(card["items"]))
        if card["omitted_count"]:
            card["display_limit_reason"] = "Additional recorded rows remain in the audit artifact; this dialog is bounded."
        if len(json.dumps(card, ensure_ascii=True, allow_nan=False).encode()) <= MAX_DETAIL_BYTES:
            return card
        if not card["items"]:
            raise ValueError("Console interaction metadata exceeds the display bound")
        card["items"].pop()
        indexes = [action["lead_index"] for item in card["items"] for action in item.get("actions", [])
                   if action.get("type") == "source"]
        card["leads"] = card["leads"][:max(indexes) + 1] if indexes else []


def independent_review_detail(repo_id, scan_job_id, review, findings, *, detail_id=None):
    """Link each validated review to its exact input location, never a title join."""
    detail_id = _detail_id(repo_id, detail_id or f"{repo_id}-independent-judge")
    review = review if isinstance(review, dict) else {}
    findings = findings if isinstance(findings, list) else []
    rows = review.get("reviews")
    rows = rows if isinstance(rows, list) else []
    card = _base(repo_id, scan_job_id, "independent-review", "completed" if review.get("status") == "completed" else "pending",
                 "Recorded independent interpretations; model decisions are not vulnerability proof.")
    for row in rows[:MAX_ITEMS]:
        if not isinstance(row, dict):
            continue
        index = row.get("index")
        lead = findings[index] if type(index) is int and 0 <= index < len(findings) and isinstance(findings[index], dict) else None
        # This is the existing judge identity protocol, not a fabricated Finding id.
        expected = (hashlib.sha256(json.dumps([index, lead.get("title"), lead.get("file"), lead.get("line")],
                    sort_keys=True, default=str).encode()).hexdigest() if lead is not None else None)
        bound = isinstance(row.get("id"), str) and row["id"] == expected
        finding = row.get("finding") if isinstance(row.get("finding"), dict) else {}
        item = {"id": _text(row.get("id"), 128), "recorded_index": index if type(index) is int else None,
            "title": _text(finding.get("title") or (lead or {}).get("title"), 300),
            "status": "manual-review" if (lead or {}).get("manual_review_required") is True else "reviewed",
            "decision": _text(row.get("decision"), 32), "reason": _text(row.get("reason")),
            "actions": _source(card, detail_id, lead) if bound else []}
        if not bound:
            item.update(status="unavailable", pending_reason="Recorded review does not match its supplied input identity.")
        elif not item["actions"]:
            item["pending_reason"] = "No safe file location was recorded for this interpretation."
        card["items"].append(item)
    if not rows:
        card["pending_reason"] = "No completed independent review rows have been recorded."
    return _finish(card, len(rows))


def _prior_console(finding):
    """Display existing output only; do not reconstruct commands or execute them."""
    values = []
    poc = finding.get("poc")
    if isinstance(poc, dict) and isinstance(poc.get("output"), str):
        values.append(poc["output"])
    evidence = finding.get("lab_evidence")
    for entry in evidence[:8] if isinstance(evidence, list) else []:
        if isinstance(entry, dict):
            for field in ("stdout", "stderr", "output"):
                if isinstance(entry.get(field), str):
                    values.append(entry[field])
    from backend.scanners import _redact_scanner_output
    text = "\n".join(value[:4096] for value in values[:8])
    bounded = _redact_scanner_output(text[:4096])[:4096]
    return bounded, len(text) > 4096 or len(values) > 8 or any(len(value) > 4096 for value in values[:8])


def lab_verification_detail(repo_id, scan_job_id, findings, results, *, status="completed", detail_id=None):
    detail_id = _detail_id(repo_id, detail_id or f"{repo_id}-lab-verification")
    card = _base(repo_id, scan_job_id, "lab-verification", status,
        "Recorded PoC/fix measurements and prior console; no action here reruns a lab or verifies a finding.")
    findings = findings if isinstance(findings, list) else []
    rows = results if isinstance(results, list) else []
    # measure_pocs_and_fixes processes this exact ordered prefix, at most five.
    count = max(len(rows), min(5, len(findings)))
    for index in range(min(count, MAX_ITEMS)):
        finding = findings[index] if index < len(findings) and isinstance(findings[index], dict) else {}
        row = rows[index] if index < len(rows) and isinstance(rows[index], dict) else {}
        matched = not row or row.get("title") == (finding.get("title") or "finding")
        console, truncated = _prior_console(finding) if matched else ("", False)
        item = {"id": f"fix_verification/{index}", "recorded_index": index,
            "title": _text(row.get("title") or finding.get("title"), 300),
            "status": _text(row.get("quality"), 64) or ("pending" if status == "running" else "unavailable"),
            "reason": _text(row.get("verdict")) or "No new measurement outcome was recorded.",
            "actions": _source(card, detail_id, finding) if matched else [],
            "console_text": console, "console_truncated": truncated,
            "console_scope": "prior recorded PoC output; not a new execution"}
        if not matched:
            item["pending_reason"] = "The recorded measurement does not match this input position; no source association was inferred."
        elif not console:
            item["console_unavailable_reason"] = "No prior console output was retained for this item."
        if row.get("recommended"):
            item["recommended"] = _text(row["recommended"], 300)
        card["items"].append(item)
    if not count:
        card["pending_reason"] = "No proof-gated inputs or lab measurements were recorded."
    return _finish(card, count)


def _skill_action(path):
    from backend.skills import get_platform_home, get_skills_dir, get_learned_dir
    if not isinstance(path, str) or not path or len(path) > 4096:
        return None
    try:
        selected = Path(path).resolve(strict=True)
        roots = [Path(fn()).resolve() for fn in (get_platform_home, get_skills_dir, get_learned_dir)]
        if (not any(selected.is_relative_to(root) for root in roots) or not selected.is_file()
                or selected.suffix != ".md" or selected.stat().st_size > 1024 * 1024
                or any(ord(c) < 32 for c in selected.name)):
            return None
        # Bound the actual read too: the file can grow after its stat. Match the
        # existing skill reader's UTF-8/universal-newline text representation.
        with selected.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return None
        content = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        return {"type": "skill", "filename": selected.name,
                "sha256": hashlib.sha256(content.encode()).hexdigest(), "label": "View recorded skill version"}
    except (OSError, ValueError, UnicodeError):
        return None


def learned_skills_detail(repo_id, scan_job_id, result):
    card = _base(repo_id, scan_job_id, "learned-skills", "completed",
        "Files actually returned by skill creation/strengthening; a changed or unavailable file must be shown explicitly.")
    result = result if isinstance(result, dict) else {}
    entries = result.get("skills") if isinstance(result.get("skills"), list) else []
    paths = result.get("paths") if isinstance(result.get("paths"), list) else []
    if isinstance(result.get("path"), str):
        entries = [result]
    # Retrospective skills appear in paths but not necessarily in skills.
    combined = [row for row in entries if isinstance(row, dict)]
    known = {row.get("path") for row in combined if isinstance(row.get("path"), str)}
    combined += [{"path": path} for path in paths if isinstance(path, str) and path not in known]
    for index, row in enumerate(combined[:MAX_ITEMS]):
        action = _skill_action(row.get("path"))
        item = {"id": f"recorded_skills/{index}", "recorded_index": index,
            "title": _text(row.get("name"), 300) or (action["filename"] if action else "Recorded skill file"),
            "status": _text(row.get("action"), 64) or "written", "reason": _text(row.get("reason")),
            "actions": [action] if action else []}
        if not action:
            item["pending_reason"] = "The returned skill file is unavailable, outside the skills directory, or too large."
        card["items"].append(item)
    if not combined:
        card["pending_reason"] = "No actual written skill files were returned."
    return _finish(card, len(combined))


def report_detail(repo_id, scan_job_id, report=None, *, handoff=None):
    card = _base(repo_id, scan_job_id, "report", "pending", "Audit report")
    if isinstance(handoff, dict):
        scope = handoff.get("scope")
        if (not isinstance(scope, dict) or type(scope.get("repo_id")) is not int
                or type(scope.get("scan_job_id")) is not int
                or scope["repo_id"] != repo_id or scope["scan_job_id"] != scan_job_id):
            raise ValueError("Report handoff belongs to another audit")
        card["handoff"] = {key: _text(handoff.get(key), 128) for key in ("producer", "consumer", "status", "receipt_hash")}
    report = report if isinstance(report, dict) else {}
    bound = all(key not in report or type(report[key]) is int and report[key] == value
                for key, value in (("repo_id", repo_id), ("scan_job_id", scan_job_id)))
    if bound and _id(report.get("id")) and not report.get("error"):
        card.update(status="ready", actions=[{"type": "report", "report_id": report["id"], "label": "Open this audit's report"}])
    else:
        card["pending_reason"] = _text(report.get("error")) or "This audit has not yet recorded a completed report publication."
    return _finish(card, 0)


def recorded_report_detail(db, job):
    """Resolve only this audit's durable publication; never create or use latest."""
    from sqlalchemy import and_
    from sqlalchemy.orm import load_only
    from backend.main import ScanJob, Report, _load_report_manifest
    from backend.json_projection import read_json_projection
    repo_id, job_id = int(job.repo_id), int(job.id)
    card = report_detail(repo_id, job_id)
    card["publication_state"] = "pending"
    card["actions"] = [{"type": "detail", "detail_id": f"{repo_id}-handoff-triage-report",
                        "label": "Check report publication"}]
    if job.status not in {"completed", "failed", "cancelled", "interrupted"}:
        card["pending_reason"] = "Report preparation is in progress. Check publication again after this audit finishes."
        return card
    try:
        data = read_json_projection(db, ScanJob.output,
            and_(ScanJob.id == job_id, ScanJob.repo_id == repo_id),
            [("automatic_report", "id"), ("automatic_report", "error")])
        saved = data.get("automatic_report") or {}
        report_id = saved.get("id")
        if not _id(report_id) or saved.get("error"):
            card["publication_state"] = "unavailable"
            card["pending_reason"] = "This audit has no completed report publication recorded. Open its audit details to inspect or retry publication."
            return card
        row = db.query(Report).options(load_only(Report.id, Report.repo_id,
            Report.manifest_json, Report.manifest_hash, raiseload=True)).filter(
                Report.id == report_id, Report.repo_id == repo_id).first()
        manifest = _load_report_manifest(row) if row is not None else {}
        evidence = manifest.get("evidence") or {}
        recorded_job = evidence.get("scan_job_id") if isinstance(evidence, dict) else None
        # Match the existing canonical legacy-ID compatibility without booleans.
        if not (type(recorded_job) is int and recorded_job == job_id
                or type(recorded_job) is str and recorded_job == str(job_id)):
            card["publication_state"] = "unavailable"
            card["pending_reason"] = "The recorded report is unavailable or its verified publication does not match this exact audit."
            return card
        card = report_detail(repo_id, job_id, {"id": report_id, "repo_id": repo_id, "scan_job_id": job_id})
        card["publication_state"] = "published"
        return card
    except (TypeError, ValueError, AttributeError, RecursionError):
        card["publication_state"] = "unavailable"
        card["pending_reason"] = "This audit's publication metadata could not be read safely; no report link was inferred."
        return card
