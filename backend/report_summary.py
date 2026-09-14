"""Small presentation derived only from a verified, immutable report snapshot.

This module assigns no finding eligibility, proof status, or coverage credit.
The caller verifies the publication before invoking it; no live state is read.
"""
from __future__ import annotations

from collections import Counter
import html
import re
import unicodedata


def _obj(value):
    return value if isinstance(value, dict) else {}


def _count(value):
    return value if type(value) is int and 0 <= value <= 10**12 else None


def _text(value, limit=320):
    if not isinstance(value, str):
        return ""
    return " ".join("".join(
        c if c.isspace() or unicodedata.category(c) not in {"Cc", "Cf"} else ""
        for c in value[:limit * 2]
    ).split())[:limit]


def _md(value):
    value = html.escape(_text(value, 600), quote=False)
    escaped = re.sub(r"([\\`*_{}#!|>])", r"\\\1", value)
    # Ordinary branch labels such as [main] are literal text. Escape brackets
    # when they could introduce an inline/reference link or definition.
    if re.search(r"\]\s*(?:\(|\[|:)", value):
        escaped = escaped.replace("[", r"\[").replace("]", r"\]")
    return escaped


def recorded_lab_blocker(lab):
    """Select a structured recorded reason; never mine stdout or build logs."""
    lab = _obj(lab)
    recorded = _obj(lab.get("blocker"))
    adapter = _obj(_obj(lab.get("source_build")).get("adapter"))
    candidate = _obj(adapter.get("candidate"))
    # An earlier format rejection may have been repaired before the final
    # candidate declined a runtime. Do not present that repaired error as the
    # reason the lab is unavailable, including in derived historical summaries.
    if (adapter.get("status") == "blocked" and candidate.get("profile") == "unsupported"
            and _text(candidate.get("reason"))
            and (not recorded or str(recorded.get("source_ref", "")).startswith(
                "lab_status/source_build/adapter/attempts/"))):
        return {"reason": _text(candidate["reason"]),
                "source_ref": "lab_status/source_build/adapter/candidate/reason"}
    attempts = adapter.get("attempts")
    latest_primary = _obj(attempts[-1]) if isinstance(attempts, list) and 0 < len(attempts) <= 8 else {}
    judge = _obj(adapter.get("judge"))

    def same_candidate(review):
        review_hash = review.get("candidate_sha256")
        for primary_hash in (adapter.get("candidate_sha256"), latest_primary.get("candidate_sha256")):
            if primary_hash is not None and review_hash is not None and (
                    not isinstance(primary_hash, str) or not isinstance(review_hash, str)
                    or primary_hash != review_hash):
                return False
        return True

    # Only a final review of the last valid candidate may supersede a repaired
    # primary error. A later failed correction, build failure or unrelated
    # explicit blocker retains its own chronology and recorded provenance.
    if (adapter.get("status") == "blocked" and latest_primary.get("status") == "schema-valid"
            and candidate.get("profile") == "native-service" and not _obj(adapter.get("failure"))
            and (not recorded or str(recorded.get("source_ref", "")).startswith(
                "lab_status/source_build/adapter/attempts/"))):
        if judge.get("decision") == "revise" and _text(judge.get("reason")) and same_candidate(judge):
            return {"reason": _text(judge["reason"]),
                    "source_ref": "lab_status/source_build/adapter/judge/reason"}
        if judge.get("status") == "missing-after-revision" and _text(adapter.get("reason")) and same_candidate(judge):
            return {"reason": _text(adapter["reason"]),
                    "source_ref": "lab_status/source_build/adapter/reason"}
        reviews = adapter.get("judge_attempts")
        if judge.get("status") == "quality-blocked" and isinstance(reviews, list) and 0 < len(reviews) <= 8:
            latest_review = _obj(reviews[-1])
            if latest_review.get("status") == "invalid" and _text(latest_review.get("reason")) and same_candidate(latest_review):
                return {"reason": _text(latest_review["reason"]),
                        "source_ref": f"lab_status/source_build/adapter/judge_attempts/{len(reviews) - 1}/reason"}
    if _text(recorded.get("reason")) and _text(recorded.get("source_ref")):
        return {"reason": _text(recorded["reason"]), "source_ref": _text(recorded["source_ref"], 240)}
    # A compiled image is only an intermediate success. Preserve the later
    # structured startup/admission failure instead of its earlier build note.
    if (lab.get("healthy") is False and lab.get("status") in {
            "isolation-blocked", "apply-failed", "attestation-unavailable",
            "unhealthy", "run-failed", "failed", "timeout", "timed-out",
            "image-pull-failed", "crash-loop", "error",
    } and _text(lab.get("reason"))):
        return {"reason": _text(lab["reason"]), "source_ref": "lab_status/reason"}
    build = _obj(_obj(adapter.get("failure")).get("build"))
    if _text(build.get("reason")):
        return {"reason": _text(build["reason"]), "source_ref": "lab_status/source_build/adapter/failure/build/reason"}
    if isinstance(attempts, list):
        for index in range(min(len(attempts), 8) - 1, -1, -1):
            row = _obj(attempts[index])
            if row.get("status") in {"invalid", "failed", "blocked", "unsupported", "error"} and _text(row.get("reason")):
                return {"reason": _text(row["reason"]),
                        "source_ref": f"lab_status/source_build/adapter/attempts/{index}/reason"}
    for row, pointer in ((adapter, "lab_status/source_build/adapter/reason"), (lab, "lab_status/reason")):
        if _text(row.get("reason")):
            return {"reason": _text(row["reason"]), "source_ref": pointer}
    return {}


def build_report_summary(manifest, *, verified=False, expected_repo_id=None):
    """Project captured facts; missing or conflicting audit binding stays unknown."""
    unavailable = {"schema_version": 1, "status": "unavailable",
                   "reason": "A verified publication with an exact matching audit and source binding is required."}
    if verified is not True or not isinstance(manifest, dict):
        return unavailable
    evidence = _obj(manifest.get("evidence"))
    binding = _obj(_obj(manifest.get("report_context")).get("binding"))
    repo_id, job_id = binding.get("repo_id"), binding.get("scan_job_id")
    tree = _obj(binding.get("target_identity")).get("tree_hash")
    if expected_repo_id is not None and (type(expected_repo_id) is not int or repo_id != expected_repo_id):
        return unavailable
    if not (type(repo_id) is int and repo_id > 0 and type(job_id) is int and job_id > 0
            and isinstance(tree, str) and re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", tree)
            and type(evidence.get("repo_id")) is int and evidence["repo_id"] == repo_id
            and type(evidence.get("scan_job_id")) is int and evidence["scan_job_id"] == job_id
            and _obj(evidence.get("target_identity")).get("tree_hash") == tree):
        return unavailable
    findings = manifest.get("findings")
    if not isinstance(findings, list) or any(not isinstance(row, dict) for row in findings):
        return unavailable
    finding_count = sum(bool(row.get("report_eligible", True)) for row in findings)
    lifecycle = _obj(evidence.get("lead_lifecycle"))
    review = _obj(evidence.get("primary_triage"))
    ai_reviewed = _count(review.get("reviewed_count"))
    if ai_reviewed is None:
        ai_reviewed = _count(_obj(evidence.get("ai")).get("candidates_analyzed"))

    metadata = _obj(evidence.get("coverage_map_metadata"))
    coverage_bound = (metadata.get("status") == "recorded"
                      and type(metadata.get("repo_id")) is int and metadata["repo_id"] == repo_id
                      and type(metadata.get("scan_job_id")) is int and metadata["scan_job_id"] == job_id
                      and metadata.get("target_tree_hash") == tree)
    coverage = _obj(metadata.get("summary")) if coverage_bound else {}
    total, covered = _count(coverage.get("total")), _count(coverage.get("covered"))
    if total is None or covered is None or covered > total or _count(metadata.get("node_count")) != total:
        total = covered = None
    planning = _obj(coverage.get("planning"))
    source_reviewed = _count(planning.get("source_review_completed"))
    observations = _count(planning.get("observations"))
    if observations is None or source_reviewed is None or source_reviewed > observations:
        source_reviewed = None
    counts = {
        "findings": finding_count, "observations": _count(lifecycle.get("observations_examined")),
        "leads_retained": _count(lifecycle.get("leads_retained")), "ai_reviewed": ai_reviewed,
        "source_reviewed": source_reviewed, "runtime_covered": covered, "runtime_total": total,
    }
    lab, smoke = _obj(evidence.get("lab")), _obj(evidence.get("runtime_smoke"))
    lab_blocker = recorded_lab_blocker(lab)
    usable_lab = lab.get("healthy") is True and lab.get("status") not in {
        "failed", "rejected", "run-failed", "error", "unavailable", "disabled",
    }
    smoke_ok = smoke.get("ran") is True and smoke.get("ok") is True
    all_covered = (total is not None and total > 0 and covered == total
                   and coverage.get("complete") is True
                   and _obj(metadata.get("gate")).get("complete") is True)
    raw_gaps = evidence.get("gaps")
    gaps = list(dict.fromkeys(_text(gap) for gap in raw_gaps[:100] if _text(gap))) if isinstance(raw_gaps, list) else []
    # Known controller labels can be clarified in this read projection. Retain
    # arbitrary recorded diagnostic text and the signed source snapshot as-is.
    gap_labels = {
        "audit evidence contract is incomplete": "Required audit checks are incomplete.",
        "Phase 2 includes skipped applicable tasks; skipped work is not exhaustive evidence":
            "Some applicable Phase 2 checks were skipped; those checks did not validate target behavior.",
    }
    gaps = [gap_labels.get(gap, gap) for gap in gaps]
    incomplete = (not all_covered or not usable_lab or not smoke_ok or bool(gaps)
                  or evidence.get("evidence_status") != "complete")
    if finding_count:
        outcome = {"code": "findings_with_gaps" if incomplete else "findings_recorded",
                   "title": f"{finding_count} confirmed finding{'s' if finding_count != 1 else ''} published",
                   "detail": "Published findings met the required proof checks. Untested areas and limitations of the tests are listed separately."}
    else:
        outcome = {"code": "no_findings_incomplete" if incomplete else "no_findings_recorded_scope",
                   "title": "No confirmed findings; validation incomplete" if incomplete else "No confirmed findings in the recorded test scope",
                   "detail": "No lead met all requirements for a confirmed finding. This does not establish that the codebase is secure or that every retained lead is a false positive."}
    status = _text(evidence.get("job_status"), 64) or "unknown"
    completion = _text(evidence.get("completion_state"), 64) or "unknown"
    if completion == "preparing_evidence_report":
        workflow_detail = "Report published; this snapshot was captured during report preparation. Later job status is not part of this publication."
    elif status == "completed":
        workflow_detail = "The audit workflow completed. Source inspection and runtime validation are assessed separately below."
    else:
        workflow_detail = "Report published; the status below was saved with this report and may differ from the audit's current status."
    work = []
    tools_complete = _count(_obj(evidence.get("coverage")).get("completed"))
    if tools_complete is not None:
        work.append({"label": "Source analysis", "detail": f"{tools_complete} Phase 1 tools completed. This does not mean every source path was checked or that the target ran in a lab."})
    if ai_reviewed is not None:
        work.append({"label": "Primary AI review", "detail": f"{ai_reviewed} candidate interpretations reviewed. AI review does not confirm a vulnerability or replace a runtime test."})
    if source_reviewed is not None:
        work.append({"label": "Source review", "detail": f"{source_reviewed} source-review items completed. These are recorded review contexts, not counts of files, unique leads, or runtime tests."})
    runtime_detail = (f"{covered}/{total} mapped checks have recorded runtime validation results. "
                      if total is not None else "Runtime coverage counts were not recorded. ")
    if covered == 0:
        runtime_detail += "No runtime validation was completed for these checks. "
    runtime_detail += ("A usable lab and passing smoke check were recorded; finding proof is separate."
                       if usable_lab and smoke_ok else "No usable lab with a passing startup check was recorded; target behavior was not validated in that lab.")
    work.append({"label": "Runtime validation", "detail": runtime_detail})
    unverified = []
    if not usable_lab:
        unverified.append("Target runtime behavior was not verified in a usable lab.")
        unverified.append("Recorded lab blocker: " + lab_blocker["reason"] if lab_blocker else
                          "The publication did not retain the lab rejection reason; inspect the recorded audit details.")
    elif not smoke_ok:
        unverified.append("A passing target runtime smoke check was not recorded.")
    if not all_covered:
        unverified.append(f"{total - covered} of {total} mapped checks still lack runtime validation." if total is not None
                          else "Complete, target-bound coverage accounting is unavailable.")
    unverified.extend(gaps)
    unverified = list(dict.fromkeys(unverified))[:5]

    # Labels are recorded observations, not inferred security categories. Repeated
    # map nodes are explicitly counted as nodes, never as unique vulnerabilities.
    mapped = _obj(evidence.get("coverage_map"))
    nodes = mapped.get("nodes")
    node_counts = Counter()
    if (coverage_bound and mapped.get("repo_id") == repo_id
            and mapped.get("scan_job_id", job_id) == job_id
            and mapped.get("target_tree_hash", tree) == tree and isinstance(nodes, list)):
        for node in nodes[:10000]:
            node = _obj(node)
            if node.get("kind") == "lead" and node.get("status") != "covered":
                label = _text(node.get("label"), 160)
                if label:
                    node_counts[label] += 1
    risk_areas = [{"label": label, "count": count, "scope": "unproven"}
                  for label, count in sorted(node_counts.items(), key=lambda row: (-row[1], row[0]))[:5]]
    actions = []
    if finding_count:
        actions.append({"title": "Address published findings", "detail": "Review each finding's saved test results and impact, apply a fix, and rerun its original test and negative control."})
    if not usable_lab or not smoke_ok:
        actions.append({"title": "Restore a working test lab", "detail": "Check the saved lab setup or build logs, fix any missing prerequisites, and retry the same code revision in an isolated lab."})
    if counts["leads_retained"] or risk_areas:
        actions.append({"title": "Review unproven leads", "detail": "Prioritize exposed trust boundaries, check the real source path and guards, then validate impact in the exact target runtime. Lead counts are not vulnerability counts."})
    if not all_covered:
        actions.append({"title": "Close the coverage gaps", "detail": "Use the coverage map to find missing checks and unavailable tools. Rerun the affected checks and compare the new results."})
    else:
        actions.append({"title": "Review the test scope and oracles", "detail": "Confirm that recorded tests cover the intended deployment and security boundaries; successful checks do not establish universal absence of vulnerabilities."})
    if len(actions) < 3:
        actions.append({"title": "Keep a baseline for future audits", "detail": "Keep this report's code revision and saved artifacts, and rerun the relevant checks after code or deployment changes."})
    return {"schema_version": 1, "status": "available", "repo_id": repo_id, "scan_job_id": job_id,
            "target_tree_hash": tree, "target": _text(manifest.get("target"), 240),
            "outcome": outcome, "workflow": {"status": status, "completion_state": completion, "detail": workflow_detail},
            "counts": counts, "work_performed": work, "risk_areas": risk_areas,
            "unverified": unverified, "next_steps": actions[:3], "runtime_blocker": lab_blocker,
            "limitations": "This summary uses the saved audit results and does not certify that the code is secure. Counts cover different steps and should not be added together. Risk counts describe coverage items, not unique leads. The appendix links to the full saved records."}


def render_summary(summary):
    """Concise Markdown introduction; untrusted snapshot text stays literal."""
    if summary.get("status") != "available":
        return ["# Lotus Security Report", "", "## Executive Summary", "",
                "A summary tied to this audit is unavailable. Review the saved results and limitations in the appendix.", ""]
    lines = ["# Lotus Security Report", "", "## Executive Summary", "",
             f"**{_md(summary['outcome']['title'])}**", "", _md(summary["outcome"]["detail"]), "",
             f"**Target:** {_md(summary['target'])}",
             f"**Audit:** {summary['scan_job_id']} · **Source:** {summary['target_tree_hash']}", "",
             _md(summary["workflow"]["detail"]), "", "### What was done", ""]
    counts = summary["counts"]
    if counts["observations"] is not None or counts["leads_retained"] is not None:
        display = lambda v: "not recorded" if v is None else str(v)
        lines.append(f"- Discovery: {display(counts['observations'])} observations recorded; {display(counts['leads_retained'])} leads retained. These counts do not mean the leads were tested or confirmed.")
    lines += [f"- **{_md(row['label'])}:** {_md(row['detail'])}" for row in summary["work_performed"]]
    if summary["unverified"]:
        lines += ["", "### What remains unverified", ""]
        lines += [f"- {_md(gap)}" for gap in summary["unverified"]]
    if summary["risk_areas"]:
        lines += ["", "### Unproven areas to review", ""]
        lines += [f"- {_md(row['label'])} — {row['count']} recorded lead observations; not confirmed findings."
                  for row in summary["risk_areas"]]
    lines += ["", "### Next steps", ""]
    lines += [f"{index}. **{_md(row['title'])}:** {_md(row['detail'])}"
              for index, row in enumerate(summary["next_steps"], 1)]
    return lines + ["", _md(summary["limitations"]), ""]


def render_evidence_appendix(summary):
    """Keep verbose execution records accessible without duplicating them here."""
    job_id = summary["scan_job_id"]
    return ["## Saved audit results and artifacts", "",
            "The report's verified manifest retains the full captured coverage map, tool results, lab attempts, code revision, and notebook context. Saved observations are not additional confirmed findings.", "",
            "Download the artifacts ZIP from this report to inspect the manifest and saved audit files. The export lists file hashes, size limits, and omissions; it may not include every source or runtime artifact.", "",
            f"- [Recorded audit details](/api/scan-jobs/{job_id}/details)",
            f"- [Captured source snapshot](/api/scan-jobs/{job_id}/snapshot)",
            "- The report's saved-results and notebook panels retain source context, recorded commands, and observations. Running a command still requires the lab from this exact audit.", ""]
