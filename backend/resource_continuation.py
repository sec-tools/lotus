"""Explicit incomplete-report admission, separate from evidence completeness."""
from copy import deepcopy
import re

POLICIES = {"strict", "report_incomplete", "continue_with_gaps"}
RESOURCE_CLASSES = {"oom_killed", "queue_timeout", "execution_timeout", "evicted"}
TASK_TO_TOOL = {"gosec": "gosec", "govulncheck": "govulncheck", "staticcheck": "staticcheck",
                "semgrep": "semgrep", "semgrep-registry": "semgrep",
                "dynamic-path-exploration": "gofuzz", "joern-cpg": "joern"}


def audit_continuation_policy(recon, settings, *, repo_id, scan_job_id):
    """An earlier audit's recovery choice cannot waive a new audit's policy."""
    captured = settings.get("resource_gap_policy", "strict")
    captured = captured if captured in POLICIES else "strict"
    recovery = recon.get("task_recovery")
    if (isinstance(recovery, dict) and recovery.get("schema_version") == 1
            and type(recovery.get("repo_id")) is int and recovery["repo_id"] == repo_id
            and type(recovery.get("scan_job_id")) is int and recovery["scan_job_id"] == scan_job_id
            and recovery.get("continuation_policy") in POLICIES):
        return recovery["continuation_policy"]
    return captured


def resource_failure(row):
    """Only controller-owned runtime receipts or typed admission decisions qualify."""
    if not isinstance(row, dict) or row.get("status") not in {"failed", "blocked"}:
        return None
    task = row.get("name") or row.get("task_name")
    tool = TASK_TO_TOOL.get(task)
    if not tool:
        return None
    diagnostic = row.get("runtime_diagnostic") or {}
    owned_kubernetes = (isinstance(diagnostic, dict) and diagnostic.get("provider") == "kubernetes"
                        and all(diagnostic.get(key) for key in ("job_uid", "pod_uid", "image")))
    owned_joern_docker = (isinstance(diagnostic, dict) and tool == "joern"
        and diagnostic.get("provider") == "docker"
        and re.fullmatch(r"[a-f0-9]{64}", str(diagnostic.get("container_id") or ""))
        and re.fullmatch(r"sha256:[a-f0-9]{64}", str(diagnostic.get("image_id") or ""))
        and diagnostic.get("image"))
    policy = row.get("resource_policy") or {}
    effective = policy.get("effective") or {} if isinstance(policy, dict) else {}
    owned_go_docker = (isinstance(diagnostic, dict) and tool in {"gosec", "govulncheck", "staticcheck", "semgrep"}
        and diagnostic.get("provider") == "docker"
        and diagnostic.get("classification") in {"oom_killed", "queue_timeout", "execution_timeout"}
        and re.fullmatch(r"[a-f0-9]{64}", str(diagnostic.get("container_id") or ""))
        and re.fullmatch(r"sha256:[a-f0-9]{64}", str(diagnostic.get("image_id") or ""))
        and diagnostic.get("image") and diagnostic.get("cleanup_verified") is True
        and diagnostic.get("resource_envelope_verified") is True
        and isinstance(effective, dict) and type(effective.get("memory_mb")) is int
        and diagnostic.get("memory_limit") == f"{effective['memory_mb']}Mi"
        and type(effective.get("timeout_seconds")) is int
        and diagnostic.get("timeout_seconds") == effective["timeout_seconds"]
        and type(effective.get("queue_timeout_seconds")) is int
        and diagnostic.get("queue_timeout_seconds") == effective["queue_timeout_seconds"])
    if (isinstance(diagnostic, dict) and diagnostic.get("ownership_verified") is True
            and diagnostic.get("tool_id") == tool and diagnostic.get("classification") in RESOURCE_CLASSES
            and (owned_kubernetes or owned_joern_docker or owned_go_docker)):
        return {"task_name": task, "configure_tool": tool, "classification": diagnostic["classification"],
                "reason": row.get("reason") or "Owned runtime could not complete within its resource allowance",
                "runtime_diagnostic": deepcopy(diagnostic)}
    policy = row.get("resource_policy") or {}
    if (isinstance(policy, dict) and row.get("configure_tool") == tool
            and policy.get("state") in {"capacity_blocked", "resource_blocked", "resource_failed"}
            and policy.get("admission_state", policy.get("state")) == "capacity_blocked"
            and policy.get("tool_id", policy.get("id", tool)) == tool
            and policy.get("configuration_revision") and isinstance(policy.get("effective"), dict)):
        return {"task_name": task, "configure_tool": tool, "classification": "resource_admission",
                "reason": row.get("reason") or policy.get("reason") or "Configured resources could not be admitted"}
    return None


def diagnostic_completion_candidate(recon, settings, *, repo_id, scan_job_id):
    """Only explicit continuation with an unbroken source binding may finish a diagnostic report.

    The worker must additionally rehash source and receive a real report id
    before changing the terminal workflow state. Unknown errors stay errors.
    """
    if audit_continuation_policy(recon, settings, repo_id=repo_id, scan_job_id=scan_job_id) != "continue_with_gaps":
        return False
    snapshot = recon.get("target_snapshot")
    if not isinstance(snapshot, dict) or not all(re.fullmatch(r"sha256:[a-f0-9]{64}", str(snapshot.get(k) or ""))
            for k in ("tree_hash", "manifest_hash")):
        return False
    integrity = recon.get("audit_integrity") or {}
    target = integrity.get("target") or {} if isinstance(integrity, dict) else {}
    return isinstance(target, dict) and target.get("match") is not False and (
        not target.get("expected_content") or target["expected_content"] == snapshot["tree_hash"])


def task_failure(row):
    """A gap is recoverable for reporting, not necessarily retryable in place."""
    typed = resource_failure(row)
    if typed:
        return typed
    if not isinstance(row, dict) or row.get("applicable") is False:
        return None
    status = str(row.get("status") or "").lower().replace("_", "-")
    if status not in {"failed", "partial", "blocked", "not-installed", "skipped", "disabled"}:
        return None
    if status == "skipped" and "not applicable" in str(row.get("reason") or "").lower():
        return None
    name = row.get("name") or row.get("task_name")
    if not isinstance(name, str) or not name:
        return None
    return {"task_name": name, "configure_tool": TASK_TO_TOOL.get(name),
            "classification": "scope_limit" if status == "partial" else "execution_gap", "reason": str(row.get("reason") or row.get("error")
                or "The task did not collect the required evidence")[:1000]}


def _admit_audit_gaps(mapped, recon):
    """Reporting may inspect incomplete evidence; it never certifies it.

    The source identity and terminal execution accounting must still agree.
    Missing lab proofs are retained for the existing per-finding proof gates.
    A malformed inventory, source mismatch or unfinished execution is not an
    incomplete-report authorization.
    """
    execution = recon.get("phase2_execution")
    nodes = mapped.get("nodes")
    snapshot = recon.get("target_snapshot")
    integrity = recon.get("audit_integrity")
    if (mapped.get("finalized") is not True or not isinstance(nodes, list) or not nodes
            or not isinstance(execution, dict) or not isinstance(snapshot, dict)
            or not isinstance(integrity, dict)):
        return mapped
    fields = ("planned", "completed", "failed", "skipped", "unresolved", "terminal")
    if (not all(type(execution.get(k)) is int and execution[k] >= 0 for k in fields)
            or execution["unresolved"] or execution.get("invariant") == "violated"
            or execution["terminal"] != execution["planned"]
            or execution["planned"] != sum(execution[k] for k in ("completed", "failed", "skipped"))):
        return mapped
    if not all(re.fullmatch(r"sha256:[a-f0-9]{64}", str(snapshot.get(k) or ""))
               for k in ("tree_hash", "manifest_hash")):
        return mapped
    target = integrity.get("target")
    if (not isinstance(target, dict) or target.get("match") is not True
            or target.get("expected_content") != snapshot["tree_hash"]):
        return mapped
    ids = [node.get("id") if isinstance(node, dict) else None for node in nodes]
    if (any(not isinstance(key, str) or not key for key in ids) or len(set(ids)) != len(ids)
            or any(node.get("status") in {"running", "pending"} for node in nodes)
            or mapped.get("unmatched_updates")):
        return mapped
    gaps = [node for node in nodes if node.get("status") != "covered"]
    if not gaps:
        return mapped
    mapped["gate"].update(complete=False, phase3_allowed=True,
        reporting_mode="incomplete_audit_gaps", policy="continue_with_gaps",
        limitations=[{"id": node["id"], "label": node.get("label"),
                      "reason": node.get("reason") or "Not covered"} for node in gaps],
        reason="Phase 2 work settled; this audit allows evaluation and an incomplete report. Missing coverage and proof requirements remain unchanged.")
    return mapped


def apply_continuation(mapped, recon):
    """Admit reporting only for typed resource gaps, preserving all evidence.

    An opt-in does not excuse failed execution, missing target tests, unverified
    dependency resolution, runtime fidelity, or integrity failures. Every
    uncovered context node must point to an actual resource-failed analyzer.
    """
    if not isinstance(mapped, dict) or not isinstance(recon, dict):
        return mapped
    gate = mapped.get("gate")
    if not isinstance(gate, dict):
        return mapped
    # Revalidate an earlier waiver on every call. Persisted admission flags
    # cannot survive a policy change or a later unrelated evidence gap.
    if gate.get("reporting_mode") in {"incomplete_resource_gaps", "incomplete_audit_gaps"}:
        gate.update(complete=False, phase3_allowed=False)
        for key in ("reporting_mode", "policy", "limitations", "resource_failures"):
            gate.pop(key, None)
    if gate.get("complete") is True:
        return mapped
    if recon.get("resource_gap_policy") == "continue_with_gaps":
        return _admit_audit_gaps(mapped, recon)
    if recon.get("resource_gap_policy", "strict") != "report_incomplete":
        return mapped
    execution = recon.get("phase2_execution")
    nodes, tools = mapped.get("nodes"), recon.get("tool_results")
    if not isinstance(execution, dict) or not isinstance(nodes, list) or not isinstance(tools, list):
        return mapped
    counters = ("planned", "completed", "failed", "skipped", "unresolved")
    if not all(type(execution.get(k)) is int and execution[k] >= 0 for k in counters):
        return mapped
    terminal = execution.get("terminal", execution["planned"])
    inapplicable = execution.get("not_applicable", 0)
    if (mapped.get("finalized") is not True or not nodes or mapped.get("unmatched_updates")
            or recon.get("phase2_plan_error") or execution["unresolved"] or execution["failed"]
            or execution["planned"] != execution["completed"] + execution["skipped"]
            or type(terminal) is not int or terminal != execution["planned"]
            or execution.get("invariant") == "violated"
            or type(inapplicable) is not int or inapplicable < 0
            or execution["skipped"] != inapplicable
            or not all(isinstance(row, dict) and isinstance(row.get("id"), str) and row["id"] for row in nodes)):
        return mapped
    snapshot = recon.get("target_snapshot")
    if not isinstance(snapshot, dict) or not all(re.fullmatch(r"sha256:[a-f0-9]{64}", str(snapshot.get(k) or ""))
               for k in ("tree_hash", "manifest_hash")):
        return mapped
    failures = [failure for row in tools if (failure := resource_failure(row))]
    if not failures:
        return mapped
    # Check each failed observation independently, including same-name rows;
    # one OOM does not excuse a separate parser failure from that analyzer.
    for row in tools:
        if not isinstance(row, dict):
            return mapped
        status = str(row.get("status") or "").lower().replace("_", "-")
        inapplicable_row = (status == "not-applicable" or row.get("applicable") is False
                            or (status == "skipped" and "not applicable" in str(row.get("reason") or "").lower()))
        if status != "completed" and not inapplicable_row and not resource_failure(row):
            return mapped
    gaps = [row for row in nodes if row.get("status") != "covered"]
    if not gaps:
        return mapped
    for row in gaps:
        # These nodes are rebuilt by coverage_mapper from controller tool
        # receipts on every gate check, never inferred from a label or prose.
        failure = resource_failure(row.get("observation"))
        if (row.get("context_derived") is not True or row.get("category") != "analyzer"
                or row.get("status") != "blocked" or row.get("task_ids")
                or not failure or failure not in failures):
            return mapped
    limitations = [{"id": row["id"], "label": row.get("label"), "reason": row.get("reason") or "Not covered"}
                   for row in gaps]
    gate.update(complete=False, phase3_allowed=True, reporting_mode="incomplete_resource_gaps",
        policy="report_incomplete", limitations=limitations, resource_failures=failures,
        reason="Phase 2 execution settled; the operator allows Phase 3 with disclosed resource gaps. Evidence remains incomplete.")
    return mapped
