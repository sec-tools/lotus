"""Evidence-only notebook context. No target discovery, execution, or verdict inference.

The publication stores this bounded projection in its signed manifest. Reading an
old report never substitutes artifacts from the repository's latest audit.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

TEXT_LIMIT = 16000
ITEM_LIMIT = 128


def obj(value):
    return value if isinstance(value, dict) else {}


def items(value):
    return value if isinstance(value, list) else []


def text(value, limit=TEXT_LIMIT):
    return str(value or "")[:limit]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _projection(value, depth=0):
    """Bound recorded metadata without copying unrelated environment or secrets."""
    if depth > 7:
        return "[depth limit]"
    if isinstance(value, dict):
        return {str(k)[:128]: _projection(v, depth + 1) for k, v in list(value.items())[:ITEM_LIMIT]
                if not any(word in str(k).lower() for word in ("password", "secret", "token", "credential", "environment"))}
    if isinstance(value, list):
        return [_projection(v, depth + 1) for v in value[:ITEM_LIMIT]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return text(value)


def build_report_context(repo_id, scan_job_id=None, output=None, findings=None, evidence=None):
    output, evidence = obj(output), obj(evidence)
    recon = obj(output.get("recon_summary")) or output
    plan = obj(output.get("audit_plan"))
    identity_sources = [obj(output.get("target_identity")), obj(plan.get("target_identity")), plan, obj(evidence.get("target_identity"))]
    identity = {}
    for canonical, aliases in {"revision": ("target_revision", "revision", "commit"),
                               "tree_hash": ("target_tree_hash", "tree_hash"),
                               "tree": ("target_tree", "tree")}.items():
        identity[canonical] = next((source[key] for source in identity_sources for key in aliases if source.get(key)), "")
    snapshot = obj(output.get("target_snapshot")) or obj(plan.get("target_snapshot")) or obj(evidence.get("target_snapshot"))
    snapshot_view = obj(evidence.get("target_snapshot"))
    lab = obj(output.get("lab_status")) or obj(recon.get("lab_status")) or obj(evidence.get("lab"))
    binding = {
        "repo_id": repo_id, "scan_job_id": scan_job_id,
        "target_identity": {k: text(identity.get(k), 256) for k in ("revision", "tree_hash", "tree")},
        "snapshot": {"snapshot_ref": text(snapshot_view.get("key") or snapshot.get("key") or snapshot.get("snapshot_ref") or str(snapshot.get("path") or "").rstrip("/").rsplit("/", 1)[-1], 256),
                     "verified": snapshot_view.get("verified") is True or snapshot.get("verified") is True},
        "lab": {k: text(lab.get(k), 512) for k in
                ("provider", "lab_run_id", "container", "container_id", "container_started_at", "container_init_start_ticks", "container_boot_id", "pod", "pod_uid", "job_uid", "namespace", "image_digest")},
    }
    missing = []
    for key, present, reason in (
        ("audit", scan_job_id is not None, "No exact audit job is recorded; notebook target execution is unavailable."),
        ("target", binding["target_identity"]["tree_hash"], "Target content hash is not recorded."),
        ("runtime", binding["lab"]["lab_run_id"], "Exact lab run identity is not recorded; a current repository lab is not interchangeable."),
    ):
        if not present:
            missing.append({"id": key, "reason": reason, "source_refs": []})
    architecture = {"status": "unavailable", "nodes": [], "edges": [], "unknowns": []}
    component_map = obj(recon.get("component_map")) or obj(output.get("component_map"))
    components = component_map.get("components")
    if isinstance(components, dict):
        components = [dict(obj(v), name=k) for k, v in components.items()]
    for index, component in enumerate(items(components)[:ITEM_LIMIT]):
        component = obj(component)
        architecture["nodes"].append({"id": f"component-{index}", "label": text(component.get("name") or component.get("path") or f"Component {index + 1}", 512),
                                       "kind": text(component.get("kind") or "recorded_component", 128),
                                       "source_refs": [f"scan-job:{scan_job_id}/component_map/components/{index}"]})
    # Only explicit recorded relationships are diagram edges. Co-location does
    # not establish a dataflow, trust boundary, or reachable security sink.
    by_label = {n["label"]: n["id"] for n in architecture["nodes"]}
    node_ids = {n["id"] for n in architecture["nodes"]}
    for index, edge in enumerate(items(component_map.get("edges"))[:ITEM_LIMIT]):
        edge = obj(edge)
        source, target = text(edge.get("source"), 512), text(edge.get("target"), 512)
        source, target = by_label.get(source, source), by_label.get(target, target)
        if source in node_ids and target in node_ids:
            architecture["edges"].append({"id": f"edge-{index}", "source": source, "target": target,
                                           "label": text(edge.get("label") or "recorded relationship", 512),
                                           "evidence_scope": "recorded", "source_refs": [f"scan-job:{scan_job_id}/component_map/edges/{index}"]})
    if architecture["nodes"]:
        architecture["status"] = "recorded_inventory"
    if not architecture["edges"]:
        architecture["unknowns"].append("No explicit component relationships were recorded; dataflow and intended architecture remain unknown.")
    comparisons = []
    for row in items(findings)[:ITEM_LIMIT]:
        row = obj(row)
        source = [f"finding:{row.get('id')}"]
        intended = obj(row.get("intended_behavior"))
        observed = obj(row.get("observed_behavior"))
        receipt_valid = row.get("proof_receipt_valid") is True
        gaps = []
        if not intended.get("text") or not intended.get("source_refs"):
            intended = {"status": "unknown", "text": "No source-backed intended behavior was recorded.", "source_refs": []}
            gaps.append("Intended behavior requires a specification, test, or maintainer statement with a source reference.")
        else:
            intended = {"status": "recorded", "text": text(intended["text"]), "source_refs": _projection(items(intended["source_refs"]))}
        if not observed.get("text") or not observed.get("source_refs"):
            observed = {"status": "unknown", "text": "No structured observation with source references was recorded.", "source_refs": []}
            gaps.append("Observed behavior needs an execution result and its exact runtime context.")
        else:
            observed = {"status": "recorded", "text": text(observed["text"]), "source_refs": _projection(items(observed["source_refs"]))}
        comparisons.append({"id": f"finding-{row.get('id')}", "finding_id": row.get("id"), "title": text(row.get("title"), 512),
                            "lifecycle": text(row.get("lifecycle") or row.get("status") or "unproven", 128),
                            "proof_status": "receipt_verified" if receipt_valid else "unproven", "claim": text(row.get("description")),
                            "intended_behavior": intended, "observed_behavior": observed,
                            "comparison": {"status": "requires_review" if not gaps else "inconclusive", "reason": "Recorded evidence does not automatically establish a behavioral mismatch."},
                            "source_refs": source, "missing_context": gaps})
    appendix = []
    groups = [("poc_chains", "hypothesis"), ("failed_pocs", "hypothesis"), ("fix_verification", "observation")]
    phase2 = obj(output.get("phase2_execution")) or obj(recon.get("phase2_execution"))
    groups.append(("task_outcomes", "observation"))
    for key, scope in groups:
        values = phase2.get(key) if key == "task_outcomes" else recon.get(key, output.get(key))
        for index, entry in enumerate(items(values)[:ITEM_LIMIT]):
            entry = obj(entry)
            status = text(entry.get("status"), 128).lower()
            if key == "failed_pocs" or entry.get("success") is False or status in ("failed", "error", "timeout"):
                status = "failed"
            elif entry.get("success") is True or status in ("success", "passed", "succeeded", "completed"):
                status = "succeeded"
            else:
                status = "inconclusive"
            commands = []
            for command in items(entry.get("commands"))[:16]:
                if isinstance(command, dict) and command.get("code"):
                    commands.append({"language": text(command.get("language"), 32), "code": text(command["code"], 50000), "evidence_scope": "recorded", "source_refs": [f"scan-job:{scan_job_id}/{key}/{index}/commands"]})
                elif isinstance(command, str):
                    commands.append({"language": "unknown", "code": text(command, 50000), "evidence_scope": "recorded", "source_refs": [f"scan-job:{scan_job_id}/{key}/{index}/commands"]})
            gaps = []
            if not commands:
                gaps.append("Original runnable commands were not retained.")
            stdout, stderr = text(entry.get("stdout") or entry.get("output")), text(entry.get("stderr"))
            if not stdout and not stderr:
                gaps.append("Command output was not retained.")
            if key == "failed_pocs":
                gaps.append("Legacy failed PoC summaries may contain only the first 200 characters of output; complete verification context is unavailable.")
            if len(str(entry.get("stdout") or entry.get("output") or "")) > TEXT_LIMIT or len(str(entry.get("stderr") or "")) > TEXT_LIMIT:
                gaps.append("Displayed output was truncated to the notebook artifact size limit.")
            appendix.append({"id": f"{key}-{index}", "kind": key, "title": text(entry.get("title") or entry.get("name") or key, 512),
                             "status": status, "evidence_scope": scope, "commands": commands, "stdout": stdout, "stderr": stderr,
                             "reason": text(entry.get("reason") or entry.get("error") or "Recorded outcome; this is not an independent proof verdict."),
                             "source_refs": [f"scan-job:{scan_job_id}/{key}/{index}"], "missing_context": gaps})
        if len(items(values)) > ITEM_LIMIT:
            missing.append({"id": f"{key}-limit", "reason": f"Only the first {ITEM_LIMIT} recorded {key} entries are included; retain the original audit artifact for remaining entries.", "source_refs": [f"scan-job:{scan_job_id}/{key}"]})
    context = {"schema_version": 1, "binding": binding, "architecture": architecture, "comparisons": comparisons, "appendix": appendix,
               "missing_context": missing, "prior_audit_context": _projection([recon["prior_audit_context"]] if isinstance(recon.get("prior_audit_context"), dict) else items(recon.get("prior_audit_context"))),
               "agent_handoffs": _projection([recon["agent_handoffs"]] if isinstance(recon.get("agent_handoffs"), dict) else items(recon.get("agent_handoffs")))}
    # The complete map is stored once in manifest.evidence, outside the notebook
    # transcript budget. Bind the notebook to that exact artifact by content hash.
    coverage_metadata = obj(evidence.get("coverage_map_metadata"))
    if coverage_metadata:
        from copy import deepcopy
        context["coverage"] = deepcopy(coverage_metadata)
        if coverage_metadata.get("status") != "recorded":
            missing.append({"id": "coverage-map", "reason": coverage_metadata.get("reason") or "No recorded coverage map is available.",
                            "source_refs": [f"scan-job:{scan_job_id}/coverage_map"]})
    # Bound the projection as a whole, not only each output. Keep outcome
    # metadata and source references even when long transcripts need omission.
    remaining_text = 262144
    display_truncated = False
    def bound_text(value):
        nonlocal remaining_text, display_truncated
        if isinstance(value, dict):
            for key, item in list(value.items()):
                if key in ("stdout", "stderr", "claim", "code", "text", "reason") and isinstance(item, str):
                    if len(item) > remaining_text:
                        value[key] = item[:remaining_text]
                        if key == "code":
                            value["language"] = "truncated"
                        display_truncated = True
                    remaining_text = max(0, remaining_text - len(value[key]))
                else:
                    bound_text(item)
        elif isinstance(value, list):
            for item in value:
                bound_text(item)
    bound_text(context)
    if display_truncated:
        missing.append({"id": "display-text-limit", "reason": "Long notebook text exceeded the total display limit. Some commands or output are truncated; retrieve original source artifacts before retrying.", "source_refs": [f"scan-job:{scan_job_id}"]})
        # Truncated commands must not be offered as runnable partial programs.
        for row in appendix:
            if any(not command["code"] for command in row["commands"]):
                row["commands"] = []
                row["missing_context"].append("Commands omitted after the total display limit; consult the original artifact.")
    # Preserve the exact bounded capsule only when recorded with this audit.
    # Validation is deferred to explicit attachment admission; a declaration
    # alone never authorizes a command or supplies a finding verdict.
    capsule = output.get("runtime_capsule") or recon.get("runtime_capsule") or lab.get("runtime_capsule")
    if isinstance(capsule, dict) and len(json.dumps(capsule)) <= 32000:
        context["runtime_capsule"] = capsule
    if isinstance(recon.get("runtime_capsule_capture"), dict):
        context["runtime_capsule_capture"] = _projection(recon["runtime_capsule_capture"])
    context["assurance"] = "A signed receipt attests recorded provenance. The validity of its success criterion and the finding's behavioral meaning still require review."
    context["context_hash"] = digest(context)
    return context


def require_runtime_binding(context, state):
    """Fail closed before a repo-keyed operation could touch a replacement lab."""
    binding = obj(context.get("binding"))
    expected = obj(binding.get("lab"))
    identity = obj(binding.get("target_identity"))
    if not binding.get("scan_job_id") or not identity.get("tree_hash") or not expected.get("lab_run_id"):
        raise ValueError("Exact audit target and lab identity are unavailable. Replay this audit snapshot before using a lab notebook.")
    if str(state.get("lab_run_id") or "") != expected["lab_run_id"] or str(state.get("target_tree_hash") or "") != identity["tree_hash"]:
        raise ValueError("The running lab belongs to a different audit target or lab run. Replay this audit snapshot; no command was executed.")
    for key in ("pod_uid", "job_uid", "namespace", "image_digest"):
        if expected.get(key) and state.get(key) != expected[key]:
            raise ValueError(f"The running lab {key} differs from the recorded audit context.")
