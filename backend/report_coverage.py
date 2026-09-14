"""Capture an audit's recorded map once, as part of its signed publication."""
from __future__ import annotations

from copy import deepcopy

from backend.report_context import digest


def capture_coverage(output: dict, repo_id: int, scan_job_id: int, tree_hash: str):
    """Return the full recorded map or an explicit gap; never read live state.

    No paging or notebook text limit is applied to the publication artifact.
    Signing records provenance, not an independent coverage or proof verdict.
    """
    progress = output.get("progress")
    progress = progress if isinstance(progress, dict) else {}
    mapped = output.get("coverage_map")
    source_ref = f"scan-job:{scan_job_id}/coverage_map"
    if mapped is None:
        mapped = progress.get("coverage_map")
        if "coverage_map" in progress:
            source_ref = f"scan-job:{scan_job_id}/progress/coverage_map"
    reason = "No surface coverage map was recorded for this audit."
    if mapped is not None:
        reason = "The recorded coverage map is malformed or belongs to a different audit target."
        if (isinstance(mapped, dict) and type(mapped.get("schema_version")) is int and mapped["schema_version"] == 1
                and type(mapped.get("repo_id")) is int and mapped["repo_id"] == repo_id
                and type(mapped.get("scan_job_id", scan_job_id)) is int and mapped.get("scan_job_id", scan_job_id) == scan_job_id
                and isinstance(tree_hash, str) and bool(tree_hash)
                and mapped.get("target_tree_hash", tree_hash) == tree_hash
                and isinstance(mapped.get("nodes"), list)
                and isinstance(mapped.get("tasks"), list)
                and isinstance(mapped.get("summary"), dict)
                and isinstance(mapped.get("gate"), dict)
                and all(isinstance(mapped["gate"].get(key, []), list) for key in ("blockers", "limitations"))):
            nodes = mapped["nodes"]
            ids = [node.get("id") for node in nodes if isinstance(node, dict)]
            task_ids = [task.get("id") for task in mapped["tasks"] if isinstance(task, dict)]
            if (len(ids) == len(nodes) and all(isinstance(key, str) and key for key in ids)
                    and len(set(ids)) == len(ids)
                    and len(task_ids) == len(mapped["tasks"])
                    and all(isinstance(key, str) and key for key in task_ids)
                    and len(set(task_ids)) == len(task_ids)
                    and all(isinstance(node.get("provenance", []), list)
                            and all(isinstance(ref, dict) for ref in node.get("provenance", [])) for node in nodes)):
                copied = deepcopy(mapped)
                gate = mapped["gate"]
                gate_summary = {key: deepcopy(gate[key]) for key in
                                ("complete", "phase3_allowed", "reason", "reporting_mode", "policy") if key in gate}
                gate_summary.update(blocker_count=len(gate.get("blockers") or []),
                                    limitation_count=len(gate.get("limitations") or []))
                return copied, {
                    "status": "recorded", "repo_id": repo_id, "scan_job_id": scan_job_id,
                    "target_tree_hash": tree_hash, "map_hash": digest(copied),
                    "node_count": len(nodes), "task_count": len(mapped["tasks"]),
                    "source_ref": source_ref,
                    "summary": deepcopy(mapped["summary"]), "gate": gate_summary,
                }
    return None, {"status": "unavailable", "reason": reason,
                  "repo_id": repo_id, "scan_job_id": scan_job_id,
                  "source_ref": source_ref}
