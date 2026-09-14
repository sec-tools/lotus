"""Complete observation accounting and bounded, non-executing source review.

Static review is supporting work. It cannot replace the runtime observation
required by the coverage gate, disprove a lead, or produce a finding.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
import re
from pathlib import PurePosixPath

BATCH_SIZE = 32
WINDOW_LINES = 80
MAX_BATCH_TEXT_BYTES = 512 * 1024
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
MAX_BATCH_SOURCE_BYTES = 16 * 1024 * 1024


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _source_location(node):
    observation = node.get("observation") or {}
    if not isinstance(observation, dict):
        observation = {}
    # A route, dependency name or caller symbol is not a source filename.
    raw = next((observation[key] for key in ("file", "handler_file", "route_file", "unguarded_file", "manifest")
                if isinstance(observation.get(key), str) and observation[key]), "")
    if not raw and node.get("kind") in {"lead", "exploit-lead", "deferred-lead", "handler-sink", "component", "untested-function", "danger-sink", "data-flow", "complexity"}:
        raw = node.get("target") or ""
    path = PurePosixPath(raw.replace("\\", "/"))
    if not raw or path.is_absolute() or any(part in {"..", ".git", ".lotus"} for part in path.parts) or any(c in raw for c in "*?:\x00"):
        return None
    if len(path.parts) == 1 and not path.suffix:
        return None
    line = observation.get("line") or observation.get("handler_line") or 1
    if type(line) is not int or line < 1:
        line = 1
    return {"file": path.as_posix(), "line": line}


def _next_action(node):
    kind = node.get("kind")
    if kind == "inventory-gap":
        return "Regenerate the complete Phase 1 artifact and account for each omitted record before planning validation."
    if kind == "dependency":
        return "Bind the declared dependency revision and trace a concrete caller from untrusted input; validate that interface in an isolated harness."
    if kind in {"endpoint", "entry-point", "trust-boundary", "handler-sink", "component"}:
        return "Confirm the source entry point, deployment prerequisites and trust boundary; create a target-bound local harness with a baseline and an explicit effect oracle."
    return "Inspect the recorded source location, establish input reachability and guards, then implement a target-bound isolated test with an explicit oracle."


def complete_phase2_plan(repo_id, dest, recon, findings, plan):
    """Account for all supplied observations, including those outside previews.

    This inventories the same frozen artifacts as the coverage mapper. It does
    not reopen stale on-disk analyzer JSON, execute target code or call AI.
    """
    from backend.coverage_mapper import build_coverage_map
    from backend.phase2 import phase2_task_id
    result = deepcopy(plan)
    # Rebuild generated support work when a durable plan is reclassified.
    # Retaining it would duplicate batches and bind dispositions to stale refs.
    result["tasks"] = [task for task in result.get("tasks", [])
                       if not isinstance(task, dict) or task.get("category") != "static-source-review"]
    result.pop("dispositions", None)
    result.pop("mapping_summary", None)
    mapped = build_coverage_map(repo_id, dest, recon, findings, result)
    dispositions, review_items = [], []
    snapshot = recon.get("target_snapshot") or {}
    binding = {key: snapshot.get(key) or "" for key in ("tree_hash", "manifest_hash")}
    bound = all(isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in binding.values())
    for node in mapped["nodes"]:
        if node.get("context_derived") or node["kind"] == "planned-task":
            continue
        row = {"coverage_id": node["id"], "source_refs": deepcopy(node["provenance"]),
               "category": node["category"], "next_action": _next_action(node),
               "task_ids": list(node["task_ids"]), "review_task_ids": [],
               "runtime_validation": "pending" if node["task_ids"] else "unproven",
               "runtime_executor": "scheduled" if node["task_ids"] else "not-scheduled",
               "required_evidence": "target-bound runtime observation"}
        if node["task_ids"]:
            row.update(status="scheduled", reason="Mapped to a target-bound Phase 2 executor; execution evidence is still required.")
        else:
            location = _source_location(node) if node["kind"] != "inventory-gap" else None
            row.update(status="unsupported", reason=node.get("reason") or "A safe runtime validator is not registered for this observation.")
            if location and bound:
                row.update(status="static-review-pending", reason="Source review is scheduled; runtime validation remains unproven.")
                review_items.append({"coverage_id": node["id"], "source_refs": deepcopy(node["provenance"]),
                                     "label": node["label"], "kind": node["kind"], **location,
                                     "next_action": row["next_action"]})
            else:
                row["reason"] += (" The immutable snapshot identity is unavailable; prepare the source snapshot before review." if not bound else
                                  " No canonical captured source location is available for automatic source review.")
        dispositions.append(row)
    # Sort before batching so incidental planner ordering does not change IDs.
    review_items.sort(key=lambda row: (row["file"], row["line"], row["coverage_id"]))
    by_coverage = {row["coverage_id"]: row for row in dispositions}
    for offset in range(0, len(review_items), BATCH_SIZE):
        entries = review_items[offset:offset+BATCH_SIZE]
        task = {"title": f"Review source context for {len(entries)} unresolved observations (batch {offset // BATCH_SIZE + 1})",
                "category": "static-source-review", "priority": "medium", "target": entries[0]["file"],
                "technique": "authenticated source-window inspection; no target execution",
                "why": "Prepare precise source context and next validation steps; runtime coverage remains unproven.",
                "review_items": entries, "source_binding": binding, "coverage_role": "support-only",
                "task_specification_sha256": _digest({"entries": entries, "binding": binding})}
        task["id"] = phase2_task_id(task)
        result["tasks"].append(task)
        for entry in entries:
            by_coverage[entry["coverage_id"]]["review_task_ids"].append(task["id"])
    result["dispositions"] = dispositions
    result["mapping_summary"] = {"observations": len(dispositions), "classified": len(dispositions),
                                 "unmapped": 0, "states": dict(Counter(row["status"] for row in dispositions)),
                                 "static_review_tasks": (len(review_items) + BATCH_SIZE - 1) // BATCH_SIZE,
                                 "coverage_complete": False}
    result["task_count"] = len(result["tasks"])
    note = "Every supplied observation has an explicit disposition. Source-review support is separate from runtime coverage."
    previous = str(result.get("planning_note") or "").removesuffix(note).rstrip()
    result["planning_note"] = (previous + " " + note).strip()
    return result


def run_source_review_batch(task, recon):
    """Read authenticated source windows, retaining explicit per-item gaps.

    The output deliberately contains no verdict, execution command or runtime
    observation. Capturing context does not prove input reachability or safety.
    """
    from backend import source_index
    items = task.get("review_items")
    snapshot = recon.get("target_snapshot") or {}
    binding = task.get("source_binding") or {}
    if not isinstance(items, list) or not 1 <= len(items) <= BATCH_SIZE or any(not isinstance(row, dict) for row in items):
        raise ValueError("Malformed bounded source-review batch")
    if not all(isinstance(binding.get(key), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", binding[key]) and binding[key] == snapshot.get(key)
               for key in ("tree_hash", "manifest_hash")):
        raise ValueError("Source-review batch does not match the audit snapshot")
    if task.get("task_specification_sha256") != _digest({"entries": items, "binding": binding}):
        raise ValueError("Source-review specification changed after planning")
    # Consume the index prepared at audit start. Do not enqueue background
    # index construction that could outlive a cancelled source-review task.
    meta = source_index.snapshot_metadata(str(snapshot.get("path") or snapshot.get("source_path") or ""),
                                          expected_tree=binding["tree_hash"], expected_manifest=binding["manifest_hash"])
    index = source_index._load_index(meta, source_index._identity(meta))
    if index is None:
        raise ValueError("Immutable source index is not ready; finish source indexing before retrying review")
    rows, cache, text_bytes, verification_budget = [], {}, 0, 0
    for item in items:
        row = {"coverage_id": item["coverage_id"], "source_refs": deepcopy(item["source_refs"]),
               "file": item["file"], "line": item["line"], "runtime_validation": "unproven",
               "next_action": item["next_action"]}
        try:
            start = max(1, item["line"] - WINDOW_LINES // 2)
            # An analyzer may report a manifest-bound alias (for example a
            # Homebrew Aliases entry). Resolve it before checking file budgets,
            # and recheck every alias even when its canonical window is cached.
            source_relative, entry = source_index.resolve_source_entry(meta, index, item["file"])
            row["canonical_file"] = source_relative
            key = (source_relative, start)
            if key not in cache:
                if type(entry.get("bytes")) is not int or not 0 <= entry["bytes"] <= MAX_SOURCE_FILE_BYTES:
                    raise ValueError("Source file exceeds the bounded review verification budget; inspect it separately")
                # Charge each distinct window conservatively even when the
                # source reader can reuse its verified file-offset cache.
                if verification_budget + entry["bytes"] > MAX_BATCH_SOURCE_BYTES:
                    raise ValueError("Source verification exceeds the batch byte budget; split this review batch")
                verification_budget += entry["bytes"]
                window = source_index.indexed_source_window(meta, source_relative, entry,
                    start_line=start, line_count=WINDOW_LINES, anchor_line=item["line"], display_relative=item["file"])
                if window.get("status") != "ready":
                    raise ValueError("Immutable source index is not ready; retry this batch after indexing completes")
                content = "\n".join(window.get("lines") or [])
                text_bytes += len(content.encode())
                if text_bytes > MAX_BATCH_TEXT_BYTES:
                    raise ValueError("Source context exceeds the bounded batch byte budget; use a smaller window")
                cache[key] = window
            window = cache[key]
            if not window.get("lines") or item["line"] > window["total_lines"]:
                raise ValueError("Observed source line is outside the captured file")
            row.update(status="context-inspected", source_sha256=window["sha256"],
                       start_line=window["start_line"], end_line=window["end_line"], total_lines=window["total_lines"],
                       context_sha256=_digest(window["lines"]), context_lines=window["lines"],
                       review_scope="bounded source context only",
                       unresolved=["Untrusted-input reachability requires validation", "Guard effectiveness requires validation", "Runtime effect and impact require an isolated oracle"])
        except (OSError, ValueError, KeyError, TypeError) as error:
            row.update(status="gap", reason=str(error)[:300])
        rows.append(row)
    return {"kind": "static-source-review", "schema_version": 1, "status": "completed",
            "coverage_role": "support-only", "task_id": task["id"], "source_binding": binding,
            "task_specification_sha256": task["task_specification_sha256"], "items": rows,
            "inspected": sum(row["status"] == "context-inspected" for row in rows),
            "gaps": sum(row["status"] == "gap" for row in rows), "runtime_validation": "unproven",
            "source_bytes": text_bytes, "source_verification_budget_bytes": verification_budget, "finding_count": 0}
