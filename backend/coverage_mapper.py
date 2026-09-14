"""Phase 1 observation → Phase 2 execution coverage, with a fail-closed gate.

Coverage means a target-bound test ran and produced an observation; it does not
mean a vulnerability was proved. Failed, skipped, deferred, or unmapped work can
never satisfy an obligation. The mapper only consumes this run's in-memory
artifacts: an old checkout's .lotus files are deliberately not consulted.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import tempfile
from typing import Any

from backend.analyzer_resources import TOOLS as _RESOURCE_TOOLS


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _target(value: Any) -> str:
    return _text(value).replace("\\", "/").removeprefix("./")


def _provenance(artifact: str, pointer: str, observation: Any) -> dict:
    return {"artifact": artifact, "pointer": pointer, "sha256": _hash(observation)}


def build_coverage_map(repo_id: int, dest: Path, recon_summary: dict,
                       findings: list, plan: dict) -> dict:
    """Inventory every supplied observation and planned task without planner caps.

    ``dest`` identifies the enrolled checkout; no source code is executed or
    historical artifact read. Plan tasks can explicitly declare ``coverage_ids``
    or ``source_refs`` (artifact/pointer pairs) to establish exact provenance.
    """
    recon, plan = _dict(recon_summary), _dict(plan)
    state = {"schema_version": 1, "repo_id": repo_id,
             "created_at": _now(), "updated_at": _now(), "nodes": [],
             "tasks": [], "exclusions": [], "inventory_context": [], "planning_context": [], "unmatched_updates": [],
             "inventory_digest": _hash({"recon": recon, "findings": findings, "plan": plan}),
             "coverage_basis": "Observed Phase 1 obligations and planned Phase 2 tests with successful execution evidence"}
    nodes: dict[str, dict] = {}

    def add(label: str, kind: str, target: Any, category: str, artifact: str,
            pointer: str, observation: Any, *, titles: list | None = None,
            categories: list | None = None, reason: str = "") -> dict:
        target = _target(target)
        observed = _dict(observation)
        location = {key: observed[key] for key in (
            "line", "line_end", "function", "handler", "handler_line", "source",
            "sink", "path_summary", "caller", "callee", "method",
        ) if observed.get(key) not in (None, "", 0)}
        identity = [kind, label, target, category, location]
        node_id = "coverage-" + _hash(identity)[:20]
        provenance = _provenance(artifact, pointer, observation)
        if node_id in nodes:
            node = nodes[node_id]
            if provenance not in node["provenance"]:
                node["provenance"].append(provenance)
            return node
        node = {"id": node_id, "label": label, "kind": kind, "target": target,
                "category": category, "status": "blocked" if reason else "pending",
                "reason": reason, "provenance": [provenance], "observation": deepcopy(observation),
                "task_ids": [], "evidence": [], "expected_titles": titles or [],
                "compatible_categories": categories or [category]}
        nodes[node_id] = node
        return node

    def source(label, kind, target, category, pointer, observation, **kwargs):
        return add(label, kind, target, category, "phase1:recon_summary", pointer, observation, **kwargs)

    from backend.phase2 import is_inventory_summary, is_builtin_planning_guidance
    for index, finding in enumerate(_list(findings)):
        f = _dict(finding)
        if not f:
            source("Malformed Phase 1 lead", "inventory-gap", "", "validation",
                   f"/findings/{index}", finding, reason="Phase 1 lead is not a JSON object")
            continue
        if is_inventory_summary(f):
            state["inventory_context"].append({
                "label": f.get("title"), "artifact": f.get("inventory_artifact"),
                "reason": "Analyzer inventory summary; structured artifact entries are mapped independently",
                "observation": deepcopy(f),
                "provenance": [_provenance("phase1:findings", f"/{index}", f)],
            })
            continue
        if f.get("qualification") == "DISPROVE" or f.get("ai_verdict") == "DISPROVE":
            state["exclusions"].append({"label": f.get("title"), "reason": "Phase 1 explicitly disproved this lead",
                                        "provenance": [_provenance("phase1:findings", f"/{index}", f)]})
            continue
        title = _text(f.get("title")) or "Untitled Phase 1 lead"
        add(title, "lead", f.get("file"), "validation", "phase1:findings", f"/{index}", f,
            titles=["Validate: " + title])
        if f.get("rce_lead"):
            add("Exploit: " + title, "exploit-lead", f.get("file"), "exploit-poc",
                "phase1:findings", f"/{index}", f,
                titles=["Exploit PoC (gadget/SSTI): " + title])

    atk = _dict(recon.get("attack_surface"))
    endpoint_specs = [("admin_namespaces", "authorization", "Admin controller authorization: "),
                      ("api_namespaces", "api-security", "API controller input validation: "),
                      ("routes", "access-control", "Route authorization audit: "),
                      ("endpoints", "access-control", "Route authorization audit: ")]
    for key, category, prefix in endpoint_specs:
        for index, entry in enumerate(_list(atk.get(key))):
            e = _dict(entry)
            target = e.get("path") or e.get("url") or e.get("file") or entry
            if isinstance(target, dict):
                target = ""
            source(prefix + _text(target), "endpoint", target, category,
                   f"/attack_surface/{key}/{index}", entry,
                   titles=[prefix + _text(target)], categories=[category])

    for index, dep in enumerate(_list(recon.get("high_risk_dependencies"))):
        name = _dict(dep).get("name") or dep
        title = "Fuzz/audit dependency: " + _text(name)
        source(title, "dependency", name, "dependency-fuzz", f"/high_risk_dependencies/{index}", dep, titles=[title])

    tb = _dict(atk.get("trust_boundary") or recon.get("trust_boundary"))
    tb_base = "/attack_surface/trust_boundary" if "trust_boundary" in atk else "/trust_boundary"
    for key in ("unauth_mutating", "http_routes", "config_fail_open", "sibling_gaps", "queue_tcbs", "nested_io"):
        for index, value in enumerate(_list(tb.get(key))):
            item = _dict(value)
            target = item.get("file") or item.get("unguarded_file") or item.get("path") or ""
            method, route = item.get("method") or "POST", item.get("path") or ""
            category = "control-plane"
            if key == "config_fail_open":
                label, category = f"Lab: shipped auth-off config {item.get('file')}", "insecure-default"
            elif key == "sibling_gaps":
                label = f"Lab: sibling missing path guard {item.get('unguarded_file')}"
            elif key in ("unauth_mutating", "http_routes"):
                label = f"Lab: unauthenticated {method} {route}" if key == "unauth_mutating" else f"Route: {method} {route}"
            else:
                label = f"{key.replace('_', ' ')}: {target}"
            source(label, "trust-boundary", target, category, f"{tb_base}/{key}/{index}", item, titles=[label])

    for key, list_keys in (("handler_sinks", ("priority", "traces")), ("component_map", ("priority", "components"))):
        artifact = _dict(atk.get(key) or recon.get(key))
        base = f"/attack_surface/{key}" if key in atk else f"/{key}"
        for list_key in list_keys:
            for index, item in enumerate(_list(artifact.get(list_key))):
                item = _dict(item)
                if key == "handler_sinks":
                    label = f"Lab: {item.get('method') or 'POST'} {item.get('path') or ''} → {item.get('primary_sink') or 'sink'}"
                    target = item.get("handler_file") or item.get("route_file") or ""
                    kind = "handler-sink"
                else:
                    lab = _dict(item.get("lab")).get("kind") or "lab"
                    label = f"Lab component {item.get('name')} ({item.get('language')}/{lab})"
                    target = item.get("manifest") or item.get("path") or ""
                    kind = "component"
                source(label, kind, target, "control-plane", f"{base}/{list_key}/{index}", item, titles=[label])

    for index, flag in enumerate(_list(recon.get("cli_entry_flags"))):
        f = _dict(flag)
        label = f"CLI argv PoC: {f.get('flag') or ''}"
        source(label, "cli-flag", f.get("flag"), "dependency-fuzz", f"/cli_entry_flags/{index}", flag, titles=[label])

    gap = _dict(recon.get("test_coverage_gap"))
    for index, value in enumerate(_list(gap.get("untested"))):
        item = _dict(value)
        primitive = item.get("primitive_type") or "untrusted_input_handling"
        label = f"Untested surface PoC: {item.get('name') or 'function'} ({primitive.replace('_', ' ')}) @ {item.get('file', '?')}:{item.get('line', '?')}"
        source(label, "untested-function", item.get("file"), "coverage-gap", f"/test_coverage_gap/untested/{index}", item, titles=[label])

    dpe = _dict(recon.get("dynamic_path_exploration"))
    for index, artifact in enumerate(_list(dpe.get("artifacts"))):
        artifact = _dict(artifact)
        if artifact.get("type") != "danger-sink-map":
            continue
        for sink_index, sink in enumerate(_list(artifact.get("sinks"))):
            sink = _dict(sink)
            label = f"Sink PoC: {sink.get('sink')} @ {sink.get('file', '?')}:{sink.get('line', '?')}"
            source(label, "danger-sink", sink.get("file"), "sink-poc", f"/dynamic_path_exploration/artifacts/{index}/sinks/{sink_index}", sink, titles=[label])

    cpg = _dict(recon.get("joern_cpg"))
    for key, category, prefix in (("data_flows", "cpg-taint-validation", "CPG data-flow: "),
                                  ("hotspot_methods", "cpg-complexity", "Complexity hotspot: ")):
        for index, value in enumerate(_list(cpg.get(key))):
            item = _dict(value)
            title = item.get("title", "taint path") if key == "data_flows" else _text(item.get("name") or "unknown")[:60]
            label = prefix + title
            source(label, "data-flow" if key == "data_flows" else "complexity", item.get("file"), category,
                   f"/joern_cpg/{key}/{index}", item, titles=[label])
    for index, value in enumerate(_list(cpg.get("sensitive_callsites"))):
        item = _dict(value)
        label = f"Callsite: {item.get('caller') or '?'} → {item.get('callee') or '?'}"
        source(label, "callsite", item.get("file") or item.get("caller"), "cpg-callgraph",
               f"/joern_cpg/sensitive_callsites/{index}", item)

    trace = _dict(recon.get("phase1_trace"))
    disproved = {(_text(f.get("title")), _target(f.get("file"))) for f in _list(findings)
                 if isinstance(f, dict) and (f.get("qualification") == "DISPROVE" or f.get("ai_verdict") == "DISPROVE")}
    for index, value in enumerate(_list(trace.get("high_severity_leads"))):
        item = _dict(value)
        title = _text(item.get("title")) or "Untitled Phase 1 trace lead"
        if (title, _target(item.get("file"))) in disproved:
            continue
        source(title, "lead", item.get("file"), "validation", f"/phase1_trace/high_severity_leads/{index}",
               item, titles=["Validate: " + title])

    # Distinct entry points in one file are distinct obligations. Only an
    # identical named source observation can share its existing node.
    for index, value in enumerate(_list(atk.get("entry_points"))):
        item = _dict(value)
        target = _target(item.get("path") or item.get("file") or item.get("name"))
        name, entry_type = _text(item.get("name")), _text(item.get("type"))
        titles = [name]
        if entry_type == "handler-sink":
            titles.append("Lab: " + name)
        elif entry_type == "unauth-mutating":
            titles.append("Lab: unauthenticated " + name)
        elif entry_type in {"admin", "api", "route"}:
            titles.append({"admin": "Admin controller authorization: ", "api": "API controller input validation: ", "route": "Route authorization audit: "}[entry_type] + target)
        source(_text(item.get("name")) or target or "Unnamed entry point", "entry-point", target,
               "entry-point", f"/attack_surface/entry_points/{index}", item,
               titles=titles, categories=["authorization", "api-security", "access-control", "control-plane", "coverage-gap"])

    # Counters survive upstream payload limits. Missing records stay visible
    # instead of shrinking the denominator to whatever happened to fit.
    count_checks = [(gap.get("untested_surface_functions"), len(_list(gap.get("untested"))), "/test_coverage_gap/untested", "untested security functions")]
    for key, field in (("component_map", "components"), ("handler_sinks", "traces")):
        artifact = _dict(atk.get(key) or recon.get(key))
        rows = _list(artifact.get(field)) or _list(artifact.get("priority"))
        count_checks.append((_dict(artifact.get("counts")).get(field), len(rows), f"/attack_surface/{key}", field.replace("_", " ")))
    for expected, supplied, pointer, label in count_checks:
        if isinstance(expected, (int, float)) and expected > supplied:
            source(f"{int(expected - supplied)} {label} missing from Phase 1 payload", "inventory-gap", "", "planning", pointer,
                   {"reported": expected, "supplied": supplied}, reason="Phase 1 artifact was truncated; missing obligations cannot be mapped")

    title_counts = Counter((node["kind"], title, node["target"], category)
                           for node in nodes.values() for title in set(node["expected_titles"])
                           for category in set(node["compatible_categories"]))
    endpoint_counts = Counter((node["target"], category) for node in nodes.values()
                              if node["kind"] == "endpoint" for category in set(node["compatible_categories"]))
    from backend.phase2 import phase2_task_id
    supplied_ids = Counter(_text(_dict(task).get("task_id") or _dict(task).get("id")) or phase2_task_id(_dict(task))
                           for task in _list(plan.get("tasks")))
    for index, value in enumerate(_list(plan.get("tasks"))):
        task = _dict(value)
        label = _text(task.get("title")) or f"Malformed Phase 2 task #{index + 1}"
        target, category = _target(task.get("target")), _text(task.get("category"))
        task_id = _text(task.get("task_id") or task.get("id")) or phase2_task_id(task)
        if supplied_ids.get(task_id, 0) > 1:
            add("Duplicate Phase 2 task identity", "inventory-gap", target, "planning", "phase2:plan",
                f"/tasks/{index}", value, reason=f"Task identity {task_id} is not unique")
        state["tasks"].append({"id": task_id, "title": label, "category": category, "target": target,
                               "status": "pending", "reason": "Awaiting Phase 2 execution", "evidence": [], "plan_index": index + 1,
                               **({key: deepcopy(task.get(key)) for key in ("coverage_role", "source_binding", "task_specification_sha256", "review_items")}
                                  if category == "static-source-review" else {})})
        if category == "static-source-review":
            # Source-context preparation is support work, not an additional
            # vulnerability-validation obligation or a dynamic receipt.
            continue
        for node in nodes.values():
            explicit = node["id"] in _list(task.get("coverage_ids"))
            refs = _list(task.get("source_refs"))
            explicit = explicit or any(_dict(ref).get("artifact") == p["artifact"] and _dict(ref).get("pointer") == p["pointer"] for ref in refs for p in node["provenance"])
            title_match = label in node["expected_titles"] and target == node["target"] and category in node["compatible_categories"] and title_counts[(node["kind"], label, target, category)] == 1
            # Specific functions/leads sharing a file cannot substitute for
            # each other; only a location-level entry point allows this fallback.
            location_match = node["kind"] == "endpoint" and bool(target) and target == node["target"] and category in node["compatible_categories"] and endpoint_counts[(target, category)] == 1
            if explicit or (not refs and not _list(task.get("coverage_ids")) and (title_match or location_match)):
                node["task_ids"].append(task_id)
        own = add(label, "planned-task", target, category, "phase2:plan", f"/tasks/{index}", value,
                  reason="Malformed Phase 2 task" if not task else "")
        own["task_ids"].append(task_id)

    def planning_context(value, pointer):
        state["planning_context"].append({
            "label": _dict(value).get("title"),
            "reason": "Built-in methodology with no observed target; Phase 1 artifact obligations are mapped independently",
            "observation": deepcopy(value),
            "provenance": [_provenance("phase2:plan", pointer, value)],
        })

    for index, value in enumerate(_list(plan.get("planning_context"))):
        pointer = f"/planning_context/{index}"
        if is_builtin_planning_guidance(value):
            planning_context(value, pointer)
        else:
            add(_text(_dict(value).get("title")) or "Unrecognized planning context", "inventory-gap",
                _dict(value).get("target"), "planning", "phase2:plan", pointer, value,
                reason="Only exact targetless built-in guidance may be classified as planning context")

    for index, value in enumerate(_list(plan.get("deferred_leads"))):
        lead = _dict(value)
        label, target = _text(lead.get("title")) or "Deferred Phase 2 lead", _target(lead.get("target"))
        reason = _text(lead.get("reason")) or "No executable Phase 2 task was scheduled for this observed lead"
        if is_builtin_planning_guidance(lead):
            planning_context(value, f"/deferred_leads/{index}")
            continue
        refs = _list(lead.get("source_refs"))
        coverage_ids = _list(lead.get("coverage_ids"))
        if refs or coverage_ids:
            existing = [n for n in nodes.values() if n["id"] in coverage_ids or any(
                _dict(ref).get("artifact") == p["artifact"] and _dict(ref).get("pointer") == p["pointer"]
                for ref in refs for p in n["provenance"])]
        else:
            candidates = [n for n in nodes.values() if label in n["expected_titles"] and target == n["target"]]
            existing = candidates if len(candidates) == 1 else []
        if existing:
            for node in existing:
                node["reason"] = "Deferred: " + reason
                node["provenance"].append(_provenance("phase2:plan", f"/deferred_leads/{index}", value))
        else:
            add(label, "deferred-lead", target, _text(lead.get("category")), "phase2:plan",
                f"/deferred_leads/{index}", value, reason="Deferred: " + reason)
    omitted = plan.get("deferred_leads_omitted", 0)
    if isinstance(omitted, (int, float)) and omitted > 0:
        add(f"{int(omitted)} deferred leads omitted by planner", "inventory-gap", "", "planning",
            "phase2:plan", "/deferred_leads_omitted", omitted,
            reason="Planner truncated deferred leads; their coverage cannot be verified")
    if plan.get("status") in {"failed", "error"} or plan.get("error"):
        add("Phase 2 planning failed", "inventory-gap", "", "planning", "phase2:plan", "", plan,
            reason=_text(plan.get("error")) or "Phase 2 plan generation failed")
    if not nodes:
        source("Phase 1 coverage inventory unavailable", "inventory-gap", "", "planning", "", {},
               reason="No observed Phase 1 obligations or executable Phase 2 tasks were supplied")
    dispositions = {row.get("coverage_id"): row for row in _list(plan.get("dispositions")) if isinstance(row, dict)}
    task_index = {task["id"]: task for task in state["tasks"]}
    for node in nodes.values():
        disposition = dispositions.get(node["id"])
        if disposition:
            # A disposition cannot alter the original artifact or authorize a
            # task for another observation. Match its exact captured refs.
            supplied = disposition.get("source_refs")
            if supplied == node["provenance"] and disposition.get("task_ids") == node["task_ids"]:
                review_ids = _list(disposition.get("review_task_ids"))
                valid_review = all(key in task_index and task_index[key]["category"] == "static-source-review"
                                   and any(_dict(item).get("coverage_id") == node["id"]
                                           and _dict(item).get("source_refs") == supplied
                                           for item in _list(task_index[key].get("review_items"))) for key in review_ids)
                if valid_review:
                    node["planning_disposition"] = deepcopy(disposition)
                    node["review_task_ids"] = review_ids
                    node["next_action"] = disposition.get("next_action")
                    if not node["task_ids"]:
                        node["reason"] = disposition.get("reason") or node["reason"]
        if not node["task_ids"]:
            node["status"] = "blocked"
            node["reason"] = node["reason"] or "No Phase 2 task maps to this Phase 1 observation"
    state["nodes"] = list(nodes.values())
    return reconcile_coverage_context(_summarize(state), recon)


def _source_review_evidence(update: dict, task: dict, pointer: str) -> list:
    """Validate only the exact support-task receipt; never dynamic coverage."""
    if task.get("category") != "static-source-review" or task.get("coverage_role") != "support-only":
        return []
    if update.get("error") or update.get("success") is False:
        return []
    candidates = []
    for entry in _list(update.get("evidence")):
        value = _dict(entry)
        if value.get("type") == "source-review-support":
            value = _dict(value.get("observation"))
        candidates.append(value)
    expected = _list(task.get("review_items"))
    for candidate in candidates:
        if (candidate.get("kind") != "static-source-review" or candidate.get("coverage_role") != "support-only"
                or candidate.get("status") != "completed" or candidate.get("runtime_validation") != "unproven"
                or candidate.get("task_id") != task["id"] or not expected
                or candidate.get("source_binding") != task.get("source_binding")
                or candidate.get("task_specification_sha256") != task.get("task_specification_sha256")):
            continue
        items = candidate.get("items")
        if not isinstance(items, list) or len(items) != len(expected):
            continue
        valid = True
        for result, planned in zip(items, expected):
            if not isinstance(result, dict) or any(result.get(key) != planned.get(key) for key in ("coverage_id", "source_refs", "file", "line")):
                valid = False
                break
            if result.get("runtime_validation") != "unproven" or result.get("status") not in {"gap", "context-inspected"}:
                valid = False
                break
            if result["status"] == "context-inspected":
                from backend.phase2_mapping import _digest
                lines = result.get("context_lines")
                if not isinstance(lines, list) or not lines or not all(isinstance(line, str) for line in lines) or result.get("context_sha256") != _digest(lines) or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(result.get("source_sha256") or "")):
                    valid = False
                    break
            elif not result.get("reason"):
                valid = False
                break
        if valid:
            return [{"type": "source-review-support", "artifact": "phase2:execution", "pointer": pointer,
                     "sha256": _hash(candidate), "observation": deepcopy(candidate)}]
    return []


def _simulation_declared(value: Any) -> bool:
    """A successful stub receipt cannot stand in for the deployed dependency.

    Only explicit machine-readable declarations carry this restriction; names,
    command text and HTTP bodies are not interpreted as fidelity assertions.
    Follow the same receipt containers as execution evidence so a wrapper cannot
    erase a nested declaration, including when durable evidence is restored.
    """
    pending, seen = [value], set()
    while pending:
        row = pending.pop()
        if not isinstance(row, (dict, list)) or id(row) in seen:
            continue
        seen.add(id(row))
        if isinstance(row, list):
            pending.extend(row)
            continue
        if row.get("simulated") is True or _text(row.get("runtime_fidelity")).lower() == "simulated":
            return True
        pending.extend(row.get(key) for key in (
            "evidence", "receipt", "execution_receipt", "artifact", "responses", "observation",
        ))
    return False


def _execution_evidence(update: dict, pointer: str) -> list:
    if _simulation_declared(update):
        return []
    if update.get("error") or update.get("success") is False or update.get("executed") is False or update.get("skipped"):
        return []
    reason = _text(update.get("reason"))
    candidates = []
    def collect(value, depth=0):
        if depth > 5:
            return
        if isinstance(value, list):
            for item in value:
                collect(item, depth + 1)
        elif isinstance(value, dict):
            if value.get("coverage_role") == "support-only" or value.get("kind") == "static-source-review":
                return
            if value.get("error") or value.get("success") is False or value.get("status") in {"failed", "skipped", "blocked"}:
                return
            candidates.append(value)
            for key in ("evidence", "receipt", "execution_receipt", "artifact", "responses", "observation"):
                collect(value.get(key), depth + 1)
    collect(update)
    observations = []
    for candidate in candidates:
        candidate = _dict(candidate)
        if not candidate or candidate.get("error") or candidate.get("success") is False or candidate.get("status") in {"failed", "skipped", "blocked"}:
            continue
        status_code = candidate.get("status_code")
        http_observation = bool(candidate.get("method") and candidate.get("url")) and isinstance(status_code, int) and not isinstance(status_code, bool) and 100 <= status_code <= 599
        exit_code = candidate.get("exit_code")
        process_observation = bool(candidate.get("command")) and type(exit_code) is int and exit_code == 0
        if http_observation or process_observation:
            observations.append(candidate)
    if not observations:
        return []
    return [{"type": "task-execution", "artifact": "phase2:execution", "pointer": pointer,
             "status": "completed", "reason": reason, "sha256": _hash(update),
             "observation": deepcopy(observations)}]


def update_coverage_map(coverage_map: dict, *, task_update: dict | None = None,
                        execution: dict | None = None, finalized: bool = False,
                        recon_summary: dict | None = None) -> dict:
    """Return a new snapshot; reconcile by identity, never sorted task indexes.

    Repeated SSE events are idempotent. A late running event cannot overwrite a
    terminal observation. Execution reconciliation remains conservative when a
    duplicate title cannot uniquely identify its original task.
    """
    state = deepcopy(_dict(coverage_map))
    state.setdefault("unmatched_updates", [])
    state["nodes"] = [n for n in _list(state.get("nodes")) if isinstance(n, dict)]
    state["tasks"] = [t for t in _list(state.get("tasks")) if isinstance(t, dict)]
    for node in state["nodes"]:
        node.setdefault("task_ids", [])
        node.setdefault("evidence", [])
        node.setdefault("label", "Unknown coverage obligation")
        if "id" not in node:
            node["id"] = "coverage-" + _hash(node)[:20]
        node.setdefault("reason", "Coverage snapshot is incomplete")
        node.setdefault("status", "blocked")
        if node["status"] != "blocked" and not node["task_ids"]:
            node.update(status="blocked", reason="Coverage snapshot has no task mapping for this obligation", evidence=[])
    for task in state["tasks"]:
        for key in ("id", "title", "category", "target", "reason"):
            task.setdefault(key, "")
        task.setdefault("status", "blocked")
        task.setdefault("evidence", [])
        if task["status"] == "covered" and (_simulation_declared(task)
                or not (_execution_evidence({"evidence": task["evidence"]}, "/restored-task")
                        or _source_review_evidence({"evidence": task["evidence"]}, task, "/restored-task"))):
            task.update(status="blocked", reason="Restored completed task has no valid execution observation", evidence=[])
    updates = []
    if isinstance(task_update, dict):
        updates.append((task_update, "/live-task-events"))
    if isinstance(execution, dict):
        simulated_execution = _simulation_declared(execution)
        updates.extend(({**row, "runtime_fidelity": "simulated"} if simulated_execution else row,
                        f"/task_outcomes/{i}")
                       for i, row in enumerate(_list(execution.get("task_outcomes"))) if isinstance(row, dict))
        issues = []
        if finalized and "planned" in execution and execution["planned"] != len(state["tasks"]):
            issues.append("Executor planned count does not match the frozen Phase 2 coverage plan")
        if finalized and (execution.get("unresolved") or execution.get("invariant") == "violated"):
            issues.append("Executor reports unresolved Phase 2 task accounting")
        identities = [(_text(row.get("task_id") or row.get("id")), _text(row.get("title")),
                       _text(row.get("category")), _target(row.get("target")))
                      for row in _list(execution.get("task_outcomes")) if isinstance(row, dict)]
        if len(set(identities)) != len(identities):
            issues.append("Executor reports duplicate terminal outcomes for a Phase 2 task")
        for issue in issues:
            node_id = "accounting-" + _hash(issue)[:20]
            if not any(n["id"] == node_id for n in state["nodes"]):
                state["nodes"].append({"id": node_id, "label": "Phase 2 task accounting", "kind": "accounting-gap",
                    "category": "planning", "target": "", "status": "blocked", "reason": issue,
                    "task_ids": [], "evidence": [], "provenance": [_provenance("phase2:execution", "", execution)],
                    "observation": {"planned": execution.get("planned"), "outcomes": len(identities)}})
    for update, pointer in updates:
        task_id = _text(update.get("task_id") or update.get("id"))
        tasks = state.get("tasks") or []
        matches = [t for t in tasks if task_id and t["id"] == task_id]
        if task_id:
            matches = [t for t in matches
                       if (not update.get("title") or t["title"] == _text(update["title"]))
                       and (not update.get("category") or t["category"] == _text(update["category"]))
                       and (not update.get("target") or t["target"] == _target(update["target"]))]
        else:
            title = _text(update.get("title"))
            matches = [t for t in tasks if title and t["title"] == title
                       and (not update.get("category") or t["category"] == _text(update["category"]))
                       and (not update.get("target") or t["target"] == _target(update["target"]))]
        if len(matches) != 1:
            record = {"title": _text(update.get("title")), "task_id": task_id,
                      "reason": "Task update has no unique mapping to the Phase 2 plan"}
            if record not in state["unmatched_updates"]:
                state["unmatched_updates"].append(record)
            node_id = "accounting-" + _hash(record)[:20]
            if not any(n["id"] == node_id for n in state["nodes"]):
                state["nodes"].append({"id": node_id, "label": record["title"] or "Unmapped Phase 2 outcome",
                    "kind": "accounting-gap", "category": "planning", "target": "", "status": "blocked",
                    "reason": record["reason"], "task_ids": [], "evidence": [],
                    "provenance": [_provenance("phase2:execution", pointer, update)], "observation": deepcopy(update)})
            continue
        task = matches[0]
        status = _text(update.get("status")).lower()
        if status in {"running", "started"}:
            if task["status"] in {"pending", "running"}:
                task.update(status="running", reason=_text(update.get("reason")) or "Phase 2 test is running")
        elif status in {"completed", "covered", "passed", "success"}:
            evidence = (_source_review_evidence(update, task, pointer) if task.get("category") == "static-source-review"
                        else _execution_evidence(update, pointer))
            # Durable summary rows may be leaner than their live receipt; retain
            # existing verified observations for this exact task.
            if _simulation_declared(update):
                task.update(status="blocked",
                    reason="Simulated dependency execution is recorded for review; real dependency coverage remains unverified",
                    evidence=[], simulation_evidence=[{
                        "type": "simulated-task-execution", "artifact": "phase2:execution",
                        "pointer": pointer, "sha256": _hash(update), "runtime_fidelity": "simulated",
                        "observation": deepcopy(update),
                    }])
            elif evidence:
                task.update(status="covered", reason=_text(update.get("reason")) or "Test execution evidence recorded", evidence=evidence)
                task.pop("simulation_evidence", None)
            elif task["status"] != "covered":
                task.update(status="blocked", reason="Completed task has no successful execution observation", evidence=[])
        elif status in {"failed", "error", "skipped", "deferred", "blocked", "cancelled", "canceled", "not_applicable", "not-applicable"}:
            task.update(status="blocked", reason=_text(update.get("reason") or update.get("error")) or f"Phase 2 task {status}", evidence=[])
        else:
            task.update(status="blocked", reason=f"Unrecognized Phase 2 task status: {status or 'missing'}", evidence=[])
        if update.get("detail_id"):
            task["detail_id"] = update["detail_id"]
        elif str(update.get("index", "")).isdigit():
            task["detail_id"] = f"{state.get('repo_id')}-task-phase2-{update['index']}"
    if finalized:
        state["finalized"] = True
        for task in state.get("tasks") or []:
            if task["status"] in {"pending", "running"}:
                task.update(status="blocked", reason="Phase 2 execution ended without a successful terminal observation")
    by_id = {t["id"]: t for t in state.get("tasks") or []}
    for node in state.get("nodes") or []:
        reviews = [by_id[key] for key in node.get("review_task_ids", []) if key in by_id]
        if reviews:
            # A support batch can finish successfully while individual source
            # windows remain unavailable. Only its exact inspected item may
            # establish source-context completion for this observation.
            review_items = [
                (task, evidence, index, item)
                for task in reviews for evidence in task["evidence"]
                if evidence.get("type") == "source-review-support"
                and _dict(evidence.get("observation")).get("task_id") == task["id"]
                for index, item in enumerate(_list(_dict(evidence.get("observation")).get("items")))
                if _dict(item).get("coverage_id") == node["id"]
                and _dict(item).get("source_refs") == node["provenance"]]
            inspected = {
                task["id"]: bool(matching := [item for owner, _, _, item in review_items if owner["id"] == task["id"]])
                and all(item.get("status") == "context-inspected" for item in matching)
                for task in reviews}
            node["review_status"] = ("completed" if all(task["status"] == "covered" and inspected[task["id"]] for task in reviews) else
                                     "running" if any(task["status"] == "running" for task in reviews) else
                                     "blocked" if any(task["status"] == "blocked" or
                                         (task["status"] == "covered" and not inspected[task["id"]]) for task in reviews) else "pending")
            node["review_evidence"] = [
                {"task_id": task["id"], "receipt_sha256": evidence["sha256"], "item_index": index,
                 "coverage_id": node["id"], "coverage_role": "support-only"}
                for task, evidence, index, _ in review_items]
        mapped = [by_id[key] for key in node["task_ids"] if key in by_id]
        if any(key not in by_id for key in node["task_ids"]):
            node.update(status="blocked", reason="A mapped Phase 2 task is missing from the coverage snapshot", evidence=[])
            continue
        if not mapped:
            if reviews:
                node["reason"] = ({
                    "completed": "Source context inspection completed; runtime validation remains unproven.",
                    "running": "Source context inspection is running; runtime validation remains unproven.",
                    "blocked": "Source context inspection could not complete; runtime validation remains unproven.",
                    "pending": "Source context inspection is scheduled; runtime validation remains unproven.",
                }[node["review_status"]])
            continue
        # Every task attached to an observation remains in scope; a passing
        # sibling must not erase a failed test on the same endpoint.
        if all(t["status"] == "covered" for t in mapped):
            node.update(status="covered", reason="All mapped Phase 2 tests have execution evidence",
                        evidence=[e for task in mapped for e in task["evidence"]])
        elif any(t["status"] == "running" for t in mapped):
            node.update(status="running", reason="Mapped Phase 2 test is running", evidence=[])
        elif any(t["status"] == "blocked" for t in mapped):
            node.update(status="blocked", reason="; ".join(dict.fromkeys(t["reason"] for t in mapped if t["status"] == "blocked")), evidence=[])
        else:
            node.update(status="pending", reason="Awaiting mapped Phase 2 tests", evidence=[])
    # This state is already detached from every caller-owned input. Reconcile
    # context on that same owned copy and summarize once for a publication.
    if recon_summary is not None:
        return _reconcile_coverage_context_owned(state, recon_summary)
    return _summarize(state)


def reconcile_coverage_context(coverage_map: dict, recon_summary: dict) -> dict:
    """Refresh aggregate coverage blockers without rewriting target obligations.

    Phase 1 tool failures and later runtime/integrity gaps are not successes on
    any target. Context nodes are replaced on each refresh so an analyzer retry
    or newly completed runtime ledger can resolve its previous blocker.
    """
    return _reconcile_coverage_context_owned(deepcopy(_dict(coverage_map)), recon_summary)


def _reconcile_coverage_context_owned(state: dict, recon_summary: dict) -> dict:
    """Reconcile a detached mapper-owned state; public entrypoints copy first."""
    recon = _dict(recon_summary)
    state["nodes"] = [node for node in _list(state.get("nodes")) if isinstance(node, dict) and not node.get("context_derived")]

    def block(label, category, pointer, observation, reason):
        node_id = "context-" + _hash([category, pointer, label])[:20]
        configure_tool = _dict(observation).get("configure_tool")
        state["nodes"].append({"id": node_id, "label": label, "kind": "coverage-context", "category": category,
            "target": "", "status": "blocked", "reason": reason, "task_ids": [], "evidence": [],
            "context_derived": True, "provenance": [_provenance("audit:recon_summary", pointer, observation)],
            "observation": deepcopy(observation),
            **({"configure_tool": configure_tool, "task_name": _dict(observation).get("task_name") or _dict(observation).get("name")}
               if category == "analyzer" and isinstance(configure_tool, str)
               and configure_tool in _RESOURCE_TOOLS else {})})

    def analyzer_context(value, pointer, parent="", depth=0):
        row = _dict(value)
        status = _text(row.get("status")).lower().replace("_", "-")
        reason = _text(row.get("reason") or row.get("error"))
        name = _text(row.get("name") or row.get("tool")) or " / ".join(filter(None, [parent, _text(row.get("language")), _text(row.get("root"))])) or "Unknown analyzer"
        explicitly_inapplicable = status == "not-applicable" or row.get("applicable") is False or (
            status == "skipped" and "not applicable" in reason.lower())
        if _simulation_declared(row):
            block(f"Analyzer: {name}", "analyzer", pointer, row,
                  "Simulated analyzer evidence does not verify the real dependency")
        elif not explicitly_inapplicable and status != "completed":
            block(f"Analyzer: {name}", "analyzer", pointer, row,
                  reason or f"Required analyzer has no completed outcome ({status or 'missing status'})")
        if depth < 5:
            for child_index, child in enumerate(_list(row.get("target_results"))):
                analyzer_context(child, f"{pointer}/target_results/{child_index}", name, depth + 1)
    for index, value in enumerate(_list(recon.get("tool_results"))):
        analyzer_context(value, f"/tool_results/{index}")

    if "native_tool_readiness" in recon:
        readiness = _dict(recon.get("native_tool_readiness"))
        if readiness.get("status") == "blocked":
            block("Native tool prerequisites", "analyzer", "/native_tool_readiness", readiness,
                  "Installed native tool readiness could not be established")
        for index, row in enumerate(_list(readiness.get("targets"))):
            if _dict(row).get("status") not in {"ready", "module-only"}:
                block("Native package prerequisite", "analyzer", f"/native_tool_readiness/targets/{index}", row,
                      _text(_dict(row).get("reason")) or "Required native package prerequisites are unavailable")

    if "local_lab_adapter" in recon:
        adapter = _dict(recon.get("local_lab_adapter"))
        # A successful generated component smoke is useful runtime evidence,
        # but cannot erase original topology or dependency obligations.
        block("Generated adapter deployment fidelity", "lab", "/local_lab_adapter", adapter,
              "Generated native component requires comparison with the intended deployment; omitted dependencies and behaviors remain unverified")
        # Interpretations about a deliberately smaller native component never
        # close full-deployment coverage, even after a successful local smoke.
        omissions = adapter.get("omitted_behaviors", [])
        if not isinstance(omissions, list) or len(omissions) > 32:
            block("Native component omissions require review", "runtime-dependency", "/local_lab_adapter/omitted_behaviors",
                  omissions, "The adapter's omitted deployment behaviors are malformed or exceed the recorded bound")
        else:
            for index, value in enumerate(omissions):
                omission = _dict(value)
                label = _text(omission.get("behavior")) or "Unspecified omitted deployment behavior"
                reason = _text(omission.get("reason")) or "The selected native component does not verify this deployment behavior"
                block("Omitted deployment behavior: " + label, "runtime-dependency",
                      f"/local_lab_adapter/omitted_behaviors/{index}", value,
                      "Unverified outside the selected native component: " + reason)

    # The source-only deployment plan explains missing runtime dependencies; it
    # does not execute them or attest behavioral equivalence. Consequently a
    # successful stub or a hand-edited "resolved" flag cannot erase its gaps.
    # A future runtime resolver needs its own revision-bound equivalence
    # contract before it may turn these declarations into completed coverage.
    if "local_deployment_plan" in recon:
        deployment = _dict(recon.get("local_deployment_plan"))
        deployment_pointer = "/local_deployment_plan"
        deployment_status = _text(deployment.get("status"))
        gaps = deployment.get("coverage_gaps")
        if (type(deployment.get("schema_version")) is not int
                or deployment.get("schema_version") != 1
                or deployment_status not in {"requires-adaptation", "review-required", "admitted", "not-assessed"}
                or not isinstance(gaps, list)):
            block("Local deployment plan requires review", "runtime-dependency", deployment_pointer,
                  recon.get("local_deployment_plan"),
                  "Local deployment plan is malformed or uses an unsupported schema; dependency coverage cannot be verified")
        else:
            for index, value in enumerate(gaps):
                gap = _dict(value)
                dependency = _text(gap.get("dependency")) or "Unknown dependency"
                reason = _text(gap.get("reason")) or "Required local runtime dependency has no verified equivalent"
                if gap.get("status") == "resolved":
                    reason = "Source-only deployment planning cannot verify a dependency gap marked resolved; " + reason
                block("Local deployment: " + dependency, "runtime-dependency",
                      f"{deployment_pointer}/coverage_gaps/{index}", value, reason)
            if deployment_status in {"requires-adaptation", "review-required"} and not gaps:
                block("Local deployment adaptation is incomplete", "runtime-dependency", deployment_pointer,
                      deployment, "Local deployment requires adaptation or review but provides no dependency gap records")

    execution = _dict(recon.get("phase2_execution"))
    accounting_reasons = []
    if _simulation_declared(execution):
        accounting_reasons.append("simulated executor observations do not verify the real runtime dependencies")
    if execution.get("unresolved") or execution.get("invariant") == "violated":
        accounting_reasons.append("executor reports unresolved task outcomes")
    if execution.get("failed"):
        accounting_reasons.append("executor reports failed tasks")
    accounting_settled = state.get("finalized") is True or execution.get("invariant") != "pending"
    if accounting_settled and "planned" in execution and "terminal" in execution and execution["planned"] != execution["terminal"]:
        accounting_reasons.append("planned and terminal task counts do not match")
    if accounting_reasons:
        block("Phase 2 execution accounting", "accounting-gap", "/phase2_execution", execution, "; ".join(accounting_reasons))

    probe = _dict(recon.get("phase2_dynamic_probe"))
    if _simulation_declared(probe):
        block("Phase 2 dynamic probes", "runtime", "/phase2_dynamic_probe", probe,
              "Simulated probe observations do not verify the real runtime dependency")
    elif probe and probe.get("status") != "completed":
        no_http = recon.get("app_type") in {"library", "cli-tool"} and probe.get("reason") == "target has no HTTP application surface"
        if not no_http:
            block("Phase 2 dynamic probes", "runtime", "/phase2_dynamic_probe", probe,
                  _text(probe.get("reason") or probe.get("error")) or "Dynamic probe coverage is incomplete")

    lab_status = _dict(recon.get("lab_status"))
    if _simulation_declared(lab_status):
        block("Local runtime fidelity", "runtime-dependency", "/lab_status", lab_status,
              "The lab uses simulated dependencies; real dependency behavior remains unverified")

    ledger = _dict(recon.get("coverage_ledger"))
    if ledger.get("error"):
        block("Coverage ledger unavailable", "coverage-ledger", "/coverage_ledger", ledger, _text(ledger["error"]))
    if _simulation_declared(ledger):
        block("Coverage ledger runtime fidelity", "coverage-ledger", "/coverage_ledger", ledger,
              "Simulated ledger observations do not verify the real runtime dependencies")
    for index, value in enumerate(_list(ledger.get("surfaces"))):
        row = _dict(value)
        simulated_surface = _simulation_declared(row)
        if (not simulated_surface and row.get("exhausted") is True
                and all(value is True for value in _dict(row.get("gates")).values())):
            continue
        missing = [key.replace("_", " ") for key, value in _dict(row.get("gates")).items() if value is not True]
        block("Coverage ledger: " + _text(row.get("surface") or index + 1), "coverage-ledger",
              f"/coverage_ledger/surfaces/{index}", row,
              "Simulated surface evidence does not verify the real dependency" if simulated_surface else
              "Coverage gates remain incomplete" + (": " + ", ".join(missing) if missing else ""))
    if ledger and not ledger.get("surfaces") and not ledger.get("error"):
        block("Coverage ledger has no surface evidence", "coverage-ledger", "/coverage_ledger", ledger,
              "Coverage ledger does not identify any exhausted surfaces")

    integrity = _dict(recon.get("audit_integrity"))
    if integrity and integrity.get("complete") is not True:
        reasons = _list(integrity.get("reasons"))
        block("Audit evidence integrity", "integrity", "/audit_integrity", integrity,
              "; ".join(_text(reason) for reason in reasons) or _text(integrity.get("error")) or "Required audit evidence is incomplete")

    if "callgraph_scope" in recon:
        scope = _dict(recon.get("callgraph_scope"))
        gaps = scope.get("coverage_gaps")
        counters = ("discovered_source_files", "examined_files", "omitted_files",
                    "unsupported_parser_files", "decoding_loss_files", "untraversed_directories")
        valid = (type(scope.get("schema_version")) is int and scope["schema_version"] == 1
                 and type(scope.get("complete")) is bool and isinstance(gaps, list)
                 and type(scope.get("max_files")) is int and scope["max_files"] > 0
                 and type(scope.get("inventory_complete")) is bool
                 and all(type(scope.get(key)) is int and scope[key] >= 0 for key in counters))
        if valid:
            valid = (scope["discovered_source_files"] == scope["examined_files"] + scope["omitted_files"]
                     and scope["examined_files"] <= scope["max_files"]
                     and max(scope["unsupported_parser_files"], scope["decoding_loss_files"]) <= scope["examined_files"]
                     and scope["inventory_complete"] is (scope["untraversed_directories"] == 0))
        if not valid:
            block("Callgraph source scope unavailable", "inventory-gap", "/callgraph_scope", scope,
                  "Callgraph source accounting is missing or malformed; examined scope cannot be verified")
        else:
            for index, gap in enumerate(gaps):
                block("Callgraph source scope: " + (_text(_dict(gap).get("code")) or "unverified"),
                      "inventory-gap", f"/callgraph_scope/coverage_gaps/{index}", gap,
                      _text(_dict(gap).get("reason")) or "Callgraph source scope remains unverified")
            if not gaps and (scope["complete"] is not True or not scope["discovered_source_files"]
                             or any(scope[key] for key in counters[2:])):
                block("Callgraph source scope incomplete", "inventory-gap", "/callgraph_scope", scope,
                      "Callgraph omitted source or unsupported parsing remains unverified")

    if "dependency_source_inventory" in recon:
        inventory = _dict(recon.get("dependency_source_inventory"))
        packages, gaps = inventory.get("packages"), inventory.get("gaps")
        snapshot = _dict(recon.get("target_snapshot"))
        manifests = inventory.get("manifests")
        valid = (type(inventory.get("schema_version")) is int and inventory["schema_version"] == 1
                 and isinstance(packages, list) and isinstance(gaps, list) and isinstance(manifests, list)
                 and inventory.get("status") in {"partial", "captured", "not-applicable"}
                 and inventory.get("resolution_status") in {"not-attested", "not-applicable", "no-declarations"}
                 and bool(snapshot.get("tree_hash")) and bool(snapshot.get("manifest_hash"))
                 and inventory.get("tree_hash") == snapshot["tree_hash"]
                 and inventory.get("manifest_hash") == snapshot["manifest_hash"]
                 and all(type(inventory.get(key)) is int and inventory[key] >= 0
                         for key in ("declarations", "captured_declarations", "missing_declarations", "captured_files")))
        if valid:
            valid = (inventory["declarations"] == len(packages)
                     and inventory["captured_declarations"] + inventory["missing_declarations"] == len(packages)
                     and all(isinstance(row, dict) and row.get("source_status") in {"captured-local", "captured-external", "captured-unverified", "missing"}
                             and row.get("review_status") == "unverified" for row in packages)
                     and inventory["missing_declarations"] == sum(row["source_status"] not in {"captured-local", "captured-external"} for row in packages)
                     and (inventory["resolution_status"] != "not-applicable" or (not manifests and not packages and not gaps))
                     and (inventory["resolution_status"] != "no-declarations" or (not packages and not gaps and bool(manifests)
                          and all(isinstance(row, dict) and row.get("status") == "parsed" and row.get("declared_packages") == 0 for row in manifests)))
                     and (inventory["status"] != "not-applicable" or (not manifests and not packages and not gaps)))
        if not valid:
            block("Dependency source inventory unavailable", "inventory-gap", "/dependency_source_inventory", inventory,
                  "Dependency source inventory has missing, malformed or mismatched audit identity and scope accounting")
        else:
            missing = [row for row in packages if _dict(row).get("source_status") not in {"captured-local", "captured-external"}]
            if missing:
                block("Dependency code missing from captured source", "inventory-gap", "/dependency_source_inventory/packages",
                      {"missing_declarations": len(missing), "declarations": len(packages)},
                      f"{len(missing)} dependency declarations lack bound source code; manifest inventory is not dependency source review")
            if inventory.get("resolution_status") == "not-attested":
                block("Dependency resolution unverified", "inventory-gap", "/dependency_source_inventory/resolution_status",
                      inventory.get("resolution_status"),
                      "The complete resolved dependency graph and source equivalence have not been attested")
            if gaps:
                block("Dependency manifests need resolution", "inventory-gap", "/dependency_source_inventory/gaps", gaps,
                      f"{len(gaps)} dependency manifest parsing or resolution gaps remain; inspect the captured source inventory")

    gap_artifact = _dict(recon.get("test_coverage_gap"))
    if "source_scope" in gap_artifact:
        scope = _dict(gap_artifact.get("source_scope"))
        counters = ("discovered_source_files", "examined_files", "omitted_files", "untraversed_directories", "decoding_loss_files")
        valid = (type(scope.get("schema_version")) is int and scope["schema_version"] == 1 and type(scope.get("max_files")) is int and scope["max_files"] > 0
                 and all(type(scope.get(key)) is int and scope[key] >= 0 for key in counters)
                 and type(scope.get("inventory_complete")) is bool and type(scope.get("complete")) is bool
                 and isinstance(scope.get("coverage_gaps"), list))
        if valid:
            valid = (scope["discovered_source_files"] == scope["examined_files"] + scope["omitted_files"]
                     and scope["examined_files"] <= scope["max_files"]
                     and scope["decoding_loss_files"] <= scope["examined_files"]
                     and scope["inventory_complete"] is (scope["untraversed_directories"] == 0))
        if not valid:
            block("Static test-reference source scope unavailable", "inventory-gap", "/test_coverage_gap/source_scope", scope,
                  "Source inventory accounting is missing or malformed; static test-reference scope cannot be verified")
        else:
            for index, gap in enumerate(scope["coverage_gaps"]):
                block("Static test-reference source scope: " + (_text(_dict(gap).get("code")) or "unverified"),
                      "inventory-gap", f"/test_coverage_gap/source_scope/coverage_gaps/{index}", gap,
                      _text(_dict(gap).get("reason")) or "Static test-reference inventory remains incomplete")
            if not scope["coverage_gaps"] and (not scope["complete"] or any(scope[key] for key in counters[2:])):
                block("Static test-reference source scope incomplete", "inventory-gap", "/test_coverage_gap/source_scope", scope,
                      "Omitted or unparsed source remains outside static test-reference analysis")

    for key in ("phase1_trace", "test_coverage_gap", "joern_cpg", "dynamic_path_exploration"):
        artifact = _dict(recon.get(key))
        if artifact.get("error"):
            block(f"Phase 1 artifact: {key}", "inventory-gap", f"/{key}", artifact, _text(artifact["error"]))
    from backend.resource_continuation import apply_continuation
    return apply_continuation(_summarize(state), recon)


def _summarize(state: dict) -> dict:
    counts = Counter(node["status"] for node in state.get("nodes") or [])
    total = len(state.get("nodes") or [])
    complete = bool(total) and counts["covered"] == total
    percentage = round(100 * counts["covered"] / total, 1) if total else 0.0
    # Large inventories must not round a remaining obligation up to 100%.
    percentage = percentage if complete else min(99.9, percentage)
    summary = {"total": total, **{key: counts[key] for key in ("covered", "pending", "running", "blocked")},
               "coverage_pct": percentage,
               "complete": complete}
    task_counts = Counter(task["status"] for task in state.get("tasks") or [])
    summary["execution"] = {"planned": len(state.get("tasks") or []),
        "settled": task_counts["covered"] + task_counts["blocked"],
        "successful": task_counts["covered"], "blocked": task_counts["blocked"],
        "running": task_counts["running"], "pending": task_counts["pending"]}
    observed = [node for node in state.get("nodes") or [] if not node.get("context_derived") and node.get("kind") != "planned-task"]
    if any(node.get("planning_disposition") for node in observed):
        summary["planning"] = {"observations": len(observed),
                               "classified": sum(bool(node.get("planning_disposition")) for node in observed),
                               "unmapped": sum(not node.get("planning_disposition") for node in observed),
                               "source_review_completed": sum(node.get("review_status") == "completed" for node in observed),
                               "runtime_validation_unproven": sum(node.get("status") != "covered" for node in observed)}
    state["summary"] = summary
    allowed = complete and state.get("finalized") is True
    reason = ("All Phase 1 coverage obligations have successful Phase 2 execution evidence" if allowed else
              "All currently mapped tests are covered; Phase 3 is locked until final coverage validation" if complete else
              f"Phase 3 locked: {counts['covered']}/{total} obligations covered; {counts['blocked']} blocked, {counts['pending']} pending, {counts['running']} running")
    state["gate"] = {"complete": allowed, "phase3_allowed": allowed, "reason": reason,
                     "blockers": [{"id": n["id"], "label": n["label"], "reason": n["reason"] or "Coverage pending",
                                   **({"next_action": n["next_action"], "review_status": n.get("review_status", "pending"),
                                       "review_task_ids": n.get("review_task_ids", [])} if n.get("next_action") else {}),
                                   **({"configure_tool": n["configure_tool"], "task_name": n.get("task_name")}
                                      if isinstance(n.get("configure_tool"), str)
                                      and n["configure_tool"] in _RESOURCE_TOOLS else {})}
                                  for n in state.get("nodes") or [] if n["status"] != "covered"]}
    state["updated_at"] = _now()
    return state


def persist_coverage_map(dest: Path, coverage_map: dict) -> Path:
    """Atomically replace the durable map so reconnects never see partial JSON."""
    directory = Path(dest) / ".lotus"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "coverage_map.json"
    descriptor, temp_path = tempfile.mkstemp(prefix=".coverage-map-", suffix=".json", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            # dumps uses the C encoder; dumping an indented graph streams over
            # a million tiny Python chunks for a large audit on each event.
            handle.write(json.dumps(coverage_map, separators=(",", ":"), default=str))
            handle.write("\n")
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return path
