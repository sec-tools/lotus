"""Saved analyzer envelopes and revision-bound, typed resource failure receipts.

This module never changes cluster capacity or interprets analyzer stderr. A
resource block is incomplete coverage, never a successful empty scanner result.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import re
import tempfile
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from decimal import Decimal, DecimalException, localcontext
from pathlib import Path

TOOLS = {"gosec": "Gosec", "govulncheck": "Govulncheck", "staticcheck": "Staticcheck", "gofuzz": "Go fuzz testing", "joern": "Joern CPG", "semgrep": "Semgrep (baseline and registry)"}
MEMORY_ENV = {tool: "LOTUS_K8S_" + tool.upper() + "_MEMORY_MIB" for tool in TOOLS}
MEMORY_ENV["gofuzz"] = "LOTUS_K8S_FUZZ_MEM"
MEMORY_ENV["joern"] = "LOTUS_JOERN_MEM_LIMIT"
CAPABILITIES = {tool: "dynamic-path-exploration" if tool == "gofuzz" else tool for tool in TOOLS}
CAPABILITIES["joern"] = "joern-cpg"
FIELDS = {"enabled", "memory_mb", "timeout_seconds", "queue_timeout_seconds"}
BOUNDS = {"memory_mb": (4096, 65536), "timeout_seconds": (60, 7200), "queue_timeout_seconds": (60, 7200)}
AUDIT_CONTEXT = ContextVar("analyzer_resource_audit_context", default=None)
_HEX = re.compile(r"[a-f0-9]{64}")


def configuration_bounds(tool):
    return {**BOUNDS, **({"memory_mb": (512, 65536)} if tool in {"gofuzz", "semgrep"} else {})}


def validate_configuration(value):
    if not isinstance(value, dict) or set(value) - set(TOOLS):
        raise ValueError("analyzer_resources must map known analyzer identifiers to configuration objects")
    result = {}
    for tool, row in value.items():
        if not isinstance(row, dict) or set(row) - FIELDS:
            raise ValueError(f"Invalid resource fields for {tool}")
        clean = {}
        for field, val in row.items():
            if field == "enabled":
                if type(val) is not bool:
                    raise ValueError(f"{tool}.enabled must be a JSON boolean")
            elif val is not None and (type(val) is not int or not configuration_bounds(tool)[field][0] <= val <= configuration_bounds(tool)[field][1]):
                low, high = configuration_bounds(tool)[field]
                raise ValueError(f"{tool}.{field} must be null or an integer from {low} to {high}")
            clean[field] = val
        result[tool] = clean
    return result


def _saved(settings):
    value = settings.get("analyzer_resources", {}) if isinstance(settings, dict) else getattr(settings, "analyzer_resources", "{}")
    if isinstance(value, str):
        value = json.loads(value or "{}")
    if not isinstance(value, dict) or set(value) - set(TOOLS):
        raise ValueError("Saved analyzer resource configuration is invalid; save valid settings before retrying")
    return value


def public_configuration(settings):
    value = _saved(settings)
    clean = validate_configuration({tool: {k: v for k, v in row.items() if k != "_revision"}
                                    for tool, row in value.items() if isinstance(row, dict)})
    if len(clean) != len(value):
        raise ValueError("Saved analyzer resource configuration is invalid")
    return {tool: {"enabled": True, "memory_mb": None, "timeout_seconds": None,
                   "queue_timeout_seconds": None, **clean.get(tool, {})} for tool in TOOLS}


def merge_configuration(settings, patch):
    """Partial saves preserve unrelated tools; only explicit edits enable retry."""
    validate_configuration(patch)
    try:
        old, public = _saved(settings), public_configuration(settings)
    except (ValueError, TypeError):
        old, public = {}, public_configuration({})
    merged = copy.deepcopy(old)
    for tool, changes in patch.items():
        selected = {**public[tool], **changes}
        revision = str(old.get(tool, {}).get("_revision") or "default")
        if selected != public[tool]:
            revision = uuid.uuid4().hex
        merged[tool] = {**selected, "_revision": revision}
    return json.dumps(merged, sort_keys=True)


def _env_int(name, default, low, high):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default, "default"
    if not raw.isascii() or not raw.isdecimal() or not low <= int(raw) <= high:
        raise ValueError(f"{name} must be an integer from {low} to {high}")
    return int(raw), "environment"


def _fuzz_memory():
    """Preserve the legacy Kubernetes quantity, normalized upward to MiB."""
    from backend.k8s_runtime import _mem_to_bytes
    raw = os.environ.get(MEMORY_ENV["gofuzz"], "").strip()
    if not raw:
        return 3072, "default"
    try:
        amount = _mem_to_bytes(raw)
        if not 512 * 1024 ** 2 <= amount <= 65536 * 1024 ** 2:
            raise ValueError()
    except (ValueError, TypeError, OverflowError):
        raise ValueError("LOTUS_K8S_FUZZ_MEM must be a Kubernetes memory quantity from 512Mi to 65536Mi; Settings memory uses MiB") from None
    return (amount + 1024 ** 2 - 1) // (1024 ** 2), "environment"


def _joern_memory():
    """The inherited hard limit is also the scheduling reservation."""
    from backend.k8s_runtime import _mem_to_bytes
    raw = os.environ.get(MEMORY_ENV["joern"], "").strip()
    if not raw:
        return 4096, "default"
    try:
        amount = _mem_to_bytes(raw)
        if not 4096 * 1024 ** 2 <= amount <= 65536 * 1024 ** 2:
            raise ValueError()
    except (ValueError, TypeError, OverflowError):
        raise ValueError("LOTUS_JOERN_MEM_LIMIT must be a memory quantity from 4096Mi to 65536Mi; Settings memory uses MiB") from None
    return (amount + 1024 ** 2 - 1) // (1024 ** 2), "environment"


def snapshot_policy(settings):
    """Freeze saved policy, environment defaults and capability gates once."""
    from backend.tool_registry import is_tool_enabled
    try:
        configured, stored = public_configuration(settings), _saved(settings)
        configuration_error = ""
    except (ValueError, TypeError):
        configured, stored = public_configuration({}), {}
        configuration_error = "Saved analyzer resource configuration is invalid; save valid settings before retrying"
    rows = []
    for tool, label in TOOLS.items():
        row = {"id": tool, "label": label, "configured": configured[tool], "configure_tool": tool,
               "capability_id": CAPABILITIES[tool], "memory_unit": "MiB", "bounds": configuration_bounds(tool),
               "enabled": configured[tool]["enabled"], "state": "ready", "reason": "Configured envelope; runtime prerequisites and scheduling still apply",
               "requirements": [], "source": {}, "configuration_revision": str(stored.get(tool, {}).get("_revision") or "default")}
        try:
            row["capability_enabled"] = is_tool_enabled(CAPABILITIES[tool])
            if tool == "semgrep":
                row["capability_ids"] = ["semgrep", "semgrep-registry"]
                row["capability_enabled"] = any(is_tool_enabled(name) for name in row["capability_ids"])
            row["effective_enabled"] = row["enabled"] and row["capability_enabled"]
            effective = {}
            for field in BOUNDS:
                explicit = configured[tool][field]
                if explicit is not None:
                    value, source = explicit, "settings"
                elif field == "memory_mb":
                    value, source = (_fuzz_memory() if tool == "gofuzz" else _joern_memory() if tool == "joern"
                                     else _env_int(MEMORY_ENV[tool], 2048, 512, 65536) if tool == "semgrep"
                                     else _env_int(MEMORY_ENV[tool], 4096, 4096, 65536))
                elif field == "timeout_seconds":
                    if tool == "gofuzz":
                        value, source = None, "workload"
                    elif tool == "joern":
                        value, source = _env_int("LOTUS_JOERN_TIMEOUT", 900, 1, 7200)
                    elif tool == "semgrep":
                        name = "LOTUS_SEMGREP_TIMEOUT" if os.environ.get("LOTUS_SEMGREP_TIMEOUT") else "LOTUS_EXT_ANALYZER_TIMEOUT"
                        value, source = _env_int(name, 420, 1, 7200)
                    else:
                        name = "LOTUS_GO_ANALYZER_TIMEOUT" if os.environ.get("LOTUS_GO_ANALYZER_TIMEOUT") else "LOTUS_EXT_ANALYZER_TIMEOUT"
                        value, source = _env_int(name, 1800, 1, 7200)
                else:
                    default_queue = min(7200, max(60, 3 * effective["timeout_seconds"])) if effective["timeout_seconds"] is not None else None
                    value, source = _env_int("LOTUS_K8S_TOOL_QUEUE_TIMEOUT", default_queue, 1, 7200)
                    if value is None:
                        source = "workload"
                effective[field], row["source"][field] = value, source
            row["effective"] = {**effective, "cpu_request": "500m", "cpu_limit": "2", "memory_request_mb": effective["memory_mb"]}
            if tool == "semgrep":
                row["effective"]["cpu_limit"] = "1"
                row["runtime_options"] = {"jobs": 1}
            if tool == "joern":
                row["runtime_options"] = {"java_opts": os.environ.get("LOTUS_JOERN_JAVA_OPTS", "").strip() or f"-Xmx{effective['memory_mb'] * 3 // 4}m"}
            if not row["enabled"]:
                row.update(state="user_disabled", reason="Disabled in analyzer resource Settings; coverage remains incomplete")
            elif not row["capability_enabled"]:
                row.update(state="capability_disabled", reason="Disabled in Capabilities; re-enable that capability before execution")
            if configuration_error:
                raise ValueError(configuration_error)
        except (ValueError, TypeError) as exc:
            row.update(state="configuration_invalid", effective_enabled=False, reason=str(exc), effective={})
        rows.append(row)
    return {"schema_version": 1, "memory_unit": "MiB", "scope": "audit_configuration", "captured_at": datetime.now(timezone.utc).isoformat(), "tools": rows}


def task_resource_metadata(tool, policy, reason, *, failed=False, diagnostic=None):
    """Resource actions identify a task; the recovery API alone authorizes retry."""
    if tool not in TOOLS:
        raise ValueError("Unknown resource-managed task")
    row = {**copy.deepcopy(policy or {}), "tool_id": tool, "configure_tool": tool,
           "parent_task": CAPABILITIES[tool], "memory_unit": "MiB",
           "admission_state": (policy or {}).get("state"),
           "state": "resource_failed" if failed else "resource_blocked", "reason": reason}
    result = {"configure_tool": tool, "parent_task": CAPABILITIES[tool], "resource_policy": row}
    if diagnostic:
        row["diagnostic"] = copy.deepcopy(diagnostic)
        result["runtime_diagnostic"] = copy.deepcopy(diagnostic)
    return result


def go_fuzz_envelope(policy, workload_timeout):
    """Resolve planned-harness budgets using only the audit's frozen policy."""
    effective = policy.get("effective") or {}
    memory = effective.get("memory_mb")
    if type(memory) is not int or not 512 <= memory <= 65536:
        raise ValueError("Captured Go fuzz memory policy is invalid")
    timeout = effective.get("timeout_seconds")
    if timeout is None:
        timeout = int(workload_timeout)
    elif type(timeout) is not int or not 60 <= timeout <= 7200:
        raise ValueError("Captured Go fuzz execution budget is invalid")
    queue = effective.get("queue_timeout_seconds")
    if queue is None:
        queue = min(7200, max(60, 3 * timeout))
    elif type(queue) is not int or not 1 <= queue <= 7200:
        raise ValueError("Captured Go fuzz queue budget is invalid")
    return {"mem_request": f"{memory}Mi", "mem_limit": f"{memory}Mi", "cpu_request": "500m", "cpu_limit": "2",
            "timeout_seconds": timeout, "queue_timeout_seconds": queue}


def _reservation_memory_bytes(value):
    """Parse exact whole-byte quantities; ambiguous input is never zero RAM."""
    if type(value) not in (str, int):
        raise ValueError("Unreadable memory request")
    raw = str(value)
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]*)?|\.[0-9]+)([eE][+-]?[0-9]+|[KMGTPE]i|[kKMGTPE]|m)?", raw) if len(raw) <= 48 else None
    if match is None:
        raise ValueError("Unreadable memory request")
    suffix = match[2] or ""
    units = {"": 1, "m": Decimal("0.001"), "k": 1000, "K": 1000}
    units.update({name + "i": 1024 ** power for power, name in enumerate("KMGTPE", 1)})
    units.update({name: 1000 ** power for power, name in enumerate("MGTPE", 2)})
    try:
        with localcontext() as context:
            context.prec = 80
            amount = Decimal(match[1]) * (Decimal("1" + suffix) if suffix.startswith(("e", "E")) and suffix not in units else units[suffix])
        if not amount.is_finite() or amount < 0 or amount > 2 ** 63 - 1 or amount != amount.to_integral_value():
            raise ValueError("Unreadable memory request")
        return int(amount)
    except (DecimalException, OverflowError, KeyError):
        raise ValueError("Unreadable memory request") from None


def _pod_memory_request(pod):
    """Effective regular/init/sidecar request plus overhead for a stable Pod.

    Pod-level budgets and in-place resize require additional scheduler state;
    refuse their accounting instead of overstating known reservations.
    """
    spec, status = pod.get("spec"), pod.get("status")
    if not isinstance(spec, dict) or not isinstance(status, dict):
        raise ValueError("Unreadable Pod resources")
    conditions = status.get("conditions", [])
    if not isinstance(conditions, list) or len(conditions) > 256:
        raise ValueError("Unreadable Pod conditions")
    if spec.get("resources", {}) != {} or status.get("resize") or any(
            isinstance(item, dict) and item.get("type") in {"PodResizePending", "PodResizeInProgress"}
            and item.get("status") == "True" for item in conditions):
        raise ValueError("Pod-level or resizing resources need scheduler inspection")
    containers, init = spec.get("containers"), spec.get("initContainers", [])
    if not isinstance(containers, list) or not containers or not isinstance(init, list) or len(containers) + len(init) > 256:
        raise ValueError("Unreadable Pod containers")
    names, requests = set(), {}
    for container in containers + init:
        if not isinstance(container, dict) or not isinstance(container.get("name"), str) or not container["name"] or container["name"] in names:
            raise ValueError("Ambiguous Pod container identity")
        names.add(container["name"])
        resources = container.get("resources")
        if not isinstance(resources, dict) or not isinstance(resources.get("requests"), dict):
            raise ValueError("Missing explicit memory request")
        requests[container["name"]] = _reservation_memory_bytes(resources["requests"].get("memory"))
    # A requested/allocated mismatch may be an in-place resize still pending.
    for key in ("containerStatuses", "initContainerStatuses"):
        rows = status.get(key, [])
        if not isinstance(rows, list):
            raise ValueError("Unreadable allocated resources")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Unreadable allocated resources")
            allocated = row.get("allocatedResources")
            if allocated is not None and (not isinstance(allocated, dict) or "memory" not in allocated
                    or row.get("name") not in requests or _reservation_memory_bytes(allocated["memory"]) != requests[row["name"]]):
                raise ValueError("Allocated/requested memory differs")
    regular = sum(requests[c["name"]] for c in containers)
    if any(c.get("restartPolicy") is not None for c in containers):
        raise ValueError("Unknown regular-container restart policy")
    sidecars = init_peak = 0
    for container in init:
        restart = container.get("restartPolicy")
        if restart not in (None, "Always"):
            raise ValueError("Unknown init-container restart policy")
        memory = requests[container["name"]]
        if restart == "Always":
            sidecars += memory
            init_peak = max(init_peak, sidecars)
        else:
            init_peak = max(init_peak, sidecars + memory)
    overhead = spec.get("overhead", {})
    if not isinstance(overhead, dict):
        raise ValueError("Unreadable Pod overhead")
    return max(regular + sidecars, init_peak) + _reservation_memory_bytes(overhead.get("memory", "0"))


def _namespace_reservations(result, nodes, namespace):
    """Observed reservations are a lower bound; other namespaces remain unseen."""
    totals = {node["name"]: 0 for node in nodes if node["name"]}
    counts = dict.fromkeys(totals, 0)
    valid = isinstance(result, tuple) and len(result) == 3 and result[1] == 0 and isinstance(result[0], dict)
    items = result[0].get("items") if valid else None
    if not isinstance(items, list) or len(items) > 4096:
        return {"observed": False, "known_pods": 0, "ambiguous_pods": 0, "by_node": totals, "pod_counts": counts}
    uids = {}
    for pod in items:
        meta = pod.get("metadata") if isinstance(pod, dict) else None
        uid = meta.get("uid") if isinstance(meta, dict) else None
        if isinstance(uid, str) and uid:
            uids[uid] = uids.get(uid, 0) + 1
    unknown = known = 0
    for pod in items:
        try:
            if not isinstance(pod, dict):
                raise ValueError("Unreadable Pod")
            meta, spec, status = pod.get("metadata"), pod.get("spec"), pod.get("status")
            if not all(isinstance(item, dict) for item in (meta, spec, status)):
                raise ValueError("Unreadable Pod")
            if meta.get("namespace") != namespace or not isinstance(meta.get("uid"), str) or uids.get(meta["uid"]) != 1:
                raise ValueError("Ambiguous namespace Pod identity")
            if status.get("phase") in {"Succeeded", "Failed"}:
                continue
            if status.get("phase") not in {"Pending", "Running", "Unknown"}:
                raise ValueError("Unknown Pod lifecycle")
            node = spec.get("nodeName")
            if node in (None, ""):
                # An unbound Pending Pod has no per-node reservation yet.
                if status.get("phase") == "Pending":
                    continue
                raise ValueError("Active Pod node is unknown")
            if not isinstance(node, str) or node not in totals:
                raise ValueError("Pod node is absent from the capacity inventory")
            totals[node] += _pod_memory_request(pod)
            counts[node] += 1
            known += 1
        except (ValueError, TypeError, KeyError, AttributeError):
            unknown += 1
    return {"observed": unknown == 0, "known_pods": known, "ambiguous_pods": unknown,
            "by_node": totals, "pod_counts": counts}


async def observe_capacity():
    """Read allocatable and namespace reservations; never promise free RAM."""
    from backend import k8s_runtime as kr
    results = await asyncio.gather(*(kr.get_json(kind, timeout=5) for kind in ("nodes", "resourcequota", "limitrange", "pods")), return_exceptions=True)
    nodes, quotas, limits = [], [], []
    readable = []
    for index, (kind, result) in enumerate(zip(("nodes", "quota", "limits"), results)):
        ok = isinstance(result, tuple) and len(result) == 3 and result[1] == 0 and isinstance(result[0], dict) and isinstance(result[0].get("items"), list)
        readable.append(ok)
        if not ok:
            continue
        for item in result[0]["items"]:
            if not isinstance(item, dict):
                continue
            try:
                if kind == "nodes":
                    alloc = item.get("status", {}).get("allocatable", {})
                    memory = _reservation_memory_bytes(alloc["memory"])
                    if memory <= 0:
                        raise ValueError("Unreadable node memory")
                    ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in item.get("status", {}).get("conditions", []))
                    nodes.append({"name": str(item.get("metadata", {}).get("name", "")), "uid": str(item.get("metadata", {}).get("uid", "")),
                                  "memory_mb": memory // (1024 ** 2), "memory_bytes": memory,
                                  "cpu_millicores": kr._cpu_to_millicores(str(alloc["cpu"])),
                                  "schedulable": ready and not item.get("spec", {}).get("unschedulable", False)})
                elif kind == "quota":
                    spec = item.get("spec") or {}
                    if spec.get("scopes") or spec.get("scopeSelector"):
                        # A quota limited to another Pod class must not block
                        # this analyzer. Let admission evaluate scoped quotas.
                        readable[1] = False
                        continue
                    hard = item.get("status", {}).get("hard") or spec.get("hard") or {}
                    quotas.append({"name": str(item.get("metadata", {}).get("name", "")),
                        "memory_mb": min([kr._mem_to_bytes(str(hard[k])) // (1024 ** 2) for k in ("requests.memory", "limits.memory") if k in hard], default=None)})
                else:
                    for limit in item.get("spec", {}).get("limits", []):
                        if limit.get("type") not in {"Container", "Pod"}:
                            continue
                        bounds = {"name": str(item.get("metadata", {}).get("name", "")), "type": limit["type"]}
                        for bound in ("min", "max"):
                            value = limit.get(bound, {}).get("memory")
                            amount = kr._mem_to_bytes(str(value)) if value is not None else None
                            if amount is not None and amount <= 0:
                                raise ValueError("Unreadable LimitRange memory bound")
                            bounds[bound + "_memory_bytes"] = amount
                        limits.append(bounds)
            except (ValueError, TypeError, KeyError):
                readable[index] = False
    reservations = _namespace_reservations(results[3], nodes, kr.namespace())
    for node in nodes:
        reserved = reservations["by_node"].get(node["name"], 0)
        node.update(namespace_memory_requested_bytes=reserved,
                    namespace_reserved_pods=reservations["pod_counts"].get(node["name"], 0),
                    memory_available_upper_bound_bytes=max(0, node["memory_bytes"] - reserved))
    observed = all(readable) and reservations["observed"]
    return {"status": "observed" if observed else "unknown", "nodes_observed": readable[0], "quotas_observed": readable[1], "limits_observed": readable[2],
            "reservations_observed": reservations["observed"], "reservation_scope": "namespace", "reservation_namespace": kr.namespace(),
            "known_reserved_pods": reservations["known_pods"], "ambiguous_reserved_pods": reservations["ambiguous_pods"],
            "reason": "Remaining memory is an upper bound after observed namespace Pod requests; other namespaces and scheduling constraints remain unobserved. This is not a free-memory or successful-admission guarantee" if observed else "Some capacity, namespace Pod reservations or admission policy is unreadable or ambiguous. No available capacity is promised; Kubernetes admission remains authoritative",
            "observed_at": datetime.now(timezone.utc).isoformat(), "nodes": nodes, "quotas": quotas, "limits": limits}


async def assess_policy(snapshot):
    result = copy.deepcopy(snapshot)
    capacity = result["capacity"] = await observe_capacity()
    for row in result["tools"]:
        if row["state"] != "ready":
            continue
        requested = row["effective"]["memory_mb"]
        reasons = []
        if capacity["nodes_observed"] and not any(n["schedulable"] and n["memory_mb"] >= requested and n["cpu_millicores"] >= 500 for n in capacity["nodes"]):
            reasons.append(f"No observed Ready, schedulable node can admit {requested} MiB and 500m CPU for this Pod")
        elif capacity["nodes_observed"] and not any(n["schedulable"] and n["cpu_millicores"] >= 500
                and n["memory_available_upper_bound_bytes"] >= requested * 1024 ** 2 for n in capacity["nodes"]):
            largest = max((n["memory_available_upper_bound_bytes"] for n in capacity["nodes"]
                           if n["schedulable"] and n["cpu_millicores"] >= 500), default=0) // (1024 ** 2)
            reasons.append(f"Observed namespace Pod reservations leave at most {largest} MiB on any Ready, schedulable node, below this Pod's {requested} MiB request. Provide sufficient node capacity or explicitly change analyzer configuration; coverage remains incomplete")
        if any(q["memory_mb"] is not None and q["memory_mb"] < requested for q in capacity["quotas"]):
            reasons.append(f"Namespace memory quota is below this Pod's {requested} MiB request/limit")
        for limit in capacity.get("limits", []):
            requested_bytes = requested * 1024 ** 2
            if ((limit["min_memory_bytes"] is not None and requested_bytes < limit["min_memory_bytes"])
                    or (limit["max_memory_bytes"] is not None and requested_bytes > limit["max_memory_bytes"])):
                reasons.append(f"Namespace {limit['type']} LimitRange memory bounds reject this Pod's {requested} MiB request/limit")
        if reasons:
            row.update(state="capacity_blocked", effective_enabled=False, reason="; ".join(reasons), requirements=reasons)
        elif capacity["status"] == "unknown":
            row.update(state="unknown", reason=capacity["reason"])
    return result


async def refresh_tool_admission(policy):
    """Recheck reservations at dispatch without changing the captured envelope."""
    row = copy.deepcopy(policy)
    if row.get("state") not in {"ready", "unknown", "capacity_blocked"}:
        return row
    if row.get("enabled") is not True or row.get("capability_enabled") is not True:
        return row
    row.update(state="ready", effective_enabled=True, requirements=[],
               reason="Captured envelope; fresh Kubernetes admission observation applies")
    assessed = await assess_policy({"tools": [row]})
    result = assessed["tools"][0]
    result["capacity_observation"] = assessed["capacity"]
    return result


@contextmanager
def audit_context(snapshot, *, repo_id, scan_job_id, target_identity):
    ctx = {"policy": copy.deepcopy(snapshot), "repo_id": int(repo_id), "scan_job_id": int(scan_job_id), "target_identity": copy.deepcopy(target_identity)}
    token = AUDIT_CONTEXT.set(ctx)
    try:
        yield ctx
    finally:
        AUDIT_CONTEXT.reset(token)


def selected_tool(tool):
    context = AUDIT_CONTEXT.get()
    if not context or tool not in TOOLS:
        return None
    return copy.deepcopy(next((r for r in context["policy"].get("tools", []) if r.get("id") == tool), None))


def _receipt_path(key):
    if not _HEX.fullmatch(key):
        raise ValueError("Invalid resource receipt identity")
    return Path(os.environ.get("LOTUS_DATA_DIR", "./data")) / "runtime_resource_receipts" / (key + ".json")


def execution_identity(tool, image, target_path, script, env, effective):
    context = AUDIT_CONTEXT.get()
    if not context or context["repo_id"] <= 0 or context["scan_job_id"] <= 0:
        return None
    identity = context.get("target_identity") or {}
    raw_tree = str(identity.get("tree_hash") or identity.get("target_tree_hash") or "")
    digest = raw_tree.removeprefix("sha256:")
    if not _HEX.fullmatch(digest):
        return None
    tree = "sha256:" + digest
    payload = {"repo_id": context["repo_id"], "target_tree_hash": tree, "tool_id": tool,
        "image": image, "target_path": target_path, "effective": effective,
        "configuration_revision": (selected_tool(tool) or {}).get("configuration_revision", "default"),
        "script_sha256": hashlib.sha256((script or "").encode()).hexdigest(),
        "env_sha256": hashlib.sha256(json.dumps(env or {}, sort_keys=True).encode()).hexdigest(),
        "scratch_size": os.environ.get("LOTUS_K8S_SCRATCH_SIZE", "24Gi")}
    key = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return {**payload, "scope_hash": key, "scan_job_id": context["scan_job_id"], "target_revision": identity.get("target_revision") or identity.get("revision", "")}


def prior_resource_failure(identity):
    if not identity:
        return None
    try:
        path = _receipt_path(identity["scope_hash"])
        if path.is_symlink() or path.stat().st_size > 32768:
            return None
        row = json.loads(path.read_text())
        if row.get("scope_hash") == identity["scope_hash"] and row.get("diagnostic", {}).get("classification") == "oom_killed":
            return row
    except (OSError, ValueError, TypeError):
        pass
    return None


def record_resource_failure(identity, diagnostic):
    """Called only by an owned runtime's typed diagnostic callback."""
    if not identity or diagnostic.get("classification") != "oom_killed" or not diagnostic.get("ownership_verified"):
        return
    if (diagnostic.get("tool_id") != identity["tool_id"] or diagnostic.get("repo_id") != identity["repo_id"]
            or diagnostic.get("image") != identity["image"]):
        return
    envelope = identity["effective"]
    if (diagnostic.get("memory_request") != envelope.get("mem_request")
            or diagnostic.get("memory_limit") != envelope.get("mem_limit")
            or diagnostic.get("timeout_seconds") != envelope.get("timeout_seconds")):
        return
    path = _receipt_path(identity["scope_hash"])
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    row = {**identity, "diagnostic": diagnostic, "recorded_at": datetime.now(timezone.utc).isoformat()}
    fd, name = tempfile.mkstemp(prefix=".receipt-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(row, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
