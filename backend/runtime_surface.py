"""Select dynamic HTTP work from a verified native component observation.

This changes dispatch only. It grants no finding, full-deployment, URL-admission
or coverage authority. Static classification and omitted behaviors stay explicit.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
from pathlib import Path
import re

from backend import adapter_observation as observer
from backend.proof_receipts import _canonical, content_tree_digest, verify_blob


def _object(value):
    return value if isinstance(value, dict) else {}


def _require(condition):
    if not condition:
        raise ValueError("Native HTTP observation identity is incomplete or changed")


def _verified_observation(repo_id, scan_job_id, adapter, lab_status, identity):
    """Validate only bounded, authenticated fields; never interpret target prose."""
    _require(type(repo_id) is int and repo_id > 0 and type(scan_job_id) is int and scan_job_id > 0)
    adapter, status = _object(adapter), _object(lab_status)
    _require(adapter.get("status") == "component-ready" and adapter.get("runtime_verified") is True
             and status.get("runtime_attested") is True and status.get("target_runtime_verified") is True)
    candidate = _object(adapter.get("candidate"))
    raw = _canonical(candidate)
    _require(len(raw) <= 65536 and candidate.get("profile") == "native-service")
    candidate_hash = hashlib.sha256(raw).hexdigest()
    _require(adapter.get("candidate_sha256") == candidate_hash)
    component = _object(candidate.get("component_scope"))
    refs, component_refs = candidate.get("source_evidence"), component.get("source_evidence")
    _require(isinstance(refs, list) and 1 <= len(refs) <= 64
             and all(isinstance(name, str) and 0 < len(name) <= 1000 for name in refs)
             and len(set(refs)) == len(refs) and isinstance(component_refs, list)
             and 1 <= len(component_refs) <= 16 and all(name in refs for name in component_refs)
             and isinstance(component.get("name"), str) and 0 < len(component["name"]) <= 160
             and isinstance(component.get("included_behaviors"), list) and bool(component["included_behaviors"])
             and isinstance(candidate.get("omitted_behaviors"), list))
    # Version-only CLI probes and source/consumer harnesses cannot promote a
    # repository to an HTTP app. Require the signed source-marker GET contract.
    expected = _object(candidate.get("smoke_test"))
    _require(set(expected) == {"path", "status_code", "body_contains"}
             and type(expected.get("status_code")) is int and 200 <= expected["status_code"] < 300
             and isinstance(expected.get("path"), str)
             and re.fullmatch(r"/[A-Za-z0-9_./~-]{0,511}", expected["path"])
             and not expected["path"].startswith("//") and ".." not in expected["path"].split("/")
             and isinstance(expected.get("body_contains"), str) and 8 <= len(expected["body_contains"]) <= 256
             and type(candidate.get("port")) is int and 1024 <= candidate["port"] <= 65535)
    runtime = _object(adapter.get("runtime"))
    smoke = _object(runtime.get("smoke"))
    _require(smoke.get("ran") is True and smoke.get("ok") is True
             and type(smoke.get("exit_code")) is int and smoke["exit_code"] == 0
             and _object(status.get("lab_smoke")) == smoke)
    observation = _object(smoke.get("observation"))
    unsigned = {key: value for key, value in observation.items() if key != "catalog_signature"}
    raw = _canonical(unsigned)
    _require(len(raw) <= 65536 and verify_blob(raw, observation.get("catalog_signature"),
                                             purpose=observer.HEALTH_CATALOG_PURPOSE))
    _require(observation.get("schema_version") == 1 and observation.get("observer") == "lotus-controller-http-v1"
             and observation.get("ok") is True and type(observation.get("scan_job_id")) is int
             and observation["scan_job_id"] == scan_job_id and observation.get("candidate_sha256") == candidate_hash
             and observation.get("source_marker_matched") is True
             and observation.get("source_marker_sha256") == hashlib.sha256(expected["body_contains"].encode()).hexdigest()
             and observation.get("status_code") == expected["status_code"]
             and observation.get("request") == {"method": "GET", "path": expected["path"], "port": candidate["port"]}
             and observation.get("evidence_role") == "component-observation"
             and observation.get("full_deployment_verified") is False)
    evidence = observation.get("source_evidence")
    _require(isinstance(evidence, list) and len(evidence) == len(refs))
    for name, row in zip(refs, evidence):
        _require(isinstance(row, dict) and set(row) == {"file", "sha256"} and row["file"] == name
                 and isinstance(row["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]))
    binding = observer._registered_binding(repo_id, status, identity)
    bound = _object(observation.get("runtime"))
    _require(all(bound.get(key) == value for key, value in binding.items())
             and bool(binding["lab_run_id"]) and bool(binding["target_revision"])
             and isinstance(bound.get("container_id"), str) and bool(bound["container_id"])
             and type(bound.get("restart_count")) is int and bound["restart_count"] >= 0
             and all(runtime.get(key) == binding[key] for key in ("pod_uid", "image_digest", "target_tree_hash")))
    return candidate, observation, binding


async def effective_runtime_surface(repo_id, scan_job_id, source, app_type, adapter, lab_status, target_identity):
    """Fail closed to the static type; cancellation still propagates normally.

    Call once immediately after the current audit's successful native observation,
    before dynamic discovery/planning. Existing downstream proof gates still apply.
    No target request, provider call, source write or runtime mutation occurs here.
    """
    result = {"schema_version": 1, "static_app_type": app_type, "app_type": app_type,
              "promoted": False, "verified_native_http": False,
              "reason": "No current source-bound native HTTP observation",
              "evidence_role": "dynamic-dispatch-only", "full_deployment_verified": False}
    try:
        candidate, observation, binding = _verified_observation(
            repo_id, scan_job_id, adapter, lab_status, target_identity)
        before = await observer._inspect_exact_pod(binding)
        _require(all(observation["runtime"].get(key) == value for key, value in before.items()))
        _require(await asyncio.to_thread(content_tree_digest, Path(source)) == binding["target_tree_hash"])
        after = await observer._inspect_exact_pod(binding)
        _require(before == after and observer._registered_binding(repo_id, lab_status, target_identity) == binding)
    except (ValueError, TypeError, KeyError, OSError, RuntimeError, RecursionError):
        return result
    effective = app_type if app_type in {"web-app", "webapp", "api-service"} else "api-service"
    return {**result, "app_type": effective, "promoted": effective != app_type,
            "verified_native_http": True, "reason": "Current captured native component passed controller HTTP observation",
            "scan_job_id": scan_job_id, "candidate_sha256": observation["candidate_sha256"],
            "target_tree_hash": binding["target_tree_hash"], "pod_uid": binding["pod_uid"],
            "component_scope": deepcopy(candidate["component_scope"]),
            "omitted_behaviors": deepcopy(candidate["omitted_behaviors"])}
