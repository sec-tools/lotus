"""Deployment identity fingerprints and public host discovery.

This module is intentionally outside the vulnerability pipeline.  It produces
deployment *observations* only: a static signature for an audited target,
dynamic request/response signatures from a harmless local lab baseline, and
matches for operator-supplied hosts.  It never creates or promotes ``Finding``
rows and never sends vulnerability payloads.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import time
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from backend import deployment_request_plan as request_plans


_ROUTE_KEYS = {"path", "route", "endpoint", "url", "base_url", "health_url"}
_SOURCE_SUFFIXES = re.compile(
    r"\.(?:py|rb|go|java|kt|js|jsx|ts|tsx|php|c|cc|cpp|h|hpp|rs|ex|exs|cs|sql|md)$",
    re.I,
)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_MAX_REQUESTS = 32
_MAX_RESPONSE_BYTES = 128 * 1024
_IDENTITY_SLOTS = threading.BoundedSemaphore(2)
_IDENTITY_QUEUE_SECONDS = 15
_IDENTITY_CAPTURE_SECONDS = 105


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _walk_route_values(value: Any, *, key: str = "") -> Iterable[str]:
    if isinstance(value, dict):
        for k, v in value.items():
            if str(k).lower() in _ROUTE_KEYS:
                if isinstance(v, str):
                    yield v
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            yield item
                        elif isinstance(item, dict):
                            for nested in _walk_route_values(item, key=str(k)):
                                yield nested
            else:
                yield from _walk_route_values(v, key=str(k))
    elif isinstance(value, list):
        for item in value:
            yield from _walk_route_values(item, key=key)


def _normalise_path(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw or len(raw) > 256:
        return None
    if raw.startswith(("http://", "https://")):
        raw = urlsplit(raw).path or "/"
    if not raw.startswith("/"):
        return None
    raw = raw.split("?", 1)[0].split("#", 1)[0]
    if ".." in raw or any(ch in raw for ch in "{}[];|&$`\\\"'\n\r"):
        return None
    # Avoid probing source files accidentally surfaced by static analyzers.
    if _SOURCE_SUFFIXES.search(raw.rsplit("/", 1)[-1]):
        return None
    return "/" + "/".join(part for part in raw.split("/") if part) if raw != "/" else "/"


def _load_job_output(job: Any) -> Dict[str, Any]:
    try:
        value = json.loads(getattr(job, "output", "") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


# A route appearing in an audit is inventory, not permission to invoke it.
# Identity collection uses this fixed set of conventional read-only metadata
# resources. No arbitrary discovered route, query, body, or finding is used.
_SAFE_IDENTITY_PATHS = frozenset({
    "/", "/health", "/healthz", "/status", "/version", "/robots.txt",
    "/favicon.ico", "/openapi.json", "/swagger.json",
})
_GENERIC_MARKERS = {
    "api", "app", "service", "unknown", "default", "test", "ok", "healthy",
    "fastapi", "django", "express", "spring", "swagger", "openapi", "nginx", "apache",
}


def _target_identity(output):
    checkpoint = output.get("phase1_checkpoint") if isinstance(output.get("phase1_checkpoint"), dict) else {}
    for value in (output.get("target_identity"), output.get("audit_plan"), checkpoint.get("target_identity")):
        if isinstance(value, dict) and (value.get("target_tree_hash") or value.get("tree_hash")):
            return {"target_revision": str(value.get("target_revision") or ""),
                    "target_tree_hash": str(value.get("target_tree_hash") or value.get("tree_hash") or "")}
    return {"target_revision": "", "target_tree_hash": ""}


def build_static_signature(repo: Any, job: Any) -> Dict[str, Any]:
    """Keep full route provenance while restricting identity requests to metadata."""
    output = _load_job_output(job)
    plan = output.get("audit_plan") if isinstance(output.get("audit_plan"), dict) else {}
    surface = output.get("attack_surface") if isinstance(output.get("attack_surface"), dict) else {}
    artifact_routes = sorted({path for value in (surface, output.get("dynamic_recon") or {})
                              for raw in _walk_route_values(value) if (path := _normalise_path(raw))})
    app_type = str(output.get("app_type") or plan.get("app_type") or "unknown")
    network_service = app_type.lower() in {"api-service", "web-app", "web", "service"} or bool(artifact_routes)
    paths = sorted(set(artifact_routes) & _SAFE_IDENTITY_PATHS) if network_service else []
    static = {
        "schema_version": 2, "kind": "lotus-deployment-static-signature",
        "repo_id": int(getattr(repo, "id", 0) or 0), "scan_job_id": int(getattr(job, "id", 0) or 0),
        "source": str(getattr(repo, "source", "") or ""), "branch": str(getattr(repo, "branch", "") or ""),
        **_target_identity(output), "language": str(output.get("language") or plan.get("language") or "unknown"),
        "app_type": app_type, "network_service": network_service,
        "routes": paths, "route_count": len(paths), "artifact_routes": artifact_routes[:500],
        "excluded_route_count": len(set(artifact_routes) - set(paths)),
        "request_policy": "source-reviewed-identity-plan-v1",
        "tool_names": sorted({str(x.get("name")) for x in output.get("tool_results", []) if isinstance(x, dict) and x.get("name")}),
    }
    static["signature_hash"] = _hash(static)
    return static


def _confidence_label(value: float) -> str:
    return "high" if value >= .85 else "medium" if value >= .55 else "low" if value > 0 else "unavailable"


def _body_markers(body: str) -> List[str]:
    """Extract product identifiers; common JSON keys/framework names are weak."""
    markers = set()
    title = re.search(r"<title[^>]*>\s*([^<]{3,120})", body, re.I)
    if title:
        text = re.sub(r"\s+", " ", title.group(1)).strip().lower()
        if text not in _GENERIC_MARKERS | {"fastapi", "django", "express", "spring", "swagger", "openapi"} and not any(word in text for word in ("welcome", "not found", "error", "forbidden", "index of", "swagger ui", "login", "install worked", "congratulations")):
            markers.add("title:" + text)
    try:
        document = json.loads(body)
    except (TypeError, ValueError, RecursionError):
        document = None
    if isinstance(document, dict):
        for key in ("product", "service", "service_name", "application", "app_name"):
            value = document.get(key)
            if isinstance(value, str) and 3 <= len(value.strip()) <= 120 and value.strip().lower() not in _GENERIC_MARKERS:
                markers.add("product:" + value.strip().lower())
        if isinstance(document.get("info"), dict):
            value = document["info"].get("title")
            if isinstance(value, str) and 3 <= len(value.strip()) <= 120 and value.strip().lower() not in _GENERIC_MARKERS:
                markers.add("product:" + value.strip().lower())
    return sorted(markers)[:8]


async def _capture_http_signature(base_url: str, paths: List[str], *, timeout: float = 5.0,
                                  trusted_local: bool = False,
                                  local_binding: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Parse bounded observations returned by the destination-scoped sender Pod."""
    from backend.deployment_identity_transport import capture
    started = time.monotonic()
    while not _IDENTITY_SLOTS.acquire(blocking=False):
        if time.monotonic() - started >= _IDENTITY_QUEUE_SECONDS:
            raise TimeoutError("Identity workers are busy; retry this observation shortly")
        await asyncio.sleep(.1)
    try:
        # Cancellation is awaited through the sender's UID-bound cleanup.
        raw = await asyncio.wait_for(capture(base_url, paths, timeout=timeout, trusted_local=trusted_local,
                                            local_binding=local_binding), timeout=_IDENTITY_CAPTURE_SECONDS)
    finally:
        _IDENTITY_SLOTS.release()
    rows = []
    for response in raw["requests"]:
        row = {"method": "GET", "path": response["path"], "status": response.get("status", 0)}
        if response.get("error"):
            row["error"] = response["error"]
        else:
            body, headers = response.get("body", ""), response.get("headers", {})
            truncated = bool(response.get("truncated"))
            # Location is observation metadata only. A malformed value must not
            # discard completed GETs or become a follow-up destination.
            try:
                location_path = urlsplit(headers.get("location", "")).path[:256]
            except ValueError:
                location_path = ""
                row["metadata_warnings"] = ["invalid-location"]
            row.update(content_type=headers.get("content-type", "").split(";", 1)[0].lower()[:100],
                       server=headers.get("server", "").lower()[:80], markers=_body_markers(body),
                       body_bytes=response.get("body_bytes", 0), body_hash=_hash(body) if body and not truncated else "",
                       truncated=truncated, location_path=location_path)
        rows.append(row)
    return {"schema_version": 3, "base_url": base_url, "requests": rows,
            "successful": sum(1 for row in rows if 200 <= row.get("status", 0) < 300),
            "total": len(rows), "duration_ms": int((time.monotonic() - started) * 1000),
            "request_policy": "source-reviewed-identity-plan-v1", "response_byte_limit": _MAX_RESPONSE_BYTES,
            "transport": raw.get("transport", {})}


def _compare_signatures(static: Dict[str, Any], baseline: Dict[str, Any], observed: Dict[str, Any]) -> Dict[str, Any]:
    expected = {r.get("path"): r for r in baseline.get("requests", []) if isinstance(r, dict)
                and r.get("method") == "GET" and r.get("path") in _SAFE_IDENTITY_PATHS and 200 <= int(r.get("status") or 0) < 300}
    actual = {r.get("path"): r for r in observed.get("requests", []) if isinstance(r, dict)
              and r.get("method") == "GET" and r.get("path") in _SAFE_IDENTITY_PATHS}
    evidence, anchor_keys, contradictions = [], set(), 0
    for path, reference in expected.items():
        row = actual.get(path) or {}
        reference_markers = set(reference.get("markers") or [])
        strong_markers = {m for m in reference_markers & set(row.get("markers") or []) if m.startswith(("product:", "title:"))}
        exact = bool(reference.get("body_hash") and reference["body_hash"] == row.get("body_hash")
                     and min(reference.get("body_bytes", 0), row.get("body_bytes", 0)) >= 32)
        valid = 200 <= int(row.get("status") or 0) < 300 and not row.get("truncated") and not reference.get("truncated")
        anchored = bool(valid and strong_markers)
        if anchored:
            anchor_keys.add((tuple(sorted(strong_markers)), reference.get("body_hash") or ""))
        mismatched_product = bool(reference_markers and row.get("markers") and not strong_markers)
        contradictions += int(mismatched_product)
        evidence.append({"path": path, "method": "GET", "identity_anchor": anchored,
                         "matching_identifiers": sorted(strong_markers), "exact_body": exact,
                         "observed_status": row.get("status", 0), "expected_status": reference.get("status"),
                         "contradiction": mismatched_product})
    coverage = sum(1 for path in expected if int((actual.get(path) or {}).get("status") or 0) > 0) / max(1, len(expected))
    anchors = len(anchor_keys)
    confidence = 0.0
    if anchors:
        confidence = min(.95, .35 + .25 * anchors + .1 * coverage)
        if contradictions:
            confidence = min(.3, confidence)
    elif expected and any(row.get("status") for row in actual.values()):
        confidence = .1
    return {"confidence": round(confidence, 3), "confidence_label": _confidence_label(confidence),
            "confidence_basis": "conservative-service-identity-heuristic", "calibrated_probability": False,
            "revision_verified": False, "matched": bool(anchors and not contradictions and confidence >= .55),
            "matched_requests": anchors, "route_coverage": round(coverage, 3), "matches": evidence,
            "identity_anchors": anchors, "contradictions": contradictions,
            "reason": ("Distinctive product identifiers conflict with the selected-audit baseline." if contradictions else "Distinctive product identifiers match the selected-audit lab baseline; remote source revision is unproven."
                       if anchors and not contradictions else "Generic HTTP status/content type, default pages and shared framework headers do not establish service identity."),
            "result_type": "deployment-observation", "findings_created": 0}


async def build_profile(repo: Any, job: Any, *, local_lab: Optional[Dict[str, Any]] = None,
                        local_lab_url: Optional[str] = None,
                        request_plan: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    static = build_static_signature(repo, job)
    fresh = request_plans.make_plan(static, _load_job_output(job))
    plan = request_plans.validate_plan(request_plan, static) if request_plan is not None else fresh
    if plan.get("catalog_hash") != fresh.get("catalog_hash"):
        raise ValueError("Request candidates changed; review the source-supported plan again")
    profile = {"schema_version": 3, "kind": "lotus-deployment-profile", "network_service": static["network_service"],
               "static_signature": static, "static_signature_hash": static["signature_hash"],
               "request_plan": plan, "requests": plan["requests"],
               "confidence": 0.0, "confidence_label": "unavailable", "dynamic_status": "unavailable",
               "confidence_basis": "baseline-evidence-sufficiency", "calibrated_probability": False,
               "result_type": "deployment-observation", "findings_created": 0}
    if not static["network_service"]:
        profile.update(dynamic_status="not-applicable", reason="Selected audit describes a non-network target")
    elif not plan["requests"]:
        profile["reason"] = "No source-supported identity requests are available; inspect request-plan evidence gaps"
    elif not local_lab or not local_lab.get("identity_bound"):
        profile["reason"] = "A running isolated lab bound to the selected audit revision is required for an identity baseline"
    elif local_lab.get("repo_id") != static["repo_id"] or local_lab.get("scan_job_id") != static["scan_job_id"] or local_lab.get("target_tree_hash") != static["target_tree_hash"]:
        profile["reason"] = "Local lab identity differs from the selected audit"
    else:
        dynamic = await _capture_http_signature(local_lab["url"], request_plans.get_request_paths(plan, static),
                                               trusted_local=True, local_binding=local_lab)
        dynamic["request_plan_hash"] = plan["plan_hash"]
        profile["dynamic_signature"] = dynamic
        profile["baseline_provenance"] = {key: local_lab.get(key) for key in
            ("repo_id", "scan_job_id", "target_tree_hash", "target_revision", "provider", "container_id", "lab_run_id", "pod_uid", "source_binding")}
        profile["baseline_provenance"]["request_plan_hash"] = plan["plan_hash"]
        anchors = len({(tuple(row["markers"]), row.get("body_hash") or "") for row in dynamic["requests"]
                       if 200 <= row.get("status", 0) < 300 and row.get("markers") and not row.get("truncated")})
        profile["dynamic_status"] = "captured" if dynamic["successful"] else "unavailable"
        profile["confidence"] = min(.9, .35 + .25 * anchors) if anchors else 0.0
        profile["confidence_label"] = _confidence_label(profile["confidence"])
        profile["reason"] = "Product identifiers captured from the selected-audit isolated lab" if anchors else "Responses contain no distinctive product identifiers; identity matching remains inconclusive"
    profile["fingerprint_hash"] = _hash(profile)
    return profile


def validate_domain(value: str) -> str:
    if not isinstance(value, str) or any(ord(char) < 32 for char in value):
        raise ValueError("domain must be text without control characters")
    raw = value.strip().lower().rstrip(".")
    if raw.startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        if parsed.username or parsed.password or parsed.port or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("domain must not include a path, query or fragment")
        raw = parsed.hostname or ""
    if not _DOMAIN_RE.fullmatch(raw):
        raise ValueError("domain must be a public DNS name such as example.com")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not accepted as recon domains")
    return raw


def normalize_host(value: str, scheme: str = "https", port: Optional[int] = None) -> Tuple[str, str, Optional[int]]:
    if not isinstance(value, str) or any(ord(char) < 32 for char in value):
        raise ValueError("host must be text without control characters")
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("port must be an integer between 1 and 65535")
    raw = value.strip().lower()
    if not raw:
        raise ValueError("host is required")
    if "://" not in raw and raw.count(":") > 1 and not raw.startswith("["):
        raw = "[" + raw + "]"
    parsed = urlsplit(raw if "://" in raw else f"{scheme}://{raw}")
    if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("host must be a hostname or URL without credentials/path/query")
    host = (parsed.hostname or "").rstrip(".")
    if not host or any(ch in host for ch in "\r\n;|&$`\\\"'<>[]{}"):
        raise ValueError("invalid host")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("invalid hostname") from exc
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")
        ):
            raise ValueError("invalid hostname")
    chosen_scheme = parsed.scheme.lower()
    chosen_port = parsed.port if parsed.port is not None else port
    if chosen_scheme not in {"http", "https"}:
        raise ValueError("scheme must be http or https")
    if chosen_port is not None and not 1 <= chosen_port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if chosen_port == (443 if chosen_scheme == "https" else 80):
        chosen_port = None
    return host, chosen_scheme, chosen_port


async def discover_public_subdomains(domains: List[str], *, run_id: int, timeout: int = 180) -> Dict[str, Any]:
    from backend.deployment_passive import collect_passive
    values = sorted({validate_domain(domain) for domain in domains})
    if not values or len(values) > 50:
        raise ValueError("passive discovery requires between 1 and 50 explicit domains")
    return await collect_passive(values, run_id=run_id, timeout=timeout)


async def verify_host(base_url: str, profile: Dict[str, Any], *, owned_local: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    static = profile.get("static_signature") or {}
    provenance = profile.get("baseline_provenance") or {}
    baseline = profile.get("dynamic_signature") or {}
    common = {"result_type": "deployment-observation", "findings_created": 0,
              "confidence": 0.0, "confidence_label": "unavailable", "revision_verified": False,
              "confidence_basis": "conservative-service-identity-heuristic", "calibrated_probability": False}
    # Do not contact a saved host until a correctly scoped lab baseline exists.
    if not baseline.get("requests") or not provenance.get("container_id") or any(
        provenance.get(key) != static.get(key) for key in ("repo_id", "scan_job_id", "target_tree_hash")
    ):
        return {**common, "status": "unverified", "reason": "No isolated local-lab baseline is bound to this selected audit revision"}
    try:
        plan = request_plans.validate_plan(profile.get("request_plan") or {}, static)
        if (provenance.get("request_plan_hash") != plan["plan_hash"]
                or baseline.get("request_plan_hash") != plan["plan_hash"]):
            raise ValueError("Baseline does not match the saved request plan; capture a fresh baseline")
        paths = request_plans.get_request_paths(plan, static)
        if not paths:
            raise ValueError("No source-supported identity requests are selected")
        if owned_local is not None:
            if not owned_local.get("identity_bound") or owned_local.get("url") != base_url or owned_local.get("provider") not in {"k8s-service", "k8s-job"} or any(
                owned_local.get(key) != static.get(key) for key in ("repo_id", "scan_job_id", "target_tree_hash")
            ):
                raise ValueError("Owned local endpoint does not match the selected audit")
            observed = await _capture_http_signature(base_url, paths, trusted_local=True, local_binding=owned_local)
        else:
            observed = await _capture_http_signature(base_url, paths)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return {**common, "status": "error", "reason": str(exc)[:500]}
    result = _compare_signatures(static, baseline, observed)
    observed["request_plan_hash"] = plan["plan_hash"]
    result.update(status="match" if result["matched"] else "no-match" if result["contradictions"] else "inconclusive", observed=observed)
    return result
