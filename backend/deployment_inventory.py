"""Evidence-aware inventory/review summaries; never vulnerability severity."""
import hashlib
import json


def document(value):
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def array(value):
    try:
        parsed = json.loads(value or "[]")
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


def evidence_hash(target, fingerprint_hash):
    match = document(target.match_json)
    observed = match.get("observed") or {}
    return digest({"address": [target.kind, target.value, target.scheme, target.port, bool(target.enabled)],
                   "fingerprint_hash": fingerprint_hash, "status": target.status,
                   "observation": {key: match.get(key) for key in ("status", "confidence", "matches", "stale", "stale_reason")},
                   "requests": observed.get("requests"),
                   "local_binding": document(getattr(target, "local_binding_json", "{}"))})


def review_out(target, fingerprint_hash):
    review = document(getattr(target, "review_json", "{}"))
    current = evidence_hash(target, fingerprint_hash)
    state = review.get("status", "unreviewed")
    stale = state in {"confirmed", "rejected"} and review.get("evidence_hash") != current
    return {**review, "status": "needs-review" if stale else state,
            "previous_status": state if stale else review.get("previous_status"),
            "note": review.get("note", ""), "reviewer": review.get("reviewer", ""),
            "evidence_hash": current, "evidence_changed": stale or state == "needs-review",
            "revision": digest({"review": review, "evidence_hash": current}),
            "reviewer_identity": "operator-supplied label"}


def invalidate_review(target, reason):
    review = document(getattr(target, "review_json", "{}"))
    if review.get("status") in {"confirmed", "rejected"}:
        review.update(previous_status=review["status"], status="needs-review", invalidation_reason=reason)
        target.review_json = json.dumps(review)


def invalidate_target(target, reason):
    match = document(target.match_json)
    prior_observation = bool(target.last_checked_at or match)
    target.status = "stale" if prior_observation else "unverified"
    target.confidence, target.confidence_label = 0, "unavailable"
    if prior_observation:
        match.update(stale=True, stale_reason=reason)
        target.match_json = json.dumps(match)
    invalidate_review(target, reason)


def target_assessment(target, fingerprint_hash):
    review = review_out(target, fingerprint_hash)
    stale = target.status == "stale" or review["status"] == "needs-review"
    rejected = review["status"] == "rejected"
    return {"review": review, "machine_status": target.status,
            "machine_confidence": float(target.confidence or 0),
            "confidence": 0.0 if stale or rejected else float(target.confidence or 0),
            "confidence_label": "unavailable" if stale or rejected else target.confidence_label or "unavailable",
            "effective_status": "stale" if stale else "rejected" if rejected else target.status,
            "observation_mode": "owned-local-runtime" if document(getattr(target, "local_binding_json", "{}")) else "public"}


def summarize(targets=(), runs=(), fingerprint_hash=""):
    hosts = [row for row in targets if row.kind == "host"]
    categories = {key: [] for key in ("saved", "discovered", "enabled", "verified", "matched", "error", "stale", "unreviewed", "manual_confirmed", "rejected")}
    for target in hosts:
        assessment = target_assessment(target, fingerprint_hash)
        review = assessment["review"]["status"]
        state = assessment["effective_status"]
        flags = {"saved": True, "discovered": target.source == "recon" or bool(document(target.provenance_json).get("sources")),
                 "enabled": bool(target.enabled), "verified": bool(target.last_checked_at) and state not in {"stale", "error", "unverified"},
                 "matched": state == "match", "error": state == "error", "stale": state == "stale",
                 "unreviewed": review in {"unreviewed", "needs-review"}, "manual_confirmed": review == "confirmed", "rejected": review == "rejected"}
        for category, enabled in flags.items():
            if enabled:
                categories[category].append(target)
    discoveries = sorted((run for run in runs if run.operation == "discover"), key=lambda row: row.id, reverse=True)
    latest = discoveries[0] if discoveries else None
    results = document(latest.results_json) if latest else {}
    returned = {row.get("host") for row in (results.get("hosts") or []) if isinstance(row, dict) and isinstance(row.get("host"), str)}
    state = latest.status if latest else "never-run"
    if state == "completed" and not returned:
        state = "completed-empty"
    domains = sorted({target.value for target in targets if target.kind == "domain" and target.enabled})
    checked = [target.last_checked_at for target in hosts if target.last_checked_at]
    reviewed = [document(getattr(target, "review_json", "{}")).get("reviewed_at") for target in hosts]
    return {
        "unique_hosts": len({target.value for target in hosts}), "saved_endpoints": len(hosts),
        "counts": {key: len({row.value for row in values}) for key, values in categories.items()},
        "endpoint_counts": {key: len(values) for key, values in categories.items()},
        "aggregation": "Unique normalized hostnames; categories can overlap when one host has multiple endpoints.",
        "enabled_domains": domains, "saved_domains": len({target.value for target in targets if target.kind == "domain"}),
        "discovery": {"state": state, "requested": bool(latest), "attempts": len(discoveries),
                      "completed_attempts": sum(run.status == "completed" for run in discoveries),
                      "latest_run_id": latest.id if latest else None, "returned_hosts": len(returned),
                      "source_scope": array(latest.domains_json) if latest else [],
                      "sources": results.get("sources", []), "error": latest.error if latest else "",
                      "started_at": latest.started_at.isoformat() if latest and latest.started_at else None,
                      "finished_at": latest.finished_at.isoformat() if latest and latest.finished_at else None,
                      "requested_at": latest.created_at.isoformat() if latest and latest.created_at else None},
        "last_verified_at": max(checked).isoformat() if checked else None,
        "last_reviewed_at": max(value for value in reviewed if value) if any(reviewed) else None,
        "confidence_basis": "service-identity evidence heuristic; no vulnerability probability or source-revision proof",
        "findings_created": 0,
    }
