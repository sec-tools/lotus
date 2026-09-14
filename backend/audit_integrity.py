"""Validate the durable evidence bundle emitted by an audit.

This is deliberately a conservative completeness check, not a vulnerability
classifier.  It makes degraded labs, missing ledgers, analogue PoCs, and
unsigned observations visible to operators instead of allowing a headline
count to imply end-to-end proof.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional


REQUIRED_ARTIFACTS = (
    "audit_plan.json",
    "phase1_trace.json",
    "trust_boundary.json",
    "component_map.json",
    "lab_poc_results.json",
)


def _git_value(dest: Path, *args: str) -> str:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(dest), *args],
            stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
        return out.strip()
    except Exception:
        return ""


def _verified_replay_binding(dest: Path, snapshot: Dict[str, Any], *, expected_content: str,
                             expected_revision: str, actual_content: str) -> Dict[str, Any]:
    """Verify controller-supplied captured source when a replay has no Git objects.

    A plan path alone is not authority for this fallback. The caller supplies
    the durable snapshot reference, and its exact manifest, bytes, modes and
    aliases must still agree. Git identities remain recorded rather than
    being fabricated as observations of the disposable checkout.
    """
    from backend.target_snapshots import load_snapshot, source_selection_metadata, validate_source_metadata
    from backend.proof_receipts import source_content_files
    if (not isinstance(snapshot, dict)
            or not all(re.fullmatch(r"sha256:[a-f0-9]{64}", str(snapshot.get(key) or ""))
                       for key in ("tree_hash", "manifest_hash"))
            or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", expected_revision)
            or not expected_content or snapshot["tree_hash"] != expected_content
            or actual_content != expected_content):
        raise ValueError("replay requires an exact captured manifest and matching source content")
    verified = load_snapshot(str(snapshot.get("path") or ""))
    if (any(verified.get(key) != snapshot.get(key) for key in ("tree_hash", "manifest_hash"))
            or not verified.get("source_inventory") or not verified.get("source_metadata")):
        raise ValueError("replay snapshot manifest or source metadata is not bound")
    if snapshot.get("source_path") and Path(snapshot["source_path"]).resolve() != Path(verified["source_path"]):
        raise ValueError("replay snapshot source path differs from its manifest")
    recorded_revision = str(verified.get("target_revision") or "")
    if recorded_revision != expected_revision:
        raise ValueError("replay snapshot recorded revision differs from the audit plan")
    captured = validate_source_metadata(Path(verified["source_path"]), verified)
    observed = source_selection_metadata(dest.resolve(), source_content_files(dest))
    if (observed["aliases"] != captured["aliases"]
            or {name: mode & 0o111 for name, mode in observed["files"].items()}
            != {name: mode & 0o111 for name, mode in captured["files"].items()}):
        raise ValueError("replay source file selection, executable modes or aliases changed")
    return {"manifest_hash": verified["manifest_hash"], "tree_hash": verified["tree_hash"],
            "recorded_revision": recorded_revision or None,
            "git_objects_available": False,
            "note": "Captured source bytes, file selection, executable modes and aliases verified; original Git objects are absent from this replay checkout."}


def assess_audit_artifacts(dest: Path, lab_status: Optional[Dict[str, Any]] = None, *,
                           target_snapshot: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return a JSON-safe integrity/completeness assessment for ``dest/.lotus``."""
    dest = Path(dest)
    out_dir = dest / ".lotus"
    missing = [name for name in REQUIRED_ARTIFACTS if not (out_dir / name).is_file()]
    poc_rows = []
    parse_errors = []
    embedded_lab_status: Optional[Dict[str, Any]] = None
    runtime_smoke: Optional[Dict[str, Any]] = None
    audit_plan: Dict[str, Any] = {}
    plan_path = out_dir / "audit_plan.json"
    if plan_path.is_file():
        try:
            parsed_plan = json.loads(plan_path.read_text(encoding="utf-8"))
            if not isinstance(parsed_plan, dict):
                raise ValueError("audit plan must be a JSON object")
            audit_plan = parsed_plan
        except Exception as exc:
            parse_errors.append(f"audit_plan.json: {exc}")
    for name in REQUIRED_ARTIFACTS:
        if name in {"audit_plan.json", "lab_poc_results.json"}:
            continue
        artifact_path = out_dir / name
        if artifact_path.is_file():
            try:
                value = json.loads(artifact_path.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise ValueError("artifact must be a JSON object")
            except Exception as exc:
                parse_errors.append(f"{name}: {exc}")
    poc_path = out_dir / "lab_poc_results.json"
    if poc_path.is_file():
        try:
            raw = json.loads(poc_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("artifact must be a JSON object")
            for key in ("proven", "candidates"):
                if key in raw and not isinstance(raw[key], list):
                    raise ValueError(f"{key} must be a JSON array")
            poc_rows = list(raw.get("proven") or []) + list(raw.get("candidates") or [])
            if isinstance(raw.get("lab_status"), dict):
                embedded_lab_status = raw.get("lab_status")
        except Exception as exc:
            parse_errors.append(f"lab_poc_results.json: {exc}")
    smoke_path = out_dir / "lab_smoke.json"
    if smoke_path.is_file():
        try:
            parsed_smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
            if isinstance(parsed_smoke, dict):
                runtime_smoke = parsed_smoke
            else:
                parse_errors.append("lab_smoke.json: artifact must be a JSON object")
        except Exception as exc:
            parse_errors.append(f"lab_smoke.json: {exc}")

    unsigned = []
    unbound = []
    for row in poc_rows:
        if not isinstance(row, dict):
            parse_errors.append("lab_poc_results contains a non-object row")
            continue
        rid = row.get("id") or row.get("title") or "unknown"
        scope = str(row.get("evidence_scope") or "unknown").lower()
        if scope in {"analog", "mirror", "package-harness", "unattested", "unattested-analog", "unattested-package-harness"}:
            unbound.append(str(rid))
        if row.get("proven_in_lab") or row in (raw.get("proven") or []):
            from backend.proof_gates import has_lab_proof
            if not has_lab_proof(row):
                unsigned.append(str(rid))
            else:
                from backend.proof_receipts import verify_receipt
                receipts = row.get("proof_receipts") or row.get("proof_receipt") or []
                if isinstance(receipts, dict):
                    receipts = [receipts]
                expected = str(audit_plan.get("target_tree_hash") or "")
                if expected and not any(
                    isinstance(receipt, dict) and verify_receipt(receipt, finding=row)
                    and (receipt.get("target") or {}).get("tree_hash") == expected
                    for receipt in receipts
                ):
                    unbound.append(str(rid))

    effective_lab_status = lab_status if isinstance(lab_status, dict) else embedded_lab_status
    healthy = bool(
        isinstance(effective_lab_status, dict)
        and effective_lab_status.get("healthy") is True
        and str(effective_lab_status.get("status") or "").strip().lower()
        not in {"run-failed", "failed", "error", "unavailable", "disabled"}
    )
    reasons = []
    if missing:
        reasons.append("missing required artifacts: " + ", ".join(missing))
    if parse_errors:
        reasons.extend(parse_errors)
    if not healthy:
        reasons.append("application lab is not healthy/usable")
    # A TCP listener (especially the fallback python http.server) is not proof
    # that a library/CLI or application actually loaded.  Every generated plan
    # has a smoke command; require its durable result before calling the bundle
    # complete.  This catches the exact failure mode where a library audit was
    # marked healthy solely because port 3010 answered.
    if audit_plan.get("smoke_test"):
        if runtime_smoke is None:
            reasons.append("missing runtime smoke artifact (target load/build was not recorded)")
        elif not runtime_smoke.get("ran") or not runtime_smoke.get("ok"):
            reasons.append("runtime smoke did not pass (target load/build is unproven)")
    if unsigned:
        reasons.append("lab rows claim proof without a valid signed target-bound receipt: " + ", ".join(unsigned[:20]))
    if unbound:
        reasons.append("non-target evidence is present: " + ", ".join(unbound[:20]))

    revision = _git_value(dest, "rev-parse", "HEAD")
    tree = _git_value(dest, "rev-parse", "HEAD^{tree}")
    expected_revision = str(audit_plan.get("target_revision") or "").strip()
    expected_tree = str(audit_plan.get("target_tree") or "").strip()
    expected_content = str(audit_plan.get("target_tree_hash") or "").strip()
    target_match = True
    actual_content = ""
    if expected_content:
        try:
            from backend.proof_receipts import content_tree_digest
            actual_content = content_tree_digest(dest)
        except Exception:
            actual_content = ""
        if not actual_content or expected_content != actual_content:
            target_match = False
            reasons.append(
                "target content mismatch: "
                f"plan={expected_content} actual={actual_content or '<unavailable>'}"
            )
    replay_binding = None
    if not revision and not tree and (expected_revision or expected_tree) and target_snapshot is not None:
        try:
            replay_binding = _verified_replay_binding(dest, target_snapshot,
                expected_content=expected_content, expected_revision=expected_revision, actual_content=actual_content)
        except Exception as exc:
            target_match = False
            reasons.append("captured replay source binding failed: " + str(exc)[:500])
    if expected_revision and expected_revision != revision and replay_binding is None:
        target_match = False
        reasons.append(f"target revision mismatch: plan={expected_revision} actual={revision or '<unavailable>'}")
    if expected_tree and expected_tree != tree and replay_binding is None:
        target_match = False
        reasons.append(f"target tree mismatch: plan={expected_tree} actual={tree or '<unavailable>'}")
    status = "complete" if not reasons else "degraded"
    result = {
        "schema_version": 1,
        "status": status,
        "complete": status == "complete",
        "target": {
            "revision": revision,
            "tree": tree,
            "expected_revision": expected_revision or None,
            "expected_tree": expected_tree or None,
            "expected_content": expected_content or None,
            "match": target_match,
            "verification_basis": "verified_captured_source" if replay_binding else "checkout_identity",
            "captured_source": replay_binding,
        },
        "lab": {"healthy": healthy, "status": (effective_lab_status or {}).get("status") if isinstance(effective_lab_status, dict) else None},
        "required_artifacts": {name: name not in missing for name in REQUIRED_ARTIFACTS},
        "poc_rows": len(poc_rows),
        "unsigned_proven_rows": unsigned,
        "non_target_rows": unbound,
        "runtime_smoke": runtime_smoke or {"ran": False, "ok": False},
        "reasons": reasons,
    }
    if poc_path.is_file():
        result["poc_artifact_sha256"] = hashlib.sha256(poc_path.read_bytes()).hexdigest()
    return result


def write_audit_integrity(dest: Path, lab_status: Optional[Dict[str, Any]] = None, *,
                          target_snapshot: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    result = assess_audit_artifacts(dest, lab_status, target_snapshot=target_snapshot)
    out_dir = Path(dest) / ".lotus"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "audit_integrity.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
