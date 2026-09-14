"""Saved-model verification and explicit AI admission requirements.

Readiness receipts bind the exact provider, model, endpoint and credential.
They attest a successful model call, never repository or vulnerability proof.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import sys
from types import SimpleNamespace

from backend.ai_gateway import DEFAULT_BASE_URLS, LOCAL_PROVIDERS


class AIReadinessError(RuntimeError):
    def __init__(self, readiness):
        self.readiness = readiness
        super().__init__(readiness["reason"])


class AIRequiredError(RuntimeError):
    """A required AI response was unavailable or could not be interpreted."""

    def __init__(self, message, *, response=None):
        super().__init__(message)
        self.ai_response = response


def role_settings(settings, role="primary"):
    if role not in {"primary", "judge"}:
        raise ValueError("Unknown AI role")
    prefix = "ai_" if role == "primary" else "ai_judge_"
    provider = str(getattr(settings, prefix + "provider", "") or "").strip()
    # An empty saved selection is unfinished configuration. Inferring a
    # default here could verify and charge for a model the user never chose.
    model = str(getattr(settings, prefix + "model", "") or "").strip()
    return SimpleNamespace(ai_provider=provider, ai_model=model,
        ai_api_key=str(getattr(settings, prefix + "api_key", "") or ""),
        ai_base_url=str(getattr(settings, prefix + "base_url", "") or DEFAULT_BASE_URLS.get(provider, "")).rstrip("/"),
        _lotus_ai_role=role)


def fingerprint(settings, role="primary"):
    selected = role_settings(settings, role)
    fields = [selected.ai_provider, selected.ai_model, selected.ai_api_key, selected.ai_base_url]
    return hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest()


def receipts(settings):
    try:
        value = json.loads(getattr(settings, "ai_verification_json", "") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def readiness(settings, role="primary"):
    if role not in {"primary", "judge"}:
        raise ValueError("Unknown AI role")
    requested_role = role
    saved = receipts(settings)
    roles = {}
    for role in ("primary", "judge"):
        config = role_settings(settings, role)
        configured = bool(config.ai_provider and config.ai_provider != "none" and config.ai_model
                          and (config.ai_provider in LOCAL_PROVIDERS or config.ai_api_key))
        receipt = saved.get(role) if isinstance(saved.get(role), dict) else {}
        matches = receipt.get("configuration") == fingerprint(settings, role)
        verified = bool(configured and matches and receipt.get("status") == "verified"
                        and receipt.get("tested_at") and receipt.get("response_sha256"))
        reason = ("Configured model passed a completion test" if verified else
                  "Configure a provider and model in Settings" if not configured else
                  receipt.get("reason") if matches and receipt.get("reason") else
                  "Save and test this model in Settings before starting an audit")
        roles[role] = {"configured": configured, "verified": verified,
            "provider": config.ai_provider or "none", "model": config.ai_model,
            "tested_at": receipt.get("tested_at") if matches else None, "reason": str(reason)}
    enabled = bool(getattr(settings, "ai_judge_enabled", False))
    distinct = ((roles["primary"]["provider"], roles["primary"]["model"])
                != (roles["judge"]["provider"], roles["judge"]["model"]))
    roles["judge"].update(enabled=enabled, independent=distinct and roles["judge"]["configured"])
    # Ordinary audit admission depends only on its primary model. The optional
    # second model is admitted independently when findings/scoring need review.
    if requested_role == "primary":
        ready = roles["primary"]["verified"]
        reason = "Primary model is verified and ready" if ready else roles["primary"]["reason"]
    else:
        ready = enabled and roles["judge"]["verified"] and distinct
        reason = ("Secondary model is verified for findings and scoring review" if ready else
                  "Secondary findings review is disabled" if not enabled else
                  "Choose a different provider or model for the independent evaluator" if not distinct else
                  "Independent evaluator: " + roles["judge"]["reason"])
    platform = sys.modules.get("backend.main")
    restart_event = getattr(platform, "_PLATFORM_RESTART_REQUIRED", None)
    restart_required = bool(restart_event and restart_event.is_set())
    if restart_required:
        ready = False
        reason = "Database restored. Restart Lotus before starting work."
    return {"ready": bool(ready), "reason": reason, "restart_required": restart_required, **roles}


def require_ready(settings, role="primary"):
    state = readiness(settings, role=role)
    if not state["ready"]:
        raise AIReadinessError(state)
    return state


def record_verification(settings, role, result):
    from backend.ai_gateway import AIStatus
    stored = receipts(settings)
    valid = (result.status == AIStatus.OK and str(result.text or "").strip() == "OK"
             and not (result.meta or {}).get("mock") and not (result.meta or {}).get("simulated"))
    status = str(getattr(result.status, "value", result.status))
    reason = ("Configured model passed a completion test" if valid else
              f"Model verification failed ({status}); check credentials, selected model and endpoint, then test again")
    stored[role] = {"configuration": fingerprint(settings, role),
        "status": "verified" if valid else "failed", "tested_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason, "response_sha256": hashlib.sha256(str(result.text or "").encode()).hexdigest() if valid else ""}
    settings.ai_verification_json = json.dumps(stored, sort_keys=True)
    return valid


def invalidate(settings, role, *, expected_configuration=None, expected_tested_at=None, reason=""):
    stored = receipts(settings)
    previous = stored.get(role) if isinstance(stored.get(role), dict) else {}
    if expected_configuration and fingerprint(settings, role) != expected_configuration:
        return False
    if expected_tested_at and previous.get("tested_at") != expected_tested_at:
        return False
    stored[role] = {"configuration": fingerprint(settings, role), "status": "failed",
        "tested_at": previous.get("tested_at"), "response_sha256": "",
        "reason": reason or "The configured model failed during an audit. Check Settings and test it again."}
    settings.ai_verification_json = json.dumps(stored, sort_keys=True)
    return True
