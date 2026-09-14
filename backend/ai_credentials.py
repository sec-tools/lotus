"""Recognize only strong credential prefixes before routing cloud requests.

Unknown formats remain usable with an explicitly selected provider. Detection
is a routing guard, never an authentication or readiness claim.
"""
from __future__ import annotations


def known_key_provider(key: str) -> str:
    value = str(key or "").strip()
    if value.startswith("sk-ant"):
        return "anthropic"
    if value.startswith("sk-or-"):
        return "openrouter"
    if value.startswith("sk-"):
        return "openai"
    if value.lower().startswith(("dv-", "devin-", "apk_user_")):
        return "devin"
    return ""


def key_provider_mismatch(provider: str, key: str) -> bool:
    detected = known_key_provider(key)
    return bool(detected and detected != provider)
