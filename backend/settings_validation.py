"""Validate active options stored in the legacy ``api_keys`` settings bag.

Integration credentials remain extensible, but options with runtime behavior
must have an explicit contract. In particular, a string ``"false"`` must never
become a truthy keep-lab flag and a typo must not turn auto decisions into a
five-minute wait.
"""
from __future__ import annotations

import json
from typing import Any


def phase2_approval_required(settings: Any) -> bool:
    """Honor the current control and previously saved legacy approval flags.

    Saving the canonical field reconciles the legacy value. Until then, a
    historic opt-in remains effective rather than bypassing manual approval.
    """
    get = settings.get if isinstance(settings, dict) else lambda name, default=None: getattr(settings, name, default)
    if get("phase2_approval_required") is True:
        return True
    legacy = get("api_keys", "{}")
    try:
        legacy = json.loads(legacy) if isinstance(legacy, str) else legacy
    except (ValueError, TypeError):
        return False
    value = legacy.get("phase2_approval_required", False) if isinstance(legacy, dict) else False
    return value is True or (isinstance(value, str) and value.lower() in {"true", "1", "yes"})


def validate_compatibility_options(options: dict[str, Any]) -> dict[str, Any]:
    result = dict(options)
    for name in ("keep_lab", "parallel_dependency_audits", "phase2_approval_required", "show_coverage_map",
                 "cli_security_testing_enabled", "runtime_fuzzing_enabled"):
        if name in result and type(result[name]) is not bool:
            raise ValueError(f"api_keys.{name} must be a JSON boolean")
    for name, allowed in (
        ("audit_decision_mode", {"auto", "ask"}),
        ("skills_mode", {"default", "custom"}),
    ):
        if name in result and (not isinstance(result[name], str) or result[name] not in allowed):
            raise ValueError(f"api_keys.{name} must be {' or '.join(sorted(allowed))}")
    if "custom_skills_path" in result:
        path = result["custom_skills_path"]
        if not isinstance(path, str) or len(path) > 512 or "\x00" in path:
            raise ValueError("api_keys.custom_skills_path must be a path of at most 512 characters")
        result["custom_skills_path"] = path.strip()
    if "max_dependency_audits" in result:
        count = result["max_dependency_audits"]
        # Older clients send this number as a string. Preserve that supported
        # input while excluding booleans, floats, and silent integer truncation.
        if isinstance(count, str) and count.isascii() and count.isdecimal():
            count = int(count)
        if type(count) is not int or not 1 <= count <= 8:
            raise ValueError("api_keys.max_dependency_audits must be an integer from 1 to 8")
        result["max_dependency_audits"] = count
    return result


def runtime_test_options(settings: dict[str, Any]) -> dict[str, bool]:
    """Read optional payload-test switches from the admitted audit settings.

    Missing or legacy truthy strings never opt an audit into expensive work.
    """
    raw = settings.get("api_keys") or {}
    try:
        options = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        options = {}
    if not isinstance(options, dict):
        options = {}
    return {name: options.get(name) is True for name in (
        "cli_security_testing_enabled", "runtime_fuzzing_enabled")}
