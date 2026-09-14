"""High-severity-first scoring policy.

DoS/parser-hang leads are real but must not crowd out RCE, deserialization,
authn/authz bypass, and other CVSS≥7 classes. This module is applied after
Phase-1 collection (and in the recon benchmark) so every downstream consumer
sees the same priority.
"""
from __future__ import annotations

from typing import Any, Dict, List

from backend import ontology

# Classes that never graduate above this CVSS in recon (lab may still prove them).
_DOS_CAP = 5.3

# Floor for crown-jewel classes when a detector already scored them as a lead.
_HIGH_FLOOR = {
    "command_injection": 9.0,
    "code_injection": 8.8,
    "deserialization": 8.5,
    "authz_bypass": 8.1,
    "api_surface": 8.0,
    "sql_injection": 8.0,
    "ssti": 8.5,
    "path_traversal_write": 7.5,
}

_HIGH_SEV_TOOLS = frozenset({
    "fail-open-auth", "library-lab-poc", "insecure-default", "test-oracle-miner",
    "protocol-surface", "auth-structural-bypass", "document-library-surface",
    "db-file-sink", "stubbed-priv-check",
})


def apply_severity_policy(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Mutate-and-return findings: cap DoS, floor high-severity classes."""
    from backend.phase2 import is_inventory_summary

    out: List[Dict[str, Any]] = []
    for f in findings:
        item = dict(f)
        if is_inventory_summary(item):
            # Inventory has no vulnerability class. Classifying its descriptive
            # text would turn context back into a lead at the planning boundary.
            item["priority_class"] = "inventory"
            out.append(item)
            continue
        cls = ontology.classify_finding(item)
        cvss = float(item.get("cvss") or 0.0)
        if ontology.is_dos_only(cls) or cls == "denial_of_service":
            item["cvss"] = min(cvss, _DOS_CAP)
            item["priority_class"] = "deprioritized_dos"
            item.setdefault("qualification", "LATENT")
        elif cls in _HIGH_FLOOR and (
            cvss >= 7.0 or (item.get("tool") or "") in _HIGH_SEV_TOOLS
        ):
            # Do not promote low-signal greps (bare dlopen) into P0.
            item["cvss"] = max(cvss, _HIGH_FLOOR[cls])
            item["priority_class"] = "high_severity"
        else:
            item["priority_class"] = "normal"
        item["canonical_class"] = cls
        out.append(item)
    # High-severity first, then CVSS desc — Phase 2 budget hits the right leads.
    out.sort(key=lambda x: (
        0 if x.get("priority_class") == "high_severity" else
        2 if x.get("priority_class") == "deprioritized_dos" else 1,
        -float(x.get("cvss") or 0),
    ))
    return out
