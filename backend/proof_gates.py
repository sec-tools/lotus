"""
Proof gates  - non-negotiable confirmation rules for Lotus findings.

Doctrine (PRD §6 / §24):
  A lead may be QUALIFIED. A vulnerability is only CONFIRMED / report-eligible
  after it passes every gate **including a working PoC proven in the local lab**.

QUALIFIED ≠ vulnerability. Static scanners and LLMs produce candidates only.
"""

from __future__ import annotations

import os
import math
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Tools that perform static analysis only (no dynamic execution).
# Findings from these tools can never constitute lab proof.
STATIC_ONLY_TOOLS = frozenset({
    "grep-pattern", "taint-proximity", "methodology-pattern", "secret-scan",
    "dependency-map", "config-audit", "attack-surface-map", "lockfile-audit",
    "bundle-audit", "brakeman", "osv-cve-check", "tainted-dependency",
    "dependency-audit", "cross-file-taint", "high-yield-discovery",
    "deserialization-chain", "auth-structural-bypass", "dynamic-dispatch",
    "sql-concat-audit", "by-design-gate", "doc-driven-hypothesis",
    "boundary-crossing-audit",
    "fail-open-auth", "plugin-dlopen", "protocol-surface",
    "document-library-surface", "db-file-sink", "high-severity-surface",
    "insecure-default", "test-oracle-miner", "test-coverage-gap",
    "control-plane-surface",
    "gateway-control-plane",
    "agent-app-control-plane",
    "trust-boundary-map", "handler-sink-trace", "component-lab-map",
    "path-containment",
})

def require_lab_proof() -> bool:
    """Return the legacy diagnostic toggle (publication always requires proof)."""
    return os.environ.get("LOTUS_REQUIRE_LAB_PROOF", "1").strip().lower() not in (
        "0", "false", "no", "off",
    )


def has_lab_proof(finding: Dict[str, Any]) -> bool:
    """Return true only for a signed, target-bound runner receipt.

    Previous versions treated a short snippet or a ``poc_result`` flag as proof.
    Those values are attacker/AI-controlled and are intentionally ignored now.
    The only authority is an attested receipt issued by the trusted lab runner.
    """
    # Hard block: static-only tools never have lab proof regardless of fields
    tool = (finding.get("tool") or "").lower()
    if tool in STATIC_ONLY_TOOLS:
        return False
    # Evidence scope is part of the trust boundary.  A signed receipt attached
    # to a fixture/analog or package-only test still cannot prove the deployed
    # target; reject it before any receipt cryptography is consulted.
    evidence_scope = str(finding.get("evidence_scope") or "").strip().lower()
    if evidence_scope in {
        "analog", "mirror", "package-harness", "unattested",
        "unattested-analog", "unattested-package-harness",
    }:
        return False

    receipts = finding.get("proof_receipts")
    if receipts is None:
        receipts = finding.get("proof_receipt")
    if isinstance(receipts, dict):
        receipts = [receipts]
    if not isinstance(receipts, list) or not receipts:
        return False
    try:
        from backend.proof_receipts import verify_receipt
        return any(verify_receipt(receipt, finding=finding) for receipt in receipts)
    except Exception:
        return False


def evaluate_validity_gates(
    finding: Dict[str, Any],
    *,
    cvss_threshold: float = 7.0,
) -> Dict[str, bool]:
    """Compute the validity gates; signed lab proof is always publication-required."""
    try:
        cvss = float(finding.get("cvss", 0.0) or 0.0)
    except (TypeError, ValueError, OverflowError):
        cvss = float("nan")
    desc = (finding.get("description") or "").lower()
    file_path = finding.get("file") or ""
    file_ext = Path(str(file_path)).suffix if file_path else ""
    valid_extensions = {
        ".py", ".rb", ".js", ".go", ".c", ".java", ".php", ".ts", ".jsx", ".tsx",
        ".cpp", ".cs", ".h", ".rs", ".kt", ".swift",
    }
    try:
        conviction = int(finding.get("conviction_level") or 0)
    except (TypeError, ValueError, OverflowError):
        conviction = 0

    existence = bool(finding.get("title") and (finding.get("description") or finding.get("file")))
    reachability = (
        conviction >= 1
        or finding.get("qualification") == "QUALIFIED"
        or bool(finding.get("data_flow"))
        or bool(file_path)
    )
    # TRIGGER is the key anti-FP gate.  A receipt is mandatory for every
    # publication path, including experimental runs that set the historical
    # ``LOTUS_REQUIRE_LAB_PROOF=0`` switch.  That switch may still be useful to
    # compare diagnostic conviction in a local experiment, but it must never
    # turn an un-attested observation into a report-eligible Finding.
    trigger = has_lab_proof(finding)
    if not require_lab_proof() and not trigger:
        finding.setdefault(
            "non_publication_experiment",
            "LOTUS_REQUIRE_LAB_PROOF=0 only relaxes diagnostic labeling; signed target-bound lab proof is still required for publication",
        )

    hallucination = (
        "fake" not in desc
        and (not file_path or file_ext in valid_extensions or file_ext == "")
        and 0.0 <= cvss <= 10.0
        and len(desc) >= 8
        and not any(w in desc for w in ("could potentially", "might be vulnerable", "appears to be"))
    )
    # Weak oracle gate: oracles that match trivially short/common strings are not proof
    # A verified receipt contains the class-specific oracle.  Raw evidence is
    # deliberately not inspected here because it is not an authority source.

    # --- Strengthened hallucination checks ---
    # FP-17: Config-gated sink (defaults to off) - report with caveat (Option A)
    config_gated_keywords = ("decode_php", "debug=true", "enable_unsafe", "allow_pickle",
                             "UNSAFE_", "disable_security", "skip_auth")
    if any(kw.lower() in desc for kw in config_gated_keywords):
        finding.setdefault("config_gated", True)
        # Still report as finding, but annotate with non-default config caveat
        finding.setdefault("config_caveat", (
            "This vulnerability requires a non-default configuration setting. "
            "Report includes this caveat. Verify whether the config is enabled "
            "in production deployments."
        ))
        # Do NOT filter out - config-gated findings are still reportable per policy

    # FP-18: Migration-only / setup-only code paths - second-pass deep evaluation
    # then mark informational if no additional exploitation path found (Option A)
    _migration_path_indicators = (
        "databasechange", "migration", "changeset", "liquibase",
        "flyway", "alembic", "setup_filter", "initialization_filter",
        "schema_migration", "db/migrate", "seeds.rb",
    )
    file_lower = str(file_path).lower()
    if any(ind in file_lower or ind in desc for ind in _migration_path_indicators):
        finding.setdefault("migration_only", True)
        # Second-pass evaluation: check for additional severity/impact or exploitation paths
        # before marking informational
        _escalation_indicators = (
            "user-controlled", "attacker-controlled", "external input",
            "http request", "api parameter", "query parameter",
            "web interface", "rest endpoint", "form input",
            "second-order", "stored value", "previously injected",
        )
        has_escalation_path = any(esc in desc for esc in _escalation_indicators)
        if has_escalation_path:
            # Second-pass found additional exploitation path - keep as full finding
            finding["migration_escalation"] = (
                "Migration code has potential external input path. "
                "Second-pass evaluation found escalation indicators. "
                "Treating as full finding, not informational."
            )
        else:
            # No external path found - mark informational but keep in report
            finding["severity_override"] = "informational"
            finding["migration_note"] = (
                "This finding is in migration/setup code that runs with app privileges "
                "but is not reachable from external user input during normal runtime. "
                "Marked informational after second-pass evaluation found no additional "
                "exploitation path."
            )

    # FP-19: Deprecated or private-only methods with no external callers
    if any(tag in desc for tag in ("@deprecated", "private method", "internal only", "unused")):
        finding.setdefault("deprecated_or_private", True)

    # Boilerplate / generic description detection (AI hallucination signal)
    _boilerplate_phrases = (
        "this could lead to", "an attacker could potentially",
        "may allow an attacker", "this is a security issue",
        "vulnerability was found", "the application is vulnerable",
    )
    if sum(1 for bp in _boilerplate_phrases if bp in desc) >= 2:
        hallucination = False

    cvss_ok = math.isfinite(cvss) and 0 <= cvss <= 10 and cvss >= cvss_threshold

    # --- DoS deprioritization ---
    _dos_only_keywords = ("denial of service", "dos ", "resource exhaustion",
                          "infinite loop", "stack overflow", "oom", "memory exhaustion",
                          "cpu exhaustion", "billion laughs", "xml bomb", "zip bomb",
                          "regex dos", "redos")
    is_dos_only = any(kw in desc for kw in _dos_only_keywords)
    if is_dos_only and not any(kw in desc for kw in (
        "rce", "remote code", "command injection", "code execution",
        "deserialization", "sql injection", "auth bypass",
    )):
        cvss_ok = False
        finding.setdefault("dos_only", True)

    qualification = finding.get("qualification") not in ("NO-BOUNDARY", "MIRROR-ONLY", "BY-DESIGN")

    # --- By-design capability handling ---
    # By-design features (sandbox exec, package manager install, CLI parsing) are
    # identified but STILL evaluated for:
    #   (a) Auth bypass - can capability be reached without valid credentials?
    #   (b) Sandbox escape - can execution break out of intended isolation?
    #   (c) Boundary crossing - does finding cross intended security boundary?
    # Only disqualify if none of these apply.
    _by_design_primitives = (
        "sandbox_capability", "by_design", "intended_behavior",
        "package_manager_trust_boundary",
    )
    is_by_design = (
        finding.get("by_design") is True
        or (finding.get("primitive_type") or "") in _by_design_primitives
    )

    if is_by_design:
        # Check for boundary-crossing indicators that OVERRIDE by-design status
        _boundary_crossing_keywords = (
            "auth bypass", "authentication bypass", "authorization bypass",
            "unauthenticated", "without credentials", "without auth",
            "without ticket", "without token", "missing auth",
            "sandbox escape", "container escape", "breakout",
            "privilege escalation", "privesc", "root access",
            "escape isolation", "bypass sandbox", "bypass isolation",
            "cross-tenant", "tenant isolation", "boundary crossing",
            "path traversal outside", "read outside sandbox",
            "write outside sandbox", "execute outside sandbox",
            "host filesystem", "host network", "host process",
        )
        crosses_boundary = any(kw in desc for kw in _boundary_crossing_keywords)
        if crosses_boundary:
            # Finding crosses security boundary even on by-design capability
            # This IS a vulnerability - do NOT disqualify
            finding["boundary_crossing"] = True
            finding["boundary_note"] = (
                "This finding involves a by-design capability but crosses a security "
                "boundary (auth bypass, sandbox escape, or privilege escalation). "
                "Treated as a real vulnerability despite by-design base capability."
            )
            # Keep qualification = True, override by_design
            finding.pop("by_design", None)
            if finding.get("qualification") == "BY-DESIGN":
                finding["qualification"] = "QUALIFIED"
                qualification = True
        else:
            # Pure by-design capability with no boundary crossing
            qualification = False
            finding["qualification"] = "BY-DESIGN"
            # Annotate with what SHOULD be tested on lab
            finding["by_design_lab_tests"] = [
                "Test auth bypass: can this capability be reached without valid credentials/ticket?",
                "Test sandbox escape: can execution break out of intended isolation boundary?",
                "Test privilege escalation: can lower-privilege user access higher-privilege capability?",
                "Test boundary crossing: can this be used to read/write/execute outside intended scope?",
            ]

    return {
        "existence": existence,
        "reachability": reachability,
        "trigger": trigger,  # lab PoC
        "hallucination": hallucination,
        "cvss": cvss_ok,
        "qualification": qualification,
        "lab_proof": has_lab_proof(finding),
        "dos_only": is_dos_only and not any(kw in desc for kw in ("rce", "remote code", "code execution")),
        "config_gated": finding.get("config_gated", False),
        "migration_only": finding.get("migration_only", False),
        "boundary_crossing": finding.get("boundary_crossing", False),
    }


def all_core_gates_pass(gates: Dict[str, bool]) -> bool:
    """Core gates excluding CVSS (CVSS only affects report vs below-threshold)."""
    return all(
        gates.get(k)
        for k in ("existence", "reachability", "trigger", "hallucination", "qualification", "lab_proof")
    )


def finalize_finding_status(
    finding: Dict[str, Any],
    *,
    cvss_threshold: float = 7.0,
) -> Dict[str, Any]:
    """
    Mutate finding with gates + honest status.

    Returns summary:
      status: report-eligible | below-threshold | unproven | candidate
      report_eligible: bool
      confirmed: bool  (True only if lab-proven + core gates)
    """
    gates = evaluate_validity_gates(finding, cvss_threshold=cvss_threshold)
    finding["gates"] = gates
    proven = has_lab_proof(finding)
    finding["proven_in_lab"] = proven

    # BY-DESIGN / product capabilities are never report-eligible, even with lab proof
    # UNLESS the finding crosses a security boundary (auth bypass, sandbox escape, etc.)
    is_pure_by_design = (
        (
            finding.get("qualification") == "BY-DESIGN"
            or (finding.get("primitive_type") or "") in (
                "sandbox_capability", "by_design", "intended_behavior",
                "package_manager_trust_boundary",
            )
        )
        and not finding.get("boundary_crossing")
    )
    if is_pure_by_design:
        finding["ai_verdict"] = "BY-DESIGN"
        finding["status"] = "unproven"
        finding["report_eligible"] = False
        return {
            "status": "unproven",
            "report_eligible": False,
            "confirmed": False,
            "gates": gates,
            "by_design_lab_tests": finding.get("by_design_lab_tests", []),
        }

    if all_core_gates_pass(gates):
        finding["ai_verdict"] = "CONFIRMED"
        try:
            conviction = int(finding.get("conviction_level") or 0)
        except (TypeError, ValueError, OverflowError):
            conviction = 0
        finding["conviction_level"] = max(conviction, 3)
        # Signature verification establishes provenance. It does not make
        # the oracle's interpretation or impact assessment infallible.
        # Preserve model confidence separately from receipt verification.
        if finding.get("confidence") and finding.get("confidence") != "verified":
            finding.setdefault("ai_confidence", finding.get("confidence"))
        finding["confidence"] = "verified"
        finding["proof_confidence"] = "attested"
        finding["oracle_assessment"] = "requires_review"
        if gates["cvss"]:
            finding["status"] = "report-eligible"
            finding["report_eligible"] = True
        else:
            finding["status"] = "below-threshold"
            finding["report_eligible"] = False
        return {
            "status": finding["status"],
            "report_eligible": finding["report_eligible"],
            "confirmed": True,
            "gates": gates,
        }

    # AI/static may mark as interesting candidate  - never report-eligible without lab
    finding["report_eligible"] = False
    if finding.get("qualification") == "QUALIFIED" or finding.get("ai_verdict") in ("REAL", "CANDIDATE", "CONFIRMED"):
        # Downgrade false CONFIRMED from AI
        if finding.get("ai_verdict") == "CONFIRMED" and not proven:
            finding["ai_verdict"] = "CANDIDATE"
            finding["ai_analysis"] = (
                (finding.get("ai_analysis") or "")
                + " | Downgraded: QUALIFIED/AI-REAL is not a vulnerability until lab PoC proves trigger."
            ).strip(" |")
        finding["status"] = "unproven"
    else:
        finding["status"] = "unproven"
        if not finding.get("ai_verdict"):
            finding["ai_verdict"] = "UNCONFIRMED"

    return {
        "status": finding["status"],
        "report_eligible": False,
        "confirmed": False,
        "gates": gates,
    }


def filter_confirmed_vulnerabilities(
    findings: List[Dict[str, Any]],
    *,
    cvss_threshold: float = 7.0,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Split findings into (lab-proven confirmed, candidates-only).

    Only the first list may be report-eligible / write skills / count as confirmed.
    """
    confirmed: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    for f in findings:
        summary = finalize_finding_status(f, cvss_threshold=cvss_threshold)
        if summary["confirmed"]:
            confirmed.append(f)
        else:
            candidates.append(f)
    return confirmed, candidates


def annotate_ai_real_without_proof(finding: Dict[str, Any]) -> None:
    """AI said REAL but no lab PoC  - keep as candidate, never confirm."""
    if has_lab_proof(finding):
        finding["ai_verdict"] = "CONFIRMED"
        return
    finding["ai_verdict"] = "CANDIDATE"
    note = (
        "AI/static analysis marked interesting; awaiting lab PoC proof "
        "(existence/reachability/trigger/hallucination/qualification + dynamic PoC)."
    )
    prev = (finding.get("ai_analysis") or "").replace("Verdict: REAL", "Verdict: CANDIDATE (unproven)")
    if "awaiting lab PoC" not in prev:
        finding["ai_analysis"] = f"{prev} | {note}".strip(" |")
    else:
        finding["ai_analysis"] = prev
    finding["report_eligible"] = False
    finding["status"] = "unproven"
    finding["awaiting_lab_poc"] = True
