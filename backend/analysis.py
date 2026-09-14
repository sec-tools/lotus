"""
Advanced analysis module for Lotus BDAAS.

Implements:
1. Lead Lifecycle: Phase 1 produces leads (hypotheses), not findings
2. Reproduction Strategies: Each lead gets a concrete test plan
3. Proof-Based Validation: Leads are tested against the lab
4. Parallel Domain Agents: Specialized AI analysis by vulnerability class
5. OWASP Coverage Matrix: Track coverage per endpoint/category

This module is called by pipeline.py during Phase 2.
"""

import json
import re
from typing import List, Dict, Optional, Any
from pathlib import Path


# ---------------------------------------------------------------------------
# OWASP Top 10 Categories (2021)
# ---------------------------------------------------------------------------

OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Auth Failures",
    "A08": "Software/Data Integrity",
    "A09": "Logging/Monitoring Failures",
    "A10": "SSRF",
}

# Map tool findings to OWASP categories
FINDING_TO_OWASP = {
    "command injection": "A03",
    "code injection": "A03",
    "SQL injection": "A03",
    "XSS": "A03",
    "path traversal": "A03",
    "template injection": "A03",
    "SSTI": "A03",
    "deserialization": "A08",
    "buffer overflow": "A03",
    "format string": "A03",
    "auth bypass": "A01",
    "access control": "A01",
    "IDOR": "A01",
    "privilege": "A01",
    "admin": "A01",
    "secret": "A02",
    "crypto": "A02",
    "hardcoded": "A02",
    "weak random": "A02",
    "debug": "A05",
    "CORS": "A05",
    "SSL": "A05",
    "config": "A05",
    "dependency": "A06",
    "vulnerable": "A06",
    "SSRF": "A10",
}


# ---------------------------------------------------------------------------
# Domain-specific agent prompts
# ---------------------------------------------------------------------------

AGENT_DOMAINS = {
    "injection": {
        "name": "Injection Analysis",
        "owasp": ["A03"],
        "description": "Analyze for command injection, SQL injection, XSS, SSTI, path traversal",
        "focus": "Trace user input to exec/eval/query/render sinks. Check for sanitization at each hop.",
    },
    "access_control": {
        "name": "Access Control Analysis",
        "owasp": ["A01"],
        "description": "Analyze for auth bypass, IDOR, privilege escalation, missing auth checks",
        "focus": "Check every endpoint for auth decorators/middleware. Look for direct object references without ownership check.",
    },
    "crypto_secrets": {
        "name": "Cryptography & Secrets",
        "owasp": ["A02"],
        "description": "Analyze for weak crypto, hardcoded secrets, predictable tokens",
        "focus": "Check random sources, key storage, algorithm choices, token generation.",
    },
    "config_infra": {
        "name": "Configuration & Infrastructure",
        "owasp": ["A05", "A06"],
        "description": "Analyze for misconfigurations, vulnerable dependencies, debug mode",
        "focus": "Check default configs, enabled debug features, outdated dependencies with known CVEs.",
    },
}


def classify_lead_domain(lead: Dict) -> str:
    """Classify a lead into a domain for specialized agent analysis."""
    title_lower = (lead.get("title", "") + " " + lead.get("description", "")).lower()
    for keyword, owasp in FINDING_TO_OWASP.items():
        if keyword.lower() in title_lower:
            for domain_id, domain in AGENT_DOMAINS.items():
                if owasp in domain["owasp"]:
                    return domain_id
    return "injection"  # default domain


# ---------------------------------------------------------------------------
# Lead Lifecycle
# ---------------------------------------------------------------------------

def classify_primitive_type(lead: Dict) -> str:
    """Classify a lead into an R/W/X primitive matrix ID (X-1..X-20, W-1..W-21, R-1..R-11)."""
    t = (lead.get("title", "") + " " + lead.get("description", "")).lower()
    if "command" in t or "exec" in t or "system" in t:
        return "X-1"  # OS command injection
    if "ssti" in t or "template" in t:
        return "X-3"  # SSTI
    if "eval" in t or "dynamic" in t:
        return "X-4"  # eval/exec
    if "deserializ" in t:
        return "X-5"  # Deserialization
    if "write" in t or "upload" in t:
        return "W-1"  # Arbitrary file write
    if "travers" in t and ("write" in t or "save" in t):
        return "W-3"  # Path traversal write
    if "proto" in t or "pollution" in t:
        return "W-9"  # Prototype pollution
    if "travers" in t or "read" in t:
        return "R-3"  # Path traversal read
    if "sql" in t:
        return "R-2"  # SQL injection
    if "ssrf" in t:
        return "R-4"  # SSRF
    return "X-13"  # General callback/control primitive


def promote_to_leads(raw_findings: List[Dict]) -> List[Dict]:
    """Convert raw Phase 1 tool output into structured leads with metadata.

    A lead is a hypothesis - an unproven suspicion that a vulnerability exists.
    It carries enough context for Phase 2 to attempt reproduction.
    """
    leads = []
    for f in raw_findings:
        lead = {
            **f,
            "lifecycle": "lead",  # lead -> testing -> confirmed/rejected
            "domain": classify_lead_domain(f),
            "primitive_type": f.get("primitive_type") or classify_primitive_type(f),
            "owasp_category": _map_owasp(f),
            "reproduction_strategy": _build_reproduction_strategy(f),
            "conviction_level": f.get("conviction_level", 0),  # 0=hypothesis, 1=reachable, 2=triggerable, 3=impactful
        }
        leads.append(lead)
    return leads


def _map_owasp(finding: Dict) -> str:
    """Map a finding to its OWASP Top 10 category."""
    title = (finding.get("title", "") + " " + finding.get("description", "")).lower()
    for keyword, cat in FINDING_TO_OWASP.items():
        if keyword.lower() in title:
            return cat
    return "A04"  # Insecure Design (catch-all)


def _build_reproduction_strategy(finding: Dict) -> Dict:
    """Generate a concrete reproduction strategy for a lead.

    This tells Phase 2 exactly what to test against the lab.
    """
    tool = finding.get("tool", "")
    title = finding.get("title", "").lower()
    file_path = finding.get("file", "")
    line = finding.get("line", 0)

    strategy = {
        "type": "static_verification",  # default
        "steps": [],
        "payloads": [],
        "expected_behavior": "",
    }

    if "command injection" in title or "os.system" in title or "exec" in title:
        strategy["type"] = "injection_test"
        strategy["steps"] = [
            f"Read {file_path}:{line} to identify the injection sink",
            "Trace backward to find the input source (HTTP param, CLI arg, env var)",
            "Craft payload: `; id` or `$(id)` or `| id`",
            "Send via the identified input vector to the lab",
            "Check response/logs for command execution evidence",
        ]
        strategy["payloads"] = ["; id", "$(id)", "| id", "`id`"]
        strategy["expected_behavior"] = "uid= output in response or logs"

    elif "sql injection" in title:
        strategy["type"] = "injection_test"
        strategy["steps"] = [
            f"Read {file_path}:{line} to identify the SQL construction",
            "Identify the parameter that reaches the query",
            "Send `' OR '1'='1` via that parameter",
            "Check for authentication bypass or data leakage",
        ]
        strategy["payloads"] = ["' OR '1'='1", "' UNION SELECT 1--", "1; DROP TABLE--"]
        strategy["expected_behavior"] = "SQL error, extra data returned, or auth bypass"

    elif "xss" in title or "unescaped" in title:
        strategy["type"] = "injection_test"
        strategy["steps"] = [
            f"Read {file_path}:{line} to identify the output context",
            "Send `<script>alert(1)</script>` via input vector",
            "Check if payload appears unescaped in response",
        ]
        strategy["payloads"] = ["<script>alert(1)</script>", "<img onerror=alert(1) src=x>"]
        strategy["expected_behavior"] = "Payload reflected without encoding in HTML response"

    elif "path traversal" in title or "file" in title:
        strategy["type"] = "traversal_test"
        strategy["steps"] = [
            f"Read {file_path}:{line} to identify the file operation",
            "Send `../../../etc/passwd` as the path parameter",
            "Check if file contents are returned",
        ]
        strategy["payloads"] = ["../../../etc/passwd", "....//....//etc/passwd", "/etc/passwd"]
        strategy["expected_behavior"] = "Contents of /etc/passwd in response"

    elif "secret" in title or "hardcoded" in title or "key" in title:
        strategy["type"] = "secret_verification"
        strategy["steps"] = [
            f"Read {file_path}:{line} to extract the secret value",
            "Determine if the secret is a real credential or a placeholder",
            "Check if it matches a known token format (AWS, GitHub, etc.)",
            "Test if the credential is still active (if safe to do so)",
        ]
        strategy["expected_behavior"] = "Real, active credential with access to resources"

    elif "config" in title or "debug" in title or "cors" in title:
        strategy["type"] = "config_verification"
        strategy["steps"] = [
            f"Read {file_path}:{line} to confirm the misconfiguration",
            "Determine if this is the production/default configuration",
            "Check if the misconfiguration is exploitable",
        ]
        strategy["expected_behavior"] = "Misconfiguration confirmed in default deployment"

    else:
        strategy["steps"] = [
            f"Read {file_path}:{line} to understand the code pattern",
            "Determine if the pattern is exploitable from external input",
            "Craft a test to demonstrate the impact",
        ]
        strategy["expected_behavior"] = "Security boundary violated"

    return strategy


# ---------------------------------------------------------------------------
# OWASP Coverage Matrix
# ---------------------------------------------------------------------------

def build_coverage_matrix(leads: List[Dict], routes: List[str]) -> Dict:
    """Build an OWASP Top 10 coverage matrix showing which categories
    have been tested for which routes/surfaces.
    """
    matrix = {}
    for route in routes[:50]:  # cap at 50 routes
        matrix[route] = {}
        for cat_id in OWASP_CATEGORIES:
            # Check if any lead covers this route + category
            covered = any(
                l.get("owasp_category") == cat_id and
                (route in l.get("file", "") or route in l.get("description", ""))
                for l in leads
            )
            matrix[route][cat_id] = "covered" if covered else "not_tested"
    return matrix


def compute_coverage_stats(leads: List[Dict]) -> Dict:
    """Compute overall OWASP coverage statistics."""
    category_counts = {cat: 0 for cat in OWASP_CATEGORIES}
    for lead in leads:
        cat = lead.get("owasp_category", "A04")
        if cat in category_counts:
            category_counts[cat] += 1

    total_leads = len(leads)
    covered_categories = sum(1 for c in category_counts.values() if c > 0)
    return {
        "total_leads": total_leads,
        "categories_covered": covered_categories,
        "categories_total": len(OWASP_CATEGORIES),
        "coverage_pct": round((covered_categories / len(OWASP_CATEGORIES)) * 100, 1),
        "per_category": {
            cat_id: {"name": OWASP_CATEGORIES[cat_id], "leads": count}
            for cat_id, count in category_counts.items()
        },
    }


# ---------------------------------------------------------------------------
# Parallel Domain Agent Prompts
# ---------------------------------------------------------------------------

def build_domain_prompt(domain_id: str, leads: List[Dict], language: str, skills_context: str = "") -> str:
    """Build a focused prompt for a domain-specific analysis agent.

    Each domain agent is an expert in its area and analyzes only
    leads relevant to its domain.
    """
    domain = AGENT_DOMAINS.get(domain_id, AGENT_DOMAINS["injection"])

    leads_text = ""
    for idx, lead in enumerate(leads, 1):
        strategy = lead.get("reproduction_strategy", {})
        leads_text += (
            f"\n--- Lead {idx} ---\n"
            f"Title: {lead['title']}\n"
            f"Tool: {lead.get('tool', 'unknown')}\n"
            f"CVSS: {lead.get('cvss', 0)}\n"
            f"File: {lead.get('file', 'N/A')}:{lead.get('line', 0)}\n"
            f"Description: {lead.get('description', '')}\n"
            f"Reproduction type: {strategy.get('type', 'unknown')}\n"
            f"Steps: {' -> '.join(strategy.get('steps', []))}\n"
            f"Payloads: {', '.join(strategy.get('payloads', []))}\n"
            f"Expected: {strategy.get('expected_behavior', '')}\n"
        )

    skills_section = ""
    if skills_context:
        # Try domain-specific search
        try:
            from backend.skills import hybrid_search_skills, merge_skills_context
            domain_skills = hybrid_search_skills(f"{domain_id} vulnerability {language}", language=language, top_k=5)
            if domain_skills:
                skills_context = merge_skills_context("", domain_skills, budget=4000)
        except Exception:
            pass
        skills_section = f"\n--- METHODOLOGY CONTEXT ---\n{skills_context[:4000]}\n--- END CONTEXT ---\n\n"

    return (
        f"You are a senior security researcher specializing in {domain['name']}.\n"
        f"Target: {language} application\n"
        f"Domain: {domain['description']}\n"
        f"Focus: {domain['focus']}\n\n"
        f"{skills_section}"
        f"Below are {len(leads)} leads (unproven hypotheses) from static analysis.\n"
        f"Your job is to determine which are REAL vulnerabilities vs FALSE POSITIVES.\n\n"
        f"CRITICAL RULES:\n"
        f"- A lead is FALSE_POSITIVE unless you can trace external input to a dangerous sink\n"
        f"- Pattern matches without data flow are FALSE_POSITIVE\n"
        f"- Test/example/fixture code is always FALSE_POSITIVE\n"
        f"- Framework-protected code (parameterized queries, auto-escaping) is FALSE_POSITIVE\n"
        f"- Only mark REAL if you can describe a concrete exploitation path\n\n"
        f"For each lead, respond with a JSON array:\n"
        f'[{{"index": 1, "verdict": "REAL"|"FALSE_POSITIVE", "confidence": "high"|"medium"|"low", '
        f'"conviction_level": 0-3, "reasoning": "brief explanation", '
        f'"exploit_steps": ["step1","step2"] (only if REAL)}}]\n\n'
        f"Leads to analyze:{leads_text}"
    )


# ---------------------------------------------------------------------------
# Confidence Pipeline
# ---------------------------------------------------------------------------

def compute_lead_confidence(lead: Dict) -> str:
    """Compute confidence level for a lead based on multiple signals."""
    score = 0
    tool = lead.get("tool", "")
    confidence = lead.get("confidence", "low")
    cvss = lead.get("cvss", 0)

    # Tool confidence boost
    if tool == "taint-proximity":
        score += 3  # highest - source+sink co-occur
    elif tool in ("brakeman", "semgrep"):
        score += 2  # known-good tools
    elif tool in ("config-audit", "attack-surface-map"):
        score += 1  # structural
    # explicit confidence from tool
    if confidence == "high":
        score += 2
    elif confidence == "medium":
        score += 1
    # CVSS boost
    if cvss >= 8.0:
        score += 2
    elif cvss >= 6.0:
        score += 1

    if score >= 5:
        return "high"
    elif score >= 3:
        return "medium"
    return "low"
