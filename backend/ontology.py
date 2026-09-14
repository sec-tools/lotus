"""Unified bug ontology  - the single canonical taxonomy for Lotus.

Before this module, bug-class taxonomies were duplicated across at least seven places
(`fix_suggestions._classify`, `report_enrich._CLASS_PROFILE`, `analysis.OWASP/AGENT`,
`phase2_graph._classify_primitive`, `discovery_engine` sink/source keywords,
`skill_seeds` R/W/X matrix, `proof_gates` by-design primitives). They drifted (e.g.
`auth_bypass` vs `AUTH_BYPASS`), which quietly hurts gating precision and makes
cross-audit measurement impossible.

This module is the ONE place that defines:
  - canonical bug classes and their metadata (primitive, OWASP, sink/source, default
    conviction requirement, whether they are DoS-only / by-design-prone),
  - a `normalize()` that maps any of the historical spellings/synonyms to a canonical
    class, so discovery, gating, skills, reporting AND the quality benchmark all agree,
  - helpers the benchmark uses to match a reported finding to a labeled ground-truth
    item (same canonical class + location).

It is intentionally dependency-free and pure so it can be imported anywhere (pipeline,
gates, benchmark) without side effects.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# R/W/X capability model (aligned with skill_seeds rwx-primitive-coverage-matrix):
#   X = code/command execution, W = write primitive, R = read/disclosure primitive,
#   DOS = availability only (never RCE), TRUST = trust-boundary/authz.
PRIMITIVE_X = "X"
PRIMITIVE_W = "W"
PRIMITIVE_R = "R"
PRIMITIVE_DOS = "DOS"
PRIMITIVE_TRUST = "TRUST"


@dataclass(frozen=True)
class BugClass:
    key: str                      # canonical id (snake_case)
    label: str                    # human label
    primitive: str                # R/W/X/DOS/TRUST
    rwx_id: str                   # matrix id (X-1, R-3, ...) or ""
    owasp: str                    # OWASP 2021 category (A01..A10) or ""
    sink_hint: str                # canonical sink description
    source_hint: str              # canonical untrusted-source description
    min_conviction_for_report: int = 3   # conviction level required to be report-eligible
    dos_only: bool = False        # availability-only => capped at LATENT, never RCE
    by_design_prone: bool = False # frequently an intended capability (needs boundary check)
    synonyms: Tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Canonical registry
# ---------------------------------------------------------------------------
_CLASSES: List[BugClass] = [
    BugClass("command_injection", "OS command injection", PRIMITIVE_X, "X-1", "A03",
             "OS command execution (system/exec/popen)", "attacker-controlled request/argument",
             synonyms=("cmd injection", "command inject", "os.system", "subprocess", "shell=true",
                       "exec.command", "child_process", "rce", "os command", "shell injection")),
    BugClass("sql_injection", "SQL injection", PRIMITIVE_R, "R-2", "A03",
             "SQL query execution", "attacker-controlled request parameter",
             synonyms=("sqli", "sql inject", "raw sql", "cursor.execute", "sql concat", "sql-concat")),
    BugClass("ssti", "Server-side template injection", PRIMITIVE_X, "X-3", "A03",
             "template render", "attacker-controlled string",
             synonyms=("template injection", "render_template_string", "jinja", "sstihandler")),
    BugClass("deserialization", "Unsafe deserialization", PRIMITIVE_X, "X-5", "A08",
             "unsafe deserializer", "attacker-controlled bytes/body",
             synonyms=("deserial", "pickle", "yaml.load", "marshal.load", "unserialize",
                       "objectinputstream", "readobject", "xstream", "deserialization-chain")),
    BugClass("path_traversal_read", "Path traversal (read)", PRIMITIVE_R, "R-3", "A01",
             "filesystem open/read", "attacker-controlled path/filename",
             synonyms=("path travers", "directory travers", "lfi", "file read", "arbitrary file read",
                       "send_file", "path_traversal")),
    BugClass("path_traversal_write", "Path traversal (write)", PRIMITIVE_W, "W-3", "A01",
             "filesystem write", "attacker-controlled path/filename",
             synonyms=("arbitrary file write", "zip slip", "path write")),
    BugClass("ssrf", "Server-side request forgery", PRIMITIVE_R, "R-4", "A10",
             "outbound HTTP fetch", "attacker-controlled URL/host",
             synonyms=("server-side request", "urlopen", "requests.get", "metadata", "169.254")),
    BugClass("xss", "Cross-site scripting", PRIMITIVE_W, "W-7", "A03",
             "HTML/JS response render", "attacker-controlled content",
             synonyms=("cross-site", "innerhtml", "dangerouslyset", "html_safe", "reflected xss")),
    BugClass("authz_bypass", "Authorization/authentication bypass", PRIMITIVE_TRUST, "", "A01",
             "privileged handler (missing guard)", "unauthenticated/unauthorized request",
             by_design_prone=False,
             synonyms=("authz", "authoriz", "auth bypass", "auth_bypass", "guard-alternate",
                       "guard-authorization-bypass", "sibling", "skip_before", "missing security check",
                       "idor", "broken access control", "auth-structural-bypass",
                       "shouldPass", "E_TCPADMIN", "anonymous credential", "empty root",
                       "empty password", "KILL session", "check_auth_for_kill",
                       "no_priv_needed", "stubbed-priv-check", "OPTIMIZE TABLE",
                       "skip_sys_table_check", "ANALYZE TABLE",
                       "sql-no-priv-needed")),
    BugClass("weak_secret", "Weak/hardcoded secret or crypto", PRIMITIVE_TRUST, "", "A02",
             "auth/token/crypto use", "predictable/committed secret material",
             synonyms=("weak prng", "random.randint", "math.random", "hardcoded", "secret",
                       "api_key", "jwt", "alg:none", "weak-secret", "hardcoded credential")),
    BugClass("code_injection", "Code injection (eval/exec of expression)", PRIMITIVE_X, "X-4", "A03",
             "dynamic code evaluation", "attacker-controlled expression",
             synonyms=("code inject", "eval(", "eval", "exec(", "function(", "constantize", "dynamic-dispatch",
                       "dynamic dispatch", "instance_eval", "class_eval", "module_eval",
                       "dynamic code execution", "code execution", "dlopen", "LoadLibrary")),
    BugClass("memory_corruption", "Memory corruption", PRIMITIVE_W, "W-1", "A06",
             "unsafe memory operation (overflow/UAF/OOB)", "attacker-controlled length/index/pointer",
             synonyms=("buffer overflow", "heap overflow", "stack overflow", "use-after-free", "uaf",
                       "double free", "out-of-bounds", "oob", "oob read", "oob write", "memcpy",
                       "strcpy", "unsafe-c-api", "asan", "heap-buffer-overflow", "segfault")),
    BugClass("integer_overflow", "Integer overflow / boundary", PRIMITIVE_W, "W-1", "A06",
             "arithmetic feeding allocation/index", "attacker-controlled numeric field",
             synonyms=("integer overflow", "int overflow", "integer-boundary", "signedness",
                       "truncation")),
    BugClass("denial_of_service", "Denial of service", PRIMITIVE_DOS, "", "A06",
             "unbounded work / infinite recursion / CPU-memory blowup", "attacker-controlled malformed input",
             min_conviction_for_report=3, dos_only=True,
             synonyms=("dos", "denial of service", "infinite recursion", "infinite loop", "cpu hang",
                       "resource exhaustion", "algorithmic complexity", "billion laughs", "decompression bomb",
                       "stack overflow recursion", "hang", "oom", "unbounded")),
    BugClass("xxe", "XML external entity", PRIMITIVE_R, "R-3", "A05",
             "XML parser with external entities enabled", "attacker-controlled XML",
             synonyms=("xxe", "external entity", "xml entity", "!entity")),
    BugClass("api_surface", "Dangerous exposed API surface", PRIMITIVE_X, "", "A03",
             "dangerous exec/file API", "attacker-controlled API call",
             by_design_prone=True,
             synonyms=("dangerous api", "shell.exec", "api-surface", "v1/shell", "v1/bash",
                       "code.execute")),
    BugClass("generic", "Unclassified / trust-boundary", PRIMITIVE_TRUST, "", "",
             "the cited security-sensitive sink", "untrusted input",
             synonyms=()),
]

CLASSES: Dict[str, BugClass] = {c.key: c for c in _CLASSES}

# Build a synonym -> canonical lookup once (longest synonyms first for greedy matching).
_SYNONYM_INDEX: List[Tuple[str, str]] = []
for _c in _CLASSES:
    _SYNONYM_INDEX.append((_c.key.replace("_", " "), _c.key))
    _SYNONYM_INDEX.append((_c.key, _c.key))
    for _s in _c.synonyms:
        _SYNONYM_INDEX.append((_s.lower(), _c.key))
_SYNONYM_INDEX.sort(key=lambda kv: len(kv[0]), reverse=True)


def normalize(*texts: str) -> str:
    """Map any historical class name / free text to a canonical bug-class key.

    Accepts one or more strings (e.g. title, description, tool, primitive_type); returns
    the best canonical key, or 'generic' if nothing matches.
    """
    blob = " ".join(t for t in texts if t).lower()
    if not blob.strip():
        return "generic"
    # Exact-ish class token first.
    for token, key in _SYNONYM_INDEX:
        if not token:
            continue
        # word-ish containment (avoid matching inside unrelated words for short tokens)
        if len(token) <= 4:
            if re.search(r"(?<![a-z])" + re.escape(token) + r"(?![a-z])", blob):
                return key
        elif token in blob:
            return key
    return "generic"


def get(key: str) -> BugClass:
    return CLASSES.get(key, CLASSES["generic"])


def primitive_of(key: str) -> str:
    return get(key).primitive


def owasp_of(key: str) -> str:
    return get(key).owasp


def is_dos_only(key: str) -> bool:
    return get(key).dos_only


def is_by_design_prone(key: str) -> bool:
    return get(key).by_design_prone


def classify_finding(finding: Dict) -> str:
    """Canonical class for a finding dict (title/description/tool/primitive_type/ai_response)."""
    return normalize(
        str(finding.get("title") or ""),
        str(finding.get("primitive_type") or ""),
        str(finding.get("bug_class") or ""),
        str(finding.get("tool") or ""),
        str(finding.get("description") or ""),
        str(finding.get("ai_response") or ""),
    )


def classes_match(a: str, b: str) -> bool:
    """Do two class keys refer to the same (or compatible) canonical class?

    Path-traversal read/write and the two memory classes are treated as compatible for
    benchmark matching so a 'path_traversal' label matches either direction.
    """
    if a == b:
        return True
    groups = [
        {"path_traversal", "path_traversal_read", "path_traversal_write"},
        {"memory_corruption", "integer_overflow"},
        # command_injection vs code_injection stay DISTINCT: same file within
        # LINE_TOLERANCE must not let os.system steal an eval finding (or vice versa).
    ]
    for g in groups:
        if a in g and b in g:
            return True
    return False


# Canonical status vocabulary a high-quality audit assigns to a finding.
STATUS_REPORT_ELIGIBLE = "report-eligible"
STATUS_BELOW_THRESHOLD = "below-threshold"
STATUS_LATENT = "latent"          # reachable+real but availability-only or preconditioned
STATUS_UNPROVEN = "unproven"
STATUS_BY_DESIGN = "by-design"

ALL_STATUSES = (
    STATUS_REPORT_ELIGIBLE, STATUS_BELOW_THRESHOLD, STATUS_LATENT,
    STATUS_UNPROVEN, STATUS_BY_DESIGN,
)
