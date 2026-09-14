"""Phase-1 Intent & Boundary model.

The proof gates historically decided "is this by-design?" and "does it cross a
boundary?" by keyword-matching the AI's free-text description. That is fragile:
the same code is a feature or a bug depending on *developer intent* and *where the
trust boundaries are*. A code-execution-as-a-service platform is SUPPOSED to run
code; that is only a vulnerability when it crosses a boundary identified in
Phase 1 (reached without auth, escapes the sandbox, crosses a tenant, escalates
privilege, or is exposed on an unintended network).

This module builds ONE structured model in Phase 1:

  * ``product_intents``  - what the codebase is designed to do, with the
    primitives that are therefore *intended* (exec, subprocess, deserialize, ...)
    and the boundaries that are supposed to guard them.
  * ``boundaries``       - every trust boundary found, each with an *enforcement*
    status (enforced / fail_open / absent / unknown) and the concrete crossing
    test Phase 2 must run to prove a bug.
  * ``gating_rules``     - derived rules: for each intended primitive, the verdict
    if the finding stays within intent vs the boundaries whose crossing escalates
    it to a real vulnerability.

It is written to ``<repo>/.lotus/intent_model.json`` so Phase 2 can plan boundary
crossings (not guess) and the UI can show the operator exactly what criteria and
boundaries the audit is informed of. It never confirms a vulnerability - lab
proof is still required.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Product-intent catalog. Each intent declares the primitives that become
# *intended* when the intent is present, and the boundaries that must guard them.
# Signals are matched against documentation + dependency/config surface.
# ---------------------------------------------------------------------------
INTENT_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "exec_service",
        "label": "Code-execution service / sandbox",
        "doc_signals": [
            "execute code", "run code", "code execution", "sandbox", "run scripts",
            "execute commands", "shell execution", "eval endpoint", "code interpreter",
            "arbitrary code", "run untrusted",
        ],
        "path_signals": ["/exec", "/run", "/eval", "/bash", "/shell", "/sandbox"],
        "intended_primitives": ["command_exec", "eval", "subprocess", "rce"],
        "guarding_boundaries": ["authn", "sandbox_isolation", "tenant", "privilege"],
    },
    {
        "id": "package_manager",
        "label": "Package / dependency manager",
        # NOTE: "pip install"/"npm install"/"gem install" are setup instructions in
        # almost every README and must NOT be treated as "this IS a package manager".
        "doc_signals": [
            "package manager", "dependency manager", "package installer",
            "install recipe", "homebrew formula", "brew tap", "cask", "install formula",
            "manages packages", "installs packages from",
        ],
        "path_signals": ["/install", "/packages", "/formula"],
        "intended_primitives": ["command_exec", "subprocess", "download_execute"],
        "guarding_boundaries": ["source_trust", "signature_verification", "authn"],
    },
    {
        "id": "cli_parser",
        "label": "CLI / data-processing tool",
        # Deliberately narrow: bare "parse"/"convert" match almost any project and
        # would wrongly mark deserialization as intended. Require CLI-specific phrasing.
        "doc_signals": [
            "cli tool", "command-line tool", "command line tool", "cli utility",
            "run from the shell", "usage: ", "$ ", "standalone binary",
        ],
        "path_signals": [],
        "intended_primitives": ["parse_untrusted"],
        "guarding_boundaries": ["deserialization_trust", "plugin_trust"],
    },
    {
        "id": "plugin_host",
        "label": "Plugin / extension host",
        # Narrow: bare "plugin"/"extension"/"marketplace" appear in most web apps
        # (integrations pages). Require explicit user-supplied-plugin phrasing.
        "doc_signals": [
            "upload a plugin", "upload plugin", "plugin api", "install plugins",
            "load plugins", "custom plugin", "write a plugin", "plugin system",
            "load extensions", "third-party code", "user-provided module",
        ],
        "path_signals": ["/plugins/upload", "/extensions/install"],
        "intended_primitives": ["dynamic_load", "command_exec", "deserialize"],
        "guarding_boundaries": ["authn", "privilege", "sandbox_isolation", "source_trust"],
    },
    {
        "id": "ai_proxy",
        "label": "AI / LLM upstream proxy",
        "doc_signals": [
            "llm proxy", "ai proxy", "model gateway", "openai proxy", "inference proxy",
            "upstream model", "completions api", "chat completions",
        ],
        "path_signals": ["/v1/complete", "/v1/chat", "/v1/messages", "/completions"],
        "intended_primitives": ["upstream_fetch", "proxy_forward"],
        "guarding_boundaries": ["authn", "ssrf_egress", "tenant"],
    },
    {
        "id": "mail_dev_tool",
        "label": "Developer mail-catcher / inspection tool",
        "doc_signals": [
            "mailcatcher", "catch mail", "smtp sink", "development mail", "fake smtp",
            "email testing", "trap outgoing",
        ],
        "path_signals": ["/messages", "/mailbox", "/emails"],
        "intended_primitives": ["store_untrusted", "render_untrusted"],
        "guarding_boundaries": ["network_exposure", "authn"],
    },
    {
        "id": "config_management",
        "label": "Configuration / infrastructure management",
        "doc_signals": [
            "configuration management", "infrastructure as code", "catalog", "manifest",
            "provisioning", "orchestration", "desired state", "agent/master",
        ],
        "path_signals": ["/catalog", "/node", "/report", "/facts"],
        "intended_primitives": ["deserialize", "command_exec", "template_render"],
        "guarding_boundaries": ["authn", "source_trust", "tenant"],
    },
    {
        "id": "web_app",
        "label": "Multi-tenant web application (default)",
        "doc_signals": [],  # default fallback intent, always present at low weight
        "path_signals": [],
        "intended_primitives": [],
        "guarding_boundaries": ["authn", "tenant", "csrf", "ssrf_egress"],
    },
]

# canonical_class / primitive_type -> the intended-primitive vocabulary above.
_PRIMITIVE_ALIASES: Dict[str, str] = {
    "rce": "command_exec", "command_injection": "command_exec",
    "command_exec": "command_exec", "code_injection": "eval", "eval": "eval",
    "deserialization": "deserialize", "deser": "deserialize", "x-5": "deserialize",
    "ssrf": "upstream_fetch", "path_traversal": "parse_untrusted",
    "x-1": "command_exec",
}

# Signals (in canonical_class / phase2_hint / description) that a finding CROSSES
# a boundary. Keyed by boundary id. Used structurally, not just on prose.
_BOUNDARY_CROSSING_SIGNALS: Dict[str, Tuple[str, ...]] = {
    "authn": (
        "unauth", "without credentials", "without auth", "without token",
        "without ticket", "missing auth", "authentication bypass", "auth bypass",
        "anonymous", "pre-auth", "http_unauth_mutate", "default_allow_http",
        "empty_token", "fail-open", "fail open",
    ),
    "tenant": (
        "cross-tenant", "tenant isolation", "other user", "another user",
        "idor", "object-level", "has_message_access", "access_message",
        "horizontal privilege", "wrong owner", "ownership",
    ),
    "sandbox_isolation": (
        "sandbox escape", "container escape", "breakout", "escape isolation",
        "bypass sandbox", "bypass isolation", "host filesystem", "host network",
        "host process", "read outside sandbox", "write outside sandbox",
        "execute outside sandbox", "path traversal outside",
    ),
    "privilege": (
        "privilege escalation", "privesc", "root access", "become admin",
        "elevate", "vertical privilege", "administrator",
    ),
    "ssrf_egress": (
        "169.254", "metadata", "internal network", "ssrf", "arbitrary upstream",
        "internal service", "localhost", "cloud-metadata",
    ),
    "source_trust": (
        "untrusted source", "unsigned", "signature bypass", "man-in-the-middle",
        "tls verification disabled", "verify=false", "dependency confusion",
    ),
    "network_exposure": (
        "0.0.0.0", "all interfaces", "bind-all", "publicly exposed",
        "exposed on network", "listen-all",
    ),
}

_DOC_FILES = (
    "README.md", "README.rst", "README.txt", "SECURITY.md", "CONTRIBUTING.md",
    "docs/README.md", "doc/README.md", "docs/index.md", "package.json",
    "Cargo.toml", "pyproject.toml", "setup.py", "Gemfile",
)

_ENFORCE = "enforced"
_FAIL_OPEN = "fail_open"
_ABSENT = "absent"
_UNKNOWN = "unknown"


def _read_docs(dest: Path) -> str:
    blob = ""
    for rel in _DOC_FILES:
        try:
            blob += (dest / rel).read_text(errors="ignore")[:6000] + "\n"
        except Exception:
            continue
    return blob.lower()


def infer_product_intents(
    dest: Path,
    tb: Optional[Dict[str, Any]] = None,
    app_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Infer intended product capabilities from docs + routes + dependency surface."""
    docs = _read_docs(dest)
    route_paths = " ".join(
        str(r.get("path") or "").lower()
        for r in ((tb or {}).get("http_routes") or (tb or {}).get("unauth_mutating") or [])
    )
    intents: List[Dict[str, Any]] = []
    for spec in INTENT_CATALOG:
        if spec["id"] == "web_app":
            continue  # added as default at the end
        doc_hits = [s for s in spec["doc_signals"] if s in docs]
        path_hits = [s for s in spec["path_signals"] if s in route_paths]
        score = len(doc_hits) + len(path_hits)
        # Require 2 doc signals, OR 1 doc + 1 route, OR 2 route signals.
        if len(doc_hits) >= 2 or (doc_hits and path_hits) or len(path_hits) >= 2:
            intents.append({
                "id": spec["id"],
                "label": spec["label"],
                "confidence": "high" if score >= 3 else "medium",
                "evidence": ([f"doc:{h}" for h in doc_hits[:4]]
                             + [f"route:{h}" for h in path_hits[:4]]),
                "intended_primitives": list(spec["intended_primitives"]),
                "guarding_boundaries": list(spec["guarding_boundaries"]),
            })
    # Default multi-tenant web-app intent: HTTP routes in the trust-boundary map, OR
    # web/server framework signals in docs (covers Django/Rails which the route mapper
    # does not parse). web_app declares no intended primitives, so it never suppresses
    # a finding - it only contributes guarding boundaries + Phase-2 intel.
    has_http = bool((tb or {}).get("http_routes") or (tb or {}).get("counts", {}).get("routes"))
    web_doc_signals = (
        "web application", "web app", "web server", "http server", "rest api",
        "django", "rails", "flask", "express", "fastapi", "sinatra", "webserver",
        "runs a server", "listens on", "chat server", "message server",
    )
    # Libraries and CLI packages frequently document that they expose a web
    # server or contain an HTTP example.  That is not evidence that the
    # enrolled product is a network service.  Without this guard the planner
    # invents HTTP/auth tasks and a fallback HTTP server becomes its apparent
    # application surface, creating both false positives and false confidence.
    web_by_docs = (
        app_type not in ("library", "cli-tool")
        and sum(1 for s in web_doc_signals if s in docs) >= 1
    )
    if (has_http or web_by_docs) and not any(i["id"] == "web_app" for i in intents):
        web = next(s for s in INTENT_CATALOG if s["id"] == "web_app")
        ev = [f"routes:{(tb or {}).get('counts', {}).get('routes', 0)}"] if has_http else []
        ev += [f"doc:{s}" for s in web_doc_signals if s in docs][:3]
        intents.append({
            "id": "web_app",
            "label": web["label"],
            "confidence": "medium",
            "evidence": ev,
            "intended_primitives": list(web["intended_primitives"]),
            "guarding_boundaries": list(web["guarding_boundaries"]),
        })
    return intents


def enumerate_boundaries(dest: Path, tb: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Enumerate trust boundaries with an enforcement status + Phase-2 crossing test.

    Primarily reads the trust-boundary map (``.lotus/trust_boundary.json`` contents
    passed as ``tb``) and augments with sandbox/tenant/egress signals from the tree.
    """
    tb = tb or {}
    boundaries: List[Dict[str, Any]] = []

    auth_gates = tb.get("auth_gates") or []
    any_mw = any(g.get("has_middleware") for g in auth_gates)
    any_fail_open = any(g.get("fail_open") for g in auth_gates)
    config_fail_open = tb.get("config_fail_open") or []
    unauth_mutating = tb.get("unauth_mutating") or []

    # --- Authentication edge ---
    if any_fail_open or config_fail_open:
        authn_status = _FAIL_OPEN
    elif any_mw:
        authn_status = _ENFORCE
    elif tb.get("http_routes") or tb.get("counts", {}).get("routes"):
        authn_status = _ABSENT if not any_mw else _UNKNOWN
    else:
        authn_status = _UNKNOWN
    boundaries.append({
        "id": "authn",
        "type": "authentication",
        "label": "Authentication edge (credential check before mutating actions)",
        "enforcement": authn_status,
        "evidence": (
            [f"middleware:{g.get('file')}" for g in auth_gates if g.get("has_middleware")][:3]
            + [f"fail_open:{g.get('file')}" for g in auth_gates if g.get("fail_open")][:3]
            + [f"config_off:{c.get('file')}" for c in config_fail_open][:3]
        ),
        "crossing_test": (
            "Hit a mutating route without credentials; require a mutating oracle "
            "(create/delete/write/RCE), not a 200-without-effect."
        ),
        "phase2_hint": "http_unauth_mutate",
        "unauth_mutating_routes": [
            {"method": r.get("method"), "path": r.get("path"), "file": r.get("file")}
            for r in unauth_mutating[:12]
        ],
        "confidence": "high" if (auth_gates or config_fail_open) else "low",
    })

    # --- Network exposure ---
    binds = tb.get("listen_binds") or []
    bind_all = [b for b in binds if b.get("all_interfaces")]
    if binds:
        boundaries.append({
            "id": "network_exposure",
            "type": "network",
            "label": "Network exposure (listen interface for the control plane)",
            "enforcement": _FAIL_OPEN if bind_all else _ENFORCE,
            "evidence": [f"{b.get('file')}:{b.get('bind')}" for b in binds[:4]],
            "crossing_test": (
                "From an off-host/adjacent network position, reach the bound port and "
                "invoke a privileged verb; combine with the authn boundary."
            ),
            "phase2_hint": "empty_token_rce" if bind_all else "control_plane_map",
            "confidence": "high",
        })

    # --- Object-level / tenant boundary (authz) ---
    tenant_status, tenant_ev = _scan_tenant_boundary(dest)
    boundaries.append({
        "id": "tenant",
        "type": "authorization",
        "label": "Object-level / tenant authorization (owner check on user-supplied ids)",
        "enforcement": tenant_status,
        "evidence": tenant_ev,
        "crossing_test": (
            "As user A, request an object owned by user B by id; expect the owner/"
            "permission check to deny. A 200 with B's data is an IDOR."
        ),
        "phase2_hint": "object_authz_idor",
        "confidence": "medium",
    })

    # --- Sandbox / isolation boundary ---
    sandbox_status, sandbox_ev = _scan_sandbox_boundary(dest)
    if sandbox_status != _UNKNOWN:
        boundaries.append({
            "id": "sandbox_isolation",
            "type": "isolation",
            "label": "Execution sandbox / container isolation",
            "enforcement": sandbox_status,
            "evidence": sandbox_ev,
            "crossing_test": (
                "From inside the intended execution context, attempt to read/write/exec "
                "outside the sandbox (host FS, host network, escape the namespace)."
            ),
            "phase2_hint": "sandbox_escape",
            "confidence": "medium",
        })

    # --- SSRF egress boundary ---
    egress_status, egress_ev = _scan_egress_boundary(dest)
    if egress_status != _UNKNOWN:
        boundaries.append({
            "id": "ssrf_egress",
            "type": "egress",
            "label": "Outbound request egress control (SSRF guard on user-supplied URLs)",
            "enforcement": egress_status,
            "evidence": egress_ev,
            "crossing_test": (
                "Supply an internal/metadata URL (169.254.169.254, localhost, internal "
                "service) where the app fetches a user-controlled URL; expect it blocked."
            ),
            "phase2_hint": "ssrf_metadata",
            "confidence": "medium",
        })

    return boundaries


def _scan_tenant_boundary(dest: Path, limit: int = 1500) -> Tuple[str, List[str]]:
    """Heuristic: do object fetches by user-supplied id pair with an owner/permission
    check? Presence of authz helpers => enforced (somewhere); their absence next to
    id-fetches => at-risk."""
    authz_tokens = re.compile(
        r"has_permission|has_object_permission|check_owner|is_owner|current_user\.id\s*==|"
        r"filter\(\s*user\s*=|where\(\s*user_id|access_\w+\(|authorize!|can\?|pundit|cancancan",
        re.I,
    )
    idfetch = re.compile(r"objects\.get\(|find\(\s*params|findById|get_object_or_404|\.find\(", re.I)
    ev: List[str] = []
    has_authz = False
    has_idfetch = False
    n = 0
    for p in _iter_code(dest, limit):
        n += 1
        try:
            t = p.read_text(errors="ignore")
        except Exception:
            continue
        if authz_tokens.search(t):
            has_authz = True
            if len(ev) < 3:
                ev.append(f"authz-helper:{p.name}")
        if idfetch.search(t):
            has_idfetch = True
    if has_authz and has_idfetch:
        return _ENFORCE, ev
    if has_idfetch and not has_authz:
        return _ABSENT, ["id-fetches present with no object-authz helper detected"]
    return _UNKNOWN, ev


def _scan_sandbox_boundary(dest: Path) -> Tuple[str, List[str]]:
    tokens = {
        "seccomp": "seccomp", "namespaces": "unshare(", "nsjail": "nsjail",
        "firejail": "firejail", "gvisor": "runsc", "chroot": "chroot(",
        "docker": "dockerfile", "rlimit": "setrlimit", "cgroup": "cgroup",
        "pledge": "pledge(", "capsicum": "cap_enter",
    }
    ev: List[str] = []
    blob = ""
    for rel in ("Dockerfile", "docker-compose.yml", "SECURITY.md", "README.md"):
        try:
            blob += (dest / rel).read_text(errors="ignore").lower()
        except Exception:
            pass
    n = 0
    for p in _iter_code(dest, 800):
        n += 1
        try:
            blob += p.read_text(errors="ignore").lower()
        except Exception:
            continue
        if len(blob) > 2_000_000:
            break
    for label, tok in tokens.items():
        if tok in blob:
            ev.append(label)
    if ev:
        return _ENFORCE, ev[:5]
    return _UNKNOWN, []


def _scan_egress_boundary(dest: Path, limit: int = 1500) -> Tuple[str, List[str]]:
    fetch = re.compile(r"requests\.(get|post)|urlopen|httpx\.|net/http|fetch\(|open-uri|Faraday", re.I)
    guard = re.compile(
        r"is_safe_url|is_safe_upstream|block.*metadata|169\.254|deny.*private|"
        r"validate_url|ssrf|allowlist|allow_list|private_ip",
        re.I,
    )
    has_fetch = False
    has_guard = False
    ev: List[str] = []
    for p in _iter_code(dest, limit):
        try:
            t = p.read_text(errors="ignore")
        except Exception:
            continue
        if fetch.search(t):
            has_fetch = True
        if guard.search(t):
            has_guard = True
            if len(ev) < 3:
                ev.append(f"egress-guard:{p.name}")
    if has_fetch and has_guard:
        return _ENFORCE, ev
    if has_fetch and not has_guard:
        return _ABSENT, ["outbound fetch present with no SSRF/egress guard detected"]
    return _UNKNOWN, ev


def _iter_code(dest: Path, limit: int) -> List[Path]:
    skip = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
            "target", "build", "dist", "test", "tests", "spec", "fixtures"}
    exts = {".py", ".rb", ".js", ".ts", ".go", ".rs", ".java", ".php"}
    out: List[Path] = []
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".")]
        for fname in files:
            if Path(fname).suffix.lower() in exts:
                out.append(Path(root) / fname)
                if len(out) >= limit:
                    return out
    return out


def derive_gating_rules(intents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """For each intended primitive, the verdict when within intent and the
    boundaries whose crossing escalates it to a real vulnerability."""
    rules: List[Dict[str, Any]] = []
    seen = set()
    for intent in intents:
        for prim in intent.get("intended_primitives", []):
            if prim in seen:
                continue
            seen.add(prim)
            rules.append({
                "intended_primitive": prim,
                "from_intent": intent["id"],
                "verdict_if_within_intent": "BY-DESIGN",
                "escalates_to_bug_if_crosses": list(intent.get("guarding_boundaries", [])),
                "rationale": (
                    f"'{prim}' is an intended capability of a {intent['label']}. "
                    f"It is only a vulnerability if it crosses one of: "
                    f"{', '.join(intent.get('guarding_boundaries', [])) or 'n/a'}."
                ),
            })
    return rules


def build_intent_model(
    dest: Path,
    language: str = "",
    tb: Optional[Dict[str, Any]] = None,
    *,
    app_type: Optional[str] = None,
    write: bool = True,
) -> Dict[str, Any]:
    """Assemble the full intent+boundary model and (optionally) persist it."""
    dest = Path(dest)
    if tb is None:
        # Load the trust-boundary map if Phase 1 already wrote it.
        try:
            tb = json.loads((dest / ".lotus" / "trust_boundary.json").read_text())
        except Exception:
            tb = {}
    intents = infer_product_intents(dest, tb, app_type=app_type)
    boundaries = enumerate_boundaries(dest, tb)
    rules = derive_gating_rules(intents)

    intended_primitives = sorted({p for i in intents for p in i.get("intended_primitives", [])})
    weak = [b for b in boundaries if b["enforcement"] in (_FAIL_OPEN, _ABSENT)]
    model: Dict[str, Any] = {
        "language": language,
        "product_intents": intents,
        "intended_primitives": intended_primitives,
        "boundaries": boundaries,
        "gating_rules": rules,
        "summary": _summarize(intents, boundaries),
        "counts": {
            "intents": len(intents),
            "boundaries": len(boundaries),
            "weak_boundaries": len(weak),
            "gating_rules": len(rules),
        },
    }
    if write:
        try:
            out = dest / ".lotus"
            out.mkdir(exist_ok=True)
            (out / "intent_model.json").write_text(
                json.dumps(model, indent=2, default=str), encoding="utf-8"
            )
        except Exception:
            pass
    return model


def _summarize(intents: List[Dict[str, Any]], boundaries: List[Dict[str, Any]]) -> str:
    labels = ", ".join(i["label"] for i in intents) or "general application"
    weak = [b["id"] for b in boundaries if b["enforcement"] in (_FAIL_OPEN, _ABSENT)]
    line = f"Intent: {labels}. Boundaries enumerated: {len(boundaries)}."
    if weak:
        line += f" At-risk boundaries (fail-open/absent): {', '.join(weak)}."
    else:
        line += " No fail-open/absent boundaries detected in Phase 1."
    return line


# ---------------------------------------------------------------------------
# Gating classifier - consumed by proof_gates via the pipeline.
# ---------------------------------------------------------------------------
def _finding_primitive(finding: Dict[str, Any]) -> Optional[str]:
    for key in ("canonical_class", "primitive_type"):
        v = str(finding.get(key) or "").lower()
        if v in _PRIMITIVE_ALIASES:
            return _PRIMITIVE_ALIASES[v]
        if v in ("command_exec", "eval", "subprocess", "deserialize",
                 "upstream_fetch", "parse_untrusted", "dynamic_load"):
            return v
    return None


def _crosses_boundary(finding: Dict[str, Any], boundary_id: str) -> Optional[str]:
    """Return the matched signal if the finding crosses ``boundary_id``, else None."""
    hay = " ".join(str(finding.get(k) or "") for k in (
        "description", "title", "phase2_hint", "canonical_class", "primitive_type",
        "qualification",
    )).lower()
    for sig in _BOUNDARY_CROSSING_SIGNALS.get(boundary_id, ()):  # type: ignore[arg-type]
        if sig in hay:
            return sig
    return None


def classify_finding_against_intent(
    finding: Dict[str, Any],
    model: Dict[str, Any],
) -> Dict[str, Any]:
    """Decide whether a finding is BY-DESIGN, a BOUNDARY-CROSSING bug, or IN-SCOPE.

    * BY-DESIGN         - finding exercises an intended primitive and crosses no
      guarding boundary. Not report-eligible.
    * BOUNDARY-CROSSING - intended primitive BUT crosses a guarding boundary
      (unauth, cross-tenant, sandbox escape, privesc, ...). A real candidate.
    * IN-SCOPE          - not an intended capability; evaluate normally.
    """
    prim = _finding_primitive(finding)
    rules = {r["intended_primitive"]: r for r in model.get("gating_rules", [])}
    if prim is None or prim not in rules:
        return {"decision": "IN-SCOPE", "boundary": None,
                "rationale": "Finding is not an intended product capability; evaluated normally."}
    rule = rules[prim]
    for bid in rule.get("escalates_to_bug_if_crosses", []):
        sig = _crosses_boundary(finding, bid)
        if sig:
            return {
                "decision": "BOUNDARY-CROSSING",
                "boundary": bid,
                "matched_signal": sig,
                "rationale": (
                    f"'{prim}' is intended, but this finding crosses the '{bid}' boundary "
                    f"(signal: '{sig}') - a real vulnerability candidate."
                ),
            }
    return {
        "decision": "BY-DESIGN",
        "boundary": None,
        "rationale": rule.get("rationale", ""),
        "lab_tests_to_escalate": [
            b["crossing_test"]
            for b in model.get("boundaries", [])
            if b["id"] in rule.get("escalates_to_bug_if_crosses", [])
        ],
    }


def annotate_findings_with_intent(
    findings: List[Dict[str, Any]],
    model: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Tag each finding with the intent decision so proof_gates handles it
    structurally. Sets ``by_design`` / ``boundary_crossing`` / ``qualification``
    that the existing gate logic already honors."""
    for f in findings:
        decision = classify_finding_against_intent(f, model)
        f["intent_decision"] = decision
        if decision["decision"] == "BY-DESIGN":
            f["by_design"] = True
            if f.get("qualification") not in ("QUALIFIED",) or f.get("primitive_type"):
                f["qualification"] = "BY-DESIGN"
            f.setdefault("by_design_lab_tests", decision.get("lab_tests_to_escalate", []))
        elif decision["decision"] == "BOUNDARY-CROSSING":
            f["boundary_crossing"] = True
            f["crossed_boundary"] = decision.get("boundary")
            # A pre-existing BY-DESIGN tag is overridden - this crosses a boundary.
            f.pop("by_design", None)
            if f.get("qualification") == "BY-DESIGN":
                f["qualification"] = "QUALIFIED"
    return findings
