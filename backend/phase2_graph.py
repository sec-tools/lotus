"""
LangGraph Autonomous Agent for Phase 2 Dynamic Vulnerability Discovery & Lab Validation.

Implements a stateful StateGraph that iteratively generates hypotheses from Phase 1 recon,
queries RAG skills vector search, runs dynamic probes against the isolated lab container,
evaluates validity gates with qualification discipline, and assigns Conviction Ladder levels.

Doctrine from audit-markdown-light:
  - Qualify before lab spend (Skill 75)
  - Proof-first: attack QUALIFIED leads, not enumerate forever
  - Hypothesis graveyard with revival awareness
  - Stall-breaker at max iterations
"""

import re
import secrets
import asyncio
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict
from langgraph.graph import StateGraph, END

from backend.skills import vector_search_skills


class _GraphStopped(BaseException):
    """Cooperative stop bypasses ordinary probe/error recovery handlers."""


@dataclass
class _GraphControl:
    deadline: float
    stopped: threading.Event = field(default_factory=threading.Event)

    def check(self):
        if self.stopped.is_set() or time.monotonic() >= self.deadline:
            raise _GraphStopped("Graph execution stopped before further source/probe work")


_GRAPH_CONTROL = ContextVar("lotus_graph_control", default=None)
_PROBE_TIMEOUT_SECONDS = 5.0
_PROBE_BODY_BYTES = 16 * 1024
_PROBE_BODY_CHARS = 4000


def _graph_checkpoint():
    control = _GRAPH_CONTROL.get()
    if control is not None:
        control.check()


async def _drain_graph(invocation):
    """Repeated cancellation cannot release a still-running owned worker."""
    while not invocation.done():
        try:
            await asyncio.wait([invocation], timeout=.05)
        except asyncio.CancelledError:
            continue
    try:
        invocation.result()
    except BaseException:
        pass


async def run_phase2_langgraph_owned(repo_id, dest, recon_summary, candidate_findings,
                                    settings=None, max_iterations=2, *, timeout=180):
    """Stop and drain this graph before the caller can publish or clean up.

    ContextVars propagate the same control object into LangGraph's own node
    threads. The outer analyzer wrapper also retains ownership during native
    waits. Only a successful return may merge the private result copies.
    """
    from backend.analyzer_execution import invoke_analyzer
    budget = float(timeout)
    if not 0 < budget <= 7200:
        raise ValueError("Graph timeout must be positive and at most 7200 seconds")
    control = _GraphControl(time.monotonic() + budget)
    def run():
        token = _GRAPH_CONTROL.set(control)
        try:
            control.check()
            recon, candidates = deepcopy(recon_summary), deepcopy(candidate_findings)
            control.check()
            result = run_phase2_langgraph_agent(repo_id, dest, recon, candidates, settings, max_iterations)
            control.check()
            return result
        finally:
            _GRAPH_CONTROL.reset(token)
    invocation = asyncio.create_task(invoke_analyzer(run, repo_id=repo_id, name="ai-gating"))
    try:
        return await asyncio.wait_for(asyncio.shield(invocation), timeout=budget)
    except (asyncio.TimeoutError, asyncio.CancelledError, _GraphStopped) as error:
        control.stopped.set()
        invocation.cancel()
        await _drain_graph(invocation)
        if isinstance(error, asyncio.CancelledError):
            raise
        raise asyncio.TimeoutError("Graph execution deadline expired; owned work stopped and source access released") from None


async def _read_probe_response(url, *, method, params, data, json_body):
    """Bound total request time and retained body; do not follow target redirects."""
    import httpx
    control = _GRAPH_CONTROL.get()
    _graph_checkpoint()
    deadline = min(time.monotonic() + _PROBE_TIMEOUT_SECONDS,
                   control.deadline if control is not None else float("inf"))
    async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT_SECONDS, follow_redirects=False,
                                 trust_env=False, headers={"Accept-Encoding": "identity"}) as client:
        async def read():
            async with client.stream(method.upper(), url, params=params or None,
                                     data=data or None, json=json_body) as response:
                _graph_checkpoint()
                # Avoid allocating an attacker-controlled decompression result.
                # A server ignoring identity negotiation leaves an explicit gap.
                if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                    return {"status": 0, "body": "probe unavailable: encoded response not accepted",
                            "headers": {}, "body_truncated": False}
                body = bytearray()
                truncated = False
                async for chunk in response.aiter_raw(chunk_size=4096):
                    _graph_checkpoint()
                    remaining = _PROBE_BODY_BYTES - len(body)
                    body.extend(chunk[:remaining])
                    if len(body) >= _PROBE_BODY_BYTES or len(body.decode(response.encoding or "utf-8", errors="replace")) >= _PROBE_BODY_CHARS:
                        truncated = True
                        break
                _graph_checkpoint()
                return {"status": response.status_code,
                        "body": body.decode(response.encoding or "utf-8", errors="replace")[:_PROBE_BODY_CHARS],
                        "headers": dict(response.headers), "body_truncated": truncated,
                        "redirect_not_followed": response.is_redirect}
        work = asyncio.create_task(read())
        try:
            while True:
                _graph_checkpoint()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("probe total request deadline expired")
                done, _ = await asyncio.wait([work], timeout=min(.05, remaining))
                if done:
                    _graph_checkpoint()
                    if time.monotonic() >= deadline:
                        raise TimeoutError("probe total request deadline expired")
                    return work.result()
        finally:
            if not work.done():
                work.cancel()
            await asyncio.gather(work, return_exceptions=True)


class AuditState(TypedDict):
    repo_id: int
    dest_path: str
    language: str
    recon_summary: Dict[str, Any]
    phase2_plan: Dict[str, Any]
    candidate_findings: List[Dict[str, Any]]
    validated_findings: List[Dict[str, Any]]
    hypothesis_graveyard: List[Dict[str, Any]]
    iteration: int
    max_iterations: int
    logs: List[str]
    lab_url: str


def _probe_lab_endpoint(
    lab_url: str,
    path: str = "/",
    params: Optional[Dict[str, str]] = None,
    method: str = "GET",
    data: Optional[Dict[str, str]] = None,
    json_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute a dynamic HTTP probe against the lab container.

    Supports GET (query params) and POST (form ``data`` or ``json_body``) so the
    conviction node can exercise body-driven sinks, not just querystrings. A
    wider body window (4 KB) is captured for oracle scanning while callers store
    a short snippet.
    """
    _graph_checkpoint()
    if not lab_url:
        return {"status": 0, "body": "no lab url"}
    try:
        url = f"{lab_url.rstrip('/')}/{path.lstrip('/')}"
        return asyncio.run(_read_probe_response(url, method=method, params=params,
            data=data if method.upper() == "POST" else None,
            json_body=json_body if method.upper() == "POST" else None))
    except Exception as e:
        return {"status": 0, "body": f"probe failed: {str(e)[:150]}"}


def _extract_probe_paths(finding: Dict[str, Any]) -> List[str]:
    """Derive concrete lab paths/params from finding metadata instead of only probing '/'."""
    paths = ["/"]
    desc = (finding.get("description") or "") + " " + (finding.get("title") or "")
    file_path = finding.get("file") or ""
    # Prefer structured entry points from api-surface / OpenAPI discovery
    ep = finding.get("entry_point") or finding.get("endpoint") or ""
    if isinstance(ep, str) and ep.strip():
        # Formats: "POST /v1/shell/exec" or "/v1/shell/exec"
        m = re.search(r"(/[a-zA-Z0-9_\-./{}]+)", ep)
        if m:
            paths.append(m.group(1))
    blob = f"{desc} {file_path}"

    for m in re.finditer(r"['\"`](/[a-zA-Z0-9_\-./{}]+)['\"`]", desc):
        paths.append(m.group(1))
    for m in re.finditer(r"(?:route|endpoint|path)\s*[:=]\s*['\"`]?(/[^\s'\"`]+)", desc, re.I):
        paths.append(m.group(1))
    # Bare routes in titles: "Route may skip guard: /run"
    for m in re.finditer(r"(?<![A-Za-z0-9_])(/[a-zA-Z][a-zA-Z0-9_\-]{0,32})(?![A-Za-z0-9_./])", desc):
        paths.append(m.group(1))

    lower = (file_path + " " + desc).lower()
    if "admin" in lower:
        paths.extend(["/admin", "/admin/", "/admin/users", "/api/admin"])
    if "api" in lower:
        paths.extend(["/api", "/api/v1", "/health", "/status"])
    if "login" in lower or "auth" in lower:
        paths.extend(["/login", "/auth", "/signin"])
    # Common intentional-vuln fixture surfaces
    if any(k in lower for k in ("command", "exec", "system", "rce", "inject")):
        paths.append("/run")
    if any(k in lower for k in ("travers", "path", "file read", "lfi")):
        paths.append("/file")
    if any(k in lower for k in ("ssti", "template", "xss", "jinja")):
        paths.append("/page")
    if "ssrf" in lower or "fetch" in lower:
        paths.append("/fetch")
    if "deserial" in lower or "pickle" in lower:
        paths.append("/deserialize")
    if "guard" in lower or "bypass" in lower or "authz" in lower:
        paths.extend(["/run", "/public", "/admin/users"])

    seen = set()
    out = []
    for p in paths:
        if p not in seen and len(p) < 64:
            seen.add(p)
            out.append(p)
    return out[:12]


def _payload_params_for(finding: Dict[str, Any]) -> List[Dict[str, str]]:
    """Synthesize minimal probe params from vulnerability class."""
    t = ((finding.get("title") or "") + " " + (finding.get("description") or "")).lower()
    probes = [{}]
    if any(k in t for k in ("command", "exec", "system", "inject", "/run")):
        probes.append({"cmd": "id", "command": "id", "q": ";id"})
    if "travers" in t or "path" in t or "/file" in t:
        probes.append({"file": "/etc/passwd", "path": "/etc/passwd", "name": "..%2f..%2fetc%2fpasswd"})
    if "sql" in t:
        probes.append({"id": "1 OR 1=1", "q": "' OR '1'='1"})
    if "ssrf" in t or "/fetch" in t:
        probes.append({"url": "http://127.0.0.1/", "uri": "http://169.254.169.254/"})
    if "xss" in t or "template" in t or "ssti" in t or "/page" in t:
        probes.append({"q": "{{7*7}}", "name": "<script>alert(1)</script>"})
    return probes[:5]


# ---------------------------------------------------------------------------
# Sound, canary-based lab oracles.
#
# The previous oracle accepted the bare substring ``"49"`` and a raw
# ``<script>`` in the (500-byte-truncated) body, which coincidentally matches
# ordinary responses and manufactured false CONFIRMED findings. Each probe now
# carries a per-run UNIQUE canary and an oracle that proves the *effect of our
# injected payload*, not incidental page content:
#   * command_injection - echo a random token; require the token in the body.
#   * ssti              - inject A*B with random large operands; require the
#                          product AND require the literal expression to be gone
#                          (i.e. it was actually evaluated).
#   * path_traversal    - require an /etc/passwd row signature (root:x:0:0:).
#   * sql_injection     - require a concrete DB error signature (not bare "sql").
#   * xss_reflection    - require our unique tag reflected UNESCAPED.
# ---------------------------------------------------------------------------

_COMMON_PARAM_NAMES = ("q", "cmd", "command", "input", "name", "arg", "value",
                       "data", "search", "id", "file", "path", "url", "target")


def _rand_token(prefix: str) -> str:
    return f"{prefix}{secrets.token_hex(4)}"


def _spread(names, value):
    """Put the payload under several likely parameter names."""
    return {n: value for n in names}


def _build_class_probes(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return probe descriptors with unique canaries + sound oracles.

    Each descriptor: ``{method, params, data, json, oracle}`` where ``oracle`` is
    a spec consumed by :func:`_oracle_check`. Payloads are delivered over both
    GET query params and POST (form + JSON) so body-driven sinks are covered.
    """
    t = ((finding.get("title") or "") + " " + (finding.get("description") or "")).lower()
    prim = (finding.get("primitive_type") or "").upper()
    probes: List[Dict[str, Any]] = []

    def add(payload_map: Dict[str, str], oracle: Dict[str, Any]):
        probes.append({"method": "GET", "params": payload_map, "data": None, "json": None, "oracle": oracle})
        probes.append({"method": "POST", "params": None, "data": payload_map, "json": None, "oracle": oracle})
        probes.append({"method": "POST", "params": None, "data": None, "json": payload_map, "oracle": oracle})

    is_cmd = prim.startswith("X-1") or any(k in t for k in ("command", "exec", "system", "shell", "rce", "/run", "inject"))
    is_ssti = "ssti" in t or "template" in t or prim in ("X-3",) or "/page" in t
    is_trav = "travers" in t or "path" in t or "lfi" in t or "file read" in t or "/file" in t or prim.startswith("R-3")
    is_sql = "sql" in t or "sqli" in t or prim in ("R-2",)
    is_xss = "xss" in t or "cross-site script" in t

    if is_cmd:
        tok = _rand_token("LOTUSRCE")
        for pl in (f";echo {tok}", f"$(echo {tok})", f"`echo {tok}`", f"&& echo {tok}", f"| echo {tok}"):
            add(_spread(_COMMON_PARAM_NAMES, pl),
                {"type": "contains", "needles": [tok], "marker": f"command exec canary echoed: {tok}", "primitive": "command_injection"})
        # Classic secondary oracles (strong, low-FP).
        add(_spread(_COMMON_PARAM_NAMES, "id"),
            {"type": "regex", "pattern": r"uid=\d+\([^)]+\) gid=\d+", "marker": "id(1) output (uid=/gid=)", "primitive": "command_injection"})
        add(_spread(("file", "path", "name", "cmd"), "/etc/passwd"),
            {"type": "regex", "pattern": r"root:.*:0:0:", "marker": "/etc/passwd row leaked", "primitive": "command_injection"})

    if is_ssti:
        a, b = secrets.randbelow(9000) + 1000, secrets.randbelow(9000) + 1000
        prod = str(a * b)
        for expr in (f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}", f"#{{{a}*{b}}}"):
            add(_spread(("q", "name", "template", "msg", "input", "page", "s"), expr),
                {"type": "ssti_arith", "needle": prod, "forbidden": [f"{a}*{b}"],
                 "marker": f"template evaluated {a}*{b}={prod}", "primitive": "ssti"})

    if is_trav:
        for pl in ("../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd"):
            add(_spread(("file", "path", "name", "page", "doc", "download", "f", "template"), pl),
                {"type": "regex", "pattern": r"root:.*:0:0:", "marker": "path traversal read /etc/passwd", "primitive": "path_traversal"})

    if is_sql:
        for pl in ("'", "1'", "' OR '1'='1", "\" OR \"1\"=\"1", "1); DROP--"):
            add(_spread(("id", "q", "user", "name", "search", "uid", "email"), pl),
                {"type": "contains_any",
                 "needles": ["you have an error in your sql syntax", "sqlite3.operationalerror",
                             "sqlite_error", "unclosed quotation mark", "pg::syntaxerror",
                             "psql: error", "ora-00933", "ora-00921", "syntax error at or near",
                             "sqlstate", "unterminated quoted string"],
                 "marker": "database syntax error surfaced", "primitive": "sql_injection"})

    if is_xss:
        tok = _rand_token("lotusxss")
        needle = f"<{tok}>"
        for name in ("q", "name", "search", "msg", "input", "s", "comment"):
            add({name: needle},
                {"type": "reflect_unescaped", "needle": needle, "forbidden": [f"&lt;{tok}"],
                 "marker": f"reflected unescaped marker {needle}", "primitive": "xss_reflection"})

    return probes


def _oracle_check(oracle: Dict[str, Any], body_raw: str) -> Optional[str]:
    """Return the human marker when the oracle proves injection, else None.

    All matching is anchored to the *unique canary / concrete effect* carried by
    the probe, so ordinary page content can never satisfy it.
    """
    body = body_raw or ""
    low = body.lower()
    typ = oracle.get("type")
    forbidden = oracle.get("forbidden", [])

    if typ == "contains":
        needles = oracle.get("needles", [])
        if needles and all(n.lower() in low for n in needles) and not any(f.lower() in low for f in forbidden):
            return oracle.get("marker")
    elif typ == "contains_any":
        if any(n.lower() in low for n in oracle.get("needles", [])):
            return oracle.get("marker")
    elif typ == "regex":
        pat = oracle.get("pattern")
        if pat and re.search(pat, body, re.IGNORECASE):
            return oracle.get("marker")
    elif typ == "ssti_arith":
        needle = oracle.get("needle", "")
        # Product must appear AND the raw expression must be gone (proves eval).
        if needle and needle in body and not any(f in body for f in forbidden):
            return oracle.get("marker")
    elif typ == "reflect_unescaped":
        needle = oracle.get("needle", "")
        if needle and needle in body and not any(f in body for f in forbidden):
            return oracle.get("marker")
    return None


def _classify_primitive(title: str, desc: str) -> str:
    t = (title + " " + desc).lower()
    if "command" in t or "exec" in t or "system" in t:
        return "X-1"
    if "ssti" in t or "template" in t:
        return "X-3"
    if "eval" in t or "code load" in t or "dynamic" in t:
        return "X-4"
    if "deserializ" in t:
        return "X-5"
    if "travers" in t and ("write" in t or "save" in t):
        return "W-3"
    if "write" in t or "upload" in t:
        return "W-1"
    if "proto" in t or "pollution" in t:
        return "W-9"
    if "travers" in t or "read" in t:
        return "R-3"
    if "sql" in t:
        return "R-2"
    if "ssrf" in t:
        return "R-4"
    if "auth" in t or "guard" in t or "bypass" in t:
        return "X-13"
    return "X-13"


def _qualify(finding: Dict[str, Any]) -> str:
    """Skill 75 qualification before lab spend.

    Priority adjustments:
    - RCE/deserialization/auth bypass primitives qualify at lower CVSS (5.0 instead of 6.0)
    - DoS-only findings are deprioritized
    - By-design features are filtered out
    """
    if finding.get("qualification") in {
        "QUALIFIED", "LATENT", "NO-BOUNDARY", "MIRROR-ONLY", "PRECONDITIONED", "BY-DESIGN",
    }:
        return finding["qualification"]
    conf = (finding.get("confidence") or "low").lower()
    cvss = float(finding.get("cvss") or 0)
    has_file = bool(finding.get("file"))
    tool = (finding.get("tool") or "").lower()
    desc = (finding.get("description") or "").lower()
    prim = (finding.get("primitive_type") or "").upper()
    high_yield = tool in {
        "sink-first", "guard-alternate-path", "sibling-variant", "pattern-transfer",
        "weak-secret-detection", "cross-file-taint", "taint-proximity",
        # New high-signal tools
        "deserialization-chain", "auth-structural-bypass", "dynamic-dispatch", "sql-concat-audit",
    }

    # By-design features are never qualified for lab spend
    # UNLESS they cross a security boundary (auth bypass, sandbox escape, etc.)
    if (
        (finding.get("by_design") is True or finding.get("primitive_type") in (
            "sandbox_capability", "by_design", "intended_behavior", "package_manager_trust_boundary",
        ))
        and not finding.get("boundary_crossing")
    ):
        # Check for boundary-crossing keywords before disqualifying
        _boundary_kw = (
            "auth bypass", "authentication bypass", "unauthenticated",
            "without credentials", "without auth", "without ticket",
            "sandbox escape", "container escape", "breakout",
            "privilege escalation", "privesc", "bypass sandbox",
            "cross-tenant", "boundary crossing", "outside sandbox",
            "host filesystem", "host network",
        )
        if any(kw in desc for kw in _boundary_kw):
            finding["boundary_crossing"] = True
            # Fall through to normal qualification
        else:
            return "BY-DESIGN"

    if finding.get("status") == "noise" or "fake" in desc:
        return "NO-BOUNDARY"

    # DoS-only deprioritization: cap at LATENT, never QUALIFIED
    _dos_keywords = ("denial of service", "dos ", "resource exhaustion", "infinite loop",
                     "stack overflow", "oom", "memory exhaustion", "billion laughs",
                     "xml bomb", "zip bomb", "regex dos", "redos")
    is_dos_only = any(kw in desc for kw in _dos_keywords) and not any(
        kw in desc for kw in ("rce", "remote code", "code execution", "deserialization", "sql injection")
    )
    if is_dos_only:
        return "LATENT"

    # Priority boost: RCE, deserialization, auth bypass qualify at lower threshold
    is_high_priority = (
        prim.startswith("X-")  # Execute primitives
        or prim in ("AUTH_BYPASS",)
        or any(kw in desc for kw in (
            "deserialization", "unserialize", "readobject", "xstream",
            "command injection", "code injection", "code execution",
            "auth bypass", "authorization bypass", "authentication bypass",
            "remote code execution", "rce", "template injection", "ssti",
            "sql injection", "sqli",
        ))
    )

    if high_yield and has_file and cvss >= 6.0:
        return "QUALIFIED"
    # High-priority primitives qualify at lower CVSS threshold
    if is_high_priority and has_file and cvss >= 5.0:
        return "QUALIFIED"
    if conf in ("high", "medium") and has_file:
        return "QUALIFIED"
    if cvss >= 7.0 and has_file:
        return "QUALIFIED"
    if cvss >= 5.0:
        return "LATENT"
    return "LATENT"


# Public API alias (prefer this over _qualify)
qualify_finding = _qualify


def generate_hypotheses_node(state: AuditState) -> AuditState:
    _graph_checkpoint()
    state["iteration"] += 1
    state["logs"].append(f"[LangGraph Node: generate_hypotheses] Iteration {state['iteration']}")

    lang = state.get("language", "unknown")
    rag_skills = vector_search_skills(
        f"{lang} vulnerability guard bypass sink injection",
        language=lang,
        top_k=5,
    )
    _graph_checkpoint()
    state["logs"].append(f"RAG skills loaded: {len(rag_skills)}")

    candidates = list(state.get("candidate_findings", []))
    graveyard = list(state.get("hypothesis_graveyard", []) or [])
    graveyard_titles = {f.get("title", "") for f in graveyard if f.get("title")}

    try:
        from backend.learned_memory import titles_match as _titles_match
    except Exception:
        def _titles_match(a, b):  # type: ignore
            return (a or "") == (b or "")

    valid_candidates = []
    for f in candidates:
        _graph_checkpoint()
        title = f.get("title", "")
        if title in graveyard_titles or any(_titles_match(title, g) for g in graveyard_titles if g):
            continue
        f["qualification"] = _qualify(f)
        # Skip spending cycles on NO-BOUNDARY / MIRROR-ONLY
        if f["qualification"] in ("NO-BOUNDARY", "MIRROR-ONLY"):
            continue
        if "primitive_type" not in f or not f["primitive_type"]:
            f["primitive_type"] = _classify_primitive(f.get("title", ""), f.get("description", ""))
        if "conviction_level" not in f:
            f["conviction_level"] = 0
        valid_candidates.append(f)

    # Proof-first: QUALIFIED first
    valid_candidates.sort(
        key=lambda x: (
            0 if x.get("qualification") == "QUALIFIED" else 1,
            -float(x.get("cvss") or 0),
            -int(x.get("lead_depth") or 1),
        )
    )
    state["candidate_findings"] = valid_candidates
    state["logs"].append(
        f"Qualified {sum(1 for f in valid_candidates if f.get('qualification')=='QUALIFIED')} / "
        f"{len(valid_candidates)} candidates (graveyard skipped {len(candidates)-len(valid_candidates)})."
    )
    _graph_checkpoint()
    return state


def execute_lab_test_node(state: AuditState) -> AuditState:
    """Proof-first lab attacks on QUALIFIED leads with class-specific probes."""
    _graph_checkpoint()
    state["logs"].append(
        f"[LangGraph Node: execute_lab_test] Probing lab at {state.get('lab_url', 'N/A')}"
    )
    lab_url = state.get("lab_url", "")
    dest = Path(state.get("dest_path", "."))

    # Fast reachability pre-check: a lab_url can point to a running container that
    # exposes NO HTTP surface (e.g. a C/C++ CLI or library target like microCI).
    # Without this, the per-candidate probe matrix (candidates x paths x params)
    # spends the entire time budget on dead TCP connects/timeouts and the whole
    # LangGraph gate times out. One cheap probe lets us fall back to static-only.
    if lab_url:
        _pre = _probe_lab_endpoint(lab_url, "/")
        _graph_checkpoint()
        if _pre.get("status", 0) == 0:
            state["logs"].append(
                f"Lab at {lab_url} has no responsive HTTP surface; "
                f"skipping HTTP probe matrix (static-only conviction)."
            )
            lab_url = ""

    # Stall-breaker: on late iterations, only attack top QUALIFIED
    iteration = state.get("iteration", 1)
    candidates = state.get("candidate_findings", [])
    if iteration >= 2:
        qualified = [f for f in candidates if f.get("qualification") == "QUALIFIED"]
        work = qualified[:12] if qualified else candidates[:8]
    else:
        work = candidates[:20]

    for f in work:
        _graph_checkpoint()
        file_path = f.get("file", "")
        exists = bool(file_path and (dest / file_path).exists()) or bool(f.get("title"))

        reachable = False
        triggered = False
        evidence = []

        if lab_url:
            # Canary-carrying probes with sound oracles. A hit proves the effect
            # of OUR injected payload (echoed token / evaluated arithmetic /
            # passwd row / DB error / unescaped reflection), never incidental
            # page content. Bound work: top paths x probes.
            probes = _build_class_probes(f)
            _graph_checkpoint()
            for path in _extract_probe_paths(f)[:8]:
                _graph_checkpoint()
                for pr in probes[:24]:
                    _graph_checkpoint()
                    probe = _probe_lab_endpoint(
                        lab_url, path,
                        params=pr.get("params"), method=pr.get("method", "GET"),
                        data=pr.get("data"), json_body=pr.get("json"),
                    )
                    _graph_checkpoint()
                    if probe.get("status", 0) > 0:
                        reachable = True
                    marker = _oracle_check(pr["oracle"], probe.get("body", ""))
                    if marker:
                        triggered = True
                        evidence.append({
                            "path": path,
                            "method": pr.get("method", "GET"),
                            "params": pr.get("params"),
                            "data": pr.get("data") or pr.get("json"),
                            "status": probe.get("status"),
                            "oracle": marker,
                            "oracle_type": pr["oracle"].get("type"),
                            "primitive": pr["oracle"].get("primitive"),
                            "snippet": (probe.get("body") or "")[:200],
                        })
                        break
                if triggered:
                    break
        else:
            # No lab: static evidence can only reach L1
            reachable = exists or f.get("qualification") == "QUALIFIED"

        if exists and reachable:
            f["conviction_level"] = max(f.get("conviction_level", 0), 1)
        if triggered:
            f["conviction_level"] = max(f.get("conviction_level", 0), 2)
            f["lab_evidence"] = evidence
            f["proven_in_lab"] = True
        elif not lab_url:
            # No lab: static evidence may mark QUALIFIED candidates but MUST NOT
            # elevate to L2/trigger  - that caused mass false CONFIRMED findings.
            f["static_candidate_only"] = True
            f["proven_in_lab"] = False
            # Cap conviction at L1 (hypothesis) without dynamic PoC
            if f.get("conviction_level", 0) >= 2 and not f.get("lab_evidence"):
                f["conviction_level"] = 1

    _graph_checkpoint()
    return state


def evaluate_gates_node(state: AuditState) -> AuditState:
    _graph_checkpoint()
    state["logs"].append("[LangGraph Node: evaluate_gates] Evaluating validity gates (lab PoC required).")
    from backend.proof_gates import finalize_finding_status, has_lab_proof

    validated = list(state.get("validated_findings", []))
    graveyard = list(state.get("hypothesis_graveyard", []))
    cvss_threshold = state.get("recon_summary", {}).get("cvss_threshold", 7.0)

    for f in state.get("candidate_findings", []):
        _graph_checkpoint()
        summary = finalize_finding_status(f, cvss_threshold=float(cvss_threshold or 7.0))
        _graph_checkpoint()
        gates = summary["gates"]

        # The graph may be exercised directly by a trusted runner before the
        # durable receipt is attached (and a few callers use it as an internal
        # conviction signal).  Preserve that runtime observation in the graph's
        # *validated* set, but mark it explicitly receipt-pending and keep it
        # unreportable.  The publication path still calls ``has_lab_proof`` and
        # will refuse every row without a signed, target-bound receipt.
        evidence = f.get("lab_evidence")
        if isinstance(evidence, dict):
            evidence = [evidence]
        runtime_observed = bool(
            isinstance(evidence, list)
            and any(isinstance(item, dict) and str(item.get("path") or "").strip() for item in evidence)
            # ``execute_lab_test_node`` may clear the convenience flag when a
            # direct caller has no HTTP URL, but a concrete path/evidence row
            # with conviction >= 2 is still useful as an internal signal.
            and (f.get("proven_in_lab") is True or int(f.get("conviction_level") or 0) >= 2)
        )
        core_without_receipt = all(
            gates.get(k)
            for k in ("existence", "reachability", "hallucination", "cvss", "qualification")
        )

        # Only lab-proven findings enter validated_findings as confirmable
        if summary["confirmed"] or (runtime_observed and core_without_receipt):
            if runtime_observed and not summary["confirmed"]:
                f["validation_pending_receipt"] = True
                # This is an internal graph result, not a publication record.
                # Preserve the historical graph contract for callers that use
                # ``report_eligible`` as a conviction signal, while the
                # persistence boundary unconditionally rechecks the signed
                # receipt and strips this provisional flag.
                f["status"] = "report-eligible"
                f["report_eligible"] = bool(gates.get("cvss"))
            if not any(v.get("title") == f.get("title") for v in validated):
                validated.append(f)
        elif not gates.get("existence") and not gates.get("hallucination"):
            if not any(v.get("title") == f.get("title") for v in graveyard):
                f["graveyard_reason"] = "failed_basic_gates"
                graveyard.append(f)
        elif f.get("qualification") == "QUALIFIED" and not has_lab_proof(f):
            # Keep as candidate  - not graveyard, not confirmed
            f["status"] = "unproven"
            f["report_eligible"] = False

    state["validated_findings"] = validated
    state["hypothesis_graveyard"] = graveyard
    pending_receipts = sum(1 for f in validated if f.get("validation_pending_receipt"))
    state["logs"].append(
        f"Validation complete: {len(validated)} runtime-validated ({pending_receipts} receipt-pending), "
        f"{len(graveyard)} graveyarded (QUALIFIED without PoC stay unproven candidates)."
    )
    _graph_checkpoint()
    return state


def should_continue(state: AuditState) -> str:
    _graph_checkpoint()
    if state["iteration"] >= state["max_iterations"]:
        return "end"
    validated_titles = {f.get("title") for f in state.get("validated_findings", [])}
    graveyard_titles = {f.get("title") for f in state.get("hypothesis_graveyard", [])}
    unvalidated = [
        f for f in state.get("candidate_findings", [])
        if f.get("title") not in validated_titles
        and f.get("title") not in graveyard_titles
        and f.get("qualification") == "QUALIFIED"
    ]
    if unvalidated:
        return "continue"
    return "end"


def build_phase2_langgraph() -> StateGraph:
    workflow = StateGraph(AuditState)
    workflow.add_node("generate_hypotheses", generate_hypotheses_node)
    workflow.add_node("execute_lab_test", execute_lab_test_node)
    workflow.add_node("evaluate_gates", evaluate_gates_node)
    workflow.set_entry_point("generate_hypotheses")
    workflow.add_edge("generate_hypotheses", "execute_lab_test")
    workflow.add_edge("execute_lab_test", "evaluate_gates")
    workflow.add_conditional_edges(
        "evaluate_gates",
        should_continue,
        {"continue": "generate_hypotheses", "end": END},
    )
    return workflow.compile()


def run_phase2_langgraph_agent(
    repo_id: int,
    dest: Path,
    recon_summary: Dict[str, Any],
    candidate_findings: List[Dict[str, Any]],
    settings: Any = None,
    max_iterations: int = 2,
    hypothesis_graveyard: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    _graph_checkpoint()
    app = build_phase2_langgraph()
    lab_status = recon_summary.get("lab_status", {})
    lab_url = lab_status.get("url", "") if isinstance(lab_status, dict) else ""

    initial_state: AuditState = {
        "repo_id": repo_id,
        "dest_path": str(dest),
        "language": recon_summary.get("language", "unknown"),
        "recon_summary": recon_summary,
        "phase2_plan": recon_summary.get("phase2_plan", {}),
        "candidate_findings": candidate_findings,
        "validated_findings": [],
        "hypothesis_graveyard": list(hypothesis_graveyard or recon_summary.get("hypothesis_graveyard") or []),
        "iteration": 0,
        "max_iterations": max_iterations,
        "logs": [],
        "lab_url": lab_url,
    }

    final_state = app.invoke(initial_state)
    _graph_checkpoint()
    return {
        "validated_findings": final_state.get("validated_findings", []),
        "logs": final_state.get("logs", []),
        "iterations": final_state.get("iteration", 0),
        "graveyard": final_state.get("hypothesis_graveyard", []),
    }
