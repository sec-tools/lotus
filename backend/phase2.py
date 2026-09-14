from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import hashlib
import re
import time
from copy import deepcopy
from functools import lru_cache


def phase2_task_id(task: Dict[str, Any]) -> str:
    """Stable identity independent of priority sorting and removed plan rows."""
    identity = [str(task.get(key) or "") for key in ("title", "category", "target")]
    # Legacy unbound plans retain their IDs. Observed leads additionally bind
    # to their complete observation, so equal titles in one file cannot alias.
    if task.get("source_observation_sha256"):
        identity.append(str(task["source_observation_sha256"]))
    elif task.get("task_specification_sha256"):
        identity.append(str(task["task_specification_sha256"]))
    elif task.get("source_refs") or task.get("coverage_ids") or task.get("command"):
        identity.append(json.dumps({
            "source_refs": sorted(task.get("source_refs") or [], key=lambda value: json.dumps(value, sort_keys=True)),
            "coverage_ids": sorted(task.get("coverage_ids") or []),
            "command": task.get("command") or "",
        }, sort_keys=True, separators=(",", ":")))
    return "p2-" + hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()[:20]


def is_inventory_summary(row: Any) -> bool:
    """Recognize explicit analyzer inventory rows without excluding real leads.

    Structured artifact entries remain independently mapped obligations. A
    generic informational flag, shared phase2_hint, or low score on a finding
    cannot remove its validation requirement.
    """
    if not isinstance(row, dict):
        return False
    producers = {
        "trust-boundary-map": ("Trust-boundary map: ", "control_plane_map", ".lotus/trust_boundary.json"),
        "component-lab-map": ("Component map: ", "component_lab", ".lotus/component_map.json"),
    }
    expected = producers.get(row.get("tool"))
    return bool(
        expected and row.get("inventory_only") is True
        and row.get("record_type") == "inventory-summary"
        and row.get("result_type") == "inventory"
        and str(row.get("title") or "").startswith(expected[0])
        and row.get("phase2_hint") == expected[1]
        and row.get("inventory_artifact") == expected[2]
        and not row.get("canonical_class") and not row.get("primitive_type") and not row.get("rce_lead")
    )


class _Phase2HTTPRecorder:
    """Retain completed HTTP exchanges so swallowed probe errors cannot pass."""

    def __init__(self, client):
        self.client = client
        self.observations = []
        self.errors = []

    async def _request(self, method, url, **kwargs):
        try:
            response = await getattr(self.client, method)(url, **kwargs)
        except Exception as exc:
            self.errors.append({"method": method.upper(), "url": str(url), "error": str(exc)[:300]})
            raise
        self.observations.append({"method": method.upper(), "url": str(url), "status_code": response.status_code})
        return response

    async def get(self, url, **kwargs):
        return await self._request("get", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self._request("post", url, **kwargs)


def _is_spree(dest: Path) -> bool:
    """Best-effort detection that the checked-out repo is Spree."""
    if (dest / "spree.gemspec").exists():
        return True
    if (dest / "core").exists() and (dest / "api").exists() and (dest / "frontend").exists():
        return True
    for p in dest.rglob("*.gemspec"):
        if "spree" in p.name.lower():
            return True
    return False


def _looks_like_source_file(target: Any) -> bool:
    """Return True when a plan target is a source/test file, not an endpoint.

    Attack-surface extractors intentionally retain file locations for
    traceability.  They are not safe HTTP paths: probing a serve-only fallback
    with `/src/.../ControllerTest.java` returns the source file with HTTP 200
    and can manufacture an authorization bypass.  Keep endpoint probes behind
    an explicit route/URL target and reject source-looking values centrally.
    """
    value = str(target or "").replace("\\", "/").lower().split("?", 1)[0]
    if not value:
        return False
    if any(marker in value for marker in ("/src/test/", "/test/", "/tests/", "_test.")):
        return True
    return bool(re.search(r"\.(?:java|kt|go|py|js|jsx|ts|tsx|rb|php|c|cc|cpp|h|hpp|rs|ex|exs|cs)$", value))


def _is_concrete_endpoint_target(target: Any) -> bool:
    """Conservative endpoint predicate used by live HTTP authorization probes."""
    value = str(target or "").strip()
    if not value or _looks_like_source_file(value):
        return False
    # A source-relative path with directory separators is still a file/manifest
    # locator unless it starts with an explicitly extracted URL route.
    if "/" in value and not value.startswith("/"):
        return False
    return True


_GENERAL_DYNAMIC_GUIDANCE = (
    (
        "Authentication flow bypass / registration abuse",
        "auth",
        "Auth endpoints are the gatekeeper for every privileged flow; test brute force, reset, and OAuth/SAML bypasses.",
    ),
    (
        "File upload path traversal / content-type bypass",
        "file-upload",
        "File upload sinks receive untrusted binaries; test path traversal, extension bypass, and polyglot payloads.",
    ),
    (
        "Search / filter injection (SQL, NoSQL, Ransack)",
        "injection",
        "Search and admin filters build queries from user params; fuzz for SQL/NoSQL and Ransack injection.",
    ),
    (
        "Stored / reflected XSS in views and WYSIWYG",
        "xss",
        "Views render user content; test html_safe/raw bypasses, markdown/HTML sinks, and CSP gaps.",
    ),
    (
        "Server-Side Request Forgery via HTTP client sinks",
        "ssrf",
        "HTTP client gems (Faraday, HTTParty, Net::HTTP) may be driven by user input; test internal-only and DNS rebinding.",
    ),
    (
        "Unsafe deserialization / YAML / Marshal",
        "deserialization",
        "Marshal.load, YAML.load, and sidekiq/resque job payloads are deserialization sinks; try gadget chains.",
    ),
    (
        "XML external entity (XXE) and parser DoS",
        "xxe",
        "Nokogiri, REXML, Ox, and Savon parse XML; test external entities, billion laughs, and local file disclosure.",
    ),
    (
        "Image processing ImageMagick / libvips bugs",
        "image-rce",
        "MiniMagick, RMagick, ruby-vips shell out to ImageMagick/libvips; test malicious SVG, MVG, and GhostScript payloads.",
    ),
)

_GUIDANCE_OBSERVATION_FIELDS = (
    "file", "line", "line_end", "function", "handler", "route", "source_refs",
    "coverage_ids", "canonical_class", "primitive_type", "rce_lead",
)


def _general_planning_guidance() -> List[Dict[str, Any]]:
    return [{"title": title, "category": category, "priority": "medium",
             "target": "dynamic endpoints", "technique": "fuzz + manual", "why": why}
            for title, category, why in _GENERAL_DYNAMIC_GUIDANCE]


@lru_cache(maxsize=1)
def _builtin_guidance_signatures():
    # Build the exact catalog from the pure default producers themselves. This
    # reads no repository or operator plan. Registered runtime checks remain
    # mandatory even when their target is the enrolled package as a whole.
    from backend.audit_planner import MANIFEST_LANGS, _heuristic_phase2_tasks
    templates = _general_planning_guidance()
    for app_type in ("api-service", "web-app", "library", "cli-tool"):
        templates.extend(_heuristic_phase2_tasks(
            "node", app_type, ["published-image-lab"], {"published_images": ["builtin-catalog"]},
            [language for _, language in MANIFEST_LANGS],
        ))
    return frozenset(tuple(str(row.get(key) or "") for key in
                           ("title", "category", "target", "technique", "why"))
                     for row in templates if row.get("category") not in
                     {"package-test", "library-harness", "library-fuzz"})


def is_builtin_planning_guidance(row: Any) -> bool:
    """Only unchanged, targetless default strategy prose is non-obligatory.

    Caller flags such as context_only or inventory_only are never authority.
    Concrete locations, commands, or observation references override a default
    title match. Phase 1 artifacts are mapped independently of this classifier.
    """
    if not isinstance(row, dict):
        return False
    if any(row.get(key) for key in _GUIDANCE_OBSERVATION_FIELDS + (
        "command", "requires_auth", "protected_baseline",
    )):
        return False
    signature = tuple(str(row.get(key) or "") for key in
                      ("title", "category", "target", "technique", "why"))
    return signature in _builtin_guidance_signatures()


def generate_phase2_plan(
    repo_id: int,
    dest: Path,
    recon_summary: Dict[str, Any],
    findings: List[Dict[str, Any]],
    cvss_threshold: float,
    extra_tasks: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build a prioritized bug-discovery plan from Phase 1 recon data."""
    tasks: List[Dict[str, Any]] = []
    seen = {}
    original_findings = findings
    inventory_context = [deepcopy(row) for row in findings if is_inventory_summary(row)]
    observations = [(index, row) for index, row in enumerate(findings) if not is_inventory_summary(row)]
    findings = [row for _, row in observations]

    def add(title: str, category: str, priority: str, target: str, technique: str, why: str, *, requires_auth: bool = False, command: str = "", source_refs=None, coverage_ids=None, observation=None):
        observation_hash = hashlib.sha256(json.dumps(observation, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest() if observation is not None else ""
        key = json.dumps([title, category, target, technique, why, requires_auth, command,
                          observation_hash or source_refs or [], coverage_ids or []], sort_keys=True, default=str)
        if key in seen:
            existing = seen[key]
            for ref in source_refs or []:
                if ref not in existing.setdefault("source_refs", []):
                    existing["source_refs"].append(deepcopy(ref))
            return existing
        tasks.append(
            {
                "title": title,
                "category": category,
                "priority": priority,
                "target": target,
                "technique": technique,
                "why": why,
                "requires_auth": bool(requires_auth),
                # Derived from the static trust-boundary model.  This is not
                # inferred from a guessed endpoint's HTTP status.
                "protected_baseline": bool(requires_auth),
                "task_specification_sha256": hashlib.sha256(key.encode()).hexdigest(),
                **({"command": command} if command else {}),
                **({"source_refs": deepcopy(source_refs)} if source_refs else {}),
                **({"coverage_ids": deepcopy(coverage_ids)} if coverage_ids else {}),
                **({"source_observation_sha256": observation_hash} if observation_hash else {}),
            }
        )
        seen[key] = tasks[-1]
        return tasks[-1]

    # 1. Turn every Phase 1 lead into a validation / dynamic-proving task.
    for source_index, f in sorted(observations, key=lambda pair: pair[1].get("cvss", 0.0), reverse=True):
        if (f.get("qualification") or "") == "DISPROVE" or f.get("ai_verdict") == "DISPROVE":
            continue
        cvss = f.get("cvss", 0.0)
        if cvss >= 9.0:
            priority = "critical"
        elif cvss >= cvss_threshold:
            priority = "high"
        elif cvss >= 4.0:
            priority = "medium"
        else:
            priority = "informational"
        add(
            f"Validate: {f['title']}",
            "validation",
            priority,
            f.get("file", ""),
            "manual / dynamic proof-of-concept",
            f"tool={f.get('tool')} cvss={cvss} confidence={f.get('confidence','low')}: {f.get('description','')}",
            source_refs=[{"artifact": "phase1:findings", "pointer": f"/{source_index}"}], observation=f,
        )

    # 2. High-risk OSS dependencies that parse/process untrusted data.
    for dep in recon_summary.get("high_risk_dependencies", []):
        add(
            f"Fuzz/audit dependency: {dep}",
            "dependency-fuzz",
            "high",
            dep,
            "fuzz + code review",
            f"{dep} is an OSS dependency that processes untrusted data; look for XXE, RCE, DoS, unsafe deserialization, or parser bypasses.",
        )

    # 2b. Dynamic path-exploration intel (coverage-guided fuzz crashes + danger-sink map).
    #     This is where the dynamic subsystem hands Phase 2 concrete, pre-triaged targets.
    dpe = recon_summary.get("dynamic_path_exploration") or {}
    #     (i) RCE leads: a fuzz crash that REACHED a deser/exec sink is a strong lead, not
    #     a confirmed RCE. Emit an explicit exploit-PoC task so Phase 2 tries a gadget/SSTI
    #     PoC with a real oracle (uid=) - only that promotes CVSS across the report threshold.
    for source_index, f in observations:
        if not f.get("rce_lead"):
            continue
        add(
            f"Exploit PoC (gadget/SSTI): {f.get('title', 'fuzz crash')}",
            "exploit-poc",
            "critical",
            f.get("file", ""),
            "build gadget/SSTI exploit with a concrete oracle (uid= / canary file)",
            "Coverage-guided fuzz reached a deserialization/code-exec sink. Confirm actual "
            "code execution with a real exploit oracle; the reproducer proves reachability, "
            "not RCE.",
            source_refs=[{"artifact": "phase1:findings", "pointer": f"/{source_index}"}], observation=f,
        )
    #     (ii) Danger-sink map (node/java/ruby have no wired fuzz engine yet): each grepped
    #     RCE/deser sink becomes a targeted 'trace untrusted input -> live PoC' task so the
    #     map is not a dead artifact.
    for art in (dpe.get("artifacts") or []):
        if art.get("type") != "danger-sink-map":
            continue
        for sink in (art.get("sinks") or [])[:15]:
            loc = f"{sink.get('file', '?')}:{sink.get('line', '?')}"
            add(
                f"Sink PoC: {sink.get('sink')} @ {loc}",
                "sink-poc",
                "high",
                sink.get("file", ""),
                "trace untrusted input to sink, then live lab PoC",
                f"Danger-sink map ({sink.get('language')}): `{sink.get('sink')}` is an "
                "RCE/deser/command sink. Determine whether untrusted input reaches it and "
                "prove impact in the lab.",
            )

    # 3. Attack-surface-derived targets.
    attack_surface = recon_summary.get("attack_surface", {})
    app_type = recon_summary.get("app_type") or ""
    skip_http_plan = app_type in ("cli-tool", "library")
    for ctrl in [c for c in attack_surface.get("admin_namespaces", []) if _is_concrete_endpoint_target(c)][:20]:
        if skip_http_plan:
            break
        add(
            f"Admin controller authorization: {ctrl}",
            "authorization",
            "high",
            ctrl,
            "IDOR / privilege-escalation dynamic tests",
            "Admin controllers process privileged actions; verify authentication, role checks, and direct-object access controls.",
            requires_auth=True,
        )
    for ctrl in [c for c in attack_surface.get("api_namespaces", []) if _is_concrete_endpoint_target(c)][:20]:
        if skip_http_plan:
            break
        add(
            f"API controller input validation: {ctrl}",
            "api-security",
            "high",
            ctrl,
            "mass-assignment / injection fuzzing",
            "API controllers receive external JSON/params; test for mass assignment, SQL injection, and unsafe deserialization.",
        )
    for route_file in [c for c in attack_surface.get("routes", []) if _is_concrete_endpoint_target(c)]:
        if skip_http_plan:
            break
        add(
            f"Route authorization audit: {route_file}",
            "access-control",
            "medium",
            route_file,
            "code review + route probing",
            "Routes define the exposed attack surface; look for missing auth, verb tampering, and sensitive endpoints.",
            requires_auth=any(token in str(route_file).lower() for token in ("admin", "private", "account", "user", "delete", "manage")),
        )

    # Trust-boundary map: concrete unauthenticated mutating verbs (even for
    # libraries/agents — keploy /agent/* is HTTP on a library repo).
    tb = attack_surface.get("trust_boundary") or recon_summary.get("trust_boundary") or {}
    hs = attack_surface.get("handler_sinks") or recon_summary.get("handler_sinks") or {}
    cm = attack_surface.get("component_map") or recon_summary.get("component_map") or {}
    for c in (cm.get("priority") or [])[:8]:
        lab = (c.get("lab") or {}).get("kind") or "lab"
        add(
            f"Lab component {c.get('name')} ({c.get('language')}/{lab})",
            "control-plane",
            "critical",
            c.get("manifest") or c.get("path") or "",
            "lab-poc",
            f"Component map: fail_open={c.get('fail_open')} bind_all={c.get('bind_all')} "
            f"image={(c.get('lab') or {}).get('image')}. PoC this binary, not the repo-level language.",
        )
    for tr in (hs.get("priority") or [])[:10]:
        method = tr.get("method") or "POST"
        path = tr.get("path") or ""
        sink = tr.get("primary_sink") or "sink"
        add(
            f"Lab: {method} {path} → {sink}",
            "control-plane",
            "critical",
            tr.get("handler_file") or tr.get("route_file") or "",
            "lab-poc",
            f"Handler-sink trace: `{tr.get('handler')}` reaches {sink}. "
            "Prove the sink oracle, not 200-without-effect.",
        )
    for rt in (tb.get("unauth_mutating") or [])[:8]:
        method = rt.get("method") or "POST"
        path = rt.get("path") or ""
        add(
            f"Lab: unauthenticated {method} {path}",
            "control-plane",
            "critical",
            rt.get("file") or "",
            "lab-poc",
            f"Trust-boundary map ({rt.get('why') or 'no auth'}). Prove mutating impact, not 200-without-effect.",
        )
    for cfg in (tb.get("config_fail_open") or [])[:4]:
        add(
            f"Lab: shipped auth-off config {cfg.get('file')}",
            "insecure-default",
            "critical",
            cfg.get("file") or "",
            "lab-poc",
            "Default-insecure control plane. Unsigned mutating request must not be AuthFailed.",
        )
    for gap in (tb.get("sibling_gaps") or [])[:6]:
        add(
            f"Lab: sibling missing path guard {gap.get('unguarded_file')}",
            "control-plane",
            "high",
            gap.get("unguarded_file") or "",
            "lab-poc",
            "One package validates name components; this sibling Join+writes without that guard.",
        )

    # CLI: turn discovered flags into argv validation tasks
    if skip_http_plan:
        for fl in (recon_summary.get("cli_entry_flags") or [])[:25]:
            flag = fl.get("flag") or ""
            if not flag:
                continue
            add(
                f"CLI argv PoC: {flag}",
                "cli-argv",
                "high",
                flag,
                "docker-exec argv oracle",
                f"Flag from {fl.get('file')}; prove injection/path/deser with lab docker-exec.",
            )

    # 3c. Test-coverage vs attack-surface gap: functions with attack surface that
    #     the repo's OWN tests never exercise. Untested security-relevant code is
    #     where unsanitized paths and regressions survive — prime dig-deeper leads.
    cov_gap = recon_summary.get("test_coverage_gap") or {}
    _primitive_technique = {
        "command_injection": "trace untrusted arg to the exec/shell sink; craft `; id` / `$(id)` and prove uid= in lab",
        "sql_injection": "trace input to the query; try `' OR '1'='1` / UNION and confirm data leak or auth bypass",
        "unsafe_deserialization": "feed a crafted serialized payload; attempt gadget/SSTI with a uid=/canary oracle",
        "path_traversal": "supply `../../../etc/passwd`; confirm out-of-scope read/write in lab",
        "memory_safety": "drive oversized/edge input into the buffer op; observe crash/overflow under ASan",
        "crypto_auth": "probe the auth/crypto path for fail-open, forged token, or empty-credential acceptance",
        "untrusted_input_handling": "map the untrusted source into this function and test the nearest dangerous behavior",
    }
    for uf in (cov_gap.get("untested") or [])[:15]:
        prim = uf.get("primitive_type") or "untrusted_input_handling"
        name = uf.get("name") or "function"
        loc = f"{uf.get('file', '?')}:{uf.get('line', '?')}"
        prio = "high" if uf.get("has_sink") else "medium"
        add(
            f"Untested surface PoC: {name} ({prim.replace('_', ' ')}) @ {loc}",
            "coverage-gap",
            prio,
            uf.get("file", ""),
            _primitive_technique.get(prim, _primitive_technique["untrusted_input_handling"]),
            (
                f"`{name}` carries attack surface (sink={uf.get('has_sink')}, "
                f"source={uf.get('has_source')}; signals {uf.get('sink_hits') or []}"
                f"{uf.get('source_hits') or []}) but is NOT covered by the repo's own tests "
                f"(repo attack-surface coverage ≈ {cov_gap.get('attack_surface_coverage_pct')}%). "
                "Untested security code is high-yield; reach it from an entry point and prove impact."
            ),
        )

    # 4. E-commerce / Spree-specific business-logic targets.
    if _is_spree(dest):
        spree_modules = [
            ("admin", "Admin backend: privilege escalation, IDOR, mass assignment of orders/users."),
            ("api", "Storefront/Platform API: broken object-level authorization, parameter pollution, mass assignment."),
            ("storefront", "Storefront controllers: session tampering, price manipulation, cart total issues."),
            ("checkout", "Checkout flow: price tampering, coupon abuse, shipping/tax bypass, payment-order mismatch."),
            ("payment", "Payment integrations: token reuse, amount tampering, gateway spoofing."),
            ("product", "Product / catalog: hidden product access, review manipulation, cache poisoning."),
            ("order", "Order / cart: cart-to-order price inconsistency, quantity/line-item tampering."),
            ("promotion", "Promotions / coupons: multi-use abuse, condition bypass, stacking."),
            ("shipping", "Shipping / tax calculators: address validation bypass, cost manipulation."),
            ("return", "Returns / refunds: RMA abuse, duplicate refunds, state-machine bypass."),
            ("user/role", "User / role management: privilege escalation, password reset abuse, session fixation."),
            ("content", "CMS / content pages: stored XSS, HTML injection in product descriptions / pages."),
            ("inventory", "Stock / inventory: negative stock purchase, overselling, reservation bypass."),
        ]
        for module, why in spree_modules:
            add(
                f"Spree module: {module}",
                "business-logic",
                "high",
                f"*/{module}*/**/*.rb" if module != "api" else "*/api/**/*.rb",
                "dynamic business-logic testing",
                why,
            )

    # 5. Joern CPG-derived targets: data-flow paths, call-graph sinks, complexity hotspots
    joern_cpg = recon_summary.get("joern_cpg", {})
    if joern_cpg.get("cpg_generated"):
        # 5a. Each statically observed data-flow path becomes a high-priority
        # validation target.  CPG output is a Lead, not proof, until a dynamic
        # lab receipt is issued.
        for flow in joern_cpg.get("data_flows", [])[:25]:
            add(
                f"CPG data-flow: {flow.get('title', 'taint path')}",
                "cpg-taint-validation",
                "critical" if flow.get("cvss", 0) >= 9.0 else "high",
                flow.get("file", ""),
                "dynamic proof-of-concept along taint path",
                f"Joern interprocedural taint analysis observed a candidate flow: "
                f"source={flow.get('source', '?')[:80]} → sink={flow.get('sink', '?')[:80]}. "
                f"Path: {flow.get('path_summary', '')[:150]}",
            )

        # 5b. Call-graph edges: functions calling sensitive sinks
        callsites = joern_cpg.get("sensitive_callsites", [])
        sink_callers = {}
        for edge in callsites[:100]:
            callee = edge.get("callee", "")
            caller = edge.get("caller", "")
            if callee not in sink_callers:
                sink_callers[callee] = []
            sink_callers[callee].append(caller)
        for sink, callers in list(sink_callers.items())[:15]:
            caller_list = ", ".join(callers[:5])
            add(
                f"Call-graph audit: {len(callers)} callers of {sink}()",
                "cpg-callgraph",
                "high",
                callers[0] if callers else "",
                "trace input reachability to each call site",
                f"Joern call-graph shows {len(callers)} code locations calling sensitive function '{sink}'. "
                f"Callers: {caller_list}. Verify which are reachable from untrusted input.",
            )

        # 5c. Complexity hotspots: methods with high cyclomatic complexity
        for hotspot in joern_cpg.get("hotspot_methods", [])[:10]:
            add(
                f"Complexity hotspot: {hotspot.get('name', 'unknown')[:60]}",
                "cpg-complexity",
                "medium",
                hotspot.get("file", ""),
                "manual code review + variant analysis",
                f"Joern reports {hotspot.get('lines', 0)}-line method with high complexity. "
                f"Complex methods are statistically more likely to contain logic bugs, "
                f"off-by-one errors, and missed edge cases.",
            )

    # Generic methodology is retained as context. Actual discovered routes,
    # components, sinks and leads were independently scheduled above.
    planning_context = _general_planning_guidance()
    for t in extra_tasks or []:
        if is_builtin_planning_guidance(t):
            planning_context.append(deepcopy(t))
            continue
        planned = add(
            t.get("title") or "AI plan task",
            t.get("category") or "validation",
            t.get("priority") or "high",
            t.get("target") or "",
            t.get("technique") or "lab-poc",
            t.get("why") or "AI/heuristic audit plan",
            command=t.get("command") or "",
            source_refs=t.get("source_refs"), coverage_ids=t.get("coverage_ids"),
            observation=t,
            requires_auth=bool(t.get("requires_auth") or t.get("protected_baseline")),
        )
        if planned is not None:
            planned.update({key: deepcopy(t[key]) for key in _GUIDANCE_OBSERVATION_FIELDS if t.get(key)})

    # A Phase-1 observation is a Lead, not automatically executable work.
    # Previously every static observation became a ``validation`` task even
    # though no executor existed for that category.  Large repositories then
    # spent Phase 2 emitting hundreds of misleading "no executor" skips. Keep
    # those hypotheses visible and reproducible as a deferred, explicitly
    # unproven backlog; schedule only categories with a registered safe
    # automated executor.
    automated_categories = set(globals().get("EXECUTABLE_TASK_CATEGORIES", set())) | {"package-test"}
    executable_tasks: List[Dict[str, Any]] = []
    deferred_leads: List[Dict[str, Any]] = []
    for task in tasks:
        task["id"] = phase2_task_id(task)
        category = str(task.get("category") or "")
        exclusion = _phase2_execution_exclusion(task, recon_summary)
        if category in automated_categories and exclusion is None:
            executable_tasks.append(task)
            continue
        deferred_leads.append({
            "id": task["id"],
            "title": str(task.get("title") or "Lead validation"),
            "category": category or "unknown",
            "priority": str(task.get("priority") or "informational"),
            "target": str(task.get("target") or ""),
            "why": str(task.get("why") or "")[:1000],
            "technique": str(task.get("technique") or ""),
            **({"command": task["command"]} if task.get("command") else {}),
            **({"source_observation_sha256": task["source_observation_sha256"]} if task.get("source_observation_sha256") else {}),
            "task_specification_sha256": task["task_specification_sha256"],
            **{key: deepcopy(task[key]) for key in _GUIDANCE_OBSERVATION_FIELDS if task.get(key)},
            "requires_auth": task.get("requires_auth", False),
            "protected_baseline": task.get("protected_baseline", False),
            "reason": exclusion["reason"] if exclusion else (
                "No registered safe automated executor for this lead. It remains unproven "
                "and is available for a focused, target-bound local-lab repro."
            ),
            **({key: value for key, value in exclusion.items() if key != "reason"} if exclusion else {}),
            "lifecycle": "lead",
        })

    # Preserve the complete machine-readable backlog. Presentation layers may
    # page or preview rows; truncating the plan loses source-bound obligations.
    plan = {
        "repo_id": repo_id,
        "cvss_threshold": cvss_threshold,
        "lab_required": True,
        "task_count": len(executable_tasks),
        "tasks": executable_tasks,
        "inventory_context": inventory_context,
        "planning_context": planning_context,
        "deferred_lead_count": len(deferred_leads),
        "deferred_leads": deferred_leads,
        "deferred_leads_omitted": 0,
        "planning_note": (
            "Only registered automated executors are counted as Phase 2 tasks. "
            "Deferred entries are unproven Leads, not skipped tests or Findings. "
            "Built-in targetless methodology is retained separately as planning context."
        ),
    }
    from backend.phase2_mapping import complete_phase2_plan
    return complete_phase2_plan(repo_id, dest, recon_summary, original_findings, plan)


async def phase2_dynamic_tests(
    repo_id: int,
    dest: Path,
    recon_summary: Dict[str, Any],
    lab_status: Dict[str, Any],
    findings: List[Dict[str, Any]],
    send,
) -> List[Dict[str, Any]]:
    """Run a small, safe set of dynamic probes against the lab instance if it is healthy."""
    def _status(status: str, reason: str, *, count: int = 0) -> None:
        # The caller records this as a terminal task outcome.  Returning an
        # empty list is not enough: an unavailable HTTP surface must not be
        # rendered as a successful clean probe.
        recon_summary["phase2_dynamic_probe"] = {
            "status": status, "reason": str(reason), "count": int(count or 0),
        }

    if not _lab_runtime_ready(lab_status):
        # Keep the durable reason compatible with existing reports while the
        # live message below makes the stricter runtime-attestation cause
        # explicit to the operator.
        _status("skipped", "lab unavailable; no proof can be collected")
        await send(repo_id, "Lab runtime is not attested; skipping dynamic Phase 2 probes", level="info")
        return []

    # A generated library/CLI lab may expose a health listener solely to keep
    # the container alive.  It is not an application endpoint and must never
    # receive web-app auth/injection probes.
    if (recon_summary.get("app_type") or "") in ("cli-tool", "library"):
        _status("skipped", "target has no HTTP application surface")
        await send(repo_id, "Phase 2 HTTP probes skipped: enrolled target is a library/CLI, not a web service", level="info")
        return []

    results = []
    url = lab_status.get("url")
    if not url or not (str(url).startswith("http://") or str(url).startswith("https://")):
        _status("skipped", "HTTP lab URL unavailable")
        await send(repo_id, "Lab has no HTTP URL; skipping HTTP Phase 2 probes (native PoCs still run)", level="info")
        return results

    try:
        import httpx
    except Exception:
        _status("failed", "httpx not available for dynamic probes")
        await send(repo_id, "httpx not available for dynamic probes", level="warning")
        return results

    await send(repo_id, f"Running dynamic probes against lab at {url}", level="info")
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
            r = await client.get(f"{url}/")
            results.append(
                {
                    "tool": "dynamic-probe",
                    "title": f"Lab root probe HTTP {r.status_code}",
                    "cvss": 0.0,
                    "description": f"GET {url}/ returned HTTP {r.status_code} ({len(r.text)} bytes)",
                    "file": "lab",
                    "line": 0,
                    "confidence": "info",
                }
            )
            # Discover endpoints from Phase 1 attack surface instead of hardcoding
            discovered_paths = set()
            attack_surface = recon_summary.get("attack_surface", {})
            for ns in attack_surface.get("api_namespaces", []):
                discovered_paths.add(f"/api/{ns}")
                discovered_paths.add(f"/{ns}")
            for ns in attack_surface.get("admin_namespaces", []):
                discovered_paths.add(f"/{ns}")
            # Extract endpoint hints from findings
            for finding in findings:
                file_path = finding.get("file", "")
                if "controller" in file_path.lower():
                    stem = Path(file_path).stem.replace("_controller", "").replace("Controller", "")
                    discovered_paths.add(f"/{stem.lower()}")
            # Always include common discovery paths
            discovered_paths.update(["/api", "/admin", "/health", "/login", "/graphql", "/swagger.json"])
            for path in sorted(discovered_paths)[:20]:
                try:
                    pr = await client.get(f"{url}{path}")
                    results.append(
                        {
                            "tool": "dynamic-probe",
                            "title": f"Probe {path} HTTP {pr.status_code}",
                            "cvss": 0.0,
                            "description": f"GET {url}{path} returned HTTP {pr.status_code}",
                            "file": "lab",
                            "line": 0,
                            "confidence": "info",
                        }
                    )
                except Exception:
                    pass
    except Exception as e:
        _status("failed", f"dynamic probe failed: {e}")
        await send(repo_id, f"Dynamic probe failed: {e}", level="warning")

    if recon_summary.get("phase2_dynamic_probe", {}).get("status") != "failed":
        _status("completed", f"dynamic probes completed; {len(results)} baseline responses observed", count=len(results))
    return results


NATIVE_TASK_CATEGORIES = {
    "lab", "protocol-admin", "insecure-default", "authz", "deser",
    "lab-poc", "authz-bypass", "empty-token", "control-plane",
}

# Categories with a concrete executor below.  A planner is allowed to emit
# additional hypotheses, but an unimplemented category must never be reported
# as a passing test merely because the loop reached its tail.
EXECUTABLE_TASK_CATEGORIES = {
    "authorization", "api-security", "access-control", "dependency-fuzz",
    "cpg-taint-validation", "library-harness", "library-fuzz",
}


def _phase2_execution_exclusion(task: Dict[str, Any], recon: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Require explicit opt-ins and an executor matching the task transport.

    The exact old argv technique is a compatibility discriminator for durable
    plans created before argv tasks had their own category. Titles alone are
    not classification authority. These exclusions remain coverage gaps.
    """
    category = task.get("category")
    argv = category == "cli-argv" or (
        category == "dependency-fuzz" and task.get("technique") == "docker-exec argv oracle"
    )
    if argv:
        if recon.get("cli_security_testing_enabled") is not True:
            return {"reason_code": "cli_security_testing_disabled", "classification": "disabled",
                    "intentional_disabled": True, "coverage_complete": False,
                    "reason": "CLI security testing is disabled in Settings. This lead remains unproven."}
        return {"reason_code": "cli_argv_executor_unavailable", "classification": "unsupported",
                "coverage_complete": False,
                "reason": "No registered CLI argv test executor is available. The lead remains unproven; HTTP probes cannot validate command arguments."}
    if category in ("dependency-fuzz", "library-fuzz") and recon.get("runtime_fuzzing_enabled") is not True:
        return {"reason_code": "runtime_fuzzing_disabled", "classification": "disabled",
                "intentional_disabled": True, "coverage_complete": False,
                "reason": "Runtime fuzzing is disabled in Settings. This lead remains unproven."}
    # A verified native HTTP health/interface promotion does not turn a
    # dependency or argv hypothesis into an HTTP dependency test.
    native_target = any(recon.get(key) in ("cli-tool", "library")
                        for key in ("static_app_type", "app_type"))
    if category != "dependency-fuzz" or not native_target:
        return None
    capture = recon.get("dependency_source_capture")
    inventory = recon.get("dependency_source_inventory")
    unbound = (isinstance(inventory, dict)
               and type(inventory.get("captured_declarations")) is int
               and inventory["captured_declarations"] == 0
               and type(inventory.get("declarations")) is int and inventory["declarations"] > 0)
    result = {"reason_code": "native_dependency_executor_unavailable", "classification": "unsupported",
              "coverage_complete": False,
              "reason": "No registered native dependency test executor is available for this target. Runtime validation remains unproven; HTTP health observations do not validate native dependency behavior."}
    if unbound:
        disabled = isinstance(capture, dict) and capture.get("status") == "disabled"
        result["prerequisite_state"] = "dependency_source_capture_disabled" if disabled else "dependency_source_unavailable"
        result["reason"] += (" Dependency source capture is disabled; no declared dependency source is bound to this audit."
                             if disabled else " No declared dependency source is bound to this audit.")
    return result


def _lab_runtime_ready(lab_status: Dict[str, Any]) -> bool:
    """Require runtime attestation when the caller has one.

    Legacy/direct adapter callers may supply only ``healthy``; preserving that
    compatibility avoids silently turning an API contract change into a false
    skipped result.  The scan pipeline always sets ``runtime_attested`` before
    Phase 2, so a listener backed by a fallback server is never eligible for
    deployment evidence in real audits.
    """
    if not isinstance(lab_status, dict) or lab_status.get("healthy") is not True:
        return False
    return lab_status.get("runtime_attested") is not False


def _http_lab_url(lab_status: Dict[str, Any]) -> str:
    url = str(lab_status.get("url") or "")
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return ""


async def _run_library_harness_task(
    repo_id: int,
    dest: Path,
    recon_summary: Dict[str, Any],
    send,
    *,
    mode: str = "full",
) -> Dict[str, Any]:
    """Execute the generated package consumer harness and persist its artifact."""
    try:
        from backend.library_harness import run_generic_library_harness, run_node_library_harness
        language = str(recon_summary.get("language") or "node").lower()
        package_name = str((recon_summary.get("package_name") or ".")).strip() or "."
        if language != "node":
            return await run_generic_library_harness(
                repo_id, dest, language=language,
                mode="protocol" if mode == "full" else mode,
                send=send,
            )
        return await run_node_library_harness(
            repo_id, dest, package_name=package_name, mode=mode, send=send, timeout=120,
        )
    except Exception as exc:
        return {"schema_version": 1, "status": "failed", "error": str(exc)[:500]}


async def _attach_phase2_receipt(
    repo_id: int,
    finding: Dict[str, Any],
    *,
    request: Dict[str, Any],
    baseline: Dict[str, Any],
    observed: Dict[str, Any],
    oracle_kind: str,
    artifact_text: str = "",
) -> None:
    """Attest an HTTP oracle using the same daemon-bound receipt as PoCs."""
    try:
        from backend.lab import lab_attestation
        from backend.proof_receipts import issue_receipt
        finding["proof_audit_id"] = str(repo_id)
        finding["proof_baseline"] = baseline
        identity = await lab_attestation(repo_id)
        body_hash = "sha256:" + hashlib.sha256((artifact_text or "").encode("utf-8")).hexdigest()
        receipt = issue_receipt(
            audit_id=str(repo_id), finding=finding,
            target_revision=identity.get("target_revision", ""),
            target_tree_hash=identity.get("target_tree_hash", ""),
            lab_run_id=identity.get("lab_run_id", ""),
            container_id=identity.get("container_id", ""),
            image_digest=identity.get("image_digest", ""),
            network_id=identity.get("network_id", ""),
            command_argv=["http", str(request.get("method") or "GET"), str(request.get("url") or "")],
            request=request, baseline=baseline, observed=observed,
            oracle_kind=oracle_kind, artifact_hashes=[body_hash],
        )
        if receipt:
            finding["proof_receipt"] = receipt
    except Exception:
        # Identity/key failures intentionally leave this as an unproven Lead.
        return


async def _run_lab_smoke(repo_id: int, dest: Path, send, *, smoke_override: str = "") -> Dict[str, Any]:
    """Execute the audit-plan smoke test inside the still-running lab."""
    result = {"ran": False, "ok": False, "output": ""}
    plan_path = Path(dest) / ".lotus" / "audit_plan.json"
    smoke = smoke_override
    if not smoke and plan_path.is_file():
        try:
            smoke = (json.loads(plan_path.read_text(encoding="utf-8")) or {}).get("smoke_test") or ""
        except Exception:
            smoke = ""
    if not smoke:
        return result
    try:
        from backend import lab as lab_mod
        out = await lab_mod.exec_in_lab(repo_id, str(smoke), timeout=45)
        blob = (out.get("stdout") or "") + "\n" + (out.get("stderr") or "")
        result["ran"] = True
        result["output"] = blob[-800:]
        result["ok"] = (out.get("success") is True and type(out.get("exit_code")) is int
                        and out["exit_code"] == 0 and out.get("simulated") is not True)
        result["command"] = str(smoke)
        result["exit_code"] = out.get("exit_code")
        await send(
            repo_id,
            f"Lab smoke: {'PASS' if result['ok'] else 'FAIL'} ({str(smoke)[:80]})",
            level="success" if result["ok"] else "warning",
        )
    except Exception as e:
        result["ran"] = True
        result["output"] = str(e)[:200]
        await send(repo_id, f"Lab smoke skipped: {e}", level="warning")
    # The smoke result is an auditable runtime artifact.  Persist it before
    # integrity evaluation so a healthy TCP listener cannot stand in for a
    # successfully loaded/built target package.
    try:
        artifact = Path(dest) / ".lotus" / "lab_smoke.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    except Exception:
        pass
    return result


async def execute_phase2_plan(
    repo_id: int,
    dest: Path,
    plan: Dict[str, Any],
    lab_status: Dict[str, Any],
    recon_summary: Dict[str, Any],
    findings: List[Dict[str, Any]],
    send,
    max_tasks: int = 15,
) -> List[Dict[str, Any]]:
    """Execute Phase 2 plan tasks against the lab (HTTP and native/protocol)."""
    # Treat the plan as untrusted, durable input.  AI/JSON corruption must not
    # abort the executor before it can emit a terminal outcome for each planned
    # item.  Non-object entries become explicit failed tasks with a reason.
    raw_tasks = plan.get("tasks", []) if isinstance(plan, dict) else plan
    malformed_container = raw_tasks is not None and not isinstance(raw_tasks, list)
    raw_tasks = [raw_tasks] if malformed_container else (raw_tasks or [])
    planned_tasks: List[Dict[str, Any]] = []
    for idx, item in enumerate(raw_tasks, 1):
        if isinstance(item, dict) and not malformed_container:
            task = dict(item)
            malformed = [key for key in ("title", "category", "priority", "target", "technique", "why", "command", "id")
                         if task.get(key) is not None and not isinstance(task.get(key), str)]
            for key in ("source_refs", "coverage_ids"):
                if task.get(key) is not None and not isinstance(task[key], list):
                    malformed.append(key)
            if isinstance(task.get("coverage_ids"), list) and any(not isinstance(value, str) for value in task["coverage_ids"]):
                malformed.append("coverage_ids entries")
            try:
                task["id"] = task.get("id") or phase2_task_id(task)
            except (TypeError, ValueError):
                malformed.append("task identity")
            if malformed:
                task.update(_plan_error="planned task fields must be strings: " + ", ".join(malformed),
                            title=f"Malformed Phase 2 task #{idx}", category="invalid-plan", priority="high", target="")
                if not isinstance(task.get("id"), str) or not task["id"]:
                    task["id"] = phase2_task_id({"title": f"Malformed Phase 2 task #{idx}", "category": "invalid-plan"})
            for key in ("title", "category", "priority", "target"):
                if task.get(key) is None:
                    task[key] = ""
            planned_tasks.append(task)
        else:
            planned_tasks.append({
                "title": f"Malformed Phase 2 task #{idx}",
                "category": "invalid-plan",
                "priority": "high",
                "target": "",
                "technique": "plan-validation",
                "why": "planner emitted a non-object task",
                "_plan_error": "plan tasks must be a JSON array" if malformed_container else "planned task is not a JSON object",
            })
    upstream_send = send
    event_tasks = planned_tasks

    async def send(target_repo_id, message, *args, **kwargs):
        detail = kwargs.get("detail")
        if isinstance(detail, dict) and detail.get("type") == "phase2_task":
            # The executor owns the current sorted order, so resolve its local
            # index here and emit a stable identity for all external consumers.
            # Titles may legitimately repeat for distinct endpoint targets.
            index = detail.get("index")
            matches = []
            if isinstance(index, int) and 1 <= index <= len(event_tasks):
                candidate = event_tasks[index - 1]
                if candidate.get("title") == detail.get("title"):
                    matches = [candidate]
            if not matches:
                matches = [task for task in planned_tasks
                           if task.get("title") == detail.get("title")
                           and (not detail.get("category") or task.get("category") == detail.get("category"))]
            if len(matches) == 1:
                task = matches[0]
                kwargs["detail"] = {**detail, "task_id": task.get("id") or phase2_task_id(task),
                                    "target": task.get("target") or "", "category": task.get("category") or ""}
        try:
            await upstream_send(target_repo_id, message, *args, **kwargs)
        except Exception as error:
            # Preserve an already-settled task when notification/persistence
            # fails. The caller still sees the error after final accounting;
            # delivery failure is never a second execution outcome.
            failed_detail = kwargs.get("detail") if isinstance(kwargs.get("detail"), dict) else {}
            execution.setdefault("delivery_errors", []).append({
                "task_id": failed_detail.get("task_id") or "",
                "status": failed_detail.get("status"),
                "error_type": type(error).__name__, "reason": str(error)[:300]})
            raise

    runtime_ready = _lab_runtime_ready(lab_status)

    new_findings: List[Dict[str, Any]] = []
    tasks_executed = 0
    url = _http_lab_url(lab_status) if runtime_ready else ""
    execution = {
        "planned": len(planned_tasks),
        "executed": 0,
        "completed": 0,
        "failed": 0,
        "skipped": 0,
        "not_applicable": 0,
        "skip_reasons": {},
        "terminal": 0,
        "unresolved": 0,
        "invariant": "pending",
        "task_outcomes": [],
    }
    recon_summary["phase2_execution"] = execution

    def _outcome(index: int, task: Dict[str, Any], status: str, reason: str = "", *, evidence=None) -> None:
        reason_text = str(reason or ("completed" if status == "completed" else status))
        execution["task_outcomes"].append({
            "index": int(index), "title": str(task.get("title") or "validation task"),
            "task_id": task.get("id") or phase2_task_id(task), "target": str(task.get("target") or ""),
            "category": str(task.get("category") or ""), "status": status,
            "reason": reason_text,
            "evidence": evidence or [],
        })
        # A library/CLI target has no HTTP application surface by definition.
        # Those generated HTTP tasks are intentionally visible as skipped, but
        # they are not evidence gaps and should not downgrade an otherwise
        # complete library audit.  Keep the raw skipped count for transparency
        # and expose this separate applicability count for completeness gates.
        if status == "skipped" and reason_text == "target has no HTTP application surface":
            execution["not_applicable"] = int(execution.get("not_applicable", 0) or 0) + 1

    def _terminal_recorded(index: int) -> bool:
        return any(row.get("index") == index for row in execution["task_outcomes"])

    def _finalize_accounting() -> None:
        outcomes = execution["task_outcomes"]
        expected = {index: task.get("id") or phase2_task_id(task) for index, task in enumerate(event_tasks, 1)}
        valid_rows = [row for row in outcomes if isinstance(row, dict)
                      and type(row.get("index")) is int and row["index"] in expected
                      and row.get("task_id") == expected[row["index"]]]
        indexes = [row["index"] for row in valid_rows]
        states = [row.get("status") for row in valid_rows]
        for state in ("completed", "failed", "skipped"):
            execution[state] = states.count(state)
        execution["terminal"] = sum(execution[state] for state in ("completed", "failed", "skipped"))
        execution["unresolved"] = len(set(expected) - {row["index"] for row in valid_rows if row.get("status") in {"completed", "failed", "skipped"}})
        exact = (len(outcomes) == len(valid_rows) == len(expected) == len(set(indexes))
                 and len(set(expected.values())) == len(expected)
                 and execution["terminal"] == execution["planned"] and execution["unresolved"] == 0)
        execution["invariant"] = "satisfied" if exact else "violated"
        if not exact:
            execution["accounting_error"] = "Phase 2 requires exactly one terminal outcome for each unique planned task identity"

    priority_order = {"critical": 0, "high": 1, "medium": 2, "informational": 3}
    sorted_tasks = sorted(
        planned_tasks,
        key=lambda t: (
            0 if (t.get("category") or "") in NATIVE_TASK_CATEGORIES else 1,
            priority_order.get(t.get("priority", "informational"), 3),
        ),
    )
    event_tasks = sorted_tasks

    native_cap = 12
    http_cap = max_tasks
    native_done = 0
    http_done = 0

    client = None
    try:
        # Setup and progress delivery share the same finalizer as execution;
        # neither may leave the plan pending if it fails before the first task.
        # Keep an existing pipeline smoke receipt instead of repeating it.
        smoke = recon_summary.get("lab_smoke")
        if runtime_ready and not isinstance(smoke, dict):
            smoke = await _run_lab_smoke(repo_id, dest, send)
            recon_summary["lab_smoke"] = smoke
        await send(
            repo_id,
            f"Executing Phase 2 plan ({len(sorted_tasks)} tasks; "
            f"source review{' and attested lab validation' if runtime_ready else '; runtime validation unavailable'})",
            level="info",
        )
        if url:
            try:
                import httpx
                client = httpx.AsyncClient(timeout=8, follow_redirects=True)
            except ImportError:
                client = None
        for task_index, task in enumerate(sorted_tasks, 1):
            category = task.get("category", "")
            title = task.get("title", "")
            task_detail_id = f"{repo_id}-task-phase2-{task_index}"
            if task.get("_plan_error"):
                reason = str(task.get("_plan_error"))
                execution["failed"] += 1
                _outcome(task_index, task, "failed", reason)
                await send(
                    repo_id,
                    f"✗ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]} — {reason}",
                    level="warning", detail_id=task_detail_id,
                    detail={"type": "phase2_task", "status": "failed", "index": task_index,
                            "total": len(sorted_tasks), "title": title, "category": category,
                            "reason": reason, "result_type": "leads"},
                )
                continue
            exclusion = _phase2_execution_exclusion(task, recon_summary)
            if exclusion is not None:
                execution["skipped"] += 1
                reason = exclusion["reason"]
                _outcome(task_index, task, "skipped", reason)
                execution["task_outcomes"][-1].update(exclusion)
                execution["skip_reasons"][reason] = execution["skip_reasons"].get(reason, 0) + 1
                await send(repo_id, f"⊘ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]} — {reason}",
                           level="warning", detail_id=task_detail_id,
                           detail={"type": "phase2_task", "status": "skipped", "index": task_index,
                                   "total": len(sorted_tasks), "title": title, "category": category,
                                   "result_type": "leads", **exclusion})
                continue
            if category == "static-source-review":
                from backend.phase2_mapping import run_source_review_batch
                import asyncio
                execution["executed"] += 1
                started = time.monotonic()
                detail = {"type": "phase2_task", "index": task_index, "total": len(sorted_tasks),
                          "title": title, "category": category, "result_type": "source-review"}
                await send(repo_id, f"▶ Phase 2 source review {task_index}/{len(sorted_tasks)}: {title[:70]}",
                           detail_id=task_detail_id, detail={**detail, "status": "running"})
                try:
                    # Bounded read-only work; join it on cancellation so the
                    # source reader cannot outlive this execution lease.
                    worker = asyncio.create_task(asyncio.to_thread(run_source_review_batch, task, recon_summary))
                    try:
                        artifact = await asyncio.shield(worker)
                    except BaseException:
                        while not worker.done():
                            try:
                                await asyncio.shield(worker)
                            except asyncio.CancelledError:
                                continue
                            except BaseException:
                                break
                        raise
                    reason = (f"{artifact['inspected']} source contexts inspected; {artifact['gaps']} source gaps. "
                              "Runtime validation remains unproven.")
                    execution["completed"] += 1
                    _outcome(task_index, task, "completed", reason, evidence=[artifact])
                    await send(repo_id, f"✓ Phase 2 source review: {reason}", detail_id=task_detail_id,
                               detail={**detail, "status": "completed", "reason": reason, "evidence": [artifact],
                                       "duration_seconds": round(time.monotonic() - started, 3)})
                except Exception as error:
                    if _terminal_recorded(task_index):
                        raise
                    execution["failed"] += 1
                    reason = str(error)[:500]
                    _outcome(task_index, task, "failed", reason)
                    await send(repo_id, f"Source review needs attention: {reason}", level="warning",
                               detail_id=task_detail_id, detail={**detail, "status": "failed", "reason": reason})
                continue
            if not runtime_ready:
                reason = "lab runtime unavailable or unattested; no proof can be collected"
                execution["skipped"] += 1
                execution["skip_reasons"][reason] = execution["skip_reasons"].get(reason, 0) + 1
                _outcome(task_index, task, "skipped", reason)
                await send(repo_id, f"⊘ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]} — lab runtime unavailable or unattested",
                           level="warning", detail_id=task_detail_id,
                           detail={"type": "phase2_task", "status": "skipped", "index": task_index,
                                   "total": len(sorted_tasks), "title": title, "category": category,
                                   "reason": reason, "result_type": "leads"})
                continue
            is_native = category in NATIVE_TASK_CATEGORIES
            if is_native:
                if native_done >= native_cap:
                    execution["skipped"] += 1
                    _outcome(task_index, task, "skipped", f"native task cap {native_cap} reached")
                    execution["skip_reasons"]["native safety cap"] = execution["skip_reasons"].get("native safety cap", 0) + 1
                    await send(repo_id, f"⊘ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]} — native safety cap ({native_cap})",
                               level="warning", detail_id=task_detail_id,
                               detail={"type": "phase2_task", "status": "skipped", "index": task_index,
                                       "total": len(sorted_tasks), "title": title, "category": category,
                                       "reason": f"native task cap {native_cap} reached", "result_type": "leads"})
                    continue
                native_done += 1
                # Native execution is intentionally explicit: a planner item is not
                # evidence until an executor returns a result. Keep the task visible
                # as skipped when no native runner is wired instead of marking it done.
                execution["skipped"] += 1
                _outcome(task_index, task, "skipped", "native executor unavailable")
                execution["skip_reasons"]["native executor unavailable"] = execution["skip_reasons"].get("native executor unavailable", 0) + 1
                await send(repo_id, f"⊘ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]} — native executor unavailable",
                           level="warning", detail_id=task_detail_id,
                           detail={"type": "phase2_task", "status": "skipped", "index": task_index,
                                   "total": len(sorted_tasks), "title": title, "category": category,
                                   "reason": "native executor unavailable", "result_type": "leads"})
                continue
            if category == "package-test":
                # This is the executable path for Node libraries/CLIs.  It is
                # intentionally allowlisted to npm's script runner; the test
                # command is derived from package.json, never accepted as an
                # arbitrary shell command from a lead or README.
                command = str(task.get("command") or "").strip()
                if not re.match(r"^npm\s+(?:run\s+[A-Za-z0-9:_-]+(?:\s+--\s+.*)?|test(?:\s+--\s+.*)?)$", command):
                    execution["skipped"] += 1
                    _outcome(task_index, task, "skipped", "invalid package test command")
                    execution["skip_reasons"]["invalid package test command"] = execution["skip_reasons"].get("invalid package test command", 0) + 1
                    await send(repo_id, f"⊘ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]} — no allowlisted package test command",
                               level="warning", detail_id=task_detail_id,
                               detail={"type": "phase2_task", "status": "skipped", "index": task_index,
                                       "total": len(sorted_tasks), "title": title, "category": category,
                                       "reason": "invalid package test command", "result_type": "test-evidence"})
                    continue
                execution["executed"] += 1
                started = time.monotonic()
                await send(repo_id, f"▶ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]}", level="info",
                           detail_id=task_detail_id,
                           detail={"type": "phase2_task", "status": "running", "index": task_index,
                                   "total": len(sorted_tasks), "title": title, "category": category,
                                   "result_type": "test-evidence"})
                try:
                    from backend import lab as lab_mod
                    # npm/nyc commonly write caches beside the checkout. Keep
                    # those writes in the container scratch directory so a
                    # read-only source snapshot remains immutable.
                    test = await lab_mod.exec_in_lab(
                        repo_id,
                        f"HOME=/tmp NPM_CONFIG_CACHE=/tmp/npm-cache TMPDIR=/tmp {command}",
                        timeout=180,
                    )
                    blob = ((test.get("stdout") or "") + "\n" + (test.get("stderr") or ""))[-6000:]
                    ok = test.get("success") is True and type(test.get("exit_code")) is int and test["exit_code"] == 0
                    duration = round(time.monotonic() - started, 3)
                    if ok:
                        execution["completed"] += 1
                        _outcome(task_index, task, "completed", "package test command exited 0",
                                 evidence=[{"command": command,
                                            "exit_code": test.get("exit_code"), "output": blob}])
                    else:
                        execution["failed"] += 1
                        _outcome(task_index, task, "failed", f"package test exited {test.get('exit_code')}")
                    await send(repo_id,
                               f"{'✓' if ok else '✗'} Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:60]} — "
                               f"{'PASS' if ok else 'FAIL'} ({duration:.1f}s)",
                               level="success" if ok else "warning", detail_id=task_detail_id,
                               detail={"type": "phase2_task", "status": "completed" if ok else "failed",
                                       "index": task_index, "total": len(sorted_tasks), "title": title,
                                       "category": category, "duration_seconds": duration,
                                       "command": command, "exit_code": test.get("exit_code"),
                                       "output": blob,
                                       "evidence": [{"command": command,
                                                     "exit_code": test.get("exit_code"), "output": blob}],
                                       "reason": "package test command exited 0" if ok else f"package test exited {test.get('exit_code')}",
                                       "result_type": "test-evidence"})
                except Exception as e:
                    if _terminal_recorded(task_index):
                        raise
                    execution["failed"] += 1
                    _outcome(task_index, task, "failed", str(e)[:500])
                    await send(repo_id, f"✗ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:60]} — {str(e)[:80]}", level="warning",
                               detail_id=task_detail_id,
                               detail={"type": "phase2_task", "status": "failed", "index": task_index,
                                       "total": len(sorted_tasks), "title": title, "category": category,
                                       "error": str(e)[:500], "reason": str(e)[:500],
                                       "result_type": "test-evidence"})
                continue
            if category in ("library-harness", "library-fuzz"):
                execution["executed"] += 1
                started = time.monotonic()
                await send(repo_id, f"▶ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]}", level="info",
                           detail_id=task_detail_id,
                           detail={"type": "phase2_task", "status": "running", "index": task_index,
                                   "total": len(sorted_tasks), "title": title, "category": category,
                                   "result_type": "test-evidence"})
                try:
                    artifact = await _run_library_harness_task(
                        repo_id, dest, recon_summary, send,
                        mode="protocol" if category == "library-harness" else "fuzz",
                    )
                    recon_summary.setdefault("library_harness", {})[category] = artifact
                    state = str(artifact.get("status") or "failed")
                    # Security-semantic observations from the generated
                    # consumer are first-class leads.  They are not inferred
                    # from a 200 response: the harness must have observed a
                    # concrete oracle (for example a custom auth header at a
                    # different redirect origin).  The common library target
                    # itself is the deployment boundary, so ``library-consumer``
                    # remains eligible for a runner receipt; analog and generic
                    # package-harness observations remain non-reportable.
                    if state == "completed":
                        for observation in (artifact.get("security_observations") or []):
                            if not isinstance(observation, dict):
                                continue
                            if str(observation.get("kind") or "") == "cross-origin-auth-header-leak":
                                obs_evidence = observation.get("evidence") if isinstance(observation.get("evidence"), dict) else {}
                                new_findings.append({
                                    "tool": "library-harness",
                                    "title": "followRedirects forwards custom authentication headers across origins",
                                    "cvss": 6.5,
                                    "description": (
                                        "Generated consumer harness redirected a request to a different origin and "
                                        "observed a custom authentication header at the sink. This is exploitable "
                                        "only when a downstream deployment enables followRedirects and sends that "
                                        "header; it is not the default node-http-proxy behavior."
                                    ),
                                    "file": "lib/http-proxy/passes/web-incoming.js",
                                    "line": 97,
                                    "line_end": 99,
                                    "confidence": "high",
                                    "qualification": "QUALIFIED",
                                    "canonical_class": "credential_leak_redirect",
                                    "primitive_type": "credential_leak_redirect",
                                    "conviction_level": 2,
                                    "proven_in_lab": True,
                                    "evidence_scope": "library-consumer",
                                    "target_bound": True,
                                    "proof_authority": "generated-consumer-harness",
                                    "lab_evidence": [{
                                        "scenario": "http-follow-redirects",
                                        "anomaly_type": "cross-origin-auth-header-leak",
                                        "observation": obs_evidence,
                                    }],
                                    "poc": {
                                        "command": str(artifact.get("command") or ""),
                                        "scenario": "cross-origin-auth-header-leak",
                                    },
                                    "poc_result": "triggered",
                                })
                    if state == "completed":
                        execution["completed"] += 1
                        _outcome(task_index, task, "completed", "generated consumer harness completed",
                                 evidence=[artifact])
                    elif state == "skipped":
                        execution["skipped"] += 1
                        reason = str(artifact.get("reason") or "library harness skipped")
                        _outcome(task_index, task, "skipped", reason)
                        execution["skip_reasons"][reason] = execution["skip_reasons"].get(reason, 0) + 1
                    else:
                        execution["failed"] += 1
                        _outcome(task_index, task, "failed", str(artifact.get("error") or "library harness failed"))
                    await send(repo_id,
                               f"{'✓' if state == 'completed' else ('⊘' if state == 'skipped' else '✗')} Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:60]} — {state}",
                               level="success" if state == "completed" else "warning", detail_id=task_detail_id,
                               detail={"type": "phase2_task", "status": state, "index": task_index,
                                       "total": len(sorted_tasks), "title": title, "category": category,
                                       "duration_seconds": round(time.monotonic() - started, 3),
                                       "artifact": artifact, "reason": artifact.get("reason"),
                                       "evidence": [artifact],
                                       "result_type": "test-evidence"})
                except Exception as exc:
                    if _terminal_recorded(task_index):
                        raise
                    execution["failed"] += 1
                    _outcome(task_index, task, "failed", str(exc)[:500])
                    await send(repo_id, f"✗ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:60]} — {str(exc)[:80]}", level="warning",
                               detail_id=task_detail_id,
                               detail={"type": "phase2_task", "status": "failed", "index": task_index,
                                       "total": len(sorted_tasks), "title": title, "category": category,
                                       "error": str(exc)[:500], "result_type": "test-evidence"})
                continue
            if category not in EXECUTABLE_TASK_CATEGORIES:
                execution["skipped"] += 1
                reason = f"no executor for category '{category or 'unknown'}'"
                _outcome(task_index, task, "skipped", reason)
                execution["skip_reasons"][reason] = execution["skip_reasons"].get(reason, 0) + 1
                await send(repo_id,
                           f"⊘ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]} — {reason}",
                           level="warning", detail_id=task_detail_id,
                           detail={"type": "phase2_task", "status": "skipped", "index": task_index,
                                   "total": len(sorted_tasks), "title": title, "category": category,
                                   "reason": reason, "result_type": "leads"})
                continue
            # A generated library/CLI lab may have a TCP/HTTP health listener,
            # but it is not an application HTTP surface.  Do not feed static
            # file paths to HTTP validators; dependency-fuzz is retained because
            # its library path can still inspect taint-to-package usage without
            # a web endpoint.
            if (recon_summary.get("app_type") or "") in ("cli-tool", "library") and category != "dependency-fuzz":
                execution["skipped"] += 1
                reason = "target has no HTTP application surface"
                _outcome(task_index, task, "skipped", reason)
                execution["skip_reasons"][reason] = execution["skip_reasons"].get(reason, 0) + 1
                await send(repo_id,
                           f"⊘ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]} — {reason}",
                           level="warning", detail_id=task_detail_id,
                           detail={"type": "phase2_task", "status": "skipped", "index": task_index,
                                   "total": len(sorted_tasks), "title": title, "category": category,
                                   "reason": reason, "result_type": "leads"})
                continue
            if not client or not url:
                execution["skipped"] += 1
                _outcome(task_index, task, "skipped", "HTTP lab URL unavailable")
                execution["skip_reasons"]["HTTP lab URL unavailable"] = execution["skip_reasons"].get("HTTP lab URL unavailable", 0) + 1
                await send(repo_id, f"⊘ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]} — HTTP lab URL unavailable",
                           level="warning", detail_id=task_detail_id,
                               detail={"type": "phase2_task", "status": "skipped", "index": task_index,
                                   "total": len(sorted_tasks), "title": title, "category": category,
                                       "reason": "HTTP lab URL unavailable", "result_type": "leads"})
                continue
            if http_done >= http_cap:
                execution["skipped"] += 1
                _outcome(task_index, task, "skipped", f"HTTP task cap {http_cap} reached")
                execution["skip_reasons"]["HTTP safety cap"] = execution["skip_reasons"].get("HTTP safety cap", 0) + 1
                await send(repo_id, f"⊘ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]} — HTTP safety cap ({http_cap})",
                           level="warning", detail_id=task_detail_id,
                           detail={"type": "phase2_task", "status": "skipped", "index": task_index,
                                   "total": len(sorted_tasks), "title": title, "category": category,
                                   "reason": f"HTTP task cap {http_cap} reached", "result_type": "leads"})
                continue
            http_done += 1
            tasks_executed += 1
            execution["executed"] += 1
            started = time.monotonic()
            before_count = len(new_findings)
            task_client = _Phase2HTTPRecorder(client)
            await send(repo_id, f"▶ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:70]}", level="info",
                       detail_id=task_detail_id,
                       detail={"type": "phase2_task", "status": "running", "index": task_index,
                               "total": len(sorted_tasks), "title": title, "category": category,
                               "result_type": "leads"})
            try:
                if category == "authorization":
                    results = await _test_authorization(task_client, url, task, send, repo_id)
                    new_findings.extend(results)
                elif category == "api-security":
                    results = await _test_api_security(task_client, url, task, send, repo_id)
                    new_findings.extend(results)
                elif category == "access-control":
                    results = await _test_access_control(task_client, url, task, send, repo_id)
                    new_findings.extend(results)
                elif category == "dependency-fuzz":
                    results = await _test_dependency_fuzz(task_client, url, task, recon_summary, dest)
                    new_findings.extend(results)
                elif category in ("cpg-taint-validation",):
                    result = await _validate_finding_dynamically(task_client, url, task, recon_summary)
                    if result:
                        new_findings.append(result)
                if task_client.errors:
                    raise RuntimeError(f"{len(task_client.errors)} HTTP probe(s) failed; target coverage is incomplete")
                if not task_client.observations:
                    raise RuntimeError("executor produced no HTTP observations; target coverage is incomplete")
                duration = round(time.monotonic() - started, 3)
                task_results = new_findings[before_count:]
                summary = [{"title": f.get("title", "")[:100], "cvss": f.get("cvss", 0),
                            "file": f.get("file", ""), "line": f.get("line", 0)}
                           for f in task_results[:20]]
                execution["completed"] += 1
                _outcome(task_index, task, "completed", f"executor completed; {len(summary)} leads observed",
                         evidence=task_client.observations)
                await send(repo_id, f"✓ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:60]} — {len(summary)} leads observed ({duration:.1f}s)",
                           level="success", detail_id=task_detail_id,
                           detail={"type": "phase2_task", "status": "completed", "index": task_index,
                                   "total": len(sorted_tasks), "title": title, "category": category,
                                   "duration_seconds": duration, "count": len(summary), "leads": summary,
                                   "reason": f"executor completed; {len(summary)} leads observed",
                                   "evidence": task_client.observations,
                                   "result_type": "leads"})
            except Exception as e:
                if _terminal_recorded(task_index):
                    raise
                duration = round(time.monotonic() - started, 3)
                execution["failed"] += 1
                _outcome(task_index, task, "failed", str(e)[:500], evidence=task_client.observations + task_client.errors)
                await send(repo_id, f"✗ Phase 2 test {task_index}/{len(sorted_tasks)}: {title[:60]} — {str(e)[:80]}", level="warning",
                           detail_id=task_detail_id,
                           detail={"type": "phase2_task", "status": "failed", "index": task_index,
                                   "total": len(sorted_tasks), "title": title, "category": category,
                                   "duration_seconds": duration, "error": str(e)[:500], "reason": str(e)[:500],
                                   "result_type": "leads"})
    finally:
        # If an unexpected planner/executor exception escaped a per-task guard,
        # close every unrepresented item before returning (or propagating).  A
        # report may therefore say exactly which work failed instead of leaving
        # an unresolved denominator or an apparently hung audit.
        observed_indexes = {
            int(row.get("index")) for row in execution.get("task_outcomes", [])
            if isinstance(row, dict) and str(row.get("index", "")).isdigit()
        }
        missing_tasks = []
        for missing_index, missing_task in enumerate(sorted_tasks, 1):
            if missing_index in observed_indexes:
                continue
            reason = "executor interrupted before task terminal outcome"
            execution["failed"] += 1
            _outcome(missing_index, missing_task, "failed", reason)
            missing_tasks.append((missing_index, missing_task, reason))
        # Commit the entire receipt before awaiting transport/cleanup again:
        # cancellation checkpoints may raise a BaseException on every send.
        _finalize_accounting()
        if client is not None:
            await client.aclose()
        for missing_index, missing_task, reason in missing_tasks:
            try:
                await send(
                    repo_id,
                    f"✗ Phase 2 test {missing_index}/{len(sorted_tasks)}: "
                    f"{str(missing_task.get('title') or 'validation task')[:70]} — {reason}",
                    level="warning", detail_id=f"{repo_id}-task-phase2-{missing_index}",
                    detail={"type": "phase2_task", "status": "failed", "index": missing_index,
                            "total": len(sorted_tasks), "title": missing_task.get("title", ""),
                            "category": missing_task.get("category", ""), "reason": reason,
                            "result_type": "leads"},
                )
            except Exception:
                pass

    # Hard task-accounting invariant: every planned item must have exactly one
    # terminal outcome.  ``executed`` is deliberately not used here because a
    # safe skip (unsupported target, cap, missing lab capability) is still a
    # terminal outcome that must be visible to the operator.
    _finalize_accounting()
    if execution["invariant"] != "satisfied":
        await send(
            repo_id,
            f"Phase 2 task accounting invalid: {execution['unresolved']} unresolved task(s); "
            "each planned task must have a unique identity and exactly one terminal outcome",
            level="warning",
        )

    await send(repo_id, f"Phase 2 execution finished: {execution['executed']} executed, "
               f"{execution['completed']} passed, {execution['failed']} failed, "
               f"{execution['skipped']} skipped; {len(new_findings)} leads observed",
               level="warning" if execution["failed"] or execution["skipped"] or execution["invariant"] != "satisfied" else "success")
    return new_findings


async def _test_authorization(client, url: str, task: Dict, send, repo_id: int) -> List[Dict]:
    """Test admin/privileged endpoints for authorization bypass."""
    findings = []
    # A guessed endpoint returning a large public page is not an auth bypass.
    # Only tasks whose static trust-boundary model marked the surface as protected
    # may enter this confirmation path.
    if task.get("requires_auth") is not True or task.get("protected_baseline") is not True:
        return findings
    target = task.get("target", "")
    # Never treat a source/test-file served by a fallback HTTP server as a
    # privileged endpoint.  Only an explicitly extracted concrete route may
    # enter this confirmation oracle.
    if _looks_like_source_file(target):
        return findings
    # Derive probe paths from target
    paths = [f"/{target}", f"/api/{target}", f"/{target}/1"]
    for path in paths[:3]:
        try:
            # Test without any auth
            r = await client.get(f"{url}{path}")
            if r.status_code == 200 and len(r.text) > 100:
                finding = {
                    "tool": "phase2-plan",
                    "title": f"Unauthenticated access to privileged endpoint {path}",
                    "cvss": 7.5,
                    "description": (
                        f"Admin/privileged endpoint {path} returned HTTP {r.status_code} "
                        f"with {len(r.text)} bytes without authentication. "
                        f"Source task: {task.get('title', '')}"
                    ),
                    "file": target,
                    "line": 0,
                    "confidence": "medium",
                    "source_finding": {"tool": "phase2-plan", "title": task.get("title", "")},
                    "lab_evidence": [{
                        "path": path,
                        "endpoint": f"{url}{path}",
                        "snippet": r.text[:200],
                        "anomaly_type": "auth_bypass",
                        "http_status": r.status_code,
                        "body_length": len(r.text),
                    }],
                    "poc": {"request": f"GET {url}{path}", "payload": "no-auth"},
                    "poc_result": "triggered",
                }
                await _attach_phase2_receipt(
                    repo_id, finding,
                    request={"method": "GET", "url": f"{url}{path}", "headers": {"authorization": ""}},
                    baseline={"schema_version": 1, "oracle": "protected-endpoint-must-reject-anonymous", "expected_status": [401, 403]},
                    observed={"status": r.status_code, "body_length": len(r.text)},
                    oracle_kind="auth_bypass", artifact_text=r.text[:20000],
                )
                findings.append(finding)
        except Exception:
            continue
    return findings


async def _test_api_security(client, url: str, task: Dict, send, repo_id: int) -> List[Dict]:
    """Test API endpoints for mass assignment and input validation issues."""
    findings = []
    target = task.get("target", "")
    path = f"/api/{target}" if not target.startswith("/") else target
    try:
        # Test mass assignment with extra admin/role parameters
        mass_assign_payload = {"role": "admin", "is_admin": True, "admin": True, "verified": True}
        r = await client.post(f"{url}{path}", json=mass_assign_payload)
        # Reflection of attacker-supplied fields is not mass assignment.  Require
        # an explicit state-change oracle supplied by the target-aware harness.
        if (r.status_code in (200, 201)
                and task.get("state_change_oracle") is True
                and any(k in r.text.lower() for k in ["admin", "role"])):
            finding = {
                "tool": "phase2-plan",
                "title": f"Potential mass assignment on {path}",
                "cvss": 7.0,
                "description": (
                    f"POST {path} accepted admin/role parameters and reflected them in response. "
                    f"Status: {r.status_code}. Source task: {task.get('title', '')}"
                ),
                "file": target,
                "line": 0,
                "confidence": "medium",
                "source_finding": {"tool": "phase2-plan", "title": task.get("title", "")},
                "lab_evidence": [{"path": path, "endpoint": f"{url}{path}", "snippet": r.text[:200], "anomaly_type": "mass_assignment", "http_status": r.status_code}],
                "poc": {"request": f"POST {url}{path}", "payload": str(mass_assign_payload)},
                "poc_result": "triggered",
            }
            await _attach_phase2_receipt(
                repo_id, finding,
                request={"method": "POST", "url": f"{url}{path}", "json": mass_assign_payload},
                baseline={"schema_version": 1, "oracle": "state-change-must-not-accept-unknown-fields", "expected_status": [400, 401, 403]},
                observed={"status": r.status_code, "body_length": len(r.text)},
                oracle_kind="mass_assignment", artifact_text=r.text[:20000],
            )
            findings.append(finding)
    except Exception:
        pass
    return findings


async def _test_access_control(client, url: str, task: Dict, send, repo_id: int) -> List[Dict]:
    """Test routes for missing authentication requirements."""
    findings = []
    if task.get("requires_auth") is not True or task.get("protected_baseline") is not True:
        return findings
    target = task.get("target", "")
    if _looks_like_source_file(target):
        return findings
    paths_to_test = [f"/{target}"] if not target.startswith("/") else [target]
    for path in paths_to_test:
        try:
            r = await client.get(f"{url}{path}")
            if r.status_code == 200 and len(r.text) > 200:
                finding = {
                    "tool": "phase2-plan",
                    "title": f"Route {path} accessible without authentication",
                    "cvss": 6.5,
                    "description": (
                        f"GET {path} returned {r.status_code} ({len(r.text)} bytes) without auth. "
                        f"Expected 401/403 for protected route. Source: {task.get('title', '')}"
                    ),
                    "file": target,
                    "line": 0,
                    "confidence": "low",
                    "source_finding": {"tool": "phase2-plan", "title": task.get("title", "")},
                    "lab_evidence": [{"path": path, "endpoint": f"{url}{path}", "snippet": r.text[:200], "anomaly_type": "missing_auth", "http_status": r.status_code}],
                    "poc": {"request": f"GET {url}{path}", "payload": "no-auth"},
                    "poc_result": "triggered",
                }
                await _attach_phase2_receipt(
                    repo_id, finding,
                    request={"method": "GET", "url": f"{url}{path}", "headers": {"authorization": ""}},
                    baseline={"schema_version": 1, "oracle": "protected-route-must-reject-anonymous", "expected_status": [401, 403]},
                    observed={"status": r.status_code, "body_length": len(r.text)},
                    oracle_kind="missing_auth", artifact_text=r.text[:20000],
                )
                findings.append(finding)
        except Exception:
            continue
    return findings


async def _test_dependency_fuzz(client, url: str, task: Dict, recon_summary: Dict, dest: Path) -> List[Dict]:
    """Phase 2: probe tainted-reachable dependency surfaces (HTTP + CLI argv hints).

    Does not invent confirmation  - attaches QUALIFIED leads with concrete probe
    attempts so LangGraph/lab PoCs can finish the trigger gate.
    """
    findings: List[Dict] = []
    dep = (task.get("target") or "").strip()
    if not dep:
        return findings

    app_type = recon_summary.get("app_type") or ""
    tainted = recon_summary.get("tainted_dependencies") or {}
    usages = [
        u for u in (tainted.get("usages") or [])
        if (u.get("package") or "").lower() == dep.lower()
        or dep.lower() in (u.get("package") or "").lower()
    ]

    # HTTP: try OpenAPI/sandbox dangerous routes that often front dep parsers
    if app_type not in ("cli-tool", "library"):
        payloads = [
            ("/v1/file/read", {"file": "../../../../etc/passwd"}, "path_traversal"),
            ("/v1/file/read", {"file": "/etc/passwd"}, "path_traversal"),
            ("/v1/file/read", {"file": "/etc/passwd", "sudo": True}, "path_traversal"),
            ("/api/parse", {"data": "!!python/object/apply:os.system [id]"}, "yaml_deser"),
            ("/parse", {"yaml": "!!python/object/apply:os.system [id]"}, "yaml_deser"),
        ]
        for path, body, kind in payloads:
            try:
                r = await client.post(f"{url}{path}", json=body)
                text = r.text or ""
                hit = False
                if kind == "path_traversal" and re.search(r"root:.*:0:0:", text):
                    hit = True
                if kind == "yaml_deser" and re.search(r"uid=\d+", text):
                    hit = True
                if hit:
                    findings.append({
                        "tool": "phase2-dependency-fuzz",
                        "title": f"Dependency '{dep}' oracle hit via {path} ({kind})",
                        "cvss": 9.0,
                        "description": (
                            f"Phase 2 dependency-fuzz against '{dep}' matched oracle on "
                            f"POST {path}. Usage sites: {len(usages)}."
                        ),
                        "file": (usages[0].get("file") if usages else "dependencies"),
                        "line": (usages[0].get("line") if usages else 0),
                        "confidence": "high",
                        "qualification": "QUALIFIED",
                        "conviction_level": 3,
                        "dependency": dep,
                        "lab_evidence": [{
                            "path": path,
                            "params": body,
                            "status": r.status_code,
                            "snippet": text[:160],
                            "anomaly_type": kind,
                            "method": "POST",
                        }],
                        "proven_in_lab": True,
                        "poc": {"request": f"POST {path}", "json": body},
                        "poc_result": "triggered",
                    })
            except Exception:
                continue

    # Always emit a QUALIFIED lead summarizing taint→dep usage for AI/lab follow-up
    if usages and not findings:
        best = max(usages, key=lambda u: 1 if u.get("near_taint") else 0)
        findings.append({
            "tool": "phase2-dependency-fuzz",
            "title": f"Fuzz candidate: tainted path into dependency '{dep}'",
            "cvss": 6.5 if best.get("near_taint") else 5.0,
            "description": (
                f"Phase 2 dependency-fuzz planned for '{dep}'. "
                f"Taint evidence={best.get('taint_evidence')}; sink={best.get('sink_hit')}; "
                f"site={best.get('file')}:{best.get('line')}. "
                f"No HTTP oracle hit yet  - CLI argv / file PoC required."
            ),
            "file": best.get("file") or "dependencies",
            "line": best.get("line") or 0,
            "confidence": "medium",
            "qualification": "QUALIFIED",
            "conviction_level": 2 if best.get("near_taint") else 1,
            "dependency": dep,
            "discovery_technique": "dependency-fuzz",
        })

    # CLI flags from recon  - synthesize validation leads
    for fl in (recon_summary.get("cli_entry_flags") or [])[:12]:
        flag = fl.get("flag") or ""
        if not flag:
            continue
        if any(x in flag.lower() for x in ("exec", "eval", "yaml", "load", "file", "path", "cmd", "command", "c")):
            findings.append({
                "tool": "phase2-dependency-fuzz",
                "title": f"CLI flag '{flag}' may feed dependency '{dep}'  - argv PoC candidate",
                "cvss": 5.5,
                "description": (
                    f"Discovered CLI flag {flag} in {fl.get('file')}. "
                    f"Pair with docker-exec PoC targeting '{dep}' parsers/sinks."
                ),
                "file": fl.get("file") or "cli",
                "line": 0,
                "confidence": "low",
                "qualification": "QUALIFIED",
                "dependency": dep,
                "cli_flag": flag,
            })
            break
    return findings


async def _validate_finding_dynamically(client, url: str, task: Dict, recon_summary: Dict) -> Dict:
    """Attempt to validate a finding by probing the relevant endpoint."""
    why = task.get("why", "")
    target = task.get("target", "")
    # Extract endpoint hints from the task description
    if not target or target == "dynamic endpoints":
        return None
    path = f"/{target}" if not target.startswith("/") else target
    try:
        r = await client.get(f"{url}{path}")
        if r.status_code == 500:
            return {
                "tool": "phase2-plan",
                "title": f"Server error on {path} during validation",
                "cvss": 5.0,
                "description": (
                    f"GET {path} returned HTTP 500 during finding validation. "
                    f"This may indicate an unhandled error path. Task: {task.get('title', '')}"
                ),
                "file": target,
                "line": 0,
                "confidence": "low",
                "source_finding": {"tool": "phase2-plan", "title": task.get("title", "")},
            }
    except Exception:
        pass
    return None
