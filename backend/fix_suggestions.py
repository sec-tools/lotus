"""
Ranked remediation alternatives for Lotus findings.

Design (principal researcher judgment)
-------------------------------------
For each report-eligible finding, emit **three** concrete fix options, ranked:

  1. Minimal effective fix  - simplest change that actually closes the sink
  2. Structural / durable fix  - higher effort, lower residual risk
  3. Defense-in-depth  - complementary control (or temporary mitigation)

Why three (not one, not five)
- One fix biases maintainers toward a single incomplete patch.
- Five options create choice paralysis and dilute reports.
- Three matches common triage practice: ship-today / do-it-right / harden.

Why NOT "lab-performance-test every alternative" by default
- Most remediations are correctness/authz changes; wall-clock "performance"
  of three hypothetical patches is usually meaningless and easy to hallucinate.
- Lab should verify **PoC no longer succeeds after a candidate patch** when a
  runnable PoC exists  - that is effectiveness, not microbenchmarking.
- Performance trade-offs are still recorded as **estimated** overhead classes
  (none / low / medium / high) with rationale, measured only when relevant
  (e.g. regex sanitizers, crypto upgrades).

Anti-hallucination
- Templates are class-driven from title/description/tool  - never invent
  file-specific patches without citing the finding's own location.
- If class is unknown, emit conservative generic options and mark confidence low.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple


PerformanceClass = str  # "none" | "low" | "medium" | "high"


def _blob(finding: Dict[str, Any]) -> str:
    parts = [
        str(finding.get("title") or ""),
        str(finding.get("description") or ""),
        str(finding.get("tool") or ""),
        str(finding.get("discovery_technique") or ""),
        str(finding.get("ai_response") or ""),
    ]
    return " ".join(parts).lower()


def _location(finding: Dict[str, Any]) -> str:
    file_ = finding.get("file") or ""
    line = finding.get("line")
    if not file_ and finding.get("description"):
        m = re.search(r"file=([^\s|]+)", str(finding["description"]))
        if m:
            file_ = m.group(1)
            if ":" in file_:
                file_, _, rest = file_.partition(":")
                if rest.isdigit():
                    line = int(rest)
    if file_ and line:
        return f"`{file_}:{line}`"
    if file_:
        return f"`{file_}`"
    return "the cited sink"


def _classify(blob: str) -> str:
    """Map finding text to a catalog key via the canonical ontology.

    The fix catalog still uses the coarser `path_traversal` key (read/write share a
    remediation playbook), so those ontology classes are folded here.
    """
    try:
        from backend.ontology import normalize
        key = normalize(blob)
        if key.startswith("path_traversal"):
            return "path_traversal"
        if key != "generic":
            return key
    except Exception:
        pass
    return _classify_legacy(blob)


def _classify_legacy(blob: str) -> str:
    rules: List[Tuple[str, Tuple[str, ...]]] = [
        ("command_injection", ("command inject", "os.system", "subprocess", "shell=true", "exec.command", "child_process")),
        ("sql_injection", ("sql inject", "sqli", "raw sql", "execute(", "cursor.execute")),
        ("ssti", ("ssti", "template injection", "render_template_string", "jinja")),
        ("deserialization", ("deserial", "pickle", "yaml.load", "marshal.load", "unserialize", "objectinputstream")),
        ("path_traversal", ("path travers", "directory travers", "lfi", "file read", "send_file")),
        ("ssrf", ("ssrf", "server-side request", "urlopen", "requests.get", "metadata")),
        ("xss", ("xss", "cross-site", "innerhtml", "dangerouslyset", "html_safe")),
        ("authz_bypass", ("authz", "authoriz", "guard-alternate", "sibling", "skip_before", "bypass", "missing security check")),
        ("weak_secret", ("weak prng", "random.randint", "math.random", "hardcoded", "secret", "api_key", "jwt", "alg:none")),
        ("code_injection", ("code inject", "eval(", "exec(", "function(", "constantize")),
        ("api_surface", ("dangerous api", "shell.exec", "api-surface", "v1/shell", "v1/bash", "code.execute")),
    ]
    for cls, keys in rules:
        if any(k in blob for k in keys):
            return cls
    return "generic"


def _option(
    rank: int,
    title: str,
    approach: str,
    steps: List[str],
    *,
    effort: str,
    residual_risk: float,
    effectiveness: float,
    performance: PerformanceClass,
    performance_note: str,
    tradeoffs: List[str],
    when_to_choose: str,
) -> Dict[str, Any]:
    return {
        "rank": rank,
        "title": title,
        "approach": approach,
        "steps": steps,
        "effort": effort,  # hours_band: "<1h" | "1-4h" | "1-2d" | "3d+"
        "residual_risk": residual_risk,  # 0 low residual … 10 high residual
        "effectiveness": effectiveness,  # 0–10
        "performance_impact": performance,
        "performance_note": performance_note,
        "tradeoffs": tradeoffs,
        "when_to_choose": when_to_choose,
        # Composite: prefer high effectiveness, low residual, low effort
        "score": round(
            effectiveness * 1.2
            - residual_risk * 0.8
            + {"<1h": 2.0, "1-4h": 1.2, "1-2d": 0.4, "3d+": 0.0}.get(effort, 0.5),
            2,
        ),
    }


# ---------------------------------------------------------------------------
# Class catalogs: always exactly 3 options, pre-sorted preferred → deeper
# ---------------------------------------------------------------------------

def _catalog(cls: str, loc: str) -> List[Dict[str, Any]]:
    if cls == "command_injection":
        return [
            _option(
                1,
                "Pass argv lists  - never shell=True",
                f"At {loc}, replace shell string construction with an argv list and disable shell interpolation.",
                [
                    "Change `os.system` / `subprocess(..., shell=True)` to `subprocess.run([bin, *args], shell=False)`.",
                    "Allowlist the executable binary; do not take the binary path from the user.",
                    "Add a regression test that rejects metacharacters (`|;$`).",
                ],
                effort="<1h",
                residual_risk=2.0,
                effectiveness=9.0,
                performance="none",
                performance_note="argv exec is typically equal or faster than shell spawning.",
                tradeoffs=[
                    "Simple and closes most command-injection sinks.",
                    "Does not help if the binary itself is attacker-chosen.",
                ],
                when_to_choose="Default fix for almost all command-injection findings.",
            ),
            _option(
                2,
                "Move execution behind a typed job API",
                "Replace free-form command execution with an allowlisted operation enum (e.g. `rebuild`, `export`).",
                [
                    "Define an allowlist of operations → fixed argv templates.",
                    "Accept only structured parameters (ids, paths under a root).",
                    "Run the worker with dropped privileges / seccomp where available.",
                ],
                effort="1-2d",
                residual_risk=0.5,
                effectiveness=9.5,
                performance="low",
                performance_note="Indirection cost is negligible vs process spawn.",
                tradeoffs=[
                    "Best long-term design; requires API/product changes.",
                    "More code churn than option 1.",
                ],
                when_to_choose="When the product truly needs remote execution features.",
            ),
            _option(
                3,
                "Temporary harden: strict allowlist + timeout",
                "If a full rewrite is blocked, constrain inputs and runtime immediately.",
                [
                    "Reject any input matching `[;&|`$<>]`.",
                    "Set process timeout and resource limits.",
                    "Log and alert on blocked attempts; schedule option 1/2.",
                ],
                effort="<1h",
                residual_risk=6.0,
                effectiveness=5.0,
                performance="low",
                performance_note="Regex allowlist is cheap; do not treat as permanent.",
                tradeoffs=[
                    "Ships fast but bypasses via encoding/edge cases are common.",
                    "Must be paired with a tracked follow-up for option 1 or 2.",
                ],
                when_to_choose="Emergency mitigation only.",
            ),
        ]

    if cls == "sql_injection":
        return [
            _option(
                1,
                "Parameterized queries / bound ORM",
                f"At {loc}, stop concatenating or interpolating untrusted strings into SQL.",
                [
                    "Use `?` / `%s` placeholders or ORM `.filter()` with bound parameters.",
                    "Ban `f\"...{user}...\"`, `.format`, and string `+` into SQL.",
                    "Add a unit test that treats quotes as data, not syntax.",
                ],
                effort="<1h",
                residual_risk=1.5,
                effectiveness=9.5,
                performance="none",
                performance_note="Bound parameters are equal or faster than string-built SQL.",
                tradeoffs=["Standard correct fix.", "Does not fix ORM misuse of `.raw()` elsewhere."],
                when_to_choose="Default for every SQLi lead.",
            ),
            _option(
                2,
                "Query builder + column allowlist",
                "For dynamic ORDER BY / column names (cannot bind), allowlist identifiers.",
                [
                    "Map user-facing sort keys → fixed column identifiers.",
                    "Reject unknown keys; never interpolate raw identifiers.",
                    "Prefer a query builder that separates identifiers from values.",
                ],
                effort="1-4h",
                residual_risk=1.0,
                effectiveness=9.0,
                performance="none",
                performance_note="Allowlist lookup is O(1).",
                tradeoffs=["Needed when identifiers (not values) are dynamic.", "Slightly more code."],
                when_to_choose="Dynamic sort/filter surfaces.",
            ),
            _option(
                3,
                "DB least privilege + WAF rule (complement)",
                "Limit blast radius while patches roll out.",
                [
                    "App DB role: no DDL; only required DML on needed tables.",
                    "Optional WAF SQLi signature as temporary shield.",
                    "Do not treat WAF as the primary fix.",
                ],
                effort="1-4h",
                residual_risk=5.0,
                effectiveness=4.0,
                performance="low",
                performance_note="WAF inspection adds latency; DB privilege changes do not.",
                tradeoffs=["Does not remove the bug.", "Useful defense-in-depth."],
                when_to_choose="Alongside option 1, never instead of it.",
            ),
        ]

    if cls == "deserialization":
        return [
            _option(
                1,
                "Refuse unsafe loaders on untrusted data",
                f"At {loc}, replace `pickle` / unsafe `yaml.load` / `Marshal.load` with safe formats.",
                [
                    "Prefer JSON / `yaml.safe_load` / schema-validated protobufs.",
                    "If pickle is required, sign payloads with HMAC and verify before load.",
                    "Reject content-type / magic bytes that do not match the safe format.",
                ],
                effort="1-4h",
                residual_risk=1.5,
                effectiveness=9.5,
                performance="low",
                performance_note="JSON/safe_load usually comparable; signing adds small HMAC cost.",
                tradeoffs=["May require client migration.", "Correct default."],
                when_to_choose="Default whenever untrusted bytes reach a deserializer.",
            ),
            _option(
                2,
                "Isolate deserializer in a sandboxed worker",
                "If unsafe formats cannot be removed yet, isolate blast radius.",
                [
                    "Run deserialization in a separate process with no secrets / no net.",
                    "Strict timeouts and memory caps.",
                    "Treat output as untrusted data needing re-validation.",
                ],
                effort="1-2d",
                residual_risk=3.0,
                effectiveness=7.0,
                performance="medium",
                performance_note="Process isolation adds spawn/IPC overhead.",
                tradeoffs=["Complex ops cost.", "Still risk of sandbox escapes."],
                when_to_choose="Legacy formats that cannot be migrated immediately.",
            ),
            _option(
                3,
                "Network gate: disable endpoint / require authz",
                "Remove or lock down the exposure while a safe format ships.",
                [
                    "Disable the public deserialize route or put behind strong authz.",
                    "Rate-limit and audit access.",
                    "Track migration to option 1.",
                ],
                effort="<1h",
                residual_risk=4.5,
                effectiveness=6.0,
                performance="none",
                performance_note="No runtime overhead beyond auth checks.",
                tradeoffs=["Product impact if feature is required.", "Not a root-cause fix alone."],
                when_to_choose="Emergency exposure reduction.",
            ),
        ]

    if cls == "ssti":
        return [
            _option(
                1,
                "Never render untrusted strings as templates",
                f"At {loc}, pass user data as template **variables**, not as template **source**.",
                [
                    "Replace `render_template_string(user)` with a static template + `render_template(..., q=user)`.",
                    "Ensure autoescaping is enabled.",
                    "Add a test that `{{7*7}}` does not evaluate.",
                ],
                effort="<1h",
                residual_risk=1.0,
                effectiveness=9.5,
                performance="none",
                performance_note="Static templates are faster than compiling attacker strings.",
                tradeoffs=["May change API if clients sent templates intentionally.", "Correct fix."],
                when_to_choose="Default for SSTI.",
            ),
            _option(
                2,
                "Sandbox template environment",
                "If user templates are a product requirement, use a locked-down engine.",
                [
                    "Disable dangerous builtins / attributes.",
                    "Timeout renders; limit AST complexity.",
                    "Prefer purpose-built sandboxed engines over Jinja defaults.",
                ],
                effort="1-2d",
                residual_risk=3.5,
                effectiveness=7.0,
                performance="medium",
                performance_note="Sandboxing and limits add CPU checks per render.",
                tradeoffs=["Hard to get right; history of escapes.", "Higher maintenance."],
                when_to_choose="Only if user-authored templates are required.",
            ),
            _option(
                3,
                "Output-encode and strip template markers (weak)",
                "Temporary mitigation while option 1 ships.",
                [
                    "Reject input containing `{{`, `{%`, `${`.",
                    "HTML-encode on output.",
                    "Do not treat as sufficient alone.",
                ],
                effort="<1h",
                residual_risk=6.5,
                effectiveness=4.0,
                performance="low",
                performance_note="Simple string checks are cheap.",
                tradeoffs=["Easily bypassed.", "Emergency only."],
                when_to_choose="Hotfix while deploying option 1.",
            ),
        ]

    if cls == "path_traversal":
        return [
            _option(
                1,
                "Resolve + confine to an allowlisted root",
                f"At {loc}, canonicalize the path and reject escapes from the data root.",
                [
                    "Use `Path.resolve()` (or OS equivalent) then require `root in resolved.parents`.",
                    "Open only the resolved path; never concatenate blindly.",
                    "Reject null bytes and absolute paths from users.",
                ],
                effort="<1h",
                residual_risk=1.5,
                effectiveness=9.0,
                performance="low",
                performance_note="One filesystem resolve per request  - usually negligible.",
                tradeoffs=["Standard correct fix.", "Symlink races need care on some OSes."],
                when_to_choose="Default for file read/write sinks.",
            ),
            _option(
                2,
                "Object-storage / opaque IDs instead of paths",
                "Stop exposing filesystem paths to clients.",
                [
                    "Map document IDs → server-side storage keys.",
                    "Authorize access per object ACL.",
                    "Serve via signed URLs with short TTL if needed.",
                ],
                effort="1-2d",
                residual_risk=0.8,
                effectiveness=9.5,
                performance="low",
                performance_note="Extra DB/ACL lookup; usually fine.",
                tradeoffs=["API redesign.", "Best for multi-tenant apps."],
                when_to_choose="User-facing file features.",
            ),
            _option(
                3,
                "Chroot / container read-only mount (complement)",
                "Reduce blast radius of remaining bugs.",
                [
                    "Run the worker with a minimal filesystem view.",
                    "Mount data volumes read-only when possible.",
                ],
                effort="1-4h",
                residual_risk=4.0,
                effectiveness=5.0,
                performance="none",
                performance_note="No per-request overhead once configured.",
                tradeoffs=["Ops change; does not fix the logic bug."],
                when_to_choose="Defense-in-depth with option 1.",
            ),
        ]

    if cls == "ssrf":
        return [
            _option(
                1,
                "Allowlist outbound hosts + block link-local",
                f"At {loc}, validate URL scheme/host before any fetch.",
                [
                    "Allowlist schemes (`https`) and destination hosts.",
                    "Block `127.0.0.0/8`, `10/8`, `169.254.169.254`, IPv6 link-local, DNS rebinding.",
                    "Resolve DNS then re-check the IP before connect.",
                ],
                effort="1-4h",
                residual_risk=2.0,
                effectiveness=8.5,
                performance="low",
                performance_note="Extra DNS/IP checks add small latency per fetch.",
                tradeoffs=["Must maintain allowlist.", "Correct baseline."],
                when_to_choose="Default for URL-fetch sinks.",
            ),
            _option(
                2,
                "Server-side proxy with fixed upstreams",
                "Application never fetches arbitrary URLs; only known upstreams.",
                [
                    "Map resource ids → configured upstream base URLs.",
                    "Egress via locked-down proxy network policy.",
                ],
                effort="1-2d",
                residual_risk=1.0,
                effectiveness=9.5,
                performance="low",
                performance_note="Proxy hop adds latency; often acceptable.",
                tradeoffs=["Less flexible product behavior.", "Strongest design."],
                when_to_choose="When arbitrary URL fetch is not a real requirement.",
            ),
            _option(
                3,
                "Disable user-controlled URL fetch (temporary)",
                "Remove the feature flag / endpoint until allowlisting ships.",
                [
                    "Return 410/403 on the vulnerable route.",
                    "Document timeline for option 1.",
                ],
                effort="<1h",
                residual_risk=3.0,
                effectiveness=7.0,
                performance="none",
                performance_note="No overhead.",
                tradeoffs=["Product downtime for that feature."],
                when_to_choose="Emergency.",
            ),
        ]

    if cls == "authz_bypass":
        return [
            _option(
                1,
                "Apply the same guard on every sibling path",
                f"Mirror the proven authorize/authenticate check onto the unguarded path at {loc}.",
                [
                    "Copy the guard used by sibling handlers (B6).",
                    "Fail closed: missing authz → 401/403.",
                    "Add a test that unauthenticated/unauthorized calls are denied.",
                ],
                effort="<1h",
                residual_risk=2.0,
                effectiveness=8.5,
                performance="none",
                performance_note="One extra check is negligible.",
                tradeoffs=["Simplest correct fix for sibling divergence.", "Easy to miss other siblings."],
                when_to_choose="Default for sibling-variant / guard-alternate leads.",
            ),
            _option(
                2,
                "Central middleware  - deny by default",
                "Move authz to a single middleware/policy layer; routes opt into public.",
                [
                    "Default-deny all routes.",
                    "Explicit `@public` / `skip` only for documented endpoints.",
                    "Policy tests enumerate every route's authz class.",
                ],
                effort="1-2d",
                residual_risk=0.8,
                effectiveness=9.5,
                performance="low",
                performance_note="Central check once per request.",
                tradeoffs=["Larger refactor.", "Prevents class of bugs permanently."],
                when_to_choose="Apps with many routes / repeated skips.",
            ),
            _option(
                3,
                "Remove or disable the unguarded route",
                "If the alternate path is unused, delete it.",
                [
                    "Delete dead endpoints / unused controllers.",
                    "Confirm no clients depend on them.",
                ],
                effort="<1h",
                residual_risk=1.5,
                effectiveness=9.0,
                performance="none",
                performance_note="Less code → less surface.",
                tradeoffs=["Only works if route is truly unused."],
                when_to_choose="Dead code / forgotten admin paths.",
            ),
        ]

    if cls == "weak_secret":
        return [
            _option(
                1,
                "Use CSPRNG / secrets manager",
                f"At {loc}, replace `random`/`Math.random` for security tokens; remove hardcoded secrets.",
                [
                    "Use `secrets` / `crypto.randomBytes` / OS CSPRNG.",
                    "Load secrets from env/secret manager; rotate any exposed values.",
                    "Add lint rules banning insecure RNG near token/session code.",
                ],
                effort="<1h",
                residual_risk=1.5,
                effectiveness=9.0,
                performance="low",
                performance_note="CSPRNG is slightly slower than PRNG  - irrelevant for tokens.",
                tradeoffs=["May require secret rotation ops.", "Correct default."],
                when_to_choose="Default for weak RNG / hardcoded secrets.",
            ),
            _option(
                2,
                "Short-lived signed tokens (JWT with strong alg)",
                "Replace bespoke tokens with signed, expiring credentials.",
                [
                    "Use HS256/RS256 with keys from a secret manager  - never `alg:none`.",
                    "Set short `exp`; validate `aud`/`iss`.",
                    "Reject algorithms from the header allowlist-side.",
                ],
                effort="1-4h",
                residual_risk=1.5,
                effectiveness=9.0,
                performance="low",
                performance_note="HMAC/RSA verify costs are usually fine at auth rates.",
                tradeoffs=["Protocol change for clients."],
                when_to_choose="Session/API auth redesigns.",
            ),
            _option(
                3,
                "Rotate + monitor (complement)",
                "Assume compromise if secrets were committed.",
                [
                    "Rotate all affected credentials.",
                    "Scan git history; purge from images.",
                    "Add detection for anomalous use of old keys.",
                ],
                effort="1-4h",
                residual_risk=3.0,
                effectiveness=6.0,
                performance="none",
                performance_note="Ops work, not runtime cost.",
                tradeoffs=["Does not fix code alone.", "Required when exposure already happened."],
                when_to_choose="Always with option 1 when secrets leaked.",
            ),
        ]

    if cls == "xss":
        return [
            _option(
                1,
                "Context-aware output encoding",
                f"At {loc}, encode untrusted data for the HTML/JS/attr context; avoid `|safe` / `dangerouslySetInnerHTML`.",
                [
                    "Use framework auto-escape; remove unsafe sinks.",
                    "If HTML is required, sanitize with a vetted library allowlist.",
                    "Add CSP as complement (option 3).",
                ],
                effort="1-4h",
                residual_risk=2.0,
                effectiveness=9.0,
                performance="low",
                performance_note="Encoding is cheap vs network.",
                tradeoffs=["May break intentional HTML features.", "Correct default."],
                when_to_choose="Default XSS fix.",
            ),
            _option(
                2,
                "Sanitize with allowlist HTML policy",
                "When rich text is required, sanitize server-side before store/render.",
                [
                    "Use a maintained sanitizer with explicit tag/attr allowlist.",
                    "Sanitize on input and encode on output.",
                ],
                effort="1-4h",
                residual_risk=2.5,
                effectiveness=8.0,
                performance="medium",
                performance_note="HTML sanitizers cost CPU on large bodies.",
                tradeoffs=["Sanitizer bypass history  - keep updated.", "Needed for rich text."],
                when_to_choose="User-authored HTML features.",
            ),
            _option(
                3,
                "Strict CSP (complement)",
                "Reduce impact of residual XSS.",
                [
                    "Deploy CSP with nonces/hashes; disable `unsafe-inline`.",
                    "Use `Trusted Types` where supported.",
                ],
                effort="1-4h",
                residual_risk=4.0,
                effectiveness=6.0,
                performance="none",
                performance_note="Header only.",
                tradeoffs=["Does not remove the sink.", "Excellent defense-in-depth."],
                when_to_choose="Always alongside option 1/2 for web apps.",
            ),
        ]

    if cls == "code_injection":
        return [
            _option(
                1,
                "Delete eval/exec on untrusted input",
                f"At {loc}, remove `eval`/`exec`/`Function`/`constantize` on user data.",
                [
                    "Replace with explicit parsers, maps, or interpreters.",
                    "If dynamic dispatch is needed, allowlist callables.",
                    "Add lint bans for eval-family APIs in app code.",
                ],
                effort="1-4h",
                residual_risk=1.0,
                effectiveness=9.5,
                performance="none",
                performance_note="Removing eval usually improves performance.",
                tradeoffs=["May need redesign of dynamic features."],
                when_to_choose="Default.",
            ),
            _option(
                2,
                "Allowlisted dispatcher",
                "Map string names → vetted functions only.",
                [
                    "Maintain an explicit dict/enum of permitted operations.",
                    "Never construct code strings from user input.",
                ],
                effort="1-4h",
                residual_risk=2.0,
                effectiveness=8.5,
                performance="none",
                performance_note="Dict lookup is O(1).",
                tradeoffs=["Must keep allowlist complete."],
                when_to_choose="When dynamic operation selection is required.",
            ),
            _option(
                3,
                "Isolate interpreter (last resort)",
                "Run dynamic code in a locked-down sandbox process.",
                [
                    "No filesystem/network secrets in the sandbox.",
                    "Hard timeouts; treat results as untrusted.",
                ],
                effort="3d+",
                residual_risk=4.0,
                effectiveness=6.5,
                performance="high",
                performance_note="Sandboxing and process isolation dominate latency.",
                tradeoffs=["High complexity; escapes happen.", "Avoid if option 1 is possible."],
                when_to_choose="Only when executing untrusted code is a core product need.",
            ),
        ]

    if cls == "api_surface":
        return [
            _option(
                1,
                "Authz + allowlist on dangerous API sinks",
                f"For the dangerous surface near {loc}, require strong authz and constrain commands/paths.",
                [
                    "Authenticate and authorize every `/shell|/bash|/code|/file` style route.",
                    "Allowlist commands or map to typed operations; never raw shell from untrusted callers.",
                    "Audit-log every invocation with actor + args.",
                ],
                effort="1-4h",
                residual_risk=2.5,
                effectiveness=8.5,
                performance="low",
                performance_note="Authz/audit overhead is usually small vs command runtime.",
                tradeoffs=["Product may rely on open exec  - needs product decision."],
                when_to_choose="Default for OpenAPI/SDK exec surfaces.",
            ),
            _option(
                2,
                "Isolate execution sandbox per tenant",
                "Assume commands run  - contain them.",
                [
                    "Per-session containers with no host mounts / no cloud metadata.",
                    "Egress deny by default; CPU/memory/time caps.",
                    "Separate credentials from the execution environment.",
                ],
                effort="3d+",
                residual_risk=1.5,
                effectiveness=9.0,
                performance="medium",
                performance_note="Container start/cold-start dominates; pool warm sandboxes.",
                tradeoffs=["Significant platform work.", "Right architecture for agent sandboxes."],
                when_to_choose="Agent/code-execution products.",
            ),
            _option(
                3,
                "Disable or split admin-only exec APIs",
                "Expose exec only on an admin network / break-glass path.",
                [
                    "Remove public SDK wrappers for exec if unused.",
                    "Gate remaining routes on mTLS + admin RBAC.",
                ],
                effort="1-4h",
                residual_risk=3.0,
                effectiveness=7.5,
                performance="none",
                performance_note="No overhead.",
                tradeoffs=["May break legitimate automation."],
                when_to_choose="When broad exec is not required for all users.",
            ),
        ]

    # generic
    return [
        _option(
            1,
            "Validate at the trust boundary + fail closed",
            f"Treat input reaching {loc} as untrusted; validate/allowlist before the sink.",
            [
                "Identify the untrusted source and sink from the finding evidence.",
                "Add allowlist/validation immediately before the sink; deny by default.",
                "Add a regression test proving the reported PoC path is blocked.",
            ],
            effort="1-4h",
            residual_risk=3.0,
            effectiveness=7.5,
            performance="low",
            performance_note="Validation cost depends on checks; usually low.",
            tradeoffs=["Generic  - refine once class is clearer.", "Still the right first move."],
            when_to_choose="Unknown or mixed classes.",
        ),
        _option(
            2,
            "Remove or feature-flag the risky path",
            "If the behavior is non-essential, disable it until a durable fix lands.",
            [
                "Feature-flag or delete the endpoint/code path.",
                "Document customer impact and timeline.",
            ],
            effort="<1h",
            residual_risk=2.5,
            effectiveness=8.0,
            performance="none",
            performance_note="No overhead.",
            tradeoffs=["Product impact.", "Buys time for a correct fix."],
            when_to_choose="When exposure outweighs feature value.",
        ),
        _option(
            3,
            "Layer monitoring + least privilege (complement)",
            "Reduce blast radius and detect exploitation attempts.",
            [
                "Drop privileges / segment network.",
                "Alert on anomalous sink usage.",
            ],
            effort="1-4h",
            residual_risk=5.0,
            effectiveness=4.5,
            performance="low",
            performance_note="Telemetry has small overhead.",
            tradeoffs=["Does not remove the bug.", "Useful alongside 1/2."],
            when_to_choose="Always as complement for high-CVSS sinks.",
        ),
    ]


def propose_fixes(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return three ranked fix alternatives with trade-offs and estimated metrics.

    Rank order is the authored catalog order:
      1 = simplest effective (ship-today correct fix)
      2 = structural / durable
      3 = defense-in-depth / temporary mitigation
    Composite `score` is informational only  - we do NOT re-sort by score, because
    that would bury low-effort fixes under multi-day refactors.
    """
    t0 = time.perf_counter()
    blob = _blob(finding)
    cls = _classify(blob)
    loc = _location(finding)
    options = _catalog(cls, loc)
    for i, opt in enumerate(options, 1):
        opt["rank"] = i
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
    return {
        "bug_class": cls,
        "location": loc,
        "recommended_rank": 1,
        "design_note": (
            "Three alternatives: (1) minimal effective, (2) structural, "
            "(3) defense-in-depth/mitigation. Performance figures are estimated "
            "overhead classes  - lab microbenchmarks are skipped unless a runnable "
            "PoC exists to verify effectiveness (PoC blocked after patch)."
        ),
        "options": options,
        "generation_ms": elapsed_ms,
        "confidence": "high" if cls != "generic" else "low",
    }


def format_fixes_markdown(fix_block: Dict[str, Any]) -> str:
    """Render ranked fixes for Phase 3 reports."""
    lines = [
        "### Suggested Fixes (ranked)",
        "",
        f"_Class: `{fix_block.get('bug_class')}` · confidence: {fix_block.get('confidence')} · "
        f"location: {fix_block.get('location')}_",
        "",
        "> Rank 1 is the **simplest effective** fix. Rank 2 is the stronger structural fix. "
        "Rank 3 is defense-in-depth or temporary mitigation. Performance notes are estimated "
        "overhead, not lab microbenchmarks.",
        "",
    ]
    for opt in fix_block.get("options") or []:
        lines.append(
            f"#### Option {opt['rank']}: {opt['title']} "
            f"(effectiveness {opt['effectiveness']}/10 · effort {opt['effort']} · "
            f"residual risk {opt['residual_risk']}/10 · perf {opt['performance_impact']})"
        )
        lines.append("")
        lines.append(opt.get("approach") or "")
        lines.append("")
        lines.append("**Steps**")
        for s in opt.get("steps") or []:
            lines.append(f"- {s}")
        lines.append("")
        lines.append("**Trade-offs**")
        for t in opt.get("tradeoffs") or []:
            lines.append(f"- {t}")
        lines.append("")
        lines.append(f"**Performance:** {opt.get('performance_note')}")
        lines.append("")
        lines.append(f"**When to choose:** {opt.get('when_to_choose')}")
        lines.append("")
    return "\n".join(lines)


def measure_fix_engine(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Benchmark fix generation over a list of findings (local-lab measurement)."""
    t0 = time.perf_counter()
    classes: Dict[str, int] = {}
    total_opts = 0
    per_ms: List[float] = []
    samples = []
    for f in findings:
        block = propose_fixes(f)
        classes[block["bug_class"]] = classes.get(block["bug_class"], 0) + 1
        total_opts += len(block["options"])
        per_ms.append(block["generation_ms"])
        if len(samples) < 5:
            samples.append({
                "title": (f.get("title") or "")[:80],
                "class": block["bug_class"],
                "option1": block["options"][0]["title"] if block["options"] else None,
                "generation_ms": block["generation_ms"],
            })
    elapsed = (time.perf_counter() - t0) * 1000
    return {
        "findings": len(findings),
        "options_emitted": total_opts,
        "avg_options_per_finding": round(total_opts / max(len(findings), 1), 2),
        "class_histogram": classes,
        "generation_ms_total": round(elapsed, 3),
        "generation_ms_avg": round(sum(per_ms) / max(len(per_ms), 1), 3),
        "generation_ms_p95": round(sorted(per_ms)[int(0.95 * (len(per_ms) - 1))] if per_ms else 0, 3),
        "samples": samples,
        "verdict": (
            "3-alternative ranked fixes are appropriate; "
            "skip per-option lab microbenchmarks; verify PoC-blocked when lab+PoC exist."
        ),
    }
