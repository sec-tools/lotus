"""Phase-1 mapper for reverse-proxy / API-gateway / WAF control planes.

Generic grep, C++ high-severity-surface, and CubeSandbox-shaped control-plane
regexes miss the bug classes that actually ship in Envoy, Apache ShenYu, frp,
and SafeLine:

  Envoy  — ext_authz ``failure_mode_allow``, admin bind 0.0.0.0, Lua os.execute
  ShenYu — Groovy/SpEL plugin script RCE, Hessian/XStream config deser, JWT skip
  frp    — empty token fail-open, dashboard default creds, HTTP plugin exec
  SafeLine — management API vs data-plane, trusted X-Forwarded-For, rule compile

DoS/parser-hang is ignored. Every lead is CVSS ≥ 7 and tagged with a Phase-2
hint so ``backend/gateway_poc.py`` can prove or disprove it in the local lab.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".bundle", "__pycache__", ".venv", "venv",
    "target", "build", "dist", "testdata", "third_party", "thirdparty",
    "bazel-bin", "bazel-out", "generated", ".tox",
}

_EXT = {
    ".go", ".java", ".yaml", ".yml", ".json", ".lua", ".cc", ".cpp", ".h",
    ".proto", ".conf", ".xml", ".properties",
}

# (regex, title, cvss, description, phase2_hint, family)
# family: authz | rce | deser | logic
_RULES: List[Tuple[re.Pattern, str, float, str, str, str]] = [
    # --- Envoy / C++ proxy ---
    (re.compile(r"failure_mode_allow\s*:\s*true|failure_mode_allow\s*:\s*true", re.I),
     "Envoy ext_authz failure_mode_allow fail-open", 8.6,
     "When the authorization service is down/timeout Envoy allows the request. "
     "Pre-auth RCE/data-plane bypass: take ext_authz offline and send a privileged request.",
     "envoy_fail_open", "authz"),
    (re.compile(r"status_on_error\s*:\s*0\b"),
     "Envoy ext_authz status_on_error=0 (allow)", 8.4,
     "HTTP 0 / default on authz error is fail-open. Lab: RST the authz cluster.",
     "envoy_fail_open", "authz"),
    (re.compile(r"admin\s*:[\s\S]{0,240}address:\s*0\.0\.0\.0|address:\s*0\.0\.0\.0[\s\S]{0,80}port_value:\s*(9901|9902|9903|8001)", re.I),
     "Envoy admin interface bound on 0.0.0.0", 8.8,
     "Admin /quitquitquit, /config_dump, /certs exposed on all interfaces. "
     "Lab: unauthenticated GET /config_dump then POST /quitquitquit.",
     "envoy_admin_unauth", "authz"),
    (re.compile(r"os\.execute\s*\(|io\.popen\s*\("),
     "Envoy Lua filter OS command execution", 9.0,
     "Lua filter calls os.execute/io.popen. If request headers/body reach the arg, this is RCE.",
     "lua_os_execute", "rce"),
    (re.compile(r"inline_code\s*:|inline_code\s*:|inline_string\s*:"),
     "Envoy inline Lua code in config", 7.8,
     "Inline Lua in xDS/bootstrap. If config is writable via ADS or filesystem, code exec.",
     "lua_inline", "rce"),
    (re.compile(r"ignore_path\s*:\s*true|ignore_path\s*:\s*true|shadow_rules_stat_prefix"),
     "Envoy RBAC ignore_path / shadow-only", 7.5,
     "RBAC path ignored or shadow-only: policy never denies. Lab: hit denied path, expect 200.",
     "envoy_rbac_shadow", "authz"),
    # --- Apache ShenYu / Java gateway ---
    (re.compile(r"failure_mode_allow_|FailureModeAllow|failureModeAllow\s*\("),
     "Envoy ext_authz FailureModeAllow C++/proto", 8.6,
     "Generated/C++ field for ext_authz fail-open. Same class as YAML failure_mode_allow: true.",
     "envoy_fail_open", "authz"),
    (re.compile(r"GroovyShell|GroovyClassLoader|groovy\.lang\.GroovyShell|GroovyUtil"),
     "ShenYu-style GroovyShell script execution", 9.8,
     "Plugin/selector compiles Groovy from stored plugin handle. Admin write → RCE. "
     "Lab: PUT plugin script `Runtime.getRuntime().exec(\"id\")` then traffic the selector.",
     "groovy_plugin_rce", "rce"),
    (re.compile(r"SpelExpressionParser|StandardEvaluationContext|parseExpression\s*\("),
     "SpEL expression evaluation on plugin/config input", 9.6,
     "Spring SpEL eval of selector/handle JSON. Classic ShenYu/Spring-gateway RCE class.",
     "spel_plugin_rce", "rce"),
    (re.compile(r"ScriptEngineManager|getEngineByName\s*\(\s*\"(js|nashorn|groovy)\""),
     "Java ScriptEngine on plugin input", 9.3,
     "JSR-223 engine evaluates plugin script. Lab: engine.eval(request body).",
     "script_engine_rce", "rce"),
    (re.compile(r"HessianProxyFactory|Hessian2Input|com\.caucho\.hessian"),
     "Hessian deserialization of plugin/RPC payload", 8.8,
     "Hessian gadget chains (Rome, Commons-Collections) if type is untrusted.",
     "hessian_deser", "deser"),
    (re.compile(r"ObjectInputStream\s*\("),
     "Java ObjectInputStream on gateway config/RPC", 9.0,
     "readObject of plugin handle / session blob. Lab: ysoserial payload + canary file.",
     "java_ois_deser", "deser"),
    (re.compile(r"@AnonymousAccess|skipSign\s*=\s*true|isSkip\s*\(.*[Aa]uth"),
     "ShenYu anonymous / skip-sign plugin path", 8.2,
     "Selector skips sign/JWT. Sibling routes require auth. Lab: replay without sign header.",
     "shenyu_skip_auth", "authz"),
    (re.compile(r"secret[Kk]ey\s*=\s*\"[A-Za-z0-9]{8,}\"|jwtSecret\s*=\s*\""),
     "Hardcoded JWT/HMAC secret in gateway admin", 8.5,
     "Forge admin JWT. Lab: HS256 token with stolen secret → /dashboard user list.",
     "jwt_hardcoded", "authz"),
    (re.compile(r"fastjson|ParserConfig\.getGlobalInstance|autoTypeSupport"),
     "Fastjson autoType on gateway JSON", 9.4,
     "autoType gadget RCE (TemplatesImpl). Lab: JSON with @type.",
     "fastjson_autotype", "deser"),
    # --- frp ---
    (re.compile(r"if\s+.*[Tt]oken\s*==\s*\"\"\s*\{[^}]{0,200}(return nil|return true|pass)|getDefaultTokenConf[\s\S]{0,120}Token:\s*\"\""),
     "frp-style empty token fail-open", 9.1,
     "Empty token skips auth for control connection. Lab: frpc with token=\"\" joins server.",
     "frp_empty_token", "authz"),
    (re.compile(r"dashboard_pwd\s*:?=\s*\"\"|dashboard_user\s*:?=\s*\"\"|DefaultDashboard(?:Pwd|User)|dashboard_pwd\",\s*\"\",\s*\"admin\""),
     "frp dashboard default/empty credentials", 8.7,
     "Dashboard binds with empty or default user/pwd. Lab: GET /api/proxy/tcp unauthenticated.",
     "frp_dashboard", "authz"),
    (re.compile(r"plugin\.(Handle|Handler)|plugin\.Open\s*\(|HTTPPlugin|NewHTTPPlugin"),
     "frp HTTP plugin handler (command/unix)", 8.3,
     "Server-side HTTP plugin receives Login/NewProxy RPCs. If plugin addr is attacker-influenced, RCE/SSRF.",
     "frp_plugin", "rce"),
    (re.compile(r"allowUsers\s*==\s*nil|len\(allowUsers\)\s*==\s*0"),
     "frp allowUsers empty = all users", 7.8,
     "Empty allow-list means every authenticated user can bind every proxy. Logic/authz.",
     "frp_allow_users", "logic"),
    # --- SafeLine / WAF management ---
    (re.compile(
        r"(?is)(trust(?:ed)?|allow(?:list)?|whitelist|real[_-]?ip|client[_-]?ip).{0,120}X-Forwarded-For"
        r"|X-Forwarded-For.{0,120}(trust(?:ed)?|allow(?:list)?|whitelist|real[_-]?ip)"
    ),
     "WAF trusts client-supplied forwarding header", 8.0,
     "Detector/ACL uses X-Forwarded-For from the client as a trusted identity. "
     "Lab: spoof header to bypass IP allowlist / reach management plane.",
     "waf_xff_trust", "authz"),
    (re.compile(r"/api/open/|/manage/|/safeline/api/"),
     "WAF management API path", 7.9,
     "Management plane next to data plane. Lab: unauthenticated GET/POST on /api/open/* vs 401.",
     "waf_mgmt_api", "authz"),
    (re.compile(r"exec\.Command\s*\([^)]*(nginx|safeline|reload|iptables)"),
     "WAF exec.Command of nginx/reload/iptables", 8.9,
     "Management action shells out. If rule/name is interpolated, command injection.",
     "waf_exec_reload", "rce"),
    (re.compile(r"Compile\s*\(.*[Rr]ule|regexp\.MustCompile\s*\(.*[Bb]ody"),
     "WAF compiles user-supplied rule to regexp/bytecode", 7.6,
     "Rule compile from API. Prefer RCE if template/script; else logic bypass (never-match rule).",
     "waf_rule_compile", "logic"),
]


def _rel(dest: Path, p: Path) -> str:
    try:
        return str(p.relative_to(dest))
    except Exception:
        return str(p)


def _iter_files(dest: Path, limit: int = 5000) -> Iterable[Path]:
    dest = Path(dest)
    n = 0
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        rel_root = Path(root).relative_to(dest)
        if any(part in SKIP_DIRS for part in rel_root.parts):
            continue
        for fname in files:
            p = Path(root) / fname
            if p.suffix.lower() not in _EXT and fname not in {"Dockerfile", "envoy.yaml", "bootstrap.yaml"}:
                continue
            n += 1
            if n > limit:
                return
            yield p


def collect_gateway_plane(dest: Path, language: str = "") -> Tuple[List[dict], Dict[str, Any]]:
    dest = Path(dest)
    findings: List[dict] = []
    n_files = 0
    for path in _iter_files(dest):
        n_files += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if len(text) > 800_000:
            text = text[:800_000]
        rel = _rel(dest, path)
        low = rel.lower()
        if any(x in low for x in ("/vendor/", "/third_party/", "/testdata/")):
            continue
        if (
            low.startswith("test/")
            or "/test/" in low
            or "/tests/" in low
            or "_test.go" in low
            or "/docs/" in low
        ) and path.suffix.lower() not in {".yaml", ".yml", ".lua", ".conf"}:
            if not any(k in low for k in ("example", "conf", "config", "lua", "testdata")):
                continue
        suf = path.suffix.lower()
        for rx, title, cvss, desc, hint, family in _RULES:
            if hint in {
                "groovy_plugin_rce", "spel_plugin_rce", "fastjson_autotype",
                "hessian_deser", "java_ois_deser",
            } and suf not in {".java", ".kt", ".xml", ".gradle"}:
                continue
            if hint in {"frp_empty_token", "frp_dashboard", "frp_plugin", "frp_allow_users"} and suf not in {".go", ".toml", ".ini", ".json", ".yml", ".yaml"}:
                continue
            m = rx.search(text)
            if not m:
                continue
            line = text[:m.start()].count("\n") + 1
            findings.append({
                "tool": "gateway-control-plane",
                "title": title,
                "cvss": cvss,
                "description": f"{desc} Hit `{m.group(0)[:80]}` in {rel}:{line}.",
                "file": rel,
                "line": line,
                "confidence": "high",
                "qualification": "QUALIFIED",
                "qualification": "QUALIFIED",
                "phase2_hint": hint,
                "canonical_class": family,
                "primitive_type": {
                    "rce": "X-1", "deser": "X-5", "authz": "auth_bypass", "logic": "logic",
                }.get(family, family),
                "discovery_technique": "gateway-control-plane",
            })
    seen = set()
    uniq: List[dict] = []
    for f in findings:
        k = (f["title"], f["file"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    uniq.sort(key=lambda x: -float(x.get("cvss") or 0))
    trace = {
        "n_files": n_files,
        "n_findings": len(uniq),
        "language": language,
        "families": sorted({f["canonical_class"] for f in uniq}),
        "hints": sorted({f.get("phase2_hint") or "" for f in uniq} - {""}),
    }
    try:
        out = dest / ".lotus"
        out.mkdir(exist_ok=True)
        (out / "gateway_plane_trace.json").write_text(
            json.dumps({"trace": trace, "leads": [
                {"title": f["title"], "file": f["file"], "cvss": f["cvss"], "hint": f.get("phase2_hint")}
                for f in uniq[:80]
            ]}, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass
    return uniq, trace


def _run_gateway_control_plane(dest: Path, language: str) -> List[dict]:
    findings, _ = collect_gateway_plane(dest, language)
    return findings


def gateway_control_plane_strategy(dest: Path, language: str) -> List[dict]:
    """Discovery-engine strategy wrapper."""
    return _run_gateway_control_plane(dest, language)
