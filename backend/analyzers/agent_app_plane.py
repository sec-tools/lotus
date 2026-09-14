"""Phase-1 mapper for Ruby agents/CM, unauth mail UIs, Rails+Node SSR, AI proxies,
privileged ACME CLIs, and Django object-authz.

Generic grep, Rails Marshal/PDF skills, and gateway-control-plane miss the
classes that actually ship in Puppet, Mailcatcher, react_on_rails, Headroom,
Certbot, and Zulip:

  Puppet         — YAML/PSON catalog deser, Execution.execute interpolation, auth.conf allow *
  Mailcatcher    — Sinatra/Thin UI with no auth bound on 0.0.0.0
  react_on_rails — ExecJS / Open3 node prerender of attacker-influenced JS
  Headroom       — caller-supplied upstream URL (SSRF) + identity header spoof
  Certbot        — root deploy/pre/post hooks via subprocess, yaml.load of config
  Zulip          — missing has_message_access / access_stream sibling, webhook SSRF

DoS/parser-hang is ignored. Every lead is CVSS ≥ 7 and tagged with a Phase-2
hint so ``backend/agent_app_poc.py`` can prove or disprove it in the local lab.
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
    "spec", "tests", "test", "docs", "examples", "website", "changelog",
    ".agents",
}

_EXT = {
    ".rb", ".py", ".js", ".ts", ".jsx", ".tsx", ".yml", ".yaml", ".json",
    ".conf", ".pp", ".erb", ".ru", ".rake",
}

_HINT_EXT = {
    "puppet_": {".rb", ".pp", ".erb", ".conf", ".yaml", ".yml"},
    "ror_": {".rb", ".js", ".ts", ".jsx", ".tsx", ".yml", ".yaml"},
    "mail_": {".rb", ".ru"},
    "sinatra_": {".rb", ".ru"},
    "ruby_bind": {".rb", ".ru", ".yml", ".yaml"},
    "ai_": {".py", ".ts", ".js", ".yml", ".yaml", ".json"},
    "certbot_": {".py", ".sh", ".yml", ".yaml"},
    "zulip_": {".py"},
    "django_": {".py"},
}

_RUBY_EXECUTION_HINTS = {"ror_execjs_rce", "ror_open3_node", "ror_system_node"}

# (regex, title, cvss, description, phase2_hint, family)
_RULES: List[Tuple[re.Pattern, str, float, str, str, str]] = [
    # --- Puppet / Ruby agent ---
    (re.compile(r"YAML\.load\s*\(|Psych\.load\s*\(|Psych\.unsafe_load\s*\("),
     "Puppet-style YAML.load of catalog/facts (Ruby deser RCE)", 9.1,
     "YAML.load/Psych.load of network or file catalogs instantiates !!ruby/object. "
     "Lab: catalog with gadget / analog POST /catalog yaml → uid=.",
     "puppet_yaml_deser", "deser"),
    (re.compile(r"PSON\.parse\s*\(|JSON\.load\s*\([^)]*create_additions:\s*true"),
     "PSON/JSON.create_additions object instantiation", 8.8,
     "Puppet PSON historically instantiates Ruby classes from JSON. Lab: json_class payload.",
     "puppet_pson_deser", "deser"),
    (re.compile(r"Puppet::Util::Execution\.execute|Puppet::Util::Execution\.execute|Execution\.execute\s*\("),
     "Puppet Execution.execute command sink", 9.0,
     "Agent exec resource / provider shells out. If command interpolates catalog params, RCE.",
     "puppet_exec_rce", "rce"),
    (re.compile(r"allow\s+['\"]\*['\"]"),
     "Puppet auth.conf allow * (unauthenticated REST)", 8.6,
     "REST endpoints allow any caller. Lab: unauthenticated GET /puppet/v3/catalog.",
     "puppet_auth_star", "authz"),
    (re.compile(r"instance_eval\s*\(|module_eval\s*\([^)]*(catalog|manifest|source)"),
     "Puppet instance_eval of catalog/manifest text", 9.3,
     "Eval of catalog DSL/ERB from the wire is RCE. Lab: instance_eval analog.",
     "puppet_eval_rce", "rce"),
    (re.compile(r"Marshal\.(load|restore)\s*\("),
     "Marshal.load of reports/facts", 9.0,
     "Puppet reports historically Marshal.load client blobs. Lab: marshal analog uid=.",
     "puppet_marshal_deser", "deser"),
    (re.compile(r"\bpluginsync\b|\bpluginfactssync\b"),
     "Puppet pluginsync loads Ruby from modules", 8.4,
     "pluginsync drops .rb from a master into the agent load path. Compromised module → RCE.",
     "puppet_pluginsync", "rce"),
    # --- Mailcatcher / Sinatra mail UI ---
    (re.compile(r"MailCatcher|mailcatcher"),
     "MailCatcher-style catch-all SMTP+HTTP UI", 7.8,
     "Catch-all mailbox UI. If bound without auth this dumps all captured mail.",
     "mail_ui_unauth", "authz"),
    (re.compile(r"bind[:\s=>]+['\"]0\.0\.0\.0['\"]|set\s+:bind,\s*['\"]0\.0\.0\.0"),
     "Ruby HTTP server bound on 0.0.0.0", 8.1,
     "Sinatra/Thin/WEBrick listen on all interfaces. Pair with missing Rack::Auth.",
     "ruby_bind_all", "authz"),
    (re.compile(r"class\s+\w+\s*<\s*Sinatra::Base|Sinatra::Base"),
     "Sinatra app class (check auth wrapping)", 7.2,
     "Sinatra apps often ship with no before { authorize }. Lab: GET /messages unauthenticated.",
     "sinatra_unauth", "authz"),
    # --- react_on_rails / ExecJS ---
    (re.compile(r"ExecJS\.(eval|compile|exec)|ReactOnRails::ServerRendering"),
     "ExecJS / ReactOnRails server render eval", 9.0,
     "SSR eval of JS. If props/bundle path is attacker-influenced, RCE in Node.",
     "ror_execjs_rce", "rce"),
    (re.compile(r"Open3\.(popen3|capture3|pipeline)\s*\([^)]*(?:\bnode\b|webpack|yarn|npm)"),
     "Open3 spawn of node/webpack/yarn", 8.7,
     "Prerender/assets shell out to node. Interpolated env/path → command injection.",
     "ror_open3_node", "rce"),
    (re.compile(r"(?<![\w.])(?:Kernel\.)?system\s*\([^)]*\b(?:webpack|yarn)\b|`[^`]*\bwebpack\b[^`]*`"),
     "Kernel.system/backtick of webpack toolchain", 8.5,
     "Asset compile/prerender via shell. Lab: PATH= analog uid=.",
     "ror_system_node", "rce"),
    (re.compile(r"\bprerender\s*[:=]|server_render"),
     "ReactOnRails prerender flag", 7.6,
     "Prerender executes JS at request time. Untrusted props reaching ExecJS is RCE.",
     "ror_prerender", "rce"),
    # --- Headroom / AI proxy ---
    (re.compile(r"x-headroom-base-url|HEADROOM_.*BASE_URL|x-headroom-user-id", re.I),
     "AI-proxy caller-supplied upstream or identity header", 8.8,
     "Client sets upstream URL (SSRF to metadata) or spoofs user id. Lab: header analog.",
     "ai_proxy_header", "ssrf"),
    (re.compile(r"HEADROOM_PROXY_TOKEN|proxy_token.*optional"),
     "AI-proxy token optional / fail-open", 8.3,
     "Missing proxy token still serves. Lab: unauthenticated /v1/messages.",
     "ai_proxy_token_optional", "authz"),
    (re.compile(r"verify\s*=\s*False|CERT_NONE|ssl\._create_unverified_context"),
     "TLS verification disabled on upstream client", 8.0,
     "MITM of LLM/upstream. Combined with bind-all this is credential theft.",
     "ai_tls_off", "authz"),
    (re.compile(r"tarfile\.extract(?:all)?\s*\(|extractall\s*\("),
     "tarfile.extractall without data filter", 7.9,
     "Path traversal / overwrite from a model/bundle tarball. Lab: tar analog write.",
     "ai_tar_slip", "logic"),
    (re.compile(r"169\.254\.169\.254|metadata\.google|is_safe_upstream"),
     "Cloud-metadata / upstream-guard surface", 8.5,
     "SSRF guard present or missing. Lab: http://169.254.169.254 analog.",
     "ai_ssrf_metadata", "ssrf"),
    # --- Certbot / privileged CLI ---
    (re.compile(r"pre_hook|post_hook|deploy_hook|renew_hook"),
     "Certbot-style privileged hook execution", 8.9,
     "Hooks run as root via subprocess. If hook path/content is writable, RCE.",
     "certbot_hook_rce", "rce"),
    (re.compile(r"yaml\.load\s*\((?![^)\n]*(?:Safe|Base|Full|CLoader|json))[^)\n]*\)"),
     "Unsafe yaml.load (arbitrary object instantiation)", 8.2,
     "yaml.load without a safe loader can instantiate objects. Lab: !!python/object/apply:os.system.",
     "certbot_yaml_deser", "deser"),
    (re.compile(r"subprocess\.(call|run|Popen|check_call)\s*\([^)]*(hook|renew|apache|nginx|certbot)"),
     "subprocess of apache/nginx/certbot hook", 8.6,
     "Installer plugins shell out. Interpolated vhost/name → command injection.",
     "certbot_subprocess", "rce"),
    (re.compile(r"os\.system\s*\(|os\.popen\s*\("),
     "os.system/popen in privileged CLI", 9.0,
     "Root CLI os.system. Lab: analog hook uid=.",
     "certbot_os_system", "rce"),
    (re.compile(r"chmod\s*\([^,]+,\s*0o?777|os\.chmod\s*\([^,]+,\s*0o?777"),
     "chmod 0777 on cert/challenge path", 7.5,
     "World-writable live certs or webroot lets a local user replace keys.",
     "certbot_chmod_777", "logic"),
    # --- Zulip / Django object authz / SSRF ---
    (re.compile(r"csrf_exempt|@csrf_exempt"),
     "Django csrf_exempt on mutating view", 7.8,
     "Webhook/API csrf_exempt. If combined with weak token, state change is CSRF/authz.",
     "django_csrf_exempt", "authz"),
    (re.compile(r"preview_url|get_link_embed|fetch_open_graph|urlopen\s*\(\s*(url|link)"),
     "Link-preview / embed fetch (SSRF)", 8.1,
     "Markdown/link previews fetch user URLs. Lab: 169.254.169.254 analog.",
     "zulip_link_ssrf", "ssrf"),
    (re.compile(r"subprocess\.(run|Popen|check_output)\s*\([^)]*(thumbnail|ffmpeg|convert|identify)"),
     "Thumbnail/ffmpeg subprocess", 8.4,
     "Upload pipeline shells out. Filename interpolation → RCE.",
     "zulip_thumb_rce", "rce"),
    (re.compile(r"pickle\.loads?\s*\(|yaml\.unsafe_load\s*\("),
     "Python pickle/unsafe yaml in app path", 9.0,
     "Session/cache pickle or yaml.unsafe_load. Lab: analog uid=.",
     "django_pickle", "deser"),
]


def _rel(dest: Path, p: Path) -> str:
    try:
        return str(p.relative_to(dest))
    except Exception:
        return str(p)


def _hint_ok(hint: str, suf: str) -> bool:
    if hint in _RUBY_EXECUTION_HINTS:
        return suf in {".rb", ".ru", ".rake"}
    for prefix, exts in _HINT_EXT.items():
        if hint.startswith(prefix) or hint == prefix.rstrip("_"):
            return suf in exts
    return True


def _without_ruby_comments(text: str) -> str:
    """Blank ordinary Ruby comments while retaining source offsets and strings.

    This is a lexical filter for these existing lead rules, not a Ruby parser.
    Quoted arguments and backtick commands remain available for sink matching.
    """
    result = list(text)
    quote = ""
    escaped = False
    block = False
    offset = 0
    for line in text.splitlines(keepends=True):
        if not quote and (block or re.match(r"^=begin(?:\s|$)", line)):
            block = not bool(re.match(r"^=end(?:\s|$)", line))
            for i, char in enumerate(line):
                if char not in "\r\n":
                    result[offset + i] = " "
        else:
            for i, char in enumerate(line):
                if escaped:
                    escaped = False
                elif quote:
                    if char == "\\":
                        escaped = True
                    elif char == quote:
                        quote = ""
                elif char in "\"'`":
                    quote = char
                elif char == "#":
                    for j in range(i, len(line)):
                        if line[j] not in "\r\n":
                            result[offset + j] = " "
                    break
        offset += len(line)
    return "".join(result)


def _iter_files(dest: Path, limit: int = 8000) -> Iterable[Path]:
    dest = Path(dest)
    n = 0
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        rel_root = Path(root).relative_to(dest)
        if any(part in SKIP_DIRS for part in rel_root.parts):
            continue
        for fname in files:
            p = Path(root) / fname
            if p.suffix.lower() not in _EXT:
                continue
            if fname.lower().startswith("readme"):
                continue
            if fname in {"pnpm-lock.yaml", "package-lock.json", "yarn.lock", "Gemfile.lock", "Cargo.lock"}:
                continue
            n += 1
            if n > limit:
                return
            yield p


def collect_agent_app_plane(dest: Path, language: str = "") -> Tuple[List[dict], Dict[str, Any]]:
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
        if any(x in low for x in ("/vendor/", "/third_party/", "/node_modules/", "/.agents/")):
            continue
        suf = path.suffix.lower()
        ruby_text = _without_ruby_comments(text) if suf in {".rb", ".ru", ".rake"} else ""
        for rx, title, cvss, desc, hint, family in _RULES:
            if not _hint_ok(hint, suf):
                continue
            if hint.startswith("certbot_hook") and not any(
                k in low or k in text.lower()
                for k in ("certbot", "letsencrypt", "acme", "renew_hook", "deploy_hook")
            ):
                continue
            if hint.startswith("ror_") and not any(
                k in low or k in text
                for k in ("ExecJS", "ReactOnRails", "prerender", "webpack", "react_on_rails")
            ):
                continue
            m = rx.search(ruby_text if hint in _RUBY_EXECUTION_HINTS else text)
            if not m:
                continue
            line = text[:m.start()].count("\n") + 1
            findings.append({
                "tool": "agent-app-control-plane",
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
                    "rce": "X-1", "deser": "X-5", "authz": "auth_bypass",
                    "ssrf": "ssrf", "logic": "logic",
                }.get(family, family),
                "discovery_technique": "agent-app-control-plane",
            })
        # Sibling skip: object fetch without the canonical access helper in this file.
        helpers = ("has_message_access", "access_message", "access_stream_by_id")
        if (
            suf == ".py"
            and re.search(r"Message\.objects\.(?:get|filter)|get_raw_message|message_id", text)
            and not any(h in text for h in helpers)
            and re.search(r"def\s+\w+", text)
            and any(k in low for k in ("view", "zerver", "zulip", "api", "webhook"))
        ):
            findings.append({
                "tool": "agent-app-control-plane",
                "title": "Django/Zulip object fetch skips has_message_access",
                "cvss": 8.2,
                "description": (
                    f"View reads a message/stream by id without the canonical access helper. IDOR. {rel}."
                ),
                "file": rel,
                "line": 1,
                "confidence": "high",
                "qualification": "QUALIFIED",
                "qualification": "QUALIFIED",
                "phase2_hint": "zulip_idor_skip",
                "canonical_class": "authz",
                "primitive_type": "auth_bypass",
                "discovery_technique": "agent-app-control-plane",
            })
        # Sinatra mailbox UI with no Rack::Auth in the same file.
        if (
            suf in {".rb", ".ru"}
            and "Sinatra::Base" in text
            and "Rack::Auth" not in text
            and re.search(r"messages|/messages|mailbox|MailCatcher", text, re.I)
        ):
            findings.append({
                "tool": "agent-app-control-plane",
                "title": "Sinatra mailbox UI with no Rack::Auth",
                "cvss": 8.0,
                "description": f"Mail UI routes exist without Rack::Auth. Lab: GET /messages unauthenticated. {rel}.",
                "file": rel,
                "line": 1,
                "confidence": "high",
                "qualification": "QUALIFIED",
                "qualification": "QUALIFIED",
                "phase2_hint": "mail_ui_unauth",
                "canonical_class": "authz",
                "primitive_type": "auth_bypass",
                "discovery_technique": "agent-app-control-plane",
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
    uniq = [f for f in uniq if float(f.get("cvss") or 0) >= 7.0]
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
        (out / "agent_app_plane_trace.json").write_text(
            json.dumps({"trace": trace, "leads": [
                {"title": f["title"], "file": f["file"], "cvss": f["cvss"], "hint": f.get("phase2_hint")}
                for f in uniq[:80]
            ]}, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass
    return uniq, trace


def _run_agent_app_plane(dest: Path, language: str) -> List[dict]:
    findings, _ = collect_agent_app_plane(dest, language)
    return findings


def agent_app_plane_strategy(dest: Path, language: str) -> List[dict]:
    """Discovery-engine strategy wrapper."""
    return _run_agent_app_plane(dest, language)
