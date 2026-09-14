"""Phase-1 high-severity surface mapper.

Feeds Phase 2 with protocol/auth/plugin/document-parsing intel that generic
grep + web-centric auth-structural analysis miss — especially C/C++ brokers
and databases, and Ruby document libraries.

Detectors are deterministic (no AI, no Docker). Lab proof happens later.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".bundle", "__pycache__", ".venv", "venv",
    "target", "build", "dist", "test", "tests", "spec", "specs", "testdata",
    "fixtures", "examples", "example", "mock", "mocks", "__tests__", "docs",
    "doc", "benchmark", "benchmarks", "unittest", "unittests", "third_party",
    "thirdparty", ".tox", "sorbet", "rbi", "licenses",
}

_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".rb", ".py", ".go",
        ".java", ".json", ".yml", ".yaml", ".conf", ".cnf", ".rs"}

# Fail-open / skip-auth shapes that are CVSS≥7 when they sit on a network plane.
_AUTH_FAIL_OPEN = [
    (re.compile(r"d_shouldPass\s*=\s*true"), "Anonymous authenticator defaults shouldPass=true"),
    (re.compile(r"shouldPass\s*=\s*true"), "Anonymous/allow authenticator shouldPass defaults true"),
    (re.compile(r"return true;\s*\n\s*\}", re.M), None),  # too broad; used with authorize() context
    (re.compile(r"Authorize allow on"), "Default authorizer logs allow-all"),
    (re.compile(r"implicitly\s+assigned the default anonymous credential", re.I),
     "Unauthenticated clients implicitly get anonymous credential"),
    (re.compile(r"clients that do not\s+send an authentication request will be implicitly", re.I),
     "Skip-auth: missing auth request still authenticates"),
    (re.compile(r"allow_empty_user|allow-empty-password|skip[-_]?grant", re.I),
     "Empty-password / skip-grant authentication"),
]

_AUTHORIZE_ALLOW_ALL = re.compile(
    r"bool\s+\w*Authorizer\w*::authorize\s*\([^)]*\)[^{]*\{[^}]{0,400}return\s+true\s*;",
    re.S,
)

_DLOPEN = re.compile(r"\bdlopen\s*\(\s*([^,]+)\s*,")
_LISTEN = re.compile(r"\b(listen|bind|asio::ip::tcp|CreateListenSocket|oblistener)\s*\(")
_PORT_JSON = re.compile(r'"port"\s*:\s*(\d+)')
_LOAD_DATA = re.compile(r"LOAD DATA\s+(?:LOCAL\s+)?INFILE|INTO\s+OUTFILE|load_file\s*\(", re.I)
_MARSHAL = re.compile(r"Marshal\.(load|restore)\b")
_PDF_SEND = re.compile(r"receiver\.send\s*\(\s*name")
_PLUGIN_PATH = re.compile(r"pluginPath|plugin_path|pluginsDir|plugin.?dir", re.I)
_STUB_TRUE = re.compile(r"if\s*\(\s*!\s*\(\s*true\s*\)\s*\)")
_KILL_NO_PRIV = re.compile(r"T_KILL\s*,\s*no_priv_needed")
_OPTIMIZE_NO_PRIV = re.compile(r"T_OPTIMIZE_TABLE\s*,\s*no_priv_needed")
_ANALYZE_NO_PRIV = re.compile(r"T_ANALYZE\s*,\s*no_priv_needed")
_SKIP_SYS_DDL = re.compile(r"skip_sys_table_check_\s*=\s*true")


_PRIORITY_GLOBS = (
    "**/mqbauthn_*.cpp",
    "**/mqbauthz_*.cpp",
    "**/mqbplug_pluginmanager.cpp",
    "**/mqba_adminsession.cpp",
    "**/*brkrcfg.json",
    "**/obmp_connect.cpp",
    "**/ob_privilege_check.cpp",
    "**/ob_load_data_*.cpp",
    "**/ob_kill_session_arg.cpp",
    "**/ob_kill_executor.cpp",
    "**/ob_stmt_type.h",
    "**/ob_local_management_service.cpp",
    "**/page_state.rb",
    "**/page.rb",
    "**/form_xobject.rb",
    "**/docker-compose.y*ml",
    "**/compose.y*ml",
)


def _iter_files(dest: Path, limit: int = 6000) -> Iterable[Path]:
    dest = Path(dest)
    seen = set()
    n = 0
    for pat in _PRIORITY_GLOBS:
        for p in dest.glob(pat):
            if not p.is_file():
                continue
            key = str(p)
            if key in seen:
                continue
            seen.add(key)
            n += 1
            yield p
            if n >= limit:
                return
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in files:
            p = Path(root) / fname
            key = str(p)
            if key in seen:
                continue
            if p.suffix.lower() not in _EXT and fname not in (
                "bmqbrkrcfg.json", "CMakeLists.txt", "docker-compose.yaml", "docker-compose.yml",
            ):
                continue
            seen.add(key)
            n += 1
            if n > limit:
                return
            yield p


def _rel(dest: Path, p: Path) -> str:
    try:
        return str(p.relative_to(dest))
    except Exception:
        return str(p)


def _hit(tool: str, title: str, cvss: float, desc: str, file: str, line: int,
         **extra) -> Dict[str, Any]:
    rec = {
        "tool": tool,
        "title": title,
        "cvss": cvss,
        "description": desc,
        "file": file,
        "line": line,
        "confidence": extra.pop("confidence", "high"),
        "qualification": extra.pop("qualification", "QUALIFIED"),
        "phase2_hint": extra.pop("phase2_hint", ""),
    }
    rec.update(extra)
    return rec


def run_fail_open_auth(dest: Path, language: str = "") -> List[Dict[str, Any]]:
    """C++/native fail-open authentication and allow-all authorization."""
    results: List[Dict[str, Any]] = []
    dest = Path(dest)
    for p in _iter_files(dest):
        if p.suffix.lower() not in {".c", ".cc", ".cpp", ".h", ".hpp", ".hxx"}:
            continue
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        rel = _rel(dest, p)
        if _AUTHORIZE_ALLOW_ALL.search(text):
            line = text[:_AUTHORIZE_ALLOW_ALL.search(text).start()].count("\n") + 1
            results.append(_hit(
                "fail-open-auth",
                "Allow-all Authorizer::authorize() always returns true",
                8.6,
                "Authorization primitive returns true for every action, ignoring "
                "AuthenticationResult. Combined with a networked control plane this is "
                "an authz bypass (CWE-285). Lab: issue a privileged admin/control "
                "command with no credentials and require a success oracle.",
                rel, line,
                primitive_type="auth_bypass",
                canonical_class="authz_bypass",
                phase2_hint="protocol_admin_unauth",
            ))
        if "shouldPass" in text and "true" in text and "Anon" in text:
            m = re.search(r"d_shouldPass\s*=\s*true", text)
            line = (text[:m.start()].count("\n") + 1) if m else 1
            results.append(_hit(
                "fail-open-auth",
                "AnonAuthenticator defaults shouldPass=true (fail-open)",
                8.4,
                "Anonymous authentication succeeds with no identity unless an operator "
                "explicitly sets shouldPass=false. Lab: negotiate with no "
                "authenticationRequest and require brokerResponse.code==0.",
                rel, line,
                primitive_type="auth_bypass",
                canonical_class="authz_bypass",
                phase2_hint="protocol_negotiate_unauth",
            ))
        if "implicitly" in text.lower() and "anonymous" in text.lower() and "authentication" in text.lower():
            idx = text.lower().find("implicitly")
            line = text[:idx].count("\n") + 1
            results.append(_hit(
                "fail-open-auth",
                "Unauthenticated clients are implicitly authenticated",
                8.8,
                "When anonymousCredential is unset, clients that never send an auth "
                "request are still assigned the ANONYMOUS principal. Enabling "
                "BasicAuthenticator without also setting anonymousCredential.disallow "
                "does NOT close this path (documented by test_basic_auth_allows_anonymous). "
                "Lab: configure BasicAuthenticator only, connect with empty identity, "
                "run an admin command; oracle = adminCommandResponse text.",
                rel, line,
                primitive_type="auth_bypass",
                canonical_class="authz_bypass",
                phase2_hint="protocol_admin_unauth",
            ))
    return results


def run_plugin_dlopen(dest: Path, language: str = "") -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    dest = Path(dest)
    for p in _iter_files(dest):
        if p.suffix.lower() not in {".c", ".cc", ".cpp", ".h", ".hpp"}:
            continue
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        m = _DLOPEN.search(text)
        if not m:
            continue
        rel = _rel(dest, p)
        arg = m.group(1).strip()[:80]
        line = text[:m.start()].count("\n") + 1
        results.append(_hit(
            "plugin-dlopen",
            f"dlopen() of plugin path ({arg})",
            8.2,
            "Native plugin loader maps attacker-influenced or config-file paths into "
            "the broker process. If the path is writable by a less-privileged role "
            "(or an unauthenticated admin command can set it), this is RCE via a "
            "malicious .so. Lab: confirm whether plugin path is config-only or "
            "runtime-controllable; do not score RCE until a loaded library runs.",
            rel, line,
            primitive_type="code_execution",
            canonical_class="code_injection",
            phase2_hint="plugin_path_origin",
        ))
    return results


def run_protocol_surface(dest: Path, language: str = "") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Map listen/bind/ports/admin schemas for Phase-2 protocol PoCs."""
    results: List[Dict[str, Any]] = []
    dest = Path(dest)
    ports: List[int] = []
    admin_schemas: List[str] = []
    listen_files: List[str] = []
    for p in _iter_files(dest):
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        rel = _rel(dest, p)
        if p.suffix.lower() in {".json", ".yml", ".yaml", ".conf", ".cnf"}:
            for m in _PORT_JSON.finditer(text):
                try:
                    ports.append(int(m.group(1)))
                except ValueError:
                    pass
        if _LISTEN.search(text) and p.suffix.lower() in {".c", ".cc", ".cpp", ".h", ".hpp"}:
            listen_files.append(rel)
        if "ADMIN_COMMAND" in text or "adminCommand" in text or "E_TCPADMIN" in text:
            admin_schemas.append(rel)
            line = 1
            for i, ln in enumerate(text.splitlines(), 1):
                if "E_TCPADMIN" in ln or "adminCommand" in ln:
                    line = i
                    break
            results.append(_hit(
                "protocol-surface",
                "Admin control-plane schema (E_TCPADMIN / adminCommand)",
                8.7,
                "Broker exposes an admin session type distinct from data-plane clients. "
                "If negotiation as E_TCPADMIN succeeds without credentials, any host "
                "that can reach the TCP port can run admin commands. Phase-2 PoC: "
                "JSON control event clientIdentity.clientType=E_TCPADMIN then "
                "adminCommand.command=help; oracle = 'CMD subcommands' in the body.",
                rel, line,
                primitive_type="auth_bypass",
                canonical_class="authz_bypass",
                phase2_hint="protocol_admin_unauth",
            ))
    trace = {
        "ports": sorted(set(ports))[:20],
        "listen_files": listen_files[:30],
        "admin_schemas": admin_schemas[:20],
        "suggested_poc": "protocol_admin_unauth" if admin_schemas else "",
    }
    if ports and not results:
        results.append(_hit(
            "protocol-surface",
            f"Network listen ports from config: {sorted(set(ports))[:8]}",
            6.5,
            "Native service publishes TCP ports. Phase 2 must speak the native "
            "protocol (not HTTP) — HTTP /admin probes will miss the control plane.",
            admin_schemas[0] if admin_schemas else (listen_files[0] if listen_files else "config"),
            1,
            qualification="LATENT",
            phase2_hint="native_tcp_handshake",
        ))
    return results, trace


def run_document_library_surface(dest: Path, language: str = "") -> List[Dict[str, Any]]:
    """Ruby/PDF (and similar) untrusted-document sinks: Marshal, send, file open."""
    results: List[Dict[str, Any]] = []
    dest = Path(dest)
    for p in _iter_files(dest):
        if p.suffix.lower() != ".rb":
            continue
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        rel = _rel(dest, p)
        # Skip tools/spec — already skipped via SKIP_DIRS mostly
        if "/spec/" in rel.replace("\\", "/") or rel.startswith("tools/"):
            continue
        m = _MARSHAL.search(text)
        if m:
            line = text[:m.start()].count("\n") + 1
            results.append(_hit(
                "document-library-surface",
                "Marshal.load in document/parser state cloning",
                8.1,
                "Marshal.load deserializes Ruby objects. If attacker-controlled PDF "
                "state can be cloned through this path, gadget-chain RCE is possible. "
                "If the stack only ever contains Hashes/numerics built by the parser, "
                "lab must DISPROVE (PoC fails). Never report without lab oracle.",
                rel, line,
                primitive_type="deserialization",
                canonical_class="deserialization",
                phase2_hint="pdf_marshal_clone_state",
            ))
        if _PDF_SEND.search(text) and "OPERATORS" in text:
            # Gated send — still a lab target: prove operator names cannot escape the map
            m2 = _PDF_SEND.search(text)
            line = text[:m2.start()].count("\n") + 1
            results.append(_hit(
                "document-library-surface",
                "Content-stream receiver.send of operator-mapped methods",
                7.4,
                "Page/XObject walk dispatches PDF operators via Object#send. Operators "
                "are mapped through PagesStrategy::OPERATORS (not raw tokens). Lab must "
                "attempt an unmapped operator name (e.g. `system`) and confirm it is "
                "NOT invoked. A successful Kernel#system call would be RCE.",
                rel, line,
                primitive_type="code_execution",
                canonical_class="code_injection",
                phase2_hint="pdf_operator_send_escape",
            ))
    return results


def run_db_file_sinks(dest: Path, language: str = "") -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    dest = Path(dest)
    for p in _iter_files(dest):
        if p.suffix.lower() not in {".c", ".cc", ".cpp", ".h", ".hpp"}:
            continue
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        m = _LOAD_DATA.search(text)
        if not m:
            continue
        rel = _rel(dest, p)
        line = text[:m.start()].count("\n") + 1
        results.append(_hit(
            "db-file-sink",
            "LOAD DATA INFILE / INTO OUTFILE file sink",
            7.8,
            "SQL file-read/write primitive. High-severity if a low-privilege session "
            "can specify an absolute path (LOCAL INFILE / secure_file_priv bypass). "
            "Lab: connect as a restricted user and attempt LOAD DATA INFILE '/etc/passwd' "
            "or INTO OUTFILE under a world-writable dir; oracle = file bytes or created file.",
            rel, line,
            primitive_type="file_access",
            canonical_class="path_traversal_read",
            phase2_hint="sql_load_data_infile",
        ))
    return results


def run_stubbed_priv_checks(dest: Path, language: str = "") -> List[Dict[str, Any]]:
    """Privilege/auth functions compiled into always-allow (intent vs actual)."""
    results: List[Dict[str, Any]] = []
    dest = Path(dest)
    for p in _iter_files(dest):
        if p.suffix.lower() not in {".c", ".cc", ".cpp", ".h", ".hpp", ".hxx"}:
            continue
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        rel = _rel(dest, p)
        for m in _STUB_TRUE.finditer(text):
            line = text[:m.start()].count("\n") + 1
            ctx = text[max(0, m.start() - 240):m.start() + 120]
            title = "Privilege check stubbed to always-allow (if (!(true)))"
            cvss = 7.5
            hint = "sql_kill_any_session"
            if "kill" in ctx.lower() or "check_auth_for_kill" in text:
                title = "KILL session auth stub always returns success"
                cvss = 7.5
                hint = "sql_kill_any_session"
            results.append(_hit(
                "stubbed-priv-check",
                title,
                cvss,
                "A privilege/auth helper contains `if (!(true))` — the deny branch is "
                "dead code, so the function always succeeds. Adjacent comments/fields "
                "(SUPER, same-user KILL) describe a check that is not enforced. "
                "Lab: limited user SHOW PROCESSLIST + KILL <other session>; oracle = "
                "victim connection drops (2013 / Lost connection).",
                rel, line,
                primitive_type="auth_bypass",
                canonical_class="authz_bypass",
                phase2_hint=hint,
            ))
        if p.name == "ob_stmt_type.h" and _KILL_NO_PRIV.search(text):
            line = text[:_KILL_NO_PRIV.search(text).start()].count("\n") + 1
            results.append(_hit(
                "stubbed-priv-check",
                "T_KILL mapped to no_priv_needed in stmt privilege table",
                7.1,
                "KILL is registered with no_priv_needed, so the statement-level "
                "privilege mapper adds zero required privileges. Combined with a "
                "stubbed check_auth_for_kill this is cross-user session kill.",
                rel, line,
                primitive_type="auth_bypass",
                canonical_class="authz_bypass",
                phase2_hint="sql_kill_any_session",
            ))
        if p.name == "ob_stmt_type.h" and _OPTIMIZE_NO_PRIV.search(text):
            line = text[:_OPTIMIZE_NO_PRIV.search(text).start()].count("\n") + 1
            results.append(_hit(
                "stubbed-priv-check",
                "T_OPTIMIZE_TABLE mapped to no_priv_needed in stmt privilege table",
                8.1,
                "OPTIMIZE TABLE is registered with no_priv_needed. The executor still "
                "issues AlterTable (PROGRESSIVE_MERGE_ROUND) including system catalogs "
                "because skip_sys_table_check_ is set. Lab: USAGE-only user "
                "OPTIMIZE TABLE oceanbase.__all_user; oracle = progressive_merge_round increments.",
                rel, line,
                primitive_type="auth_bypass",
                canonical_class="authz_bypass",
                phase2_hint="sql_optimize_any_table",
            ))
        if p.name == "ob_stmt_type.h" and _ANALYZE_NO_PRIV.search(text):
            line = text[:_ANALYZE_NO_PRIV.search(text).start()].count("\n") + 1
            results.append(_hit(
                "sql-no-priv-needed",
                "T_ANALYZE mapped to no_priv_needed in stmt privilege table",
                6.5,
                "ANALYZE TABLE is registered with no_priv_needed. Lab on seekdb: "
                "USAGE-only ANALYZE TABLE lotus_secret.creds writes min_value/max_value "
                "(including secrets) into oceanbase.__all_column_stat, but the attacker "
                "cannot SELECT those catalogs (1142) and information_schema.COLUMN_STATISTICS "
                "does not exist. Treat as a stats-integrity lead; promote to CVSS≥7 only "
                "if a stats-read oracle returns the secret to the attacker.",
                rel, line,
                primitive_type="auth_bypass",
                canonical_class="authz_bypass",
                phase2_hint="sql_analyze_any_table",
                confidence="medium",
            ))
        if _SKIP_SYS_DDL.search(text) and "optimize_table" in text:
            m = _SKIP_SYS_DDL.search(text)
            line = text[:m.start()].count("\n") + 1
            results.append(_hit(
                "stubbed-priv-check",
                "OPTIMIZE TABLE skips system-table DDL guard",
                8.1,
                "optimize_table sets skip_sys_table_check_=true before AlterTable, bypassing "
                "check_enable_sys_table_ddl. Combined with T_OPTIMIZE_TABLE/no_priv_needed, "
                "any login can ALTER catalog tables they cannot even SHOW.",
                rel, line,
                primitive_type="auth_bypass",
                canonical_class="authz_bypass",
                phase2_hint="sql_optimize_any_table",
            ))
    return results


def run_insecure_defaults(dest: Path, language: str = "") -> List[Dict[str, Any]]:
    """Shipped config/README that leave admin/root open on a published port."""
    results: List[Dict[str, Any]] = []
    dest = Path(dest)
    for p in dest.rglob("*brkrcfg.json"):
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        if '"port"' not in text:
            continue
        if '"authentication"' not in text.lower() and "anonymousCredential" not in text:
            rel = _rel(dest, p)
            results.append(_hit(
                "insecure-default",
                "Broker config publishes TCP with no authentication block",
                9.1,
                "Default bmqbrkrcfg.json sets tcpInterface.port but omits authentication. "
                "AnonAuthenticator + DefaultAuthorizer then fail open. Lab: official "
                "ghcr.io/bloomberg/blazingmq with docker/single-node/config, E_TCPADMIN "
                "+ help (oracle 'CMD subcommands') then BROKERCONFIG DUMP / DOMAINS PURGE.",
                rel, 1,
                primitive_type="auth_bypass",
                canonical_class="authz_bypass",
                phase2_hint="protocol_admin_unauth",
            ))
    readme = dest / "README.md"
    if readme.is_file():
        try:
            rtxt = readme.read_text(errors="ignore")[:24000]
        except Exception:
            rtxt = ""
        if "oceanbase/seekdb" in rtxt and "-p 2881:2881" in rtxt:
            results.append(_hit(
                "insecure-default",
                "README docker quick-start publishes 2881 with default empty root password",
                9.8,
                "Project README `docker run -p 2881:2881 oceanbase/seekdb` does not set "
                "ROOT_PASSWORD. Upstream image docs: if ROOT_PASSWORD is unset, root and "
                "the :2886 dashboard accept a blank password. Lab: mysql -h127.0.0.1 -P2881 "
                "-uroot with empty pass; oracle = SELECT USER() plus a write (CREATE DATABASE).",
                "README.md", 205,
                primitive_type="auth_bypass",
                canonical_class="authz_bypass",
                phase2_hint="sql_empty_root",
            ))
    return results


def collect_high_severity(dest: Path, language: str = "") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    dest = Path(dest)
    findings: List[Dict[str, Any]] = []
    findings.extend(run_fail_open_auth(dest, language))
    findings.extend(run_plugin_dlopen(dest, language))
    proto, trace = run_protocol_surface(dest, language)
    findings.extend(proto)
    findings.extend(run_document_library_surface(dest, language))
    findings.extend(run_db_file_sinks(dest, language))
    findings.extend(run_insecure_defaults(dest, language))
    findings.extend(run_stubbed_priv_checks(dest, language))
    # Dedup by (tool, file, title)
    seen = set()
    uniq = []
    for f in findings:
        k = (f.get("tool"), f.get("file"), f.get("title"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    trace["n_findings"] = len(uniq)
    trace["tools"] = sorted({f["tool"] for f in uniq})
    try:
        out_dir = dest / ".lotus"
        out_dir.mkdir(exist_ok=True)
        (out_dir / "phase1_trace.json").write_text(
            json.dumps({"language": language, "trace": trace,
                        "high_severity_leads": [
                            {"title": f["title"], "file": f["file"], "line": f["line"],
                             "cvss": f["cvss"], "hint": f.get("phase2_hint")}
                            for f in uniq[:40]
                        ]}, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass
    return uniq, trace


def _run_high_severity_surface(dest: Path, language: str) -> List[dict]:
    """Pipeline/tool-registry entry point."""
    findings, _trace = collect_high_severity(dest, language)
    return findings
