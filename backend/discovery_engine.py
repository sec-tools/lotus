"""
High-yield bug discovery engine for Lotus.

Distilled from audit-markdown-light doctrine:
  - Sink-first backward reachability (Skill 76)
  - Guard-alternate-path completeness (Skill 49)  - #1 real finding shape
  - Upstream silent-fix / sibling-variant mining (Skill 82 / B6)
  - Weak PRNG / predictable secret detection (Skill 88)
  - Cross-audit pattern transfer (Skill 48)
  - Documentation-driven hunting (Skill 36)
  - Complexity × taint hotspots (Skill 37)
  - Coverage ledger five-gate exhaustion (SYSTEM D33)
  - Discovery effectiveness metrics (QUALIFIED confirm-rate, lead depth, etc.)

This module is intentionally deterministic and lab-independent so Phase 1 always
produces high-signal leads even when Docker/AI are unavailable.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".bundle", "__pycache__", ".venv", "venv",
    "target", "build", "dist", "test", "tests", "spec", "specs", "testdata",
    "fixtures", "examples", "example", "mock", "mocks", "__tests__", "__mocks__",
    "testing", "docs", "doc", "benchmark", "benchmarks", ".tox", ".mypy_cache",
    # Lotus writes traces and plans into this directory; it is audit metadata,
    # never target source.  Scanning it creates self-referential false positives.
    ".lotus",
}

SKIP_FILE_PATTERNS = ("test_", "_test.", "_spec.", ".test.", ".spec.", "mock_", "fake_", "stub_")

# Crown-jewel sinks used for sink-first BFS (language -> list of regex / keywords)
SINK_KEYWORDS = {
    "python": [
        "os.system", "subprocess", "eval(", "exec(", "pickle.loads", "pickle.load",
        "cloudpickle.loads", "dill.loads", "joblib.load", "torch.load", "yaml.load",
        "render_template_string", "open(", ".execute(", "requests.get", "requests.post",
        "urllib.request", "httpx.get", "httpx.post", "socket.connect", "fsspec.open",
        "exec_command", "shell.exec", "code.execute", "bash.exec", "run_exec",
    ],

    "node": [
        "child_process", "exec(", "eval(", "Function(", "fs.readFile", "fs.writeFile",
        "require(", "innerHTML", "deserialize", "JSON.parse", "axios.get", "fetch(",
        "execCommand", "execSync", "spawn(", "shell.exec", "v1/shell/exec", "v1/bash/exec",
        "v1/code/execute", "v1/file/read", "v1/file/write",
    ],
    "ruby/rails": [
        "system(", "exec(", "eval(", "`", "File.read", "File.open", "YAML.load",
        "Marshal.load", "Marshal.restore", "Psych.unsafe_load", "Psych.load", "JSON.load",
        "constantize", "const_get", "render inline", "send(", "public_send",
        "connection.execute", "open(", "shell_out(", "shell_out!(", "powershell_out(",
        "powershell_out!(", "powershell_exec(", "powershell_exec!(", "Mixlib::ShellOut.new",
        "Open3.popen3", "Open3.capture3", "IO.popen", "Process.spawn", "PTY.spawn",
        "URI.open(", "FileUtils.chmod",
    ],
    "go": [
        "exec.Command", "os.Open", "db.Query", "db.Exec", "http.Get", "ioutil.ReadFile",
        "template.HTML", "json.Unmarshal", "plugin.Open", "jwt.ParseUnverified",
        "yaml.Unmarshal",
    ],
    "java": [
        "Runtime.getRuntime().exec", "ProcessBuilder", "ObjectInputStream",
        "Statement.execute", "Class.forName", "Files.read", "DocumentBuilder",
        "GroovyShell", "SpelExpressionParser", "Hessian2Input", "ScriptEngine",
    ],
    "php": [
        "eval(", "exec(", "system(", "shell_exec", "passthru", "unserialize",
        "include(", "require(", "mysql_query", "mysqli_query",
    ],
    "c/cpp": [
        "system(", "popen(", "exec(", "strcpy(", "strcat(", "sprintf(",
        "gets(", "memcpy(", "memmove(", "malloc(", "realloc(", "calloc(",
        "free(", "fopen(", "fread(", "recv(", "read(", "inja::render",
        "fmt::format", "Script() <<", "tar -C", "chown ",
        # YAML/parser specific
        "yaml_parser_parse", "yaml_document_get_node", "yaml_parser_scan",
        # PHP extension specific
        "emalloc(", "efree(", "ZVAL_STRING(", "convert_to_string(",
        "php_stream_open", "zend_parse_parameters(",
    ],

}

SOURCE_KEYWORDS = {
    "python": [
        "request.args", "request.form", "request.json", "request.values", "request.data",
        "request.headers", "request.files", "request.query_params", "sys.argv", "os.environ",
        "input(", "argparse", "spec", "body", "task", "runtime", "function", "artifact",
        "key_path", "stop_condition", "params",
    ],

    "node": ["req.query", "req.body", "req.params", "process.argv", "process.env"],
    "ruby/rails": ["params[", "request.", "ENV[", "cookies[", "ARGV", "node[", "attributes", "new_resource.", "options[", "config[", "payload", "Chef::Config"],

    "go": ["r.URL.Query", "r.Form", "os.Args", "os.Getenv", "flag."],
    "java": ["request.getParameter", "System.getenv", "args["],
    "php": ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER"],
    "c/cpp": [
        "argv", "getenv(", "fgets(", "read(", "recv(", "scanf(",
        "fread(", "stdin", "getc(", "fgetc(", "YAML::LoadFile",
        "step[", "item[", "cmdsStr", "stepName", "parseRunAs",
        # YAML parser input
        "yaml_parser_set_input", "yaml_parser_set_input_string",
        # PHP extension input
        "zend_parse_parameters(", "ZEND_PARSE_PARAMETERS(",
    ],

}

# High-severity sinks where untrusted flow implies RCE/injection/deser (used to
# gate sink-first-proximity QUALIFICATION so weak proximity stays LATENT).
_HI_SEV_SINK_TOKENS = (
    "os.system(", "os.popen(", "commands.getoutput", "shell=true", "eval(", "exec(",
    "pickle.load", "pickle.loads", "yaml.load(", "marshal.load", "subprocess.getoutput",
    "__import__(", "compile(", "cursor.execute", ".executescript(", "os.exec",
    "popen(", "system(", "/bin/sh", "load_pem", "unserialize",
)

# Genuinely attacker-controlled sources (subset of SOURCE_KEYWORDS that is truly
# external, excluding generic tokens like "params"/"spec"/"function").
_UNTRUSTED_SOURCE_TOKENS = (
    "request.args", "request.form", "request.json", "request.values", "request.data",
    "request.headers", "request.files", "request.query_params", "sys.argv", "os.environ",
    "input(", "req.query", "req.body", "req.params", "process.argv", "process.env",
    "getenv(", "recv(", "stdin", "$_get", "$_post", "$_request", "$_cookie", "$_server",
    "r.url.query", "r.form", "os.args", "argv", "fgets(", "read(",
)

GUARD_PATTERNS = {
    "python": [
        (r"@login_required", "login_required"),
        (r"@require_auth", "require_auth"),
        (r"@permission_required", "permission_required"),
        (r"current_user\.is_authenticated", "is_authenticated"),
        (r"if\s+not\s+\w+\.is_admin", "is_admin_check"),
        (r"abort\s*\(\s*40[13]\s*\)", "http_403_abort"),
        (r"raise\s+PermissionDenied", "PermissionDenied"),
        (r"@jwt_required", "jwt_required"),
        # Custom / common authz helpers (Flask/FastAPI apps often use these)
        (r"\bauthorize\s*\(", "authorize"),
        (r"\bauthenticate\s*\(", "authenticate"),
        (r"\bcheck_permission\s*\(", "check_permission"),
        (r"\brequire_admin\s*\(", "require_admin"),
        (r"Depends\s*\(\s*\w*auth", "fastapi_Depends_auth"),
        (r"HTTPBearer\s*\(", "HTTPBearer"),
    ],
    "node": [
        (r"passport\.authenticate", "passport_auth"),
        (r"requireAuth\s*\(", "requireAuth"),
        (r"isAuthenticated\s*\(", "isAuthenticated"),
        (r"authorize\s*\(", "authorize"),
        (r"checkPermission\s*\(", "checkPermission"),
        (r"verifyToken\s*\(", "verifyToken"),
        (r"req\.user\s*&&", "req.user_guard"),
    ],
    "ruby/rails": [
        (r"before_action\s+:authenticate", "authenticate"),
        (r"before_filter\s+:authenticate", "authenticate_filter"),
        (r"authorize!\s*", "pundit_authorize"),
        (r"authenticate_user!", "devise_auth"),
        (r"skip_before_action\s+:authenticate", "skip_authenticate"),
        (r"can\?\s*\(", "cancancan"),
    ],
    "go": [
        (r"middleware\.Auth", "auth_middleware"),
        (r"RequireAuth", "RequireAuth"),
        (r"CheckAdmin", "CheckAdmin"),
        (r"http\.StatusUnauthorized", "401_response"),
        (r"http\.StatusForbidden", "403_response"),
    ],
    "java": [
        (r"@PreAuthorize", "PreAuthorize"),
        (r"@Secured", "Secured"),
        (r"@RolesAllowed", "RolesAllowed"),
        (r"SecurityContextHolder", "SecurityContext"),
        (r"isAuthenticated\s*\(", "isAuthenticated"),
    ],
    "php": [
        (r"middleware\s*\(\s*['\"]auth", "auth_middleware"),
        (r"Gate::authorize", "Gate_authorize"),
        (r"\$this->authorize\s*\(", "authorize"),
        (r"Auth::check\s*\(", "Auth_check"),
    ],
}

WEAK_PRNG_PATTERNS = [
    (r"\brandom\.random\s*\(", "Weak PRNG: random.random()", 7.5,
     "Security-sensitive value generated with random.random(); use secrets module."),
    (r"\brandom\.randint\s*\(", "Weak PRNG: random.randint()", 7.5,
     "Security-sensitive value generated with random.randint(); use secrets.randbelow."),
    (r"\brandom\.choice\s*\(", "Weak PRNG: random.choice()", 7.0,
     "Token/secret generation via random.choice is predictable."),
    (r"\bMath\.random\s*\(", "Weak PRNG: Math.random()", 7.5,
     "Math.random() is not cryptographically secure; use crypto.randomBytes."),
    (r"\bmt_rand\s*\(", "Weak PRNG: mt_rand()", 7.5,
     "mt_rand() is predictable; use random_bytes()/random_int()."),
    (r"\brand\s*\(\s*\)", "Weak PRNG: rand()", 7.0,
     "C rand() is predictable; use getrandom()/arc4random."),
    (r"\bsrand\s*\(\s*time\s*\(", "Predictable PRNG seed (time)", 7.5,
     "srand(time()) makes the entire sequence attacker-reproducible."),
    (r"\bSecureRandom\b", "SecureRandom usage (check strength)", 3.0,
     "SecureRandom present  - verify algorithm and seeding."),
    (r"uuid\.uuid[14]\s*\(", "Non-crypto UUID for security token", 6.5,
     "UUID v1/v4 used as capability token; ensure not sole auth secret."),
    (r"Date\.now\s*\(\s*\).*toString\s*\(\s*36\s*\)", "Time-based token generation", 7.0,
     "Token derived from Date.now(); trivially predictable."),
    (r"time\.time\s*\(\s*\).*str\s*\(", "Time-based secret material", 6.5,
     "Secret material derived from time.time(); forgeable."),
    (r"JWT.*(kid|jku|x5u)", "JWT header attack surface", 7.0,
     "JWT kid/jku/x5u handling present; verify no path/URL injection."),
    (r"['\"]alg['\"]\s*:\s*['\"]none['\"]", "JWT alg:none accepted", 9.0,
     "JWT algorithm 'none' explicitly referenced  - signature bypass risk."),
    (r"algorithms\s*=\s*\[.*['\"]HS256['\"].*['\"]RS256['\"]", "JWT alg confusion risk", 8.0,
     "Both HS256 and RS256 accepted  - classic algorithm confusion."),
    (r"startsWith\s*\([^)]*redirect", "OAuth redirect prefix match", 8.0,
     "redirect_uri validated via startsWith/prefix  - open redirect / code theft."),
    (r"redirect_uri.*startswith|startswith.*redirect", "OAuth redirect prefix match", 8.0,
     "redirect_uri prefix match enables open redirect."),
]

SECURITY_COMMIT_RE = re.compile(
    r"(?i)\b(fix|cve|vulnerab|secur|inject|sanitize|escape|bypass|authz?|xss|ssrf|"
    r"travers|deserial|rce|overflow|privilege|csrf|path.?traversal|command.?inject)\b"
)

PATTERN_DB_PATH = Path(os.environ.get(
    "LOTUS_PATTERN_DB",
    str(Path(__file__).resolve().parent.parent / "data" / "skills" / "pattern_db.json"),
))


def _iter_source_files(dest: Path, extensions: Optional[List[str]] = None, limit: int = 400) -> List[Path]:
    """Walk source files with priority for security-relevant paths.

    Large SDK/monorepos otherwise exhaust the scan budget on generated types/
    fixtures before reaching shell/auth/route handlers.
    """
    exts = extensions or [".py", ".js", ".ts", ".rb", ".go", ".java", ".php", ".c", ".cpp", ".h", ".rs"]
    priority_tokens = (
        "shell", "bash", "exec", "auth", "admin", "route", "api", "handler",
        "controller", "middleware", "security", "session", "upload", "file",
        "command", "sandbox", "deserialize", "pickle", "jwt", "oauth",
    )

    def _score(rel: Path) -> Tuple[int, str]:
        parts_l = [p.lower() for p in rel.parts]
        name = rel.name.lower()
        score = 0
        if any(t in name for t in priority_tokens):
            score -= 100
        if any(any(t in p for t in priority_tokens) for p in parts_l):
            score -= 50
        if "types" in parts_l or "fixtures" in parts_l or "generated" in parts_l:
            score += 80
        if name.endswith((".d.ts", "_pb2.py", ".pb.go")):
            score += 120
        return (score, str(rel))

    candidates: List[Path] = []
    for f in dest.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in exts:
            continue
        try:
            if f.stat().st_size > 1_000_000:
                continue
        except OSError:
            continue
        parts = {p.lower() for p in f.relative_to(dest).parts}
        if parts & SKIP_DIRS:
            continue
        name = f.name.lower()
        if any(p in name for p in SKIP_FILE_PATTERNS):
            continue
        candidates.append(f)

    candidates.sort(key=lambda p: _score(p.relative_to(dest)))
    return candidates[:limit]


def _rel(dest: Path, f: Path) -> str:
    try:
        return str(f.relative_to(dest))
    except ValueError:
        return str(f)


def _lang_key(language: str) -> str:
    if language.startswith("ruby"):
        return "ruby/rails"
    if language in ("javascript", "typescript", "js"):
        return "node"
    if language in ("c", "cpp", "c/cpp"):
        return "c/cpp"
    return language if language in SINK_KEYWORDS else "python"


# ---------------------------------------------------------------------------
# 1. Sink-first backward reachability
# ---------------------------------------------------------------------------

def sink_first_reachability(dest: Path, language: str) -> List[dict]:
    """BFS backward from crown-jewel sinks toward untrusted sources.

    Unlike forward grep, this starts at dangerous sinks and walks callers /
    nearby source indicators within a proximity window and call-graph hops.
    """
    from backend.callgraph import build_call_graph, sink_first_paths

    lang = _lang_key(language)
    findings: List[dict] = []

    # Test/spec code is not attack surface; a sink reached only from a test
    # driver is a false positive (was scoring test_cli.py as cvss=8 RCE).
    def _is_test_path(p: str) -> bool:
        if not p:
            return False
        # Classify on the repo-RELATIVE path only. The absolute prefix (e.g. a
        # home directory literally named ``/Users/test/…``) must never be treated
        # as a test segment — otherwise EVERY finding is dropped as "test code"
        # on such machines, silently zeroing out sink-first reachability.
        rp = Path(p)
        if rp.is_absolute():
            try:
                rp = rp.relative_to(dest)
            except ValueError:
                rp = Path(rp.name)
        norm = str(rp).lower().replace("\\", "/")
        parts = set(norm.split("/"))
        return bool(parts & {"test", "tests", "spec", "specs", "__tests__", "testdata"}) or \
            any(tok in Path(norm).name for tok in ("test_", "_test.", "_spec.", ".test.", ".spec."))

    # Call-graph based paths
    try:
        cg = build_call_graph(dest, language)
        for path in sink_first_paths(cg, language, max_hops=4):
            if _is_test_path(path.get("sink_file", "")) or _is_test_path(path.get("source_file", "")):
                continue
            findings.append({
                "tool": "sink-first",
                "title": f"Sink-first reachability: {path['sink'][:50]} ← {path['source'][:40]}",
                "cvss": 8.0 if path.get("hops", 1) <= 2 else 7.2,
                "description": (
                    f"Backward BFS from sink `{path['sink']}` reached untrusted source "
                    f"`{path['source']}` in {path.get('hops', 1)} hop(s). "
                    f"Chain: {' ← '.join(path.get('chain', [])[:6])}. "
                    f"Hypothesis format: Developer INTENDED sink to be unreachable from "
                    f"untrusted input; actual code does allow flow when chain is exercised."
                ),
                "file": path.get("sink_file", ""),
                "line": path.get("sink_line", 0),
                "confidence": "medium" if path.get("hops", 1) <= 2 else "low",
                "qualification": "QUALIFIED" if path.get("hops", 1) <= 3 else "LATENT",
                "lead_depth": len(path.get("chain", [])),
                "data_flow": path,
                "discovery_technique": "sink-first",
            })
    except Exception:
        pass

    # Proximity fallback: sink line near source indicators in same file
    sinks = SINK_KEYWORDS.get(lang, SINK_KEYWORDS["python"])
    sources = SOURCE_KEYWORDS.get(lang, SOURCE_KEYWORDS["python"])
    for f in _iter_source_files(dest, limit=250):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        lines = text.splitlines()
        sink_lines = []
        source_lines = []
        for i, line in enumerate(lines):
            if any(s in line for s in sinks):
                sink_lines.append(i)
            if any(s in line for s in sources):
                source_lines.append(i)
        if not sink_lines or not source_lines:
            continue
        for sl in sink_lines[:8]:
            nearby = [src for src in source_lines if abs(src - sl) <= 40]
            if not nearby:
                continue
            # Skip if already covered by call-graph finding for this file
            rel = _rel(dest, f)
            if any(x.get("file") == rel and x.get("line") == sl + 1 for x in findings):
                continue
            sink_line = lines[sl].lower() if sl < len(lines) else ""
            # QUALIFY only with a HIGH-SEVERITY sink AND a genuinely UNTRUSTED
            # source in a tight window with no intervening guard. Proximity alone
            # is a weak signal that flooded bup with 54 false "qualified" hits;
            # everything else is now LATENT. This is the key precision lever.
            hi_sev = any(k in sink_line for k in _HI_SEV_SINK_TOKENS)
            if "subprocess." in sink_line and "shell=true" not in sink_line:
                hi_sev = False  # subprocess w/o shell=True is not a shell-exec sink
            close_untrusted = [
                s for s in nearby
                if abs(s - sl) <= 15 and s < len(lines)
                and any(t in lines[s].lower() for t in _UNTRUSTED_SOURCE_TOKENS)
            ]
            lo, hi = min(nearby[0], sl), max(nearby[0], sl)
            guard_between = any(
                any(g in lines[k].lower() for g in ("validate", "sanitize", "escape",
                    "shlex.quote", "allowlist", "whitelist", "is_safe", "check_"))
                for k in range(lo, hi + 1) if k < len(lines)
            )
            if hi_sev and close_untrusted and not guard_between:
                qual, conf, cvss = "QUALIFIED", "medium", 7.0
                src_desc = [n + 1 for n in close_untrusted[:3]]
                why = ("High-severity sink + untrusted source within 15 lines, no "
                       "intervening guard → QUALIFIED until guard proven.")
            else:
                qual, conf, cvss = "LATENT", "low", 5.5
                src_desc = [n + 1 for n in nearby[:3]]
                why = ("Proximity only (no high-severity shell-exec sink / untrusted "
                       "source) → LATENT; needs data-flow confirmation before promotion.")
            findings.append({
                "tool": "sink-first",
                "title": f"Sink-source proximity in {f.name}",
                "cvss": cvss,
                "description": (
                    f"Sink at line {sl + 1} near source line(s) {src_desc}. {why}"
                ),
                "file": rel,
                "line": sl + 1,
                "confidence": conf,
                "qualification": qual,
                "lead_depth": 2 if qual == "QUALIFIED" else 1,
                "discovery_technique": "sink-first-proximity",
            })
            if len(findings) >= 80:
                return findings
    return findings[:80]


# ---------------------------------------------------------------------------
# 2. Guard-alternate-path scanner (#1 real finding shape)
# ---------------------------------------------------------------------------

def guard_alternate_path(dest: Path, language: str) -> List[dict]:
    """For every guard, find sinks/routes that may skip it.

    Core shape of almost every real authz/logic finding:
    'The alternate path skips the guard.'
    """
    lang = _lang_key(language)
    guards = GUARD_PATTERNS.get(lang, GUARD_PATTERNS["python"])
    findings: List[dict] = []

    # Collect all guarded and unguarded route-like definitions
    route_patterns = {
        "python": re.compile(r"@(?:app|bp|router|api)\.(?:route|get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]"),
        "node": re.compile(r"(?:app|router)\.(?:get|post|put|delete|patch|use)\s*\(\s*['\"]([^'\"]+)['\"]"),
        "ruby/rails": re.compile(r"(?:get|post|put|delete|patch|match)\s+['\"]([^'\"]+)['\"]"),
        "go": re.compile(r"(?:HandleFunc|Handle|GET|POST|PUT|DELETE)\s*\(\s*['\"]([^'\"]+)['\"]"),
        "java": re.compile(r"@(?:Get|Post|Put|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"]"),
        "php": re.compile(r"Route::(?:get|post|put|delete|patch|any)\s*\(\s*['\"]([^'\"]+)['\"]"),
    }
    rp = route_patterns.get(lang, route_patterns["python"])

    files = _iter_source_files(dest, limit=300)
    for f in files:
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        lines = text.splitlines()
        guard_hits: List[Tuple[int, str]] = []
        for i, line in enumerate(lines):
            for pat, name in guards:
                if re.search(pat, line):
                    guard_hits.append((i, name))

        # skip_before_action / auth exceptions are explicit alternate paths
        for i, line in enumerate(lines):
            if re.search(r"skip_before_action|skip_before_filter|except\s*:\s*\[|@public|allowAnonymous|PermitAll", line, re.I):
                findings.append({
                    "tool": "guard-alternate-path",
                    "title": f"Explicit auth skip / alternate path in {f.name}",
                    "cvss": 8.2,
                    "description": (
                        f"Line {i + 1} explicitly skips or exempts an authentication/authorization "
                        f"guard (`{line.strip()[:120]}`). Guard-alternate-path doctrine: enumerate "
                        f"every sink reachable via this unguarded path and classify GUARDED vs UNGUARDED."
                    ),
                    "file": _rel(dest, f),
                    "line": i + 1,
                    "confidence": "high",
                    "qualification": "QUALIFIED",
                    "lead_depth": 2,
                    "discovery_technique": "guard-alternate-path",
                })

        # Routes without nearby guards in same file when other routes HAVE guards
        if not guard_hits:
            continue
        route_hits = [(i, m.group(1)) for i, line in enumerate(lines) for m in [rp.search(line)] if m]
        if not route_hits:
            # File has guards but also sinks  - check sinks far from any guard
            sinks = SINK_KEYWORDS.get(lang, [])
            for i, line in enumerate(lines):
                if not any(s in line for s in sinks):
                    continue
                nearest = min((abs(i - g[0]) for g in guard_hits), default=999)
                if nearest > 25:
                    findings.append({
                        "tool": "guard-alternate-path",
                        "title": f"Unguarded sink near guarded module: {f.name}:{i + 1}",
                        "cvss": 7.8,
                        "description": (
                            f"Sink at line {i + 1} is {nearest} lines from nearest guard "
                            f"({guard_hits[0][1]}). Sibling/alternate functions in this module "
                            f"may omit the guard that protects other sinks."
                        ),
                        "file": _rel(dest, f),
                        "line": i + 1,
                        "confidence": "medium",
                        "qualification": "QUALIFIED",
                        "lead_depth": 2,
                        "discovery_technique": "guard-alternate-path",
                    })
            continue

        for ri, route in route_hits:
            nearest_guard = min((abs(ri - g[0]) for g in guard_hits), default=999)
            # Decorator-style: guard should be within ~5 lines above route
            if nearest_guard > 8:
                findings.append({
                    "tool": "guard-alternate-path",
                    "title": f"Route may skip guard: {route}",
                    "cvss": 7.5,
                    "description": (
                        f"Route `{route}` at line {ri + 1} has no nearby auth/authz guard "
                        f"(nearest guard {nearest_guard} lines away). File contains guards "
                        f"elsewhere  - classic alternate-path shape."
                    ),
                    "file": _rel(dest, f),
                    "line": ri + 1,
                    "confidence": "medium",
                    "qualification": "QUALIFIED",
                    "lead_depth": 2,
                    "discovery_technique": "guard-alternate-path",
                })
        if len(findings) >= 60:
            break
    return findings[:60]


# ---------------------------------------------------------------------------
# 3. Silent-fix / sibling-variant mining
# ---------------------------------------------------------------------------

def silent_fix_and_variants(dest: Path, language: str) -> List[dict]:
    """Mine git history for security fixes and hunt sibling functions missing the guard (B6)."""
    findings: List[dict] = []
    git_dir = dest / ".git"
    if not git_dir.exists():
        # Still do sibling AST-ish divergence without git
        findings.extend(_sibling_guard_divergence(dest, language))
        return findings

    try:
        proc = subprocess.run(
            ["git", "-C", str(dest), "log", "--oneline", "-n", "80", "--all"],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            findings.extend(_sibling_guard_divergence(dest, language))
            return findings
        sec_commits = []
        for line in proc.stdout.splitlines():
            if SECURITY_COMMIT_RE.search(line):
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    sec_commits.append((parts[0], parts[1]))
        for sha, msg in sec_commits[:15]:
            findings.append({
                "tool": "silent-fix-mining",
                "title": f"Security-relevant commit: {msg[:80]}",
                "cvss": 6.5,
                "description": (
                    f"Commit `{sha}` message suggests a security fix: «{msg[:160]}». "
                    f"Silent-fix doctrine (Skill 82): extract the guard/check added and "
                    f"search sibling functions/paths for the same bug class without the fix (B6). "
                    f"Also compare pinned version vs upstream HEAD for post-tag security fixes."
                ),
                "file": "",
                "line": 0,
                "confidence": "low",
                "qualification": "LATENT",
                "lead_depth": 1,
                "discovery_technique": "silent-fix-mining",
                "commit": sha,
            })
            # Try to extract touched files from that commit
            show = subprocess.run(
                ["git", "-C", str(dest), "show", "--name-only", "--pretty=format:", sha],
                capture_output=True, text=True, timeout=15,
            )
            if show.returncode == 0:
                for touched in show.stdout.splitlines()[:5]:
                    touched = touched.strip()
                    if not touched or not (dest / touched).exists():
                        continue
                    findings.append({
                        "tool": "silent-fix-mining",
                        "title": f"Variant analysis target after fix in {Path(touched).name}",
                        "cvss": 7.0,
                        "description": (
                            f"File `{touched}` touched by security commit `{sha}`. "
                            f"Hunt B1–B6 variants: encoding, alternate path, trigger, TOCTOU, "
                            f"fix-introduced bugs, and sibling functions without the new guard."
                        ),
                        "file": touched,
                        "line": 1,
                        "confidence": "medium",
                        "qualification": "QUALIFIED",
                        "lead_depth": 2,
                        "discovery_technique": "variant-analysis",
                        "commit": sha,
                    })
    except Exception:
        pass

    findings.extend(_sibling_guard_divergence(dest, language))
    return findings[:50]


def _sibling_guard_divergence(dest: Path, language: str) -> List[dict]:
    """Find functions that look like siblings where one has a security check and peers don't."""
    lang = _lang_key(language)
    findings: List[dict] = []
    func_re = {
        "python": re.compile(r"^def\s+([a-zA-Z_]\w*)\s*\("),
        "node": re.compile(r"(?:function\s+([a-zA-Z_]\w*)|([a-zA-Z_]\w*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)"),
        "ruby/rails": re.compile(r"^\s*def\s+([a-zA-Z_]\w*[=!?]?)"),
        "go": re.compile(r"^func\s+(?:\([^)]+\)\s+)?([A-Z]\w*)\s*\("),
        "java": re.compile(r"(?:public|private|protected).+\s+([a-zA-Z_]\w*)\s*\("),
        "php": re.compile(r"function\s+([a-zA-Z_]\w*)\s*\("),
    }.get(lang, re.compile(r"def\s+([a-zA-Z_]\w*)\s*\("))

    # B6 targets object-level AUTHZ asymmetry, so the "check" must be a genuine
    # access-control guard. Generic data-integrity verbs (validate/verify/sanitize)
    # caused false positives on non-web code (e.g. bup fsck/par2 "verify" parity),
    # so they are excluded — the technique now fires only on real authz divergence.
    check_tokens = ("authorize", "authenticate", "permission", "is_admin", "can?",
                    "current_user", "require_auth", "login_required", "jwt_required",
                    "csrf", "access_denied", "forbidden", "permissiondenied",
                    "abort(403", "abort(401", "@requires", "has_role", "check_acl")

    for f in _iter_source_files(dest, limit=200):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        lines = text.splitlines()
        funcs: List[Tuple[str, int, int, bool]] = []  # name, start, end, has_check
        current = None
        for i, line in enumerate(lines):
            m = func_re.search(line)
            if m:
                if current:
                    funcs.append(current)
                name = next(g for g in m.groups() if g)
                current = [name, i, i, False]
            elif current:
                current[2] = i
                # Ignore comments so "missing authorize" docs don't false-positive
                code = line.split("#")[0].split("//")[0]
                if any(tok in code.lower() for tok in check_tokens):
                    current[3] = True
        if current:
            funcs.append(tuple(current) if not isinstance(current, list) else tuple(current))

        # Group by name stem/suffix (sibling families: create_user / update_user / delete_user)
        families: Dict[str, List] = defaultdict(list)
        for name, start, end, has_check in funcs:
            if not name or len(name) < 4:
                continue
            # Prefer suffix after first underscore (user family), else camelCase tail
            keys: List[str] = []
            if "_" in name:
                parts = name.split("_")
                if len(parts) >= 2 and len(parts[-1]) >= 3:
                    keys.append(parts[-1])  # create_user → user
                stem = "_".join(parts[1:]) if len(parts) > 1 else parts[0]
                if len(stem) >= 3:
                    keys.append(stem)
            else:
                camel = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", name)
                keys = [camel[-1].lower()] if len(camel) >= 2 else [name.lower()]
            for key in keys:
                if not key or len(key) < 3:
                    continue
                families[key].append((name, start, end, has_check))

        for stem, members in families.items():
            # Dedup function names within family
            uniq = {}
            for m in members:
                uniq[m[0]] = m
            members = list(uniq.values())
            if len(members) < 2:
                continue
            with_check = [m for m in members if m[3]]
            without = [m for m in members if not m[3]]
            if with_check and without:
                for name, start, end, _ in without[:2]:
                    findings.append({
                        "tool": "sibling-variant",
                        "title": f"Sibling missing security check: {name} (family *{stem})",
                        "cvss": 7.8,
                        "description": (
                            f"Function `{name}` at line {start + 1} lacks security validation "
                            f"present in sibling(s) {[m[0] for m in with_check][:3]}. "
                            f"B6 sibling-variant: proven guard pattern in peer → almost certainly "
                            f"needed here. Highest-yield variant analysis technique."
                        ),
                        "file": _rel(dest, f),
                        "line": start + 1,
                        "confidence": "high",
                        "qualification": "QUALIFIED",
                        "lead_depth": 3,
                        "discovery_technique": "sibling-variant-b6",
                    })
        if len(findings) >= 40:
            break
    return findings[:40]


# ---------------------------------------------------------------------------
# 3b. Path-traversal via unsafe path join (archive/backup/upload/dotfile mgrs)
# ---------------------------------------------------------------------------

# Path-composition (base + attacker-influenced name) idioms, per language.
_PATH_JOIN_TOKENS = {
    "python": ("os.path.join(", "pathlib", "path.join(", ".joinpath(", "os.path.expanduser("),
    "node": ("path.join(", "path.resolve(", "path.normalize("),
    "go": ("filepath.Join(", "path.Join("),
    "java": ("Paths.get(", "path.of(", "new File(", "new FileInputStream(", "new FileOutputStream("),
    "ruby/rails": ("File.join(", "File.expand_path("),
    "php": ("dirname(", "realpath("),
}
# Filesystem *write/extract* sinks (traversal → arbitrary write/delete/exec).
_FS_WRITE_SINKS = (
    "open(", "write(", "writefile", "write_text", "write_bytes", "writestring",
    "shutil.copy", "shutil.copytree", "shutil.move", "copyfile", "copytree",
    "os.symlink", "os.link", "symlink(", "os.makedirs", "os.mkdir", "mkdir(",
    "os.remove", "os.unlink", "shutil.rmtree", "os.rename", "os.replace",
    "extractall", ".extract(", "createwritestream", "os.create", "ioutil.writefile",
    "os.openfile", "fileoutputstream", "files.write(", "files.copy(", "files.move(",
    "file_put_contents(", "fopen(", "move_uploaded_file(", "rename(", "copy(",
)
# Signals that the joined name is externally/config/archive/request derived.
_EXTERNAL_NAME_HINTS = (
    "filename", "file_name", "fname", "member.name", "entry.name", "entryname",
    "getmembers", ".namelist(", "arcname", "config.", "configparser", ".cfg",
    "request.", "params[", "req.params", "req.query", "argv", "getname()",
    "getentry", "ziparchive", "tarfile", "zipfile", "os.environ", "userinput",
    "user_input", "target", "dest", "destination", "outpath", "out_path",
)
# Robust containment checks (presence => NOT vulnerable for this file).
_CONTAINMENT_GUARDS = (
    "commonpath", "commonprefix", "os.path.realpath", "realpath(", "is_within",
    "safe_join", "secure_filename", "werkzeug.utils", "resolve().startswith",
    "startswith(base", "startswith(root", "startswith(target_dir",
    "relpath", "abspath(", "normpath(",  # only counts with a following startswith (checked below)
    '".."', "'..'", "contains(\"..\")", "'..' in", '".." in', "includes('..')",
    "includes(\"..\")", "strings.contains", "!strings.hasprefix", "filepath.rel",
)
# Absolute-path-only guard (partial sanitization: blocks '/', misses '..').
_ABS_GUARDS = (
    'startswith("/")', "startswith('/')", "os.path.isabs(", "isabs(",
    'startswith("/")', "filepath.isabs(", 'startswith("/")', "path.isabsolute(",
    'startswith("/")', "isabsolute(", "hasprefix(", "startswith('/'",
)


def path_traversal_join_scan(dest: Path, language: str) -> List[dict]:
    """Flag attacker-influenced names joined onto a base path and used in a
    filesystem write/extract sink without a containment check (CWE-22/CWE-59).

    Two high-signal sub-patterns:

    (A) join + fs-write sink + external-name hint + **no containment guard** →
        candidate arbitrary file write/delete/symlink via ``../`` traversal.
    (B) a path/name that passes an **absolute-path guard** (rejects ``/``) but
        has **no ``..`` / containment guard** → *partial-sanitization variant*:
        the classic "blocked absolute but forgot traversal" bug (higher signal,
        it proves the author considered path safety yet missed ``..``).

    General-purpose across archive extractors, backup/sync tools, dotfile
    managers, and upload handlers - not tied to any single project.
    """
    lang = _lang_key(language)
    join_tokens = _PATH_JOIN_TOKENS.get(lang, _PATH_JOIN_TOKENS["python"])
    findings: List[dict] = []

    def _has_real_containment(lines: List[str]) -> bool:
        # Unambiguous containment idioms anywhere in the file.
        text_l = "\n".join(lines).lower()
        if any(g in text_l for g in (
            "commonpath", "commonprefix", "is_within", "safe_join",
            "secure_filename", "resolve().startswith", "startswith(base",
            "startswith(root", '".." in', "'..' in", 'contains("..")',
            "includes('..')", "includes(\"..\")", "strings.contains(", "filepath.rel(",
        )):
            return True
        # normpath/abspath/realpath only *contain* when paired with a prefix
        # check on the SAME/adjacent line(s) AND applied to a real path (not the
        # module-locating `realpath(__file__)` idiom). Windowed to avoid the FP
        # where an unrelated `realpath(__file__)` looks like a guard.
        norm_lines = [
            i for i, ln in enumerate(lines)
            if any(n in ln.lower() for n in ("normpath(", "abspath(", "realpath("))
            and "__file__" not in ln
        ]
        for i in norm_lines:
            window = " ".join(lines[max(0, i - 2): i + 3]).lower()
            if "startswith(" in window or "commonpath" in window or "relpath(" in window:
                return True
        return False

    for f in _iter_source_files(dest, limit=300):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        text_l = text.lower()
        if not any(t.lower() in text_l for t in join_tokens):
            continue
        lines = text.splitlines()
        has_containment = _has_real_containment(lines)
        has_abs_guard = any(g in text_l for g in _ABS_GUARDS)
        has_fs_sink = any(s in text_l for s in _FS_WRITE_SINKS)
        has_external = any(h in text_l for h in _EXTERNAL_NAME_HINTS)
        rel = _rel(dest, f)

        # --- Pattern A: join + fs write sink + external name, no containment ---
        if has_fs_sink and has_external and not has_containment:
            join_lines = [
                i for i, ln in enumerate(lines)
                if any(t.lower() in ln.lower() for t in join_tokens)
            ]
            # Write-sink locality: only count a join as QUALIFIED when a real fs
            # write/extract sink appears within a small window of the join (same
            # function), so a far-away sink elsewhere in a big file doesn't taint
            # every join. Read/list sinks (glob/open-r) never qualify here.
            write_sink_lines = [
                i for i, ln in enumerate(lines)
                if any(s in ln.lower() for s in _FS_WRITE_SINKS)
            ]
            ext_hint_lines = [
                i for i, ln in enumerate(lines)
                if any(h in ln.lower() for h in _EXTERNAL_NAME_HINTS)
            ]
            for jl in join_lines[:4]:
                # Local taint: an external-name hint on or adjacent to the join.
                local_ext = any(abs(e - jl) <= 2 for e in ext_hint_lines)
                # Local write sink within the enclosing block (~15 lines).
                local_sink = any(abs(w - jl) <= 15 for w in write_sink_lines)
                qualifies = local_ext and local_sink
                if qualifies:
                    sev = 8.1 if has_abs_guard else 7.5
                    qual, conf, depth = "QUALIFIED", ("high" if has_abs_guard else "medium"), 3
                    locality = "external name on the join line reaches a nearby write sink"
                else:
                    sev = 6.0
                    qual, conf, depth = "LATENT", "low", 1
                    locality = ("no local external-name+write-sink coincidence at this "
                                "join (file-level co-occurrence only) → needs data-flow "
                                "confirmation before promotion")
                variant = (
                    "partial-sanitization (absolute path blocked, `../` NOT blocked)"
                    if has_abs_guard else "no path containment check at all"
                )
                findings.append({
                    "tool": "path-containment",
                    "title": f"Unsafe path join → filesystem write in {f.name}",
                    "cvss": sev,
                    "description": (
                        f"A name is composed onto a base path (line {jl + 1}) in `{rel}` with "
                        f"{variant}; {locality}. A `../` sequence (or a symlinked entry) would "
                        f"escape the intended directory → arbitrary file write/delete (CWE-22/"
                        f"CWE-59). Verify containment with realpath+commonpath and reject `..`. "
                        f"Prove in lab: craft a name like `../../../../tmp/pwned` and confirm the "
                        f"operation lands outside the base directory."
                    ),
                    "file": rel,
                    "line": jl + 1,
                    "confidence": conf,
                    "qualification": qual,
                    "lead_depth": depth,
                    "discovery_technique": "path-traversal-join",
                })

        # --- Pattern B: absolute guard present but no `..`/containment guard ---
        if has_abs_guard and not has_containment:
            abs_line = next(
                (i for i, ln in enumerate(lines) if any(g in ln.lower() for g in _ABS_GUARDS)),
                0,
            )
            # Avoid double-emitting the same file+line already covered by A.
            if not any(x["file"] == rel and x["line"] == abs_line + 1 for x in findings):
                findings.append({
                    "tool": "path-containment",
                    "title": f"Absolute-path guard without traversal guard in {f.name}",
                    "cvss": 8.1,
                    "description": (
                        f"`{rel}` rejects absolute paths (line {abs_line + 1}) but never rejects "
                        f"`..` or verifies containment (realpath+commonpath). This is the classic "
                        f"silent-fix-variant: the author considered path safety yet a `../../` "
                        f"relative path still escapes the base directory (CWE-22). "
                        f"Hunt the downstream join+filesystem sink this list/set feeds, and prove "
                        f"traversal in lab with a `../`-prefixed entry."
                    ),
                    "file": rel,
                    "line": abs_line + 1,
                    "confidence": "high",
                    "qualification": "QUALIFIED",
                    "lead_depth": 3,
                    "discovery_technique": "path-traversal-partial-sanitization",
                })
        if len(findings) >= 60:
            break
    return findings[:60]


# ---------------------------------------------------------------------------
# 4. Weak PRNG / JWT / OAuth patterns
# ---------------------------------------------------------------------------

def weak_secret_and_token_patterns(dest: Path, language: str) -> List[dict]:
    findings: List[dict] = []
    for f in _iter_source_files(dest, limit=300):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        # Only flag weak PRNG when near security-relevant context
        security_ctx = re.search(
            r"(?i)(token|secret|password|session|nonce|otp|api[_-]?key|auth|csrf|jwt|cookie|salt)",
            text,
        )
        for pat, title, cvss, desc in WEAK_PRNG_PATTERNS:
            for m in re.finditer(pat, text):
                # Low-severity informational patterns always allowed; high ones need security context
                if cvss >= 6.5 and not security_ctx and "JWT" not in title and "OAuth" not in title and "alg" not in title:
                    # Still keep if match line itself mentions security terms
                    line_no = text[:m.start()].count("\n")
                    line_txt = text.splitlines()[line_no] if line_no < len(text.splitlines()) else ""
                    if not re.search(r"(?i)(token|secret|password|session|nonce|key|auth|csrf|jwt)", line_txt):
                        continue
                line = text[:m.start()].count("\n") + 1
                findings.append({
                    "tool": "weak-secret-detection",
                    "title": title,
                    "cvss": cvss,
                    "description": f"{desc} File: {f.name}, line {line}.",
                    "file": _rel(dest, f),
                    "line": line,
                    "confidence": "medium" if cvss >= 7 else "low",
                    "qualification": "QUALIFIED" if cvss >= 7 else "LATENT",
                    "lead_depth": 1,
                    "discovery_technique": "weak-prng-jwt-oauth",
                })
                if len(findings) >= 60:
                    return findings
    return findings


# ---------------------------------------------------------------------------
# 5. Documentation-driven hunting
# ---------------------------------------------------------------------------

def docs_driven_hunting(dest: Path, language: str) -> List[dict]:
    findings: List[dict] = []
    doc_names = ["README.md", "README.rst", "SECURITY.md", "CHANGELOG.md", "API.md", "docs/security.md"]
    claim_re = re.compile(
        r"(?i).*\b(always|never|must|requires?|ensures?|guarantees?|authenticated|"
        r"encrypted|validated|sanitized|cannot|won't|will not|all endpoints)\b.*"
    )
    for name in doc_names:
        path = dest / name
        if not path.exists() or not path.is_file():
            continue
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        for i, line in enumerate(text.splitlines()):
            if not claim_re.match(line.strip()):
                continue
            if len(line.strip()) < 20:
                continue
            findings.append({
                "tool": "docs-driven-hunting",
                "title": f"Falsifiable security claim in {name}",
                "cvss": 5.5,
                "description": (
                    f"Documentation claim (line {i + 1}): «{line.strip()[:200]}». "
                    f"Docs-first doctrine: each claim is a hypothesis  - verify the code "
                    f"actually enforces it on every entry point (pre-auth gaps, error paths)."
                ),
                "file": name,
                "line": i + 1,
                "confidence": "low",
                "qualification": "LATENT",
                "lead_depth": 1,
                "discovery_technique": "docs-driven",
            })
            if len(findings) >= 25:
                return findings
    return findings


# ---------------------------------------------------------------------------
# 6. Complexity × taint hotspots
# ---------------------------------------------------------------------------

def complexity_hotspots(dest: Path, language: str, prior_findings: Optional[List[dict]] = None) -> List[dict]:
    prior_findings = prior_findings or []
    tainted_files = {f.get("file") for f in prior_findings if f.get("file")}
    findings: List[dict] = []

    for f in _iter_source_files(dest, limit=200):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        lines = text.splitlines()
        n = len(lines)
        if n < 40:
            continue
        branches = len(re.findall(r"\b(if|elif|else|case|when|catch|except|for|while|&&|\|\|)\b", text))
        nesting = 0
        max_nest = 0
        for line in lines:
            nesting += line.count("{") + len(re.findall(r":\s*$", line)) - line.count("}")
            max_nest = max(max_nest, nesting)
        score = (branches / max(n, 1)) * 50 + max_nest * 2 + math.log1p(n)
        rel = _rel(dest, f)
        has_taint = rel in tainted_files
        if score < 25 and not has_taint:
            continue
        if score < 18:
            continue
        # File-level complexity is a TRIAGE/prioritization signal, not a specific
        # confirmable bug (points at line 1, not a sink). Always LATENT so it
        # never inflates the QUALIFIED lead set; it steers where to look next.
        cvss = 5.5 if has_taint else 5.0
        findings.append({
            "tool": "complexity-hotspot",
            "title": f"Complexity hotspot{' × taint' if has_taint else ''}: {f.name}",
            "cvss": cvss,
            "description": (
                f"File complexity score {score:.1f} (lines={n}, branches≈{branches}, "
                f"max_nest≈{max_nest}). "
                + ("Intersects taint/sink findings → P0 file to audit (not itself a "
                   "confirmed bug; drill into the sinks in this file)." if has_taint else
                   "High complexity; prioritize if untrusted input enters this module.")
            ),
            "file": rel,
            "line": 1,
            "confidence": "medium" if has_taint else "low",
            "qualification": "LATENT",
            "lead_depth": 1,
            "discovery_technique": "complexity-taint-hotspot",
            "complexity_score": round(score, 2),
        })
    findings.sort(key=lambda x: x.get("complexity_score", 0), reverse=True)
    return findings[:30]


# ---------------------------------------------------------------------------
# 7. Cross-audit pattern transfer
# ---------------------------------------------------------------------------

def _pattern_is_safe(rx: str) -> bool:
    """Reject trivially broad / broken regexes that would hallucinate hits."""
    rx = (rx or "").strip()
    if len(rx) < 4:
        return False
    if rx in {".*", ".+", "\\w+", "error", "http", "true", "false", "return", "import"}:
        return False
    # Empty alternation (e.g. a||b or |foo|) matches everywhere
    if re.search(r"(^\||\|\||\|$)", rx):
        return False
    # Extremely short character classes / single tokens
    if len(re.sub(r"[\\^$.*+?()[\]{}|]", "", rx)) < 3:
        return False
    return True


def load_pattern_db() -> List[dict]:
    if not PATTERN_DB_PATH.exists():
        return []
    try:
        data = json.loads(PATTERN_DB_PATH.read_text(encoding="utf-8"))
        patterns = data if isinstance(data, list) else data.get("patterns", [])
        return [p for p in patterns if _pattern_is_safe(p.get("regex") or "")]
    except Exception:
        return []


def save_pattern_to_db(pattern: dict) -> None:
    """Append a learned detection pattern for future audits (Skill 48)."""
    PATTERN_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not _pattern_is_safe(pattern.get("regex") or pattern.get("title", "")):
        # Title-only entries allowed if they carry a safe regex field already checked
        if not _pattern_is_safe(pattern.get("regex") or ""):
            return
    patterns = load_pattern_db()
    key = (pattern.get("regex") or pattern.get("title", "")).strip()
    if not key:
        return
    for p in patterns:
        if (p.get("regex") or p.get("title")) == key:
            p["hit_count"] = p.get("hit_count", 0)
            p["last_seen"] = datetime.utcnow().isoformat() + "Z"
            PATTERN_DB_PATH.write_text(json.dumps(patterns, indent=2), encoding="utf-8")
            return
    pattern = dict(pattern)
    pattern.setdefault("hit_count", 0)
    pattern["learned_at"] = datetime.utcnow().isoformat() + "Z"
    patterns.append(pattern)
    # Cap growth
    PATTERN_DB_PATH.write_text(json.dumps(patterns[-500:], indent=2), encoding="utf-8")


def extract_patterns_from_finding(finding: dict, language: str = "unknown") -> Optional[dict]:
    """Derive a transferable grep pattern from a confirmed finding."""
    title = (finding.get("title") or "").lower()
    file_path = finding.get("file") or ""
    ext = Path(file_path).suffix if file_path else ""
    # Map common classes → regexes
    mapping = [
        (("command inject", "os.system", "subprocess", "child_process", "exec.command"),
         r"(os\.system|subprocess\.(call|run|Popen)|child_process\.exec|exec\.Command)\s*\("),
        (("sql inject", "sql injection"),
         r"(execute|raw|where)\s*\([^)]*(\+|%|format|f[\"'])"),
        (("path travers", "directory travers"),
         r"(open|readFile|File\.(read|open)|send_file)\s*\([^)]*(request|params|req\.)"),
        (("deserial", "pickle", "yaml.load", "marshal"),
         r"(pickle\.loads?|yaml\.load|Marshal\.load|unserialize|ObjectInputStream)\s*\("),
        (("ssti", "template inject", "render_template_string"),
         r"(render_template_string|render\s+inline|Template\s*\()"),
        (("hardcoded", "secret", "password", "api key"),
         r"(password|secret|api[_-]?key)\s*=\s*['\"][^'\"]{6,}['\"]"),
        (("ssrf",),
         r"(requests\.(get|post)|httpx\.(get|post)|fetch|axios|http\.Get)\s*\([^)]*(request|params|req\.)"),
        (("weak prng", "math.random", "random.random"),
         r"(random\.(random|randint)|Math\.random|mt_rand|srand\s*\(\s*time)\s*\("),
        (("eval", "code inject"),
         r"\b(eval|exec|Function|instance_eval|class_eval)\s*\("),
    ]
    for keys, regex in mapping:
        if any(k in title for k in keys):
            return {
                "title": finding.get("title", "learned-pattern"),
                "regex": regex,
                "language": language,
                "cvss": float(finding.get("cvss", 7.0)),
                "source_file": file_path,
                "extensions": [ext] if ext else [],
            }
    # Fallback: quote a distinctive snippet from description
    return {
        "title": finding.get("title", "learned-pattern"),
        "regex": re.escape((finding.get("title") or "")[:40]) if finding.get("title") else "",
        "language": language,
        "cvss": float(finding.get("cvss", 5.0)),
        "source_file": file_path,
        "extensions": [ext] if ext else [],
    }


# ---------------------------------------------------------------------------
# 6b. OpenAPI / SDK dangerous-surface discovery
# ---------------------------------------------------------------------------

_DANGEROUS_API_PATH_RE = re.compile(
    r"(?i)/(?:v\d+/)?(?:shell|bash|code|jupyter|nodejs|file|exec|upload|deserialize|admin|debug)"
    r"(?:/[\w_{}-]+)*"
)


def openapi_and_sdk_surface_scan(dest: Path, language: str) -> List[dict]:
    """Treat documented dangerous API surfaces and SDK wrappers as QUALIFIED sinks.

    Critical for SDK/agent-sandbox style repos where classic os.system sinks live
    behind HTTP clients (`shell.exec`, `code.execute`, `file.read`) rather than
    local process APIs. Absence of classic sinks must not mean 'no findings'.
    """
    findings: List[dict] = []
    # 1) OpenAPI / swagger dangerous paths (allow under docs/  - specs are intel, not noise)
    for spec in list(dest.rglob("openapi.json"))[:8] + list(dest.rglob("swagger.json"))[:4]:
        parts = {p.lower() for p in spec.relative_to(dest).parts}
        # Skip only heavy vendor trees; keep docs/public openapi specs
        if parts & {".git", "node_modules", "vendor", ".bundle", "__pycache__", ".venv", "venv"}:
            continue
        try:
            data = json.loads(spec.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        paths = data.get("paths") or {}
        if not isinstance(paths, dict):
            continue
        for api_path, methods in paths.items():
            if not _DANGEROUS_API_PATH_RE.search(str(api_path)):
                continue
            methods = methods if isinstance(methods, dict) else {}
            verb = next((v for v in ("post", "put", "patch", "delete", "get") if v in methods), "post")
            op = methods.get(verb) or {}
            desc = (op.get("summary") or op.get("description") or "")[:180]
            findings.append({
                "tool": "api-surface",
                "title": f"Dangerous API surface: {verb.upper()} {api_path}",
                "cvss": 8.1 if any(x in str(api_path).lower() for x in ("exec", "shell", "bash", "code")) else 7.2,
                "description": (
                    f"OpenAPI documents `{verb.upper()} {api_path}`  - a crown-jewel sink for "
                    f"command/file/code execution. Hypothesis: caller-supplied command/path reaches "
                    f"this endpoint without authz/sandbox escape controls. {desc}"
                ),
                "file": _rel(dest, spec),
                "line": 1,
                "confidence": "high",
                "qualification": "QUALIFIED",
                "lead_depth": 2,
                "discovery_technique": "api-surface-openapi",
                "entry_point": f"{verb.upper()} {api_path}",
            })
            if len(findings) >= 40:
                break

    # 2) SDK wrappers that POST to dangerous endpoints / expose exec_command
    wrapper_re = re.compile(
        r"(?i)(exec_command|execCommand|shell\.exec|code\.execute|bash\.exec|"
        r"[\"']v1/(?:shell|bash|code|file|jupyter)/(?:exec|read|write|execute))"
    )
    for f in _iter_source_files(dest, limit=220):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for m in wrapper_re.finditer(text):
            line = text[:m.start()].count("\n") + 1
            findings.append({
                "tool": "api-surface",
                "title": f"SDK dangerous wrapper: {m.group(1)[:60]}",
                "cvss": 7.8,
                "description": (
                    f"Client/SDK wrapper `{m.group(1)}` at line {line} forwards into a "
                    f"remote execution or filesystem sink. Trace every caller for untrusted "
                    f"command/path injection and missing authz (guard-alternate-path on API)."
                ),
                "file": _rel(dest, f),
                "line": line,
                "confidence": "medium",
                "qualification": "QUALIFIED",
                "lead_depth": 2,
                "discovery_technique": "api-surface-sdk",
            })
            if len(findings) >= 80:
                return findings[:80]
    return findings[:80]


def _pattern_hit_is_false_positive(window: str, title_key: str, regex: str) -> bool:
    """Suppress cross-audit pattern hits that match a provably-safe idiom.

    Pattern-transfer regexes are broad by design (they generalize across repos);
    without this filter they mislabel safe code — e.g. flagging `subprocess.run(
    [list])` as "os.system/popen RCE" or a parameterized query as "SQL injection".
    This is the single biggest precision lever for the technique.
    """
    w = window.lower()
    ctx = (title_key + " " + regex).lower()

    # --- Command execution / RCE family --------------------------------------
    if (any(k in ctx for k in ("system", "popen", "subprocess", "command", "shell"))
            or re.search(r"\b(?:exec|rce)\b", ctx)):
        # Genuinely shell-invoking sinks stay flagged.
        shelly = ("os.system(" in w or "os.popen(" in w or "shell=true" in w
                  or "commands.getoutput" in w or "`" in w or "/bin/sh" in w
                  or "eval(" in w or "exec(" in w)
        # subprocess.* WITHOUT shell=True never invokes a shell, regardless of
        # whether the argv is an inline list or a variable holding one → safe.
        uses_subprocess = "subprocess." in w
        if uses_subprocess and not shelly:
            return True
        # A bare mention with no actual exec sink on the line is noise.
        if not shelly and not uses_subprocess:
            return True
        # A genuine shell-invoking sink is a real hit. Do not fall through to
        # the SQL heuristics: a title like "Command Injection via os.system"
        # contains "injection", and the SQL branch would wrongly suppress the
        # hit for lacking string interpolation.
        return False

    # --- SQL injection family -------------------------------------------------
    if any(k in ctx for k in ("sql", "select", "insert", "query", "execute")):
        # Parameterized / bound queries are safe.
        parameterized = bool(re.search(r"(execute|executemany)\s*\([^)]*[,]\s*[\(\[\{]", w)) \
            or " where " in w and "?" in w \
            or "%s" in w and "," in w \
            or re.search(r"\?\s*[,)\]]", w) is not None
        # Interpolated identifiers passed through a quoting/allow-list helper.
        quoted_ident = any(q in w for q in ("qsql_id", "quote_ident", "quote_identifier",
                                            "identifier(", "sql.identifier", "escape_string"))
        # Only a real risk when a variable is interpolated directly into SQL text.
        raw_interp = ("f'" in w or 'f"' in w or "%" in w or "+" in w or ".format(" in w)
        if parameterized or quoted_ident or not raw_interp:
            return True

    return False


def pattern_transfer_scan(dest: Path, language: str) -> List[dict]:
    """Apply learned patterns from prior audits to this repository.

    Anti-hallucination rules:
      - Deduplicate identical regexes
      - Cap hits per pattern and per file
      - Only QUALIFIED when match is near a sink or untrusted source
      - Skill-markdown backtick extracts stay LATENT unless corroborated
    """
    patterns = load_pattern_db()
    # Also extract patterns from existing skill markdown Detection Heuristic sections
    skills_dir = Path(os.environ.get("LOTUS_SKILLS_DIR", str(Path(__file__).resolve().parent.parent / "data" / "skills")))
    if skills_dir.exists():
        md_files = [
            p for p in skills_dir.rglob("*.md")
            if p.is_file()
            and "packs" not in p.parts
            and ".revisions" not in p.parts
            and ".git" not in p.parts
        ]
        for md in md_files[:200]:
            try:
                content = md.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            # Pull fenced grep hints: `grep ...` or raw regex lines
            for m in re.finditer(r"`([^`]{6,120})`", content):
                snippet = m.group(1)
                if any(x in snippet for x in (
                    "grep", "(", "system", "eval", "exec", "password", "pickle",
                    "GroovyShell", "failure_mode_allow", "plugin.Open",
                    "ParseUnverified", "Hessian", "SpelExpression",
                    "X-Forwarded-For", "dashboard_pwd",
                )):
                    # Convert simple grep -rn 'pat' hints to regex if possible
                    # A quoted function argument (e.g. filter='data') is
                    # not a detection regex. Accept only explicit search
                    # commands or an authored raw-regex literal.
                    explicit_pattern = re.match(r"^(?:(?:grep|egrep|fgrep|rg)\s|r['\"])", snippet.strip())
                    gm = re.search(r"['\"]([^'\"]+)['\"]", snippet) if explicit_pattern else None
                    if gm and len(gm.group(1)) >= 4:
                        patterns.append({
                            "title": f"skill-transfer:{md.stem[:40]}",
                            "regex": gm.group(1).replace("\\|", "|"),
                            "language": "multi",
                            "cvss": 6.5,
                            "from_skill_markdown": True,
                        })

    # Dedup patterns by regex (prefer pattern_db entries over markdown extracts)
    deduped: Dict[str, dict] = {}
    for p in patterns:
        rx = (p.get("regex") or "").strip()
        if len(rx) < 4:
            continue
        prev = deduped.get(rx)
        if prev is None or (prev.get("from_skill_markdown") and not p.get("from_skill_markdown")):
            deduped[rx] = p
    patterns = list(deduped.values())[:120]

    findings: List[dict] = []
    compiled: List[Tuple[dict, re.Pattern]] = []
    for p in patterns:
        rx = p.get("regex") or ""
        if len(rx) < 4:
            continue
        # Reject trivially broad patterns that match almost any file
        if not _pattern_is_safe(rx):
            continue
        try:
            compiled.append((p, re.compile(rx, re.IGNORECASE)))
        except re.error:
            continue

    if not compiled:
        return []

    lang = _lang_key(language)
    sinks = SINK_KEYWORDS.get(lang, SINK_KEYWORDS["python"])
    sources = SOURCE_KEYWORDS.get(lang, SOURCE_KEYWORDS["python"])
    per_pattern: Dict[str, int] = defaultdict(int)
    per_file_pattern: Dict[Tuple[str, str], int] = defaultdict(int)

    for f in _iter_source_files(dest, limit=250):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        lines = text.splitlines()
        sink_lines = {i for i, line in enumerate(lines) if any(s in line for s in sinks)}
        source_lines = {i for i, line in enumerate(lines) if any(s in line for s in sources)}
        for p, cre in compiled:
            # Language filter when specified
            plang = (p.get("language") or "multi").lower()
            if plang not in ("multi", "unknown", "any", "") and plang not in language.lower():
                if language.startswith("ruby") and "ruby" not in plang:
                    continue
            title_key = p.get("title") or p.get("regex") or "pattern"
            if per_pattern[title_key] >= 5:
                continue
            for m in cre.finditer(text):
                if per_pattern[title_key] >= 5:
                    break
                line = text[:m.start()].count("\n") + 1
                rel = _rel(dest, f)
                fp_key = (rel, title_key)
                if per_file_pattern[fp_key] >= 2:
                    continue
                # Corroboration: match near sink or source → QUALIFIED; else LATENT
                idx = line - 1
                # Precision filter: suppress provably-safe idioms (list-arg
                # subprocess, parameterized/quoted SQL) and test-infra files.
                window = "\n".join(lines[max(0, idx - 1): idx + 2])
                if _pattern_hit_is_false_positive(window, str(title_key), p.get("regex", "")):
                    continue
                if rel.endswith(("conftest.py",)) or "conftest" in Path(rel).name:
                    continue
                near_sink = any(abs(idx - s) <= 25 for s in sink_lines)
                near_source = any(abs(idx - s) <= 25 for s in source_lines)
                corroborated = near_sink or near_source
                from_md = bool(p.get("from_skill_markdown"))
                if from_md and not corroborated:
                    # Skill markdown extracts are hints only without local corroboration
                    qualification = "LATENT"
                    confidence = "low"
                    cvss = min(float(p.get("cvss", 6.5)), 5.5)
                elif corroborated:
                    qualification = "QUALIFIED"
                    confidence = "medium"
                    cvss = float(p.get("cvss", 7.0))
                else:
                    qualification = "LATENT"
                    confidence = "low"
                    cvss = min(float(p.get("cvss", 7.0)), 6.0)
                findings.append({
                    "tool": "pattern-transfer",
                    "title": f"Cross-audit pattern hit: {str(title_key)[:80]}",
                    "cvss": cvss,
                    "description": (
                        f"Learned pattern from prior audit matched at line {line}. "
                        f"Pattern transfer (Skill 48) compounds effectiveness: "
                        f"`{p.get('regex', '')[:120]}`. "
                        f"Corroboration: {'sink/source proximity' if corroborated else 'none  - LATENT until gated'}."
                    ),
                    "file": rel,
                    "line": line,
                    "confidence": confidence,
                    "qualification": qualification,
                    "lead_depth": 2 if corroborated else 1,
                    "discovery_technique": "pattern-transfer",
                    "source_pattern": p.get("title"),
                })
                per_pattern[title_key] += 1
                per_file_pattern[fp_key] += 1
                p["hit_count"] = p.get("hit_count", 0) + 1
                if len(findings) >= 80:
                    # Persist updated hit counts
                    try:
                        existing = load_pattern_db()
                        by_rx = {x.get("regex"): x for x in existing}
                        for pat, _ in compiled:
                            if pat.get("regex") in by_rx:
                                by_rx[pat["regex"]]["hit_count"] = pat.get("hit_count", 0)
                        if by_rx:
                            PATTERN_DB_PATH.write_text(
                                json.dumps(list(by_rx.values()), indent=2), encoding="utf-8"
                            )
                    except Exception:
                        pass
                    return findings
    return findings


# ---------------------------------------------------------------------------
# 8. Lifecycle / revocation scan (Skill 50)
# ---------------------------------------------------------------------------

LIFECYCLE_ASYMMETRY_PATTERNS = {
    "python": [
        (r"(remember_me|refresh_token)", r"(session\.destroy|logout)", "Session create without destroy",
         "remember_me/refresh_token issued but no matching session.destroy/logout cleanup found."),
        (r"(revoke.*token|token.*revoke)", r"(websocket|long[\._]poll)", "Token revoke without WebSocket cleanup",
         "Token revocation present but no websocket/long-poll session teardown."),
    ],
    "ruby/rails": [
        (r"session\.destroy", r"cookies\.delete", "Session destroy without cookie cleanup",
         "session.destroy called but cookies.delete not paired  - stale session cookie persists."),
        (r"Devise\.sign_out", r"warden\.logout", "Devise sign_out without warden cleanup",
         "Devise.sign_out found but warden.logout not called  - session may persist in middleware."),
    ],
    "node": [
        (r"req\.session\.destroy", r"socket\.disconnect", "Session destroy without socket disconnect",
         "req.session.destroy called but socket.disconnect missing  - WebSocket remains authenticated."),
        (r"token\.revoke", r"cache\.del", "Token revoke without cache invalidation",
         "token.revoke called but cache.del not found  - cached token remains valid."),
    ],
    "go": [
        (r"session\.Delete", r"conn\.Close", "Session delete without connection close",
         "session.Delete called but conn.Close missing  - connection may retain auth state."),
        (r"cache\.(Invalidate|Delete|Del)", r"(broadcast|Notify|Publish)", "Cache invalidation without broadcast",
         "Cache invalidated locally but no broadcast/notify to other nodes  - stale auth in cluster."),
    ],
}


def lifecycle_revocation_scan(dest: Path, language: str) -> List[dict]:
    """Detect setup/teardown asymmetry: session create without destroy, token issue
    without revoke, WebSocket auth that doesn't expire (Skill 50).

    Core insight: lifecycle operations come in pairs. When the teardown half is
    missing, auth state leaks  - sessions outlive intent, tokens can't be revoked,
    and long-lived connections retain stale permissions.
    """
    lang = _lang_key(language)
    findings: List[dict] = []
    patterns = LIFECYCLE_ASYMMETRY_PATTERNS.get(lang, [])

    if not patterns:
        return findings

    for f in _iter_source_files(dest, limit=300):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue

        for setup_pat, teardown_pat, title, desc in patterns:
            setup_matches = list(re.finditer(setup_pat, text, re.IGNORECASE))
            if not setup_matches:
                continue

            teardown_found = re.search(teardown_pat, text, re.IGNORECASE)
            if teardown_found:
                continue

            for m in setup_matches[:3]:
                line = text[:m.start()].count("\n") + 1
                findings.append({
                    "tool": "lifecycle-revocation",
                    "title": f"Lifecycle asymmetry: {title}",
                    "cvss": 7.5,
                    "description": (
                        f"{desc} File: {f.name}, line {line}. "
                        f"Setup/teardown asymmetry (Skill 50): the setup half "
                        f"`{m.group(0)[:60]}` exists but the teardown counterpart "
                        f"matching `{teardown_pat}` is absent in this module."
                    ),
                    "file": _rel(dest, f),
                    "line": line,
                    "confidence": "medium",
                    "qualification": "QUALIFIED",
                    "lead_depth": 2,
                    "discovery_technique": "lifecycle-revocation",
                })

        if len(findings) >= 50:
            break

    return findings[:50]


# ---------------------------------------------------------------------------
# 9. Coverage ledger
# ---------------------------------------------------------------------------

COVERAGE_GATES = (
    "forward_taint",
    "sink_first",
    "error_paths",
    "dynamic_trace",
    "variant_analysis",
)


def build_coverage_ledger(
    dest: Path,
    language: str,
    findings: List[dict],
    tool_results: Optional[List[dict]] = None,
    attack_surface: Optional[dict] = None,
    discovery_meta: Optional[dict] = None,
    runtime_evidence: Optional[dict] = None,
) -> Dict[str, Any]:
    """Five-gate exhaustion ledger per P1/P2 surface (SYSTEM D33).

    Strategy IDs come from ``all_discovery_strategies`` rather than a stale
    alias list.  ``discovery_meta`` and ``runtime_evidence`` are optional so
    older callers remain compatible while the final audit snapshot can include
    post-lab dynamic work.
    """
    tool_results = tool_results or []
    attack_surface = attack_surface or {}
    discovery_meta = discovery_meta or {}
    runtime_evidence = runtime_evidence or {}
    completed_tools = {t.get("name") for t in tool_results if t.get("status") == "completed"}
    finding_tools = {f.get("tool") for f in findings if isinstance(f, dict)}

    strategy_ids = {
        "sink-first", "path-containment", "guard-alternate-path",
        "object-level-authz", "silent-fix-variants", "weak-secret-detection",
        "docs-driven-hunting", "api-surface", "pattern-transfer",
        "lifecycle-revocation", "complexity-hotspot", "gateway-control-plane",
        "agent-app-control-plane",
    }
    strategy_runs = {
        str(name) for name in (discovery_meta.get("strategies") or [])
        if str(name).strip()
    }
    if "high-yield-discovery" in completed_tools:
        # pass_counts is populated for every strategy, including a clean
        # zero-hit pass, which is exactly what coverage needs to distinguish
        # "ran clean" from "was never scheduled".
        strategy_runs.update(
            str(name) for name in (discovery_meta.get("pass_counts") or {}).keys()
            if str(name).strip()
        )
    strategy_runs.update(
        str(name) for name in (completed_tools | finding_tools)
        if str(name) in strategy_ids
    )

    surfaces: List[Dict[str, Any]] = []
    # Derive surfaces from attack surface + finding files
    endpoints = []
    if isinstance(attack_surface, dict):
        endpoints = attack_surface.get("endpoints") or attack_surface.get("routes") or []
        if isinstance(endpoints, dict):
            endpoints = list(endpoints.keys())
    files_touched = sorted({f.get("file") for f in findings if f.get("file")})[:40]

    surface_names = [f"endpoint:{e}" for e in list(endpoints)[:20]]
    surface_names += [f"module:{Path(f).stem}" for f in files_touched[:20]]
    if not surface_names:
        surface_names = [f"repo:{dest.name}"]

    tech_map = {
        "forward_taint": {"taint-proximity", "cross-file-taint", "joern-cpg"},
        "sink_first": {"sink-first", "entry-point-dataflow", "api-surface"},
        "error_paths": {"methodology-patterns", "error-path-residue"},
        "dynamic_trace": {"dynamic-recon", "dynamic-path-exploration", "native-fuzzing"},
        "variant_analysis": {"silent-fix-variants", "sibling-variant", "pattern-transfer", "check-referent-mismatch"},
    }

    # Track per-skill completion status
    guard_alternate_complete = "guard-alternate-path" in finding_tools or "guard-alternate-path" in completed_tools or "guard-alternate-path" in strategy_runs
    lifecycle_scan_ran = "lifecycle-revocation" in finding_tools or "lifecycle-revocation" in completed_tools or "lifecycle-revocation" in strategy_runs
    tainted_dep_ran = "taint-proximity" in finding_tools or "tainted-dependency" in completed_tools
    comparison_fidelity_checked = "grep-patterns" in completed_tools or "grep-pattern" in finding_tools

    # Per-tool coverage tracking
    all_tool_names = strategy_ids | {
        "taint-proximity", "cross-file-taint", "methodology-patterns", "error-path-residue",
        "dynamic-path-exploration", "dynamic-recon", "native-fuzzing", "check-referent-mismatch",
    }
    tools_that_ran = (completed_tools | finding_tools | strategy_runs) & all_tool_names
    per_tool_coverage_pct = round(100.0 * len(tools_that_ran) / max(len(all_tool_names), 1), 1)

    for name in surface_names[:30]:
        gates = {}
        evidence: List[str] = []
        for gate, tools in tech_map.items():
            hit = bool(tools & (completed_tools | finding_tools | strategy_runs))
            if gate == "dynamic_trace":
                app_type = str(runtime_evidence.get("app_type") or "")
                lab_status = runtime_evidence.get("lab_status") or {}
                if isinstance(lab_status, dict) and str(lab_status.get("status") or "").lower() == "disabled":
                    # Explicit operator-disabled lab mode is a declared
                    # non-applicability decision, not a silent dynamic clean.
                    hit = True
                if app_type in {"library", "cli-tool"}:
                    harness = runtime_evidence.get("library_harness") or {}
                    hit = hit or (
                        isinstance(harness, dict)
                        and any(
                            isinstance(value, dict)
                            and str(value.get("status") or "") == "completed"
                            for value in harness.values()
                        )
                    )
                dynamic = runtime_evidence.get("dynamic_recon") or {}
                p2 = runtime_evidence.get("phase2_execution") or {}
                if isinstance(dynamic, dict) and dynamic.get("probed"):
                    hit = True
                if isinstance(p2, dict) and int(p2.get("unresolved", 0) or 0) == 0:
                    skipped = int(p2.get("skipped", 0) or 0)
                    not_applicable = int(p2.get("not_applicable", 0) or 0)
                    hit = hit or (
                        int(p2.get("failed", 0) or 0) == 0
                        and skipped <= not_applicable
                    )
            gates[gate] = hit
            if hit:
                evidence.extend(sorted(tools & (completed_tools | finding_tools | strategy_runs)))
        exhausted = all(gates.values())
        surfaces.append({
            "surface": name,
            "priority": "P1" if name.startswith("endpoint:") else "P2",
            "gates": gates,
            "exhausted": exhausted,
            "evidence": sorted(set(evidence)),
        })

    exhausted_n = sum(1 for s in surfaces if s["exhausted"])
    return {
        "surfaces": surfaces,
        "surface_count": len(surfaces),
        "exhausted_count": exhausted_n,
        "exhaustion_pct": round(100.0 * exhausted_n / max(len(surfaces), 1), 1),
        "gates_defined": list(COVERAGE_GATES),
        "skill_coverage": {
            "guard_alternate_path_complete": guard_alternate_complete,
            "lifecycle_scan_ran": lifecycle_scan_ran,
            "tainted_dependency_ran": tainted_dep_ran,
            "comparison_fidelity_checked": comparison_fidelity_checked,
        },
        "per_tool_coverage_pct": per_tool_coverage_pct,
        "tools_ran": sorted(tools_that_ran),
        "tools_missing": sorted(all_tool_names - tools_that_ran),
        "honest_exit": (
            "EXIT_A_CRITICALS" if any(f.get("cvss", 0) >= 9 and f.get("status") == "report-eligible" for f in findings)
            else ("EXIT_B_EXHAUSTED" if exhausted_n == len(surfaces) and surfaces else "IN_PROGRESS")
        ),
    }


# ---------------------------------------------------------------------------
# 9. Discovery effectiveness metrics
# ---------------------------------------------------------------------------

def measure_discovery_effectiveness(
    findings: List[dict],
    validated: Optional[List[dict]] = None,
    skills_before: int = 0,
    skills_after: int = 0,
    pattern_hits: int = 0,
    duration_ms: int = 0,
) -> Dict[str, Any]:
    """Primary KPIs from audit-markdown-light measurement doctrine."""
    validated = validated or [f for f in findings if f.get("status") in ("report-eligible", "proven")]
    qualified = [f for f in findings if f.get("qualification") == "QUALIFIED"]
    latent = [f for f in findings if f.get("qualification") == "LATENT"]
    depths = [int(f.get("lead_depth") or 1) for f in findings]
    deep = sum(1 for d in depths if d >= 3)
    techniques: Dict[str, int] = defaultdict(int)
    for f in findings:
        techniques[f.get("discovery_technique") or f.get("tool") or "unknown"] += 1

    confirmed_qualified = [
        f for f in validated
        if f.get("qualification") == "QUALIFIED" or f.get("conviction_level", 0) >= 2
    ]
    confirm_rate = (len(confirmed_qualified) / max(len(qualified), 1)) if qualified else 0.0

    return {
        "total_leads": len(findings),
        "qualified_leads": len(qualified),
        "latent_leads": len(latent),
        "validated_findings": len(validated),
        "qualified_confirm_rate": round(confirm_rate, 3),
        "lead_depth_avg": round(sum(depths) / max(len(depths), 1), 2),
        "lead_depth_ge3_pct": round(100.0 * deep / max(len(depths), 1), 1),
        "techniques": dict(techniques),
        "skills_before": skills_before,
        "skills_after": skills_after,
        "skills_learned_delta": max(0, skills_after - skills_before),
        "pattern_transfer_hits": pattern_hits,
        "duration_ms": duration_ms,
        "cvss_demonstrated_ge9": sum(
            1 for f in validated
            if float(f.get("cvss", 0)) >= 9.0 and f.get("conviction_level", 0) >= 2
        ),
        "high_signal_score": round(
            (len(qualified) * 2 + deep * 3 + pattern_hits + len(confirmed_qualified) * 5)
            / max(duration_ms / 1000.0, 0.1),
            3,
        ),
        "miss_diagnosis": _diagnose_misses(findings, validated),
    }


def _diagnose_misses(findings: List[dict], validated: List[dict]) -> Dict[str, Any]:
    """Explain why the engine may miss bugs  - actionable, not fatalistic."""
    reasons = []
    techniques = {f.get("discovery_technique") or f.get("tool") for f in findings}
    if (
        "sink-first" not in techniques
        and "sink-first-proximity" not in techniques
        and "api-surface-openapi" not in techniques
        and "api-surface-sdk" not in techniques
    ):
        reasons.append("sink_first_not_producing_leads  - call graph may be too shallow or language unsupported")
    if "guard-alternate-path" not in techniques:
        reasons.append("no_guard_alternate_path_leads  - target may lack classic web auth middleware")
    if "pattern-transfer" not in techniques:
        reasons.append("pattern_db_empty_or_no_hits  - compound learning not yet primed")
    if "sibling-variant-b6" not in techniques and "variant-analysis" not in techniques:
        reasons.append("no_sibling_variants  - shallow clone may lack history; sibling naming may not cluster")
    if not validated:
        reasons.append("zero_validated  - lab proof or AI gating did not elevate leads (proof budget / gates)")
    shallow = sum(1 for f in findings if int(f.get("lead_depth") or 1) < 2)
    if findings and shallow / len(findings) > 0.7:
        reasons.append("shallow_leads_dominant  - 70%+ cite single site; need multi-hop / sibling depth")
    return {
        "likely_miss_causes": reasons,
        "recommendation": (
            "Increase proof budget on top QUALIFIED leads; run sink-first + guard-alternate-path "
            "to completion; ensure pattern_db and skills seed are populated; do not declare "
            "code safe  - absence of findings means this pass missed them."
        ),
    }


# ---------------------------------------------------------------------------
# Orchestrator: run all high-yield discovery passes
# ---------------------------------------------------------------------------

def _detect_present_languages(dest: Path, primary: str) -> List[str]:
    """Return primary + any additional languages evidenced by manifests/extensions."""
    langs = [_lang_key(primary)]
    checks = [
        ("python", lambda: (dest / "requirements.txt").exists() or (dest / "pyproject.toml").exists()
         or any(dest.rglob("*.py"))),
        ("node", lambda: (dest / "package.json").exists() or any(dest.rglob("*.ts"))),
        ("go", lambda: (dest / "go.mod").exists()),
        ("ruby/rails", lambda: (dest / "Gemfile").exists()),
        ("java", lambda: (dest / "pom.xml").exists() or (dest / "build.gradle").exists()),
    ]
    for name, pred in checks:
        try:
            if name not in langs and pred():
                langs.append(name)
        except Exception:
            continue
    return langs[:4]


def _gateway_control_plane_strategy(dest: Path, language: str) -> List[dict]:
    """Lazy import so discovery_engine does not import analyzers at module load."""
    from backend.analyzers.gateway_plane import gateway_control_plane_strategy
    return gateway_control_plane_strategy(dest, language)


def _agent_app_plane_strategy(dest: Path, language: str) -> List[dict]:
    """Lazy import so discovery_engine does not import analyzers at module load."""
    from backend.analyzers.agent_app_plane import agent_app_plane_strategy
    return agent_app_plane_strategy(dest, language)


def object_level_authz_scan(dest: Path, language: str) -> List[dict]:
    """IDOR / broken object-level authorization (logic + authz, cross-language).

    The most common real-world web logic/authz bug: a handler fetches a record
    by a *user-supplied* identifier and then uses it **without** verifying the
    caller is allowed to access that specific object (no ownership/tenant/perm
    check). This under-served class is why Django (zulip) and Rails
    (react_on_rails) audits show rich generic-authz leads but almost no
    object-level ones.

    Heuristic (no AST): for each handler file, find object-fetch-by-user-id
    lines; within the enclosing function window, require an ownership/authz
    token (current_user/request.user/authorize/scoped query/permission check).
    If none is present, emit a QUALIFIED lead for Phase-2 to prove in the lab.
    """
    lang = _lang_key(language)
    findings: List[dict] = []

    # (fetch-by-id regex, user-input tokens) per language
    fetch = {
        "python": re.compile(
            r"(?:\.objects\.(?:get|filter)\s*\(|get_object_or_404\s*\(|"
            r"\.objects\.get_or_create\s*\(|session\.query\([^)]*\)\.get\s*\()"),
        "ruby/rails": re.compile(
            r"\b[A-Z]\w+\.(?:find|find_by|find_by_id|find_by!)\s*\(|"
            r"\.find\s*\(\s*params\["),
        "node": re.compile(
            r"\.(?:findById|findOne|findByPk|findByIdAndUpdate|findByIdAndDelete)\s*\("),
    }.get(lang)
    if fetch is None:
        return findings

    user_input = {
        "python": ("request.", "self.kwargs", "kwargs[", "pk=", "id=", "request.GET", "request.POST", "request.data", "query_params"),
        "ruby/rails": ("params[", "params.require", "params.fetch"),
        "node": ("req.params", "req.query", "req.body", "req.headers"),
    }[lang]

    # Ownership / authorization tokens that, if present in the enclosing scope,
    # indicate the object access IS checked (so it is not a naive IDOR).
    ownership = {
        "python": (
            "request.user", "self.request.user", "has_perm", "has_permission",
            "permissionrequired", "isowner", "get_queryset", "filter(user",
            "filter(realm", "user=request.user", "user_id=request.user",
            "permissiondenied", "check_", "authorize", "@login_required",
            "user_profile", "acting_user", "can_", "access_control",
            # Django/Zulip per-object authz helpers (from django-object-authz-gap skill):
            "has_message_access", "access_message", "access_stream_by_id",
            "access_stream", "access_user_by_id", "check_stream_access",
            "user_has_access", "require_member", "get_object_or_403",
            "userpassestestmixin", "permissionrequiredmixin", "validate_access",
        ),
        "ruby/rails": (
            "current_user", "current_account", "authorize", "can?", "cannot?",
            "policy", "pundit", "cancan", ".where(", "current_organization",
            "authenticate_user", "check_", "scoped", "accessible_by",
        ),
        "node": (
            "req.user", "req.session", "isowner", "ownerid", "userid ===",
            "authorize", "checkpermission", "haspermission", "req.auth",
            "verifyowner", "can(", "ability", "acl",
        ),
    }[lang]

    # Directories that never contain live request handlers -- skipping them
    # removes the dominant false-positive source (ORM calls in schema
    # migrations, tests, fixtures, and vendored/dummy apps).
    _skip_parts = {
        "migrations", "migration", "test", "tests", "spec", "specs",
        "fixtures", "factories", "examples", "example", "node_modules",
        "vendor", "__pycache__", ".venv", "seeds", "seed", "db",
        "management", "commands", "scripts", "bin", "tools", "benchmarks",
    }

    # Entry-point directory/file hints: IDOR lives at request handlers, not in
    # internal helpers (which receive already-authorized objects). Restricting
    # to handler context is the single biggest precision lever without a call graph.
    _handler_parts = {"views", "controllers", "api", "handlers", "endpoints",
                      "routes", "resources", "web", "rest"}
    _req_tok = {"python": "request", "ruby/rails": "params", "node": "req"}[lang]

    per_file_cap = 6
    files = _iter_source_files(dest, limit=400)
    for f in files:
        # Repo-RELATIVE parts only; an absolute prefix like /Users/test/… must
        # not match the "test" skip token and drop every handler file.
        try:
            _rel_parts = f.relative_to(dest).parts
        except ValueError:
            _rel_parts = f.parts
        parts_low = {p.lower() for p in _rel_parts}
        if _skip_parts & parts_low:
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        # Skip obvious non-handler files to reduce noise
        low = text.lower()
        if not any(h in low for h in ("request", "params", "req.", "def ", "class ", "function", "controller", "view")):
            continue
        path_is_handler = bool(_handler_parts & parts_low) or "controller" in f.name.lower()
        lines = text.splitlines()
        hits = 0
        for i, line in enumerate(lines):
            if hits >= per_file_cap:
                break
            if not fetch.search(line):
                continue
            # Handler context (entry-point path or a request-bearing enclosing
            # signature) is used as a CONFIDENCE signal, not a hard filter: we
            # still surface internal-helper candidates (lower confidence) so
            # Phase-2 + the lab can adjudicate, but rank true request handlers
            # higher so the operator triages them first.
            is_handler_ctx = path_is_handler
            if not is_handler_ctx:
                for j in range(i, max(-1, i - 30), -1):
                    lj = lines[j]
                    if ("def " in lj) or ("function" in lj) or re.search(r"=>\s*\{|\)\s*=>", lj):
                        is_handler_ctx = _req_tok in lj.lower()
                        break
            # Confirm the fetched id is user-controlled (same line or +/-2 lines)
            ctx = " ".join(lines[max(0, i - 2): i + 3]).lower()
            if not any(tok.lower() in ctx for tok in user_input):
                continue
            # Enclosing scope window: look back to function start-ish and forward
            window = " ".join(lines[max(0, i - 25): i + 12]).lower()
            if any(tok in window for tok in ownership):
                continue  # object access appears to be authorized
            # Capability-URL pattern: access is gated by an unguessable signed
            # token / HMAC / salt rather than a per-user check. Not a naive IDOR
            # (Phase-2 would need to forge the signature). Suppress this FP class.
            if any(tok in window for tok in (
                "badsignature", "signing", "signer", "hmac", "salt", "itsdangerous",
                "verify_signature", "signed", "message_authentication",
            )):
                continue
            snippet = line.strip()[:140]
            findings.append({
                "tool": "object-level-authz",
                "title": (
                    f"Possible IDOR / missing object-level authorization in {f.name}"
                    if is_handler_ctx else
                    f"Object fetch without ownership check (helper) in {f.name}"
                ),
                "cvss": 7.5 if is_handler_ctx else 5.5,
                "description": (
                    f"Line {i + 1} fetches an object using a user-supplied identifier "
                    f"(`{snippet}`) with no ownership/tenant/permission check in the "
                    f"enclosing handler. This is a broken-object-level-authorization "
                    f"(IDOR) logic bug: another authenticated user may read or mutate "
                    f"objects they do not own. Phase-2 must prove it in the lab by "
                    f"requesting a neighbouring object id as a different principal and "
                    f"comparing the before/after response (200 + foreign data = confirmed)."
                ),
                "file": _rel(dest, f),
                "line": i + 1,
                "confidence": "high" if is_handler_ctx else "low",
                "qualification": "QUALIFIED" if is_handler_ctx else "NEEDS-REVIEW",
                "lead_depth": 2,
                "primitive_type": "idor_object_authz",
                "handler_context": is_handler_ctx,
                "discovery_technique": "object-level-authz",
            })
            hits += 1
        if len(findings) >= 80:
            break
    return findings


def all_discovery_strategies() -> List[Tuple[str, Any, bool]]:
    """Plug-and-play registry: (id, callable, per_language).

    Callables take (dest, language) except complexity-hotspot which also
    accepts prior findings via a thin wrapper below. New detectors register
    here; the orchestrator iterates this list and nothing else.
    """
    return [
        ("sink-first", sink_first_reachability, True),
        ("path-containment", path_traversal_join_scan, True),
        ("guard-alternate-path", guard_alternate_path, True),
        ("object-level-authz", object_level_authz_scan, True),
        ("silent-fix-variants", silent_fix_and_variants, True),
        ("weak-secret-detection", weak_secret_and_token_patterns, True),
        ("docs-driven-hunting", docs_driven_hunting, True),
        ("api-surface", openapi_and_sdk_surface_scan, True),
        ("pattern-transfer", pattern_transfer_scan, True),
        ("lifecycle-revocation", lifecycle_revocation_scan, True),
        ("complexity-hotspot", complexity_hotspots, False),
        ("gateway-control-plane", _gateway_control_plane_strategy, False),
        ("agent-app-control-plane", _agent_app_plane_strategy, False),
    ]


def register_discovery_strategy(strategy_id: str, fn, per_language: bool = True) -> None:
    """Hot-add a detector. Subsequent run_high_yield_discovery() calls include it."""
    # Mutate the list returned by all_discovery_strategies via module attr.
    extra = getattr(register_discovery_strategy, "_extra", [])
    extra.append((strategy_id, fn, per_language))
    register_discovery_strategy._extra = extra


def run_high_yield_discovery(
    dest: Path,
    language: str,
    prior_findings: Optional[List[dict]] = None,
    skip_strategies: Optional[Set[str]] = None,
) -> Tuple[List[dict], Dict[str, Any]]:
    """Execute the high-yield discovery battery. Returns (findings, meta)."""
    t0 = datetime.utcnow()
    prior_findings = list(prior_findings or [])
    all_findings: List[dict] = []
    languages = _detect_present_languages(dest, language)
    pass_counts: Dict[str, int] = defaultdict(int)
    skip = set(skip_strategies or [])

    strategies = list(all_discovery_strategies())
    strategies.extend(getattr(register_discovery_strategy, "_extra", []))

    def _ingest(name: str, got: List[dict]) -> None:
        existing = {(f.get("tool"), f.get("file"), f.get("line"), f.get("title")) for f in all_findings}
        fresh = [
            f for f in (got or [])
            if (f.get("tool"), f.get("file"), f.get("line"), f.get("title")) not in existing
        ]
        pass_counts[name] += len(fresh)
        all_findings.extend(fresh)

    def _error_finding(name: str, err: Exception) -> dict:
        return {
            "tool": name,
            "title": f"Discovery pass error: {name}",
            "cvss": 0.0,
            "description": str(err)[:300],
            "file": "",
            "line": 0,
            "confidence": "low",
            "qualification": "NO-BOUNDARY",
        }

    def _run_strategy(name, fn, per_language, extra_prior=None):
        got: List[dict] = []
        try:
            if name == "complexity-hotspot":
                got = list(fn(dest, languages[0], extra_prior if extra_prior is not None else prior_findings) or [])
            elif per_language:
                for lang in languages:
                    got.extend(fn(dest, lang) or [])
            else:
                got.extend(fn(dest, languages[0]) or [])
        except Exception as e:
            got.append(_error_finding(name, e))
        return name, got

    independent = [(n, f, p) for n, f, p in strategies if n not in skip and n != "complexity-hotspot"]
    dependent = [(n, f, p) for n, f, p in strategies if n not in skip and n == "complexity-hotspot"]
    try:
        workers = max(1, int(os.environ.get("LOTUS_DISCOVERY_WORKERS", "4") or 4))
    except ValueError:
        workers = 4

    if workers <= 1 or len(independent) <= 1:
        for name, fn, per_language in independent:
            _ingest(*_run_strategy(name, fn, per_language))
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(independent))) as pool:
            futs = [pool.submit(_run_strategy, n, f, p) for n, f, p in independent]
            for fut in as_completed(futs):
                name, got = fut.result()
                _ingest(name, got)

    for name, fn, per_language in dependent:
        _ingest(*_run_strategy(name, fn, per_language, extra_prior=prior_findings + all_findings))

    # Cap total high-yield findings to keep Phase 2 focused
    all_findings.sort(
        key=lambda f: (
            0 if f.get("qualification") == "QUALIFIED" else 1,
            -float(f.get("cvss") or 0),
            -int(f.get("lead_depth") or 1),
        )
    )
    all_findings = all_findings[:250]

    duration_ms = int((datetime.utcnow() - t0).total_seconds() * 1000)
    pattern_hits = pass_counts.get("pattern-transfer", 0)
    metrics = measure_discovery_effectiveness(
        all_findings,
        validated=[],
        pattern_hits=pattern_hits,
        duration_ms=duration_ms,
    )
    meta = {
        "pass_counts": dict(pass_counts),
        "languages_scanned": languages,
        "metrics": metrics,
        "duration_ms": duration_ms,
        "strategies": [s[0] for s in strategies if s[0] not in skip],
    }
    return all_findings, meta
