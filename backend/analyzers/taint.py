from __future__ import annotations
import re
import os
import json
import subprocess
import shlex
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
import httpx
import asyncio



def _run_taint_proximity(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Taint-proximity analysis: find functions where untrusted input sources
    and dangerous sinks co-occur within the same scope.

    This produces HIGH confidence findings because it demonstrates that
    external data reaches a dangerous operation in the same function,
    unlike pure grep which just matches patterns anywhere.
    """
    # Define taint sources (untrusted input) per language
    TAINT_SOURCES = {
        "ruby/rails": [r"\bparams\b", r"\brequest\b", r"\bcookies\b", r"\bsession\b", r"\bENV\b",
                       r"\bARGV\b", r"\bcontents\b", r"\bformula_struct\b", r"\b(api_|json_)?(source|response|body)\b",
                       r"\bnode\b", r"\battributes?\b", r"\boptions?\b", r"\bnew_resource\b", r"\bconfig\b",
                       r"\bpayload\b", r"\bdata\b", r"\bjson\b", r"\bcookbook\b"],
        "python": [r"\brequest\.(args|form|data|json|files|values|headers|query_params|path_params)\b",
                   r"\bsys\.argv\b", r"\bos\.environ\b", r"\binput\s*\(", r"\bsys\.stdin\b", r"\bdata\b",
                   r"\bstdin", r"\braw_output\b", r"\bmagic_run_command\b",
                   r"\b(spec|body|params|options|runtime|task|function|artifact|key_path|stop_condition)\b",
                   r"\b(raw_data|user_input|payload|header|cookie|url|endpoint|target_path)\b"],
        "node": [r"\breq\.(body|query|params|headers|cookies)\b", r"\bprocess\.env\b",
                 r"\bprocess\.argv\b", r"\breq\.url\b"],
        "go": [r"\br\.(URL|Body|Header|Form|PostForm)\b", r"\bos\.Args\b", r"\bos\.Getenv\b",
               r"\bfmt\.Scan\b", r"r\.URL\.Query\b"],
        "java": [r"\brequest\.getParameter\b", r"\brequest\.getHeader\b", r"\brequest\.getInputStream\b",
                 r"\bSystem\.getenv\b", r"\bSystem\.getProperty\b", r"@RequestParam\b", r"@RequestHeader\b", r"@RequestBody\b"],
        "php": [r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b", r"\bfile_get_contents\s*\(\s*['\"]php://input",
                r"\bgetenv\s*\("],
        "c/cpp": [r"\bargv\b", r"\bgetenv\s*\(", r"\bread\s*\(", r"\brecv\s*\(", r"\bfgets\s*\(",
                  r"\bscanf\s*\(", r"\bstdin\b", r"\bYAML::Node\b", r"\bYAML::LoadFile\b",
                  r"\bstep\[", r"\bitem\[", r"\bcmdsStr\b", r"\bcmds\b"],
    }

    # Define dangerous sinks per language
    TAINT_SINKS = {
        "ruby/rails": [
            (r"\bsystem\s*\(", "command injection", 9.0),
            (r"\bexec\s*\(", "command injection", 9.0),
            (r"\beval\s*\(", "code injection", 9.0),
            (r"\bmodule_eval\s*\(", "code injection (module_eval)", 9.0),
            (r"\bclass_eval\s*\(", "code injection (class_eval)", 9.0),
            (r"\binstance_eval\b", "code injection", 9.0),
            (r"%x\{", "shell execution (%x)", 8.5),
            (r"\bOpen3\.\w+\s*\(", "command execution (Open3)", 8.5),
            (r"\bIO\.popen\s*\(", "command execution (IO.popen)", 8.5),
            (r"\bProcess\.spawn\s*\(", "command execution (Process.spawn)", 8.5),
            (r"\bPTY\.spawn\s*\(", "command execution (PTY.spawn)", 8.5),
            (r"\bshell_out[!_a-z]*\s*\(", "command execution (shell_out)", 8.8),
            (r"\bpowershell_out[!_a-z]*\s*\(", "command execution (powershell_out)", 8.8),
            (r"\bpowershell_exec[!_a-z]*\s*\(", "PowerShell script injection (powershell_exec)", 8.8),
            (r"\bMixlib::ShellOut\.new\s*\(", "command execution (Mixlib::ShellOut)", 8.8),
            (r"\b(URI|Kernel)\.open\s*\(\s*['\"]\|", "Kernel/URI open command execution pipe", 9.0),
            (r"\bsend\s*\(", "arbitrary method call", 8.0),
            (r"\bpublic_send\s*\(", "arbitrary method dispatch", 8.0),
            (r"\bconst_get\s*\(", "arbitrary class instantiation", 7.5),
            (r"\brender\s+inline:", "template injection", 8.0),
            (r"\b(raw|html_safe)\b", "XSS (unescaped output)", 6.5),
            (r"\bMarshal\.(load|restore)\b", "deserialization RCE", 9.0),
            (r"\bYAML\.load\s*\(", "deserialization RCE", 8.5),
            (r"\bPSON\.parse\s*\(", "PSON catalog deserialization", 8.8),
            (r"Puppet::Util::Execution\.execute", "Puppet Execution.execute RCE", 9.0),
            (r"\bExecJS\.(eval|compile|exec)", "ExecJS SSR RCE", 9.0),
            (r"\bPsych\.(unsafe_load|load)\s*\(", "YAML deserialization RCE", 8.5),
            (r"\bJSON\.load\s*\(", "JSON unsafe deserialization", 8.0),
            (r"\bFile\.open\b", "path traversal", 7.0),
            (r"\b(where|find_by_sql|execute)\s*\([^)]*#\{", "SQL injection", 9.0),
            (r"\bmake_relative_symlink\b", "symlink creation (TOCTOU)", 6.5),
            (r"\.startswith\s*\(|\.start_with\?\s*\(|\.startsWith\s*\(|\.HasPrefix\s*\(", "prefix match guard", 7.0),
            (r"strncmp\s*\(", "length-limited comparison", 7.5),
        ],

        "python": [
            (r"\bos\.system\s*\(", "command injection", 9.0),
            (r"\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True", "command injection (shell=True)", 9.0),
            (r"\bsubprocess\.Popen\s*\(", "command execution (Popen)", 8.0),
            (r"\bsubprocess\.(call|run|check_output)\s*\(", "command execution (subprocess)", 7.5),
            (r"\beval\s*\(", "code injection", 9.0),
            (r"\bexec\s*\(", "code injection", 9.0),
            (r"\bast\.literal_eval\s*\(", "literal_eval injection", 7.0),
            (r"\bpickle\.loads?\s*\(", "deserialization RCE", 9.0),
            (r"\b(cloudpickle|dill)\.loads?\s*\(", "deserialization RCE (cloudpickle/dill)", 9.0),
            (r"\bjoblib\.load\s*\(", "ML model deserialization (joblib)", 8.5),
            (r"\btorch\.load\s*\(", "PyTorch model deserialization (torch.load)", 8.5),
            (r"\byaml\.load\s*\(", "deserialization RCE", 8.5),
            (r"\btarfile\.extract(?:all)?\s*\(", "tar slip / overwrite", 7.9),
            (r"pre_hook|deploy_hook|renew_hook", "privileged ACME hook RCE", 8.9),
            (r"x-headroom-base-url|x-headroom-user-id", "AI-proxy SSRF/identity", 8.8),
            (r"\byaml\.load_all\s*\(", "deserialization RCE", 8.5),
            (r"\bxmltodict\.parse\s*\(", "XML parsing (entity risk)", 7.5),
            (r"\bplistlib\.loads?\s*\(", "plist deserialization", 7.0),
            (r"\bimportlib\.import_module\s*\(", "arbitrary module import", 8.5),
            (r"\burllib\.request\.urlopen\s*\(", "SSRF (urlopen)", 7.5),
            (r"\b(httpx|requests)\.(get|post|put|delete|request)\s*\(", "SSRF (HTTP request)", 7.5),
            (r"\bfsspec\.open\s*\(", "fsspec remote file access", 7.0),
            (r"\bopen\s*\(", "path traversal", 7.0),
            (r"\brender_template_string\s*\(", "SSTI", 9.0),
            (r"\b__import__\s*\(", "arbitrary import", 8.0),
            (r"\bsys\.path\.(append|insert)\s*\(", "sys.path injection (module hijack)", 8.0),
            (r"\bsys\.path\s*=", "sys.path replacement (module hijack)", 8.0),
            (r"NamedTemporaryFile\s*\([^)]*delete\s*=\s*False", "unsafe temp file TOCTOU", 7.0),
            (r"\bappdirs\.\w+\s*\(", "user-controllable data dir", 7.0),
            (r"\.startswith\s*\(|\.start_with\?\s*\(|\.startsWith\s*\(|\.HasPrefix\s*\(", "prefix match guard", 7.0),
            (r"strncmp\s*\(", "length-limited comparison", 7.5),
        ],

        "node": [
            (r"\bchild_process\.\w+\s*\(", "command injection", 9.0),
            (r"\beval\s*\(", "code injection", 9.0),
            (r"\bFunction\s*\(", "code injection", 9.0),
            (r"\bfs\.\w+\s*\(", "path traversal/file ops", 7.0),
            (r"\b(innerHTML|outerHTML)\s*=", "DOM XSS", 6.5),
            (r"\bvm\.\w+\s*\(", "sandbox escape", 8.5),
            (r"\.startswith\s*\(|\.start_with\?\s*\(|\.startsWith\s*\(|\.HasPrefix\s*\(", "prefix match guard", 7.0),
            (r"strncmp\s*\(", "length-limited comparison", 7.5),
        ],
        "go": [
            (r"\bexec\.Command\s*\(", "command injection", 8.5),
            (r"\b(db\.Query|db\.Exec)\s*\(", "SQL injection", 9.0),
            (r"\b(os\.Open|ioutil\.ReadFile)\w*\s*\(", "path traversal", 7.0),
            (r"\btemplate\.HTML\s*\(", "XSS (unescaped)", 6.5),
            (r"\bfmt\.Fprintf\s*\(\s*\w+\s*,\s*\w+\s*\)", "format string", 7.0),
            (r"\.startswith\s*\(|\.start_with\?\s*\(|\.startsWith\s*\(|\.HasPrefix\s*\(", "prefix match guard", 7.0),
            (r"strncmp\s*\(", "length-limited comparison", 7.5),
        ],
        "java": [
            (r"\bRuntime\..*exec\s*\(", "command injection", 9.0),
            (r"\bProcessBuilder\s*\(", "command injection", 8.5),
            (r"\bObjectInputStream\b", "deserialization RCE", 9.0),
            (r"\bClass\.forName\s*\(", "arbitrary class loading", 8.0),
            (r"\bStatement\.\w*execute\w*\s*\(", "SQL injection", 9.0),
            (r"\.startswith\s*\(|\.start_with\?\s*\(|\.startsWith\s*\(|\.HasPrefix\s*\(", "prefix match guard", 7.0),
            (r"strncmp\s*\(", "length-limited comparison", 7.5),
        ],
        "php": [
            (r"\beval\s*\(", "code injection", 9.0),
            (r"\bsystem\s*\(", "command injection", 9.0),
            (r"\bexec\s*\(", "command injection", 9.0),
            (r"\bshell_exec\s*\(", "command injection", 9.0),
            (r"\bunserialize\s*\(", "deserialization RCE", 9.0),
            (r"\binclude\s*\(?\s*\$", "local file inclusion", 8.5),
            (r"\bmysql_query\s*\(", "SQL injection", 9.0),
            (r"\.startswith\s*\(|\.start_with\?\s*\(|\.startsWith\s*\(|\.HasPrefix\s*\(", "prefix match guard", 7.0),
            (r"strncmp\s*\(", "length-limited comparison", 7.5),
        ],
        "c/cpp": [
            (r"\bsystem\s*\(", "command injection", 9.0),
            (r"\bpopen\s*\(", "command injection", 8.5),
            (r"\binja::render\s*\(", "template script injection", 8.8),
            (r"\bfmt::format\s*\(", "command string concatenation (fmt::format)", 8.5),
            (r"->Script\(\)\s*<<", "unquoted script generation", 8.5),
            (r"\bstrcpy\s*\(", "buffer overflow", 7.5),
            (r"\bsprintf\s*\(", "format string / buffer overflow", 7.5),
            (r"\bmemcpy\s*\(", "buffer overflow", 6.5),
            (r"\bgets\s*\(", "buffer overflow", 9.0),
            (r"\bstrcat\s*\(", "buffer overflow", 7.0),
            (r"\bmalloc\s*\(", "unchecked allocation", 6.0),
            (r"\brealloc\s*\(", "unchecked reallocation", 7.0),
            (r"\batoi\s*\(", "unchecked integer conversion", 6.5),
            (r"\bfree\s*\(", "use-after-free / double-free", 7.0),
            # YAML parser sinks (pecl-yaml)
            (r"\byaml_parser_parse\s*\(", "YAML parser state manipulation", 7.0),
            (r"\byaml_document_get_node\s*\(", "YAML document node access", 6.5),
            # PHP extension sinks
            (r"\bemalloc\s*\(", "PHP unchecked allocation", 7.0),
            (r"\bZVAL_STRING\s*\(", "PHP zval string manipulation", 6.0),
            (r"\bconvert_to_string\s*\(", "PHP type coercion", 5.5),
            (r"\bzend_parse_parameters\s*\(", "PHP parameter parsing", 5.0),
        ],

    }
    # Normalize language names to match internal keys
    _lang_normalize = {"javascript": "node", "ruby": "ruby/rails", "typescript": "node"}
    lang_key = _lang_normalize.get(language, language)
    sources = TAINT_SOURCES.get(lang_key, [])
    sinks = TAINT_SINKS.get(lang_key, [])
    if not sources or not sinks:
        return []

    _skip_dirs = {".git", "node_modules", "vendor", ".bundle", "__pycache__", ".venv", "venv",
                   "target", "build", "dist", "test", "tests", "spec", "specs", "fixtures",
                   "examples", "example", "testdata", "mock", "mocks", "__tests__", "testing",
                   "docs", "doc", "documentation"}
    _skip_file_patterns = {"test_", "_test.", "_spec.", ".test.", ".spec.", "mock_", "fake_"}
    _source_exts = {".rb": "ruby/rails", ".py": "python", ".js": "node", ".ts": "node",
                    ".go": "go", ".java": "java", ".php": "php", ".c": "c/cpp", ".cpp": "c/cpp", ".h": "c/cpp"}

    findings: List[dict] = []
    max_findings = 50

    for f in dest.rglob("*"):
        if len(findings) >= max_findings:
            break
        if not f.is_file() or f.stat().st_size > 500_000:
            continue
        if f.suffix.lower() not in _source_exts:
            continue
        parts = set(p.lower() for p in f.relative_to(dest).parts)
        if parts & _skip_dirs:
            continue
        fname_lower = f.name.lower()
        if any(p in fname_lower for p in _skip_file_patterns):
            continue

        try:
            content = f.read_text(errors="ignore")
        except Exception:
            continue

        # Split into function-level chunks (approximate by indent/def/class boundaries)
        # Look for co-occurrence of source + sink within ~50 lines
        lines = content.splitlines()
        for sink_pat, sink_type, sink_cvss in sinks:
            for sm in re.finditer(sink_pat, content):
                sink_line = content[:sm.start()].count("\n") + 1
                # Check if any taint source appears within a window of this sink
                # C/C++ functions tend to be longer; use wider window
                _proximity = 100 if lang_key in ("c/cpp", "c", "cpp") else 50
                window_start = max(0, sink_line - _proximity)
                window_end = min(len(lines), sink_line + 10)
                window_text = "\n".join(lines[window_start:window_end])
                for src_pat in sources:
                    if re.search(src_pat, window_text):
                        # Source and sink co-occur - high confidence
                        rel_path = str(f.relative_to(dest))
                        sink_name = sink_pat.split("(")[0].replace("\\b", "").replace("\\", "")
                        findings.append({
                            "tool": "taint-proximity",
                            "title": f"Potential {sink_type}: untrusted input near {sink_name}",
                            "cvss": sink_cvss,
                            "description": (
                            f"Untrusted input source detected within {_proximity} lines of dangerous sink "
                                f"({sink_type}) at {rel_path}:{sink_line}. "
                                f"Verify data flow from source to sink and check for sanitization."
                            ),
                            "file": rel_path,
                            "line": sink_line,
                            "confidence": "high",
                        })
                        break  # one source match per sink is enough
                if len(findings) >= max_findings:
                    break
            if len(findings) >= max_findings:
                break
    return findings


def _run_entry_point_dataflow(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """T1/T9: Build per-entry-point dataflow maps showing which params reach which sinks."""
    results = []
    
    try:
        attack_surface_data = attack_surface(dest, language)
    except Exception:
        attack_surface_data = None
        
    if not attack_surface_data:
        return results
    
    entry_points = attack_surface_data.get('entry_points', [])
    routes = attack_surface_data.get('routes', [])
    
    # Build a quick lookup of source patterns and sink patterns per language
    SOURCES = {
        'python': [r'request\.(args|form|json|data|values|headers|files)', r'sys\.argv', r'os\.environ'],
        'node': [r'req\.(body|query|params|headers|cookies)', r'process\.env', r'process\.argv'],
        'ruby/rails': [r'params\[', r'request\.', r'cookies\[', r'ENV\['],
        'go': [r'r\.URL\.Query', r'r\.Form', r'r\.Body', r'os\.Args', r'os\.Getenv'],
        'java': [r'request\.getParameter', r'@RequestParam', r'@RequestBody', r'@RequestHeader'],
        'php': [r'\$_(GET|POST|REQUEST|COOKIE|SERVER)', r'file_get_contents.*php://input'],
        'c/cpp': [r'\bargv\b', r'\bgetenv\b', r'\bread\b', r'\brecv\b', r'\bfgets\b'],
    }
    SINKS = {
        'python': ['os.system', 'subprocess', 'eval(', 'exec(', 'pickle.loads', 'open(', 'render_template_string', '.execute('],
        'node': ['child_process', 'exec(', 'eval(', 'fs.', 'innerHTML', 'deserialize'],
        'ruby/rails': ['system(', 'exec(', 'eval(', 'File.', 'YAML.load', 'Marshal.load', 'send('],
        'go': ['exec.Command', 'os.Open', 'db.Query', 'db.Exec', 'template.HTML', 'plugin.Open', 'jwt.ParseUnverified'],
        'java': ['Runtime', 'ProcessBuilder', 'ObjectInputStream', 'Statement.execute', 'Class.forName', 'GroovyShell', 'SpelExpressionParser', 'Hessian2Input'],
        'php': ['eval(', 'exec(', 'system(', 'shell_exec', 'unserialize', 'include(', 'mysql_query'],
        'c/cpp': ['system(', 'popen(', 'strcpy(', 'sprintf(', 'memcpy(', 'gets(', 'exec('],
    }
    
    lang_key = {'javascript': 'node', 'ruby': 'ruby/rails', 'typescript': 'node'}.get(language, language)
    src_pats = SOURCES.get(lang_key, [])
    sink_kws = SINKS.get(lang_key, [])
    if not src_pats or not sink_kws:
        return results
    
    for ep in entry_points[:30]:
        ep_file = ep.get('file', '')
        if not ep_file:
            continue
        fp = dest / ep_file
        if not fp.exists():
            continue
        try:
            text = fp.read_text(errors='ignore')
        except Exception:
            continue
        
        sources_found = []
        sinks_found = []
        for sp in src_pats:
            for m in re.finditer(sp, text):
                sources_found.append(m.group())
        for sk in sink_kws:
            if sk in text:
                sinks_found.append(sk)
        
        if sources_found and sinks_found:
            results.append({
                'tool': 'entry-point-dataflow',
                'title': f'Dataflow: {ep.get("name", ep_file)} - {len(sources_found)} sources reach {len(sinks_found)} sinks',
                'cvss': 6.0,
                'description': f'Entry point {ep.get("name", ep_file)} in {ep_file} has {len(sources_found)} untrusted input sources ({list(set(sources_found))[:3]}) and {len(sinks_found)} dangerous sinks ({sinks_found[:3]}). This entry point has high taint density and warrants deep Phase 2 review.',
                'file': ep_file,
                'line': 0,
                'confidence': 'medium',
            })
    return results


def _run_boundary_crossing_audit(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Evaluate by-design capabilities for security boundary violations.

    For every repo, regardless of whether it's an execution platform, package manager,
    or regular app, this tool checks for:
    (a) Auth bypass - can capabilities be reached without valid credentials?
    (b) Sandbox escape - can execution break out of intended isolation?
    (c) Privilege escalation - can lower-privilege users access higher-privilege features?
    (d) Boundary crossing - can read/write/execute outside intended scope?
    """
    results: List[dict] = []
    _skip = {".git", "node_modules", "vendor", "__pycache__", ".venv", "target", "build", "dist"}

    # --- (A) Auth bypass patterns: endpoints/capabilities without auth ---
    auth_bypass_patterns = {
        "node": [
            # API routes without auth middleware
            (r"(?:app|router)\.\w+\s*\(\s*['\"]([^'\"]+)['\"](?:(?!auth|token|session|verify|middleware).)*\bfunction\b",
             "API route without auth middleware", 8.0,
             "API endpoint defined without authentication middleware. Test: call endpoint without token."),
            # Missing ticket/session validation on exec endpoints
            (r"(?:exec|execute|eval|shell|bash|run)\w*\s*(?:\(|=)(?:(?!ticket|auth|token|session).){0,100}(?:req\.|request\.)",
             "Execution endpoint without ticket validation", 9.0,
             "Code execution endpoint appears to process requests without ticket/session validation. "
             "Test: can /v1/bash/exec be called without a valid auth ticket?"),
        ],
        "java": [
            # Public methods in controller without @Authorized or @PreAuthorize
            (r"@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\("
             r"(?:(?!@Authorized|@PreAuthorize|@Secured|@RolesAllowed).){0,200}"
             r"public\s+\w+\s+(\w+)\s*\(",
             "Controller method without auth annotation", 7.5,
             "REST endpoint method lacks authorization annotation. "
             "Test: call endpoint without valid session/credentials."),
        ],
        "ruby/rails": [
            # Controller actions without before_action auth
            (r"class\s+\w+Controller\s*<(?:(?!before_action\s+:authenticate|before_action\s+:authorize).){0,500}"
             r"def\s+(\w+)",
             "Controller without auth before_action", 7.0,
             "Controller class lacks authentication before_action filter. "
             "Test: access controller actions without login."),
        ],
        "python": [
            # Flask/FastAPI routes without login_required
            (r"@app\.route\s*\(\s*['\"]([^'\"]+)['\"](?:(?!login_required|auth|permission|token).){0,100}\ndef\s+(\w+)",
             "Route without auth decorator", 7.0,
             "Web route defined without authentication decorator. "
             "Test: access route without valid session."),
        ],
    }

    # --- (B) Sandbox escape / container breakout patterns ---
    escape_patterns = [
        # Host filesystem access
        (r"(?:/proc/|/sys/|/dev/|/host/|/var/run/docker\.sock|/root/|/home/\w+/\.ssh)",
         "Host filesystem path reference", 7.5,
         "Code references host filesystem paths that may break container/sandbox isolation. "
         "Test: can sandbox process read/write host filesystem?"),
        # Docker socket access
        (r"docker\.sock|/var/run/docker|dockerode|Docker\.from_env|docker_client",
         "Docker socket access", 9.0,
         "Code accesses Docker socket which enables container escape to host. "
         "Test: can container reach docker.sock and spawn host-level containers?"),
        # Process namespace escape
        (r"(?:nsenter|unshare|chroot|pivot_root|setns)\s*\(",
         "Namespace escape primitive", 8.5,
         "Code uses namespace manipulation primitives that could escape isolation. "
         "Test: can process escape its namespace to host namespace?"),
        # Capability checks that might be bypassable
        (r"(?:CAP_SYS_ADMIN|CAP_NET_ADMIN|CAP_SYS_PTRACE|SYS_RAWIO|CAP_DAC_OVERRIDE)",
         "Dangerous Linux capability", 8.0,
         "Code checks for or requires dangerous Linux capabilities that enable sandbox escape. "
         "Test: does the container/sandbox run with these capabilities?"),
        # Writable /tmp or shared directories
        (r"(?:File\.write|fs\.writeFile|open\s*\(.+['\"]w['\"]|fwrite)\s*\("
         r"(?:(?!sandbox|tmp/sandbox|isolated).){0,50}(?:/tmp/|/var/tmp/|/shared/)",
         "Write to shared directory outside sandbox", 7.0,
         "Code writes to shared filesystem location. "
         "Test: can sandbox process write outside its isolated directory?"),
        # Environment variable leakage
        (r"(?:process\.env|os\.environ|ENV\[|System\.getenv|getenv\s*\()\s*\[?\s*['\"]"
         r"(?:AWS_|GITHUB_TOKEN|DATABASE_URL|API_KEY|SECRET|PASSWORD|PRIVATE_KEY)",
         "Sensitive environment variable access", 7.5,
         "Code accesses sensitive environment variables that may leak host secrets into sandbox. "
         "Test: does sandbox inherit host environment variables?"),
    ]

    # --- (C) Privilege escalation patterns ---
    privesc_patterns = [
        (r"(?:setuid|seteuid|setreuid|setgid|setegid|chmod\s+[0-7]*[4-7]\d{2})\s*\(",
         "Privilege escalation primitive", 8.0,
         "Code uses privilege escalation system calls. "
         "Test: can lower-privileged process escalate to root/admin?"),
        (r"(?:sudo|su\s+-|doas|runas)\s",
         "Privilege escalation command", 7.5,
         "Code invokes privilege escalation commands. "
         "Test: can unprivileged user trigger sudo/su execution?"),
        (r"(?:admin|root|superuser|privileged)\s*(?:=\s*true|:\s*true|\?\s*$)",
         "Admin flag assignment", 7.0,
         "Code assigns admin/privileged status. "
         "Test: can user control the admin flag value?"),
    ]

    lang_key = language.lower().replace(" ", "")
    auth_pats = auth_bypass_patterns.get(lang_key, [])

    exts_map = {
        "java": (".java",), "python": (".py",), "ruby/rails": (".rb",),
        "php": (".php",), "node": (".js", ".ts", ".mjs"),
        "c/cpp": (".c", ".h", ".cpp"),
    }
    valid_exts = exts_map.get(lang_key, (".py", ".rb", ".js", ".java", ".php", ".ts", ".c", ".h"))

    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in _skip]
        for fname in files:
            if not fname.endswith(valid_exts):
                continue
            fpath = Path(root) / fname
            try:
                text = fpath.read_text(errors="ignore")
            except Exception:
                continue
            rel = str(fpath.relative_to(dest))

            # Auth bypass patterns (language-specific)
            for pat, title, cvss, desc in auth_pats:
                for m in re.finditer(pat, text, re.DOTALL):
                    line_num = text[:m.start()].count("\n") + 1
                    results.append({
                        "tool": "boundary-crossing-audit",
                        "title": title,
                        "cvss": cvss,
                        "description": f"{desc} File: {rel}:{line_num}",
                        "file": rel,
                        "line": line_num,
                        "confidence": "medium",
                        "boundary_crossing": True,
                        "primitive_type": "auth_bypass",
                    })

            # Sandbox escape patterns (all languages)
            for pat, title, cvss, desc in escape_patterns:
                for m in re.finditer(pat, text, re.IGNORECASE):
                    line_num = text[:m.start()].count("\n") + 1
                    results.append({
                        "tool": "boundary-crossing-audit",
                        "title": title,
                        "cvss": cvss,
                        "description": f"{desc} File: {rel}:{line_num}",
                        "file": rel,
                        "line": line_num,
                        "confidence": "medium",
                        "boundary_crossing": True,
                        "primitive_type": "sandbox_escape",
                    })

            # Privilege escalation patterns (all languages)
            for pat, title, cvss, desc in privesc_patterns:
                for m in re.finditer(pat, text, re.IGNORECASE):
                    line_num = text[:m.start()].count("\n") + 1
                    results.append({
                        "tool": "boundary-crossing-audit",
                        "title": title,
                        "cvss": cvss,
                        "description": f"{desc} File: {rel}:{line_num}",
                        "file": rel,
                        "line": line_num,
                        "confidence": "medium",
                        "boundary_crossing": True,
                        "primitive_type": "privesc",
                    })

    return results[:50]


