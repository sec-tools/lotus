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



def _run_complexity_hotspots(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Skill 37: Rank functions by cyclomatic complexity x taint density to prioritize review."""
    results = []
    
    # Language-specific function definition patterns
    func_pats = {
        'python': r'^\s*(?:async\s+)?def\s+(\w+)\s*\(',
        'node': r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\())',
        'ruby/rails': r'\s*def\s+(\w+)',
        'go': r'^func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(',
        'java': r'(?:public|private|protected|static)\s+\w+\s+(\w+)\s*\(',
        'php': r'(?:public|private|protected)?\s*(?:static\s+)?function\s+(\w+)\s*\(',
        'c/cpp': r'^\w[\w*\s]+\s+(\w+)\s*\([^)]*\)\s*\{',
    }
    branch_kws = ['if', 'else', 'elif', 'elsif', 'for', 'while', 'switch', 'case',
                  'catch', 'rescue', 'except', '&&', '||', '?', 'unless']
    
    lang_key = {'javascript': 'node', 'ruby': 'ruby/rails', 'typescript': 'node'}.get(language, language)
    func_pat = func_pats.get(lang_key)
    if not func_pat:
        return results
    
    SOURCES_KW = ['request', 'params', 'argv', 'getenv', 'stdin', 'recv', 'fgets', 'input', 'req.body', 'req.query']
    SINKS_KW = ['system', 'exec', 'eval', 'popen', 'strcpy', 'sprintf', 'malloc', 'open', 'query',
                'pickle', 'yaml.load', 'deserialize', 'render_template', 'innerHTML']
    
    _skip_dirs = {'.git', 'node_modules', 'vendor', '__pycache__', '.venv', 'test', 'tests', 'spec', 'fixtures', 'examples'}
    _ext_map = {'.py': 'python', '.js': 'node', '.ts': 'node', '.rb': 'ruby/rails',
                '.go': 'go', '.java': 'java', '.php': 'php', '.c': 'c/cpp', '.cpp': 'c/cpp', '.h': 'c/cpp'}
    
    hotspots = []
    for f in dest.rglob('*'):
        if not f.is_file() or _ext_map.get(f.suffix) != lang_key:
            continue
        parts = set(f.relative_to(dest).parts)
        if parts & _skip_dirs:
            continue
        try:
            text = f.read_text(errors='ignore')
        except Exception:
            continue
        lines = text.split('\n')
        for m in re.finditer(func_pat, text, re.MULTILINE):
            func_name = m.group(1) or (m.group(2) if m.lastindex >= 2 else 'unknown')
            start_line = text[:m.start()].count('\n')
            # Extract ~80 lines of function body
            func_body = '\n'.join(lines[start_line:start_line + 80])
            # Count branching complexity
            complexity = 1
            for kw in branch_kws:
                complexity += func_body.lower().count(kw)
            # Count taint density
            taint_score = 0
            for sk in SOURCES_KW:
                taint_score += func_body.lower().count(sk)
            for sk in SINKS_KW:
                taint_score += func_body.lower().count(sk) * 2
            
            hotspot_score = complexity * max(taint_score, 1)
            if hotspot_score >= 15:  # Only report significant hotspots
                hotspots.append((hotspot_score, func_name, str(f.relative_to(dest)), start_line + 1, complexity, taint_score))
    
    hotspots.sort(reverse=True)
    for score, fname, fpath, line, cmplx, taint in hotspots[:20]:
        results.append({
            'tool': 'complexity-hotspot',
            'title': f'High-complexity hotspot: {fname}() (score={score})',
            'cvss': min(5.0 + (score / 30), 8.5),
            'description': f'Function {fname}() at {fpath}:{line} has cyclomatic complexity {cmplx} and taint density {taint} (composite score {score}). High-complexity functions with taint density are prime candidates for logic bugs and missed validation.',
            'file': fpath,
            'line': line,
            'confidence': 'low',
        })
    return results


def _run_commit_security_analysis(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """T5/T8: Mine git commit history for security-relevant changes (silent fixes, reverted patches, CVE refs)."""
    results = []
    git_dir = dest / ".git"
    if not git_dir.exists():
        return results
    try:
        keywords = ['fix', 'vuln', 'cve', 'security', 'sanitize', 'escape', 'bypass',
                    'overflow', 'injection', 'auth', 'xss', 'sqli', 'rce', 'patch',
                    'buffer', 'heap', 'crash', 'dos', 'race', 'privesc']
        kw_pattern = '|'.join(keywords)
        proc = subprocess.run(
            ['git', 'log', '--all', '-n', '500', '--diff-filter=M',
             f'--grep={kw_pattern}', '-i', '--format=%H|%s|%an|%ad', '--date=short'],
            cwd=str(dest), capture_output=True, text=True, timeout=30
        )
        for line in proc.stdout.strip().split('\n')[:50]:
            if not line.strip() or '|' not in line:
                continue
            parts = line.split('|', 3)
            if len(parts) < 2:
                continue
            commit_hash, subject = parts[0][:12], parts[1]
            # Get files changed in this commit
            diff_proc = subprocess.run(
                ['git', 'diff-tree', '--no-commit-id', '--name-only', '-r', parts[0]],
                cwd=str(dest), capture_output=True, text=True, timeout=10
            )
            changed_files = [f for f in diff_proc.stdout.strip().split('\n') if f.strip()][:5]
            for cf in changed_files:
                results.append({
                    'tool': 'commit-security-analysis',
                    'title': f'Security-relevant commit: {subject[:80]}',
                    'cvss': 5.0,
                    'description': f'Commit {commit_hash} modifies {cf} with security-relevant message: "{subject}". This file may contain a silent fix or patched vulnerability that warrants re-audit for siblings/variants.',
                    'file': cf,
                    'line': 0,
                    'confidence': 'low',
                    'commit_hash': parts[0],
                })
                if len(results) >= 30:
                    break
            if len(results) >= 30:
                break
    except Exception:
        pass
    return results


def _run_deserialization_chain_audit(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Detect deserialization sinks and trace whether input reaches them.

    Targets: openmrs XStream/readObject, pecl-yaml php_var_unserialize,
    brew Marshal.load, jc yaml.load_all.
    """
    results: List[dict] = []
    _skip = {".git", "node_modules", "vendor", "__pycache__", ".venv", "target", "build", "dist"}

    # Language-specific deserialization patterns: (regex, title, cvss, desc, gadget_note)
    deser_patterns = {
        "java": [
            (r"ObjectInputStream\s*\(", "Java ObjectInputStream deserialization", 9.0,
             "ObjectInputStream.readObject() deserializes arbitrary Java objects. "
             "If input is attacker-controlled, gadget chains (CommonsCollections, Spring, XStream) enable RCE.",
             "Check for commons-collections, spring-beans, xstream in dependencies"),
            (r"XStream\s*\(\s*\)|xstream\.fromXML|xstream\.unmarshal", "XStream XML deserialization", 8.5,
             "XStream deserializes XML to Java objects. Without strict allowlists, "
             "attacker-supplied XML triggers arbitrary class instantiation.",
             "Check XStream version and security framework configuration"),
            (r"XMLDecoder\s*\(", "XMLDecoder bean deserialization", 9.0,
             "XMLDecoder instantiates arbitrary Java objects from XML. "
             "Any user-controlled XML input leads directly to RCE.",
             "No safe usage pattern - XMLDecoder should never process untrusted input"),
            (r"new\s+Yaml\(\)\.load\s*\(|yaml\.load\s*\(", "SnakeYAML unsafe load", 8.0,
             "SnakeYAML load() processes type tags (!!java.lang.ProcessBuilder). "
             "Use Yaml(new SafeConstructor()) or loadAs() instead.",
             "Check if SafeConstructor or LoaderOptions.setAllowedTypes() is used"),
            (r"@JsonTypeInfo\s*\(|enableDefaultTyping\s*\(|activateDefaultTyping\s*\(",
             "Jackson polymorphic deserialization", 8.0,
             "Jackson polymorphic type handling can instantiate arbitrary classes via @class or @type JSON fields.",
             "Check ObjectMapper configuration and deny-list effectiveness"),
            (r"GroovyShell|GroovyClassLoader|groovy\.util\.GroovyScriptEngine",
             "Groovy script deserialization/eval", 9.8,
             "GroovyShell.evaluate on plugin handle/JSON is RCE without a classic gadget chain.",
             "Lab: Runtime.getRuntime().exec(\"id\") via plugin script update"),
            (r"Hessian2Input|HessianProxyFactory|com\.caucho\.hessian",
             "Hessian2 deserialization", 8.8,
             "Hessian type tags instantiate attacker classes (Rome/CC gadget chains).",
             "Lab: Hessian payload + canary file/uid="),
        ],
        "python": [
            (r"pickle\.loads?\s*\(|cPickle\.loads?\s*\(", "Pickle deserialization", 9.0,
             "pickle.load/loads on untrusted data executes arbitrary Python code via __reduce__.",
             "No safe usage of pickle on untrusted input"),
            (r"yaml\.load\s*\([^)]*\)\s*(?!.*Loader\s*=\s*SafeLoader|.*Loader\s*=\s*yaml\.SafeLoader)",
             "YAML unsafe load", 8.0,
             "yaml.load() without SafeLoader processes !!python/object tags enabling code execution.",
             "Use yaml.safe_load() or yaml.load(data, Loader=SafeLoader)"),
            (r"marshal\.loads?\s*\(", "Marshal deserialization", 8.5,
             "marshal.load/loads on untrusted data can execute arbitrary code.",
             "Marshal is not designed for untrusted data"),
            (r"shelve\.open\s*\(", "Shelve deserialization", 7.5,
             "shelve uses pickle internally. Opening shelve files from untrusted sources enables code execution.",
             "Shelve files from untrusted sources should never be opened"),
        ],
        "ruby/rails": [
            (r"Marshal\.load\s*\(|Marshal\.restore\s*\(", "Ruby Marshal deserialization", 9.0,
             "Marshal.load on untrusted data enables arbitrary object instantiation and gadget chain RCE.",
             "Check for ActiveSupport, ERB, DRb gadget availability"),
            (r"YAML\.load\s*\([^)]*\)(?!.*safe|.*permitted)", "Ruby YAML.load (unsafe)", 8.5,
             "YAML.load processes !!ruby/object tags enabling gadget chain execution. Use YAML.safe_load.",
             "Check for Psych engine and available gadget chains"),
            (r"PSON\.parse\s*\(|JSON\.load\s*\([^)]*create_additions:\s*true", "Ruby PSON/JSON.create_additions", 8.8,
             "Puppet PSON historically instantiates Ruby classes from catalog JSON.",
             "Lab: json_class gadget; analog POST /catalog"),
            (r"ExecJS\.(eval|compile|exec)", "ExecJS SSR eval", 9.0,
             "Server-side JS eval of attacker-influenced props/bundle is Node RCE.",
             "Lab: child_process.execSync('id') via prerender analog"),
        ],
        "php": [
            (r"unserialize\s*\(", "PHP unserialize", 8.5,
             "unserialize() on untrusted data triggers __wakeup/__destruct gadget chains for RCE.",
             "Check for Monolog, Laravel, Guzzle, SwiftMailer gadget classes"),
            (r"php_var_unserialize|PHP_VAR_UNSERIALIZE", "PHP C extension unserialize", 9.0,
             "C-level php_var_unserialize() in PHP extension deserializes PHP objects from raw input.",
             "Critical in pecl-yaml: !php/object tag triggers this when yaml.decode_php=1"),
        ],
        "c/cpp": [
            (r"php_var_unserialize\s*\(", "PHP extension object deserialization", 9.0,
             "C-level deserialization of PHP objects. When reachable from user input (e.g. YAML tags), "
             "enables arbitrary PHP object instantiation and gadget chain RCE.",
             "Check yaml.decode_php ini setting and whether tag is user-controlled"),
        ],
        "node": [
            (r"node-serialize|serialize\.unserialize|funcster", "Node.js unsafe deserialization", 9.0,
             "node-serialize and funcster unserialize execute JavaScript functions embedded in serialized data.",
             "Any untrusted input to unserialize() is RCE"),
        ],
        "go": [
            (r"proto\.Unmarshal\s*\(", "Go protobuf unmarshal of untrusted bytes", 7.5,
             "proto.Unmarshal of Redis/network bytes into task/message structs. Not Java gadget RCE; "
             "pair with queue handler dispatch (asynq type string) or gob of HTTP body.",
             "Lab: enqueue attacker task type the worker handles; oracle is handler side-effect"),
            (r"gob\.NewDecoder\s*\([^)]*Body|gob\.NewDecoder\s*\(", "Go gob decode of network body", 8.1,
             "encoding/gob of HTTP bodies (keploy /agent/storemocks) is an unauthenticated deser sink "
             "when the agent binds without auth.",
             "Lab: POST gob stream without credentials; must not be 401"),
            (r"json\.Unmarshal\s*\([^,]+,\s*&?map\[string\]interface\{\}", "Go json into interface{} map", 6.5,
             "Untyped JSON can later hit eval/exec. Trace to sinks.",
             "LATENT unless a sink is proven"),
            (r"plugin\.Open\s*\(", "Go plugin.Open of untrusted path", 8.4,
             "plugin.Open loads a shared object. If the path is config/HTTP-sourced this is RCE.",
             "Lab: drop a sentinel .so and call the exported symbol"),
            (r"yaml\.Unmarshal\s*\(", "Go yaml.Unmarshal of network/config bytes", 7.2,
             "gopkg.in/yaml Unmarshal of untrusted bytes into interface{} can later dispatch plugins.",
             "Trace to plugin.Open / exec.Command"),
        ],
        "rust": [
            (r"serde_json::from_str\s*\(|from_slice\s*\(", "Rust serde JSON decode", 6.0,
             "serde of untrusted JSON is memory-safe but logic/authz bugs live in handlers that skip auth.",
             "Pair with default-allow HTTP; do not report serde itself as RCE"),
        ],
    }

    lang_key = language.lower().replace(" ", "")
    patterns = deser_patterns.get(lang_key, [])
    # Always include generic patterns
    if lang_key not in deser_patterns:
        for lang_patterns in deser_patterns.values():
            patterns.extend(lang_patterns)

    exts = {
        "java": (".java",), "python": (".py",), "ruby/rails": (".rb",),
        "php": (".php",), "c/cpp": (".c", ".h", ".cpp"),         "node": (".js", ".ts"),
        "go": (".go",),
        "rust": (".rs",),
    }
    valid_exts = exts.get(lang_key, (".py", ".rb", ".js", ".java", ".php", ".c", ".h", ".ts", ".go", ".rs"))

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
            for pat, title, cvss, desc, gadget_note in patterns:
                for m in re.finditer(pat, text):
                    line_num = text[:m.start()].count("\n") + 1
                    results.append({
                        "tool": "deserialization-chain",
                        "title": title,
                        "cvss": cvss,
                        "description": f"{desc} Gadget: {gadget_note}. File: {rel}:{line_num}",
                        "file": rel,
                        "line": line_num,
                        "confidence": "high",
                        "primitive_type": "X-5",  # Deserialization RCE primitive
                    })

    return results[:50]


def _run_sql_concat_audit(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Detect string concatenation in SQL/HQL/JPQL query construction.

    Targets: openmrs ConvertOrderersToProviders.java SQL concat,
    InitializationFilter HQL patterns.
    """
    results: List[dict] = []
    _skip = {".git", "node_modules", "vendor", "__pycache__", ".venv", "target", "build", "dist"}

    sql_concat_patterns = {
        "java": [
            (r'(?:execute|executeQuery|executeUpdate|prepareStatement|createQuery|createSQLQuery|createNativeQuery)'
             r'\s*\([^)]*\+',
             "SQL query with string concatenation", 8.0,
             "SQL/HQL/JPQL query constructed via string concatenation. "
             "If any concatenated value comes from user input, this enables SQL injection."),
            (r'(?:String\s+(?:sql|query|hql|jpql)\s*=\s*"[^"]*"\s*\+)',
             "SQL string variable built with concatenation", 7.5,
             "SQL query string built via concatenation before execution."),
            (r'statement\.execute\s*\([^)]*\+', "JDBC statement.execute with concatenation", 8.0,
             "JDBC statement executed with concatenated string input."),
        ],
        "python": [
            (r'(?:execute|executemany)\s*\(\s*(?:f"|f\'|"[^"]*"\s*%|\'[^\']*\'\s*%|"[^"]*"\s*\.format)',
             "SQL with f-string/format/percent", 8.0,
             "SQL query built with f-string, .format(), or % formatting instead of parameterized query."),
            (r'cursor\.execute\s*\([^)]*\+', "SQL with string concatenation", 7.5,
             "SQL query built via string concatenation."),
        ],
        "ruby/rails": [
            (r'(?:where|find_by_sql|execute|select_all)\s*\([^)]*#\{',
             "SQL with Ruby string interpolation", 7.5,
             "SQL query built with Ruby string interpolation (#{}). Use parameterized queries."),
        ],
        "node": [
            (r'(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|"[^"]*"\s*\+|\'[^\']*\'\s*\+)',
             "SQL with template literal/concatenation", 7.5,
             "SQL query built with template literal or string concatenation."),
        ],
        "php": [
            (r'(?:mysql_query|mysqli_query|pg_query|->query)\s*\([^)]*\$',
             "SQL with PHP variable interpolation", 7.5,
             "SQL query built with PHP variable interpolation."),
        ],
    }

    lang_key = language.lower().replace(" ", "")
    patterns = sql_concat_patterns.get(lang_key, [])
    exts = {
        "java": (".java",), "python": (".py",), "ruby/rails": (".rb",),
        "php": (".php",), "node": (".js", ".ts"),
    }
    valid_exts = exts.get(lang_key, (".py", ".rb", ".js", ".java", ".php", ".ts"))

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
            for pat, title, cvss, desc in patterns:
                for m in re.finditer(pat, text):
                    line_num = text[:m.start()].count("\n") + 1
                    results.append({
                        "tool": "sql-concat-audit",
                        "title": title,
                        "cvss": cvss,
                        "description": f"{desc} File: {rel}:{line_num}",
                        "file": rel,
                        "line": line_num,
                        "confidence": "medium",
                        "primitive_type": "R-2",  # SQL injection read primitive
                    })

    return results[:40]


def _run_by_design_gate(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Read repo documentation to identify by-design capabilities.

    Returns findings tagged with by_design=True for product capabilities
    that should NOT be reported as vulnerabilities.

    Targets: sandbox /v1/bash/exec, brew formula install, jc subprocess.Popen.
    """
    results: List[dict] = []

    # Read documentation files for security model understanding
    doc_files = ["README.md", "SECURITY.md", "CONTRIBUTING.md", "docs/README.md",
                 "doc/README.md", "README.rst", "README.txt"]
    doc_content = ""
    for df in doc_files:
        try:
            doc_content += (dest / df).read_text(errors="ignore")[:5000] + "\n"
        except Exception:
            continue

    if not doc_content:
        return results

    doc_lower = doc_content.lower()

    # Pattern: repo is a code execution platform / sandbox
    execution_platform_signals = [
        "execute code", "run code", "code execution", "sandbox",
        "execute commands", "shell execution", "eval endpoint",
        "run scripts", "execute scripts", "command execution api",
    ]
    is_execution_platform = sum(1 for s in execution_platform_signals if s in doc_lower) >= 2

    # Pattern: repo is a package manager
    package_manager_signals = [
        "package manager", "install packages", "brew install",
        "formula", "cask", "tap ", "package installer",
        "dependency manager", "gem install", "pip install", "npm install",
    ]
    is_package_manager = sum(1 for s in package_manager_signals if s in doc_lower) >= 2

    # Pattern: repo is a CLI tool that processes external data
    cli_parser_signals = [
        "parse", "parser", "convert", "transform",
        "cli tool", "command-line", "command line tool",
        "process output", "structured data",
    ]
    is_cli_parser = sum(1 for s in cli_parser_signals if s in doc_lower) >= 2

    if is_execution_platform:
        results.append({
            "tool": "by-design-gate",
            "title": "Execution platform - code execution is by-design capability",
            "cvss": 0.0,
            "description": (
                "This repository is documented as a code execution platform/sandbox. "
                "Code execution endpoints are intentional product capabilities, not vulnerabilities. "
                "Focus auditing on: auth bypass (executing without valid credentials), "
                "sandbox escape (breaking out of isolation), and privilege escalation."
            ),
            "file": "README.md",
            "line": 0,
            "confidence": "high",
            "by_design": True,
            "primitive_type": "sandbox_capability",
            "qualification": "BY-DESIGN",
        })

    if is_package_manager:
        results.append({
            "tool": "by-design-gate",
            "title": "Package manager - system/exec calls are by-design for install",
            "cvss": 0.0,
            "description": (
                "This repository is a package manager. Calls to system(), exec(), "
                "and subprocess are intentional for package installation. "
                "Focus auditing on: formula/recipe command injection from untrusted sources, "
                "dependency confusion, and trust model bypasses."
            ),
            "file": "README.md",
            "line": 0,
            "confidence": "high",
            "by_design": True,
            "primitive_type": "package_manager_trust_boundary",
            "qualification": "BY-DESIGN",
        })

    if is_cli_parser:
        results.append({
            "tool": "by-design-gate",
            "title": "CLI parser - processing external input is by-design",
            "cvss": 0.0,
            "description": (
                "This repository is a CLI parsing tool. Processing untrusted command output "
                "is its documented purpose. Focus auditing on: code execution from crafted input "
                "(not just parsing it), plugin loading from untrusted paths, and YAML/pickle deserialization."
            ),
            "file": "README.md",
            "line": 0,
            "confidence": "high",
            "by_design": True,
            "primitive_type": "intended_behavior",
            "qualification": "BY-DESIGN",
        })

    return results


def _run_doc_driven_hypothesis(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Parse documentation for falsifiable security claims to test as hypotheses.

    Extracts assertions like 'all input is sanitized', 'authentication required for all endpoints'
    and generates test leads to disprove them.
    """
    results: List[dict] = []

    doc_files = ["README.md", "SECURITY.md", "CONTRIBUTING.md", "docs/security.md",
                 "docs/README.md", "API.md", "docs/api.md"]
    doc_content = ""
    for df in doc_files:
        try:
            doc_content += f"\n--- {df} ---\n" + (dest / df).read_text(errors="ignore")[:8000]
        except Exception:
            continue

    if len(doc_content.strip()) < 50:
        return results

    # Extract falsifiable security claims
    claim_patterns = [
        (r"(?:all|every)\s+(?:input|data|parameter)s?\s+(?:is|are)\s+(?:sanitized|validated|escaped)",
         "All inputs claimed sanitized", 7.0,
         "Documentation claims all inputs are sanitized. Test: find any input path that reaches a sink without sanitization."),
        (r"(?:authentication|auth)\s+(?:is\s+)?required\s+(?:for\s+)?(?:all|every)\s+(?:endpoint|route|api|request)",
         "Auth required for all endpoints", 7.5,
         "Documentation claims auth is required everywhere. Test: enumerate all routes and check for unauthenticated access."),
        (r"(?:sql\s+injection|sqli)\s+(?:is\s+)?(?:prevented|mitigated|impossible)",
         "SQL injection claimed prevented", 7.5,
         "Documentation claims SQL injection is prevented. Test: search for string concatenation in query construction."),
        (r"(?:sandbox|isolation|containeriz)\w*\s+(?:prevent|ensure|guarantee)",
         "Sandbox isolation claimed", 8.0,
         "Documentation claims sandbox isolation. Test: check for escape vectors, shared resources, and privilege escalation."),
        (r"(?:secrets?|credentials?|tokens?|api.?keys?)\s+(?:are\s+)?(?:never|not)\s+(?:stored|logged|exposed)",
         "Secrets claimed never exposed", 6.5,
         "Documentation claims secrets are never exposed. Test: grep for hardcoded secrets, check logging, check error responses."),
    ]

    for pat, title, cvss, desc in claim_patterns:
        if re.search(pat, doc_content, re.IGNORECASE):
            results.append({
                "tool": "doc-driven-hypothesis",
                "title": f"Hypothesis: {title}",
                "cvss": cvss,
                "description": desc,
                "file": "SECURITY.md",
                "line": 0,
                "confidence": "low",
                "hypothesis": True,
            })

    return results[:20]


