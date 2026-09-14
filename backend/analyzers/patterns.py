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



def run_grep_patterns(dest: Path, repo_id: int, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    ruby_patterns = [
        (r"\beval\s*\(", "Dynamic code execution (eval)", 8.5, "eval() with untrusted input."),
        (r"\binstance_eval\s*\(", "Dynamic code execution (instance_eval)", 8.5, "instance_eval with untrusted input."),
        (r"\bclass_eval\s*\(", "Dynamic code execution (class_eval)", 8.5, "class_eval with untrusted input."),
        (r"\bmodule_eval\s*\(", "Dynamic code execution (module_eval)", 9.0, "module_eval with untrusted content (e.g. Formulary.load_formula)."),
        (r"\bpublic_send\s*\(", "Dynamic dispatch (public_send)", 6.5, "public_send with user-controlled input."),
        (r"\bsend\s*\(\s*:?", "Dynamic dispatch (send)", 6.5, "send() with user-controlled input."),
        (r"%x\{", "Shell execution (%x{} / backtick)", 8.5, "Ruby %x{} or backtick executes shell commands."),
        (r"\bOpen3\.(popen3|capture3|pipeline|popen2e?)\s*\(", "Command execution (Open3)", 8.0, "Open3 may execute attacker-controlled commands."),
        (r"\bIO\.popen\s*\(", "Command execution (IO.popen)", 8.5, "IO.popen with potential user input."),
        (r"\bKernel\.system\s*\(", "Command execution (Kernel.system)", 9.0, "Kernel.system with potential user input."),
        (r"\bProcess\.spawn\s*\(", "Command execution (Process.spawn)", 8.5, "Process.spawn with potential user input."),
        (r"\bPTY\.spawn\s*\(", "Command execution (PTY.spawn)", 8.5, "PTY.spawn with potential user input."),
        (r"\bshell_out[!_a-z]*\s*\([^,)]*#\{", "Shell command interpolation (shell_out)", 8.8, "shell_out with string interpolation allows command injection."),
        (r"\bpowershell_out[!_a-z]*\s*\([^,)]*#\{", "PowerShell command interpolation (powershell_out)", 8.8, "powershell_out with string interpolation allows command injection."),
        (r"\bpowershell_exec[!_a-z]*\s*\([^)]*#\{", "PowerShell script injection (powershell_exec)", 8.8, "powershell_exec with interpolated script blocks allows arbitrary execution."),
        (r"\bMixlib::ShellOut\.new\s*\([^,)]*#\{", "ShellOut command construction (Mixlib::ShellOut)", 8.8, "Mixlib::ShellOut with string interpolation executes via subshell."),
        (r"\b(URI|Kernel)\.open\s*\(\s*['\"]\|", "Kernel/URI open command execution pipe", 9.0, "open() with leading pipe executes arbitrary commands in Ruby."),
        (r"\bparams\s*\[", "User-controlled parameter usage", 5.5, "params[] read; check for mass assignment or injection sinks."),
        (r"\bcookies\s*\[", "Cookie value usage", 5.0, "Cookie value read without validation."),
        (r"\bsession\s*\[", "Session value usage", 5.0, "Session value read; check for unsafe usage."),
        (r"\brender\s+inline:", "Inline render with ERB", 7.5, "render inline may allow code execution if content controlled."),
        (r"\b(raw|html_safe)\b", "Unescaped output", 6.5, "Unescaped output; check for XSS."),
        (r"\bpermit!\b", "Mass assignment (permit!)", 7.0, "Strong params bypass via permit!."),
        (r"\b(File|IO|Kernel)\.open\s*\([^)]*(params|cookies|session|node|attributes)", "File open with user input", 7.5, "File path may be user-controlled."),
        (r"[`\\$]\([^)]*(params|cookies|session|node|attributes)", "Shell command with user input", 9.0, "Shell interpolation with user-controlled input."),
        (r"\bpassword\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password", 7.0, "Possible hardcoded password."),
        (r"\bsecret[_-]?key\s*=", "Hardcoded secret key", 7.5, "Possible hardcoded secret/KEY."),
        (r"\b(api[_-]?key|apikey)\s*=", "Hardcoded API key", 7.0, "Possible API key in source."),
        (r"\bMarshal\.(load|restore)\s*\(", "Unsafe deserialization (Marshal)", 9.0, "Marshal.load/restore with untrusted data allows arbitrary object instantiation and RCE."),
        (r"\bYAML\.load\s*\(", "Unsafe deserialization (YAML.load)", 8.5, "YAML.load with untrusted data allows Psych object instantiation."),
        (r"\bPSON\.parse\s*\(", "PSON catalog parse (Puppet object instantiation)", 8.8, "PSON.parse historically instantiates Ruby classes from catalog JSON."),
        (r"Puppet::Util::Execution\.execute|Puppet::Util::Execution\.execute", "Puppet Execution.execute command sink", 9.0, "Agent exec resource interpolating catalog params is RCE."),
        (r"\bExecJS\.(eval|compile|exec)\b", "ExecJS server-side JS eval", 9.0, "SSR eval of JS; attacker-influenced props/bundle path is Node RCE."),
        (r"allow\s+['\"]\*['\"]", "auth.conf allow * (unauthenticated REST)", 8.6, "Puppet REST allow '*' is pre-auth catalog/facts access."),
        (r"\bPsych\.(unsafe_load|load)\s*\(", "Unsafe YAML deserialization (Psych)", 8.5, "Psych.unsafe_load processes !!ruby/object tags enabling gadget execution."),
        (r"\bJSON\.load\s*\([^)]*create_additions:\s*true", "Unsafe JSON deserialization (JSON.load additions)", 8.0, "JSON.load with create_additions allows arbitrary Ruby object instantiation."),
        (r"\bChef::JSONCompat\.from_json\s*\(", "Chef JSON parsing (Chef::JSONCompat)", 6.5, "Chef::JSONCompat from_json deserialization point."),
        (r"\bdeserialize\b", "Deserialization call", 7.0, "Potential unsafe deserialization."),
        (r"\bconstantize\b", "User-controlled constantization", 7.0, "constantize() with user input can load arbitrary classes."),
        (r"\bconst_get\s*\([^)]*(params|node|attributes|payload|type)", "Dynamic class constant resolution (const_get)", 7.5, "const_get with external input allows arbitrary class instantiation."),
        # TOCTOU / symlink patterns
        (r"File\.exist\?\s*\(.*\).*\n.*File\.(open|read|write|delete)", "TOCTOU file race", 6.5, "File existence check then operation - race window."),
        (r"\bsymlink\?\s*\(", "Symlink check (potential TOCTOU)", 5.5, "Symlink detection may indicate TOCTOU or symlink-following concern."),
        (r"\bFile\.readlink\s*\(", "Readlink (symlink resolution)", 5.0, "Symlink resolution; check for symlink-following attacks."),
        (r"\bmake_relative_symlink\b", "Symlink creation during install", 6.0, "Symlink creation; attacker-controlled prefix may redirect."),
        (r"/\^[^$]*\$/", "Ruby regex without \\A\\z anchors (multiline bypass)", 7.5, "Ruby ^/$ are multiline by default; use \\A/\\z for string boundaries."),
        (r"\.startsWith\s*\(|\.start_with\?\s*\(", "Prefix match (potential bypass)", 7.0, "startsWith/start_with? allows longer strings to match."),
        (r"FileUtils\.(chmod|chmod_R)\s*\(\s*0?777", "Insecure file permissions (0777)", 7.0, "FileUtils chmod 0777 grants world-writable permissions."),
        # PDF / Document & IaC Stream Patterns
        (r"\bPDF::Reader\b", "PDF Reader object instantiation", 6.0, "PDF::Reader entrypoint - verify stream and object boundary handling."),
        (r"\b(Zlib::Inflate|Zlib::Deflate)\.(inflate|deflate)\s*\(", "Decompression operation (decompression bomb risk)", 7.5, "Unbounded decompression of untrusted streams can lead to memory exhaustion."),
        (r"\b(LZW|Flate|ASCIIHex|ASCII85|RunLength)Decode\b", "PDF stream filter decoder", 7.0, "Custom stream decoder - check bounds and recursion limits."),
        (r"\barchive_file\b", "Chef archive_file resource (Zip-Slip risk)", 8.0, "archive_file extracting untrusted archives may allow directory traversal."),
    ]

    python_patterns = [
        (r"\beval\s*\(", "Dynamic code execution (eval)", 8.5, "eval() with untrusted input."),
        (r"\bexec\s*\(", "Dynamic code execution (exec)", 8.5, "exec() with untrusted input."),
        (r"\bos\.system\s*\(", "OS command injection via os.system", 9.0, "User input reaches os.system() call."),
        (r"\bos\.popen\s*\(", "OS command injection via os.popen", 9.0, "User input reaches os.popen() call."),
        (r"\bsubprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True", "Subprocess shell injection", 8.8, "subprocess with shell=True."),
        (r"\bsubprocess\.Popen\s*\(", "Subprocess execution (Popen)", 7.5, "subprocess.Popen; check if argv is attacker-influenced."),
        (r"\bast\.literal_eval\s*\(", "ast.literal_eval with untrusted input", 7.0, "ast.literal_eval on attacker-mangled data may cause DoS or unexpected values."),
        (r"\bplistlib\.loads?\s*\(", "Plist deserialization", 7.0, "plistlib.load with untrusted binary data."),
        (r"\bimportlib\.import_module\s*\(", "Dynamic module import", 8.0, "importlib.import_module with potentially attacker-controlled module path."),
        (r"\burllib\.request\.urlopen\s*\(", "URL fetch (SSRF risk)", 7.5, "urlopen with potentially attacker-controlled URL."),
        (r"\b(httpx|requests)\.(get|post|put|delete|request)\s*\([^)]*(url|uri|endpoint|target)", "HTTP client request (SSRF risk)", 7.5, "HTTP request with user-controlled URL/endpoint."),
        (r"\bpickle\.loads?\s*\(", "Unsafe deserialization (pickle)", 9.0, "pickle.load with untrusted data can execute arbitrary code."),
        (r"\b(cloudpickle|dill)\.loads?\s*\(", "Unsafe deserialization (cloudpickle/dill)", 9.0, "cloudpickle or dill loads with untrusted data executes arbitrary bytecode."),
        (r"\bjoblib\.load\s*\(", "Unsafe ML model deserialization (joblib)", 8.5, "joblib.load with untrusted data deserializes arbitrary Python objects."),
        (r"\btorch\.load\s*\(", "PyTorch model deserialization (torch.load)", 8.5, "torch.load without weights_only=True executes arbitrary code via pickle."),
        (r"\byaml\.load\s*\([^)]*Loader\s*=\s*yaml\.FullLoader", "YAML FullLoader deserialization", 8.0, "yaml.load with FullLoader processes Python object tags."),
        (r"\byaml\.load\s*\(", "Unsafe deserialization (yaml.load)", 7.5, "yaml.load without SafeLoader can execute code."),
        (r"x-headroom-base-url|x-headroom-user-id", "AI-proxy caller-supplied upstream/identity header", 8.8, "Client sets upstream URL (SSRF) or spoofs user id."),
        (r"pre_hook|post_hook|deploy_hook|renew_hook", "Privileged ACME/CLI hook execution", 8.9, "Root deploy/pre/post hooks via subprocess are RCE if writable."),
        (r"\btarfile\.extract(?:all)?\s*\(", "tarfile.extractall without data filter", 7.9, "Path traversal/overwrite from a model/bundle tarball."),
        (r"has_message_access|access_message|access_stream_by_id", "Django object-access helper (check siblings)", 8.0, "Canonical helper exists; sibling views that skip it are IDOR."),
        (r"\byaml\.load_all\s*\(", "Unsafe deserialization (yaml.load_all)", 7.5, "yaml.load_all without SafeLoader can execute code."),
        # MLOps & Distributed Pipeline Patterns
        (r"\b(mlrun|nuclio)\.new_function\s*\(", "MLOps dynamic function instantiation", 8.0, "Dynamic creation of execution functions from spec/code origin."),
        (r"\b(FastAPI|APIRouter)\s*\(", "FastAPI endpoint definitions", 5.0, "FastAPI router definition - check route authorization dependencies."),
        (r"\bmlrun\.api\.api\.endpoints\b", "MLRun API endpoint module", 6.5, "MLRun API endpoint - check for pre-auth reachability."),
        (r"\b__import__\s*\(", "Dynamic import", 6.5, "__import__ with user-controlled input."),
        (r"\bgetattr\s*\(", "Dynamic attribute access", 5.5, "getattr with user input may reach dangerous attributes."),
        (r"\brequest\.(args|form|data|json|values|files)\[", "User input read", 5.0, "Flask/Django user input read."),
        (r"\bSELECT\b.*%s|\bSELECT\b.*\.format\(", "SQL injection (heuristic)", 8.9, "String formatting in SQL query."),
        (r"\bpassword\s*=\s*['\"][^'\"]+['\"]", "Hardcoded credential", 7.2, "Possible hardcoded password."),
        (r"\bBEGIN\s+(RSA\s+)?PRIVATE\s+KEY", "Private key in source", 8.5, "Possible private key material."),
        (r"\bopen\s*\([^)]*(request\.|params|options|spec|file_name|path)", "File open with user input", 7.5, "File path from user input."),
        (r"\brender_template_string\s*\(", "SSTI (Jinja2)", 8.0, "render_template_string with user data."),
        (r"\bxmltodict\.parse\s*\(", "XML parsing (XXE/entity risk)", 7.0, "xmltodict.parse without entity hardening."),
        # TOCTOU / path traversal in file ops
        (r"\bos\.path\.exists\s*\([^)]*\).*\n.*\bopen\s*\(", "TOCTOU file race", 6.5, "Existence check then open - race window."),
        (r"\bshutil\.(copy|move|rmtree)\s*\(", "File operation (check path source)", 5.5, "shutil file op; check if path is attacker-controlled."),
        (r"\.startswith\s*\(", "Prefix match (potential bypass)", 7.0, "str.startswith() allows prefix match bypasses."),
        (r"==\s*['\"]0e", "Potential weak hash comparison", 6.5, "Loose comparison with '0e' prefixed hash."),
        # sys.path manipulation - module hijack / import confusion
        (r"\bsys\.path\s*=\s*\[", "sys.path modification (module hijack risk)", 7.5, "Direct sys.path reassignment can shadow stdlib modules."),
        (r"\bsys\.path\.append\s*\(", "sys.path extension (import injection risk)", 7.0, "sys.path.append with user-controllable directory enables module injection."),
        (r"\bsys\.path\.insert\s*\(", "sys.path insertion (import injection risk)", 7.0, "sys.path.insert with user-controllable directory enables module injection."),
        # Unsafe temp file patterns - TOCTOU / predictable paths
        (r"NamedTemporaryFile\s*\([^)]*delete\s*=\s*False", "Unsafe temp file (delete=False TOCTOU)", 7.0, "NamedTemporaryFile with delete=False creates persistent predictable path; TOCTOU if re-opened."),
        (r"\btempfile\.mk(s?temp|dtemp)\s*\(", "Predictable temp file (mktemp/mkstemp)", 6.5, "mktemp creates predictable paths; prefer TemporaryDirectory or NamedTemporaryFile."),
        # Plugin/module loading from user-controllable paths
        (r"appdirs\.|user_data_dir\(|user_config_dir\(", "User data dir used for code loading", 7.5, "User-controllable data directory used in code loading path - module injection."),
        # Dependency version floor allowing known-vulnerable versions
        (r">=\s*0\.\d+\.\d+", "Loose dependency floor (potential known-vuln versions)", 5.0, "Minimum version floor may allow installation of versions with known vulnerabilities."),
    ]

    node_patterns = [
        (r"\beval\s*\(", "Dynamic code execution (eval)", 8.5, "eval() with untrusted input."),
        (r"\bFunction\s*\(", "Dynamic Function constructor", 8.0, "new Function() from user input."),
        (r"\bchild_process\.exec\s*\(", "OS command injection", 9.0, "child_process.exec with user input."),
        (r"\brequire\s*\([^)]*req\.", "Dynamic require with user input", 7.5, "require() path from user input."),
        (r"\breq\.(body|params|query|headers)\[", "User input read", 5.0, "Express user input access."),
        (r"\bfs\.(readFile|writeFile|unlink)\s*\([^)]*req\.", "File operation with user input", 7.5, "fs call with user-controlled path."),
        (r"\b(innerHTML|outerHTML)\s*=", "DOM XSS sink", 6.5, "innerHTML assignment."),
        (r"\bdocument\.write\s*\(", "DOM XSS via document.write", 6.5, "document.write with dynamic content."),
        (r"\bdeserialize\s*\(", "Deserialization call", 7.0, "Potential unsafe deserialization."),
        (r"\bpassword\s*=\s*['\"][^'\"]+['\"]", "Hardcoded credential", 7.2, "Possible hardcoded password."),
        (r"\bBEGIN\s+(RSA\s+)?PRIVATE\s+KEY", "Private key in source", 8.5, "Possible private key material."),
        (r"===?\s*['\"]0e", "Potential weak hash comparison", 6.5, "Loose comparison with '0e' prefixed hash."),
        (r"\.startsWith\s*\(", "Prefix match (potential bypass)", 7.0, "startsWith allows longer strings to match prefix guard."),
        (r"==\s", "Loose equality (type coercion)", 5.5, "== allows type coercion; use === for security comparisons."),
    ]
    java_patterns = [
        (r"Runtime\.getRuntime\(\)\.exec\s*\(", "OS command injection", 9.0, "Runtime.exec with user input."),
        (r"ProcessBuilder\s*\(", "OS command injection (ProcessBuilder)", 8.5, "ProcessBuilder with user input."),
        (r"ObjectInputStream", "Unsafe deserialization", 8.5, "Java deserialization; gadget chain risk."),
        (r"\bXMLInputFactory|SAXParser|DocumentBuilder", "XML parsing (XXE risk)", 7.5, "XML parser without disabling external entities."),
        (r"\bStatement\s*\.\s*execute(Query|Update)?\s*\(", "SQL injection (Statement)", 8.9, "Statement.execute with string concat."),
        (r"\+\s*request\.getParameter\s*\(", "Parameter concat (injection)", 7.5, "String concat with request parameter."),
        (r"\bClass\.forName\s*\(", "Dynamic class loading", 7.0, "Class.forName from user input."),
        (r"\bBEGIN\s+(RSA\s+)?PRIVATE\s+KEY", "Private key in source", 8.5, "Possible private key material."),
        (r"\bpassword\s*=\s*\"", "Hardcoded credential", 7.2, "Possible hardcoded password."),
        # HQL/JPQL injection - common in Hibernate apps like OpenMRS
        (r"createQuery\s*\([^)]*\+", "HQL injection (string concat in createQuery)", 8.5, "HQL/JPQL query built with string concatenation - injection risk."),
        (r"createSQLQuery\s*\([^)]*\+", "Native SQL injection (createSQLQuery + concat)", 9.0, "Native SQL query with string concatenation - direct injection."),
        # Manual parameterization (pseudo-prepared statements) - often insufficient
        (r"replaceFirst\s*\(\s*\"\\\\\\?\"\s*,", "Manual SQL parameterization (SQLi risk)", 8.5, "replaceFirst('?', arg) is not real parameterization - all metacharacters pass through."),
        (r"\.replace\s*\(\s*\";\"\s*,", "Semicolon-only SQL sanitization", 9.0, "Only stripping semicolons from SQL input - insufficient; quotes/comments/UNION pass through."),
        (r"createStatement\s*\(\s*\)\s*;?\s*\n?\s*.*execute", "Statement.executeUpdate without PreparedStatement", 7.5, "Raw Statement instead of PreparedStatement - parameterization missing."),
        # Second-order SQL injection - values from DB used in new queries
        (r"\"select\s.*where\s.*=\s*'\"\s*\+", "String concat in SQL WHERE (second-order SQLi)", 8.5, "Database-stored value concatenated into SQL - second-order injection."),
        (r"\"update\s.*set\s.*=\s*'\"\s*\+", "String concat in SQL UPDATE (second-order SQLi)", 8.5, "Database value in SQL UPDATE - second-order injection."),
        # XStream deserialization whitelist manipulation
        (r"allowTypesByWildcard|allowTypeHierarchy\s*\(", "XStream whitelist modification (deser RCE)", 8.5, "XStream type whitelist expanded - gadget chain classes may be allowed."),
        (r"GlobalPropert.*serializer|whitelist.*types|serializer.*whitelist", "Configurable deserialization whitelist", 7.5, "Deserialization whitelist loaded from config - admin can expand to enable RCE."),
        (r"createCriteria\s*\(", "Hibernate Criteria API (check dynamic params)", 5.0, "Criteria API usage; verify no user input in restrictions."),
        # Spring-specific auth patterns
        (r"@RequestMapping.*method\s*=", "Spring endpoint (check @Authorized)", 5.0, "Spring endpoint; verify auth annotation present."),
        (r"permitAll\(\)|anonymous\(\)", "Spring Security permitAll/anonymous", 6.5, "Endpoint explicitly allows unauthenticated access."),
        (r"@PreAuthorize|@Secured|@RolesAllowed|@Authorized", "Auth annotation (verify coverage)", 4.0, "Auth annotation present; verify all endpoints covered."),
        # Expression Language injection
        (r"SpelExpressionParser|ExpressionParser", "Spring EL (SpEL injection risk)", 8.5, "SpEL parser with potential user input - RCE via expression injection."),

        (r"\bScriptEngine\b|\beval\s*\(", "Script engine / eval", 8.5, "Script execution with potential user input."),
        (r"GroovyShell|GroovyClassLoader|groovy\.lang\.GroovyShell", "Groovy script engine (plugin RCE)", 9.8, "GroovyShell on plugin/selector input is admin-write RCE."),
        (r"HessianProxyFactory|Hessian2Input|com\.caucho\.hessian", "Hessian deserialization", 8.8, "Hessian gadget chains if the payload type is untrusted."),
        (r"ParserConfig\.getGlobalInstance|autoTypeSupport|Feature\.SupportAutoType", "Fastjson autoType", 9.4, "Fastjson autoType gadget RCE."),
        # LDAP injection (common in healthcare)
        (r"LdapTemplate|ldapSearch|SearchFilter", "LDAP operations (injection risk)", 7.0, "LDAP query with potential user input."),
    ]
    php_patterns = [
        (r"\beval\s*\(", "Dynamic code execution (eval)", 8.5, "eval() with untrusted input."),
        (r"\bexec\s*\(", "OS command execution", 9.0, "exec() with user input."),
        (r"\bsystem\s*\(", "OS command execution (system)", 9.0, "system() with user input."),
        (r"\bshell_exec\s*\(", "OS command execution (shell_exec)", 9.0, "shell_exec() with user input."),
        (r"\bpassthru\s*\(", "OS command execution (passthru)", 9.0, "passthru() with user input."),
        (r"\bunserialize\s*\(", "Unsafe deserialization", 8.5, "unserialize with untrusted data."),
        (r"\b\$_(GET|POST|REQUEST|COOKIE)\[", "User input read", 5.0, "Superglobal user input access."),
        (r"\binclude\s*\(\s*\$", "Local file inclusion", 8.0, "include with variable path."),
        (r"\brequire\s*\(\s*\$", "Local file inclusion", 8.0, "require with variable path."),
        (r"\bpassword\s*=\s*['\"][^'\"]+['\"]", "Hardcoded credential", 7.2, "Possible hardcoded password."),
        (r"\bmysql_query\s*\(", "SQL injection (deprecated API)", 8.9, "mysql_query is deprecated and lacks parameterization."),
        # PHP extension / deserialization patterns
        (r"\byaml_parse\s*\(", "YAML parsing (potential deser via !php/object)", 7.5, "yaml_parse with untrusted input; check yaml.decode_php setting."),
        (r"yaml\.decode_php|decode_php", "yaml.decode_php config (object deser toggle)", 8.0, "Runtime-configurable setting enabling PHP object deserialization in YAML."),
        (r"\bunserialize\s*\(", "Unsafe deserialization (unserialize)", 8.5, "unserialize with untrusted data enables POP chain RCE."),
    ]
    go_patterns = [
        (r"\bexec\.Command\s*\(", "OS command execution", 8.5, "exec.Command with potential user input."),
        (r"\bos\.Exec\s*\(", "OS command execution", 8.5, "os.Exec with potential user input."),
        (r'"sh"\s*,\s*"-c"', "Shell via sh -c", 8.6, "sh -c of a string; if cmdStr is config/HTTP-sourced this is RCE."),
        (r'if\s+token\s*==\s*""', "Empty token fail-open", 9.0, "Empty access token skips auth (ctx.Next). Lab POST /command."),
        (r"os\.Chmod\([^,]+,\s*0?777\s*\)", "World-writable chmod 0777", 7.8, "Config/secrets world-writable; local PE via rewritten command."),
        (r'Contains\([^,]+,\s*"\.\."\)', "Weak path validator (only ..)", 8.1, "Does not reject paths after filepath.Join Clean removed '..'; Go Join does not drop absolute second args."),
        (r"proto\.Unmarshal\s*\(", "Protobuf unmarshal", 7.5, "Untrusted Redis/network protobuf into task structs."),
        (r"gob\.NewDecoder\s*\(", "Gob decode", 8.0, "gob of HTTP body; pair with unauthenticated agent routes."),
        (r"\bfmt\.Sprintf\s*\([^)]*%s[^)]*\+", "Format string injection", 6.5, "Sprintf with potential user input in SQL/command."),
        (r"\btemplate\.HTML\s*\(", "Unescaped HTML output", 6.5, "template.HTML bypass; XSS risk."),
        (r"\bxml\.NewDecoder\s*\(", "XML parsing (XXE risk)", 7.0, "XML decoder without entity limits."),
        (r"\bpassword\s*=\s*\"", "Hardcoded credential", 7.2, "Possible hardcoded password."),
        (r"\bBEGIN\s+(RSA\s+)?PRIVATE\s+KEY", "Private key in source", 8.5, "Possible private key material."),
        (r"plugin\.Open\s*\(", "Go plugin.Open dynamic load", 8.4, "plugin.Open of a path from config/HTTP is RCE via malicious .so."),
        (r"jwt\.ParseUnverified\s*\(|ParseUnverified\s*\(", "JWT parsed without signature verify", 8.1, "jwt.ParseUnverified accepts attacker-signed tokens. Lab: forge alg/none or HS256."),
        (r"yaml\.Unmarshal\s*\([^,]+,\s*&?map\[string\]interface\{\}", "YAML into interface{} (type confusion)", 7.4, "Untyped YAML can later hit plugin/exec sinks."),
        (r"if\s+.*[Tt]oken\s*==\s*\"\"", "Empty token fail-open", 9.0, "Empty token skips control-plane auth (frp-style)."),
    ]
    rust_patterns = [
        (r"CorsLayer::permissive\s*\(", "Permissive CORS", 7.1, "Any origin can call the API; dangerous if auth is off by default."),
        (r"auth_configured", "Conditional auth layer", 8.8, "If false, middleware is not applied; default-allow mutating routes."),
        (r"all requests are allowed", "Default-allow auth comment/docs", 9.1, "Documented unauthenticated allow. Lab: POST create without credentials."),
        (r"CUBE_API_KEY", "API key auth (check empty passthrough)", 7.5, "Empty key often treated as unset."),
        (r"unsafe\s*\{", "Rust unsafe block", 6.0, "unsafe; not auto RCE — check raw pointers near parsers."),
    ]
    generic_patterns = [
        (r"\beval\s*\(", "Dynamic code execution (eval)", 8.5, "eval() with untrusted input."),
        (r"\bos\.system\s*\(", "OS command injection via os.system", 9.0, "User input reaches os.system() call."),
        (r"\bsubprocess\.call\s*\([^)]*shell\s*=\s*True", "Subprocess shell injection", 8.8, "subprocess call with shell=True and user input."),
        (r"\bpassword\s*=\s*['\"][^'\"]+['\"]", "Hardcoded credential", 7.2, "Possible hardcoded password in source."),
        (r"\bSELECT\b.*\+.*\bFROM\b", "SQL injection (heuristic)", 8.9, "String concatenation near a SQL SELECT may indicate injection."),
        (r"\bBEGIN\s+(RSA\s+)?PRIVATE\s+KEY", "Private key in source", 8.5, "Possible private key material in source."),
    ]
    c_cpp_patterns = [
        # Memory safety - buffer overflows
        (r"\bstrcpy\s*\(", "Unsafe string copy (strcpy)", 7.5, "strcpy has no bounds check; use strncpy/strlcpy or snprintf."),
        (r"\bstrcat\s*\(", "Unsafe string concatenation (strcat)", 7.0, "strcat has no bounds check; buffer overflow risk."),
        (r"\bsprintf\s*\(", "Unsafe sprintf (no bounds)", 7.5, "sprintf has no bounds check; use snprintf."),
        (r"\bgets\s*\(", "Extremely unsafe gets()", 9.0, "gets() has no length limit; guaranteed buffer overflow on long input."),
        (r"\bmemcpy\s*\([^)]*,\s*[^)]*,\s*[^)]*\)", "memcpy (check length source)", 6.0, "memcpy with potentially attacker-controlled length."),
        (r"\bscanf\s*\(\s*\"%[^\"]*s", "scanf %s without width limit", 7.5, "scanf %s reads unbounded input into buffer."),
        # PHP C extension patterns (pecl modules)
        (r"\bphp_var_unserialize\s*\(", "PHP object deserialization in C extension (CWE-502)", 9.5, "php_var_unserialize deserializes arbitrary PHP objects - RCE via POP chains."),

        (r"!php/object|php_unserialize", "PHP object YAML tag (deserialization RCE)", 9.0, "!php/object tag triggers PHP deserialization from YAML input."),
        (r"\(int\)\s*\w+\s*[;,].*size_t|size_t.*\(int\)", "Integer truncation size_t to int", 7.0, "size_t to int cast truncates on 64-bit; potential heap overflow."),
        # Integer overflow / signedness
        (r"\b(int|short|signed)\s+\w+\s*=\s*.*\b(strlen|read|recv|size)\b", "Signed integer for size/length", 6.5, "Signed variable holding size/length value; negative wrap possible."),
        (r"\bmalloc\s*\(\s*[^)]*\*[^)]*\)", "Multiplication in malloc size", 7.0, "Integer overflow in allocation size (a*b wraps to small value)."),
        (r"\brealloc\s*\(\s*\w+\s*,", "realloc (check NULL return)", 6.0, "realloc NULL return loses original pointer if unchecked."),
        (r"\b(size_t|unsigned)\s+\w+\s*=\s*.*-", "Unsigned arithmetic subtraction", 6.5, "Unsigned subtraction can underflow to large value."),
        # Format string
        (r"\b(printf|fprintf|snprintf|syslog)\s*\([^\"]*\buser\b", "Format string with user data", 8.0, "User-controlled format string; arbitrary read/write via %n."),
        (r"\b(printf|fprintf|sprintf|snprintf)\s*\(\s*[^\"]\w+\s*\)", "Format string (variable as format)", 8.0, "Variable used as format string; if attacker-controlled, RCE possible."),
        # Use-after-free indicators
        (r"\bfree\s*\(\s*(\w+)\s*\)", "free() call (check for UAF)", 5.5, "free() call; verify pointer not used after this point."),
        # Dangerous functions
        (r"\bsystem\s*\(", "OS command execution (system)", 9.0, "system() call; if input is user-controlled, command injection."),
        (r"\bpopen\s*\(", "OS command execution (popen)", 8.5, "popen() call; if input is user-controlled, command injection."),
        (r"\bexecve?\s*\(", "Process execution", 7.5, "exec family call; verify arguments are not attacker-controlled."),
        # Crypto/randomness
        (r"\brand\s*\(\s*\)", "Weak random (rand())", 5.5, "rand() is predictable; use /dev/urandom or getrandom() for security."),
        (r"\bsrand\s*\(\s*time\s*\(", "Predictable random seed", 6.0, "srand(time()) is predictable; attacker can reproduce sequence."),
        # Type confusion / casts
        (r"\(\s*(void|char)\s*\*\s*\)\s*\w+", "Pointer type cast", 5.0, "Type cast may indicate type confusion or unsafe reinterpretation."),
        (r"\bunion\s+\w+\s*\{", "Union type (type confusion risk)", 5.0, "Union types can enable type confusion if tag not checked."),
        # Off-by-one indicators
        (r"\bstrncpy\s*\([^)]*,\s*[^)]*,\s*sizeof\s*\(\s*\w+\s*\)\s*\)", "strncpy sizeof (no null-termination)", 6.5, "strncpy does NOT null-terminate when src >= n bytes."),
        (r"\<=\s*(sizeof|size|len|length|count|num)", "Off-by-one boundary (<=)", 5.5, "Less-than-or-equal with size; check for off-by-one."),
        # Hardcoded secrets
        (r"\bpassword\s*=\s*\"[^\"]+\"", "Hardcoded password", 7.2, "Possible hardcoded password in source."),
        (r"\bBEGIN\s+(RSA\s+)?PRIVATE\s+KEY", "Private key in source", 8.5, "Possible private key material in source."),
        (r"#define\s+\w*(KEY|SECRET|PASSWORD|TOKEN)\w*\s+\"", "Hardcoded secret in define", 7.5, "Preprocessor macro with secret value."),
        # Null pointer
        (r"if\s*\(\s*\w+\s*==\s*NULL\s*\)\s*\{[^}]*\}\s*\n\s*\w+->", "NULL check then dereference", 6.0, "Pointer used after NULL check path; verify correct branch."),
        # Signal safety
        (r"\bsignal\s*\(\s*SIG\w+\s*,", "Signal handler registration", 5.0, "Signal handler must be async-signal-safe; check for malloc/printf/lock in handler."),
        # CI/CD pipeline and template injection patterns
        (r"inja::render\s*\([^)]*\{\{\s*(WORKSPACE|COMMAND|FILENAME|TARGET|GIT_REMOTE|STEP_NAME|DEFAULT_TARGET)", "Template shell script interpolation (inja)", 8.8, "inja::render interpolates unescaped YAML variables into shell scripts executed by build runners."),
        (r"fmt::format\s*\([^)]*&&\s*\{\}", "Dynamic command concatenation (fmt::format)", 8.5, "fmt::format with subshell commands allows injection of metacharacters."),
        (r"tar\s+-[^\n]*\{\{\s*TARGET\s*\}\}", "Unsanitized tar extract directory (path traversal)", 8.0, "tar extraction without path validation allows arbitrary directory overwriting."),
        (r"chown\s+.*\{\{\s*(TARGET|DEFAULT_TARGET)\s*\}\}", "Unsanitized chown path target", 7.5, "chown on user-controlled path variable allows privilege elevation or arbitrary file ownership change."),
        # Fail-open native authn/authz (brokers, databases) — CVSS stays <7 so
        # severity_policy does not promote every hit to P0; high-severity-surface
        # owns the QUALIFIED 8.x leads after context checks.
        (r"d_shouldPass\s*=\s*true", "AnonAuthenticator shouldPass defaults true", 8.4,
         "Anonymous authenticator fails open. Lab: negotiate with no credentials."),
        (r"Authorize allow on", "Allow-all authorizer (always-allow log)", 8.6,
         "Authorizer logs allow-all. Combined with a networked admin plane this is authz bypass."),
        (r"implicitly assigned the default anonymous credential", "Unauthenticated clients implicitly authenticated", 8.8,
         "Missing auth request still authenticates as ANONYMOUS."),
        (r"user account with empty password do not need auth switch", "Empty-password accounts skip auth switch", 7.8,
         "MySQL-compat empty-password path. High-sev if default root is empty on a published port."),
        # Dynamic library loading (LATENT unless path is attacker-controlled)
        (r"\bdlopen\s*\(", "Dynamic library loading (dlopen)", 6.5, "dlopen may load attacker-controlled shared library if path is from env/input."),
        (r"\bLoadLibrary[AW]?\s*\(", "Dynamic library loading (LoadLibrary)", 6.5, "LoadLibrary may load attacker-controlled DLL if path is from env/input."),
        (r"\bgetenv\s*\([^)]*\)\s*.*\bdlopen\b", "Environment-controlled dlopen path", 8.5, "dlopen path from getenv allows arbitrary code execution via malicious .so."),
        (r"std::getenv\s*\(", "Environment variable read (getenv)", 5.0, "std::getenv read; trace where the value flows (dlopen, exec, path construction)."),
        # URI/URL handling and SSRF
        (r"\bcurl_easy_perform\s*\(", "HTTP request (curl)", 6.0, "curl HTTP request; check if URL is user/schema-controlled (SSRF risk)."),
        (r"\bcurl_easy_setopt\s*\([^,]*,\s*CURLOPT_URL", "curl URL set", 7.0, "URL passed to curl; if from untrusted input/schema $ref, SSRF risk."),
        # Recursive processing without depth limits
        (r"(validate|evaluate|resolve|compile|traverse|visit)\s*\([^)]*\)\s*\{[^}]*\b(validate|evaluate|resolve|compile|traverse|visit)\s*\(", "Recursive processor without depth check", 6.5, "Recursive function call pattern; check for depth limits to prevent stack overflow."),
    ]

    _lang_patterns = {
        "ruby/rails": ruby_patterns,
        "python": python_patterns,
        "node": node_patterns,
        "java": java_patterns,
        "php": php_patterns,
        "go": go_patterns,
        "rust": rust_patterns,
        "c/cpp": c_cpp_patterns,
        "c": c_cpp_patterns,
        "cpp": c_cpp_patterns,
        "unknown": generic_patterns,
    }
    patterns = _lang_patterns.get(language, generic_patterns)
    _skip_dirs = {".git", "node_modules", "vendor", ".bundle", "__pycache__", ".venv", "venv",
                   "target", "build", "dist", "test", "tests", "spec", "specs", "test_data",
                   "fixtures", "examples", "example", "testdata", "mock", "mocks", "stub",
                   "stubs", "__tests__", "__mocks__", "testing", "licenses", "sorbet", "rbi",
                   "unittest", "unittests", "docs", "doc", "doxygen", "third_party", "thirdparty",
                   ".lotus"}
    _skip_file_patterns = {"test_", "_test.", "_spec.", ".test.", ".spec.", "mock_", "fake_", "stub_"}
    results: List[dict] = []
    max_results = 200  # Cap to reduce noise; quality over quantity
    for f in dest.rglob("*"):
        if len(results) >= max_results:
            break
        if not f.is_file() or f.stat().st_size > 1_000_000:
            continue
        # Skip common non-source and test directories
        parts = set(p.lower() for p in f.relative_to(dest).parts)
        if parts & _skip_dirs:
            continue
        # Skip test files by name pattern
        fname_lower = f.name.lower()
        if any(p in fname_lower for p in _skip_file_patterns):
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for pat, title, cvss, desc in patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                line = text[:m.start()].count("\n") + 1
                results.append({
                    "tool": "grep-pattern",
                    "title": title,
                    "cvss": cvss,
                    "description": f"{desc} File: {f.name}, line {line}.",
                    "file": str(f.relative_to(dest)),
                    "line": line,
                    "confidence": "low",
                })
                if len(results) >= max_results:
                    break
            if len(results) >= max_results:
                break
    # P1: Calibrate CVSS for non-web apps
    _app_type = detect_application_type(dest, language)
    if _app_type in ('cli-tool', 'library'):
        for r in results:
            tool_title = r.get('title', '').lower()
            file_path = r.get('file', '').lower()
            # Parser/deserializer paths process untrusted stdin/file data  - keep CVSS
            is_parser_path = any(x in file_path for x in (
                'parser', 'deserializ', 'plist', 'yaml', 'xml', 'json', 'csv',
                'marshal', 'pickle', 'formulary', 'tap', 'download', 'plugin',
            ))
            if is_parser_path:
                continue  # untrusted data enters via stdin/pipe/file; don't downrate
            if any(k in tool_title for k in ('eval', 'exec', 'os.system', 'subprocess', 'popen')):
                r['cvss'] = min(r['cvss'], 5.5)
            elif 'hardcoded' in tool_title or 'password' in tool_title:
                r['cvss'] = min(r['cvss'], 5.5)

    return results


def run_advanced_patterns(dest: Path, repo_id: int, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Apply audit-methodology-driven patterns (T4 error-path, T5 unreachable, T6 semantic confusion,
    T7 concurrency, T9 pre-auth) as static heuristics. These supplement basic grep-patterns
    with deeper structural analysis."""
    results: List[dict] = []
    _skip_dirs = {".git", "node_modules", "vendor", ".bundle", "__pycache__", ".venv", "venv", "target", "build", "dist"}

    # T4: Error-path residue patterns
    error_path_patterns = {
        "python": [
            (r"except\s*(\w+)?\s*:\s*\n\s*pass", "Bare except with pass (swallowed error)", 6.5,
             "T4: Exception swallowed; error state may persist. Check if auth/cleanup skipped."),
            (r"except\s+Exception\s*(as\s+\w+)?\s*:\s*\n\s*(pass|return\s+None)", "Broad exception catch swallowing error", 6.0,
             "T4: Broad exception handler may hide security-critical failures."),
        ],
        "node": [
            (r"catch\s*\(\w*\)\s*\{\s*\}", "Empty catch block", 6.0,
             "T4: Empty catch block swallows errors; security checks may be bypassed."),
            (r"\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)", "Swallowed promise rejection", 6.5,
             "T4: Promise rejection silently consumed; undefined state propagates."),
        ],
        "ruby/rails": [
            (r"rescue\s*=>\s*\w*\s*\n\s*nil", "Rescue returning nil", 6.0,
             "T4: Error returns nil; caller may treat nil as success/no-restriction."),
            (r"rescue\s+StandardError", "Broad rescue swallowing errors", 5.5,
             "T4: Broad rescue may hide auth/validation failures."),
        ],
        "go": [
            (r"if\s+err\s*!=\s*nil\s*\{\s*\n\s*//", "Error check with only comment", 5.5,
             "T4: Error detected but only commented, not handled."),
            (r"_\s*=\s*\w+\.\w+\(", "Discarded error return value", 6.5,
             "T4: Error return discarded via blank identifier. Security check may be missed."),
        ],
        "java": [
            (r"catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}", "Empty catch block", 6.0,
             "T4: Exception swallowed; security state may be inconsistent."),
            (r"catch\s*\(\s*\w+\s+\w+\s*\)\s*\{\s*//", "Catch with only comment", 5.5,
             "T4: Exception caught but only commented; potential fail-open."),
        ],
        "php": [
            (r"catch\s*\(\s*\\?Exception\s+\$\w+\s*\)\s*\{\s*\}", "Empty catch block", 6.0,
             "T4: Exception swallowed; security state may be inconsistent."),
        ],
    }

    # T7: Concurrency/race-condition patterns
    concurrency_patterns = {
        "python": [
            (r"async\s+def\s+\w+.*\n(?:.*\n)*?.*await.*\n(?:.*\n)*?.*(?:session|user|auth|permission)", "Async gap near auth state", 6.5,
             "T7: Await between auth check and use creates async interleave window."),
        ],
        "go": [
            (r"go\s+func\s*\(\s*\)\s*\{[^}]*range", "Goroutine loop variable capture", 7.0,
             "T7: Loop variable captured by reference in goroutine; all goroutines may use last value."),
            (r"map\[.*\]\s*=.*//.*concurrent|concurrent.*map\[", "Concurrent map access", 6.5,
             "T7: Concurrent map access without mutex can panic or corrupt data."),
        ],
        "node": [
            (r"await\s+\w+.*\n.*await\s+\w+", "Multiple awaits without atomic guard", 5.0,
             "T7: Sequential awaits may allow state change between checks."),
        ],
    }

    # T9: Pre-auth surface patterns
    preauth_patterns = {
        "python": [
            (r"@app\.route.*\n(?:(?!@login_required|@auth|@require).*\n)*def\s+\w+", "Route without auth decorator", 6.0,
             "T9: Endpoint may be accessible without authentication."),
        ],
        "node": [
            (r"app\.(get|post|put|delete)\s*\([^)]+,\s*(?!auth|requireAuth|isAuthenticated)", "Route without auth middleware", 6.0,
             "T9: Express route without auth middleware in handler chain."),
        ],
        "ruby/rails": [
            (r"skip_before_action\s*:authenticate", "Auth skip in controller", 7.0,
             "T9: Authentication explicitly skipped; verify this is intentional."),
            (r"before_action.*except:.*\[.*:create.*:new", "Auth exemption on create/new", 5.5,
             "T9: Auth exempted on creation actions; check for abuse."),
        ],
        "java": [
            (r"@PermitAll|permitAll\(\)", "Endpoint marked permit-all", 5.5,
             "T9: Endpoint accessible without auth; verify intended."),
        ],
        "php": [
            (r"\$this->middleware\([^)]*\)->except\(", "Middleware exception", 6.0,
             "T9: Middleware explicitly exempted on some routes; verify security."),
        ],
    }

    # T6: Type juggling / comparison confusion (language-specific)
    comparison_patterns = {
        "php": [
            (r"==\s*(true|false|null|0|\"\"|\'\')(?!\s*=)", "Loose comparison (type juggling)", 7.0,
             "T6: Loose == comparison in PHP allows type juggling bypasses. Use === instead."),
            (r"in_array\s*\([^)]*\)(?!\s*,\s*true)", "in_array without strict flag", 6.5,
             "T6: in_array without strict=true uses loose comparison; type juggling."),
        ],
        "node": [
            (r"==\s*(?:null|undefined|true|false|0|\"\")", "Loose equality check", 5.5,
             "T6: == instead of === allows type coercion; potential auth bypass."),
        ],
    }

    all_pattern_sets = [error_path_patterns, concurrency_patterns, preauth_patterns, comparison_patterns]

    for f in dest.rglob("*"):
        if len(results) >= 200:
            break
        if not f.is_file() or f.stat().st_size > 500_000:
            continue
        if not f.suffix in (".py", ".js", ".ts", ".rb", ".go", ".java", ".php"):
            continue
        parts = set(f.relative_to(dest).parts)
        if parts & _skip_dirs:
            continue
        # Also skip test files for lower false-positive rate
        rel_lower = str(f.relative_to(dest)).lower()
        if any(t in rel_lower for t in ("test", "spec", "fixture", "mock", "example", "sample")):
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for pattern_set in all_pattern_sets:
            lang_patterns = pattern_set.get(language, [])
            for pat, title, cvss, desc in lang_patterns:
                for m in re.finditer(pat, text, re.MULTILINE):
                    line = text[:m.start()].count("\n") + 1
                    results.append({
                        "tool": "methodology-pattern",
                        "title": title,
                        "cvss": cvss,
                        "description": f"{desc} File: {f.name}, line {line}.",
                        "file": str(f.relative_to(dest)),
                        "line": line,
                        "confidence": "medium",
                    })
                    if len(results) >= 200:
                        break
                if len(results) >= 200:
                    break
            if len(results) >= 200:
                break
        if len(results) >= 200:
            break
    # P1: Calibrate CVSS for non-web app types
    # Detect app type for calibration (reuse cached value if available)
    _app_type = detect_application_type(dest, language)
    if _app_type in ('cli-tool', 'library'):
        for r in results:
            # Error-handling patterns are code quality, not security, in non-web contexts
            if 'T4' in r.get('description', '') or 'swallow' in r.get('title', '').lower():
                r['cvss'] = min(r['cvss'], 4.0)
            # Pre-auth patterns don't apply to CLI tools
            if 'T9' in r.get('description', ''):
                r['cvss'] = min(r['cvss'], 3.0)

    return results

