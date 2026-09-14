"""Joern Code Property Graph (CPG) integration for Phase 1 reconnaissance.

Joern generates a Code Property Graph and allows interprocedural data-flow,
control-flow, and call-graph analysis. This module:
  1. Creates a CPG from repo source using joern-parse / joern-cli
  2. Runs taint-tracking queries (source→sink reachability)
  3. Extracts call-graph edges around sensitive functions
  4. Returns structured findings + a rich CPG summary for Phase 2

If Joern is not installed the module gracefully degrades and returns empty results.
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.async_process import terminate_and_reap

# Language-specific dangerous sinks and sources for taint queries
TAINT_QUERIES: Dict[str, List[Dict[str, Any]]] = {
    "c/cpp": [
        {
            "name": "command-injection",
            "title": "OS Command Injection (data flow)",
            "cvss": 9.5,
            "query": 'def src = cpg.method.name("main").parameter ++ cpg.call.name("recv|read|fgets|gets|getenv|scanf").argument; def snk = cpg.call.name("system|popen|execl|execlp|execle|execv|execvp|dlopen").argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "buffer-overflow",
            "title": "Buffer Overflow (unchecked copy)",
            "cvss": 9.0,
            "query": 'def src = cpg.call.name("recv|read|fgets|gets").argument; def snk = cpg.call.name("strcpy|strcat|sprintf|memcpy").argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "format-string",
            "title": "Format String Vulnerability",
            "cvss": 8.5,
            "query": 'def src = cpg.call.name("recv|read|fgets|gets|getenv").argument; def snk = cpg.call.name("printf|fprintf|sprintf|snprintf").argument(0); println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "use-after-free",
            "title": "Use After Free (heuristic)",
            "cvss": 8.0,
            "query": 'println(cpg.call.name("free").argument.usedAt.filter(_.lineNumber.isDefined).l)',
        },
        {
            "name": "sql-injection",
            "title": "SQL Injection (C/C++ data flow)",
            "cvss": 9.0,
            "query": 'def src = cpg.call.name("recv|read|fgets|gets|getenv").argument; def snk = cpg.call.name("mysql_query|sqlite3_exec|PQexec|PQexecParams").argument; println(snk.reachableByFlows(src).p)',
        },
    ],
    "java": [
        {
            "name": "command-injection",
            "title": "OS Command Injection (data flow)",
            "cvss": 9.5,
            "query": 'def src = cpg.method.parameter.evalType(".*HttpServletRequest.*"); def snk = cpg.call.name("exec").where(_.receiver.evalType(".*Runtime.*")).argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "sql-injection",
            "title": "SQL Injection (data flow)",
            "cvss": 9.0,
            "query": 'def src = cpg.method.parameter.evalType(".*HttpServletRequest.*"); def snk = cpg.call.name("executeQuery|executeUpdate|execute").argument(0); println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "deserialization",
            "title": "Unsafe Deserialization (data flow)",
            "cvss": 9.0,
            "query": 'def src = cpg.call.name("read|readObject").where(_.receiver.evalType(".*InputStream.*")); def snk = cpg.call.name("readObject"); println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "xxe",
            "title": "XML External Entity Injection",
            "cvss": 8.0,
            "query": 'println(cpg.call.name("parse|newSAXParser|newDocumentBuilder").where(_.receiver.evalType(".*XML.*|.*SAX.*|.*DocumentBuilder.*")).l)',
        },
        {
            "name": "path-traversal",
            "title": "Path Traversal (data flow)",
            "cvss": 8.0,
            "query": 'def src = cpg.method.parameter.evalType(".*HttpServletRequest.*"); def snk = cpg.call.name(".*File.*|.*Path.*").argument; println(snk.reachableByFlows(src).p)',
        },
    ],
    "python": [
        {
            "name": "command-injection",
            "title": "OS Command Injection (data flow)",
            "cvss": 9.5,
            "query": 'def src = cpg.call.name("input|request\\..*").argument; def snk = cpg.call.name("system|popen|exec|eval|subprocess\\..*").argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "sql-injection",
            "title": "SQL Injection (data flow)",
            "cvss": 9.0,
            "query": 'def src = cpg.call.name("input|request\\..*").argument; def snk = cpg.call.name("execute|executemany|raw").argument(0); println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "deserialization",
            "title": "Unsafe Deserialization (data flow)",
            "cvss": 8.5,
            "query": 'def snk = cpg.call.name("loads|load").where(_.receiver.code(".*pickle.*|.*yaml.*|.*marshal.*")); println(snk.l)',
        },
        {
            "name": "ssti",
            "title": "Server-Side Template Injection",
            "cvss": 8.5,
            "query": 'def src = cpg.call.name("request\\..*").argument; def snk = cpg.call.name("render_template_string|Template").argument; println(snk.reachableByFlows(src).p)',
        },
    ],
    "node": [
        {
            "name": "command-injection",
            "title": "OS Command Injection (data flow)",
            "cvss": 9.5,
            "query": 'def src = cpg.call.name(".*req\\.body.*|.*req\\.params.*|.*req\\.query.*"); def snk = cpg.call.name("exec|execSync|spawn").argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "prototype-pollution",
            "title": "Prototype Pollution",
            "cvss": 8.0,
            "query": 'println(cpg.call.name("merge|extend|assign|defaultsDeep").where(_.argument.code(".*req\\.(body|params|query).*")).l)',
        },
        {
            "name": "path-traversal",
            "title": "Path Traversal (data flow)",
            "cvss": 8.0,
            "query": 'def src = cpg.call.name(".*req\\..*").argument; def snk = cpg.call.name("readFile|readFileSync|createReadStream|writeFile").argument(0); println(snk.reachableByFlows(src).p)',
        },
    ],
    "go": [
        {
            "name": "command-injection",
            "title": "OS Command Injection (data flow)",
            "cvss": 9.5,
            "query": 'def src = cpg.method.parameter.evalType(".*Request.*"); def snk = cpg.call.name("Command|CommandContext").argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "sql-injection",
            "title": "SQL Injection (data flow)",
            "cvss": 9.0,
            "query": 'def src = cpg.method.parameter.evalType(".*Request.*"); def snk = cpg.call.name("Query|Exec|QueryRow").argument(0); println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "path-traversal",
            "title": "Path Traversal (data flow)",
            "cvss": 8.0,
            "query": 'def src = cpg.method.parameter.evalType(".*Request.*"); def snk = cpg.call.name("Open|ReadFile|Create").argument(0); println(snk.reachableByFlows(src).p)',
        },
    ],
    "php": [
        {
            "name": "command-injection",
            "title": "OS Command Injection (data flow)",
            "cvss": 9.5,
            "query": 'def src = cpg.call.name(".*_GET.*|.*_POST.*|.*_REQUEST.*"); def snk = cpg.call.name("system|exec|passthru|shell_exec|popen").argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "sql-injection",
            "title": "SQL Injection (data flow)",
            "cvss": 9.0,
            "query": 'def src = cpg.call.name(".*_GET.*|.*_POST.*|.*_REQUEST.*"); def snk = cpg.call.name("query|mysql_query|pg_query").argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "deserialization",
            "title": "Unsafe Deserialization (data flow)",
            "cvss": 8.5,
            "query": 'def src = cpg.call.name(".*_GET.*|.*_POST.*|.*_REQUEST.*|file_get_contents"); def snk = cpg.call.name("unserialize").argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "file-inclusion",
            "title": "Local/Remote File Inclusion",
            "cvss": 9.0,
            "query": 'def src = cpg.call.name(".*_GET.*|.*_POST.*|.*_REQUEST.*"); def snk = cpg.call.name("include|require|include_once|require_once").argument; println(snk.reachableByFlows(src).p)',
        },
    ],
    "ruby/rails": [
        {
            "name": "command-injection",
            "title": "OS Command / Shell Injection (Ruby data flow)",
            "cvss": 9.5,
            "query": 'def src = cpg.call.name(".*params.*|.*request.*|.*ENV.*").argument; def snk = cpg.call.name("system|exec|popen|shell_out|powershell_out|powershell_exec|open").argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "code-execution",
            "title": "Dynamic Code Execution / Metaprogramming (Ruby data flow)",
            "cvss": 9.0,
            "query": 'def src = cpg.call.name(".*params.*|.*request.*|.*node.*|.*attributes.*").argument; def snk = cpg.call.name("eval|instance_eval|class_eval|module_eval|send|public_send|const_get|constantize").argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "deserialization",
            "title": "Unsafe Ruby Deserialization (data flow)",
            "cvss": 8.5,
            "query": 'def src = cpg.call.name(".*params.*|.*read.*|.*request.*").argument; def snk = cpg.call.name("load|restore|unsafe_load").where(_.receiver.code(".*Marshal.*|.*YAML.*|.*Psych.*|.*JSON.*")).argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "sql-injection",
            "title": "SQL Injection (ActiveRecord/Ruby data flow)",
            "cvss": 9.0,
            "query": 'def src = cpg.call.name(".*params.*|.*request.*").argument; def snk = cpg.call.name("execute|find_by_sql|where|select|joins|order").argument; println(snk.reachableByFlows(src).p)',
        },
        {
            "name": "path-traversal",
            "title": "Path Traversal / File Access (Ruby data flow)",
            "cvss": 8.0,
            "query": 'def src = cpg.call.name(".*params.*|.*request.*").argument; def snk = cpg.call.name("read|write|delete|unlink|open|chmod").where(_.receiver.code(".*File.*|.*FileUtils.*|.*IO.*")).argument(0); println(snk.reachableByFlows(src).p)',
        },
    ],
}

# Call-graph extraction queries per language
CALLGRAPH_QUERIES: Dict[str, str] = {
    "c/cpp": 'cpg.call.filter(c => Set("system","popen","exec","execv","execvp","strcpy","strcat","sprintf","free","malloc","realloc","memcpy","mmap","read","recv","send","write","open","fopen","connect","bind","listen","accept","ioctl","fork","setuid","setgid","chown","chmod","unlink","rename","socket","setsockopt").contains(c.name)).map(c => Map("caller" -> c.method.fullName, "callee" -> c.name, "file" -> c.file.name.headOption.getOrElse(""), "line" -> c.lineNumber.getOrElse(-1))).toJson',
    "java": 'cpg.call.filter(c => Set("exec","executeQuery","executeUpdate","execute","readObject","parse","getParameter","getHeader","getInputStream","forName","newInstance","invoke").contains(c.name)).map(c => Map("caller" -> c.method.fullName, "callee" -> c.name, "file" -> c.file.name.headOption.getOrElse(""), "line" -> c.lineNumber.getOrElse(-1))).toJson',
    "python": 'cpg.call.filter(c => Set("eval","exec","system","popen","subprocess","loads","load","open","input","execute","executemany","render_template_string").contains(c.name)).map(c => Map("caller" -> c.method.fullName, "callee" -> c.name, "file" -> c.file.name.headOption.getOrElse(""), "line" -> c.lineNumber.getOrElse(-1))).toJson',
    "node": 'cpg.call.filter(c => Set("eval","Function","exec","execSync","spawn","readFile","readFileSync","writeFile","require","createReadStream").contains(c.name)).map(c => Map("caller" -> c.method.fullName, "callee" -> c.name, "file" -> c.file.name.headOption.getOrElse(""), "line" -> c.lineNumber.getOrElse(-1))).toJson',
    "go": 'cpg.call.filter(c => Set("Command","CommandContext","Query","Exec","QueryRow","Open","ReadFile","Create","ListenAndServe").contains(c.name)).map(c => Map("caller" -> c.method.fullName, "callee" -> c.name, "file" -> c.file.name.headOption.getOrElse(""), "line" -> c.lineNumber.getOrElse(-1))).toJson',
    "php": 'cpg.call.filter(c => Set("system","exec","passthru","shell_exec","popen","eval","unserialize","include","require","query","mysql_query","file_get_contents").contains(c.name)).map(c => Map("caller" -> c.method.fullName, "callee" -> c.name, "file" -> c.file.name.headOption.getOrElse(""), "line" -> c.lineNumber.getOrElse(-1))).toJson',
    "ruby/rails": 'cpg.call.filter(c => Set("system","exec","popen","shell_out","powershell_out","powershell_exec","eval","instance_eval","class_eval","send","public_send","const_get","load","restore","unsafe_load","open","read","write","chmod","delete","execute").contains(c.name)).map(c => Map("caller" -> c.method.fullName, "callee" -> c.name, "file" -> c.file.name.headOption.getOrElse(""), "line" -> c.lineNumber.getOrElse(-1))).toJson',
}

# Method-complexity query (methods with high cyclomatic complexity = audit hotspots)
COMPLEXITY_QUERY = 'cpg.method.filter(_.numberOfLines > 30).map(m => Map("name" -> m.fullName, "file" -> m.file.name.headOption.getOrElse(""), "lines" -> m.numberOfLines, "params" -> m.parameter.size)).toJson'

# The call-graph and complexity queries are *expression* queries ending in
# ``.toJson``.  Joern's ``--script`` / ``@main`` runner evaluates the block but
# does not echo its value, so the JSON must be emitted with ``println(...)`` --
# unlike the taint queries above, which call ``println`` themselves.  Without
# this wrapper these queries silently produce no output (and thus zero
# call-graph edges / hotspots) on current Joern releases, in *both* the Docker
# and Kubernetes runtimes.  Wrapping the shared constants keeps the two runtimes
# byte-identical and fixes the latent gap in one place.
CALLGRAPH_QUERIES = {lang: f"println({q})" for lang, q in CALLGRAPH_QUERIES.items()}
COMPLEXITY_QUERY = f"println({COMPLEXITY_QUERY})"

# Extension mapping for Joern frontends
LANG_EXTENSIONS: Dict[str, List[str]] = {
    "c/cpp": [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"],
    "java": [".java"],
    "python": [".py"],
    "node": [".js", ".ts", ".jsx", ".tsx"],
    "go": [".go"],
    "php": [".php"],
    "ruby/rails": [".rb"],
}


JOERN_DOCKER_IMAGE = os.environ.get("LOTUS_JOERN_IMAGE", "ghcr.io/joernio/joern:nightly")

# --- Kubernetes single-Job execution markers -------------------------------
# The k8s path runs CPG generation + every query inside one Job (one pod) and
# frames each query's output with these markers on stdout so the existing
# Docker-path parsers can be reused verbatim on each slice.  The trailing "__"
# keeps ``_JQS 1`` from prefix-matching ``_JQS 10``.
_JQS = "__LOTUS_JQS__"
_JQE = "__LOTUS_JQE__"
_PARSE_MARK = "__LOTUS_JOERN_PARSE_RC__"
_CPG_OK_MARK = "__LOTUS_CPG_OK__"
_QUERY_RC_MARK = "__LOTUS_JQRC__"


def _joern_query_script(cpg_path_in_pod: str, query: str) -> str:
    """Scala ``@main`` wrapper for one query -- byte-identical to the Docker path
    (see :func:`run_joern_query`) apart from the in-pod CPG path."""
    return (
        '@main def exec() = {\n'
        f'  importCpg("{cpg_path_in_pod}")\n'
        '  try {\n'
        f'    {query}\n'
        '  } catch {\n'
        '    case e: Exception => println(s"QUERY_ERROR: ${e.getMessage}")\n'
        '  }\n'
        '}\n'
    )


def _build_joern_job_script(joern_lang: str, specs: List[Tuple[int, str]], *, timeout_seconds: Optional[int] = None) -> str:
    """Build the in-pod shell script: parse the source to a CPG once, then run
    each query as its own ``joern --script`` (same per-query semantics as the
    Docker path) with marker-framed, stderr-merged output on stdout."""
    lines = [
        "set +e",
        # joern's REPL/script runner creates a `workspace/` directory in the
        # current working directory when it opens a CPG.  The tool Job mounts the
        # source PVC read-only at /src (the default workdir), so joern must run
        # from a writable directory or every query fails with the opaque
        # "Error during compilation: null".  /tmp is a writable emptyDir.
        "cd /tmp",
        f"joern-parse --language {joern_lang} --output /tmp/cpg.bin /src 2>&1",
        "lotus_parse_rc=$?",
        f'printf "{_PARSE_MARK}%s\\n" "$lotus_parse_rc"',
        # Do not launch query JVMs after a failed frontend or an empty graph.
        'if [ "$lotus_parse_rc" -ne 0 ]; then exit "$lotus_parse_rc"; fi',
        'if [ ! -s /tmp/cpg.bin ]; then printf "Joern frontend produced no nonempty CPG\\n" >&2; exit 65; fi',
        f'echo "{_CPG_OK_MARK}"',
    ]
    for idx, query in specs:
        delim = f"__LOTUS_JEOF_{idx}__"
        lines.append(f"cat > /tmp/q{idx}.sc <<'{delim}'")
        lines.append(_joern_query_script("/tmp/cpg.bin", query).rstrip("\n"))
        lines.append(delim)
        lines.append(f'echo "{_JQS}{idx}__"')
        lines.append(f"joern --script /tmp/q{idx}.sc 2>&1")
        lines.append(f'printf "{_QUERY_RC_MARK}{idx}__%s\\n" "$?"')
        lines.append(f'echo "{_JQE}{idx}__"')
    script = "\n".join(lines) + "\n"
    if timeout_seconds is None:
        return script
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 7200:
        raise ValueError("Joern execution watchdog requires an integer budget from 1 to 7200 seconds")
    # The whole parse/query sequence has one in-container clock. Kubernetes
    # scheduling/image-pull time cannot consume it, and losing the controller
    # cannot leave query JVMs running for the longer Job queue backstop.
    # GNU timeout owns a process group (never --foreground), escalating TERM
    # to KILL for ordinary descendants that ignore termination. Custom images
    # must provide this prerequisite; do not silently run without the bound.
    import shlex
    # Keep timeout's direct child alive through escalation even when the
    # intermediate script shell exits on TERM before a JVM/grandchild does.
    # A plain `timeout sh -c ...` can otherwise finish without the KILL step.
    guardian = ("lotus_stopping=0\ntrap 'lotus_stopping=1' TERM\n"
                f"sh -c {shlex.quote(script)} &\nlotus_child=$!\n"
                "wait \"$lotus_child\"\nlotus_child_rc=$?\n"
                "if [ \"$lotus_stopping\" -eq 1 ]; then while :; do sleep 1; done; fi\n"
                "exit \"$lotus_child_rc\"\n")
    return ("case \"$(timeout --version 2>/dev/null)\" in *'GNU coreutils'*) ;; "
            "*) printf 'Joern requires GNU timeout for its execution watchdog\\n' >&2; exit 69;; esac\n"
            f"timeout --signal=TERM --kill-after=5s {timeout_seconds}s sh -c {shlex.quote(guardian)}\n"
            "lotus_watchdog_rc=$?\n"
            "if [ \"$lotus_watchdog_rc\" -eq 124 ] || [ \"$lotus_watchdog_rc\" -eq 137 ]; then "
            "printf 'Joern watchdog-compatible exit; analysis is incomplete (not an OOM determination)\\n' >&2; fi\n"
            "exit \"$lotus_watchdog_rc\"\n")


def _split_joern_sections(stdout: str, count: int) -> Dict[int, str]:
    """Slice combined stdout back into per-query output using the frame markers."""
    sections: Dict[int, str] = {}
    for idx in range(count):
        start_tok = f"{_JQS}{idx}__"
        end_tok = f"{_JQE}{idx}__"
        s = stdout.find(start_tok)
        e = stdout.find(end_tok)
        if s >= 0 and e > s:
            sections[idx] = stdout[s + len(start_tok):e].strip("\n")
        else:
            sections[idx] = ""
    return sections


def _taint_finding(q: Dict[str, Any], flow: Dict[str, Any]) -> Dict[str, Any]:
    """Build a taint finding from a query spec + parsed flow.  Shared by the
    Docker and Kubernetes joern paths so both emit byte-identical findings."""
    return {
        "tool": "joern-taint",
        "title": f"{q['title']}: {flow.get('sink_method', 'unknown')}",
        "cvss": q["cvss"],
        "description": (
            f"Joern CPG taint analysis found data flow from source to sink.\n"
            f"Source: {flow.get('source', 'unknown')}\n"
            f"Sink: {flow.get('sink', 'unknown')}\n"
            f"Path length: {flow.get('path_length', '?')} nodes\n"
            f"Flow: {flow.get('path_summary', '')}"
        ),
        "file": flow.get("file", ""),
        "line": flow.get("line", 0),
        "confidence": "high",
        "data_flow": flow,
    }

# Joern/Scala writes diagnostics to the same stream as query output.  Treating
# those diagnostics as flow nodes is especially dangerous: the old parser
# turned strings such as ``replpp.scripting.ScriptRunner`` and ``Re-run with
# --verbose`` into CVSS 9.5 command-injection leads with ``file=exec``.  Keep
# this list narrow enough not to reject a legitimate application symbol named
# ``error_handler`` while rejecting the stable runtime diagnostics.
_JOERN_ERROR_MARKERS = (
    "query_error:",
    "error while invoking",
    "exception in thread",
    "nonforking",
    "scriptrunner",
    "re-run with",
    "please check error output",
    "errors found",
    "closing/saving project",
    "for given input files:",
)
_SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".java",
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".php", ".rb", ".rs",
}


def _joern_clean(value: Any) -> str:
    """Remove terminal decoration before validating data returned by Joern."""
    text = str(value or "")
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text).strip()


def _joern_diagnostic(value: Any) -> bool:
    text = _joern_clean(value).lower()
    return any(marker in text for marker in _JOERN_ERROR_MARKERS)


def _joern_file_candidate(value: Any) -> str:
    """Return a plausible repository source path, never a Joern diagnostic."""
    text = _joern_clean(value).strip("`\"'")
    if not text or text in ("N/A", "-", "unknown") or _joern_diagnostic(text):
        return ""
    # Joern can prefix a path with a line number or a container root.  Keep the
    # relative suffix; the source-viewer performs the final traversal check.
    text = re.sub(r":\d+$", "", text)
    suffix = Path(text).suffix.lower()
    if suffix not in _SOURCE_EXTENSIONS:
        return ""
    return text


def _joern_line_candidate(value: Any) -> Optional[int]:
    text = _joern_clean(value)
    m = re.search(r"(?:line(?:number)?\s*[=:]\s*)(\d+)", text, re.I)
    if m:
        return int(m.group(1))
    if text.isdigit() and int(text) > 0:
        return int(text)
    return None


def _container_runtime_args(repo_id: Optional[int] = None) -> List[str]:
    """Return the centrally enforced sandbox flags for Joern containers.

    Joern is an analyzer, but it still processes attacker-controlled source and
    CPG/query data.  Keep its Docker invocation on the same containment path as
    application labs and external analyzers.  Import lazily to avoid the
    joern/lab import cycle during API startup; fail closed if the policy module
    cannot be loaded rather than running an unconfined container.
    """
    try:
        from backend.lab import hardened_runtime_args
        args = list(hardened_runtime_args(repo_id))
    except Exception as exc:
        raise RuntimeError(f"Joern containment policy unavailable: {exc}") from exc
    # Static analysis never needs egress.  Keep this explicit here because the
    # shared target-lab policy cannot force network isolation for HTTP services.
    args.extend(["--network", "none", "--env", "HOME=/tmp", "--env", "XDG_CACHE_HOME=/tmp/.cache"])
    return args


def _joern_docker_available() -> bool:
    """Check if joern Docker image is available locally."""
    if not shutil.which("docker"):
        return False
    try:
        # The image name is configurable via LOTUS_JOERN_IMAGE.  Do not feed
        # that value to a shell: a malformed/operator-controlled image string
        # must not become command execution in the API process.
        try:
            from backend.lab import _controlled_child_env
            child_env = _controlled_child_env()
        except Exception:
            child_env = None
        result = subprocess.run(
            ["docker", "images", "-q", JOERN_DOCKER_IMAGE],
            capture_output=True, text=True, timeout=10,
            env=child_env, check=False,
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except Exception:
        return False


def _joern_available() -> bool:
    """Check if a validated Joern image is available for execution.

    Docker being installed is not evidence that the configured Joern image is
    present.  The old ``docker ||`` fallback attempted a run against a missing
    image and then reported a generic CPG failure, obscuring a concrete
    capability gap.    Require the image probe to succeed so callers can record
    ``not-installed`` and keep the report's completeness honest.

    On a Kubernetes-first host (no local Docker) the capability still exists via
    the k8s Job path, so treat a configured provider + reachable ``kubectl`` as
    available; the actual cluster reachability probe happens in
    :func:`run_joern_scan`, which falls back to Docker or reports a concrete
    skip reason if the cluster turns out to be unreachable.
    """
    if _joern_docker_available():
        return True
    try:
        from backend.lab_provider import provider_name
        from backend import k8s_lab
        if provider_name() == "k8s-job" and shutil.which(k8s_lab.kubectl_binary()):
            return True
    except Exception:
        pass
    return False


def _validate_joern_image() -> Dict[str, Any]:
    """Validate the configured Joern image before trusting its output.

    ``docker images`` only proves that a tag resolves locally; it does not
    prove that the image can be inspected or that the daemon returned a
    content identity.  Resolve the image ID with an argv-only command and
    expose whether the configured reference is immutable.  A mutable tag is
    allowed for local evaluation (the resolved ID is still recorded), but is
    explicitly surfaced as a supply-chain limitation in the evidence report.
    """
    metadata: Dict[str, Any] = {
        "image": JOERN_DOCKER_IMAGE,
        "validated": False,
        "image_id": "",
        "immutable_reference": "@sha256:" in JOERN_DOCKER_IMAGE,
        "reason": "not checked",
    }
    if not shutil.which("docker"):
        metadata["reason"] = "docker executable unavailable"
        return metadata
    try:
        try:
            from backend.lab import _controlled_child_env
            child_env = _controlled_child_env()
        except Exception:
            child_env = None
        result = subprocess.run(
            ["docker", "image", "inspect", JOERN_DOCKER_IMAGE, "--format", "{{.Id}}"],
            capture_output=True, text=True, timeout=15, env=child_env, check=False,
        )
        image_id = str(result.stdout or "").strip().splitlines()[0] if result.stdout else ""
        metadata["image_id"] = image_id
        if result.returncode != 0:
            metadata["reason"] = str(result.stderr or "docker image inspect failed")[-300:]
            return metadata
        if not image_id.startswith("sha256:"):
            metadata["reason"] = "docker returned no content-addressed image ID"
            return metadata
        metadata["validated"] = True
        metadata["reason"] = "content-addressed image ID resolved"
        return metadata
    except Exception as exc:
        metadata["reason"] = str(exc)[:300]
        return metadata


def _map_language_to_joern(language: str) -> Optional[str]:
    """Map internal language detection to Joern frontend name."""
    mapping = {
        "c/cpp": "c",
        "java": "javasrc",
        "python": "pythonsrc",
        "node": "jssrc",
        # Joern's CLI accepts the generated language identifier GOLANG;
        # gosrc2cpg is its executable name, not a --language value.
        "go": "golang",
        "php": "php",
        "ruby/rails": "rubysrc",
    }
    return mapping.get(language)


async def _run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 300) -> Tuple[str, int]:
    """Run a subprocess and return (output, return_code)."""
    try:
        # Docker commands may contain repository-controlled paths and must not
        # inherit credentials/tokens from the API process.
        from backend.lab import _controlled_child_env
        child_env = _controlled_child_env()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd) if cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=child_env,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out.decode(errors="ignore"), proc.returncode
    except asyncio.CancelledError:
        await terminate_and_reap(locals().get("proc"))
        raise
    except asyncio.TimeoutError:
        await terminate_and_reap(locals().get("proc"))
        return f"timed out after {timeout}s", -1
    except Exception as e:
        return f"error: {e}", -1


async def generate_cpg(
    dest: Path,
    language: str,
    send: Callable,
    repo_id: int,
) -> Optional[Path]:
    """Generate a Code Property Graph inside an isolated Joern container pod."""
    joern_lang = _map_language_to_joern(language)
    if not joern_lang:
        await send(repo_id, f"Joern: no frontend for language '{language}'; skipping CPG", level="info")
        return None

    cpg_path = dest / "cpg.bin"

    # Always generate CPG in isolated Joern container pod
    if _joern_available():
        await send(repo_id, f"Joern: generating CPG in container pod ({JOERN_DOCKER_IMAGE}, frontend: {joern_lang})", level="info")
        container_name = f"lotus-joern-{repo_id}"
        await _run_cmd(["docker", "rm", "-f", container_name], timeout=10)
        cmd = [
            "docker", "run", "--rm", "--name", container_name,
            *_container_runtime_args(repo_id),
            "-v", f"{dest}:/app:ro",
            "-v", f"{dest}:/output:rw",
            JOERN_DOCKER_IMAGE,
            "joern-parse", "--language", joern_lang, "--output", "/output/cpg.bin", "/app"
        ]
        out, rc = await _run_cmd(cmd, timeout=300)
        if rc == 0 and cpg_path.is_file() and cpg_path.stat().st_size > 0:
            await send(repo_id, f"Joern: CPG generated in container pod ({cpg_path.stat().st_size // 1024}KB)", level="info")
            return cpg_path
        await send(repo_id, f"Joern: container CPG generation failed (rc={rc}): {out[:200]}", level="warning")

    return None


async def run_joern_query(
    query: str,
    cpg_path: Path,
    send: Callable,
    repo_id: int,
    timeout: int = 120,
) -> Optional[str]:
    """Execute a Joern/CPGQL query against a generated CPG in container pod."""
    cpg_dir = cpg_path.parent
    script_name = f"_q_{repo_id}_{int(datetime.utcnow().timestamp())}.sc"
    script_path = cpg_dir / script_name

    # Create temporary scala script
    script_content = (
        '@main def exec() = {\n'
        '  importCpg("/data/cpg.bin")\n'
        '  try {\n'
        f'    {query}\n'
        '  } catch {\n'
        '    case e: Exception => println(s"QUERY_ERROR: ${e.getMessage}")\n'
        '  }\n'
        '}\n'
    )
    try:
        script_path.write_text(script_content)
    except Exception:
        pass

    if _joern_available() and script_path.exists():
        container_name = f"lotus-joern-q-{repo_id}"
        cmd = [
            "docker", "run", "--rm", "--name", container_name,
            *_container_runtime_args(repo_id),
            "-v", f"{cpg_dir}:/data:ro",
            JOERN_DOCKER_IMAGE,
            "joern", "--script", f"/data/{script_name}"
        ]
        try:
            out, rc = await _run_cmd(cmd, timeout=timeout)
            return out if rc == 0 or "---" in out or "│" in out or "[" in out or "{" in out else None
        finally:
            if script_path.exists():
                try:
                    script_path.unlink()
                except Exception:
                    pass

    return None


async def run_taint_analysis(
    cpg_path: Path,
    language: str,
    send: Callable,
    repo_id: int,
    diagnostics: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Run language-specific taint-flow queries against the CPG in container pod."""
    findings: List[Dict[str, Any]] = []
    queries = TAINT_QUERIES.get(language, [])

    if diagnostics is not None:
        diagnostics.clear()
        diagnostics.update({
            "query_count": len(queries),
            "query_outcomes": [],
            "queries_without_output": 0,
            "queries_without_valid_flows": 0,
        })

    if not queries:
        await send(repo_id, f"Joern: no taint queries defined for '{language}'", level="info")
        return findings

    await send(repo_id, f"Joern: running {len(queries)} taint-flow queries in container pod", level="info")

    for q in queries:
        result = await run_joern_query(q["query"], cpg_path, send, repo_id, timeout=90)
        if not result:
            if diagnostics is not None:
                diagnostics["queries_without_output"] += 1
                diagnostics["query_outcomes"].append({
                    "title": q.get("title", "taint query"),
                    "status": "failed",
                    "reason": "Joern query returned no output",
                })
            continue

        # Parse Joern output for flow paths
        flows = _parse_flow_output(result)
        if diagnostics is not None:
            if flows:
                query_status = "completed"
            else:
                diagnostics["queries_without_valid_flows"] += 1
                query_status = "completed_no_valid_flows"
            diagnostics["query_outcomes"].append({
                "title": q.get("title", "taint query"),
                "status": query_status,
                "flow_count": len(flows),
            })
        for flow in flows:
            findings.append(_taint_finding(q, flow))

    if findings:
        await send(repo_id, f"Joern: taint analysis produced {len(findings)} data-flow leads", level="info")
    else:
        await send(repo_id, "Joern: taint analysis found no exploitable flows", level="info")

    return findings


async def extract_callgraph(
    cpg_path: Path,
    language: str,
    send: Callable,
    repo_id: int,
) -> List[Dict[str, Any]]:
    """Extract call-graph edges to/from security-sensitive functions."""
    query = CALLGRAPH_QUERIES.get(language)
    if not query:
        return []

    await send(repo_id, "Joern: extracting call graph around sensitive sinks", level="info")
    result = await run_joern_query(query, cpg_path, send, repo_id, timeout=90)
    if not result:
        return []

    edges = _parse_json_output(result)
    if edges:
        await send(repo_id, f"Joern: extracted {len(edges)} call-graph edges to sensitive functions", level="info")
    return edges


async def extract_complexity_hotspots(
    cpg_path: Path,
    send: Callable,
    repo_id: int,
) -> List[Dict[str, Any]]:
    """Extract complex methods that are priority audit targets."""
    result = await run_joern_query(COMPLEXITY_QUERY, cpg_path, send, repo_id, timeout=60)
    if not result:
        return []

    hotspots = _parse_json_output(result)
    if hotspots:
        await send(repo_id, f"Joern: identified {len(hotspots)} complexity hotspots (>30 lines)", level="info")
    return hotspots


def _parse_flow_output(output: str) -> List[Dict[str, Any]]:
    """Parse Joern flow table output into structured path descriptions.

    A flow is only emitted when it has at least two path nodes *and* a
    repository source file plus a positive line number.  Joern's diagnostics
    are deliberately ignored.  This is a conservative lead-quality boundary:
    a missing location becomes a coverage gap, not a fabricated high-severity
    lead that cannot be reproduced or linked to source.
    """
    flows: List[Dict[str, Any]] = []
    current_flow: Dict[str, Any] = {}
    path_nodes: List[str] = []

    def flush() -> None:
        nonlocal current_flow, path_nodes
        if not current_flow or len(path_nodes) < 2:
            current_flow, path_nodes = {}, []
            return
        source = _joern_clean(current_flow.get("source"))
        sink = _joern_clean(current_flow.get("sink"))
        file_name = _joern_file_candidate(current_flow.get("file"))
        line_no = current_flow.get("line")
        if (
            not source or not sink or _joern_diagnostic(source) or _joern_diagnostic(sink)
            or not file_name or not isinstance(line_no, int) or line_no <= 0
        ):
            current_flow, path_nodes = {}, []
            return
        current_flow["source"] = source[:100]
        current_flow["sink"] = sink[:100]
        current_flow["file"] = file_name
        current_flow["path_summary"] = " -> ".join(path_nodes[:10])
        current_flow["path_length"] = len(path_nodes)
        flows.append(current_flow)
        current_flow, path_nodes = {}, []

    for line in output.splitlines():
        line = _joern_clean(line)
        if not line:
            flush()
            continue

        # Diagnostics often contain pipe characters and therefore used to be
        # parsed as rows.  Flush any preceding flow and discard the line.
        if _joern_diagnostic(line):
            flush()
            continue

        # Header / divider line detection
        if any(div in line for div in ["==", "---", "┌", "└", "├", "nodeType"]):
            if ("└" in line or "==" in line) and current_flow and path_nodes:
                flush()
            continue

        # Check for unicode table row (│) or ASCII pipe row (|)
        sep = "│" if "│" in line else "|" if "|" in line else None
        if sep:
            parts = [p.strip() for p in line.split(sep) if p.strip()]
            # Joern row columns: [nodeType, tracked, line, method, file]
            if len(parts) >= 4:
                node_type = _joern_clean(parts[0])
                tracked = _joern_clean(parts[1])
                # Joern versions have emitted both ``line`` and
                # ``lineNumber=`` columns, and compact fixtures may omit the
                # nodeType column.  Detect the values by shape rather than by
                # fixed offsets.
                line_no = next((n for n in (_joern_line_candidate(p) for p in parts) if n), None)
                file_str = next((_joern_file_candidate(p) for p in reversed(parts)), "")
                method_parts = [
                    _joern_clean(p) for p in parts
                    if _joern_line_candidate(p) is None and not _joern_file_candidate(p)
                ]
                method = method_parts[-1] if method_parts else node_type

                path_nodes.append(f"{method}:{tracked}"[:60])
                if not current_flow.get("source"):
                    current_flow["source"] = f"{method}:{tracked}"[:100]
                current_flow["sink"] = f"{method}:{tracked}"[:100]
                current_flow["sink_method"] = method

                if line_no is not None:
                    current_flow.setdefault("line", line_no)
                if file_str:
                    current_flow.setdefault("file", file_str)
            elif len(parts) >= 2:
                node_info = _joern_clean(parts[0])
                path_nodes.append(node_info[:60])
                for part in parts:
                    line_no = _joern_line_candidate(part)
                    file_name = _joern_file_candidate(part)
                    if line_no is not None:
                        current_flow.setdefault("line", line_no)
                    if file_name:
                        current_flow.setdefault("file", file_name)
                if not current_flow.get("source"):
                    current_flow["source"] = node_info[:100]
                current_flow["sink"] = node_info[:100]
                current_flow["sink_method"] = node_info.split("(")[0].strip() if "(" in node_info else node_info[:40]

        elif (
            line and "->" in line and not line.startswith("#")
            and not line.startswith("//") and not line.startswith("[INFO")
        ):
            # Some Joern versions render a textual arrow path instead of a
            # table.  Accept it only when a real file and line are present.
            path_nodes.append(line[:60])
            if not current_flow.get("source"):
                current_flow["source"] = line[:100]
            current_flow["sink"] = line[:100]
            for token in line.split():
                line_no = _joern_line_candidate(token)
                file_name = _joern_file_candidate(token)
                if line_no is not None:
                    current_flow.setdefault("line", line_no)
                if file_name:
                    current_flow.setdefault("file", file_name)

    flush()

    return flows


def _parse_json_output(output: str) -> List[Dict[str, Any]]:
    """Parse JSON array output from Joern queries."""
    results: List[Dict[str, Any]] = []

    try:
        data = json.loads(output)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except (json.JSONDecodeError, ValueError):
        pass

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith("[INFO"):
            continue
        if line.startswith("{") or line.startswith("["):
            try:
                data = json.loads(line)
                if isinstance(data, list):
                    results.extend(data)
                elif isinstance(data, dict):
                    results.append(data)
            except (json.JSONDecodeError, ValueError):
                continue

    return results


def _joern_policy():
    from backend import analyzer_resources as resources
    captured = resources.selected_tool("joern")
    if captured is None:
        captured = next(row for row in resources.snapshot_policy({})["tools"] if row["id"] == "joern")
    return captured


def _resource_error(policy, reason, *, failed=False, diagnostic=None):
    from backend import analyzer_resources as resources
    from backend.ext_analyzers import AnalyzerExecutionError, AnalyzerUnavailable
    error = AnalyzerExecutionError(reason) if failed else AnalyzerUnavailable(reason)
    for key, value in resources.task_resource_metadata("joern", policy, reason, failed=failed, diagnostic=diagnostic).items():
        setattr(error, key, value)
    return error


def _joern_envelope(policy):
    effective = policy.get("effective") or {}
    for field, low in (("memory_mb", 4096), ("timeout_seconds", 1), ("queue_timeout_seconds", 1)):
        value = effective.get(field)
        if type(value) is not int or not low <= value <= (65536 if field == "memory_mb" else 7200):
            raise _resource_error(policy, "Captured Joern resource configuration is invalid; save valid Settings before retrying")
    memory = effective["memory_mb"]
    return {"mem_request": f"{memory}Mi", "mem_limit": f"{memory}Mi", "cpu_request": "500m", "cpu_limit": "2",
            "timeout_seconds": effective["timeout_seconds"], "queue_timeout_seconds": effective["queue_timeout_seconds"]}


async def _joern_docker_job(repo_id, dest, image, script, env, envelope, diagnostic_sink):
    """Run the same full CPG script in one owned, bounded backup container.

    Daemon state provides OOM evidence; client timeout provides deadline evidence.
    Cleanup addresses only the verified immutable container ID, including when
    allocation or execution is cancelled. Scratch is tmpfs inside the memory cap.
    """
    import uuid
    from backend.notebook_runtime import _docker, _allocate
    owner = uuid.uuid4().hex
    name = f"lotus-joern-{int(repo_id)}-{owner[:12]}"
    container_id = None
    timed_out = None
    result = {"stdout": "", "stderr": "", "returncode": -1}
    memory = int(envelope["mem_limit"].removesuffix("Mi"))
    args = _container_runtime_args(repo_id)
    filtered = []
    index = 0
    while index < len(args):
        flag = args[index]
        if flag in {"--memory", "--cpus"}:
            index += 2
            continue
        if flag == "--tmpfs" and index + 1 < len(args) and args[index + 1].startswith("/tmp:"):
            index += 2
            continue
        filtered.append(flag)
        index += 1
    command = ["create", "--name", name, "--label", f"lotus.joern.owner={owner}", *filtered,
               "--hostname", "lotus-joern", "--add-host", "lotus-joern:127.0.0.1",
               "--memory", f"{memory}m", "--memory-swap", f"{memory}m", "--cpus", "2",
               "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={memory}m",
               "--volume", f"{Path(dest).resolve()}:/src:ro", "--workdir", "/src"]
    for key, value in env.items():
        command.extend(["--env", f"{key}={value}"])
    command.extend(["--entrypoint", "sh", image, "-c", script])

    async def inspect_owned():
        nonlocal container_id
        observed = await _docker("inspect", container_id or name, timeout=15, output_limit=64000)
        if observed["returncode"] != 0:
            return None
        try:
            rows = json.loads(observed["stdout"])
            row = rows[0] if isinstance(rows, list) and len(rows) == 1 else {}
            actual = row.get("Id", "")
            if (not re.fullmatch(r"[a-f0-9]{64}", actual) or (container_id and actual != container_id)
                    or row.get("Name") != "/" + name
                    or row.get("Config", {}).get("Labels", {}).get("lotus.joern.owner") != owner
                    or row.get("Config", {}).get("Image") != image):
                return None
            container_id = actual
            return row
        except (ValueError, TypeError, KeyError, AttributeError):
            return None

    def envelope_verified(row):
        host = row.get("HostConfig") or {}
        return host.get("Memory") == memory * 1024 ** 2 and host.get("NanoCpus") == 2_000_000_000

    async def cleanup():
        row = await inspect_owned()
        if row is None:
            raise RuntimeError("Joern backup cleanup could not verify owned container identity or absence; no unverified container was deleted")
        if row is not None:
            removed = await _docker("rm", "-f", container_id, timeout=30, output_limit=4000)
            if removed["returncode"] != 0:
                raise RuntimeError("Owned Joern backup container could not be removed; inspect Docker runtime cleanup before retrying")

    try:
        try:
            allocated = await _allocate(*command, timeout=envelope["queue_timeout_seconds"], output_limit=64000)
        except asyncio.TimeoutError:
            timed_out = "queue_timeout"
        else:
            if allocated["returncode"] != 0:
                return "", allocated["stderr"], -1
            proposed = allocated["stdout"].strip()
            if not re.fullmatch(r"[a-f0-9]{64}", proposed):
                return "", "Docker allocation returned no immutable container identity", -1
            container_id = proposed
        before = await inspect_owned()
        if before is None:
            return "", "Docker Joern ownership could not be verified", -1
        if not envelope_verified(before):
            return "", "Docker Joern resource limits did not match before execution", -1
        if timed_out is None:
            try:
                result = await _docker("start", "--attach", container_id,
                                       timeout=envelope["timeout_seconds"], output_limit=400000)
            except asyncio.TimeoutError:
                timed_out = "execution_timeout"
        after = await inspect_owned()
        if after is None:
            return "", "Docker Joern identity changed before result inspection", -1
        verified = envelope_verified(after)
        state = after.get("State") or {}
        classification = "oom_killed" if state.get("OOMKilled") is True else timed_out
        if verified and classification:
            diagnostic_sink({"schema_version": 1, "provider": "docker", "classification": classification,
                "ownership_verified": True, "repo_id": int(repo_id), "tool_id": "joern", "configure_tool": "joern",
                "container_id": container_id, "image": image, "image_id": after.get("Image", ""),
                "memory_request": envelope["mem_request"], "memory_limit": envelope["mem_limit"],
                "timeout_seconds": envelope["timeout_seconds"], "queue_timeout_seconds": envelope["queue_timeout_seconds"],
                "exit_code": state.get("ExitCode") if state.get("Running") is False else None})
        if not verified:
            return "", "Docker Joern resource limits did not match the captured envelope", -1
        if timed_out:
            return "", "Docker Joern bounded runtime deadline expired", 124
        if result.get("output_truncated"):
            return "", "Docker Joern output exceeded the bounded capture; analysis is incomplete", -1
        if state.get("Running") is not False or type(state.get("ExitCode")) is not int:
            return "", "Docker Joern did not provide a terminal container exit receipt", -1
        code = result["returncode"] or state["ExitCode"]
        return result["stdout"], result["stderr"], code
    finally:
        import logging
        import sys
        original_error = sys.exc_info()[1]
        def record_cleanup_gap(error, cleanup_error):
            error.cleanup_gap = str(cleanup_error)
            logging.getLogger(__name__).warning("Joern owned backup cleanup remains unverified: %s", cleanup_error)
        clean = asyncio.create_task(cleanup())
        try:
            await asyncio.shield(clean)
        except asyncio.CancelledError as cancelled:
            try:
                await asyncio.shield(clean)
            except Exception as cleanup_error:
                record_cleanup_gap(cancelled, cleanup_error)
            raise
        except Exception as cleanup_error:
            if original_error is None:
                raise
            # Stop/cancel/lease loss keeps its original control semantics even
            # if the daemon cannot prove cleanup. The explicit gap is logged.
            record_cleanup_gap(original_error, cleanup_error)



async def _run_joern_scan_k8s(dest: Path, repo_id: int, language: str, send: Callable):
    return await _run_joern_scan_job(dest, repo_id, language, send, runtime="kubernetes")


async def _run_joern_scan_job(
    dest: Path,
    repo_id: int,
    language: str,
    send: Callable,
    *, runtime="kubernetes", image_validation=None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Run the full Joern CPG analysis as a single Kubernetes Job.

    CPG generation and every taint/call-graph/complexity query execute in one
    pod (source mounted read-only, no egress -- Joern is purely static), with
    each query's output framed on stdout so the Docker-path parsers are reused
    verbatim.  Emits the same ``(findings, cpg_summary)`` contract as the Docker
    path so the pipeline is oblivious to which runtime produced the CPG.
    """
    from backend import k8s_runtime as kr

    joern_lang = _map_language_to_joern(language)
    if not joern_lang:
        await send(repo_id, f"Joern: no frontend for language '{language}'; skipping CPG", level="info")
        return [], {"available": True, "cpg_generated": False, "reason": f"no joern frontend for {language}"}

    # Ordered query specs: taint queries first (each parsed into flows), then the
    # call-graph and complexity queries (each parsed as JSON).  The index drives
    # the stdout framing so each slice is fed to the correct parser.
    taint_qs = TAINT_QUERIES.get(language, [])
    specs: List[Tuple[int, str]] = []
    kinds: List[Tuple[int, str, Optional[Dict[str, Any]]]] = []
    idx = 0
    for q in taint_qs:
        specs.append((idx, q["query"]))
        kinds.append((idx, "taint", q))
        idx += 1
    cg_query = CALLGRAPH_QUERIES.get(language)
    if cg_query:
        specs.append((idx, cg_query))
        kinds.append((idx, "callgraph", None))
        idx += 1
    specs.append((idx, COMPLEXITY_QUERY))
    kinds.append((idx, "complexity", None))
    idx += 1
    total = idx

    from backend import analyzer_resources as resources
    policy = _joern_policy()
    if runtime == "kubernetes":
        policy = await resources.refresh_tool_admission(policy)
    if policy.get("state") not in {"ready", "unknown"}:
        raise _resource_error(policy, policy.get("reason") or "Joern resource policy blocks execution")
    envelope = _joern_envelope(policy)
    selected_image = os.environ.get("LOTUS_JOERN_IMAGE", "").strip() or JOERN_DOCKER_IMAGE
    if runtime == "docker":
        selected_image = (image_validation or {}).get("image_id") or selected_image
    elif not os.environ.get("LOTUS_JOERN_IMAGE", "").strip() and shutil.which("joern") and shutil.which("joern-parse"):
        try:
            from backend.lab_selftest import _kubernetes_selftest_image
            selected_image = await _kubernetes_selftest_image(use_explicit_override=False)
        except (ValueError, OSError):
            pass
    await send(repo_id, f"Joern: generating CPG + {total} queries in {runtime} ({selected_image}, frontend {joern_lang}); "
               f"{envelope['mem_limit']} memory, {envelope['timeout_seconds']}s execution budget", level="info")
    script = _build_joern_job_script(joern_lang, specs, timeout_seconds=envelope["timeout_seconds"])
    env = {"HOME": "/tmp", "XDG_CACHE_HOME": "/tmp/.cache",
           "JAVA_OPTS": (policy.get("runtime_options") or {}).get("java_opts") or f"-Xmx{policy['effective']['memory_mb'] * 3 // 4}m"}
    identity = resources.execution_identity("joern", selected_image, ".", script, env, envelope)
    prior = resources.prior_resource_failure(identity)
    if prior:
        raise _resource_error(policy, "This revision and Joern resource envelope previously exhausted memory; "
                              "increase memory with sufficient capacity or explicitly disable and re-enable before retrying. Coverage remains incomplete",
                              diagnostic=prior["diagnostic"])
    diagnostic = {}
    def capture(value):
        if (not isinstance(value, dict) or value.get("ownership_verified") is not True or value.get("tool_id") != "joern"
                or value.get("repo_id") != int(repo_id) or value.get("image") != selected_image
                or value.get("memory_request") != envelope["mem_request"] or value.get("memory_limit") != envelope["mem_limit"]
                or value.get("timeout_seconds") != envelope["timeout_seconds"]):
            return
        diagnostic.update(value)
        try:
            resources.record_resource_failure(identity, diagnostic)
        except OSError:
            diagnostic["receipt_persisted"] = False
    t0 = datetime.utcnow()
    if runtime == "kubernetes":
        pvc = await kr.ensure_source_pvc(int(repo_id), Path(dest), send=send)
        if not pvc:
            return [], {"available": True, "cpg_generated": False, "reason": "k8s source volume unavailable for joern"}
        try:
            out, err, rc = await kr.run_to_completion(
                int(repo_id), "joern", selected_image, script=script, workdir="/src",
                timeout=envelope["timeout_seconds"], queue_timeout=envelope["queue_timeout_seconds"],
                allow_egress=False, send=send, env=env, diagnostic_sink=capture,
                **{key: envelope[key] for key in ("mem_request", "mem_limit", "cpu_request", "cpu_limit")})
        except kr.KubernetesToolCleanupError as exc:
            raise _resource_error(policy, "Joern runtime cleanup remains unverified; inspect the owned runtime before retrying; coverage remains incomplete",
                                  failed=True, diagnostic=getattr(exc, "runtime_diagnostic", None) or diagnostic) from exc
    else:
        out, err, rc = await _joern_docker_job(repo_id, dest, selected_image, script, env, envelope, capture)
    if diagnostic.get("classification") in {"oom_killed", "queue_timeout", "execution_timeout", "evicted"}:
        reasons = {"oom_killed": "Owned Joern runtime exhausted its memory limit; increase memory only with sufficient capacity",
                   "queue_timeout": "Joern startup/resource wait expired; review capacity and runtime prerequisites or increase its queue budget",
                   "execution_timeout": "Joern execution budget expired; review progress and increase its execution budget before retrying",
                   "evicted": "Owned Joern runtime was evicted; review node memory and scratch capacity"}
        raise _resource_error(policy, reasons[diagnostic["classification"]] + "; coverage remains incomplete", failed=True, diagnostic=diagnostic)
    duration = (datetime.utcnow() - t0).total_seconds()

    # Only the exact controller markers form the parse receipt. A normal Pod
    # exit, a partial CPG file, or an absent/contradictory receipt is not success.
    parse_codes = re.findall(rf"^{re.escape(_PARSE_MARK)}([0-9]{{1,3}})$", out, re.MULTILINE)
    parse_rc = int(parse_codes[0]) if len(parse_codes) == 1 else None
    cpg_nonempty = out.splitlines().count(_CPG_OK_MARK) == 1
    parse_ok = rc == 0 and parse_rc == 0 and cpg_nonempty
    parse_diagnostics = {
        "stage": "parse", "frontend": joern_lang,
        "status": "completed" if parse_ok else "failed",
        "parse_exit_code": parse_rc, "job_exit_code": rc,
        "cpg_nonempty": cpg_nonempty,
    }
    if not parse_ok:
        reason = "joern runtime failed to run" if rc == -1 else "CPG generation failed"
        reason_code = ("runtime_failed" if rc == -1 else "parse_receipt_missing" if parse_rc is None
                       else "frontend_failed" if parse_rc != 0 else "cpg_missing_or_empty" if not cpg_nonempty
                       else "job_failed")
        diagnostic = (str(err or "") + ("\n" if err and out else "") + str(out or "")).strip()
        parse_diagnostics.update(reason_code=reason_code, output_excerpt=diagnostic[:2000],
                                 output_truncated=len(diagnostic) > 2000)
        await send(repo_id, f"Joern: {reason} (frontend={joern_lang}, parse rc={parse_rc}, job rc={rc}): {diagnostic[:200]}", level="warning")
        return [], {"available": True, "cpg_generated": False, "reason": reason,
                    "runtime": runtime, "language": language, "duration_seconds": duration,
                    "parse_diagnostics": parse_diagnostics, "image": selected_image}

    sections = _split_joern_sections(out, total)

    findings: List[Dict[str, Any]] = []
    taint_findings: List[Dict[str, Any]] = []
    callgraph_edges: List[Dict[str, Any]] = []
    hotspots: List[Dict[str, Any]] = []
    taint_diagnostics: Dict[str, Any] = {
        "query_count": len(taint_qs), "query_outcomes": [],
        "queries_without_output": 0, "queries_without_valid_flows": 0,
    }

    query_outcomes = []
    for (i, kind, meta) in kinds:
        sec = sections.get(i, "")
        codes = re.findall(rf"^{re.escape(_QUERY_RC_MARK)}{i}__([0-9]{{1,3}})$", sec, re.MULTILINE)
        query_rc = int(codes[0]) if len(codes) == 1 else None
        failed_query = query_rc != 0 or bool(re.search(r"^QUERY_ERROR:", sec, re.MULTILINE))
        query_outcomes.append({"index": i, "kind": kind, "exit_code": query_rc,
                               "status": "failed" if failed_query else "completed"})
        if failed_query:
            if kind == "taint":
                taint_diagnostics["query_outcomes"].append({"title": (meta or {}).get("title", "taint query"),
                    "status": "failed", "reason": "Joern query failed or its completion receipt was missing"})
            continue
        sec = re.sub(rf"^{re.escape(_QUERY_RC_MARK)}{i}__[0-9]{{1,3}}$", "", sec, flags=re.MULTILINE)
        if kind == "taint":
            q = meta or {}
            if not sec.strip():
                taint_diagnostics["queries_without_output"] += 1
                taint_diagnostics["query_outcomes"].append({
                    "title": q.get("title", "taint query"), "status": "failed",
                    "reason": "Joern query returned no output",
                })
                continue
            flows = _parse_flow_output(sec)
            if flows:
                q_status = "completed"
            else:
                taint_diagnostics["queries_without_valid_flows"] += 1
                q_status = "completed_no_valid_flows"
            taint_diagnostics["query_outcomes"].append({
                "title": q.get("title", "taint query"), "status": q_status,
                "flow_count": len(flows),
            })
            for flow in flows:
                finding = _taint_finding(q, flow)
                findings.append(finding)
                taint_findings.append(finding)
        elif kind == "callgraph":
            callgraph_edges = _parse_json_output(sec)
        elif kind == "complexity":
            hotspots = _parse_json_output(sec)

    await send(repo_id, f"Joern: CPG queries returned in {duration:.1f}s - {len(taint_findings)} flows, {len(callgraph_edges)} call edges, {len(hotspots)} hotspots", level="info")

    # Content identity is handled by the cluster container runtime (containerd
    # resolves the image by digest); record that provenance path explicitly.
    image_validation = image_validation or {
        "image": selected_image,
        "validated": True,
        "runtime": runtime,
        "immutable_reference": "@sha256:" in selected_image,
        "image_id": "",
        "reason": "executed via kubernetes job (image resolved by cluster container runtime)",
    }
    cpg_summary = {
        "available": True,
        "resource_policy": policy,
        "runtime_diagnostic": diagnostic,
        "validated": True,
        "image_validation": image_validation,
        "cpg_generated": True,
        "parse_diagnostics": parse_diagnostics,
        "cpg_path": "",
        "language": language,
        "duration_seconds": duration,
        "runtime": runtime,
        "taint_flows": len(taint_findings),
        "taint_query_diagnostics": taint_diagnostics,
        "query_outcomes": query_outcomes,
        "callgraph_edges": len(callgraph_edges),
        "complexity_hotspots": len(hotspots),
        "data_flows": [
            {
                "title": f.get("title", ""),
                "source": f.get("data_flow", {}).get("source", ""),
                "sink": f.get("data_flow", {}).get("sink", ""),
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "cvss": f.get("cvss", 0),
                "path_summary": f.get("data_flow", {}).get("path_summary", ""),
            }
            for f in taint_findings[:50]
        ],
        "sensitive_callsites": callgraph_edges[:100],
        "hotspot_methods": [
            {"name": h.get("name", ""), "file": h.get("file", ""), "lines": h.get("lines", 0)}
            for h in sorted(hotspots, key=lambda x: x.get("lines", 0), reverse=True)[:30]
        ],
    }
    return findings, cpg_summary


async def _run_joern_scan(
    dest: Path,
    repo_id: int,
    language: str,
    send: Callable,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Main entry point: run full Joern CPG analysis in container pod during Phase 1."""
    if os.environ.get("LOTUS_DISABLE_JOERN", "").strip().lower() in ("1", "true", "yes", "on"):
        await send(repo_id, "Joern disabled (LOTUS_DISABLE_JOERN); CPG analysis skipped", level="info")
        return [], {"available": False, "reason": "disabled_by_env"}

    # Kubernetes-first: when the cluster runtime is selected, run the whole CPG
    # analysis as one Job.  This runs before the Docker-only image validation so
    # a host without a local Docker daemon still gets full Joern coverage.
    try:
        from backend import k8s_runtime as kr
        if await kr.use_k8s_runtime(repo_id):
            return await _run_joern_scan_k8s(dest, repo_id, language, send)
    except Exception as exc:
        if getattr(exc, "resource_policy", None):
            raise
        await send(repo_id, f"Joern: Kubernetes analysis unavailable ({exc}); selected runtime preserved", level="warning")
        return [], {"available": False, "cpg_generated": False,
                    "reason": f"Kubernetes analysis unavailable: {str(exc)[:500]}"}

    if not _joern_available():
        await send(repo_id, "Joern container pod unavailable; CPG analysis skipped.", level="warning")
        return [], {"available": False, "reason": "docker or joern image unavailable"}

    image_validation = _validate_joern_image()
    if not image_validation.get("validated"):
        await send(
            repo_id,
            f"Joern image validation failed; CPG analysis skipped ({image_validation.get('reason', 'unknown')})",
            level="warning",
        )
        return [], {
            "available": False,
            "validated": False,
            "cpg_generated": False,
            "reason": "Joern image could not be content-identity validated",
            "image_validation": image_validation,
        }

    return await _run_joern_scan_job(dest, repo_id, language, send,
                                     runtime="docker", image_validation=image_validation)


def execution_complete(summary: Dict[str, Any]) -> bool:
    """Recorded query failures remain failures even when a CPG artifact exists."""
    if not isinstance(summary, dict) or summary.get("cpg_generated") is not True or summary.get("execution_complete") is False:
        return False
    queries = summary.get("query_outcomes", [])
    if not isinstance(queries, list) or any(not isinstance(r, dict) or r.get("status") != "completed" for r in queries):
        return False
    diagnostics = summary.get("taint_query_diagnostics") or {}
    if not isinstance(diagnostics, dict):
        return False
    missing = diagnostics.get("queries_without_output", 0)
    outcomes = diagnostics.get("query_outcomes", [])
    return (type(missing) is int and missing == 0 and isinstance(outcomes, list)
            and all(isinstance(row, dict) and row.get("status") in {"completed", "completed_no_valid_flows"}
                    for row in outcomes))


async def run_joern_scan(dest: Path, repo_id: int, language: str, send: Callable):
    """Bind all Joern runtime observations to its one canonical audit task.

    Pod completion is not analyzer success: only the adapter's parsed result
    supplies the terminal task event. Reset context even on cancellation.
    """
    from backend import k8s_runtime as kr
    from backend.ai_runtime import active_audit_context

    context = active_audit_context()
    identity = None
    detail_id = f"{repo_id}-tool-joern-cpg"
    if context is not None and int(context.repo_id) == int(repo_id):
        identity = {"repo_id": int(repo_id), "scan_job_id": int(context.job_id),
                    "task_name": "joern-cpg", "task_detail_id": detail_id}
    token = kr.TOOL_TASK.set(identity)
    try:
        await send(repo_id, "▶ Joern CPG analysis starting", detail_id=detail_id,
                   detail={"tool": "joern-cpg", "category": "cpg", "status": "running"})
        try:
            findings, summary = await _run_joern_scan(dest, repo_id, language, send)
        except Exception as exc:
            await send(repo_id, f"✗ Joern CPG analysis failed: {str(exc)[:500]}", level="warning",
                       detail_id=detail_id, detail={"tool": "joern-cpg", "category": "cpg",
                                                   "status": "failed", "reason": str(exc)[:500],
                                                   **{key: getattr(exc, key) for key in ("configure_tool", "parent_task", "resource_policy", "runtime_diagnostic") if hasattr(exc, key)}})
            raise
        summary["execution_complete"] = execution_complete(summary)
        if summary.get("cpg_generated") and not summary["execution_complete"]:
            summary.setdefault("reason", "CPG generated, but recorded Joern query outcomes are incomplete or failed")
        summary.setdefault("source_scope_limitations", "CPG existence and query results do not establish that every source file parsed or every program edge was mapped.")
        status = ("skipped" if summary.get("reason") == "disabled_by_env" else
                  "completed" if summary["execution_complete"] else "failed")
        reason = summary.get("reason") or ("CPG analysis completed" if status == "completed" else "CPG analysis did not complete")
        marker = {"completed": "✓", "failed": "✗", "skipped": "⊘"}[status]
        await send(repo_id, f"{marker} Joern CPG {status}: {reason}",
                   level="warning" if status == "failed" else "info", detail_id=detail_id,
                   detail={"tool": "joern-cpg", "category": "cpg", "status": status,
                           "reason": reason, "count": len(findings), "lead_count": len(findings),
                           "result_type": "leads"})
        return findings, summary
    finally:
        kr.TOOL_TASK.reset(token)
