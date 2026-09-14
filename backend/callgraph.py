"""Lightweight cross-file call graph tracker for inter-procedural taint analysis.

Provides basic cross-file taint tracking without requiring Joern/JVM.
Traces function definitions, imports, and call sites to find paths from
untrusted sources to dangerous sinks across module boundaries.
"""
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

def build_call_graph(dest: Path, language: str, max_files: int = 200) -> Dict[str, Any]:
    """Build a lightweight call graph from source files.
    
    Args:
        dest: Path to the repository root.
        language: Detected language (python, node, ruby/rails, go, java, php).
        max_files: Maximum number of source files to process (default 200).
    
    Returns:
        {
            "functions": {"module.func": {"file": str, "line": int, "params": [...], "calls": [...]}},
            "imports": {"module_a": ["module_b", "module_c"]},
            "taint_paths": [{"source": ..., "sink": ..., "chain": [...], "file_chain": [...]}],
        }
    """
    if type(max_files) is not int or max_files < 1:
        raise ValueError("Callgraph file limit must be a positive integer")
    dest = Path(dest).resolve()
    # Language-specific source extensions
    ext_map = {
        "python": [".py"],
        "node": [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        "ruby/rails": [".rb"],
        "ruby": [".rb"],
        "go": [".go"],
        "java": [".java"],
        "php": [".php"],
        "c/cpp": [".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx"],
        "c": [".c", ".h"],
        "cpp": [".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx"],
        # Languages without a bespoke extractor still get the correct file set +
        # the generic extractor below, so cross-file-taint is never a silent
        # no-op for them (previously they fell back to scanning .py/.js/.rb).
        "rust": [".rs"],
        "kotlin": [".kt", ".kts"],
        "scala": [".scala"],
        "csharp": [".cs"],
        "dotnet": [".cs"],
        "swift": [".swift"],
        "elixir": [".ex", ".exs"],
        "dart": [".dart"],
        "zig": [".zig"],
    }
    # Unknown language: scan the broad universal source set rather than a wrong
    # trio, so the generic extractor has real files to work with.
    _UNIVERSAL_EXTS = [".py", ".js", ".ts", ".rb", ".go", ".java", ".php", ".c",
                       ".cc", ".cpp", ".h", ".hpp", ".rs", ".kt", ".scala", ".cs",
                       ".swift", ".ex", ".exs", ".dart", ".zig"]
    extensions = ext_map.get(language, _UNIVERSAL_EXTS)
    
    # Skip non-source directories
    skip_dirs = {'.git', 'node_modules', 'vendor', '.bundle', '__pycache__', 
                 '.venv', 'venv', 'target', 'build', 'dist'}
    
    functions = {}  # "module.func" -> {file, line, params, calls, has_source, has_sink}
    imports = {}    # "module" -> [imported_modules]
    
    source_files = []
    known_extensions = {ext for values in ext_map.values() for ext in values} | {'.hh'}
    omitted = Counter()
    examples = {}
    discovered = 0
    untraversed = 0
    generic_files = 0
    decoded_with_loss = 0
    examined = 0

    def gap_sample(reason, path):
        samples = examples.setdefault(reason, [])
        if len(samples) < 8:
            try:
                samples.append(Path(path).relative_to(dest).as_posix())
            except (ValueError, TypeError):
                samples.append('.')

    def walk_error(error):
        nonlocal untraversed
        untraversed += 1
        gap_sample('unreadable_directory', getattr(error, 'filename', None))

    # Count recognized source paths even in excluded trees, without reading
    # their content. VCS metadata and Lotus output are outside the source scope.
    # Do not follow directory aliases: their unenumerated scope stays explicit.
    for current, dirs, files in os.walk(dest, followlinks=False, onerror=walk_error):
        current = Path(current)
        retained = []
        for name in sorted(dirs):
            if name in {'.git', '.lotus'}:
                continue
            directory = current / name
            if directory.is_symlink():
                untraversed += 1
                gap_sample('directory_alias', directory)
            else:
                retained.append(name)
        dirs[:] = retained
        for name in sorted(files):
            path = current / name
            if path.suffix.lower() not in known_extensions:
                continue
            discovered += 1
            relative = path.relative_to(dest)
            if set(part.lower() for part in relative.parts[:-1]) & skip_dirs:
                reason = 'excluded_directory'
            elif path.suffix.lower() not in extensions:
                reason = 'language_filter'
            else:
                reason = ''
                try:
                    if not path.resolve().is_relative_to(dest) or not path.is_file():
                        reason = 'unsafe_path'
                    elif path.stat().st_size > 500_000:
                        reason = 'oversized'
                except (OSError, RuntimeError):
                    reason = 'unreadable'
            if reason:
                omitted[reason] += 1
                gap_sample(reason, path)
            else:
                source_files.append(path)
    source_files.sort(key=lambda path: path.relative_to(dest).as_posix())
    omitted['file_cap'] = max(0, len(source_files) - max_files)
    for path in source_files[max_files:max_files + 8]:
        gap_sample('file_cap', path)
    
    # Phase 1: Extract function definitions and calls
    for src_file in source_files[:max_files]:
        try:
            with src_file.open('rb') as handle:
                raw = handle.read(500_001)
            if len(raw) > 500_000:
                omitted['oversized'] += 1
                gap_sample('oversized', src_file)
                continue
            try:
                text = raw.decode('utf-8')
            except UnicodeDecodeError:
                text = raw.decode('utf-8', errors='ignore')
                decoded_with_loss += 1
                gap_sample('decoding_loss', src_file)
        except OSError:
            omitted['unreadable'] += 1
            gap_sample('unreadable', src_file)
            continue
        examined += 1
        
        module_name = str(src_file.relative_to(dest)).replace('/', '.').rsplit('.', 1)[0]

        # Dispatch by file extension so both single-language and universal
        # (unknown-language) scans route each file to the right bespoke
        # extractor; anything without one falls to the generic extractor so no
        # source file is silently ignored.
        ext = src_file.suffix.lower()
        if ext == ".py":
            _extract_python(text, module_name, src_file, functions, imports)
        elif ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
            _extract_node(text, module_name, src_file, functions, imports)
        elif ext == ".rb":
            _extract_ruby(text, module_name, src_file, functions, imports)
        elif ext == ".go":
            _extract_go(text, module_name, src_file, functions, imports)
        elif ext == ".java":
            _extract_java(text, module_name, src_file, functions, imports)
        elif ext in (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".hh"):
            _extract_c(text, module_name, src_file, functions, imports)
        elif ext == ".php":
            _extract_php(text, module_name, src_file, functions, imports)
        else:
            generic_files += 1
            gap_sample('unsupported_parser', src_file)
            _extract_generic(text, module_name, src_file, functions, imports)
    
    # Phase 2: Find taint paths (source -> ... -> sink across files)
    taint_paths = _find_cross_file_taint_paths(functions, imports, language)
    
    reasons = {
        'file_cap': 'Source files omitted by the configured callgraph file cap',
        'excluded_directory': 'Source files in excluded dependency/generated directories were not analyzed',
        'language_filter': 'Source files outside the selected language were not analyzed',
        'oversized': 'Source files larger than 500000 bytes were not analyzed',
        'unreadable': 'Source files could not be read',
        'unsafe_path': 'Source paths outside the captured root or without regular-file content were not read',
    }
    gaps = [{'code': code, 'count': count, 'reason': reasons[code], 'examples': examples.get(code, [])}
            for code, count in sorted(omitted.items()) if count]
    for code, count, reason in (
        ('unsupported_parser', generic_files, 'Only a generic function inventory is available; language-specific callgraph parsing is unsupported'),
        ('decoding_loss', decoded_with_loss, 'Invalid UTF-8 bytes were omitted from parsed source text'),
        ('untraversed_directory', untraversed, 'Directories could not be enumerated safely; their omitted source-file count is unknown'),
    ):
        if count:
            gap_examples = examples.get(code, [])
            if code == 'untraversed_directory':
                gap_examples = sorted(examples.get('directory_alias', []) + examples.get('unreadable_directory', []))[:8]
            gaps.append({'code': code, 'count': count, 'reason': reason, 'examples': gap_examples})
    if not discovered:
        gaps.append({'code': 'no_source_files', 'count': 0,
                     'reason': 'No recognized source files were inventoried for callgraph analysis', 'examples': []})
    scope = {
        'schema_version': 1, 'language': language, 'max_files': max_files,
        'max_file_bytes': 500_000, 'discovered_source_files': discovered,
        'eligible_source_files': len(source_files), 'attempted_files': min(len(source_files), max_files),
        'examined_files': examined, 'omitted_files': sum(omitted.values()),
        'omitted_by_reason': {code: count for code, count in sorted(omitted.items()) if count},
        'unsupported_parser_files': generic_files, 'decoding_loss_files': decoded_with_loss,
        'untraversed_directories': untraversed, 'inventory_complete': untraversed == 0,
        'complete': not gaps, 'coverage_gaps': gaps,
        'excluded_directories': sorted(skip_dirs - {'.git'}),
        'limitations': 'Lightweight static callgraph extraction; file accounting does not establish semantic or dynamic coverage.',
    }
    return {
        "functions": functions,
        "functions_count": len(functions),
        "modules_count": len(set(f.rsplit('.', 1)[0] for f in functions if '.' in f)),
        "taint_paths": taint_paths,
        "cross_file_calls": sum(1 for f in functions.values() if f.get("calls")),
        "scope": scope,
    }


def _extract_python(text: str, module_name: str, src_file: Path, functions: Dict, imports: Dict):
    lines = text.splitlines()
    imports[module_name] = []
    for line in lines:
        if line.startswith("import ") or line.startswith("from "):
            parts = line.split()
            if len(parts) >= 2:
                imports[module_name].append(parts[1])
                
    func_pattern = re.compile(r'def\s+([a-zA-Z_]\w*)\s*\((.*?)\):')
    call_pattern = re.compile(r'([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*\(')
    
    current_func = None
    for i, line in enumerate(lines):
        m = func_pattern.search(line)
        if m:
            current_func = f"{module_name}.{m.group(1)}"
            functions[current_func] = {
                "file": str(src_file), "line": i + 1,
                "params": [p.strip().split(':')[0] for p in m.group(2).split(',') if p.strip()],
                "calls": [], "has_source": False, "has_sink": False
            }
            continue
        if current_func:
            for call_m in call_pattern.finditer(line):
                call_name = call_m.group(1)
                if call_name not in ("def", "if", "while", "for", "return"):
                    functions[current_func]["calls"].append(call_name)
            if any(s in line for s in ["request.args", "request.form", "request.json", "os.getenv", "sys.argv"]):
                functions[current_func]["has_source"] = True
            if any(s in line for s in ["eval(", "exec(", "subprocess.", "os.system(", ".execute(", "open("]):
                functions[current_func]["has_sink"] = True


def _extract_node(text: str, module_name: str, src_file: Path, functions: Dict, imports: Dict):
    lines = text.splitlines()
    imports[module_name] = []
    for line in lines:
        if "require(" in line or line.startswith("import "):
            imports[module_name].append(line)
            
    func_pattern = re.compile(r'(?:function\s+([a-zA-Z_]\w*)\s*\(|([a-zA-Z_]\w*)\s*=\s*function\s*\(|([a-zA-Z_]\w*)\s*=\s*\([^)]*\)\s*=>)')
    call_pattern = re.compile(r'([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*\(')
    
    current_func = None
    for i, line in enumerate(lines):
        m = func_pattern.search(line)
        if m:
            fname = m.group(1) or m.group(2) or m.group(3) or "anonymous"
            current_func = f"{module_name}.{fname}"
            functions[current_func] = {
                "file": str(src_file), "line": i + 1, "params": [],
                "calls": [], "has_source": False, "has_sink": False
            }
            continue
        if current_func:
            for call_m in call_pattern.finditer(line):
                call_name = call_m.group(1)
                if call_name not in ("function", "if", "while", "for", "return"):
                    functions[current_func]["calls"].append(call_name)
            if any(s in line for s in ["req.query", "req.body", "process.argv", "process.env"]):
                functions[current_func]["has_source"] = True
            if any(s in line for s in ["eval(", "exec(", "child_process", "fs.readFile", "db.query("]):
                functions[current_func]["has_sink"] = True


def _extract_ruby(text: str, module_name: str, src_file: Path, functions: Dict, imports: Dict):
    lines = text.splitlines()
    imports[module_name] = []
    for line in lines:
        if line.strip().startswith("require ") or line.strip().startswith("include "):
            imports[module_name].append(line)
            
    func_pattern = re.compile(r'def\s+([a-zA-Z_]\w*[=!?]?)\s*(?:\((.*?)\))?')
    call_pattern = re.compile(r'([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*\(') # Simplified
    
    current_func = None
    for i, line in enumerate(lines):
        m = func_pattern.search(line)
        if m:
            current_func = f"{module_name}.{m.group(1)}"
            functions[current_func] = {
                "file": str(src_file), "line": i + 1, "params": [],
                "calls": [], "has_source": False, "has_sink": False
            }
            continue
        if current_func:
            for call_m in call_pattern.finditer(line):
                call_name = call_m.group(1)
                functions[current_func]["calls"].append(call_name)
            if any(s in line for s in ["params[", "request.", "ENV["]):
                functions[current_func]["has_source"] = True
            if any(s in line for s in ["eval(", "system(", "exec(", "`", "File.read", "ActiveRecord::Base.connection.execute"]):
                functions[current_func]["has_sink"] = True


def _extract_go(text: str, module_name: str, src_file: Path, functions: Dict, imports: Dict):
    lines = text.splitlines()
    imports[module_name] = []
    
    func_pattern = re.compile(r'func\s+(?:\([^)]+\)\s+)?([a-zA-Z_]\w*)\s*\((.*?)\)')
    call_pattern = re.compile(r'([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*\(')
    
    current_func = None
    for i, line in enumerate(lines):
        m = func_pattern.search(line)
        if m:
            current_func = f"{module_name}.{m.group(1)}"
            functions[current_func] = {
                "file": str(src_file), "line": i + 1, "params": [],
                "calls": [], "has_source": False, "has_sink": False
            }
            continue
        if current_func:
            for call_m in call_pattern.finditer(line):
                call_name = call_m.group(1)
                functions[current_func]["calls"].append(call_name)
            if any(s in line for s in ["r.URL.Query", "r.Form", "os.Args", "os.Getenv"]):
                functions[current_func]["has_source"] = True
            if any(s in line for s in ["exec.Command", "os.Open", "sql.Open", "db.Query"]):
                functions[current_func]["has_sink"] = True


def _extract_java(text: str, module_name: str, src_file: Path, functions: Dict, imports: Dict):
    lines = text.splitlines()
    imports[module_name] = []
    
    func_pattern = re.compile(r'(?:public|private|protected)\s+(?:static\s+)?[a-zA-Z_][\w<>,\[\]]*\s+([a-zA-Z_]\w*)\s*\((.*?)\)')
    call_pattern = re.compile(r'([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*\(')
    
    current_func = None
    for i, line in enumerate(lines):
        m = func_pattern.search(line)
        if m:
            current_func = f"{module_name}.{m.group(1)}"
            functions[current_func] = {
                "file": str(src_file), "line": i + 1, "params": [],
                "calls": [], "has_source": False, "has_sink": False
            }
            continue
        if current_func:
            for call_m in call_pattern.finditer(line):
                call_name = call_m.group(1)
                functions[current_func]["calls"].append(call_name)
            if any(s in line for s in ["request.getParameter", "System.getenv", "args["]):
                functions[current_func]["has_source"] = True
            if any(s in line for s in ["Runtime.getRuntime().exec", "ProcessBuilder", "Statement.executeQuery"]):
                functions[current_func]["has_sink"] = True


# C/C++ control-flow keywords that look like calls (``if (``) but are not.
_C_KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "catch", "do", "else",
    "case", "goto", "static_cast", "dynamic_cast", "reinterpret_cast", "const_cast",
    "and", "or", "not", "assert", "typeof", "decltype", "alignof",
}
# Untrusted-input sources / dangerous sinks for C/C++, aligned with the
# taint-proximity analyzer so both surface the same crown-jewel patterns.
_C_SOURCES = ("argv", "getenv(", "read(", "recv(", "recvfrom(", "fgets(", "scanf(",
              "sscanf(", "fread(", "getline(", "stdin", "environ", "std::cin")
_C_SINKS = ("system(", "popen(", "execl", "execv", "execlp", "execvp", "execve",
            "strcpy(", "strcat(", "sprintf(", "vsprintf(", "memcpy(", "memmove(",
            "gets(", "alloca(", "strncpy(", "snprintf(")

# Function definition (not a call/prototype): ``<type...> name(<params no ; { >) [const] {``
# ``[^;{]*`` params exclude prototypes (end ``;``) and statements; a trailing/next
# ``{`` requirement (checked by the caller) confirms it's a real body.
_C_FUNC_DEF = re.compile(
    r'^[A-Za-z_][\w\s\*&:<>,~]*?[\s\*&:~]'   # return type / qualifiers (ptrs, refs, ns, templates)
    r'([A-Za-z_]\w*)'                          # captured function (or Class::method) leaf name
    r'\s*\(([^;{]*)\)\s*'                      # params without ; or {
    r'(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:->[^;{]+)?'
    r'\{?\s*$'
)
_C_CALL = re.compile(r'\b([A-Za-z_]\w*)\s*\(')


def _c_mark_source_sink(line: str, fn: Dict) -> None:
    if any(s in line for s in _C_SOURCES):
        fn["has_source"] = True
    if any(s in line for s in _C_SINKS):
        fn["has_sink"] = True


def _extract_c(text: str, module_name: str, src_file: Path, functions: Dict, imports: Dict):
    """Heuristic C/C++ function + call extraction.

    Regex-based (no compiler): recognises function *definitions* (body ``{``
    present) versus prototypes/calls, records inter-function calls, and flags
    untrusted-input sources and dangerous sinks so the cross-file/sink-first
    taint passes can connect them. Approximate by design - it feeds a lead
    generator, so recall matters more than perfect parsing.
    """
    lines = text.splitlines()
    imports[module_name] = []
    for line in lines:
        s = line.strip()
        if s.startswith("#include"):
            imports[module_name].append(s[len("#include"):].strip().strip('"<>'))

    current_func = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "*", "/*", "#")):
            continue
        m = _C_FUNC_DEF.match(line)
        if m and m.group(1) not in _C_KEYWORDS:
            # Confirm a real body: ``{`` on this line or the next non-blank line
            # (guards against prototypes, which end in ``;``, and macro noise).
            ends_brace = stripped.endswith("{")
            next_brace = False
            if not ends_brace:
                for j in range(i + 1, min(i + 3, len(lines))):
                    nb = lines[j].strip()
                    if not nb:
                        continue
                    next_brace = nb.startswith("{")
                    break
            if ends_brace or next_brace:
                current_func = f"{module_name}.{m.group(1)}"
                functions[current_func] = {
                    "file": str(src_file), "line": i + 1,
                    "params": [p.strip() for p in m.group(2).split(',') if p.strip()],
                    "calls": [], "has_source": False, "has_sink": False,
                }
                _c_mark_source_sink(line, functions[current_func])
                continue
        if current_func:
            for cm in _C_CALL.finditer(line):
                name = cm.group(1)
                if name not in _C_KEYWORDS:
                    functions[current_func]["calls"].append(name)
            _c_mark_source_sink(line, functions[current_func])


def _extract_php(text: str, module_name: str, src_file: Path, functions: Dict, imports: Dict):
    """Heuristic PHP function + call extraction (ext_map listed PHP but no
    extractor existed, so the call graph was silently empty for PHP too)."""
    lines = text.splitlines()
    imports[module_name] = []
    for line in lines:
        s = line.strip()
        if s.startswith(("require", "include", "use ")):
            imports[module_name].append(s)

    func_pattern = re.compile(r'function\s+([a-zA-Z_]\w*)\s*\((.*?)\)')
    call_pattern = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')
    current_func = None
    for i, line in enumerate(lines):
        m = func_pattern.search(line)
        if m:
            current_func = f"{module_name}.{m.group(1)}"
            functions[current_func] = {
                "file": str(src_file), "line": i + 1,
                "params": [p.strip() for p in m.group(2).split(',') if p.strip()],
                "calls": [], "has_source": False, "has_sink": False,
            }
            continue
        if current_func:
            for cm in call_pattern.finditer(line):
                if cm.group(1) not in ("function", "if", "while", "for", "return", "foreach", "switch"):
                    functions[current_func]["calls"].append(cm.group(1))
            if any(s in line for s in ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES", "php://input", "getenv("]):
                functions[current_func]["has_source"] = True
            if any(s in line for s in ["eval(", "exec(", "system(", "shell_exec", "passthru(", "unserialize(", "include(", "require(", "->query("]):
                functions[current_func]["has_sink"] = True


# Universal function-definition forms for languages without a bespoke extractor
# (Rust, Kotlin, Swift, Scala, C#, Elixir, Dart, Zig, ...). Best-effort.
_GENERIC_FUNC = re.compile(
    r"(?:\bfn\s+(?P<n1>[A-Za-z_]\w*)\s*[<(])"                          # rust
    r"|(?:\bfun\s+(?P<n2>[A-Za-z_]\w*)\s*\()"                          # kotlin
    r"|(?:\bfunc\s+(?P<n3>[A-Za-z_]\w*)\s*\()"                         # swift
    r"|(?:\b(?:def|defp)\s+(?P<n4>[A-Za-z_]\w*)\s*[\(,])"             # scala/elixir
    r"|(?:(?:public|private|protected|internal|static|override|virtual|final)\s+)+"
    r"[A-Za-z_][\w<>,\[\]\.\* &:?]*\s+(?P<n5>[A-Za-z_]\w*)\s*\([^;{]*\)\s*\{?"  # C#/typed
)
_GENERIC_CALL = re.compile(r"(?:\.|\b)([A-Za-z_]\w{2,})\s*\(")
_GENERIC_KEYWORDS = {"if", "for", "while", "switch", "return", "catch", "match",
                     "when", "with", "case", "do", "else", "fn", "fun", "func", "def"}
_GENERIC_SOURCES = ("argv", "std::env::args", "env::var", "getenv", "os.args",
                    "req.query", "req.body", "req.params", "request.", "params[",
                    "stdin", "read_line", "recv", "socket", "http", "@requestparam",
                    "@pathvariable", "form(", "queryparam", "environment")
_GENERIC_SINKS = ("command::new", "process::command", "system(", "popen(", "exec",
                  "eval(", "spawn(", "runtime.exec", "processbuilder", "sql", ".query(",
                  ".execute(", "deserialize", "unmarshal", "readobject", "fromjson",
                  "file.read", "file.write", "fs::", "open(", "include(", "render(",
                  "template", "unserialize", "loadclass", "reflect")


def _extract_generic(text: str, module_name: str, src_file: Path, functions: Dict, imports: Dict):
    """Language-agnostic best-effort extractor for source files that have no
    bespoke extractor, so cross-file-taint produces a real function inventory
    (with source/sink flags) instead of silently nothing."""
    lines = text.splitlines()
    imports.setdefault(module_name, [])
    for line in lines[:2000]:
        s = line.strip()
        if s.startswith(("import ", "use ", "require", "#include", "using ")):
            imports[module_name].append(s[:200])
    current_func = None
    for i, line in enumerate(lines):
        if len(line) > 4000:
            continue
        m = _GENERIC_FUNC.search(line)
        if m:
            name = next((m.group(g) for g in ("n1", "n2", "n3", "n4", "n5") if m.group(g)), None)
            if name and name.lower() not in _GENERIC_KEYWORDS:
                current_func = f"{module_name}.{name}"
                functions[current_func] = {
                    "file": str(src_file), "line": i + 1, "params": [],
                    "calls": [], "has_source": False, "has_sink": False,
                }
                continue
        if current_func:
            for cm in _GENERIC_CALL.finditer(line):
                if cm.group(1).lower() not in _GENERIC_KEYWORDS:
                    functions[current_func]["calls"].append(cm.group(1))
            low = line.lower()
            if any(t in low for t in _GENERIC_SOURCES):
                functions[current_func]["has_source"] = True
            if any(t in low for t in _GENERIC_SINKS):
                functions[current_func]["has_sink"] = True


def _find_cross_file_taint_paths(functions: Dict, imports: Dict, language: str) -> List[Dict]:
    taint_paths = []
    
    # Mapping of potential short call names to full function names
    name_to_full = {}
    for f in functions.keys():
        short = f.split('.')[-1]
        if short not in name_to_full:
            name_to_full[short] = []
        name_to_full[short].append(f)

    # Build reverse map: module_name -> set of imported module names
    # This is used to reduce false positive taint paths from short-name
    # collisions (e.g. parse() in auth.py matching parse() in xml_parser.py)
    module_imports = {}
    for mod, imp_list in imports.items():
        module_imports[mod] = set()
        for imp in imp_list:
            # Normalize: "backend.analysis" -> "backend.analysis", also store leaf
            module_imports[mod].add(imp)
            if "." in imp:
                module_imports[mod].add(imp.rsplit(".", 1)[-1])

    for func_a_name, func_a in functions.items():
        if not func_a.get("has_source"):
            continue

        caller_module = func_a_name.rsplit(".", 1)[0] if "." in func_a_name else ""
        caller_imports = module_imports.get(caller_module, set())

        for call_name in func_a.get("calls", []):
            short_call = call_name.split('.')[-1]
            possible_targets = _resolve_call_targets(func_a_name, short_call, name_to_full, functions)

            for target_func in possible_targets:
                if target_func == func_a_name:
                    continue
                if not functions[target_func].get("has_sink"):
                    continue

                file_a = func_a["file"]
                file_b = functions[target_func]["file"]
                
                if file_a == file_b:
                    continue

                # Validate: does the calling module import the target module?
                # This reduces false positives from common function names
                target_module = target_func.rsplit(".", 1)[0] if "." in target_func else ""
                target_leaf = target_module.rsplit(".", 1)[-1] if "." in target_module else target_module
                has_import = (
                    not caller_imports  # No import info - allow (legacy compat)
                    or target_module in caller_imports
                    or target_leaf in caller_imports
                    or call_name.split(".")[0] in caller_imports  # e.g. "auth.validate"
                )
                if not has_import:
                    continue

                taint_paths.append({
                    "source": func_a_name,
                    "sink": target_func,
                    "chain": [func_a_name, target_func],
                    "file_chain": [file_a, file_b]
                })

    # Multi-hop engine (same-file AND cross-file, import-scoped + param-gated).
    # This subsumes the direct-call cross-file loop above for depth>1 and adds a
    # full per-hop file trail. Direct depth-1 hits are deduped by (source, sink).
    for path in sink_first_paths(
        {"functions": functions}, language, max_hops=5, module_imports=module_imports
    ):
        key = (path.get("source"), path.get("sink"))
        if any((t.get("source"), t.get("sink")) == key for t in taint_paths):
            continue
        taint_paths.append({
            "source": path["source"],
            "sink": path["sink"],
            # Prefer the forward (source->sink) chain the engine now emits.
            "chain": path.get("chain_forward") or list(reversed(path.get("chain", []))),
            "file_chain": path.get("file_chain")
            or [path.get("source_file", ""), path.get("sink_file", "")],
            "line_chain": path.get("line_chain") or [],
            "hops": path.get("hops", len(path.get("chain", [])) - 1),
        })

    return taint_paths


def _module_of(func_full: str) -> str:
    return func_full.rsplit(".", 1)[0] if "." in func_full else ""


def _resolve_call_targets(
    caller_full: str,
    short_name: str,
    name_to_full: Dict[str, List[str]],
    functions: Dict,
) -> List[str]:
    """Resolve an unqualified call to its likely definition(s).

    Local-shadowing rule: an unqualified call resolves to a definition in the
    caller's own file when one exists, mirroring real name resolution in Python/
    JS/most languages. This removes the dominant cross-file false-positive where
    a common short name (``run``/``process``/``parse``) collides with an
    unrelated - and often unimported - function in another file.
    """
    candidates = [c for c in name_to_full.get(short_name, []) if c != caller_full]
    caller_file = functions.get(caller_full, {}).get("file", "")
    same_file = [c for c in candidates if functions.get(c, {}).get("file", "") == caller_file]
    return same_file or candidates


def _cross_file_edge_allowed(
    caller: str,
    callee: str,
    functions: Dict,
    module_imports: Optional[Dict[str, Set[str]]],
) -> bool:
    """Import-scope a cross-file taint hop to kill short-name collisions.

    Same-file hops are always allowed. Cross-file hops are allowed only when the
    caller's module actually imports the callee's module (leaf or full), or when
    we have no import info for the caller (legacy compat / languages without a
    reliable import map)."""
    cf = functions.get(caller, {}).get("file", "")
    ef = functions.get(callee, {}).get("file", "")
    if cf and ef and cf == ef:
        return True  # intra-file: no import needed
    if not module_imports:
        return True  # no import graph available -> don't over-prune
    caller_imports = module_imports.get(_module_of(caller), set())
    if not caller_imports:
        return True
    callee_mod = _module_of(callee)
    callee_leaf = callee_mod.rsplit(".", 1)[-1] if "." in callee_mod else callee_mod
    callee_short = callee.split(".")[-1]
    return (
        callee_mod in caller_imports
        or callee_leaf in caller_imports
        or callee_short in caller_imports
    )


def sink_first_paths(
    call_graph: Dict[str, Any],
    language: str,
    max_hops: int = 4,
    max_sinks: int = 80,
    max_results: int = 60,
    module_imports: Optional[Dict[str, Set[str]]] = None,
) -> List[Dict]:
    """BFS backward from sink-bearing functions to source-bearing callers.

    This is the primary inversion over forward grep: start at crown-jewel sinks
    and walk the reverse call graph until an untrusted source is reached. The
    walk is now genuinely multi-hop AND cross-file with two false-positive
    controls:

    * **Import scoping** - a cross-file hop is only followed when the caller's
      module imports the callee's module (via ``module_imports``). This removes
      the classic ``parse()``/``process()`` short-name-collision chains.
    * **Parameter-flow gate** - a hop is only followed when the upstream caller
      can actually carry taint forward, approximated as "the caller reads a
      source OR declares parameters". This prunes zero-arg orchestrators (e.g.
      ``main()``) that merely call a sink without forwarding attacker data. The
      gate is only applied when the extractor populated parameter lists for this
      language (so regex-only languages are not over-pruned).

    Output adds ``chain_forward`` / ``file_chain`` / ``line_chain`` (source->sink
    order) while preserving the legacy ``chain`` (sink->source order) and the
    ``source_file`` / ``sink_file`` / ``hops`` keys existing consumers rely on.
    """
    functions = call_graph.get("functions") or {}
    if not functions:
        return []

    # Reverse edges: callee_short -> [caller_full]
    name_to_full: Dict[str, List[str]] = {}
    for full in functions:
        short = full.split(".")[-1]
        name_to_full.setdefault(short, []).append(full)

    callers_of: Dict[str, Set[str]] = {k: set() for k in functions}
    for caller, meta in functions.items():
        for call in meta.get("calls", []):
            short = call.split(".")[-1]
            # Local-shadowing resolution kills unrelated same-name cross-file edges.
            for callee in _resolve_call_targets(caller, short, name_to_full, functions):
                callers_of.setdefault(callee, set()).add(caller)

    # Only apply the parameter-flow gate when parameters were actually captured
    # for this language (Python/JS/Go/Java/PHP/C populate them; the generic
    # regex extractor does not, so gating there would wrongly prune everything).
    params_available = any(m.get("params") for m in functions.values())

    def _can_forward(node: str) -> bool:
        if not params_available:
            return True
        m = functions.get(node, {})
        return bool(m.get("has_source") or m.get("params"))

    sinks = [n for n, m in functions.items() if m.get("has_sink")]
    results: List[Dict] = []

    for sink in sinks[:max_sinks]:
        # BFS upward. Track the chain so we can emit a per-hop file/line trail.
        queue: List[Tuple[str, List[str]]] = [(sink, [sink])]
        seen = {sink}
        while queue:
            node, chain = queue.pop(0)
            if len(chain) - 1 > max_hops:
                continue
            meta = functions.get(node, {})
            if meta.get("has_source") and node != sink:
                # chain is [sink, ..., source]; forward view reverses it.
                fwd = list(reversed(chain))
                results.append({
                    "source": node,
                    "sink": sink,
                    "chain": chain,  # legacy: sink ... source (backward order)
                    "chain_forward": fwd,  # source ... sink
                    "file_chain": [functions.get(n, {}).get("file", "") for n in fwd],
                    "line_chain": [functions.get(n, {}).get("line", 0) for n in fwd],
                    "hops": len(chain) - 1,
                    "sink_file": functions[sink].get("file", ""),
                    "sink_line": functions[sink].get("line", 0),
                    "source_file": meta.get("file", ""),
                    "source_line": meta.get("line", 0),
                })
                break
            for caller in callers_of.get(node, set()):
                if caller in seen:
                    continue
                # FP control 1: import-scope cross-file hops.
                if not _cross_file_edge_allowed(caller, node, functions, module_imports):
                    continue
                # FP control 2: caller must be able to forward taint.
                if not _can_forward(caller):
                    continue
                seen.add(caller)
                queue.append((caller, chain + [caller]))

        # Same-function source+sink
        sink_meta = functions.get(sink, {})
        if sink_meta.get("has_source") and sink_meta.get("has_sink"):
            results.append({
                "source": sink,
                "sink": sink,
                "chain": [sink],
                "chain_forward": [sink],
                "file_chain": [sink_meta.get("file", "")],
                "line_chain": [sink_meta.get("line", 0)],
                "hops": 0,
                "sink_file": sink_meta.get("file", ""),
                "sink_line": sink_meta.get("line", 0),
                "source_file": sink_meta.get("file", ""),
                "source_line": sink_meta.get("line", 0),
            })

    # Dedup by (source, sink), preferring the shortest chain.
    uniq: Dict[Tuple[str, str], Dict] = {}
    for r in results:
        key = (r["source"], r["sink"])
        if key not in uniq or r["hops"] < uniq[key]["hops"]:
            uniq[key] = r
    return sorted(uniq.values(), key=lambda r: r["hops"])[:max_results]
