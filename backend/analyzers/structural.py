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



def _run_guard_consistency(
    dest: Path,
    language: str,
    prior_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """Sibling-function guard divergence (Skill 49).

    Runs *only* the guard-alternate-path detector. Never re-invokes the full
    high-yield battery (that used to double Phase-1 CPU). If ``prior_findings``
    from an already-run high-yield pass is provided, filter those instead.
    Failures become a visible finding rather than a silent ``pass``.
    """
    results: List[dict] = []
    try:
        if prior_findings:
            src = list(prior_findings)
        else:
            from backend.discovery_engine import guard_alternate_path
            src = list(guard_alternate_path(dest, language) or [])
        for f in src:
            blob = f"{f.get('title') or ''} {f.get('description') or ''}".lower()
            if any(k in blob for k in ("guard", "sibling", "alternate", "authz", "auth ")):
                item = dict(f)
                item["tool"] = "guard-consistency"
                results.append(item)
    except Exception as e:
        results.append({
            "tool": "guard-consistency",
            "title": f"Guard-consistency pass error: {e}",
            "cvss": 0.0,
            "description": str(e)[:400],
            "file": "",
            "line": 0,
            "confidence": "low",
            "qualification": "NO-BOUNDARY",
        })
    return results


def _run_check_referent_mismatch(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """D4/T7: Detect check-then-use patterns where the checked object differs from the used object (TOCTOU, check-referent mismatch)."""
    results = []
    # Patterns: check X, then use Y (different variable/path/parameter)
    patterns_by_lang = {
        'c/cpp': [
            # TOCTOU file operations
            (r'\baccess\s*\([^)]+\)', r'\bopen\s*\(', 'TOCTOU: access() then open() - symlink race window', 7.5),
            (r'\bstat\s*\([^)]+\)', r'\bopen\s*\(', 'TOCTOU: stat() then open() - file may change between calls', 7.0),
            (r'\bstat\s*\([^)]+\)', r'\bfopen\s*\(', 'TOCTOU: stat() then fopen() - file may change between calls', 7.0),
            (r'\brealpath\s*\([^)]+\)', r'\bopen\s*\(', 'TOCTOU: realpath() then open() - symlink race', 6.5),
            (r'\bchmod\s*\(', r'\bopen\s*\(', 'TOCTOU: chmod() then open() - permission race', 6.0),
        ],
        'python': [
            (r'os\.path\.exists\s*\(', r'open\s*\(', 'TOCTOU: os.path.exists() then open() - race window', 6.0),
            (r'os\.access\s*\(', r'open\s*\(', 'TOCTOU: os.access() then open() - race window', 6.5),
            (r'os\.path\.isfile\s*\(', r'open\s*\(', 'TOCTOU: isfile() then open() - race window', 5.5),
        ],
        'node': [
            (r'fs\.existsSync\s*\(', r'fs\.readFileSync\s*\(', 'TOCTOU: existsSync then readFileSync - race window', 6.0),
            (r'fs\.access\s*\(', r'fs\.(readFile|writeFile)\s*\(', 'TOCTOU: access then read/write - race window', 6.0),
        ],
        'go': [
            (r'os\.Stat\s*\(', r'os\.(Open|OpenFile)\s*\(', 'TOCTOU: os.Stat then os.Open - race window', 6.5),
        ],
        'php': [
            (r'\bfile_exists\s*\(', r'\bfile_get_contents\s*\(', 'TOCTOU: file_exists then file_get_contents - race window', 6.0),
            (r'\bis_writable\s*\(', r'\bfile_put_contents\s*\(', 'TOCTOU: is_writable then file_put_contents - race window', 6.5),
        ],
        'ruby/rails': [
            (r'File\.exist\?\s*\(', r'File\.(read|open|write|delete|unlink)\s*\(', 'TOCTOU: File.exist? then File operation - race window', 6.0),
            (r'File\.symlink\?\s*\(', r'File\.(read|open|write|delete)\s*\(', 'TOCTOU: File.symlink? then File operation - symlink race', 6.5),
            (r'File\.stat\s*\(', r'File\.(open|read|write)\s*\(', 'TOCTOU: File.stat then File operation', 6.0),
        ],

    }
    lang_key = {'javascript': 'node', 'ruby': 'ruby/rails', 'typescript': 'node'}.get(language, language)
    patterns = patterns_by_lang.get(lang_key, [])
    if not patterns:
        return results

    _skip_dirs = {'.git', 'node_modules', 'vendor', '__pycache__', '.venv', 'venv',
                  'target', 'build', 'dist', 'test', 'tests', 'spec', 'fixtures', 'examples'}
    _ext_map = {'.c': 'c/cpp', '.cpp': 'c/cpp', '.h': 'c/cpp', '.py': 'python',
                '.go': 'go', '.java': 'java', '.php': 'php', '.js': 'node', '.rb': 'ruby/rails'}

    for f in dest.rglob('*'):
        if not f.is_file():
            continue
        parts = set(f.relative_to(dest).parts)
        if parts & _skip_dirs:
            continue
        if _ext_map.get(f.suffix) != lang_key:
            continue
        try:
            text = f.read_text(errors='ignore')
        except Exception:
            continue
        lines = text.split('\n')
        for check_pat, use_pat, title, cvss in patterns:
            for i, line in enumerate(lines):
                if re.search(check_pat, line):
                    # Look within next 10 lines for the use pattern
                    window = '\n'.join(lines[i+1:i+11])
                    if re.search(use_pat, window):
                        results.append({
                            'tool': 'check-referent-mismatch',
                            'title': title,
                            'cvss': cvss,
                            'description': f'{title}. Check at {f.name}:{i+1}, use within 10 lines. The checked object may differ from the used object due to race condition or symlink swap between the check and the use.',
                            'file': str(f.relative_to(dest)),
                            'line': i + 1,
                            'confidence': 'medium',
                        })
                        if len(results) >= 40:
                            return results
    return results


def _run_single_pass_strip_detection(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """D2/Bug 25: Detect single-pass sanitization that can be bypassed by nested/reconstituted payloads."""
    results = []
    patterns_by_lang = {
        'python': [
            (r"\.replace\s*\(\s*['\"]\.\.\/['\"]", 'Single-pass ../ removal - ....// reconstitutes to ../', 7.0),
            (r"\.replace\s*\(\s*['\"]\.\.\\\\['\"]", 'Single-pass ..\\ removal - reconstitutable', 7.0),
            (r"re\.sub\s*\(\s*['\"]<script", 'Single-pass script tag removal - nesting bypasses', 6.5),
            (r"\.replace\s*\(\s*['\"]javascript:", 'Single-pass javascript: removal - nesting bypasses', 6.5),
        ],
        'php': [
            (r"str_replace\s*\(\s*['\"]\.\.\/['\"]", 'PHP single-pass str_replace ../ - ....// reconstitutes', 7.5),
            (r"str_replace\s*\(\s*['\"]<script", 'PHP single-pass script removal - nesting bypasses', 6.5),
            (r"preg_replace\s*\(\s*['\"]\/\.\.\\\//", 'PHP single-pass regex ../ removal', 7.0),
        ],
        'node': [
            (r"\.replace\s*\(\s*['\"]\.\.\/['\"]", 'JS single-pass ../ removal - ....// reconstitutes', 7.0),
            (r"\.replace\s*\(\s*\/\\\.\\\.\\\/\/", 'JS regex ../ removal - reconstitutable if not global+loop', 7.0),
            (r"\.replaceAll\s*\(\s*['\"]javascript:", 'JS single-pass javascript: removal', 6.5),
        ],
        'ruby/rails': [
            (r"\.gsub\s*\(\s*['\"]\.\.\/['\"]", 'Ruby gsub ../ removal - single pass', 7.0),
            (r"\.sub\s*\(\s*['\"]\.\.\/['\"]", 'Ruby sub ../ removal - replaces only first occurrence', 7.5),
            (r"\.gsub\s*\(\s*\/\<script/", 'Ruby gsub script removal - nesting bypasses', 6.5),
            (r"\.gsub\s*\(\s*\/[`'\"#]/", 'Incomplete PowerShell/Shell character escape filter', 7.0),
        ],

        'go': [
            (r"strings\.ReplaceAll\s*\(\s*\w+\s*,\s*\"\.\.\/\"", 'Go ReplaceAll ../ - single pass, reconstitutable', 7.0),
            (r"strings\.NewReplacer\s*\(\s*\"\.\.\/\"", 'Go Replacer ../ - single pass', 7.0),
        ],
        'java': [
            (r"\.replace\s*\(\s*\"\.\.\/\"", 'Java replace ../ - non-recursive single pass', 7.0),
            (r"\.replaceAll\s*\(\s*\"\\.\\.\/\"", 'Java replaceAll ../ - single pass regex', 7.0),
        ],
        'c/cpp': [
            (r"str_replace|strstr.*memmove|while.*strstr.*\.\./", 'C custom path sanitizer - verify loop-until-clean', 6.0),
        ],
    }
    lang_key = {'javascript': 'node', 'ruby': 'ruby/rails', 'typescript': 'node'}.get(language, language)
    patterns = patterns_by_lang.get(lang_key, [])
    if not patterns:
        return results

    _skip_dirs = {'.git', 'node_modules', 'vendor', '__pycache__', '.venv', 'venv',
                  'target', 'build', 'dist', 'test', 'tests', 'spec', 'fixtures', 'examples'}
    _ext_map = {'.c': 'c/cpp', '.cpp': 'c/cpp', '.h': 'c/cpp', '.py': 'python',
                '.go': 'go', '.java': 'java', '.php': 'php', '.js': 'node', '.rb': 'ruby/rails'}

    for f in dest.rglob('*'):
        if not f.is_file():
            continue
        parts = set(f.relative_to(dest).parts)
        if parts & _skip_dirs:
            continue
        if _ext_map.get(f.suffix) != lang_key:
            continue
        try:
            text = f.read_text(errors='ignore')
        except Exception:
            continue
        for pat, title, cvss in patterns:
            for m in re.finditer(pat, text):
                line = text[:m.start()].count('\n') + 1
                snippet = text[max(0, m.start()-30):m.end()+50].replace('\n', ' ').strip()
                results.append({
                    'tool': 'single-pass-strip',
                    'title': title,
                    'cvss': cvss,
                    'description': f'{title}. Found at {f.name}:{line}. Context: `{snippet[:120]}`. Single-pass removal can be bypassed by nesting: ....// becomes ../ after one pass.',
                    'file': str(f.relative_to(dest)),
                    'line': line,
                    'confidence': 'medium',
                })
                if len(results) >= 30:
                    return results
    return results


def _run_error_path_residue(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """T4/D3: Detect error paths that leave residue - half-committed state, leaked resources, fail-open auth."""
    results = []
    patterns_by_lang = {
        'python': [
            (r'except\s*:\s*\n\s*(pass|\.\.\.)', 'Bare except with pass/... - swallows all errors including auth failures', 7.0),
            (r'except\s+Exception\s*:\s*\n\s*(pass|continue|\.\.\.)', 'Broad except swallowing errors - may hide security failures', 6.0),
            (r'except\s*:\s*\n\s*return\s+(True|None)', 'Except returning truthy/None - fail-open pattern', 7.5),
        ],
        'node': [
            (r'catch\s*\(\s*\w*\s*\)\s*\{\s*\}', 'Empty catch block - swallows errors silently', 6.5),
            (r'catch\s*\(\s*\w*\s*\)\s*\{\s*(//|/\*)', 'Catch with only comment - error swallowed', 6.0),
            (r'\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)', 'Promise .catch with empty handler - swallowed', 6.5),
        ],
        'go': [
            (r'if\s+err\s*!=\s*nil\s*\{[^}]*\}\s*\n\s*//\s*(use|proceed|continue)', 'Error checked but execution continues - verify error impact', 5.5),
            (r'_\s*=\s*\w+\.\w+\(', 'Discarded error return value - error ignored', 6.0),
        ],
        'java': [
            (r'catch\s*\(\s*(Exception|Throwable)\s+\w+\s*\)\s*\{[^}]*\}', 'Broad catch - may swallow security exceptions', 5.5),
            (r'catch\s*\(\s*\w+\s*\)\s*\{\s*(//|/\*|\})', 'Empty or comment-only catch block', 6.5),
        ],
        'php': [
            (r'catch\s*\(\s*\\?Exception\s+\$\w+\s*\)\s*\{[^}]*\}', 'Broad Exception catch - verify security implications', 5.5),
            (r'@\s*(file_get_contents|unlink|mkdir|fopen|include)', 'Error suppression (@) on file operation - errors hidden', 6.0),
        ],
        'ruby/rails': [
            (r'rescue\s*=>\s*\w*\s*\n\s*(nil|#)', 'Broad rescue with nil/comment - error swallowed', 6.0),
            (r'rescue\s+StandardError', 'Broad StandardError rescue - may swallow auth errors', 5.5),
        ],
        'c/cpp': [
            (r'if\s*\(\s*\w+\s*==\s*NULL\s*\)\s*\{[^}]*goto\s+\w+', 'NULL check with goto cleanup - verify all resources freed', 5.5),
            (r'if\s*\(\s*\w+\s*<\s*0\s*\)\s*\{[^}]*return\s', 'Error return - check if partially committed state left behind', 5.5),
        ],
    }
    lang_key = {'javascript': 'node', 'ruby': 'ruby/rails', 'typescript': 'node'}.get(language, language)
    patterns = patterns_by_lang.get(lang_key, [])
    if not patterns:
        return results

    _skip_dirs = {'.git', 'node_modules', 'vendor', '__pycache__', '.venv', 'venv',
                  'target', 'build', 'dist', 'test', 'tests', 'spec', 'fixtures', 'examples'}
    _ext_map = {'.c': 'c/cpp', '.cpp': 'c/cpp', '.h': 'c/cpp', '.py': 'python',
                '.go': 'go', '.java': 'java', '.php': 'php', '.js': 'node', '.rb': 'ruby/rails'}

    for f in dest.rglob('*'):
        if not f.is_file():
            continue
        parts_set = set(f.relative_to(dest).parts)
        if parts_set & _skip_dirs:
            continue
        if _ext_map.get(f.suffix) != lang_key:
            continue
        try:
            text = f.read_text(errors='ignore')
        except Exception:
            continue
        for pat, title, cvss in patterns:
            for m in re.finditer(pat, text):
                line = text[:m.start()].count('\n') + 1
                snippet = text[max(0, m.start()-20):m.end()+60].replace('\n', ' ').strip()
                results.append({
                    'tool': 'error-path-residue',
                    'title': title,
                    'cvss': cvss,
                    'description': f'{title}. Found at {f.name}:{line}. Context: `{snippet[:120]}`. Error paths that swallow exceptions or fail-open can hide auth failures, leave resources leaked, or allow bypasses.',
                    'file': str(f.relative_to(dest)),
                    'line': line,
                    'confidence': 'medium',
                })
                if len(results) >= 40:
                    return results
    return results


def _run_auth_bypass_structural(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Detect structural authorization gaps by comparing sibling methods.

    Finds methods/routes that lack auth decorators/annotations present on their siblings.
    Targets: openmrs @Authorized, brew Trust, sandbox ticket auth.
    """
    results: List[dict] = []
    _skip = {".git", "node_modules", "vendor", "__pycache__", ".venv", "target", "build", "dist",
             "test", "tests", "spec", "__tests__"}

    # Auth decorator/annotation patterns by language
    auth_patterns = {
        "c/cpp": {
            "auth_re": re.compile(r"\b(authenticate|Authorize|authorize|checkAuth|IsAuthenticated)\b"),
            "method_re": re.compile(r"\b(\w+::)?(authorize|authenticate|handleAdmin|onOpen)\s*\("),
            "class_re": re.compile(r"class\s+(\w+)"),
        },
        "java": {
            "auth_re": re.compile(r"@(?:Authorized|PreAuthorize|Secured|RolesAllowed|RequiresPermissions)\s*\("),
            "method_re": re.compile(r"(?:public|protected)\s+\w[\w<>,\s]*\s+(\w+)\s*\("),
            "class_re": re.compile(r"(?:class|interface)\s+(\w+)"),
        },
        "python": {
            "auth_re": re.compile(r"@(?:login_required|permission_required|requires_auth|auth_required|authenticated)"),
            "method_re": re.compile(r"def\s+(\w+)\s*\("),
            "class_re": re.compile(r"class\s+(\w+)"),
        },
        "ruby/rails": {
            "auth_re": re.compile(r"before_action\s+:(?:authenticate|authorize|require_login|check_auth)"),
            "method_re": re.compile(r"def\s+(\w+)"),
            "class_re": re.compile(r"class\s+(\w+)"),
        },
        "node": {
            "auth_re": re.compile(r"(?:requireAuth|isAuthenticated|authMiddleware|verifyToken|checkPermission)"),
            "method_re": re.compile(r"(?:router\.\w+|app\.\w+)\s*\(\s*['\"]([^'\"]+)['\"]"),
            "class_re": re.compile(r"class\s+(\w+)"),
        },
        "go": {
            "auth_re": re.compile(r"(?:accessTokenMiddleware|Middleware\(|JWT|Bearer|RequireAuth|authorize)"),
            "method_re": re.compile(r"func\s+\([^)]+\)\s+(\w+)\s*\("),
            "class_re": re.compile(r"func\s+(\w+)\s*\("),
        },
        "rust": {
            "auth_re": re.compile(r"(?:unified_auth|auth_configured|from_fn_with_state|layer\(.*auth)"),
            "method_re": re.compile(r"(?:async\s+)?fn\s+(\w+)\s*\("),
            "class_re": re.compile(r"(?:struct|impl)\s+(\w+)"),
        },
    }

    lang_key = language.lower().replace(" ", "")
    if lang_key in {"c", "cpp"}:
        lang_key = "c/cpp"
    if lang_key == "c/cpp":
        dest = Path(dest)
        for rel in (
            "src/groups/mqb/mqbauthz/mqbauthz_defaultauthorizer.cpp",
            "src/groups/mqb/mqbauthn/mqbauthn_anonauthenticator.cpp",
            "src/groups/mqb/mqbauthn/mqbauthn_authenticationcontroller.cpp",
        ):
            p = dest / rel
            if not p.is_file():
                continue
            try:
                text = p.read_text(errors="ignore")
            except Exception:
                continue
            if "return true" in text and "authorize" in text.lower():
                results.append({
                    "tool": "auth-structural-bypass",
                    "title": "Authorizer::authorize always returns true (no sibling deny path)",
                    "cvss": 8.6,
                    "description": (
                        f"{rel} has authorize() with no deny/ACL sibling. Every action is "
                        "allowed. Lab: unauthenticated admin command on the native port."
                    ),
                    "file": rel,
                    "line": text.lower().find("return true") + 1,
                    "confidence": "high",
                    "primitive_type": "auth_bypass",
                    "canonical_class": "authz_bypass",
                    "phase2_hint": "protocol_admin_unauth",
                })
            if "d_shouldPass(true)" in text or "d_shouldPass = true" in text:
                results.append({
                    "tool": "auth-structural-bypass",
                    "title": "Anonymous authenticator has no fail-closed sibling",
                    "cvss": 8.4,
                    "description": f"{rel} defaults shouldPass=true with no compile-time fail-closed.",
                    "file": rel,
                    "line": 1,
                    "confidence": "high",
                    "primitive_type": "auth_bypass",
                    "canonical_class": "authz_bypass",
                    "phase2_hint": "protocol_negotiate_unauth",
                })
        return results[:40]

    if lang_key not in auth_patterns:
        return results

    pats = auth_patterns[lang_key]
    exts = {"java": ".java", "python": ".py", "ruby/rails": ".rb", "node": ".js",
            "c/cpp": ".cpp", "c": ".cpp", "cpp": ".cpp", "go": ".go", "rust": ".rs"}
    ext = exts.get(lang_key, ".py")
    extra_exts = {".cc", ".cxx", ".h", ".hpp"} if lang_key in {"c/cpp", "c", "cpp"} else set()
    if lang_key == "node":
        extra_exts.add(".ts")

    # Collect methods and their auth status per file
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in _skip]
        for fname in files:
            if not (fname.endswith(ext) or any(fname.endswith(e) for e in extra_exts)):
                continue
            # Skip auth/decorator plumbing modules: functions defined here ARE the guards
            # (e.g. require_realm_admin, webhook_view, do_login), not guarded endpoints.
            # The "siblings have auth" heuristic is meaningless in a definitions module.
            _stem = fname.rsplit(".", 1)[0].lower()
            if _stem in (
                "decorator", "decorators", "auth", "authentication", "authorization",
                "permissions", "permission", "middleware", "guards", "guard",
                "access_control", "acl",
            ):
                continue
            fpath = Path(root) / fname
            try:
                text = fpath.read_text(errors="ignore")
            except Exception:
                continue
            rel = str(fpath.relative_to(dest))
            lines = text.split("\n")

            # Find which methods have auth and which don't
            authed_methods = set()
            unauthed_methods = []
            has_any_auth = bool(pats["auth_re"].search(text))

            if not has_any_auth:
                continue  # No auth in this file at all - skip

            for i, line in enumerate(lines):
                method_match = pats["method_re"].search(line)
                if method_match:
                    method_name = method_match.group(1)
                    # Check preceding 5 lines for auth decorator
                    context = "\n".join(lines[max(0, i - 5):i + 1])
                    if pats["auth_re"].search(context):
                        authed_methods.add(method_name)
                    else:
                        unauthed_methods.append((method_name, i + 1))

            # Flag methods that lack auth when siblings have it
            if authed_methods and unauthed_methods:
                for method_name, line_num in unauthed_methods:
                    # Skip constructors, private/internal, and common non-API methods
                    if method_name.startswith("_") or method_name in (
                        "__init__", "initialize", "setup", "teardown",
                        "toString", "hashCode", "equals", "compareTo",
                    ):
                        continue
                    # Skip authorization/guard primitives themselves: a decorator like
                    # `require_realm_admin` or a decorator inner `wrapper` is a guard, not a
                    # guarded endpoint. Flagging it as "missing auth" is a false positive.
                    _mn = method_name.lower()
                    if _mn in (
                        "wrapper", "wrapped", "decorator", "inner", "func", "fn",
                    ):
                        continue
                    if (
                        _mn.startswith(("require_", "check_", "assert_", "ensure_",
                                        "validate_", "authorize", "authenticate",
                                        "verify_", "has_", "guard_"))
                        or _mn.endswith(("_required", "_decorator", "_guard"))
                    ):
                        continue
                    # Skip pure data helpers (formatters/parsers/builders): these are not
                    # request-handling endpoints, so "missing auth" is a false positive.
                    if _mn.startswith(("format_", "parse_", "build_", "render_",
                                       "serialize_", "deserialize_", "truncate")):
                        continue
                    results.append({
                        "tool": "auth-structural-bypass",
                        "title": f"Missing auth on {method_name} (siblings have auth)",
                        "cvss": 7.5,
                        "description": (
                            f"Method '{method_name}' in {rel}:{line_num} lacks authorization "
                            f"but sibling methods {sorted(authed_methods)[:3]} in the same file have auth. "
                            f"This may allow unauthorized access."
                        ),
                        "file": rel,
                        "line": line_num,
                        "confidence": "medium",
                        "primitive_type": "auth_bypass",
                    })

    return results[:40]


def _run_dynamic_dispatch_audit(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Detect reflection/metaprogramming APIs where dispatch target comes from input.

    Targets: brew public_send, jc importlib.import_module, openmrs SpEL/Class.forName.
    """
    results: List[dict] = []
    _skip = {".git", "node_modules", "vendor", "__pycache__", ".venv", "target", "build", "dist"}

    dispatch_patterns = {
        "ruby/rails": [
            (r"(?:send|public_send)\s*\(\s*(?:params|request|args|input|data)", "Dynamic dispatch via send with user input", 8.5,
             "send/public_send called with potentially user-controlled method name enables arbitrary method invocation."),
            (r"constantize|const_get\s*\(", "Dynamic class instantiation via constantize", 8.0,
             "constantize/const_get loads arbitrary Ruby classes. If input-controlled, enables loading dangerous classes."),
            (r"Kernel\.open\s*\(|URI\.open\s*\(", "Kernel#open / URI.open (pipe command injection)", 9.0,
             "Kernel#open with leading pipe character executes OS commands: open(\"|id\"). "
             "Use File.open or URI.parse instead."),
        ],
        "python": [
            (r"importlib\.import_module\s*\([^)]*(?:request|args|input|params|user|data|sys\.argv)",
             "Dynamic module import with user input", 8.0,
             "importlib.import_module() with user-controlled module name can load arbitrary Python modules."),
            (r"getattr\s*\([^,]+,\s*(?:request|args|input|params|data)", "getattr with user-controlled attribute", 7.5,
             "getattr() with user-controlled attribute name enables calling arbitrary methods on objects."),
            (r"__import__\s*\(", "Dynamic import via __import__", 7.5,
             "__import__() with user input loads arbitrary modules."),
        ],
        "java": [
            (r"Class\.forName\s*\([^)]*(?:request|param|input|arg|header|user)",
             "Reflection with user-controlled class name", 8.5,
             "Class.forName() with user input enables loading and instantiating arbitrary Java classes."),
            (r"SpelExpressionParser\s*\(\s*\).*parseExpression\s*\([^)]*(?:request|param|input|arg)",
             "SpEL injection via user input", 9.0,
             "Spring Expression Language evaluation of user-controlled expressions enables arbitrary code execution."),
            (r"ScriptEngine.*eval\s*\([^)]*(?:request|param|input|arg|user)",
             "Script engine evaluation with user input", 9.0,
             "Java ScriptEngine.eval() with user input executes arbitrary JavaScript/Groovy/etc."),
        ],
        "node": [
            (r"require\s*\(\s*(?:req\.|params\.|input|user|data|args)", "Dynamic require with user input", 8.5,
             "require() with user-controlled path loads arbitrary Node.js modules."),
            (r"\[\s*(?:req\.|params\.|input|user)\s*[^\]]*\]\s*\(", "Bracket notation method dispatch", 7.5,
             "obj[user_input]() pattern enables calling arbitrary methods on objects."),
        ],
        "php": [
            (r"call_user_func\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|input|user|data)",
             "call_user_func with user-controlled callback", 9.0,
             "call_user_func() with user-controlled function name enables calling arbitrary PHP functions."),
            (r"\$\$\w+|\$\{?\$", "Variable variables ($$var)", 7.0,
             "PHP variable variables with user input can overwrite arbitrary variable values."),
        ],
    }

    lang_key = language.lower().replace(" ", "")
    patterns = dispatch_patterns.get(lang_key, [])
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
                        "tool": "dynamic-dispatch",
                        "title": title,
                        "cvss": cvss,
                        "description": f"{desc} File: {rel}:{line_num}",
                        "file": rel,
                        "line": line_num,
                        "confidence": "medium",
                        "primitive_type": "X-10",  # Dynamic dispatch RCE
                    })

    return results[:40]


