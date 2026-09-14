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



def _run_integer_boundary_analysis(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """T2: Detect integer overflow/underflow, signed-unsigned confusion, unchecked size casts."""
    results = []
    patterns_by_lang = {
        'c/cpp': [
            (r'\batoi\s*\(', 'Unchecked atoi() - no range validation on converted integer', 7.0),
            (r'\bstrtol\s*\([^)]+\)\s*;', 'strtol() without errno/range check', 6.5),
            (r'\(\s*(int|short|char)\s*\)\s*\w+', 'Narrowing integer cast - potential truncation', 6.0),
            (r'\(\s*size_t\s*\)\s*\w+', 'Cast to size_t - negative value becomes huge unsigned', 7.5),
            (r'\bmalloc\s*\([^)]*\*[^)]*\)', 'malloc with multiplication - potential integer overflow in size', 8.0),
            (r'\brealloc\s*\([^)]+\)\s*;', 'realloc() return value unchecked - may return NULL on failure', 7.0),
            (r'\blen\s*[-+]\s*\d+', 'Arithmetic on length variable - potential off-by-one or underflow', 6.5),
            (r'if\s*\([^)]*<\s*0[^)]*\)', 'Signed comparison on potentially unsigned value', 5.5),
        ],
        'python': [
            (r'\bint\s*\(\s*(request|params|args|input|sys\.argv)', 'Unchecked int() from untrusted input', 6.0),
            (r'\brange\s*\(\s*int\s*\(', 'range() with user-controlled size - potential DoS', 5.5),
        ],
        'go': [
            (r'\bstrconv\.Atoi\s*\(', 'Atoi without bounds check on result', 6.0),
            (r'\bint\(\w+\)', 'Type cast to int - potential truncation on 32-bit', 5.5),
            (r'\bmake\s*\([^,]+,\s*\w+\)', 'make() with user-controlled size - potential DoS or overflow', 6.5),
        ],
        'java': [
            (r'Integer\.parseInt\s*\(', 'parseInt without try-catch or range validation', 5.5),
            (r'\(int\)\s*\w+', 'Narrowing cast to int - potential truncation from long', 6.0),
            (r'\bnew\s+byte\s*\[\s*\w+', 'Array allocation with variable size - unchecked bounds', 6.5),
        ],
        'php': [
            (r'\bintval\s*\(\s*\$', 'intval on user input without validation', 5.5),
            (r'\(int\)\s*\$', 'Cast to int from user data', 5.5),
        ],
    }
    lang_key = {'javascript': 'node', 'ruby': 'ruby/rails', 'typescript': 'node'}.get(language, language)
    patterns = patterns_by_lang.get(lang_key, [])
    if not patterns:
        return results
    
    _skip_dirs = {'.git', 'node_modules', 'vendor', '.bundle', '__pycache__', '.venv', 'venv',
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
                snippet = text[max(0, m.start()-40):m.end()+40].replace('\n', ' ').strip()
                results.append({
                    'tool': 'integer-boundary',
                    'title': title,
                    'cvss': cvss,
                    'description': f'{title}. Found at {f.name}:{line}. Context: `{snippet[:120]}`. Integer boundary violations can cause buffer overflows (C), denial of service, or logic errors.',
                    'file': str(f.relative_to(dest)),
                    'line': line,
                    'confidence': 'medium',
                })
                if len(results) >= 50:
                    return results
    return results


def _run_unsafe_c_api_audit(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """T2/T8/T11: Audit C/C++ and PHP extension code for unsafe API usage patterns."""
    results = []
    if language not in ('c/cpp', 'c', 'cpp', 'php'):
        return results
    
    patterns = [
        # Memory allocation without size check
        # NOTE: the paren body allows ONE level of nesting so common calls like
        # ``malloc(sizeof(Foo) * n)`` are matched (a bare ``[^)]+`` stops at the
        # inner ``)`` and silently misses the majority of real allocations).
        (r'\bmalloc\s*\((?:[^()]|\([^()]*\))*\)\s*;\s*(?!\s*if)', 'malloc() without NULL check', 8.0, 'Unchecked malloc return - NULL dereference or use of invalid pointer on allocation failure'),
        (r'\bcalloc\s*\((?:[^()]|\([^()]*\))*\)\s*;\s*(?!\s*if)', 'calloc() without NULL check', 7.5, 'Unchecked calloc return'),
        (r'\brealloc\s*\((?:[^()]|\([^()]*\))*\)\s*;', 'realloc() without return check', 7.5, 'realloc may return NULL; original pointer lost causing memory leak and NULL deref'),
        # Unsafe string operations
        (r'\bsprintf\s*\(', 'sprintf() - use snprintf() instead', 7.5, 'sprintf has no bounds checking; buffer overflow if format output exceeds buffer'),
        (r'\bstrcat\s*\(', 'strcat() - use strncat() instead', 7.0, 'strcat has no bounds checking; buffer overflow on concatenation'),
        (r'\bstrcpy\s*\(', 'strcpy() - use strncpy() or strlcpy()', 7.5, 'strcpy has no bounds checking'),
        (r'\bgets\s*\(', 'gets() - REMOVED in C11, use fgets()', 9.0, 'gets() is inherently unsafe; no buffer size limit'),
        # Free without NULL
        (r'\bfree\s*\((?:[^()]|\([^()]*\))*\)\s*;(?!\s*\w+\s*=\s*NULL)', 'free() without setting pointer to NULL', 6.0, 'Use-after-free risk: pointer not nulled after free'),
        # PHP extension specific
        (r'\bZVAL_STRING\s*\(', 'ZVAL_STRING - check for type confusion', 5.5, 'PHP zval string manipulation - verify type checks before access'),
        (r'\bconvert_to_string\s*\(', 'convert_to_string - implicit type coercion', 5.5, 'PHP type coercion may produce unexpected results'),
        (r'\bemalloc\s*\((?:[^()]|\([^()]*\))*\)\s*;\s*(?!\s*if)', 'emalloc() without NULL check', 7.5, 'PHP memory allocation without NULL check'),
        (r'\bZ_STR(VAL|LEN)\s*\(', 'Z_STRVAL/Z_STRLEN without ZVAL_DEREF', 6.0, 'Accessing zval string without dereferencing reference - potential type confusion'),
        (r'\bZ_TYPE_P?\s*\([^)]+\)\s*!=\s*IS_', 'zval type check pattern', 5.0, 'Verify all zval accesses are preceded by type checks'),
        # Integer issues in C
        (r'\bsizeof\s*\([^)]*\)\s*[-+]\s*\d+', 'sizeof arithmetic - potential miscalculation', 6.5, 'Arithmetic on sizeof result - may cause under/over-allocation'),
    ]
    
    _skip_dirs = {'.git', 'node_modules', 'vendor', '__pycache__', 'test', 'tests'}
    for f in dest.rglob('*'):
        if not f.is_file() or f.suffix not in ('.c', '.cc', '.cxx', '.cpp', '.h', '.hh', '.hpp', '.hxx', '.php'):
            continue
        parts = set(f.relative_to(dest).parts)
        if parts & _skip_dirs:
            continue
        try:
            text = f.read_text(errors='ignore')
        except Exception:
            continue
        for pat, title, cvss, desc in patterns:
            for m in re.finditer(pat, text):
                line = text[:m.start()].count('\n') + 1
                results.append({
                    'tool': 'unsafe-c-api',
                    'title': title,
                    'cvss': cvss,
                    'description': f'{desc}. File: {f.name}, line {line}.',
                    'file': str(f.relative_to(dest)),
                    'line': line,
                    'confidence': 'medium',
                })
                if len(results) >= 60:
                    return results
    return results


def _run_parser_boundary_analysis(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """T3/T6: Analyze parser/deserializer code for boundary condition vulnerabilities."""
    results = []
    # Line-level patterns (no DOTALL to avoid catastrophic backtracking)
    line_patterns = [
        # Unbounded allocation from parsed size
        (r'(malloc|calloc|emalloc|new\s+\w+\[)\s*\([^)]*(?:len|size|count|num|length)\b', 'Allocation from parsed size field', 8.0, 'Memory allocation using size from parsed/untrusted data without bounds check'),
        # Missing length bounds in loops
        (r'while\s*\([^)]*(!|!=)\s*(EOF|NULL|0|nil|None|"")', 'Loop until sentinel without length bound', 6.0, 'Parser loop bounded only by sentinel - malformed input may cause infinite loop or overread'),
        # YAML/JSON specific
        (r'yaml_parser_parse|yaml_event_t|yaml_document_t', 'libyaml parser usage', 5.5, 'Direct libyaml API usage - check for proper error handling and bounds on all parsed values'),
        (r'yaml_emitter_emit|yaml_scalar_event_initialize', 'libyaml emitter usage', 5.0, 'libyaml emitter - verify buffer bounds on output'),
    ]
    # Multi-line patterns (check within function scope using line windows)
    func_patterns = {
        'python': r'def\s+\w*parse\w*\s*\(',
        'ruby/rails': r'def\s+\w*parse\w*',
        'node': r'function\s+\w*parse\w*\s*\(',
        'c/cpp': r'\w+\s+\w*parse\w*\s*\(',
        'go': r'func\s+\w*[Pp]arse\w*\s*\(',
        'php': r'function\s+\w*parse\w*\s*\(',
    }

    _skip_dirs = {'.git', 'node_modules', 'vendor', '__pycache__', '.venv', 'test', 'tests'}
    for f in dest.rglob('*'):
        if not f.is_file():
            continue
        if f.suffix not in ('.c', '.cpp', '.h', '.py', '.js', '.rb', '.go', '.java', '.php', '.rs'):
            continue
        parts = set(f.relative_to(dest).parts)
        if parts & _skip_dirs:
            continue
        try:
            stat = f.stat()
            if stat.st_size > 500_000:  # Skip files > 500KB to avoid slowness
                continue
            text = f.read_text(errors='ignore')
        except Exception:
            continue

        # Line-level patterns
        for pat, title, cvss, desc in line_patterns:
            for m in re.finditer(pat, text):
                line = text[:m.start()].count('\n') + 1
                results.append({
                    'tool': 'parser-boundary',
                    'title': title,
                    'cvss': cvss,
                    'description': f'{desc}. File: {f.name}, line {line}.',
                    'file': str(f.relative_to(dest)),
                    'line': line,
                    'confidence': 'medium',
                })
                if len(results) >= 40:
                    return results

        # Recursive parser detection (line-by-line, not DOTALL)
        lang_key = {'javascript': 'node', 'ruby': 'ruby/rails', 'typescript': 'node'}.get(language, language)
        func_pat = func_patterns.get(lang_key)
        if func_pat:
            lines = text.split('\n')
            for i, line in enumerate(lines):
                if re.search(func_pat, line):
                    func_name_match = re.search(r'(\w*parse\w*)', line, re.IGNORECASE)
                    if func_name_match:
                        func_name = func_name_match.group(1)
                        # Check within next 25 lines for recursive call
                        window = '\n'.join(lines[i+1:i+26])
                        if func_name in window:
                            results.append({
                                'tool': 'parser-boundary',
                                'title': 'Recursive parser without depth limit',
                                'cvss': 7.0,
                                'description': f'Recursive descent parser `{func_name}` may stack overflow on deeply nested input. File: {f.name}, line {i+1}.',
                                'file': str(f.relative_to(dest)),
                                'line': i + 1,
                                'confidence': 'medium',
                            })
                            if len(results) >= 40:
                                return results
    return results


