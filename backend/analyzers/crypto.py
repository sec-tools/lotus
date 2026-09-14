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



def _run_crypto_timing_audit(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Detect non-constant-time comparisons on secrets, weak PRNGs, and weak crypto."""
    results = []
    patterns_by_lang = {
        'python': [
            (r'==\s*(?:token|secret|password|api_key|hmac|hash|mac|signature|digest)',
             'Non-constant-time comparison on secret value', 7.0,
             'Use hmac.compare_digest() instead of == for comparing secrets.'),
            (r'random\.(random|randint|choice|randrange)\s*\(', 'Weak PRNG for security use', 6.5,
             'random module is not cryptographically secure. Use secrets module for tokens/keys.'),
            (r'hashlib\.(md5|sha1)\s*\(', 'Weak hash algorithm for security decision', 5.5,
             'MD5/SHA1 are collision-vulnerable. Use SHA-256+ for security hashing.'),
            (r'AES\.new\([^)]*AES\.MODE_ECB', 'AES ECB mode - deterministic encryption', 7.0,
             'AES ECB mode leaks plaintext patterns. Use CBC, GCM, or CTR mode.'),
        ],
        'node': [
            (r'===?\s*(?:token|secret|password|apiKey|hmac|hash|mac|signature)',
             'Non-constant-time comparison on secret', 7.0,
             'Use crypto.timingSafeEqual() instead of === for comparing secrets.'),
            (r'Math\.random\s*\(\)', 'Math.random() for security use', 7.5,
             'Math.random() is not cryptographically secure. Use crypto.randomBytes().'),
            (r'createHash\s*\(\s*[\'"](?:md5|sha1)[\'"]', 'Weak hash algorithm', 5.5,
             'MD5/SHA1 are collision-vulnerable. Use SHA-256+.'),
        ],
        'java': [
            (r'\.equals\s*\(\s*(?:token|secret|password|apiKey|hmac|hash|mac|signature)',
             'Non-constant-time comparison via String.equals()', 7.0,
             'Use MessageDigest.isEqual() or constant-time comparison for secrets.'),
            (r'new\s+Random\s*\(\)', 'java.util.Random for security use', 6.5,
             'java.util.Random is predictable. Use SecureRandom for tokens/keys.'),
            (r'getInstance\s*\(\s*[\'"](?:MD5|SHA-1)[\'"]', 'Weak hash algorithm', 5.5,
             'MD5/SHA-1 are collision-vulnerable. Use SHA-256+.'),
        ],
        'go': [
            (r'==\s*(?:token|secret|password|apiKey|hmac|hash|mac|signature)',
             'Non-constant-time comparison on secret', 7.0,
             'Use subtle.ConstantTimeCompare() instead of == for comparing secrets.'),
            (r'math/rand', 'math/rand for security use', 6.5,
             'math/rand is not cryptographically secure. Use crypto/rand.'),
        ],
        'c/cpp': [
            (r'strcmp\s*\(\s*\w*(token|secret|password|key|hash|mac|hmac|nonce)',
             'strcmp on secret value - timing side-channel', 7.5,
             'strcmp returns early on first mismatch, leaking secret length. Use constant-time comparison.'),
            (r'memcmp\s*\(\s*\w*(token|secret|password|key|hash|mac|hmac)',
             'memcmp on secret - timing side-channel', 7.0,
             'memcmp may return early on mismatch. Use a constant-time comparison function.'),
            (r'\brand\s*\(\s*\)', 'rand() for security use', 7.0,
             'rand() is a weak PRNG with predictable output. Use getrandom() or /dev/urandom.'),
            (r'srand\s*\(\s*time\s*\(', 'srand(time()) - predictable seed', 7.5,
             'Seeding with time() makes PRNG output predictable to within seconds.'),
        ],
        'php': [
            (r'===?\s*\$(?:token|secret|password|api_key|hmac|hash|mac|signature)',
             'Non-constant-time comparison on secret', 7.0,
             'Use hash_equals() instead of == for comparing secrets.'),
            (r'\brand\s*\(\s*\)|mt_rand\s*\(\s*\)', 'Weak PRNG for security use', 6.5,
             'rand()/mt_rand() are predictable. Use random_bytes() or random_int().'),
            (r'md5\s*\(\s*\$|sha1\s*\(\s*\$', 'Weak hash for security decision', 5.5,
             'MD5/SHA1 are collision-vulnerable. Use hash("sha256", ...).'),
        ],
        'ruby/rails': [
            (r'==\s*(?:token|secret|password|api_key|hmac|hash|mac|signature)',
             'Non-constant-time comparison on secret', 7.0,
             'Use ActiveSupport::SecurityUtils.secure_compare() for secrets.'),
            (r'SecureRandom\s*\.\s*random_number', 'Verify SecureRandom usage context', 3.0,
             'SecureRandom is safe, but verify it is used for all security-relevant random values.'),
        ],
    }

    lang_key = {'javascript': 'node', 'ruby': 'ruby/rails', 'typescript': 'node'}.get(language, language)
    patterns = patterns_by_lang.get(lang_key, [])
    if not patterns:
        return results

    _skip_dirs = {'.git', 'node_modules', 'vendor', '__pycache__', '.venv', 'venv',
                  'target', 'build', 'dist', 'test', 'tests', 'spec', 'fixtures', 'examples'}
    _ext_map = {'.c': 'c/cpp', '.cpp': 'c/cpp', '.h': 'c/cpp', '.py': 'python',
                '.go': 'go', '.java': 'java', '.php': 'php', '.js': 'node',
                '.rb': 'ruby/rails', '.ts': 'node'}

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
            if len(text) > 500_000:
                continue
        except Exception:
            continue

        for line_text in text.split('\n'):
            for pat, title, cvss, advice in patterns:
                if re.search(pat, line_text, re.IGNORECASE):
                    line_num = text[:text.index(line_text)].count('\n') + 1
                    results.append({
                        'tool': 'crypto-timing-audit',
                        'title': title,
                        'cvss': cvss,
                        'description': f'{title}. {advice} File: {f.name}, line {line_num}.',
                        'file': str(f.relative_to(dest)),
                        'line': line_num,
                        'confidence': 'medium',
                    })
                    if len(results) >= 40:
                        return results
    return results


