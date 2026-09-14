"""Phase-1 test-oracle miner.

Integration tests are the highest-signal map of intended vs actual security
behavior. Assertions like "negotiate succeeds without authenticate" or
"admin help works with default anonymous" are ready-made Phase-2 PoC recipes
that grep on production code alone will miss.

Does not confirm vulnerabilities. Lab proof still required.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

_SKIP = {".git", "node_modules", "vendor", ".venv", "target", "build", "dist",
         "third_party", "thirdparty", ".tox"}

_TEST_DIR_HINTS = (
    "integration-tests", "integration_tests", "it", "e2e", "systest",
)
_TEST_NAME = re.compile(r"(^test_|_test\.|_spec\.|\.t\.cpp$|\.test\.)", re.I)

_ORACLE_PATTERNS = [
    (re.compile(r"test_admin_with_default_anonymous|admin commands with default anonymous", re.I),
     "Unauthenticated admin command succeeds under default anonymous auth",
     9.1, "protocol_admin_unauth",
     "AdminClient connects with no credentials and send_admin('help') returns CMD subcommands."),
    (re.compile(r"test_basic_auth_allows_anonymous|BasicAuthenticator coexists with default anonymous", re.I),
     "Enabling BasicAuthenticator does not close anonymous negotiate",
     8.8, "protocol_negotiate_unauth",
     "Negotiate without authenticationRequest still returns brokerResponse.code==0."),
    (re.compile(r"assert.*brokerResponse.*code.*=\s*0", re.I),
     "Test asserts unauthenticated/anonymous negotiate success",
     8.1, "protocol_negotiate_unauth",
     "brokerResponse.result.code == 0 is the success oracle for the native handshake."),
    (re.compile(r"anonymousCredential.*disallow|anonymous credential disallowed", re.I),
     "Anonymous-disallow is an opt-in, not the default",
     8.4, "protocol_negotiate_unauth",
     "Default config omits anonymousCredential.disallow; unauthenticated clients stay in."),
    (re.compile(r"IDENTIFIED BY ''|identified by \"\"", re.I),
     "Test/fixture creates empty-password SQL account",
     8.2, "sql_empty_password",
     "Empty-password accounts skip the auth-switch path (obmp_connect). Lab: login with empty pass."),
    (re.compile(r"shouldPass.*=\s*true|AnonPass", re.I),
     "Test documents AnonAuthenticator shouldPass=true (fail-open)",
     8.4, "protocol_negotiate_unauth",
     "Anonymous authenticator defaults to pass."),
]


def _iter_test_files(dest: Path, limit: int = 400) -> Iterable[Path]:
    n = 0
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in _SKIP and not d.startswith(".")]
        rel_root = os.path.relpath(root, dest).replace("\\", "/")
        in_test_tree = any(h in rel_root.lower() for h in _TEST_DIR_HINTS) or any(
            p in rel_root.lower() for p in ("/test/", "/tests/", "/spec/")
        )
        for fname in files:
            if not in_test_tree and not _TEST_NAME.search(fname):
                continue
            if Path(fname).suffix.lower() not in {".py", ".rb", ".java", ".go", ".cpp", ".cc",
                                                    ".h", ".hpp", ".sql", ".sh"}:
                continue
            n += 1
            if n > limit:
                return
            yield Path(root) / fname


def collect_test_oracles(dest: Path, language: str = "") -> List[Dict[str, Any]]:
    dest = Path(dest)
    results: List[Dict[str, Any]] = []
    seen = set()
    for p in _iter_test_files(dest):
        try:
            text = p.read_text(errors="ignore")[:120000]
        except Exception:
            continue
        try:
            rel = str(p.relative_to(dest))
        except Exception:
            rel = str(p)
        for rx, title, cvss, hint, desc in _ORACLE_PATTERNS:
            m = rx.search(text)
            if not m:
                continue
            key = (title, rel)
            if key in seen:
                continue
            seen.add(key)
            line = text[:m.start()].count("\n") + 1
            results.append({
                "tool": "test-oracle-miner",
                "title": title,
                "cvss": cvss,
                "description": (
                    f"{desc} Source: integration/unit test `{rel}:{line}` is an executable "
                    f"oracle for Phase 2. Reproduce the same client sequence in the lab; "
                    f"do not report until the live oracle matches."
                ),
                "file": rel,
                "line": line,
                "confidence": "high",
                "qualification": "QUALIFIED",
                "phase2_hint": hint,
                "primitive_type": "auth_bypass",
                "canonical_class": "authz_bypass",
            })
    return results[:30]


def _run_test_oracle_miner(dest: Path, language: str) -> List[dict]:
    return collect_test_oracles(dest, language)
