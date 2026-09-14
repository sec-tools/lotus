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



def _run_config_audit(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Audit configuration files for dangerous settings, defaults, and exposures."""
    findings: List[dict] = []
    _skip_dirs = {".git", "node_modules", "vendor", ".bundle", "__pycache__", "target", "build", "dist"}
    # Dangerous config patterns
    dangerous_configs = [
        (r"debug\s*[=:]\s*(true|1|yes|on)", "Debug mode enabled", 6.5, "Debug mode in production exposes internals."),
        (r"(cors|allow.origin)\s*[=:]\s*['\"]?\*", "CORS allows all origins", 6.0, "Wildcard CORS allows any origin."),
        (r"(ssl|tls|https)\s*[=:]\s*(false|0|disabled|off)", "SSL/TLS disabled", 7.0, "Transport security disabled."),
        (r"(verify.ssl|ssl.verify|verify_ssl)\s*[=:]\s*(false|0|no)", "SSL verification disabled", 7.0, "Certificate verification skipped."),
        (r"(secret.key|jwt.secret|app.secret)\s*[=:]\s*['\"]?(change.me|secret|password|default|example)", "Default secret key", 8.0, "Default/weak secret key in config."),
        (r"(rate.limit|throttle)\s*[=:]\s*(0|false|disabled|off|none)", "Rate limiting disabled", 5.5, "No rate limiting enables brute force."),
        (r"(admin|root|superuser)\s*[=:]\s*['\"]?(true|1|yes)", "Admin flag in config", 5.0, "Admin/superuser flag set in configuration."),
        (r"(password|passwd|secret)\s*[=:]\s*['\"]([^'\"]{1,30})['\"]", "Password in config file", 7.5, "Credential in configuration file."),
        (r"(bind|listen|host)\s*[=:]\s*['\"]?0\.0\.0\.0", "Binding to all interfaces", 5.0, "Service binds to all interfaces (not localhost)."),
        (r"(x.frame.options|x.content.type|x.xss.protection|content.security.policy)\s*[=:]\s*(none|disabled|off|''|\"\")", "Security header disabled", 5.5, "Security header explicitly disabled."),
    ]
    
    # Secret patterns in source code
    source_secret_patterns = [
        (r"secret_key\s*=\s*[\"']", "Hardcoded Python secret key", 6.5, "Hardcoded secret key in source code."),
        (r"password\s*=\s*[\"'][^\"']{6,}", "Hardcoded Python password", 7.0, "Hardcoded password in source code."),
        (r"API_KEY\s*=\s*[\"']", "Hardcoded Python API key", 6.5, "Hardcoded API key in source code."),
        (r"const.*SECRET\s*=\s*['\"]", "Hardcoded JS secret", 6.5, "Hardcoded secret in source code."),
        (r"const.*PASSWORD\s*=\s*['\"]", "Hardcoded JS password", 7.0, "Hardcoded password in source code."),
        (r"const.*API_KEY\s*=\s*['\"]", "Hardcoded JS API key", 6.5, "Hardcoded JS API key in source code."),
        (r"[A-Z_]*PASSWORD\s*=\s*[\"']", "Hardcoded Ruby password", 7.0, "Hardcoded password in source code."),
        (r"[A-Z_]*SECRET\s*=\s*[\"']", "Hardcoded Ruby secret", 6.5, "Hardcoded secret in source code."),
        (r"[A-Z_]*API_KEY\s*=\s*[\"']", "Hardcoded Ruby API key", 6.5, "Hardcoded Ruby API key in source code."),
        (r"const\s+\w*(Password|Secret|Key)\s*=\s*\"", "Hardcoded Go secret", 6.5, "Hardcoded secret in source code."),
        (r"[a-zA-Z_]*(Password|Secret|Key|PASSWORD|SECRET|KEY)\s*[:=]\s*[\"'][^\"']{6,}", "Hardcoded Go secret", 6.5, "Hardcoded secret in source code."),
        (r"(private|public|static).*(?:PASSWORD|SECRET|KEY)\s*=\s*\"", "Hardcoded Java secret", 6.5, "Hardcoded Java secret in source code."),
        (r"final.*String.*(password|secret|key)\s*=\s*\"", "Hardcoded Java secret", 6.5, "Hardcoded Java secret in source code."),
    ]
    
    # Docker/container security audit
    docker_security_patterns = [
        (r"seccomp\s*:\s*unconfined", "seccomp disabled (unconfined)", 7.0, "seccomp:unconfined disables syscall filtering  - container has full kernel syscall access."),
        (r"privileged\s*:\s*true", "Privileged container", 8.0, "Privileged mode gives container full host capabilities."),
        (r"cap_add.*SYS_ADMIN|cap_add.*ALL", "Dangerous Linux capability", 7.5, "SYS_ADMIN or ALL capabilities grant near-root host access."),
        (r"network_mode\s*:\s*['\"]?host", "Host network mode", 6.5, "Container shares host network namespace."),
        (r"pid\s*:\s*['\"]?host", "Host PID namespace", 7.0, "Container can see and signal host processes."),
        (r"volumes.*:/var/run/docker.sock|volumes.*/var/run/docker.sock", "Docker socket mounted", 9.0, "Docker socket access = host root equivalent."),
    ]
    for compose_name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        compose_path = dest / compose_name
        if compose_path.exists():
            try:
                content = compose_path.read_text(errors="ignore")
                for pat, title, cvss, desc in docker_security_patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        line = 0
                        for i, ln in enumerate(content.splitlines(), 1):
                            if re.search(pat, ln, re.IGNORECASE):
                                line = i
                                break
                        findings.append({
                            "tool": "config-audit",
                            "title": f"Docker: {title}",
                            "cvss": cvss,
                            "description": f"{desc} File: {compose_name}, line {line}.",
                            "file": compose_name,
                            "line": line,
                            "severity": cvss,
                            "confidence": "high",
                        })
            except Exception:
                pass

    # CWE-776: Missing defusedxml / entity expansion protection
    for f_name in ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg"):
        req_path = dest / f_name
        if req_path.exists():
            try:
                req_text = req_path.read_text(errors="ignore")
                if "xmltodict" in req_text and "defusedxml" not in req_text:
                    findings.append({
                        "tool": "config-audit",
                        "title": "CWE-776: xmltodict without defusedxml (entity expansion DoS)",
                        "cvss": 5.5,
                        "description": (
                            f"Project uses xmltodict but does NOT depend on defusedxml. "
                            f"xmltodict.parse() uses expat which expands internal DTD entities by default. "
                            f"A billion-laughs XML bomb can cause OOM. File: {f_name}."
                        ),
                        "file": f_name,
                        "line": 0,
                        "severity": 5.5,
                        "confidence": "high",
                    })
            except Exception:
                pass

    config_extensions = {".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env", ".json", ".properties", ".xml"}
    source_extensions = {".py", ".js", ".rb", ".go", ".java", ".ts", ".php", ".rs", ".c", ".cpp"}
    config_names = {"config", "settings", "application", "environment", "env", ".env"}
    for f in dest.rglob("*"):
        if not f.is_file() or f.stat().st_size > 200_000:
            continue
        if set(f.relative_to(dest).parts) & _skip_dirs:
            continue
        
        is_config = f.suffix.lower() in config_extensions or f.stem.lower() in config_names
        is_source = f.suffix.lower() in source_extensions
        
        if not (is_config or is_source):
            continue
            
        try:
            content = f.read_text(errors="ignore")
        except Exception:
            continue

        if is_config:
            for pat, title, cvss, desc in dangerous_configs:
                if re.search(pat, content, re.IGNORECASE):
                    line = 0
                    for i, ln in enumerate(content.splitlines(), 1):
                        if re.search(pat, ln, re.IGNORECASE):
                            line = i
                            break
                    findings.append({
                        "tool": "config-audit",
                        "title": title,
                        "cvss": cvss,
                        "description": f"{desc} File: {f.relative_to(dest)}, line {line}.",
                        "file": str(f.relative_to(dest)),
                        "line": line,
                        "severity": cvss,
                        "confidence": "medium",
                    })
                    if len(findings) >= 50:
                        return findings
                        
        if is_source:
            for pat, title, cvss, desc in source_secret_patterns:
                if re.search(pat, content):
                    line = 0
                    for i, ln in enumerate(content.splitlines(), 1):
                        if re.search(pat, ln):
                            line = i
                            break
                    findings.append({
                        "tool": "config-audit",
                        "title": title,
                        "cvss": cvss,
                        "description": f"{desc} File: {f.relative_to(dest)}, line {line}.",
                        "file": str(f.relative_to(dest)),
                        "line": line,
                        "severity": cvss,
                        "confidence": "medium",
                    })
                    if len(findings) >= 50:
                        return findings

    return findings


def _run_build_flag_audit(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Scan Makefile/CMakeLists/configure.ac for missing binary hardening flags."""
    results = []
    if language not in ('c/cpp', 'c', 'cpp', 'php'):
        return results

    build_files = {
        'Makefile': [],
        'Makefile.am': [],
        'CMakeLists.txt': [],
        'configure.ac': [],
        'configure.in': [],
        'meson.build': [],
    }

    for f in dest.rglob('*'):
        if f.name in build_files and f.is_file():
            try:
                text = f.read_text(errors='ignore')
                build_files[f.name].append((f, text))
            except Exception:
                continue

    # Hardening flags to check
    hardening_checks = [
        ('-fstack-protector-strong', 'Stack canary protection missing',
         'Missing -fstack-protector-strong: stack buffer overflows may be exploitable without canary protection.', 6.0),
        ('-D_FORTIFY_SOURCE', 'FORTIFY_SOURCE not set',
         'Missing -D_FORTIFY_SOURCE=2: dangerous C library functions (strcpy, sprintf) will not have runtime bounds checking.', 5.5),
        ('-fPIE', 'Position-Independent Executable flag missing',
         'Missing -fPIE/-pie: ASLR effectiveness reduced without position-independent executable.', 5.0),
        ('-Wl,-z,relro', 'RELRO not enabled',
         'Missing -Wl,-z,relro: GOT entries remain writable after loading, enabling GOT overwrite attacks.', 5.5),
        ('-Wl,-z,now', 'Full RELRO (immediate binding) not enabled',
         'Missing -Wl,-z,now: lazy PLT binding leaves GOT entries writable, enabling GOT overwrite attacks.', 5.0),
        ('-Wl,-z,noexecstack', 'Executable stack not disabled',
         'Missing -Wl,-z,noexecstack: stack may be executable, simplifying shellcode execution.', 5.5),
    ]

    for bname, instances in build_files.items():
        for fpath, text in instances:
            upper_text = text.upper()
            rel = str(fpath.relative_to(dest))

            # Check for missing hardening flags
            for flag, title, desc, cvss in hardening_checks:
                if flag.lower() not in text.lower():
                    results.append({
                        'tool': 'build-flag-audit',
                        'title': title,
                        'cvss': cvss,
                        'description': f'{desc} File: {rel}.',
                        'file': rel,
                        'line': 1,
                        'confidence': 'medium',
                    })

            # Check for unsafe flags
            unsafe_patterns = [
                (r'-O3', 'Aggressive optimization -O3 may hide undefined behavior', 4.5),
                (r'-fno-stack-protector', 'Stack protector explicitly disabled', 7.5),
                (r'-fno-exceptions', 'Exceptions disabled - throws become abort()', 4.0),
                (r'-DNDEBUG', 'NDEBUG set - assert() calls are removed in release', 4.0),
            ]
            for pat, title, cvss in unsafe_patterns:
                if re.search(pat, text):
                    line = 1
                    for i, l in enumerate(text.split('\n'), 1):
                        if re.search(pat, l):
                            line = i
                            break
                    results.append({
                        'tool': 'build-flag-audit',
                        'title': title,
                        'cvss': cvss,
                        'description': f'{title}. File: {rel}, line {line}.',
                        'file': rel,
                        'line': line,
                        'confidence': 'high',
                    })

    return results[:40]


def _run_container_security_audit(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Scan Dockerfiles and docker-compose for security misconfigurations."""
    results = []

    docker_files = []
    for f in dest.rglob('*'):
        if f.name in ('Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
                       'compose.yml', 'compose.yaml') or f.name.startswith('Dockerfile'):
            if f.is_file():
                try:
                    docker_files.append((f, f.read_text(errors='ignore')))
                except Exception:
                    continue

    for fpath, text in docker_files:
        rel = str(fpath.relative_to(dest))

        checks = [
            (r'--privileged', 'Privileged container flag', 8.5,
             'Container runs with --privileged flag, granting full host access. This defeats container isolation.'),
            (r'/proc\b|/sys\b|/dev\b', 'Host filesystem mount', 7.0,
             'Mounts host /proc, /sys, or /dev into container, potentially exposing sensitive kernel interfaces.'),
            (r'USER\s+root|user:\s*root', 'Container runs as root', 6.0,
             'Container runs as root user. Use a non-root USER directive for defense in depth.'),
            (r'EXPOSE\s+(22|3306|5432|27017|6379|11211)\b', 'Sensitive port exposed', 5.5,
             'Sensitive service port exposed in container (SSH/DB/cache). Verify this is intentional.'),
            (r'LD_PRELOAD|GCONV_PATH|LD_LIBRARY_PATH', 'Dangerous environment variable', 7.5,
             'Dangerous loader environment variable set. Can be abused for library injection attacks.'),
            (r'(?:curl|wget)\s+[^\n]*\|\s*(?:bash|sh)', 'Pipe-to-shell install pattern', 6.5,
             'Piping remote content to shell. Verify HTTPS is used and content is integrity-checked.'),
            (r'--cap-add\s+(?:SYS_ADMIN|SYS_PTRACE|NET_ADMIN|ALL)', 'Dangerous capability added', 7.5,
             'Dangerous Linux capability added to container. SYS_ADMIN can lead to container escape.'),
            (r'network_mode:\s*host', 'Host network mode', 6.5,
             'Container shares host network namespace, bypassing network isolation.'),
        ]

        for pat, title, cvss, desc in checks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                line_num = text[:m.start()].count('\n') + 1
                results.append({
                    'tool': 'container-security-audit',
                    'title': title,
                    'cvss': cvss,
                    'description': f'{desc} File: {rel}, line {line_num}.',
                    'file': rel,
                    'line': line_num,
                    'confidence': 'high',
                })

    return results[:40]


