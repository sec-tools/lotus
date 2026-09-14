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



def _parse_dependencies(dest: Path) -> List[tuple]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    deps: List[tuple] = []
    lock = dest / "Gemfile.lock"
    if lock.exists():
        for line in lock.read_text(errors="ignore").splitlines():
            m = re.match(r"^\s{4}([a-zA-Z0-9_.-]+) \(([^)]+)\)", line)
            if m:
                deps.append((m.group(1), m.group(2)))
        return deps

    # Fallback for gem projects that do not commit Gemfile.lock (e.g. Spree)
    gemfile = dest / "Gemfile"
    if gemfile.exists():
        for line in gemfile.read_text(errors="ignore").splitlines():
            m = re.match(r"^\s*gem\s+['\"]([a-zA-Z0-9_.-]+)['\"]", line)
            if m:
                deps.append((m.group(1), "unknown"))
    for gemspec in dest.rglob("*.gemspec"):
        for line in gemspec.read_text(errors="ignore").splitlines():
            m = re.search(r"add_(?:runtime_|development_)?dependency\s+['\"]([a-zA-Z0-9_.-]+)['\"]", line)
            if m:
                deps.append((m.group(1), "unknown"))
    return deps


HIGH_RISK_GEMS = {
    # XML / HTML parsers
    "nokogiri": ("xml/html parser", "parses untrusted XML/HTML; XXE and parsing bugs are common"),
    "loofah": ("html sanitizer", "sanitizes untrusted HTML; bypasses can lead to XSS"),
    "rails-html-sanitizer": ("html sanitizer", "sanitizes untrusted HTML; bypasses can lead to XSS"),
    "ruby-nokogumbo": ("html5 parser", "parses untrusted HTML5"),
    "nokogumbo": ("html5 parser", "parses untrusted HTML5"),
    "rexml": ("xml parser", "parses untrusted XML; XXE/history of DoS"),
    "ox": ("xml parser", "parses untrusted XML; XXE and deserialization risks"),
    "oga": ("xml parser", "parses untrusted XML"),
    "libxml-ruby": ("xml parser", "binds to libxml; XXE and parser bugs"),
    "savon": ("soap client", "parses untrusted SOAP/XML responses"),
    "crack": ("xml/json parser", "parses untrusted XML/JSON"),
    "xml-simple": ("xml parser", "parses untrusted XML"),
    "hpricot": ("html parser", "parses untrusted HTML"),
    # JSON / YAML / serialization
    "oj": ("json parser", "high-performance JSON parser; untrusted input can crash it"),
    "yajl-ruby": ("json parser", "C-based JSON parser; untrusted input can crash it"),
    "ffi-yajl": ("json parser", "FFI/C-based JSON parser used in Chef/IaC"),
    "psych": ("yaml parser", "parses YAML; unsafe load can execute code"),
    "syck": ("yaml parser", "legacy YAML parser; unsafe load can execute code"),
    "json": ("json parser", "parses untrusted JSON"),
    "msgpack": ("binary serializer", "deserializes untrusted binary data"),
    # Chef / IaC Execution & Process Spawning
    "mixlib-shellout": ("process spawner", "executes system commands with elevated privileges"),
    "mixlib-authentication": ("auth handler", "handles RSA HTTP request signing for Chef Server"),
    "mixlib-config": ("config engine", "parses configuration files with dynamic evaluation"),
    "chef-config": ("config engine", "parses Chef client/solo configuration"),
    "erubis": ("erb template engine", "evaluates Ruby code in recipe templates"),
    # PDF / Document parsing
    "pdf-reader": ("pdf parser", "parses complex PDF object streams and decode filters"),
    "prawn": ("pdf generator", "generates PDF documents from user inputs"),
    "combine_pdf": ("pdf manipulator", "merges/parses PDF structures"),
    "hexapdf": ("pdf engine", "decodes PDF streams and encrypts/decrypts documents"),
    # Image / media processing
    "rmagick": ("image processor", "processes untrusted images; ImageMagick bugs common"),
    "mini_magick": ("image processor", "shells out to ImageMagick on untrusted images"),
    "ruby-vips": ("image processor", "processes untrusted images"),
    "vips": ("image processor", "processes untrusted images"),
    "image_processing": ("image pipeline", "processes untrusted images"),
    "marcel": ("mime type sniffing", "sniffs untrusted file content; magic-byte parsing bugs"),
    "mimemagic": ("mime type sniffing", "sniffs untrusted file content"),
    "paperclip": ("file uploader", "handles untrusted file uploads"),
    "kt-paperclip": ("file uploader", "handles untrusted file uploads"),
    "carrierwave": ("file uploader", "handles untrusted file uploads"),
    "dragonfly": ("file uploader", "handles untrusted file uploads"),
    "shrine": ("file uploader", "handles untrusted file uploads"),
    "active_storage": ("file storage", "stores/processing untrusted user uploads"),
    "ckeditor": ("rich text editor", "submits rich HTML; XSS surface"),
    "tinymce-rails": ("rich text editor", "submits rich HTML; XSS surface"),
    # HTTP / network clients
    "httparty": ("http client", "issues outbound HTTP from user input; SSRF risk"),
    "faraday": ("http client", "issues outbound HTTP from user input; SSRF risk"),
    "rest-client": ("http client", "issues outbound HTTP from user input; SSRF risk"),
    "typhoeus": ("http client", "issues outbound HTTP from user input; SSRF risk"),
    "excon": ("http client", "issues outbound HTTP from user input; SSRF risk"),
    "httpclient": ("http client", "issues outbound HTTP from user input; SSRF risk"),
    "curb": ("http client", "issues outbound HTTP from user input; SSRF risk"),
    "net-http": ("http client", "issues outbound HTTP from user input; SSRF risk"),
    # Template / rendering
    "erubi": ("erb engine", "compiles ERB templates; code injection if content controlled"),
    "erb": ("erb engine", "compiles ERB templates; code injection if content controlled"),
    "tilt": ("template engine", "renders multiple template types from user content"),
    "haml": ("template engine", "renders HAML from user content"),
    "slim": ("template engine", "renders Slim from user content"),
    "liquid": ("template engine", "renders Liquid templates; sandbox bypass possible"),
    "redcarpet": ("markdown parser", "parses untrusted Markdown; XSS bypass history"),
    "kramdown": ("markdown parser", "parses untrusted Markdown"),
    "bluecloth": ("markdown parser", "parses untrusted Markdown"),
    "markdown": ("markdown parser", "parses untrusted Markdown"),
    # Auth / crypto / payment
    "devise": ("auth framework", "handles auth flows; privilege escalation target"),
    "omniauth": ("oauth framework", "handles OAuth; bypass and token leak risks"),
    "jwt": ("jwt parser", "parses untrusted JWTs; algorithm confusion/common vulns"),
    "json-jwt": ("jwt parser", "parses untrusted JWTs"),
    "activemerchant": ("payment gateway", "processes payment data; high-value target"),
    "stripe": ("payment sdk", "processes payment tokens"),
    "braintree": ("payment sdk", "processes payment tokens"),
    "paypal-sdk": ("payment sdk", "processes payment tokens"),
    # Search / indexing
    "elasticsearch": ("search client", "queries Elasticsearch; injection/query DoS risks"),
    "ransack": ("search DSL", "builds SQL from user params; injection risk"),
    "sunspot": ("search client", "queries Solr from user input"),
    # Background jobs / cache / DB
    "sidekiq": ("job processor", "deserializes job payloads; RCE history"),
    "resque": ("job processor", "deserializes job payloads"),
    "delayed_job": ("job processor", "deserializes job payloads"),
    "redis": ("cache/store", "high-value cache; injection/DoS surface"),
    "dalli": ("memcached client", "cache injection / deserialization risks"),
    "mongoid": ("ODM", "NoSQL injection surface"),
    "mysql2": ("db driver", "SQL injection surface"),
    "pg": ("db driver", "SQL injection surface"),
    "sqlite3": ("db driver", "SQL injection surface"),
    "unicorn": ("http server", "faces untrusted HTTP requests"),
    "puma": ("http server", "faces untrusted HTTP requests"),
    "thin": ("http server", "faces untrusted HTTP requests"),
    "webrick": ("http server", "faces untrusted HTTP requests"),
    "rack": ("http middleware", "handles untrusted HTTP; middleware bypass risks"),
    "activerecord": ("ORM", "builds SQL from user params; injection/mass-assignment surface"),
    "actionpack": ("web framework", "handles untrusted HTTP parameters and sessions"),
    "actionview": ("rendering", "renders views; template injection/XSS surface"),
    "activesupport": ("core extensions", "XML/YAML/JSON serialization surface"),
}


def _flag_high_risk_deps(dest: Path, language: str) -> tuple:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Flag high-risk OSS deps across languages (not Ruby-only)."""
    findings: List[dict] = []
    all_deps: List[dict] = []

    # Universal keyword categories (parsers / exec / template / serialize)
    HIGH_RISK_ANY = {
        "yaml", "pyyaml", "psych", "nokogiri", "rexml", "ox", "libxml",
        "pickle", "marshal", "serialize", "msgpack", "bson",
        "subprocess", "shelljs", "child_process", "posix-spawn",
        "jinja2", "handlebars", "liquid", "erb", "mustache", "ejs",
        "lxml", "xmldom", "xmltodict", "beautifulsoup", "html5lib",
        "requests", "urllib3", "httpx", "faraday", "typhoeus", "rest-client",
        "jwt", "jsonwebtoken", "pyjwt", "devise", "passport",
        "lodash", "underscore", "marked", "markdown", "commonmarker",
        "eval", "vm2", "isolated-vm", "execjs", "mixlib-shellout", "pdf-reader",
    }

    if language == "ruby/rails":
        for name, version in _parse_dependencies(dest):
            all_deps.append({"name": name, "version": version})
            info = HIGH_RISK_GEMS.get(name)
            if info:
                category, rationale = info
                findings.append({
                    "tool": "dependency-audit",
                    "title": f"OSS dependency parses/processes untrusted data: {name}",
                    "cvss": 6.0,
                    "description": (
                        f"{name} ({version}) is a {category}. {rationale}. "
                        f"Flagged for Phase 2 fuzzing/audit in the lab."
                    ),
                    "file": "Gemfile.lock",
                    "line": 0,
                    "confidence": "medium",
                    "dependency": name,
                })
        return findings, all_deps

    try:
        from backend.dependency_audit import collect_manifest_packages
        # Production reachability excludes dev/test/build dependencies.  The
        # full declared graph remains available to dependency-map discovery,
        # but only shipped packages can create a deployable vulnerability lead.
        packages = collect_manifest_packages(dest, language, include_dev=False)
    except Exception:
        packages = []
    for name, version in packages:
        all_deps.append({"name": name, "version": version})
        key = name.lower().replace("_", "-")
        if key in HIGH_RISK_ANY or name.lower() in HIGH_RISK_ANY or any(
            k in key for k in ("yaml", "xml", "pickle", "jwt", "shell", "exec", "template")
        ):
            findings.append({
                "tool": "dependency-audit",
                "title": f"OSS dependency parses/processes untrusted data: {name}",
                "cvss": 5.5,
                "description": (
                    f"{name} ({version or '?'}) matches a high-risk parser/exec/template/"
                    f"serialize category. Confirm taint reachability before treating as vuln."
                ),
                "file": "dependencies",
                "line": 0,
                "confidence": "low",
                "dependency": name,
            })
    return findings, all_deps


def _run_dependency_map(dest: Path, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Parse ALL dependency/lockfiles regardless of language to find high-risk deps."""
    findings: List[dict] = []
    _skip_dirs = {".git", "node_modules", "vendor", ".bundle", "__pycache__", "target", "build", "dist"}
    # High-risk dependency categories (parsers, HTTP, auth, serialization, template, file)
    HIGH_RISK_KEYWORDS = {
        "xml", "yaml", "json", "parser", "serialize", "deserialize", "marshal",
        "upload", "file", "image", "pdf", "zip", "tar", "compress",
        "http", "request", "fetch", "curl", "net", "socket", "ssl", "tls",
        "auth", "oauth", "jwt", "session", "cookie", "csrf", "token",
        "crypto", "cipher", "hash", "bcrypt", "argon", "scrypt",
        "template", "render", "view", "html", "markdown",
        "sql", "database", "mongo", "redis", "orm", "query",
        "exec", "shell", "command", "process", "spawn",
        "eval", "script", "vm", "sandbox",
    }
    dep_files = {
        "Gemfile.lock": "ruby", "Gemfile": "ruby",
        "package-lock.json": "node", "package.json": "node", "yarn.lock": "node",
        "requirements.txt": "python", "Pipfile.lock": "python", "poetry.lock": "python",
        "go.sum": "go", "go.mod": "go",
        "Cargo.lock": "rust", "Cargo.toml": "rust",
        "composer.lock": "php", "composer.json": "php",
        "pom.xml": "java", "build.gradle": "java",
    }
    deps_found = set()
    for f in dest.rglob("*"):
        if not f.is_file() or (set(f.relative_to(dest).parts) & _skip_dirs):
            continue
        if f.name in dep_files:
            try:
                content = f.read_text(errors="ignore")
                # Extract dependency names via simple regex
                for m in re.finditer(r'["\']([a-zA-Z0-9_.-]{2,60})["\']', content):
                    dep = m.group(1).lower()
                    if any(kw in dep for kw in HIGH_RISK_KEYWORDS) and dep not in deps_found:
                        deps_found.add(dep)
            except Exception:
                pass
    # Generate findings for high-risk dependencies
    for dep in sorted(deps_found)[:50]:
        matched_kw = [kw for kw in HIGH_RISK_KEYWORDS if kw in dep][:3]
        findings.append({
            "tool": "dependency-map",
            "title": f"High-risk dependency: {dep}",
            "cvss": 5.5,
            "description": f"Dependency '{dep}' matches risk keywords: {', '.join(matched_kw)}. "
                           f"Review for known vulnerabilities, unsafe defaults, and attack surface.",
            "file": "dependencies",
            "line": 0,
            "confidence": "low",
        })
    return findings


async def _run_osv_check(dest: Path, repo_id: int, language: str) -> List[dict]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Check project dependencies against the OSV.dev vulnerability database."""
    await _send(repo_id, "Checking dependencies against OSV.dev CVE database")
    
    # Map language to ecosystem
    ecosystem_map = {
        "python": ("PyPI", "requirements.txt"),
        "node": ("npm", "package.json"),
        "ruby/rails": ("RubyGems", "Gemfile.lock"),
        "go": ("Go", "go.mod"),
        "java": ("Maven", "pom.xml"),
        "php": ("Packagist", "composer.json"),
        "rust": ("crates.io", "Cargo.toml"),
    }
    
    eco_info = ecosystem_map.get(language)
    if not eco_info:
        return []
    
    ecosystem, manifest = eco_info
    manifest_path = dest / manifest
    if not manifest_path.exists():
        return []
    
    # Extract package names and versions from manifest
    packages = _parse_manifest_packages(manifest_path, language)
    if not packages:
        return []
    
    findings = []
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10) as client:
            for pkg_name, pkg_version in packages[:50]:  # Cap at 50 to avoid API abuse
                try:
                    query = {"package": {"name": pkg_name, "ecosystem": ecosystem}}
                    if pkg_version:
                        query["version"] = pkg_version
                    resp = await client.post("https://api.osv.dev/v1/query", json=query)
                    if resp.status_code == 200:
                        vulns = resp.json().get("vulns", [])
                        for vuln in vulns[:3]:  # Max 3 CVEs per package
                            cve_id = ""
                            for alias in vuln.get("aliases", []):
                                if alias.startswith("CVE-"):
                                    cve_id = alias
                                    break
                            severity = 7.0  # Default high for known CVEs
                            for s in vuln.get("severity", []):
                                if s.get("type") == "CVSS_V3":
                                    try:
                                        # Extract base score from CVSS vector
                                        score_str = s["score"]
                                        if "/" in score_str:  # It's a vector string
                                            severity = 7.0  # Default for vector strings
                                        else:
                                            severity = float(score_str)
                                    except (ValueError, KeyError):
                                        pass
                            findings.append({
                                "tool": "osv-cve-check",
                                "title": f"Known CVE in {pkg_name}: {cve_id or vuln.get('id', 'unknown')}",
                                "cvss": severity,
                                "description": (
                                    f"{vuln.get('summary', 'Known vulnerability')}. "
                                    f"Package: {pkg_name}@{pkg_version or 'unknown'}. "
                                    f"ID: {vuln.get('id', '')}. "
                                    f"Details: {vuln.get('details', '')[:200]}"
                                ),
                                "file": manifest,
                                "line": 0,
                                "confidence": "high",
                            })
                except Exception:
                    continue  # Skip individual package failures
    except ImportError:
        await _send(repo_id, "httpx not available for OSV check", level="warning")
    except Exception as e:
        await _send(repo_id, f"OSV check error: {str(e)[:100]}", level="warning")
    
    if findings:
        await _send(repo_id, f"OSV.dev: observed {len(findings)} dependency-risk leads")
    return findings


def _parse_manifest_packages(manifest_path: Path, language: str, *, include_dev: bool = True) -> List[tuple]:
    from backend.pipeline import detect_application_type, detect_language, _tool_present, _parse_generic_tool_output, _send, TOOL_SEMAPHORE, STREAM_QUEUES, CUSTOM_TOOLS
    """Extract (package_name, version) tuples from manifest files."""
    packages = []
    try:
        text = manifest_path.read_text(errors="ignore")
    except Exception:
        return packages
    
    if language == "python":
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            # Match: package==version, package>=version, package~=version
            import re
            m = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=><!~]+\s*([\d.]+)', line)
            if m:
                packages.append((m.group(1), m.group(2)))
            elif re.match(r'^[a-zA-Z0-9_.-]+$', line):
                packages.append((line, ""))
    elif language == "node":
        try:
            import json
            import re
            data = json.loads(text)
            sections = ('dependencies', 'devDependencies') if include_dev else ('dependencies',)
            for section in sections:
                for pkg, ver in data.get(section, {}).items():
                    # Strip ^ ~ >= etc.
                    clean_ver = re.sub(r'^[^\d]*', '', ver)
                    packages.append((pkg, clean_ver))
        except (ValueError, AttributeError):
            pass
    elif language == "ruby/rails":
        # Parse Gemfile.lock
        import re
        in_specs = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped == 'specs:':
                in_specs = True
                continue
            if in_specs and stripped and not stripped.startswith('GEM') and not stripped.startswith('PLATFORMS'):
                m = re.match(r'^([a-zA-Z0-9_.-]+)\s*\(([\d.]+)', stripped)
                if m:
                    packages.append((m.group(1), m.group(2)))
            elif in_specs and not stripped:
                in_specs = False
    elif language == "go":
        from backend.dependency_sources import parse_go_mod
        packages.extend((row["name"], row["version"]) for row in parse_go_mod(text)["dependencies"])
    elif language == "java":
        import re
        # Simple pom.xml parsing
        for m in re.finditer(r'<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>', text):
            packages.append((m.group(1), m.group(2)))
    
    return packages
