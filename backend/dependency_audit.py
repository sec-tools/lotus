"""
Tainted-dependency attack-surface analysis + optional parallel child audits.

Doctrine:
  A dependency is only Phase-2/report-interesting when untrusted input can reach
  into it (argv/env/HTTP/file → first-party call/import of dep API). Keyword and
  OSV matches alone are candidates until usage+taint evidence exists.
"""

from __future__ import annotations

import asyncio
import ast
import hashlib
import configparser
import json
import os
import re
import tempfile
import time
from contextvars import ContextVar
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_CANCELLING_DEPENDENCIES = ContextVar("lotus_cancelling_dependencies", default=False)

# Untrusted entry points by language family
_TAINT_SOURCE_PATTERNS = [
    r"\bsys\.argv\b",
    r"\bprocess\.argv\b",
    r"\bARGV\b",
    r"\bENV\[",
    r"\bos\.environ\b",
    r"\brequest\.(args|form|json|data|files|GET|POST|params|query)\b",
    r"\bparams\[",
    r"\bflask\.request\b",
    r"\bexpress\.request\b",
    r"\bctx\.(query|body|params)\b",
    r"\binput\s*\(",
    r"\bgets\b",
    r"\breadline\b",
    r"\bopen\s*\([^)]*(?:argv|args|path|file|name)",
]

_SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".bundle", "__pycache__", "target",
    "build", "dist", ".venv", "venv", "site-packages", "eggs", ".tox",
    "coverage", ".mypy_cache", "test", "tests", "spec", "fixtures",
}

# Import / require shapes: (language_hint, regex with group 'pkg')
_IMPORT_PATTERNS = [
    ("python", re.compile(r"^\s*(?:from|import)\s+([a-zA-Z0-9_]+)", re.M)),
    ("python", re.compile(r"^\s*import\s+([a-zA-Z0-9_]+)", re.M)),
    ("node", re.compile(r"""require\(\s*['"]([a-zA-Z0-9_@/.-]+)['"]\s*\)""")),
    ("node", re.compile(r"""from\s+['"]([a-zA-Z0-9_@/.-]+)['"]""")),
    ("ruby", re.compile(r"""(?:require|require_relative|gem)\s+['"]([a-zA-Z0-9_/-]+)['"]""")),
    ("go", re.compile(r"""^\s*"([a-zA-Z0-9._/-]+)"\s*$""", re.M)),
    ("go", re.compile(r'^\s*import\s+(?:\w+\s+)?"([a-zA-Z0-9._/-]+)"', re.M)),
]

_SOURCE_EXTS = {".py", ".rb", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".php", ".rs"}
DEPENDENCY_SCAN_FILE_LIMIT = 12000
DEPENDENCY_SCAN_BYTE_LIMIT = 64 * 1024 * 1024
DEPENDENCY_SCAN_SECONDS = 20

# Known dangerous APIs inside popular deps (local sink hints when imported)
_DEP_SINK_HINTS = {
    "yaml": [r"yaml\.(load|unsafe_load)\s*\(", r"YAML\.load\b", r"Psych\.load\b"],
    "pyyaml": [r"yaml\.(load|unsafe_load)\s*\("],
    "pickle": [r"pickle\.loads?\s*\("],
    "marshal": [r"marshal\.loads?\s*\("],
    "serialize": [r"Marshal\.load\b", r"JSON\.parse\b"],
    "nokogiri": [r"Nokogiri::XML\(", r"Nokogiri::HTML\("],
    "rexml": [r"REXML::Document"],
    "subprocess": [r"subprocess\.(call|run|Popen|check_output)\s*\("],
    "child_process": [r"child_process\.(exec|execSync|spawn)\s*\("],
    "shelljs": [r"shell\.(exec|rm)\s*\("],
    "lodash": [r"_\.template\s*\(", r"_\.merge\s*\("],
    "handlebars": [r"Handlebars\.compile\s*\("],
    "jinja2": [r"jinja2\.Template\s*\(", r"Environment\s*\("],
    "ermarkdown": [r"markdown\.(markdown|Markdown)\s*\("],
    "marked": [r"marked\s*\("],
    "xmldom": [r"DOMParser", r"parseFromString"],
    "xml": [r"etree\.parse\s*\(", r"XMLParser\s*\("],
    "lxml": [r"etree\.(parse|fromstring|XML)\s*\("],
    "requests": [r"requests\.(get|post|request)\s*\("],
    "urllib": [r"urllib\.request\.urlopen\s*\("],
    "open-uri": [r"URI\.open\b", r"open\s*\(.*https?:"],
}


@dataclass
class DepUsage:
    package: str
    import_name: str
    file: str
    line: int
    snippet: str
    near_taint: bool = False
    taint_evidence: str = ""
    sink_hit: str = ""
    risk: str = "low"  # low|medium|high|critical; scheduling priority, never a verdict
    source_sha256: str = ""
    import_line: int = 0
    taint_line: int = 0
    sink_line: int = 0
    evidence_scope: str = "lexical-proximity"


@dataclass
class DepAuditCandidate:
    name: str
    version: str = ""
    local_path: str = ""  # relative path under dest if vendored/source present
    git_url: str = ""
    reason: str = ""
    usages: List[DepUsage] = field(default_factory=list)
    priority_score: int = 0
    priority_reasons: List[str] = field(default_factory=list)
    evidence_scope: str = "unverified-selection"
    source_identity: Dict[str, Any] = field(default_factory=dict)
    source_refs: List[Dict[str, Any]] = field(default_factory=list)
    selection_gaps: List[str] = field(default_factory=list)
    external_bundle: Dict[str, Any] = field(default_factory=dict)


def _truthy(val: Any, default: bool = False) -> bool:
    if val is None:
        return default
    # Match the Settings checkbox's exact legacy representations. Coercing
    # numeric 1 or strings such as 'yes' would enable imported policy that
    # the browser displays as disabled. New saves require JSON booleans.
    return val is True or (type(val) is str and val in {"true", "1"})


def read_dep_audit_settings(api_keys: Optional[Dict[str, Any]] = None, *,
                            dependency_audit_enabled: bool = True, depth: int = 0) -> Dict[str, Any]:
    """Saved options govern expansion; legacy environment flags cannot enable it."""
    keys = api_keys or {}
    requested = _truthy(keys.get("parallel_dependency_audits"), default=False)
    enabled = dependency_audit_enabled is not False and requested
    raw_limit = keys.get("max_dependency_audits")
    if raw_limit is None:
        raw_limit = 3
    try:
        if type(raw_limit) not in {int, str}:
            raise ValueError("child limit must be an integer")
        max_children = int(raw_limit)
        if not 1 <= max_children <= 8:
            raise ValueError("child limit is outside supported bounds")
    except (TypeError, ValueError):
        max_children = 0  # Refuse expansion for malformed imported/legacy policy.
    try:
        depth = max(0, int(depth))
    except (TypeError, ValueError):
        depth = 1  # Unknown ancestry must not permit recursive expansion.
    return {
        "parallel_dependency_audits": enabled,
        "max_dependency_audits": max_children,
        "dep_audit_depth": depth,
        "max_dep_audit_depth": 1,
        "dependency_audit_enabled": dependency_audit_enabled is not False,
        "requested": requested,
        "source": "settings",
    }


def _iter_source_files(dest: Path, limit: int = 2500):
    n = 0
    root = dest.resolve()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in _SKIP_DIRS and not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            if n >= limit:
                return
            p = Path(directory) / name
            if p.suffix.lower() not in _SOURCE_EXTS or p.is_symlink() or not p.is_file():
                continue
            n += 1
            yield p


def _window_has_taint(text: str) -> Tuple[bool, str]:
    for pat in _TAINT_SOURCE_PATTERNS:
        m = re.search(pat, text)
        if m:
            return True, m.group(0)[:80]
    return False, ""


def _normalize_pkg(name: str) -> str:
    name = (name or "").strip().lstrip("@")
    if "/" in name:
        # scoped npm @org/pkg → pkg; go module path → last segment
        name = name.split("/")[-1]
    return name.replace("-", "_").lower()


def _package_key(name: str) -> str:
    """Preserve scope/module paths; normalization must never erase identity."""
    return str(name or "").strip().lower().replace("-", "_")


def _matching_package(raw: str, package_index: dict) -> str:
    key = _package_key(raw)
    if key in package_index:
        return key
    # Imports have few path components, while monorepos may declare thousands
    # of packages. Look up longest component prefixes without scanning them all.
    for index in range(len(key) - 1, -1, -1):
        if key[index] in "/." and key[:index] in package_index:
            return key[:index]
    return ""


def _python_direct_input_sites(text: str, package_index: dict) -> list[dict]:
    """Observe direct argv/environment expressions passed to imported APIs.

    This narrow syntax check executes nothing and does not prove runtime
    reachability. Aliases reassigned anywhere in the file are excluded; calls,
    transforms and cross-function assignments are deliberately not propagated.
    Other framework inputs remain explicitly weaker proximity candidates.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    assigned = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))}
    assigned.update(node.arg for node in ast.walk(tree) if isinstance(node, ast.arg))
    assigned.update(node.name for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    imported, source_modules = {}, {}
    binding_counts = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                binding_counts[local] = binding_counts.get(local, 0) + 1
                if local in assigned:
                    continue
                matched = _matching_package(alias.name, package_index)
                if matched:
                    imported[local] = (matched, node.lineno)
                if alias.name in {"sys", "os"}:
                    source_modules[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and not node.level:
            for alias in node.names:
                local = alias.asname or alias.name
                binding_counts[local] = binding_counts.get(local, 0) + 1
            matched = _matching_package(node.module or "", package_index)
            if matched:
                for alias in node.names:
                    local = alias.asname or alias.name
                    if local not in assigned and alias.name != "*":
                        imported[local] = (matched, node.lineno)
    imported = {name: value for name, value in imported.items() if binding_counts[name] == 1}
    source_modules = {name: value for name, value in source_modules.items() if binding_counts[name] == 1}
    sites = []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        function = call.func
        while isinstance(function, ast.Attribute):
            function = function.value
        if not isinstance(function, ast.Name) or function.id not in imported:
            continue
        for argument in [*call.args, *(entry.value for entry in call.keywords)]:
            # A wrapper may sanitize or replace its input. Only a direct
            # attribute/subscript expression gets this stronger syntax rank.
            expression = argument
            while isinstance(expression, ast.Subscript):
                expression = expression.value
            if not isinstance(expression, ast.Attribute) or not isinstance(expression.value, ast.Name):
                continue
            source = source_modules.get(expression.value.id)
            if (source, expression.attr) not in {("sys", "argv"), ("os", "environ")}:
                continue
            package, import_line = imported[function.id]
            sites.append({"package": package, "line": call.lineno, "import_line": import_line,
                          "taint_line": expression.lineno,
                          "taint_evidence": (ast.get_source_segment(text, argument) or "")[:160],
                          "sink_hit": (ast.get_source_segment(text, call.func) or "")[:100],
                          "evidence_scope": "direct-input-expression"})
            break
    return sorted(sites, key=lambda row: (row["line"], row["package"]))


def collect_manifest_packages(
    dest: Path, language: str, *, include_dev: bool = True,
) -> List[Tuple[str, str]]:
    """Best-effort (name, version) from common manifests.

    Discovery callers may request the full declared graph, while production
    reachability/audit callers set ``include_dev=False`` so test/build tooling
    cannot be mistaken for shipped attack surface.
    """
    pkgs: List[Tuple[str, str]] = []
    try:
        from backend.pipeline import _parse_manifest_packages, _parse_dependencies
    except Exception:
        _parse_manifest_packages = None
        _parse_dependencies = None

    if language == "ruby/rails" and _parse_dependencies:
        try:
            pkgs.extend(_parse_dependencies(dest))
        except Exception:
            pass

    manifest_map = {
        "python": ["requirements.txt", "pyproject.toml", "setup.py"],
        "node": ["package.json"],
        "ruby/rails": ["Gemfile.lock", "Gemfile"],
        "go": ["go.mod"],
        "php": ["composer.json"],
        "rust": ["Cargo.toml"],
        "java": ["pom.xml"],
    }
    for fname in manifest_map.get(language, []):
        path = dest / fname
        if path.exists() and _parse_manifest_packages:
            try:
                try:
                    pkgs.extend(_parse_manifest_packages(path, language, include_dev=include_dev))
                except TypeError:
                    pkgs.extend(_parse_manifest_packages(path, language))
            except Exception:
                pass
    # Always try package.json / requirements as extras for polyglot (sandbox)
    for fname, lang in (("package.json", "node"), ("requirements.txt", "python"), ("Gemfile.lock", "ruby/rails")):
        path = dest / fname
        if path.exists() and _parse_manifest_packages:
            try:
                try:
                    pkgs.extend(_parse_manifest_packages(path, lang, include_dev=include_dev))
                except TypeError:
                    pkgs.extend(_parse_manifest_packages(path, lang))
            except Exception:
                pass

    # npm's lockfile contains the transitive production graph that
    # ``package.json`` alone cannot describe.  Include those packages for
    # reachability matching, while honoring npm's per-entry ``dev`` marker so
    # build/test-only modules cannot become deployable vulnerability leads.
    if language == "node":
        lock_path = dest / "package-lock.json"
        if lock_path.is_file():
            try:
                lock = json.loads(lock_path.read_text(errors="ignore"))
                lock_packages = lock.get("packages") if isinstance(lock, dict) else None
                if isinstance(lock_packages, dict):
                    for path_name, entry in lock_packages.items():
                        if not isinstance(entry, dict) or not path_name.startswith("node_modules/"):
                            continue
                        if not include_dev and entry.get("dev") is True:
                            continue
                        pkg_name = str(entry.get("name") or path_name.rsplit("node_modules/", 1)[-1])
                        version = str(entry.get("version") or "")
                        if pkg_name:
                            pkgs.append((pkg_name, version))
                else:
                    # npm lockfile v1 nests dependencies recursively.
                    def walk(tree: Any) -> None:
                        if not isinstance(tree, dict):
                            return
                        for pkg_name, entry in (tree.get("dependencies") or {}).items():
                            if not isinstance(entry, dict):
                                continue
                            if include_dev or entry.get("dev") is not True:
                                pkgs.append((str(pkg_name), str(entry.get("version") or "")))
                            walk(entry)
                    walk(lock)
            except Exception:
                # A malformed lockfile is surfaced by the native npm audit;
                # discovery remains best-effort and does not abort the scan.
                pass

    # de-dupe
    seen = set()
    out = []
    for n, v in pkgs:
        key = (n.lower(), v or "")
        if key in seen:
            continue
        seen.add(key)
        out.append((n, v or ""))
    return out


def analyze_tainted_dependency_usage(
    dest: Path,
    language: str,
    packages: Optional[List[Tuple[str, str]]] = None,
) -> Dict[str, Any]:
    """Find first-party imports of deps that sit near untrusted data / dep sinks."""
    dest = Path(dest).resolve()
    packages = collect_manifest_packages(dest, language, include_dev=False) if packages is None else packages
    supported = {"python", "node", "ruby/rails", "go"}
    if language not in supported:
        reason = (f"Dependency import mapping for {language or 'unknown language'} is unsupported; "
                  "mapping currently covers Python, JavaScript/TypeScript, Ruby and Go. Dependency coverage remains incomplete.")
        return {"findings": [], "usages": [], "reachable_packages": [], "package_count": len(packages),
                "usage_count": 0, "status": "blocked", "reason": reason, "gaps": [reason]}
    pkg_index: Dict[str, str] = {}
    for name, ver in packages:
        pkg_index[name.lower().replace("-", "_")] = name
    for distribution, import_name in {"pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "pil", "pyjwt": "jwt"}.items():
        if distribution in pkg_index:
            pkg_index[import_name] = pkg_index[distribution]

    usages: List[DepUsage] = []
    seen_keys: Set[Tuple[str, str, int]] = set()
    gaps = []
    analyzed_files = 0
    read_bytes = 0
    started = time.monotonic()
    limits_reached = []

    for file_index, path in enumerate(_iter_source_files(dest, limit=DEPENDENCY_SCAN_FILE_LIMIT + 1)):
        if file_index >= DEPENDENCY_SCAN_FILE_LIMIT:
            limits_reached.append("files")
            gaps.append(f"Source file limit {DEPENDENCY_SCAN_FILE_LIMIT} reached; remaining dependency imports are unexamined")
            break
        if time.monotonic() - started >= DEPENDENCY_SCAN_SECONDS:
            limits_reached.append("time")
            gaps.append(f"Dependency mapping reached its {DEPENDENCY_SCAN_SECONDS}s scan budget; remaining imports are unexamined")
            break
        if read_bytes >= DEPENDENCY_SCAN_BYTE_LIMIT:
            limits_reached.append("bytes")
            gaps.append("Dependency mapping reached its byte budget; remaining imports are unexamined")
            break
        if path.suffix.lower() in {".java", ".php", ".rs"}:
            gaps.append(f"Unsupported dependency import syntax: {path.relative_to(dest)}")
            continue
        try:
            with path.open("rb") as handle:
                read_limit = min(400_001, DEPENDENCY_SCAN_BYTE_LIMIT - read_bytes)
                raw = handle.read(read_limit)
                # One EOF probe distinguishes an exactly fitting complete file
                # from a truncated prefix, retaining all fully read results.
                overflow = handle.read(1) if read_limit < 400_001 and len(raw) == read_limit else b""
            read_bytes += len(raw) + len(overflow)
            if overflow:
                limits_reached.append("bytes")
                gaps.append(f"Dependency source reached the byte budget: {path.relative_to(dest)}")
                break
            source_sha256 = "sha256:" + hashlib.sha256(raw).hexdigest() if len(raw) <= 400_000 else ""
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            gaps.append(f"Dependency source is not valid UTF-8: {path.relative_to(dest)}")
            continue
        except OSError:
            gaps.append(f"Dependency source could not be read: {path.relative_to(dest)}")
            continue
        if len(raw) > 400_000:
            gaps.append(f"Dependency source truncated at 400000 bytes: {path.relative_to(dest)}")
            text = text[:400_000]
        analyzed_files += 1
        lines = text.splitlines()
        rel = str(path.relative_to(dest))

        imported: Set[str] = set()
        import_lines = {}
        for _, cre in _IMPORT_PATTERNS:
            for m in cre.finditer(text):
                raw = m.group(1)
                raw_key = _package_key(raw)
                # Match exact package identities or real submodule imports;
                # basename matching conflates @a/parser and @b/parser, and
                # splitting at '.' loses all github.com Go module identities.
                matched = _matching_package(raw, pkg_index)
                if matched:
                    imported.add(matched)
                    import_lines.setdefault(matched, text.count("\n", 0, m.start()) + 1)
                elif raw_key.split(".")[0] in _DEP_SINK_HINTS:
                    imported.add(raw_key.split(".")[0])
                    import_lines.setdefault(raw_key.split(".")[0], text.count("\n", 0, m.start()) + 1)

        if not imported:
            # Still scan sink hints for stdlib-like yaml/pickle even if not in lockfile
            for hint_pkg, pats in _DEP_SINK_HINTS.items():
                if any(re.search(p, text) for p in pats):
                    imported.add(hint_pkg)

        for norm in sorted(imported):
            canon = pkg_index.get(norm, norm)
            # Find a representative line
            line_no = import_lines.get(norm, 1)
            snippet = ""
            for i, line in enumerate(lines, 1):
                if i == import_lines.get(norm) or (not import_lines.get(norm) and
                        (norm in line.lower().replace("-", "_") or canon.lower() in line.lower())):
                    line_no = i
                    snippet = line.strip()[:160]
                    break
            # Proximity window around import/use
            lo = max(0, line_no - 25)
            hi = min(len(lines), line_no + 40)
            window = "\n".join(lines[lo:hi])
            near, tev = _window_has_taint(window)

            sink_hit = ""
            for hint_pkg, pats in _DEP_SINK_HINTS.items():
                if hint_pkg not in norm and hint_pkg not in canon.lower().replace("-", "_"):
                    continue
                for p in pats:
                    sm = re.search(p, window)
                    if sm:
                        sink_hit = sm.group(0)[:100]
                        break
                if sink_hit:
                    break

            risk = "low"
            if near and sink_hit:
                risk = "critical"
            elif near:
                risk = "high"
            elif sink_hit:
                risk = "medium"

            key = (canon, rel, line_no)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            usages.append(DepUsage(
                package=canon,
                import_name=norm,
                file=rel,
                line=line_no,
                snippet=snippet or f"import/use of {canon}",
                near_taint=near,
                taint_evidence=tev,
                sink_hit=sink_hit,
                risk=risk,
                source_sha256=source_sha256,
                import_line=import_lines.get(norm, 0),
                taint_line=next((lo + offset + 1 for offset, line in enumerate(lines[lo:hi])
                                 if near and tev in line), 0),
                sink_line=next((lo + offset + 1 for offset, line in enumerate(lines[lo:hi])
                                if sink_hit and sink_hit in line), 0),
            ))

        if path.suffix.lower() == ".py" and source_sha256:
            for site in _python_direct_input_sites(text, pkg_index):
                package = pkg_index[site["package"]]
                key = (package, rel, site["line"])
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                usages.append(DepUsage(package=package, import_name=site["package"], file=rel,
                    line=site["line"], snippet=lines[site["line"] - 1].strip()[:160], near_taint=True,
                    taint_evidence=site["taint_evidence"], sink_hit=site["sink_hit"], risk="high",
                    source_sha256=source_sha256, import_line=site["import_line"],
                    taint_line=site["taint_line"], sink_line=site["line"], evidence_scope=site["evidence_scope"]))

    by_pkg: Dict[str, List[DepUsage]] = {}
    for u in usages:
        by_pkg.setdefault(u.package, []).append(u)

    findings: List[Dict[str, Any]] = []
    reachable_high_risk: List[str] = []
    for pkg, ulist in sorted(by_pkg.items()):
        best = max(ulist, key=lambda u: (u.evidence_scope == "direct-input-expression",
                   {"critical": 4, "high": 3, "medium": 2, "low": 1}[u.risk], -u.line))
        if best.risk in ("low",) and not best.near_taint:
            continue
        cvss = {"critical": 8.5, "high": 7.0, "medium": 5.5, "low": 3.0}[best.risk]
        reachable_high_risk.append(pkg)
        findings.append({
            "tool": "tainted-dependency",
            "title": (
                f"Potential input path near dependency '{pkg}'"
                + (f" via {best.sink_hit}" if best.sink_hit else "")
            ),
            "cvss": cvss,
            "description": (
                f"First-party code imports/uses '{pkg}' with candidate input evidence "
                f"(taint={best.taint_evidence or 'none'}; sink={best.sink_hit or 'import-only'}). "
                f"Site: {best.file}:{best.line} `{best.snippet}`. "
                f"{len(ulist)} usage site(s). Proximity is a candidate for validation, "
                "not a proven dataflow or vulnerability."
            ),
            "file": best.file,
            "line": best.line,
            "confidence": "low",
            "qualification": "CANDIDATE",
            "conviction_level": 1,
            "reachability_proven": False,
            "dependency": pkg,
            "discovery_technique": "tainted-dependency-usage",
            "taint_evidence": best.taint_evidence,
            "dep_sink": best.sink_hit,
            "dep_usages": [asdict(u) for u in ulist[:8]],
            "evidence_scope": best.evidence_scope,
            "source_sha256": best.source_sha256,
        })

    if not analyzed_files:
        gaps.append("No supported first-party source files were available for dependency import mapping")
    return {
        "findings": findings,
        "usages": [asdict(u) for u in usages],
        "reachable_packages": reachable_high_risk,
        "candidate_packages": reachable_high_risk,
        "package_versions": [{"name": name, "version": version} for name, version in packages],
        "reachability_proven": False,
        "analysis_scope": "Import proximity and direct Python argv/environment expressions; no runtime or cross-function dataflow proof",
        "package_count": len(packages),
        "usage_count": len(usages),
        "status": ("partial" if analyzed_files else "blocked") if gaps else "completed",
        "scope_complete": not gaps,
        "scope": {"files_examined": analyzed_files, "bytes_read": read_bytes,
                  "file_limit": DEPENDENCY_SCAN_FILE_LIMIT, "byte_limit": DEPENDENCY_SCAN_BYTE_LIMIT,
                  "time_limit_seconds": DEPENDENCY_SCAN_SECONDS, "limits_reached": limits_reached,
                  "excluded_directories": sorted(_SKIP_DIRS),
                  "basis": "First-party import mapping; excluded directories and unexamined imports are not covered"},
        "reason": "; ".join(gaps[:8]),
        "gaps": gaps[:100],
        "gap_count": len(gaps),
    }


def discover_cli_entry_flags(dest: Path) -> List[Dict[str, Any]]:
    """Extract argparse/click/optparse/Homebrew/jc-style CLI flags for PoC planning."""
    dest = Path(dest).resolve()
    flags: List[Dict[str, Any]] = []
    patterns = [
        re.compile(r"""add_argument\(\s*['"](-{1,2}[a-zA-Z0-9-]+)['"]"""),
        re.compile(r"""@(?:click|typer)\.(?:option|argument)\(\s*['"](-{1,2}[a-zA-Z0-9-]+)['"]"""),
        re.compile(r"""opts\.on\(\s*['"](-{1,2}[a-zA-Z0-9-]+)['"]"""),
        # jc cli_data / completions: '--pretty': or "--yaml"
        re.compile(r"""['"](-{1,2}[a-zA-Z][\w-]{1,40})['"]\s*:"""),
        # Homebrew AbstractCommand: switch "--formula" / flag "--cask"
        re.compile(r"""(?:switch|flag|option)\s+['"](-{1,2}[a-zA-Z][\w-]{1,40})['"]"""),
        # Generic long-option string literals near help text
        re.compile(r"""['"](--(?:yaml|exec|eval|file|path|formula|cask|cmd|command|load|parse)[\w-]*)['"]"""),
    ]
    for path in _iter_source_files(dest, limit=1200):
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        if len(text) > 200_000:
            continue
        rel = str(path.relative_to(dest))
        for cre in patterns:
            for m in cre.finditer(text):
                flag = m.group(1)
                if len(flag) < 2:
                    continue
                flags.append({"flag": flag, "file": rel})
                if len(flags) >= 120:
                    break
            if len(flags) >= 120:
                break
        if len(flags) >= 120:
            break
    # de-dupe
    seen = set()
    out = []
    for f in flags:
        if f["flag"] in seen:
            continue
        seen.add(f["flag"])
        out.append(f)
    return out


def _contained_dependency_path(dest: Path, relative: str) -> Path:
    """Admit a real child directory, never an arbitrary path from repository text."""
    path = Path(str(relative or ""))
    root = dest.resolve()
    if not relative or path.is_absolute() or "\\" in relative or any(p in {"..", ".git", ".lotus"} for p in path.parts):
        raise ValueError("dependency path must be a contained local source directory")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("dependency root must not traverse a symlink")
    if current == root or not current.is_dir() or not current.resolve().is_relative_to(root):
        raise ValueError("dependency path is missing or outside the captured source")
    return current


def find_local_dep_roots(dest: Path, package_names: List[str]) -> List[DepAuditCandidate]:
    """Select contained roots by recorded package identity, never a basename."""
    from backend.dependency_sources import parse_manifest, parse_go_mod
    dest = Path(dest).resolve()
    requested = {str(name) for name in package_names if str(name).strip()}
    candidates = []
    identity_manifests = {"package.json", "pyproject.toml", "go.mod", "Cargo.toml", "composer.json"}
    visited = 0
    for dirname in ("vendor", "third_party", "third-party", "packages", "libs", "external", "deps", "sdk", "cli", "node_modules"):
        root = dest / dirname
        if root.is_symlink() or not root.is_dir():
            continue
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(name for name in dirs if name not in {".git", ".lotus", "__pycache__"}
                             and not (Path(directory) / name).is_symlink())
            visited += 1
            if visited > 2500:
                break
            for filename in sorted(identity_manifests.intersection(files)):
                path = Path(directory) / filename
                if path.is_symlink():
                    continue
                try:
                    with path.open("rb") as handle:
                        raw = handle.read(1_048_577)
                    if len(raw) > 1_048_576:
                        continue
                    parsed = parse_manifest(filename, raw.decode("utf-8"))
                    identity = parsed.get("identity") or {}
                    name = str(identity.get("name") or "")
                    matches = [package for package in requested if package == name or
                               (parsed["ecosystem"] == "python" and _package_key(package) == _package_key(name))]
                    if len(matches) != 1:
                        continue
                    relative = Path(directory).relative_to(dest).as_posix()
                    _contained_dependency_path(dest, relative)
                    candidates.append(DepAuditCandidate(name=matches[0], version=str(identity.get("version") or ""),
                        local_path=relative, reason="captured package manifest identity",
                        source_identity={"status": "manifest-identity", "name": name,
                            "version": str(identity.get("version") or ""), "ecosystem": parsed["ecosystem"],
                            "manifest": path.relative_to(dest).as_posix(),
                            "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}))
                except (OSError, ValueError, TypeError, KeyError, AttributeError):
                    continue
    # Go's vendor tool removes nested go.mod files. Its explicit module list
    # can identify a root only when the owning go.mod declares that version.
    module, vendor = dest / "go.mod", dest / "vendor/modules.txt"
    if module.is_file() and vendor.is_file() and not module.is_symlink() and not vendor.is_symlink():
        try:
            with module.open("rb") as handle:
                module_raw = handle.read(1_048_577)
            with vendor.open("rb") as handle:
                vendor_raw = handle.read(1_048_577)
            if max(len(module_raw), len(vendor_raw)) <= 1_048_576:
                declared = parse_go_mod(module_raw.decode("utf-8"))
                replaced = {row["name"] for row in declared["replacements"]}
                versions = {(row["name"], row["version"]) for row in declared["dependencies"]}
                for line in vendor_raw.decode("utf-8").splitlines():
                    match = re.fullmatch(r"# (\S+) (v\S+)", line.strip())
                    if not match or match.group(1) not in requested or match.group(1) in replaced or match.groups() not in versions:
                        continue
                    name, version = match.groups()
                    relative = "vendor/" + name
                    _contained_dependency_path(dest, relative)
                    candidates.append(DepAuditCandidate(name=name, version=version, local_path=relative,
                        reason="captured Go module and vendor identity",
                        source_identity={"status": "vendor-identity", "name": name, "version": version,
                            "ecosystem": "go", "manifest": "vendor/modules.txt",
                            "sha256": "sha256:" + hashlib.sha256(vendor_raw).hexdigest(),
                            "declaration_manifest": "go.mod",
                            "declaration_sha256": "sha256:" + hashlib.sha256(module_raw).hexdigest()}))
        except (OSError, ValueError, TypeError, KeyError):
            pass
    unique = {}
    for candidate in sorted(candidates, key=lambda row: (row.name, row.local_path, row.version)):
        unique.setdefault((candidate.name, candidate.local_path), candidate)
    return list(unique.values())


def usages_to_audit_candidates(dest: Path, analysis: Dict[str, Any], max_n: int = 3, *,
                              target_snapshot: Optional[dict] = None,
                              external_capture: Optional[dict] = None) -> List[DepAuditCandidate]:
    """Rank observed input interfaces; names and sink keywords are insufficient.

    Scores express review priority only. Missing runtime reachability, source
    resolution and version equivalence are retained as gaps for each child.
    """
    if type(max_n) is not int or max_n < 1:
        return []
    by_package = {}
    for raw in analysis.get("usages") or []:
        if not isinstance(raw, dict) or raw.get("near_taint") is not True or not raw.get("taint_evidence"):
            continue
        if not raw.get("import_line") or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(raw.get("source_sha256") or "")):
            continue
        try:
            usage = DepUsage(**{key: value for key, value in raw.items() if key in DepUsage.__dataclass_fields__})
        except (TypeError, ValueError):
            continue
        by_package.setdefault(usage.package, []).append(usage)
    roots = find_local_dep_roots(Path(dest), list(by_package))
    if external_capture and target_snapshot:
        from backend.dependency_source_views import registered_bundles, bundle_root
        for receipt in registered_bundles(target_snapshot, external_capture):
            # Missing checksum bytes remain browsable, but cannot silently
            # become a revision-attested dependency child source.
            if receipt["source_status"] != "captured-external":
                continue
            for ref in receipt["references"]:
                name, version = ref["declared_name"], ref["declared_version"]
                if name not in by_package or any(row.name == name and row.version == version for row in roots):
                    continue
                roots.append(DepAuditCandidate(name=name, version=version,
                    source_identity={"manifest": ref["manifest"], "sha256": ref["sha256"],
                        "ecosystem": "go", "basis": "verified-go-sum", "captured_name": receipt["name"],
                        "captured_version": receipt["version"]},
                    external_bundle={"bundle_path": receipt["bundle_path"],
                        "manifest_sha256": receipt["manifest_sha256"], "source_root": bundle_root(receipt)}))
    declared_versions = {}
    for row in analysis.get("package_versions") or []:
        if isinstance(row, dict):
            declared_versions.setdefault(row.get("name"), set()).add(str(row.get("version") or ""))
    out = []
    for candidate in roots:
        usages = sorted(by_package.get(candidate.name, []), key=lambda row: (row.file, row.line, row.import_line))
        if not usages:
            continue
        direct = sum(usage.evidence_scope == "direct-input-expression" for usage in usages)
        sink = sum(bool(usage.sink_hit) for usage in usages)
        sites = len({(usage.file, usage.line) for usage in usages})
        candidate.priority_score = (80 if direct else 40) + (10 if sink else 0) + min(sites, 9)
        candidate.evidence_scope = "direct-input-expression" if direct else "lexical-proximity"
        candidate.priority_reasons = [
            f"{direct} direct Python argv/environment argument site(s)" if direct else
            "Imported dependency appears near a potential untrusted input source; dataflow is unproven",
            f"{sites} recorded input candidate site(s)",
            "Sink/API syntax observed; this is review priority, not vulnerability severity" if sink else
            "No dependency sink syntax was recorded",
        ]
        candidate.usages = usages
        candidate.source_refs = [{"file": usage.file, "sha256": usage.source_sha256,
            "line": usage.line, "import_line": usage.import_line, "taint_line": usage.taint_line,
            "sink_line": usage.sink_line, "evidence_scope": usage.evidence_scope} for usage in usages]
        candidate.selection_gaps = ["Runtime reachability and dependency behavior require fresh validation",
                                    "Captured package metadata does not attest installed/build version equivalence"]
        versions = declared_versions.get(candidate.name, set()) - {""}
        candidate.source_identity["declared_versions"] = sorted(versions)
        if not candidate.version and len(versions) == 1:
            candidate.version = next(iter(versions))
            candidate.source_identity["version_status"] = "declared-constraint-only"
        elif candidate.version:
            candidate.source_identity["version_status"] = "verified-go-sum" if candidate.external_bundle else "captured-package-metadata"
        else:
            candidate.source_identity["version_status"] = "unknown"
            candidate.selection_gaps.append("Dependency version is not recorded")
        candidate.reason = "; ".join(candidate.priority_reasons)
        out.append(candidate)
    out.sort(key=lambda row: (-row.priority_score, row.name, row.version, row.local_path or row.external_bundle.get("source_root", "")))
    selected = out[:max_n]
    analysis["candidate_selection"] = {
        "method": "evidence-priority-v1", "budget": max_n, "eligible": len(out), "selected": len(selected),
        "not_selected": [{"name": row.name, "path": row.local_path, "priority_score": row.priority_score,
                          "reason": "Outside the selected child audit budget"} for row in out[max_n:]],
        "gaps": [{"name": name, "reason": "No matching captured package identity was found within local root discovery scope (2500 directories); basename matches are not source evidence"}
                 for name in sorted(set(by_package) - {row.name for row in out})],
        "coverage_complete": False,
    }
    return selected


def candidate_from_payload(value: dict) -> DepAuditCandidate:
    """Restore the full controller-produced handoff without dropping evidence."""
    payload = {key: item for key, item in value.items() if key in DepAuditCandidate.__dataclass_fields__}
    payload["usages"] = [DepUsage(**{key: item for key, item in usage.items()
                                     if key in DepUsage.__dataclass_fields__})
                         if isinstance(usage, dict) else usage for usage in payload.get("usages") or []]
    return DepAuditCandidate(**payload)


def _verify_candidate_evidence(source: Path, candidate: DepAuditCandidate) -> None:
    """Rebind selection evidence to the parent's captured bytes before enqueue."""
    checks = [(row.get("file"), row.get("sha256")) for row in candidate.source_refs]
    identity = candidate.source_identity
    if identity:
        checks.append((identity.get("manifest"), identity.get("sha256")))
        if identity.get("declaration_manifest"):
            checks.append((identity["declaration_manifest"], identity.get("declaration_sha256")))
    for name, expected in set(checks):
        relative = Path(str(name or ""))
        if (not name or relative.is_absolute() or "\\" in str(name)
                or any(part in {"..", ".git", ".lotus"} for part in relative.parts)
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(expected or ""))):
            raise ValueError("Dependency selection evidence has an invalid source binding")
        path = source / relative
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(source):
            raise ValueError("Dependency selection evidence is absent from the captured source")
        with path.open("rb") as handle:
            actual = "sha256:" + hashlib.file_digest(handle, "sha256").hexdigest()
        if actual != expected:
            raise ValueError("Dependency selection evidence differs from the captured parent source")


def _snapshot_dependency_subtree(captured: dict, local: Path, repo_id: int, job_id: int) -> dict:
    """Project the parent's exact tracked inventory, modes and confined aliases."""
    from backend.target_snapshots import (snapshot_files, validate_source_metadata, copy_source_selection,
        preserve_checkout_selection, create_snapshot)
    from backend.proof_receipts import source_content_files
    source = Path(captured["source_path"])
    inventory = snapshot_files(source, captured)
    inventory = source_content_files(source) if inventory is None else inventory
    selected = [path for path in inventory if path.is_relative_to(local)]
    if not selected:
        raise ValueError("Dependency root has no captured source files")
    metadata = validate_source_metadata(source, captured)
    modes, aliases = {}, {}
    for path in selected:
        modes[path.relative_to(local).as_posix()] = (metadata["files"][path.relative_to(source).as_posix()]
            if metadata is not None else path.stat().st_mode & 0o777)
    for name, target in (metadata or {}).get("aliases", {}).items():
        alias = source / name
        if not alias.is_relative_to(local):
            continue
        resolved = source / target
        if not resolved.is_relative_to(local):
            raise ValueError("Dependency root requires source outside its subtree; audit the complete workspace instead")
        aliases[alias.relative_to(local).as_posix()] = resolved.relative_to(local).as_posix()
    with tempfile.TemporaryDirectory(prefix="lotus-dependency-source-") as temporary:
        staged = Path(temporary) / "source"
        copy_source_selection(local, staged, selected,
            metadata={"schema_version": 1, "files": modes, "aliases": aliases})
        # Tracked dist/build files remain source even though their generic
        # directory names are normally excluded for untracked local inputs.
        preserve_checkout_selection(staged, sorted(modes))
        return create_snapshot(staged, repo_id=repo_id, job_id=job_id)


def _snapshot_external_dependency(receipt: dict, repo_id: int, job_id: int) -> dict:
    """Project signed archive bytes into the ordinary immutable child format."""
    from backend.source_index import _open_source
    from backend.target_snapshots import preserve_checkout_selection, create_snapshot
    with tempfile.TemporaryDirectory(prefix="lotus-external-dependency-") as temporary:
        staged = Path(temporary) / "source"
        staged.mkdir()
        for entry in receipt["files"]:
            target = staged / entry["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            digest, size = hashlib.sha256(), 0
            with _open_source(receipt["source_path"], entry["path"]) as source, target.open("xb") as output:
                while chunk := source.read(65536):
                    digest.update(chunk)
                    size += len(chunk)
                    if size > entry["bytes"]:
                        raise ValueError("Dependency source grew during child projection")
                    output.write(chunk)
            if size != entry["bytes"] or "sha256:" + digest.hexdigest() != entry["sha256"]:
                raise ValueError("Dependency source changed during child projection")
        preserve_checkout_selection(staged, sorted(row["path"] for row in receipt["files"]))
        return create_snapshot(staged, repo_id=repo_id, job_id=job_id)


async def spawn_parallel_dependency_audits(
    *, parent_repo_id: int, dest: Path, language: str,
    candidates: List[DepAuditCandidate], db_factory: Callable, repo_cls: type,
    finding_cls: type, scan_job_cls: type, notify: Optional[Callable] = None,
    cvss_threshold: float = 7.0, max_children: int = 3,
    settings: Optional[Dict[str, Any]] = None, parent_job_id: Optional[int] = None,
    target_snapshot: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Schedule independent, snapshot-bound jobs through the normal worker pool.

    Never await child completion here: with one worker the parent occupies the
    only slot. Enqueue receipts are not coverage evidence or completion claims.
    """
    from backend.ai_readiness import require_ready
    from backend.main import Settings
    from backend.scan_worker import _submit_durable_from_drain
    from backend.target_snapshots import load_snapshot

    settings = read_dep_audit_settings() if settings is None else settings
    result = {"enabled": False, "parent_repo_id": parent_repo_id,
              "parent_job_id": parent_job_id, "spawned": [], "coverage_complete": False,
              "execution": "independent-durable-jobs", "candidate_count": len(candidates),
              "candidate_limit": 64,
              "unexamined_candidates": max(0, len(candidates) - 64)}
    if settings.get("dependency_audit_enabled") is False:
        return {**result, "skipped_reason": "dependency_audit_enabled disabled in Settings"}
    if not settings.get("parallel_dependency_audits"):
        return {**result, "skipped_reason": "disabled"}
    result["enabled"] = True
    try:
        depth = int(settings.get("dep_audit_depth", 0))
        if depth < 0:
            raise ValueError("negative depth")
        saved_limit = settings.get("max_dependency_audits", max_children)
        if type(max_children) not in {int, str} or type(saved_limit) not in {int, str}:
            raise ValueError("child budget is not an integer")
        limit = min(int(max_children), int(saved_limit))
        if limit < 1 or limit > 8:
            raise ValueError("empty child budget")
    except (TypeError, ValueError):
        return {**result, "skipped_reason": "invalid dependency audit policy"}
    if depth >= 1:
        return {**result, "skipped_reason": "maximum child depth 1"}
    if not candidates:
        return {**result, "skipped_reason": "no matching captured dependency roots"}

    with db_factory() as db:
        require_ready(db.query(Settings).first())
        parent = db.query(scan_job_cls).filter(scan_job_cls.repo_id == parent_repo_id)
        parent = (parent.filter(scan_job_cls.id == parent_job_id).first() if parent_job_id is not None
                  else parent.order_by(scan_job_cls.id.desc()).first())
        if parent is None or parent.status not in {"running", "paused"} or parent.control == "cancel":
            return {**result, "skipped_reason": "parent audit is no longer active"}
        parent_job_id = int(parent.id)
        parent_output = json.loads(parent.output or "{}")
        snapshot_ref = target_snapshot or parent_output.get("target_snapshot") or {}
        recorded_snapshot = parent_output.get("target_snapshot") or {}
        if recorded_snapshot and any(recorded_snapshot.get(key) != snapshot_ref.get(key)
                                     for key in ("tree_hash", "manifest_hash")):
            raise ValueError("dependency snapshot differs from the recorded parent audit")
        parent_repo = db.query(repo_cls).filter(repo_cls.id == parent_repo_id).first()
        branch = str(getattr(parent_repo, "branch", "") or "main")
    result["parent_job_id"] = parent_job_id
    # Verify the entire parent object once before selecting any source root.
    captured = await asyncio.to_thread(load_snapshot, str(snapshot_ref.get("path") or ""))
    if (snapshot_ref.get("tree_hash") != captured["tree_hash"]
            or snapshot_ref.get("manifest_hash") != captured["manifest_hash"]):
        raise ValueError("dependency source differs from the selected parent snapshot")
    source = Path(captured["source_path"])
    seen = set()
    for cand in candidates[:64]:
        if sum(bool(row.get("repo_id")) for row in result["spawned"]) >= limit:
            break
        candidate_path = cand.local_path or str(cand.external_bundle.get("source_root") or "")
        if candidate_path in seen:
            continue
        seen.add(candidate_path)
        row = {"name": cand.name, "version": cand.version, "path": candidate_path, "reason": cand.reason,
               "priority_score": cand.priority_score, "priority_reasons": cand.priority_reasons,
               "evidence_scope": cand.evidence_scope, "source_identity": cand.source_identity,
               "source_refs": cand.source_refs, "selection_gaps": cand.selection_gaps}
        try:
            _verify_candidate_evidence(source, cand)
            external = None
            if cand.external_bundle:
                from backend.dependency_source_capture import verify_capture_bundle
                from backend.dependency_source_views import bundle_root
                external = verify_capture_bundle(cand.external_bundle.get("bundle_path") or "", captured)
                if (external["source_status"] != "captured-external"
                        or external["manifest_sha256"] != cand.external_bundle.get("manifest_sha256")
                        or bundle_root(external) != candidate_path
                        or not cand.source_refs
                        or not any(ref["declared_name"] == cand.name and ref["declared_version"] == cand.version
                            and ref["manifest"] == cand.source_identity.get("manifest")
                            and ref["sha256"] == cand.source_identity.get("sha256") for ref in external["references"])):
                    raise ValueError("External dependency child source differs from its captured declaration")
            else:
                local = _contained_dependency_path(source, cand.local_path)
        except (ValueError, TypeError, AttributeError, OSError) as exc:
            result["spawned"].append({**row, "status": "rejected", "reason": str(exc)})
            continue
        # This independent object survives parent checkout/lab cleanup and
        # cannot acquire subsequently generated files from the working tree.
        try:
            if external:
                child_snapshot = await asyncio.to_thread(_snapshot_external_dependency, external,
                    parent_repo_id, parent_job_id)
            else:
                child_snapshot = await asyncio.to_thread(_snapshot_dependency_subtree, captured, local,
                    parent_repo_id, parent_job_id)
        except ValueError as exc:
            result["spawned"].append({**row, "status": "rejected", "reason": str(exc)})
            continue
        context = {"repo_id": parent_repo_id, "job_id": parent_job_id,
                   "path": candidate_path, "depth": depth + 1,
                   "parent_snapshot": captured["path"], "parent_tree_hash": captured["tree_hash"],
                   "parent_manifest_hash": captured["manifest_hash"],
                   "parent_target_revision": str(captured.get("target_revision") or ""),
                   "child_tree_hash": child_snapshot["tree_hash"],
                   "child_manifest_hash": child_snapshot["manifest_hash"],
                   "dependency": {"name": cand.name, "version": cand.version,
                                  "source_identity": cand.source_identity,
                                  "external_bundle": cand.external_bundle},
                   "selection": {"priority_score": cand.priority_score, "reasons": cand.priority_reasons,
                                 "evidence_scope": cand.evidence_scope, "source_refs": cand.source_refs,
                                 "gaps": cand.selection_gaps},
                   "runtime_contract": {"mode": "independent-child-runtime", "owns_parent_runtime": False,
                                        "shared_parent_runtime": False,
                                        "gap": "Shared parent lab observation requires an exact runtime binding and retained ownership lease"},
                   "source_revision_status": "verified-go-module-archive" if external else "captured-parent-subtree" if captured.get("target_revision") else "content-hash-only",
                   "dependency_revision_status": "independent Git revision is not attested",
                   "evidence_basis": "potential dependency input path; fresh child validation required"}
        with db_factory() as db:
            parent = db.query(scan_job_cls).filter(scan_job_cls.id == parent_job_id,
                scan_job_cls.repo_id == parent_repo_id).first()
            if parent is None or parent.control == "cancel" or parent.status not in {"running", "paused"}:
                result["skipped_reason"] = "parent audit stopped during dependency scheduling"
                break
            # Share a write fence with parent controls. If cancellation wins,
            # this CAS fails; if enrollment wins, cancellation cannot inspect
            # children until this child is committed and visible to its cascade.
            fenced = db.query(scan_job_cls).filter(scan_job_cls.id == parent_job_id,
                scan_job_cls.repo_id == parent_repo_id, scan_job_cls.status == parent.status,
                scan_job_cls.control == parent.control).update({"status": parent.status}, synchronize_session=False)
            if not fenced:
                db.rollback()
                result["skipped_reason"] = "parent audit changed during dependency scheduling"
                break
            require_ready(db.query(Settings).first())
            existing, linked_children = None, []
            for prior in db.query(scan_job_cls).filter(scan_job_cls.id > parent_job_id,
                    scan_job_cls.repo_id != parent_repo_id):
                try:
                    prior_context = json.loads(prior.output or "{}").get("dependency_parent") or {}
                except (TypeError, ValueError, AttributeError):
                    continue
                if prior_context.get("repo_id") == parent_repo_id and prior_context.get("job_id") == parent_job_id:
                    linked_children.append(prior)
                    if (prior_context.get("path") == candidate_path
                            and prior_context.get("child_tree_hash") == child_snapshot["tree_hash"]
                            and prior.replay_snapshot_path == child_snapshot["source_path"]):
                        existing = prior
            if existing is not None:
                result["spawned"].append({**row, "repo_id": int(existing.repo_id), "job_id": int(existing.id),
                    "status": str(existing.status), "reused": True, "target_tree_hash": child_snapshot["tree_hash"]})
                continue
            # The captured budget applies to the whole parent audit, including
            # resumed scheduling calls and already terminal children. This
            # count is read under the same parent-row write fence as enrollment.
            if len(linked_children) >= limit:
                result["skipped_reason"] = f"Parent dependency audit budget {limit} is already allocated"
                result["allocated_children"] = len(linked_children)
                break
            child = repo_cls(source=child_snapshot["source_path"], branch=branch,
                             mode="one-time", status="queued")
            db.add(child)
            db.flush()
            from backend.audit_depth import admitted_depth
            job = scan_job_cls(repo_id=child.id, status="queued", started_at=datetime.now(timezone.utc),
                audit_depth=admitted_depth(settings or {}, previous=parent),
                output=json.dumps({"dependency_parent": context}),
                replay_snapshot_path=child_snapshot["source_path"],
                replay_target_identity_json=json.dumps({"target_tree_hash": child_snapshot["tree_hash"]}))
            db.add(job)
            db.commit()
            child_id, job_id = int(child.id), int(job.id)
        try:
            admission = await asyncio.to_thread(_submit_durable_from_drain,
                child_id, job_id, db_factory, repo_cls, finding_cls, scan_job_cls, None, cvss_threshold)
            status = str(admission.get("status") or "deferred")
        except Exception:
            status = "not_scheduled"
        if status in {"queue_full", "not_scheduled"}:
            # The child is already durable. Normal backpressure defers it to
            # the existing queue drain; it is not an audit failure and must
            # not overwrite a lease another replica may have just acquired.
            row["dispatch_reason"] = "Waiting for worker capacity" if status == "queue_full" else "Durable audit awaiting scheduler recovery"
            status = "deferred"
        elif status == "resetting":
            from backend.scan_worker import set_scan_control
            try:
                outcome = set_scan_control(child_id, "cancel", expected_job_id=job_id)
                status = "cancelled" if outcome.get("control") == "cancelled" else "cancelling"
            except RuntimeError:
                status = "cancelling"
        result["spawned"].append({**row, "repo_id": child_id, "job_id": job_id,
            "status": status, "target_tree_hash": child_snapshot["tree_hash"]})
        if notify:
            await notify(parent_repo_id,
                f"Dependency audit {cand.name}: {status} (audit #{job_id}); track its separate coverage and report",
                detail_id=f"{parent_repo_id}-dependency-child-{job_id}",
                detail={"type": "dependency-child", **result["spawned"][-1]})
    result["depth"] = depth + 1
    result["scheduled"] = sum(row.get("status") in {"queued", "started", "running", "already_running", "deferred"}
                              for row in result["spawned"])
    return result


def cancel_dependency_children(parent_repo_id: int, parent_job_id: Optional[int] = None) -> list[int]:
    """Cancel only active children bound to this exact parent audit, never its history."""
    from backend.main import SessionLocal, ScanJob
    from backend.scan_worker import set_scan_control
    if _CANCELLING_DEPENDENCIES.get():
        return []
    with SessionLocal() as db:
        parent = db.query(ScanJob).filter(ScanJob.repo_id == int(parent_repo_id))
        parent = (parent.filter(ScanJob.id == int(parent_job_id)).first() if parent_job_id is not None
                  else parent.order_by(ScanJob.id.desc()).first())
        if parent is None:
            return []
        selected_job = int(parent.id)
        targets = []
        for child in db.query(ScanJob).filter(ScanJob.status.in_(["queued", "running", "paused"])):
            try:
                context = json.loads(child.output or "{}").get("dependency_parent") or {}
            except (TypeError, ValueError, AttributeError):
                continue
            if (context.get("repo_id") == int(parent_repo_id) and context.get("job_id") == selected_job
                    and child.repo_id != int(parent_repo_id)):
                targets.append((int(child.repo_id), int(child.id)))
    token = _CANCELLING_DEPENDENCIES.set(True)
    try:
        cancelled = []
        for repo_id, job_id in targets:
            try:
                outcome = set_scan_control(repo_id, "cancel", expected_job_id=job_id)
                if not outcome.get("running") and outcome.get("control") != "cancelled":
                    from backend.audit_cancellation import schedule_runtime_cleanup
                    schedule_runtime_cleanup(repo_id, job_id)
                cancelled.append(job_id)
            except RuntimeError:
                # An independently completed child must not prevent the
                # remaining children or parent from being cancelled.
                continue
        return cancelled
    finally:
        _CANCELLING_DEPENDENCIES.reset(token)
