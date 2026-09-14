"""Static dependency declarations and source availability in an exact snapshot.

This never installs packages, executes a manifest, or treats a controller/module
cache as audited source. Format adapters preserve raw version constraints; a
declaration, captured code, and completed review are separate states.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
import shlex
import tomllib
from bisect import bisect_left
from collections import defaultdict

from backend import source_index

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PARSE_BYTES = 16 * 1024 * 1024
MANIFEST_NAMES = {
    "go.mod", "go.work", "package.json", "package-lock.json", "npm-shrinkwrap.json",
    "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "pyproject.toml", "setup.py",
    "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "Gemfile",
    "Gemfile.lock", "Cargo.toml", "Cargo.lock", "composer.json", "composer.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "packages.lock.json",
}


def _is_manifest_name(name: str) -> bool:
    """Recognize unsupported declarations so their absence is not invented."""
    return (name in MANIFEST_NAMES or name == "Directory.Packages.props"
            or name.lower().endswith((".csproj", ".fsproj", ".vbproj"))
            or re.fullmatch(r"requirements[^/]*\.(?:txt|in)", name, re.IGNORECASE) is not None)


def parse_go_mod(text: str) -> dict:
    """Preserve complete module versions, single/block requires and replacements."""
    result = {"module": "", "dependencies": [], "replacements": [], "gaps": []}
    block = ""
    for number, line in enumerate(text.splitlines(), 1):
        try:
            # Go line comments start outside strings even without preceding
            # whitespace. Preserve // inside quoted local replacement paths.
            quoted = escaped = False
            for offset, char in enumerate(line):
                if escaped:
                    escaped = False
                elif quoted and char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = not quoted
                elif not quoted and line[offset:offset + 2] == "//":
                    line = line[:offset]
                    break
            lexer = shlex.shlex(line, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            parts = []
            for token in lexer:
                if token.startswith("//"):
                    break
                parts.append(token)
        except ValueError:
            result["gaps"].append(f"Unparsed Go module line {number}")
            continue
        if not parts:
            continue
        if parts == [")"]:
            block = ""
            continue
        directive, values = (block, parts) if block else (parts[0], parts[1:])
        if values == ["("]:
            block = directive
            continue
        if directive == "module":
            if len(values) != 1 or not values[0] or result["module"]:
                result["gaps"].append(f"Unparsed or duplicate Go module declaration at line {number}")
            else:
                result["module"] = values[0]
        elif directive == "require":
            if len(values) != 2 or not values[1].startswith("v"):
                result["gaps"].append(f"Unparsed Go require line {number}")
            else:
                result["dependencies"].append({"name": values[0], "version": values[1], "line": number})
        elif directive == "replace":
            if "=>" not in values:
                result["gaps"].append(f"Unparsed Go replacement line {number}")
                continue
            split = values.index("=>")
            left, right = values[:split], values[split + 1:]
            if len(left) not in (1, 2) or len(right) not in (1, 2):
                result["gaps"].append(f"Unparsed Go replacement line {number}")
            else:
                result["replacements"].append({"name": left[0], "version": left[1] if len(left) == 2 else "",
                    "replacement": right[0], "replacement_version": right[1] if len(right) == 2 else ""})
    if block:
        result["gaps"].append("Unclosed Go module declaration block")
    if not result["module"]:
        result["gaps"].append("Go module identity is missing")
    return result


def _requirements(lines):
    from packaging.requirements import Requirement, InvalidRequirement
    deps, gaps = [], []
    for number, text in enumerate(lines, 1):
        raw = str(text).strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            req = Requirement(raw.split(" #", 1)[0])
        except InvalidRequirement:
            gaps.append(f"Unresolved requirement at entry {number}; includes, options and executable setup need a locked resolver")
            continue
        deps.append({"name": req.name, "version": req.url or str(req.specifier),
                     "marker": str(req.marker or ""), "line": number})
    return deps, gaps


def parse_manifest(name: str, text: str) -> dict:
    """Return declared identities without claiming a resolved transitive graph."""
    result = {"ecosystem": "unknown", "dependencies": [], "identity": {}, "gaps": []}
    if name == "go.mod":
        parsed = parse_go_mod(text)
        return {**result, **parsed, "ecosystem": "go", "identity": {"name": parsed["module"]}}
    if name == "package.json":
        data = json.loads(text)
        result.update(ecosystem="node", identity={"name": data.get("name", ""), "version": data.get("version", "")})
        for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            for package, version in (data.get(section) or {}).items():
                result["dependencies"].append({"name": package, "version": str(version), "scope": section})
        declared = {row["name"] for row in result["dependencies"]}
        for key in ("bundleDependencies", "bundledDependencies"):
            bundled = data.get(key)
            if isinstance(bundled, list) and any(not isinstance(name, str) or name not in declared for name in bundled):
                result["gaps"].append("Bundled package identities without corresponding dependency declarations require a resolved source adapter")
            elif bundled is not None and type(bundled) is not bool and not isinstance(bundled, list):
                result["gaps"].append("Bundled dependency declaration format is unsupported")
    elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
        data = json.loads(text)
        result["ecosystem"] = "node"
        if isinstance(data.get("packages"), dict):
            for path, entry in data["packages"].items():
                if not path or not isinstance(entry, dict):
                    continue
                if entry.get("link"):
                    result["gaps"].append(f"Workspace link {path} needs its captured package identity")
                    continue
                package = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
                result["dependencies"].append({"name": package, "version": str(entry.get("version") or ""),
                    "install_path": path, "integrity": str(entry.get("integrity") or ""),
                    "scope": "development" if entry.get("dev") else "locked"})
        else:
            result["gaps"].append("npm lockfile v1 requires a resolved source adapter")
    elif name == "requirements.txt":
        result["ecosystem"] = "python"
        result["dependencies"], result["gaps"] = _requirements(text.splitlines())
    elif name == "pyproject.toml":
        data = tomllib.loads(text)
        project = data.get("project") or {}
        result.update(ecosystem="python", identity={"name": project.get("name", ""), "version": project.get("version", "")})
        declarations = list(project.get("dependencies") or [])
        for entries in (project.get("optional-dependencies") or {}).values():
            declarations.extend(entries)
        result["dependencies"], result["gaps"] = _requirements(declarations)
        if (data.get("tool") or {}).get("poetry") or any(key in (project.get("dynamic") or []) for key in ("dependencies", "optional-dependencies")):
            result["gaps"].append("Dynamic or Poetry dependency declarations require a locked resolver")
    elif name in {"Cargo.toml", "Cargo.lock"}:
        data = tomllib.loads(text)
        result["ecosystem"] = "rust"
        if name == "Cargo.lock":
            result["dependencies"] = [{"name": row["name"], "version": row["version"], "integrity": row.get("checksum", "")}
                                      for row in data.get("package", [])]
        else:
            result["identity"] = {key: (data.get("package") or {}).get(key, "") for key in ("name", "version")}
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                for package, entry in (data.get(section) or {}).items():
                    result["dependencies"].append({"name": entry.get("package", package) if isinstance(entry, dict) else package,
                        "version": str(entry.get("version", "")) if isinstance(entry, dict) else str(entry), "scope": section})
            if data.get("workspace") or data.get("target"):
                result["gaps"].append("Cargo workspace/target selections require the resolved lock graph")
    elif name in {"composer.json", "composer.lock"}:
        data = json.loads(text)
        result["ecosystem"] = "php"
        if name.endswith(".lock"):
            result["dependencies"] = [{"name": row["name"], "version": row["version"]}
                                      for row in [*data.get("packages", []), *data.get("packages-dev", [])]]
        else:
            result["identity"] = {key: data.get(key, "") for key in ("name", "version")}
            for section in ("require", "require-dev"):
                result["dependencies"].extend({"name": package, "version": str(version), "scope": section}
                                              for package, version in (data.get(section) or {}).items())
    else:
        result["gaps"].append(f"{name} is captured; a source-resolution adapter for this format is unavailable")
    return result


def _contained_path(base: str, relative: str) -> str:
    if not relative or relative.startswith(("/", "\\")) or "\\" in relative:
        return ""
    parts = []
    for part in (PurePosixPath(base) / relative).parts:
        if part == "..":
            if not parts:
                return ""
            parts.pop()
        elif part != ".":
            parts.append(part)
    return "/".join(parts) or "."


def dependency_source_inventory(snapshot: dict, external_capture: dict | None = None) -> dict:
    """Describe all captured manifests, exact local roots, and missing code."""
    meta, index, pending = source_index._source_index(snapshot)
    if pending:
        return pending
    files, manifests, packages, gaps = index["files"], [], [], []
    file_names = sorted(files)

    def captured_count(root):
        if root == ".":
            return len(file_names)
        # Every root/ descendant sorts before root0. This avoids rescanning
        # the whole repository once per locked dependency declaration.
        return bisect_left(file_names, root + "0") - bisect_left(file_names, root + "/")

    parsed_bytes = 0
    parsed = {}
    for path in file_names:
        entry = files[path]
        if not _is_manifest_name(PurePosixPath(path).name):
            continue
        row = {"path": path, "sha256": entry["sha256"], "bytes": entry["bytes"]}
        manifests.append(row)
        try:
            if entry["bytes"] > MAX_MANIFEST_BYTES:
                raise ValueError("Manifest exceeds the 4 MiB parsing budget; all original bytes remain captured")
            if parsed_bytes + entry["bytes"] > MAX_PARSE_BYTES:
                raise ValueError("Dependency inventory exceeds the 16 MiB parsing budget; this manifest remains unparsed")
            parsed_bytes += entry["bytes"]
            with source_index._open_source(meta["source_path"], path) as handle:
                raw = handle.read(MAX_MANIFEST_BYTES + 1)
            if "sha256:" + hashlib.sha256(raw).hexdigest() != entry["sha256"]:
                raise source_index.SourceChanged("Dependency manifest no longer matches the audit")
            item = parse_manifest(PurePosixPath(path).name, raw.decode("utf-8"))
            parsed[path] = item
            row.update(ecosystem=item["ecosystem"], declared_packages=len(item["dependencies"]), status="partial" if item["gaps"] else "parsed")
            gaps.extend({"manifest": path, "reason": reason} for reason in item["gaps"])
        except source_index.SourceChanged:
            raise
        except (ValueError, TypeError, KeyError, AttributeError, OSError) as exc:
            row.update(status="blocked", reason=str(exc)[:300])
            gaps.append({"manifest": path, "reason": row["reason"]})
    vendored_go = {}
    for vendor_path in (path for path in file_names if path == "vendor/modules.txt" or path.endswith("/vendor/modules.txt")):
        module_path = str(PurePosixPath(vendor_path).parent.parent / "go.mod")
        if module_path not in parsed:
            gaps.append({"manifest": vendor_path, "reason": "Go vendor identities have no parsed owning go.mod; dependency declarations remain unresolved"})
        size = files[vendor_path]["bytes"]
        if size > MAX_MANIFEST_BYTES:
            gaps.append({"manifest": vendor_path, "reason": "Go vendor identity inventory exceeds its parsing budget"})
            continue
        if parsed_bytes + size > MAX_PARSE_BYTES:
            gaps.append({"manifest": vendor_path, "reason": "Go vendor identity inventory exceeds the shared dependency parsing budget"})
            continue
        parsed_bytes += size
        with source_index._open_source(meta["source_path"], vendor_path) as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
        if "sha256:" + hashlib.sha256(raw).hexdigest() != files[vendor_path]["sha256"]:
            raise source_index.SourceChanged("Go vendor identity inventory differs from the audit")
        vendor_root = str(PurePosixPath(vendor_path).parent)
        try:
            lines = raw.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            gaps.append({"manifest": vendor_path, "reason": "Go vendor identity inventory is not valid UTF-8"})
            continue
        for line in lines:
            # Replaced modules require their replacement identity; never erase
            # the distinction by matching only the left-hand module name.
            match = re.fullmatch(r"# (\S+) (v\S+)", line.strip())
            if match:
                vendored_go[(vendor_root, *match.groups())] = vendor_root + "/" + match.group(1)
    identities_by_root = defaultdict(list)
    for path, item in parsed.items():
        identities_by_root[(str(PurePosixPath(path).parent), item["ecosystem"])].append(item.get("identity") or {})
    for path, item in parsed.items():
        base = str(PurePosixPath(path).parent)
        replacements_by_name = defaultdict(list)
        for replacement in item.get("replacements", []):
            replacements_by_name[replacement["name"]].append(replacement)
        for dep in item["dependencies"]:
            row = {**dep, "ecosystem": item["ecosystem"], "manifest": path,
                   "source_status": "missing", "source_roots": [], "source_files": 0, "review_status": "unverified"}
            expected_name = dep["name"]
            candidates = []
            if item["ecosystem"] == "node" and str(dep["version"]).startswith("file:"):
                candidates.append(_contained_path(base, dep["version"][5:]))
            elif item["ecosystem"] == "node" and dep.get("install_path"):
                candidates.append(_contained_path(base, dep["install_path"]))
            elif item["ecosystem"] == "go":
                for replacement in replacements_by_name.get(expected_name, []):
                    if replacement["version"] in ("", dep["version"]):
                        row["replacement"] = dict(replacement)
                        if replacement["replacement"].startswith("."):
                            candidates.append(_contained_path(base, replacement["replacement"]))
                vendor_root = _contained_path(base, "vendor")
                vendor = vendored_go.get((vendor_root, expected_name, dep["version"])) if "replacement" not in row else None
                captured = captured_count(vendor) if vendor else 0
                if captured:
                    row["source_roots"].append(vendor)
                    row["source_files"] += captured
                    row["captured_identities"] = [{"name": expected_name, "version": dep["version"],
                                                   "basis": vendor_root + "/modules.txt"}]
            for candidate in set(candidates) - {""}:
                identities = identities_by_root.get((candidate, item["ecosystem"]), [])
                if any(identity.get("name") == expected_name and (not dep.get("install_path") or identity.get("version") == dep["version"])
                       for identity in identities):
                    captured = captured_count(candidate)
                    if captured:
                        row["source_roots"].append(candidate)
                        row["source_files"] += captured
                        row["captured_identities"] = identities
            if row["source_roots"]:
                row["source_status"] = "captured-local"
                row["reason"] = "Explicit local path and package identity captured; version/build equivalence and review remain unverified"
            else:
                row["reason"] = "Dependency code is not bound to a captured source root; resolver/download caches are not audit evidence"
            packages.append(row)
    external_files, external_bytes = 0, 0
    if external_capture:
        from backend.dependency_source_views import registered_bundles, bundle_context
        by_declaration = defaultdict(list)
        for receipt in registered_bundles(meta, external_capture):
            external_files += receipt["source_files"]
            external_bytes += receipt["source_bytes"]
            for ref in receipt["references"]:
                by_declaration[(ref["manifest"], ref["declared_name"], ref["declared_version"])].append((receipt, ref))
        for row in packages:
            matches = by_declaration.get((row["manifest"], row["name"], row["version"]), [])
            if row["ecosystem"] != "go" or row["source_status"] == "captured-local" or not matches:
                continue
            # Ambiguous capture never selects an arbitrary version/source.
            if len(matches) != 1:
                gaps.append({"manifest": row["manifest"], "name": row["name"], "reason": "Multiple external sources claim this declaration"})
                continue
            receipt, ref = matches[0]
            if ref["sha256"] != files[row["manifest"]]["sha256"]:
                raise source_index.SourceChanged("Dependency bundle declaration hash differs from the parent index")
            context = bundle_context(receipt)
            row.update(source_status=receipt["source_status"], source_roots=[context["source_root"]],
                       source_files=receipt["source_files"], external_source=context,
                       reason="Separate immutable dependency bundle; " + receipt["checksum_status"] + "; review and resolved build graph remain unverified")
        # A disabled downloader is an explicit task exclusion, not evidence of
        # unresolved packages when the authenticated inventory parsed every
        # captured declaration input and found none. Preserve its notice in
        # the capture receipt; actual/unknown/limited declarations remain gaps.
        no_capture_inputs = (external_capture.get("status") == "disabled"
            and external_capture.get("packages") == [] and not packages and not gaps
            and all(row.get("status") == "parsed" for row in manifests))
        if not no_capture_inputs:
            gaps.extend({"kind": "external-capture", **gap} for gap in external_capture.get("gaps", []) if isinstance(gap, dict))
        gaps.extend({"kind": "external-capture", "name": row.get("name"), "reason": row.get("reason", "Dependency capture blocked")}
                    for row in external_capture.get("packages", []) if row.get("status") == "blocked")
    missing = sum(row["source_status"] not in {"captured-local", "captured-external"} for row in packages)
    return {"schema_version": 1, "status": "partial" if gaps or missing else "captured" if manifests else "not-applicable",
            "tree_hash": meta["tree_hash"], "manifest_hash": meta["manifest_hash"],
            "captured_files": len(files), "external_files": external_files, "external_bytes": external_bytes,
            "manifests": manifests, "packages": packages,
            "declarations": len(packages), "captured_declarations": len(packages) - missing,
            "missing_declarations": missing, "gaps": gaps,
            "resolution_status": ("not-applicable" if not manifests and not gaps else
                                  "no-declarations" if manifests and not packages and not gaps
                                  and all(row.get("status") == "parsed" for row in manifests) else "not-attested"),
            "coverage_basis": "Declared packages and independently authenticated source; complete transitive resolution and dependency review are not attested"}
