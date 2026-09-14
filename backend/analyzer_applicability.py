"""Conservative static scope checks; absence is valid only after a complete walk.

This module reads source as data. It never evaluates Ruby, runs a package
manager, or treats an unreadable/truncated tree as evidence of inapplicability.
"""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import re
import time


class AnalyzerNotApplicable(RuntimeError):
    def __init__(self, reason, *, scope=None):
        super().__init__("not applicable: " + reason)
        self.applicability_scope = scope or {}


# Conservative superset of automatic source inputs documented by OSV-Scanner.
# C/C++ commit scanning and custom/SBOM inputs prevent a false absence claim.
_OSV_INPUTS = {
    "conan.lock", "pubspec.lock", "mix.lock", "go.mod", "go.work", "go.sum",
    "cabal.project.freeze", "stack.yaml.lock", "buildscript-gradle.lockfile",
    "gradle.lockfile", "verification-metadata.xml", "pom.xml", "bun.lock", "bun.lockb",
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
    "deps.json", "packages.config", "packages.lock.json", "composer.lock",
    "Pipfile.lock", "poetry.lock", "requirements.txt", "pdm.lock", "pylock.toml", "uv.lock",
    "renv.lock", "Gemfile.lock", "gems.locked", "Cargo.lock", ".gitmodules",
    "osv-scanner-custom.json", "osv-scanner.json", "osv-scanner.toml", "bom.json", "bom.xml",
}
_C_SOURCE = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"}


def _unified_diff(text):
    """Recognize complete textual patch data, never infer it from a filename.

    This deliberately accepts a small unified-diff grammar. Unknown metadata,
    binary patches, malformed/truncated hunks, or trailing source stay possible
    scanner inputs. No paths named inside a patch are read or applied.
    """
    if not text or "\x00" in text:
        return False
    lines, index, hunks, header = text.splitlines(), 0, 0, False
    # Empty separators after the final complete hunk contain no source. Keep
    # space-prefixed context lines intact so hunk counts still must match.
    while lines and lines[-1] == "":
        lines.pop()
    while index < len(lines):
        line = lines[index]
        if line.startswith("diff "):
            header = False
            index += 1
            if index >= len(lines) or not lines[index].startswith("--- "):
                return False
            continue
        if line.startswith("--- "):
            if index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
                return False
            header = True
            index += 2
            if index >= len(lines) or not lines[index].startswith("@@ "):
                return False
            continue
        match = re.fullmatch(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@(?: .*)?", line)
        if not header or not match:
            return False
        old = int(match[1]) if match[1] is not None else 1
        new = int(match[2]) if match[2] is not None else 1
        if old == new == 0:
            return False
        index += 1
        consumed = False
        while old or new:
            if index >= len(lines):
                return False
            body = lines[index]
            if body == "\\ No newline at end of file" and consumed:
                index += 1
                continue
            if not body or body[0] not in " +-":
                return False
            old -= body[0] in " -"
            new -= body[0] in " +"
            if old < 0 or new < 0:
                return False
            consumed = True
            index += 1
        if index < len(lines) and lines[index] == "\\ No newline at end of file":
            index += 1
        hunks += 1
    return hunks > 0


def _non_manifest_patches(dest, inputs):
    """Bound full reads of possible C inputs; retain exact artifact hashes."""
    from backend.source_index import _open_source
    if len(inputs) > 32 or any(Path(path).suffix.lower() not in _C_SOURCE for path in inputs):
        return None
    total, patches = 0, []
    try:
        for relative in inputs:
            with _open_source(str(dest), relative) as handle:
                raw = handle.read(256 * 1024 + 1)
            total += len(raw)
            if len(raw) > 256 * 1024 or total > 1024 * 1024 or not _unified_diff(raw.decode("utf-8")):
                return None
            patches.append({"path": relative, "bytes": len(raw), "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
                            "kind": "unified-diff", "applied": False})
    except (OSError, ValueError):
        return None
    return patches


def _unresolved_ruby_dependency_call(text):
    for call in re.finditer(r"\b(?:gem|add_(?:runtime_)?dependency)\b([^\n]*)", text):
        literal = re.match(r'''\s*(?:\(\s*)?(?P<quote>['"])(?P<name>(?:\\.|(?!(?P=quote)).)*)(?P=quote)(?P<rest>.*)''', call[1])
        if (not literal or "\\" in literal["name"] or "#{" in literal["name"]
                or literal["rest"].lstrip()[:1] not in {"", ",", ")", "#"}):
            return True
    return False


def _inventory(dest, *, max_entries=100000, max_seconds=10):
    root = Path(dest).absolute()
    result = {"complete": True, "entries_examined": 0, "files_examined": 0,
              "file_aliases_examined": 0, "osv_inputs": [], "rails_inputs": [], "gaps": []}
    if root.is_symlink() or not root.is_dir():
        return {**result, "complete": False, "gaps": ["Source root is absent or is a symlink"]}
    stack, deadline = [root], time.monotonic() + max_seconds
    try:
        while stack:
            directory = stack.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    result["entries_examined"] += 1
                    if result["entries_examined"] > max_entries or time.monotonic() > deadline:
                        raise ValueError("Source applicability inventory exceeded its entry/time budget")
                    relative = Path(entry.path).relative_to(root).as_posix()
                    if entry.name in {".git", ".lotus"}:
                        continue
                    if entry.is_symlink():
                        try:
                            target = Path(entry.path).resolve(strict=True)
                            target_relative = target.relative_to(root)
                            if not target.is_file() or any(part in {".git", ".lotus"} for part in target_relative.parts):
                                raise ValueError("not a contained regular source file")
                        except (OSError, ValueError, RuntimeError):
                            result["gaps"].append("Source symlink requires explicit scope resolution: " + relative)
                            if len(result["gaps"]) >= 100:
                                raise ValueError("Source applicability inventory has at least 100 unresolved links")
                            continue
                        # A confined file alias adds no unwalked source: its
                        # physical target participates in the complete walk.
                        # Still inspect the alias name so e.g. Gemfile.lock ->
                        # data.txt cannot hide a manifest-shaped scanner input.
                        result["file_aliases_examined"] += 1
                    elif entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                        continue
                    elif not entry.is_file(follow_symlinks=False):
                        raise ValueError("Source contains a non-regular entry: " + relative)
                    else:
                        result["files_examined"] += 1
                    name = entry.name
                    if (name in _OSV_INPUTS or name.endswith((".deps.json", ".spdx", ".spdx.json", ".cdx.json", ".cdx.xml"))
                            or re.fullmatch(r"requirements[^/]*\.(?:txt|in)", name, re.I)
                            or Path(name).suffix.lower() in _C_SOURCE):
                        result["osv_inputs"].append(relative)
                    if (name in {"Gemfile", "gems.rb"} or name.endswith(".gemspec")
                            or relative in {"config/application.rb", "config/environment.rb", "config/routes.rb"}
                            or relative.endswith(("/config/application.rb", "/config/environment.rb", "/config/routes.rb"))):
                        result["rails_inputs"].append(relative)
                    if max(len(result["osv_inputs"]), len(result["rails_inputs"])) > 1000:
                        raise ValueError("Source applicability inventory exceeded its input metadata budget")
    except (OSError, ValueError) as error:
        result["gaps"].append(str(error)[:300])
    result["complete"] = not result["gaps"]
    result["osv_inputs"].sort(); result["rails_inputs"].sort()
    return result


def brakeman_scope(dest, **limits):
    inventory = _inventory(dest, **limits)
    roots, total_bytes = set(), 0
    from backend.source_index import _open_source
    for relative in inventory["rails_inputs"]:
        path = PurePosixPath(relative)
        if path.parent.name == "config":
            # A Rails-shaped config remains applicable even when damaged or
            # dynamic; do not hide a real missing scanner behind failed parsing.
            roots.add(str(path.parent.parent))
            continue
        try:
            with _open_source(str(dest), relative) as handle:
                raw = handle.read(256 * 1024 + 1)
            total_bytes += len(raw)
            if len(raw) > 256 * 1024 or total_bytes > 4 * 1024 * 1024:
                raise ValueError("Ruby framework declarations exceeded the static read budget")
            text = "\n".join(line for line in raw.decode("utf-8").splitlines() if not line.lstrip().startswith("#"))
            if re.search(r"\b(?:gem|add_(?:runtime_)?dependency)\s*(?:\(\s*)?['\"](?:rails|railties)['\"]", text):
                roots.add(str(path.parent))
            elif (re.search(r"\b(?:eval|eval_gemfile|instance_eval|class_eval|module_eval|instance_exec|class_exec|module_exec|send|public_send|gemspec|require|require_relative|load|autoload)\b", text)
                    or _unresolved_ruby_dependency_call(text)):
                inventory["gaps"].append("Dynamic Ruby dependency declarations require framework resolution: " + relative)
                inventory["complete"] = False
        except (OSError, ValueError) as error:
            inventory["gaps"].append(str(error)[:300]); inventory["complete"] = False
    state = "applicable" if roots else "unknown" if not inventory["complete"] else "not-applicable"
    return {"state": state, "roots": sorted(roots), "inventory": inventory,
            "reason": ("Rails source/configuration or dependency declaration found" if roots else
                       "Ruby framework scope is incomplete; Rails applicability cannot be excluded" if state == "unknown" else
                       "Brakeman is Rails-specific; complete source inventory found no Rails configuration or framework declaration")}


def osv_no_sources_scope(dest, output, error, code, **limits):
    """Recognize only OSV's documented no-packages exit with no missed inputs."""
    if code != 128:
        return None
    lines = (str(output) + "\n" + str(error)).splitlines()
    marker = re.compile(r"\s*(?:\[(?:ERROR|WARN|INFO)\]\s*|(?:ERROR|WARN|INFO):\s*)?No package sources found(?:, --help for usage information\.)?[.!]?\s*", re.I)
    if not any(marker.fullmatch(line) for line in lines):
        return None
    # No-package diagnostics may accompany an empty JSON result, but malformed
    # or nonempty structured output is never reclassified as inapplicable.
    for payload in (str(output), str(error)):
        payload_lines = [line for line in payload.splitlines() if not marker.fullmatch(line)]
        start = next((index for index, line in enumerate(payload_lines)
                      if line.lstrip().startswith(("{", "["))
                      and not line.lstrip().startswith(("[INFO]", "[WARN]", "[ERROR]"))), None)
        if start is not None:
            structured = "\n".join(payload_lines[start:]).strip()
            try:
                parsed = json.loads(structured)
            except ValueError:
                return None
            if not isinstance(parsed, dict) or parsed.get("results") != [] or set(parsed) != {"results"}:
                return None
    for line in lines:
        if marker.fullmatch(line):
            continue
        if re.search(r"\b(?:error|errors|failed|failure|panic|fatal|exception|denied|unreadable|segmentation|killed)\b", line, re.I):
            return None
        counts = re.findall(r"\bExtract calls\s*[:=]\s*(\d+)|\b(\d+)\s+Extract calls\b", line, re.I)
        if any(int(left or right) != 0 for left, right in counts):
            return None
    inventory = _inventory(dest, **limits)
    if not inventory["complete"]:
        return None
    patches = _non_manifest_patches(dest, inventory["osv_inputs"])
    if patches is None:
        return None
    inventory["non_manifest_patch_artifacts"] = patches
    return {"state": "not-applicable", "scanner_exit_code": 128, "inventory": inventory,
            "dependency_coverage": "unestablished", "packages_extracted": 0,
            "reason": "OSV reported no package sources; complete source inventory found no compatible package manifests or commit/SBOM inputs. "
                      + (f"{len(patches)} complete unified-diff artifacts were inspected as patch data, not deployed C/C++ dependencies. " if patches else "")
                      + "Dependency coverage is not established"}
