"""Bounded package-input and installed-tool readiness before scanner dispatch.

This checks declared inputs and existing tool images. It never installs target
dependencies, generates a replacement lockfile, or executes repository scripts.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import re

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_LOCK_BYTES = 16 * 1024 * 1024


class NativePrerequisiteUnavailable(RuntimeError):
    """An input or qualified tool runtime is unavailable before execution."""

    def __init__(self, message: str, *, partial_findings=None, target_results=None):
        super().__init__(message)
        self.partial_findings = list(partial_findings or [])
        self.target_results = list(target_results or [])


def _read(source: Path, path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.resolve().is_relative_to(source) or not path.is_file():
        raise NativePrerequisiteUnavailable("Package input must be a regular file within the captured source")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise NativePrerequisiteUnavailable("Package input exceeds its bounded inspection limit")
    return data


def node_audit_contract(target: Path, source_root: Path | None = None) -> dict:
    """Select the captured graph's manager, never create an npm graph for Yarn."""
    target, source = Path(target).resolve(), Path(source_root or target).resolve()
    if not target.is_relative_to(source):
        raise NativePrerequisiteUnavailable("Package target is outside the captured source")
    try:
        manifest_bytes = _read(source, target / "package.json", MAX_MANIFEST_BYTES)
        manifest = json.loads(manifest_bytes)
    except (ValueError, UnicodeError, OSError):
        raise NativePrerequisiteUnavailable("package.json is unreadable or invalid JSON") from None
    if not isinstance(manifest, dict):
        raise NativePrerequisiteUnavailable("package.json must be a JSON object")
    declared = manifest.get("packageManager", "")
    if not isinstance(declared, str) or len(declared) > 256:
        raise NativePrerequisiteUnavailable("packageManager declaration is malformed")
    manager = declared.partition("@")[0] if declared else ""
    locks = [name for name in ("npm-shrinkwrap.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
             if (target / name).exists() or (target / name).is_symlink()]
    families = {"npm" if name in {"package-lock.json", "npm-shrinkwrap.json"} else "yarn" if name == "yarn.lock" else "pnpm" if name == "pnpm-lock.yaml" else "bun" for name in locks}
    if len(families) > 1:
        raise NativePrerequisiteUnavailable("Conflicting package-manager lockfiles need an explicit source-bound graph selection")
    if not families:
        raise NativePrerequisiteUnavailable("No captured package-manager lockfile: exact dependency versions are unresolved; provide the original lockfile or qualify its workspace owner. No replacement graph was generated")
    observed = next(iter(families))
    if manager and manager != observed:
        raise NativePrerequisiteUnavailable("packageManager conflicts with the captured lockfile")
    if observed not in {"npm", "yarn"}:
        raise NativePrerequisiteUnavailable(f"Captured {observed} graph requires a qualified {observed} audit adapter; npm cannot substitute for it")
    lock = next(name for name in locks if (observed == "yarn") == (name == "yarn.lock"))
    raw = _read(source, target / lock, MAX_LOCK_BYTES)
    if observed == "npm":
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise NativePrerequisiteUnavailable("Captured npm lockfile is invalid JSON") from None
        if not isinstance(value, dict) or type(value.get("lockfileVersion")) is not int or value["lockfileVersion"] not in {1, 2, 3}:
            raise NativePrerequisiteUnavailable("Captured npm lockfile has an unsupported schema")
        tool = "npm"
    else:
        # Yarn Berry is not interchangeable with Classic's lockfile/JSON format.
        major = re.match(r"yarn@([0-9]+)(?:\.|$)", declared)
        if (major and major.group(1) != "1") or b"__metadata:" in raw[:8192] or not re.search(br"(?m)^# yarn lockfile v1\s*$", raw[:8192]):
            raise NativePrerequisiteUnavailable("Captured Yarn graph is not a qualified Yarn Classic v1 lockfile")
        for directory in (target, *target.parents):
            if not directory.is_relative_to(source):
                break
            rc = directory / '.yarnrc'
            if rc.exists() or rc.is_symlink():
                if re.search(br'(?m)^\s*["\']?(?:yarn-path|yarnPath)["\']?\s', _read(source, rc, MAX_MANIFEST_BYTES)):
                    raise NativePrerequisiteUnavailable("Repository-selected Yarn executables need separate toolchain qualification; no source-provided package-manager script was executed")
        tool = "yarn"
    return {"tool": tool, "lockfile": lock, "lockfile_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "manifest_sha256": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
            "graph_origin": "captured-source", "generated_lockfile": False}


def go_module_has_source(target: Path) -> bool:
    """A Hugo/theme go.mod alone is not a buildable Go source target."""
    from backend.scanners import _NATIVE_AUDIT_SKIP_DIRS
    visited = 0
    for current, directories, files in os.walk(target, followlinks=False):
        visited += len(directories) + len(files)
        if visited > 100000:
            raise NativePrerequisiteUnavailable("Go source inventory exceeds its bounded inspection limit")
        path = Path(current)
        if path != target and "go.mod" in files:
            directories[:] = []
            continue
        directories[:] = sorted(name for name in directories if name not in _NATIVE_AUDIT_SKIP_DIRS
                                and not name.startswith('.') and not (path / name).is_symlink())
        if any(name.endswith('.go') and (path / name).is_file() and not (path / name).is_symlink() for name in files):
            return True
    return False


def go_version_key(version: str) -> tuple:
    """Compare released and prerelease Go versions without float rounding."""
    match = re.fullmatch(r"(?:go)?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:(beta|rc)([0-9]+))?", version)
    if not match:
        raise NativePrerequisiteUnavailable("Go version declaration is not a supported version")
    major, minor, patch, stage, number = match.groups()
    return (int(major), int(minor), int(patch or 0), {"beta": 0, "rc": 1, None: 2}[stage], int(number or 0))


def go_audit_contract(target: Path, source_root: Path | None = None) -> dict:
    """Read the captured module and nearest active workspace's Go minimum.

    A toolchain directive is a suggestion, not the go directive's minimum.
    GOTOOLCHAIN=local prevents automatic replacement during the audit.
    """
    target, source = Path(target).resolve(), Path(source_root or target).resolve()
    if not target.is_relative_to(source):
        raise NativePrerequisiteUnavailable("Go package target is outside the captured source")
    inputs = [target / "go.mod"]
    for directory in (target, *target.parents):
        if not directory.is_relative_to(source):
            break
        workspace = directory / "go.work"
        if workspace.exists() or workspace.is_symlink():
            inputs.append(workspace)
            break
    minimum, records = None, []
    for path in inputs:
        try:
            raw = _read(source, path, MAX_MANIFEST_BYTES)
            text = raw.decode("utf-8")
        except (OSError, UnicodeError):
            raise NativePrerequisiteUnavailable("Captured Go module/workspace is unreadable") from None
        versions = []
        for line in text.splitlines():
            fields = line.partition("//")[0].split()
            if not fields or fields[0] != "go":
                continue
            if len(fields) != 2:
                raise NativePrerequisiteUnavailable("Captured Go version directive is malformed")
            go_version_key(fields[1])
            versions.append(fields[1])
        if len(versions) > 1 or (path.name == "go.work" and not versions):
            raise NativePrerequisiteUnavailable("Captured Go module/workspace has an ambiguous or missing go directive")
        required = versions[0] if versions else "1.16"  # Go's default without a go directive.
        if minimum is None or go_version_key(required) > go_version_key(minimum):
            minimum = required
        records.append({"path": path.relative_to(source).as_posix(), "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "minimum_go": required})
    return {"minimum_go": minimum, "go_inputs": records, "automatic_toolchain_download": False}


def _installed_go_version(output: str) -> str:
    match = re.search(r"(?m)^go version go(\S+)", output)
    if not match:
        raise NativePrerequisiteUnavailable("Go tool image did not report its installed Go version")
    go_version_key(match[1])
    return match[1]


def inspect_native_readiness(source: Path, *, target_identity=None) -> dict:
    from backend.scanners import discover_native_audit_targets, native_nonproduction_audit_option
    root = Path(source).resolve()
    include_nonproduction = native_nonproduction_audit_option(root)
    rows = []
    for language, target in discover_native_audit_targets(root, include_nonproduction_fixtures=include_nonproduction):
        row = {"language": language, "root": target.relative_to(root).as_posix(),
               "status": "declared", "tool": "", "reason": "Installed tool image must pass preflight"}
        try:
            if language == "node":
                row.update(node_audit_contract(target, root))
            elif language == "python":
                from backend.python_dependency_audit import python_audit_contract
                row.update(python_audit_contract(target, root))
            elif language == "java":
                row["tool"] = "maven" if (target / "pom.xml").is_file() else "gradle"
                if (target / "gradlew").is_file() and not (target / "gradlew").stat().st_mode & 0o111:
                    raise NativePrerequisiteUnavailable("Captured Gradle wrapper is not executable")
            elif language == "go":
                row["tool"] = "go"
                row.update(go_audit_contract(target, root))
                if not go_module_has_source(target):
                    row.update(status="module-only", reason="This module declares dependencies but contains no Go source; dependency-map/OSV must cover its recorded graph. Go source analyzers are not dispatched here")
            else:
                raise NativePrerequisiteUnavailable(f"No qualified restricted Kubernetes native {language} auditor is packaged; generic source/dependency analysis remains separate")
        except (NativePrerequisiteUnavailable, OSError) as error:
            row.update(status="blocked", reason=str(error) if isinstance(error, NativePrerequisiteUnavailable) else "Package prerequisites could not be read")
        rows.append(row)
    identity = target_identity if isinstance(target_identity, dict) else {}
    return {"type": "native-tool-readiness", "schema_version": 1, "provider": "k8s-job",
            "target_identity": {key: str(identity[key])[:128] for key in ("target_revision", "target_tree_hash") if identity.get(key)},
            "source_root": str(root), "targets": rows, "toolchains": [],
            "include_nonproduction_fixtures": include_nonproduction,
            "execution_performed": False, "scope": "Known package auditor inputs and installed tools only; target build dependencies and runtime behavior require separate qualification"}


async def prepare_native_readiness(source: Path, repo_id: int, send, *, target_identity=None, enabled_tools=None) -> dict:
    """Warm/check each required immutable tool image once before audit work."""
    from backend import k8s_runtime, native_k8s
    # None is an explicit library request to inspect all supported auditors.
    # The audit pipeline passes its selected capabilities, including an empty
    # set, so disabling analysis also suppresses inventory and preflight Pods.
    if enabled_tools is not None and not enabled_tools:
        return {"type": "native-tool-readiness", "schema_version": 1, "provider": "k8s-job",
                "source_root": str(Path(source).resolve()), "targets": [], "toolchains": [],
                "status": "skipped", "execution_performed": False, "coverage_complete": False,
                "reason": "Native analyzer preflight skipped: no native package or Go analyzers are enabled. Lab build validation remains separate."}
    result = await asyncio.to_thread(inspect_native_readiness, source, target_identity=target_identity)
    if enabled_tools is not None:
        for row in result["targets"]:
            selected = ("native-package-audits" in enabled_tools or
                        (row["root"] == "." and (
                            bool(set(enabled_tools) & {"gosec", "govulncheck", "staticcheck"})
                            if row["language"] == "go" else "lockfile-audit" in enabled_tools)))
            if not selected:
                row.update(status="skipped", reason="No selected native analyzer consumes this package root")
    tools = sorted({row["tool"] for row in result["targets"] if row["status"] == "declared"})
    if not tools:
        return result
    await k8s_runtime.ensure_source_pvc(repo_id, Path(source), send)
    for tool in tools:
        entry = {"tool": tool, "status": "blocked", "image": ""}
        try:
            if tool == "go":
                from backend.ext_analyzers import prepared_go_image
                image = await prepared_go_image(True)
                # govulncheck -version fetches database metadata before its
                # version-only return (upstream internal/scan/run.go). Help
                # invokes the binary offline; Go build info supplies its exact
                # module version without a hidden network timeout.
                command = ('set -eu; go version; gosec -version 2>&1; '
                           'govulncheck -help >/dev/null 2>&1; '
                           'go version -m "$(command -v govulncheck)"; staticcheck -version')
            elif tool == "python":
                from backend.python_dependency_audit import prepared_python_image, AUDITOR_PYTHON
                image = await prepared_python_image()
                command = f"set -eu; {AUDITOR_PYTHON} --version; {AUDITOR_PYTHON} -m pip --version; {AUDITOR_PYTHON} -m pip_audit --version"
            else:
                image = native_k8s.toolchain_image("npm" if tool == "yarn" else tool)
                command = {"npm": "set -eu; node --version; npm --version", "yarn": "set -eu; node --version; yarn --version",
                           "maven": "mvn --version", "gradle": "gradle --version"}[tool]
            entry["image"] = image
            output, error, code = await k8s_runtime.run_to_completion(repo_id, "prerequisite-" + tool, image,
                script=command, workdir="/tmp", timeout=180, allow_egress=False,
                mem_request="256Mi", mem_limit="1Gi", cpu_request="100m", cpu_limit="1",
                env={"HOME": "/tmp", "PATH": "/usr/local/go/bin:/opt/lotus-tools:/usr/local/bin:/usr/bin:/bin", "GRADLE_USER_HOME": "/tmp/gradle", "GOTOOLCHAIN": "local"}, send=send)
            if code != 0 or not output.strip():
                raise NativePrerequisiteUnavailable("Installed tool image preflight did not produce successful version evidence; rebuild or configure the required image before retrying")
            entry.update(status="ready", versions=output[:2000], exit_code=code)
            if tool == "python":
                version = re.search(r"(?m)^Python (\d+\.\d+\.\d+)\s*$", output)
                if not version:
                    raise NativePrerequisiteUnavailable("Installed Python version could not be verified")
                entry["python_version"] = version[1]
            if tool == "go":
                entry["go_version"] = _installed_go_version(output)
                separate = await prepared_go_image(True, gosec=True)
                if separate != image:
                    extra_out, _extra_error, extra_code = await k8s_runtime.run_to_completion(
                        repo_id, "prerequisite-gosec", separate,
                        script="set -eu; go version; gosec -version 2>&1", workdir="/tmp", timeout=180,
                        allow_egress=False, mem_request="256Mi", mem_limit="1Gi", cpu_request="100m", cpu_limit="1",
                        env={"HOME":"/tmp", "PATH":"/usr/local/go/bin:/opt/lotus-tools:/usr/local/bin:/usr/bin:/bin", "GOTOOLCHAIN":"local"}, send=send)
                    if extra_code != 0 or not extra_out.strip():
                        raise NativePrerequisiteUnavailable("The separate gosec image failed installed-tool preflight")
                    entry["additional_images"] = [{"tool":"gosec", "image":separate, "versions":extra_out[:2000], "exit_code":extra_code, "go_version":_installed_go_version(extra_out)}]
        except Exception:
            # Registry/configuration values and arbitrary tool output must not
            # leak through a parser or transport exception into the UI.
            entry.update(status="blocked", reason="Required installed tool image is unavailable or failed preflight; no target analyzer was run")
        result["toolchains"].append(entry)
        for row in result["targets"]:
            if row["tool"] == tool and row["status"] == "declared":
                row.update(status=entry["status"], reason="Installed tool version verified; source/build validity still unproven" if entry["status"] == "ready" else entry["reason"])
                if tool == "python" and entry["status"] == "ready":
                    from packaging.specifiers import SpecifierSet
                    row["installed_python"] = entry["python_version"]
                    if row.get("requires_python") and not SpecifierSet(row["requires_python"]).contains(entry["python_version"]):
                        row.update(status="blocked", reason=f"Captured project requires Python {row['requires_python']}; installed auditor provides Python {entry['python_version']}. Configure a compatible immutable Python auditor image before retrying")
                if tool == "go" and entry["status"] == "ready":
                    versions = [entry["go_version"], *(item["go_version"] for item in entry.get("additional_images", []))]
                    installed = min(versions, key=go_version_key)
                    row["installed_go"] = installed
                    if go_version_key(installed) < go_version_key(row["minimum_go"]):
                        row.update(status="blocked", reason=f"Captured module/workspace requires Go >= {row['minimum_go']}; installed tools image provides Go {installed}. Rebuild or configure a compatible immutable tools image before retrying; no Go analyzer was run")
    result["execution_performed"] = True
    return result
