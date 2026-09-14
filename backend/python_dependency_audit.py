"""Audit a recorded Python dependency graph without installing target code.

Only registry requirements are admitted. Pip resolves wheels in disposable
scratch; pip-audit then checks those exact versions without dependency loading.
The resulting graph describes this lab resolution, never an existing deployment.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import tomllib
from urllib.parse import urlsplit, unquote

MAX_REPORT_BYTES = 4 * 1024 * 1024
AUDITOR_PYTHON = '/opt/python-audit/bin/python'


def python_audit_contract(target: Path, source_root: Path | None = None) -> dict:
    from packaging.requirements import Requirement, InvalidRequirement
    from backend.native_readiness import _read, NativePrerequisiteUnavailable, MAX_MANIFEST_BYTES
    target, source = Path(target).resolve(), Path(source_root or target).resolve()
    if not target.is_relative_to(source):
        raise NativePrerequisiteUnavailable('Python package target is outside captured source')
    selected = target / 'requirements.txt'
    requires_python = ''
    project = None
    interpreter_input = {}
    metadata_path = target / 'pyproject.toml'
    if metadata_path.exists() or metadata_path.is_symlink():
        metadata_raw = _read(source, metadata_path, MAX_MANIFEST_BYTES)
        try:
            project = tomllib.loads(metadata_raw.decode('utf-8')).get('project')
            if project is not None:
                if not isinstance(project, dict):
                    raise ValueError('invalid project metadata')
                requires_python = project.get('requires-python', '')
                if not isinstance(requires_python, str) or 'requires-python' in project.get('dynamic', []):
                    raise ValueError('invalid or dynamic interpreter constraint')
        except (ValueError, TypeError, UnicodeError):
            raise NativePrerequisiteUnavailable('Python interpreter metadata must be valid and static; repository build hooks were not executed') from None
        interpreter_input = {
            'python_constraint_manifest': metadata_path.relative_to(source).as_posix(),
            'python_constraint_manifest_sha256': 'sha256:' + hashlib.sha256(metadata_raw).hexdigest(),
        }
    if selected.exists() or selected.is_symlink():
        raw = _read(source, selected, MAX_MANIFEST_BYTES)
        try:
            lines = raw.decode('utf-8').splitlines()
        except UnicodeError:
            raise NativePrerequisiteUnavailable('Python requirements must be UTF-8 text') from None
        inputs = [line.split(' #', 1)[0].strip() for line in lines if line.strip() and not line.lstrip().startswith('#')]
    else:
        selected = metadata_path
        if not interpreter_input:
            raise NativePrerequisiteUnavailable('Provide captured requirements.txt or static project.dependencies in pyproject.toml; no replacement for a Poetry/Pipenv lock was inferred')
        raw = metadata_raw
        try:
            if not isinstance(project, dict) or 'dependencies' in project.get('dynamic', []):
                raise ValueError('dynamic or absent project metadata')
            inputs = project.get('dependencies', [])
            if not isinstance(inputs, list):
                raise ValueError('invalid dependency metadata')
        except (ValueError, TypeError, UnicodeError):
            raise NativePrerequisiteUnavailable('Python dependency metadata must be static; repository build hooks were not executed') from None
    if len(inputs) > 2000:
        raise NativePrerequisiteUnavailable('Python dependency input exceeds 2000 requirements')
    from packaging.specifiers import SpecifierSet, InvalidSpecifier
    try:
        SpecifierSet(requires_python)
    except InvalidSpecifier:
        raise NativePrerequisiteUnavailable('Captured requires-python declaration is invalid') from None
    requirements = []
    for value in inputs:
        try:
            if not isinstance(value, str) or len(value) > 4096 or value.startswith('-'):
                raise ValueError('unsupported requirement')
            requirement = Requirement(value)
            if requirement.url:
                raise ValueError('direct source reference')
        except (ValueError, InvalidRequirement):
            raise NativePrerequisiteUnavailable('Python audit accepts registry requirements only; file/URL/VCS references, includes, and installer options require a separately qualified graph') from None
        requirements.append(str(requirement))
    return {'tool': 'python', **interpreter_input, 'manifest': selected.relative_to(source).as_posix(),
            'manifest_sha256': 'sha256:' + hashlib.sha256(raw).hexdigest(),
            'requirements': requirements, 'requires_python': requires_python,
            'graph_origin': 'isolated-wheel-resolution', 'target_code_executed': False,
            'scope': 'Resolved for the recorded local Python environment; existing deployment versions remain unknown'}


async def prepared_python_image() -> str:
    from backend.scanners import ToolUnavailable
    image = os.environ.get('LOTUS_K8S_PYTHON_IMAGE', '').strip()
    if not image:
        from backend.lab_selftest import _kubernetes_selftest_image
        image = await _kubernetes_selftest_image(use_explicit_override=False)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-fA-F0-9]{64}', image):
        raise ToolUnavailable('Python auditing requires a preinstalled immutable LOTUS_K8S_PYTHON_IMAGE or packaged controller image')
    return image


def _json_file(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError('Python dependency report missing or exceeds output limit')
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('Python dependency report must be an object')
    return value


def _run_isolated(contract: dict, *, work: Path = Path('/tmp/lotus-python-audit')) -> dict:
    """Trusted image entrypoint. No source scripts, sdists or environment installs."""
    from packaging.specifiers import SpecifierSet
    import platform
    if contract.get('requires_python') and not SpecifierSet(contract['requires_python']).contains(platform.python_version()):
        raise ValueError('Packaged Python version does not satisfy the captured requires-python declaration')
    work.mkdir(parents=True, exist_ok=False)
    requirements = work / 'requirements.txt'
    requirements.write_text('\n'.join(contract['requirements']) + '\n')
    environment = dict(os.environ, HOME=str(work), XDG_CACHE_HOME=str(work / 'cache'), PIP_CONFIG_FILE=os.devnull)
    for key in list(environment):
        if key.startswith('PIP_') and key != 'PIP_CONFIG_FILE':
            environment.pop(key)
    resolution_path = work / 'resolution.json'
    command = [sys.executable, '-m', 'pip', '--isolated', '--disable-pip-version-check', 'install',
               '--dry-run', '--ignore-installed', '--only-binary=:all:', '--no-input', '--no-cache-dir',
               '--index-url', 'https://pypi.org/simple', '--report', str(resolution_path), '-r', str(requirements)]
    completed = subprocess.run(command, env=environment, cwd=work, capture_output=True, text=True, timeout=150)
    if completed.returncode:
        raise ValueError('Wheel-only dependency resolution failed: ' + completed.stderr[-2000:])
    resolution = _json_file(resolution_path)
    installed = resolution.get('install')
    if not isinstance(installed, list) or not isinstance(resolution.get('environment'), dict):
        raise ValueError('Incomplete pip resolution report')
    packages = []
    for row in installed:
        from packaging.requirements import Requirement
        metadata, download = row.get('metadata') or {}, row.get('download_info') or {}
        location = urlsplit(download.get('url', ''))
        requirements_dist = metadata.get('requires_dist', [])
        if (location.scheme != 'https' or location.hostname != 'files.pythonhosted.org'
                or location.username is not None or location.password is not None
                or location.port not in (None, 443) or not unquote(location.path).lower().endswith('.whl')
                or row.get('is_direct') is True or not isinstance(requirements_dist, list)
                or any(Requirement(item).url for item in requirements_dist)):
            raise ValueError('Resolved graph contains a non-registry or non-wheel dependency; no audit coverage was claimed')
        name, version = metadata.get('name', ''), metadata.get('version', '')
        digest = (download.get('archive_info') or {}).get('hashes', {}).get('sha256', '')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.!+_-]*', version) or not re.fullmatch(r'[a-f0-9]{64}', digest):
            raise ValueError('Unverifiable resolved package identity')
        packages.append({'name': name, 'version': version, 'wheel_sha256': digest,
                         'requested': bool(row.get('requested')), 'requires_dist': requirements_dist})
    locked = work / 'resolved.txt'
    locked.write_text(''.join(row['name'] + '==' + row['version'] + '\n' for row in packages))
    audit = {'dependencies': [], 'fixes': []}
    if packages:
        audit_path = work / 'audit.json'
        command = [sys.executable, '-m', 'pip_audit', '--format=json', '--disable-pip', '--no-deps',
                   '--progress-spinner=off', '--cache-dir', str(work / 'cache'), '--output', str(audit_path), '-r', str(locked)]
        completed = subprocess.run(command, env=environment, cwd=work, capture_output=True, text=True, timeout=150)
        if completed.returncode not in (0, 1):
            raise ValueError('Python vulnerability lookup failed: ' + completed.stderr[-2000:])
        audit = _json_file(audit_path)
    report = {'schema_version': 1, 'contract': contract, 'packages': packages, 'audit': audit,
              'environment': resolution['environment'], 'recorded_at': datetime.now(timezone.utc).isoformat()}
    if len(json.dumps(report, ensure_ascii=False).encode()) + 1 > MAX_REPORT_BYTES:
        raise ValueError('Python dependency report exceeds the 4 MiB artifact limit')
    return report


def _findings(report: dict, contract: dict) -> list[dict]:
    from packaging.utils import canonicalize_name
    from backend.scanners import ScannerExecutionError
    if report.get('schema_version') != 1 or report.get('contract') != contract:
        raise ScannerExecutionError('Python audit report is not bound to the captured inputs')
    dependencies = (report.get('audit') or {}).get('dependencies')
    packages = report.get('packages')
    if not isinstance(dependencies, list) or not isinstance(packages, list) or not isinstance(report.get('environment'), dict):
        raise ScannerExecutionError('Python audit report is incomplete')
    expected = {(canonicalize_name(p['name']), p['version']) for p in packages}
    observed = set()
    result = []
    for dependency in dependencies:
        if not isinstance(dependency, dict) or dependency.get('skip_reason') or not isinstance(dependency.get('vulns'), list):
            raise ScannerExecutionError('Python audit skipped a resolved package; coverage is incomplete')
        observed.add((canonicalize_name(dependency.get('name', '')), dependency.get('version')))
        for advisory in dependency['vulns']:
            if not isinstance(advisory, dict) or not advisory.get('id'):
                raise ScannerExecutionError('Python audit contains an invalid advisory')
            result.append({'tool': 'pip-audit', 'title': f"PyPI vulnerable package: {dependency['name']} ({advisory['id']})",
                'description': f"pip-audit reported {advisory['id']} for {dependency['name']} {dependency['version']} in the recorded wheel-only lab resolution. Existing deployment versions and first-party reachability require validation.",
                'file': contract['manifest'], 'line': 0, 'cvss': 7.0, 'confidence': 'high', 'qualification': 'CANDIDATE',
                'dependency_graph_origin': contract['graph_origin'], 'advisory_id': advisory['id']})
    if observed != expected or len(observed) != len(dependencies):
        raise ScannerExecutionError('Python audit does not cover every resolved package exactly once')
    return result


async def run_python_package_audit(target: Path, repo_id: int, send, *, source_root: Path | None = None) -> list[dict]:
    from backend import k8s_runtime, native_k8s, scanners
    contract = python_audit_contract(target, source_root)
    image = await prepared_python_image()
    await k8s_runtime.ensure_source_pvc(repo_id, Path(source_root or target), send)
    encoded = base64.b64encode(json.dumps(contract).encode()).decode()
    command = [AUDITOR_PYTHON, '/app/backend/python_dependency_audit.py', '--run', encoded]
    started = time.monotonic()
    output, error, code = await k8s_runtime.run_to_completion(repo_id, 'native-python', image,
        script=shlex.join(command), workdir='/tmp', timeout=330, allow_egress=True,
        mem_request='256Mi', mem_limit='1Gi', cpu_request='100m', cpu_limit='1',
        env={'HOME': '/tmp', 'PYTHONPATH': '/app'}, send=send)
    await scanners._persist_scanner_tool_artifact(repo_id, command[:3], Path(target),
        status='completed' if code == 0 else 'failed', exit_code=code, output=output,
        duration_ms=int((time.monotonic() - started) * 1000), send=send, safe_writer=native_k8s._store_tool_artifact)
    if code != 0:
        raise scanners.ScannerExecutionError('Restricted Python dependency audit failed: ' + (error or output)[-1000:])
    try:
        report = json.loads(output)
        if not isinstance(report, dict):
            raise ValueError('not an object')
        findings = _findings(report, contract)
    except (ValueError, TypeError, KeyError) as exc:
        raise scanners.ScannerExecutionError('Python audit returned an incomplete or invalid source-bound report') from exc
    native_k8s._store_tool_artifact(Path(target), 'python-dependency-resolution.json', report)
    return findings


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != '--run':
        raise SystemExit(2)
    try:
        print(json.dumps(_run_isolated(json.loads(base64.b64decode(sys.argv[2])))))
    except Exception as error:
        print(str(error)[:2500], file=sys.stderr)
        raise SystemExit(2)
