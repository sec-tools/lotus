"""Transport for existing Node/Java dependency auditors in restricted tool Jobs.

No auditor or detection logic is installed on the API host. Source is mounted
read-only, copied to bounded scratch, and parsed by the existing scanner parsers.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import shlex
import time
import uuid

from backend import k8s_runtime

# Docker Official Images OCI indexes, verified against registry response-body
# hashes. Provenance: docs/verification/kubernetes-native-toolchain-images.json.
_IMAGES = {
    'npm': 'docker.io/library/node@sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553',  # 24.21.0-bookworm-slim
    'maven': 'docker.io/library/maven@sha256:a972570be789ee5c9fa23446a8914ac7327560b5c022f662cfa9452aef829f18',  # 3.9.16, Temurin 21
    'gradle': 'docker.io/library/gradle@sha256:5c9d1de39fa1779945bd7b1e1c7872150480832a268ecfa3bfed119bb752ac04',  # 9.7.1, JDK 21
}
_REPORT_LIMIT = 4 * 1024 * 1024
_WORK = '/tmp/lotus-native/work'
_REPORT_DIR = '/tmp/lotus-native/report'


def toolchain_image(tool: str) -> str:
    from backend.scanners import ToolUnavailable
    variable = 'LOTUS_K8S_' + tool.upper() + '_IMAGE'
    image = os.environ.get(variable, '').strip() or _IMAGES[tool]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-fA-F0-9]{64}', image):
        raise ToolUnavailable(f'{variable} must be an immutable OCI image reference (@sha256:<64 hex>)')
    return image


def _store_artifact(target: Path, report: dict, *, folder: str, filename: str) -> None:
    """Write only the fixed artifact, without following source-provided links."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(target, flags)
    descriptors = [root_fd]
    temporary = '.report-' + uuid.uuid4().hex + '.tmp'
    try:
        parent = root_fd
        for part in ('.lotus', folder):
            try: os.mkdir(part, 0o700, dir_fd=parent)
            except FileExistsError: pass
            parent = os.open(part, flags, dir_fd=parent)
            descriptors.append(parent)
        data = (json.dumps(report, ensure_ascii=False) + '\n').encode()
        if len(data) > _REPORT_LIMIT:
            raise ValueError('Java dependency report exceeds the artifact size limit')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
        os.replace(temporary, filename, src_dir_fd=parent, dst_dir_fd=parent)
    finally:
        if len(descriptors) == 3:
            try: os.unlink(temporary, dir_fd=descriptors[-1])
            except FileNotFoundError: pass
        for fd in reversed(descriptors): os.close(fd)


def _store_java_report(target: Path, report: dict) -> None:
    _store_artifact(target, report, folder='dependency-check', filename='dependency-check-report.json')


def _store_tool_artifact(target: Path, filename: str, payload: dict) -> None:
    _store_artifact(target, payload, folder='tool_runs', filename=filename)


async def run_package_audit(target: Path, repo_id: int, language: str, send, *, source_root: Path | None = None):
    from backend import scanners
    target = Path(target).resolve()
    source = Path(source_root or target).resolve()
    if not target.is_relative_to(source):
        raise scanners.ScannerExecutionError('Native package target is outside the bound source root')
    relative = target.relative_to(source).as_posix()
    if language == 'node':
        from backend.native_readiness import node_audit_contract
        contract = node_audit_contract(target, source)
        tool = contract['tool']
        command = (['yarn', 'audit', '--json', '--groups', 'dependencies optionalDependencies']
                   if tool == 'yarn' else ['npm', 'audit', '--omit=dev', '--json'])
    elif (target / 'pom.xml').is_file():
        tool = 'maven'
        command = ['mvn', '-B', '-DskipTests', '-DskipTestScope=true',
                   'org.owasp:dependency-check-maven:check', '-Dformat=JSON', '-DoutputDirectory=' + _REPORT_DIR]
    else:
        tool = 'gradle'
        wrapper = target / 'gradlew'
        if wrapper.is_file() and not os.access(wrapper, os.X_OK):
            raise scanners.ToolUnavailable('Gradle wrapper exists but is not executable')
        command = ['./gradlew' if wrapper.is_file() else 'gradle', '--no-daemon', 'dependencyCheckAnalyze',
                   '-DskipTestScope=true', '-Dformat=JSON', '-DoutputDirectory=' + _REPORT_DIR]
    image = toolchain_image('npm' if tool == 'yarn' else tool)
    try:
        await k8s_runtime.ensure_source_pvc(repo_id, source, send)
    except k8s_runtime.KubernetesSourceUnavailable as exc:
        raise scanners.ToolUnavailable(str(exc)) from exc
    report_marker = 'LOTUS_NATIVE_REPORT_' + uuid.uuid4().hex
    setup = ('set -eu; mkdir -p ' + _WORK + ' ' + _REPORT_DIR + '; '
             'cp -R /src/. ' + _WORK + '/; chmod -R u+rwX ' + _WORK + '; '
             'cd ' + shlex.quote(_WORK + '/' + relative) + '; ')
    if language == 'node':
        # The image is preinstalled, while source input is locked separately.
        # Validate exact captured bytes after copying; no lockfile is invented.
        setup += ('printf ' + shlex.quote(contract['lockfile_sha256'].removeprefix('sha256:') + '  ' + contract['lockfile'] + '\n') + ' | sha256sum -c - >/dev/null; ')
        if tool == 'yarn':
            # Classic audit's resolver does not enforce frozen-lockfile itself.
            # First validate/install its locked graph with lifecycle scripts off
            # in disposable scratch, then audit that same graph and verify the
            # lock remains byte-identical. Never run repository build hooks.
            setup += ('yarn install --frozen-lockfile --ignore-scripts --non-interactive >/tmp/lotus-native/prepare.log 2>&1 '
                      '|| { tail -c 2000 /tmp/lotus-native/prepare.log >&2; exit 65; }; '
                      'printf ' + shlex.quote(contract['lockfile_sha256'].removeprefix('sha256:') + '  yarn.lock\n') + ' | sha256sum -c - >/dev/null; ')

    async def execute(cmd):
        started = time.monotonic()
        script = setup + shlex.join(cmd)
        if language == 'java':
            # Copied reports are stale by definition. The only accepted output
            # is newly generated inside this Job; plugin failure stays a gap.
            script = setup + "find . -name dependency-check-report.json -type f -delete; "
            script += 'if ' + shlex.join(cmd) + ' >/tmp/lotus-native/build.log 2>&1; then :; else rc=$?; tail -c 8000 /tmp/lotus-native/build.log >&2; exit "$rc"; fi; '
            script += ('report=' + _REPORT_DIR + '/dependency-check-report.json; '
                       'if [ ! -f "$report" ]; then report=$(find target build/reports -name dependency-check-report.json -type f 2>/dev/null | head -1); fi; '
                       '[ -n "$report" ] && [ -f "$report" ] || { tail -c 8000 /tmp/lotus-native/build.log >&2; echo "Fresh dependency-check report missing" >&2; exit 65; }; '
                       '[ "$(wc -c < "$report")" -le ' + str(_REPORT_LIMIT) + ' ] || { echo "Dependency-check report exceeds output limit" >&2; exit 66; }; '
                       'printf ' + shlex.quote(report_marker + '\n') + '; base64 "$report"')
        output, error, code = await k8s_runtime.run_to_completion(repo_id, 'native-' + tool, image,
            script=script, workdir='/tmp', timeout=300 if language == 'java' or tool == 'yarn' else 120,
            allow_egress=True, writable_paths=['/tmp/lotus-native'], send=send,
            env={'HOME': '/tmp/lotus-native/home', 'XDG_CACHE_HOME': '/tmp/lotus-native/cache',
                 'GRADLE_USER_HOME': '/tmp/lotus-native/gradle', 'MAVEN_OPTS': '-Duser.home=/tmp/lotus-native/home',
                 'YARN_IGNORE_PATH': '1', 'YARN_IGNORE_SCRIPTS': 'true', 'NPM_CONFIG_IGNORE_SCRIPTS': 'true'})
        accepted_codes = (0,) if language == 'java' else tuple(range(32)) if tool == 'yarn' else (0, 1)
        await scanners._persist_scanner_tool_artifact(repo_id, cmd, target,
            status='completed' if code in accepted_codes else 'failed', exit_code=code,
            output=output if language == 'node' else error[-8000:],
            duration_ms=int((time.monotonic() - started) * 1000), send=send, safe_writer=_store_tool_artifact)
        legacy_flag = tool == 'npm' and re.search(r'unknown option|invalid option|unexpected argument|usage:|invalid arg', output, re.I)
        if code not in accepted_codes and not legacy_flag:
            raise scanners.ScannerExecutionError(f'Kubernetes {tool} audit failed (rc={code}): {error[-500:] or output[-500:]}')
        return output

    output = await execute(command)
    if language == 'node':
        if tool == 'yarn':
            return _yarn_audit_findings(output)
        if re.search(r'unknown option|invalid option|unexpected argument|usage:|invalid arg', output, re.I):
            output = await execute(['npm', 'audit', '--production', '--json'])
        return scanners._npm_audit_findings(output)
    try:
        marker, encoded = output.split('\n', 1)
        if marker != report_marker or len(encoded) > _REPORT_LIMIT * 2:
            raise ValueError('missing or oversized current-Job report envelope')
        raw = base64.b64decode(''.join(encoded.split()), validate=True)
        if len(raw) > _REPORT_LIMIT: raise ValueError('report size limit exceeded')
        report = json.loads(raw)
        findings = scanners._parse_java_dependency_report(report)
        _store_java_report(target, report)
        return findings
    except (ValueError, OSError, TypeError) as exc:
        raise scanners.ScannerExecutionError('Java dependency report transfer failed: ' + str(exc)[:300]) from exc


def _yarn_audit_findings(output: str) -> list[dict]:
    """Require Classic's terminal summary; partial/error JSONL is not clean."""
    from backend.scanners import ScannerExecutionError
    if len(output.encode()) > _REPORT_LIMIT:
        raise ScannerExecutionError('Yarn audit report exceeds output limit')
    findings, summary, seen = [], None, set()
    try:
        for line in output.splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict) or row.get('type') == 'error':
                raise ValueError('error or invalid record')
            if row.get('type') == 'auditSummary':
                if summary is not None or not isinstance(row.get('data'), dict):
                    raise ValueError('ambiguous summary')
                summary = row['data']
            elif row.get('type') == 'auditAdvisory':
                data = row.get('data') or {}
                advisory = data.get('advisory') or {}
                if not isinstance(advisory, dict) or not advisory.get('module_name') or advisory.get('id') is None:
                    raise ValueError('invalid advisory')
                key = str(advisory['id'])
                if key in seen:
                    continue
                seen.add(key)
                findings.append({'tool': 'yarn-audit', 'title': 'Yarn vulnerable package: ' + str(advisory['module_name']),
                    'cvss': 7.0, 'description': 'Yarn Classic audit of the captured production graph: ' + str(advisory.get('title') or key)[:1000] + '. Verify first-party reachability before reporting.',
                    'file': 'yarn.lock', 'line': 0, 'confidence': 'high', 'advisory_id': key,
                    'dependency_graph_origin': 'captured-source'})
        counts = summary.get('vulnerabilities') if isinstance(summary, dict) else None
        if not isinstance(counts, dict) or any(type(counts.get(key)) is not int or counts[key] < 0 for key in ('info', 'low', 'moderate', 'high', 'critical')):
            raise ValueError('missing terminal vulnerability counts')
        if sum(counts.values()) and not findings:
            raise ValueError('summary reports issues without advisory records')
    except (ValueError, TypeError, AttributeError):
        raise ScannerExecutionError('Yarn audit did not produce a complete valid report for the captured dependency graph') from None
    return findings
