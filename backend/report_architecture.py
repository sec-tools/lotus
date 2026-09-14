"""Bounded, inert declarations from an audit's verified source snapshot.

Declarations describe the source, never observed runtime behavior or finding
proof. This supplemental view is hashed separately from immutable publications.
"""
import hashlib
import json
import os
import re
import stat
from copy import deepcopy
from pathlib import Path

from backend.report_context import digest

MAX_FILES = 512
MAX_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024
MAX_RECORDS = 128

# Start at a literal method marker instead of an unbounded receiver name.
# Searching for ``\w+\.get`` at every character of a long generated identifier
# takes quadratic time, even though the file itself is below the byte limit.
_ROUTE_DECLARATION = re.compile(r'\.(get|post|put|delete|patch|route)\(\s*[\'\"]([^\'\"]{1,256})[\'\"]')


def _literal_route(value):
    """Find the first existing receiver/method declaration in linear time."""
    for match in _ROUTE_DECLARATION.finditer(value):
        # The previous pattern required a word-character receiver. Checking
        # its final character preserves decorators, dotted names and Unicode
        # identifiers without repeatedly scanning their prefixes.
        if match.start() and (value[match.start() - 1].isalnum() or value[match.start() - 1] == '_'):
            return match
    return None


def _files(root):
    """Never follow directory/file links; bound even ignored directory entries."""
    remaining = MAX_FILES
    total = 0
    pending = [(os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW), "", 0)]
    try:
        while pending and remaining > 0 and total < MAX_BYTES:
            fd, prefix, depth = pending.pop()
            try:
                with os.scandir(fd) as entries:
                    for entry in entries:
                        remaining -= 1
                        if remaining < 0:
                            return
                        relative = prefix + entry.name
                        if entry.is_dir(follow_symlinks=False) and depth < 8:
                            if not entry.name.startswith('.') and entry.name not in ('node_modules', 'vendor'):
                                try:
                                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                                    pending.append((child, relative + '/', depth + 1))
                                except OSError:
                                    pass
                            continue
                        if not entry.is_file(follow_symlinks=False) or not re.search(r'(\.json|\.ya?ml|\.py|\.js|\.ts|\.md|\.toml|requirements\.txt)$', relative, re.I):
                            continue
                        file_fd = None
                        try:
                            file_fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                            info = os.fstat(file_fd)
                            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES or total + info.st_size > MAX_BYTES:
                                continue
                            with os.fdopen(file_fd, 'rb') as stream:
                                file_fd = None
                                data = stream.read(MAX_FILE_BYTES + 1)
                            total += len(data)
                            if len(data) <= MAX_FILE_BYTES:
                                yield relative, data
                        except OSError:
                            pass
                        finally:
                            if file_fd is not None:
                                os.close(file_fd)
            finally:
                os.close(fd)
    finally:
        for fd, _, _ in pending:
            os.close(fd)


def extract_architecture(source_root):
    result = {'status': 'source_declarations', 'nodes': [], 'edges': [], 'declarations': [], 'commands': [],
              'unknowns': ['Source declarations do not establish runtime reachability, trust boundaries, or intended behavior for a finding.',
                           'Bounded extraction covers recognized manifests and literal routes; dynamic configuration and dependency resolution require separate evidence.']}
    nodes = {}
    def node(label, kind, ref):
        key = (str(label)[:256], kind)
        if key not in nodes and len(nodes) < MAX_RECORDS:
            nodes[key] = 'source-' + digest(key)[:16]
            result['nodes'].append({'id': nodes[key], 'label': key[0], 'kind': kind, 'evidence_scope': 'declared', 'source_refs': [ref]})
        return nodes.get(key)
    def edge(a, b, label, ref):
        if a and b and len(result['edges']) < MAX_RECORDS:
            result['edges'].append({'id': 'source-edge-' + str(len(result['edges'])), 'source': a, 'target': b,
                                    'label': label, 'evidence_scope': 'declared', 'source_refs': [ref]})
    def declaration(kind, text, ref):
        if len(result['declarations']) < MAX_RECORDS:
            result['declarations'].append({'kind': kind, 'text': str(text)[:1000], 'evidence_scope': 'declared', 'source_refs': [ref]})
    for path, data in _files(Path(source_root)):
        content = data.decode('utf-8', errors='replace')
        file_hash = 'sha256:' + hashlib.sha256(data).hexdigest()
        def ref(line=1):
            return {'path': path, 'line': line, 'sha256': file_hash}
        basename = Path(path).name.lower()
        document = {}
        if basename.endswith('.json'):
            try:
                document = json.loads(content)
            except (ValueError, RecursionError):
                pass
        elif basename.endswith(('.yaml', '.yml')) and any(s in basename for s in ('compose', 'openapi', 'swagger')):
            try:
                import yaml
                document = yaml.safe_load(content)
            except (ValueError, RecursionError, yaml.YAMLError):
                pass
        if not isinstance(document, dict):
            document = {}
        if basename == 'package.json':
            owner = node(document.get('name') or path, 'package', ref())
            for group in ('dependencies', 'devDependencies', 'peerDependencies'):
                deps = document.get(group)
                if isinstance(deps, dict):
                    for name, version in list(deps.items())[:MAX_RECORDS]:
                        dep = node(name, 'dependency', ref())
                        edge(owner, dep, group + ': ' + str(version)[:128], ref())
            scripts = document.get('scripts')
            if isinstance(scripts, dict):
                for name, code in list(scripts.items())[:32]:
                    if len(result['commands']) >= MAX_RECORDS:
                        break
                    if not isinstance(code, str):
                        continue
                    # Display declarations only. Do not turn shell text into
                    # an executable cell or expose obvious inline credentials.
                    redacted = re.sub(r'(?i)(password|token|secret|api[_-]?key)(\s*[=:]\s*)[^\s]+', r'\1\2[redacted]', code)
                    result['commands'].append({'name': str(name)[:128], 'code': redacted[:2000], 'language': 'unknown',
                                               'evidence_scope': 'declared', 'source_refs': [ref()]})
        services = document.get('services')
        if isinstance(services, dict):
            for name, config in list(services.items())[:MAX_RECORDS]:
                if not isinstance(config, dict):
                    continue
                owner = node(name, 'compose_service', ref())
                dependencies = config.get('depends_on', [])
                if isinstance(dependencies, dict):
                    dependencies = list(dependencies)
                if isinstance(dependencies, list):
                    for dependency in dependencies[:MAX_RECORDS]:
                        if isinstance(dependency, str):
                            edge(owner, node(dependency, 'compose_service', ref()), 'depends_on', ref())
                for key in ('image', 'ports', 'read_only', 'network_mode'):
                    value = config.get(key)
                    if isinstance(value, (str, bool, int)):
                        declaration('compose_configuration', str(name) + ' ' + key + ': ' + str(value), ref())
                env = config.get('environment')
                if isinstance(env, dict):
                    declaration('configuration_keys', str(name) + ': ' + ', '.join(str(k)[:80] for k in list(env)[:32]) + ' (values omitted)', ref())
        paths = document.get('paths')
        if isinstance(paths, dict) and ('openapi' in document or 'swagger' in document):
            owner = node(path, 'api_specification', ref())
            for route, operations in list(paths.items())[:MAX_RECORDS]:
                if not isinstance(operations, dict):
                    continue
                for verb, operation in list(operations.items())[:16]:
                    if verb.lower() not in ('get', 'post', 'put', 'patch', 'delete', 'options', 'head'):
                        continue
                    label = verb.upper() + ' ' + str(route)
                    edge(owner, node(label, 'specified_route', ref()), 'specifies', ref())
                    if isinstance(operation, dict):
                        responses = operation.get('responses')
                        if isinstance(responses, dict):
                            declaration('specified_responses', label + ': ' + ', '.join(str(k)[:64] for k in list(responses)[:32]), ref())
        if basename.endswith(('.py', '.js', '.ts')):
            owner = None
            for line, value in enumerate(content.splitlines(), 1):
                match = _literal_route(value)
                if match:
                    owner = owner or node(path, 'source_module', ref())
                    edge(owner, node(match[1].upper() + ' ' + match[2], 'literal_route', ref(line)), 'declares literal route', ref(line))
        if basename.endswith('.md'):
            for line, value in enumerate(content.splitlines(), 1):
                if len(value) <= 1000 and re.search(r'\b(MUST|SHALL|must|shall)\b', value):
                    declaration('documentation_requirement', value, ref(line))
    if not result['nodes']:
        result['unknowns'].append('No recognized architecture declarations were found within the extraction limits.')
    result['limits'] = {'entries': MAX_FILES, 'file_bytes': MAX_FILE_BYTES, 'total_bytes': MAX_BYTES, 'nodes': MAX_RECORDS, 'edges': MAX_RECORDS}
    return result


def report_source_artifacts(context):
    """Load only the original content-addressed snapshot, never current checkout."""
    result = {'schema_version': 1, 'original_context_hash': context.get('context_hash'), 'status': 'unavailable', 'missing_context': []}
    try:
        from backend.target_snapshots import load_snapshot
        binding = context.get('binding') or {}
        snapshot = load_snapshot((binding.get('snapshot') or {}).get('snapshot_ref') or '')
        expected = (binding.get('target_identity') or {}).get('tree_hash')
        if not expected or expected != snapshot.get('tree_hash'):
            raise ValueError('Original report source content hash does not match the retained snapshot.')
        result.update({'status': 'available', 'target_tree_hash': expected, 'snapshot_manifest_hash': snapshot['manifest_hash'],
                       'architecture': extract_architecture(snapshot['source_path'])})
    except (OSError, ValueError, KeyError) as exc:
        result['missing_context'].append(str(exc)[:300])
    result['artifact_hash'] = digest(result)
    return result


def recorded_report_source_artifacts(context):
    """Project declarations from an already verified publication, without I/O.

    Historical reading does not revalidate a retained checkout or authorize
    execution. Explicit source and runtime operations keep their own checks.
    The caller must obtain this context from the verified report manifest.
    """
    context = context if isinstance(context, dict) else {}
    result = {'schema_version': 1, 'original_context_hash': context.get('context_hash'),
              'status': 'unavailable', 'provenance': 'recorded_report_context',
              'evidence_scope': 'recorded_source_declarations',
              'source_revalidated_on_read': False, 'missing_context': []}
    recorded = context.get('source_architecture')
    if recorded is None:
        result['missing_context'].append(
            'Source architecture declarations were not recorded in this publication. '
            'Reading a historical report does not rescan source or substitute a newer audit.')
    elif (not isinstance(recorded, dict)
          or any(not isinstance(recorded.get(key), list)
                 or any(not isinstance(row, dict) for row in recorded[key])
                 for key in ('nodes', 'edges', 'declarations', 'commands'))):
        result['missing_context'].append('The publication contains unsupported source architecture declarations.')
    else:
        binding = context.get('binding') if isinstance(context.get('binding'), dict) else {}
        identity = binding.get('target_identity') if isinstance(binding.get('target_identity'), dict) else {}
        result.update(status='recorded', target_tree_hash=identity.get('tree_hash') or '',
                      architecture=deepcopy(recorded))
    result['artifact_hash'] = digest(result)
    return result
