"""Bounded captured build-input facts; never execute or synthesize source assets.

The adapter brackets this helper with its full source-identity checks. Literal
Go embed directives identify compile-time inputs even when their producer is a
separate frontend build. This inventory does not infer the selected Go graph.
"""
from collections import Counter
from pathlib import Path, PurePosixPath
import re
import shlex

from backend.adapter_source_context import _context_paths, _excerpt, _safe_name

MAX_SCAN_FILES = 256
MAX_SCAN_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024
MAX_INPUTS = 16
MAX_ADDED_FILES = 8
_PATTERN = re.compile(r'(?:all:)?[A-Za-z0-9_./-]{1,160}')


def literal_pattern(value):
    if not isinstance(value, str) or not _PATTERN.fullmatch(value):
        return None
    name = value.removeprefix('all:')
    if name.startswith('/') or any(part in ('', '.', '..') for part in name.split('/')):
        return None
    return name


def embed_directives(text):
    """Recognize actual line comments, not strings or block-comment examples."""
    state = ''
    for number, line in enumerate(text.splitlines(), 1):
        index = 0
        while index < len(line):
            pair, char = line[index:index+2], line[index]
            if state == 'block':
                if pair == '*/': state = ''; index += 2
                else: index += 1
            elif state:
                if char == state: state = ''; index += 1
                elif char == '\\' and state != '`': index += 2
                else: index += 1
            elif pair == '//':
                directive = re.fullmatch(r'//go:embed[ \t]+(.+)', line[index:])
                if not line[:index].strip() and directive and '\\' not in directive[1]:
                    try: patterns = shlex.split(directive[1])
                    except ValueError: patterns = []
                    for pattern in patterns[:MAX_INPUTS]:
                        if literal_pattern(pattern) is not None: yield number, pattern
                break
            elif pair == '/*': state = 'block'; index += 2
            elif char in ('"', "'", '`'): state = char; index += 1
            else: index += 1
        if state in ('"', "'"): state = ''


def add_build_inputs(source, files, *, inventory=None):
    root = Path(source).resolve()
    inventory = _context_paths(root, inventory)
    names = {name for name in inventory if _safe_name(name)}
    descendants = Counter()
    for name in names:
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.': descendants[str(parent)] += 1
    existing = {row['file'] for row in files}
    package_dirs = {str(PurePosixPath(name).parent) for name in existing if name.endswith('package.json')}
    candidates = sorted((name for name in names if name.endswith('.go')), key=lambda name: (
        PurePosixPath(name).name != 'embed.go',
        str(PurePosixPath(name).parent) not in package_dirs, len(PurePosixPath(name).parts), name))
    read_files = read_bytes = added = 0
    inputs = []
    for name in candidates:
        if read_files >= MAX_SCAN_FILES or read_bytes >= MAX_SCAN_BYTES or len(inputs) >= MAX_INPUTS:
            break
        path = inventory[name]
        if (path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root)
                or any(parent.is_symlink() for parent in path.parents if parent != root)
                or path.stat().st_size > MAX_FILE_BYTES):
            continue
        if read_bytes + path.stat().st_size > MAX_SCAN_BYTES: continue
        read_files += 1
        with path.open("rb") as handle: raw = handle.read(MAX_FILE_BYTES + 1)
        read_bytes += len(raw)
        if len(raw) > MAX_FILE_BYTES or read_bytes > MAX_SCAN_BYTES or b'\x00' in raw: continue
        try: text = raw.decode('utf-8')
        except UnicodeError: continue
        directives = []
        for line, pattern in embed_directives(text):
            target = (PurePosixPath(name).parent / literal_pattern(pattern)).as_posix()
            directives.append({'file': name, 'line': line, 'pattern': pattern,
                'input_path': target, 'captured_matches': int(target in names) + descendants[target]})
        if not directives: continue
        if name not in existing:
            if added >= MAX_ADDED_FILES: continue
            files.append({'file': name, **_excerpt(raw), 'selection_reason': 'literal Go embedded build inputs'})
            existing.add(name); added += 1
        sha = next(row['sha256'] for row in files if row['file'] == name)
        for row in directives[:MAX_INPUTS-len(inputs)]:
            row.update(sha256=sha, absent_from_capture=row['captured_matches'] == 0)
            inputs.append(row)
    return {'schema_version': 1, 'go_embeds': inputs, 'scanned_go_files': read_files,
        'inspected_bytes': read_bytes, 'inventory_go_files': len(candidates),
        'complete': read_files == len(candidates),
        'interpretation': 'Literal source build inputs, not a resolved Go import/build-tag graph. Missing generated inputs require their real source-defined producer before compilation; omitting UI coverage does not remove compile-time embeds.'}


def supports_embed_diagnostic(context, row):
    if row.get('kind') != 'missing-go-embed': return True
    contract = context.get('build_inputs') or {}
    files = {item.get('file'): item.get('sha256') for item in context.get('files', [])}
    return any(item.get('file') == row.get('reference') and item.get('pattern') == row.get('pattern')
        and item.get('sha256') == files.get(item.get('file'))
        for item in contract.get('go_embeds', []))
