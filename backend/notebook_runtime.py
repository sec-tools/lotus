"""Explicit, owned Docker attachments for immutable report runtime capsules.

No image pulls, builds, dependency installation, latest-lab fallback or finding
promotion. A capsule must have been recorded with the original audit. Missing
capsules stay readable but cannot be reconstructed by guessing a recipe.
"""
import asyncio
import json
import os
import re
import shutil
import uuid
import hashlib
import io
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from contextlib import asynccontextmanager
from datetime import datetime

from backend.report_context import digest

RUNTIME_TASKS = {}
RUNTIME_TASK_REPOS = {}
EXECUTION_TASKS = {}
OUTPUT_LIMIT = 65536


@asynccontextmanager
async def admitted_task(repo_id=None):
    """Synchronize task admission with destructive maintenance, without await."""
    from backend import main
    from fastapi import HTTPException
    lock = main._PLATFORM_RESET_LOCK
    if not lock.acquire(blocking=False):
        raise HTTPException(503, 'Platform maintenance is in progress.', headers={'Retry-After': '2'})
    task_key = 'notebook:' + str(uuid.uuid4())
    try:
        if main._PLATFORM_RESET_IN_PROGRESS.is_set():
            raise HTTPException(503, 'Platform maintenance is in progress.', headers={'Retry-After': '2'})
        RUNTIME_TASKS[task_key] = asyncio.current_task()
        RUNTIME_TASK_REPOS[task_key] = repo_id
    finally:
        lock.release()
    try:
        yield
    finally:
        RUNTIME_TASKS.pop(task_key, None)
        RUNTIME_TASK_REPOS.pop(task_key, None)


def capsule_for_context(context):
    binding = context.get('binding') or {}
    capsule = context.get('runtime_capsule')
    if not isinstance(capsule, dict) or capsule.get('schema_version') != 1:
        raise ValueError('This audit did not retain an immutable runtime capsule. Source alone cannot reproduce its dependencies and startup recipe.')
    capsule = dict(capsule)
    expected = capsule.pop('capsule_hash', '')
    if expected != digest(capsule):
        raise ValueError('Recorded runtime capsule hash is invalid.')
    if capsule.get('provider') != 'docker':
        raise ValueError('This attachment provider supports recorded Docker capsules only; Kubernetes volume and dependency replay is not available.')
    if not binding.get('scan_job_id') or not binding.get('repo_id'):
        raise ValueError('An exact original repository and audit job are required.')
    if capsule.get('target_tree_hash') != (binding.get('target_identity') or {}).get('tree_hash'):
        raise ValueError('Runtime capsule belongs to different source content.')
    lab = binding.get('lab') or {}
    if not capsule.get('lab_run_id') or capsule['lab_run_id'] != lab.get('lab_run_id'):
        raise ValueError('Runtime capsule does not belong to the original lab run.')
    image = capsule.get('image', '')
    if not isinstance(image, str) or not re.fullmatch(r'(?:[a-zA-Z0-9./:_-]+@)?sha256:[a-f0-9]{64}', image):
        raise ValueError('Runtime capsule requires an immutable image ID or digest; mutable tags are unavailable for replay.')
    if image != lab.get('image_digest'):
        raise ValueError('Runtime capsule image differs from the original audit image.')
    if capsule.get('dependencies') != 'in_image' or capsule.get('network') not in ('none', 'internal') or capsule.get('user') not in ('65534:65534', '65532:65532'):
        raise ValueError('Replay requires dependencies frozen in the image, isolated networking, and the recorded unprivileged user.')
    if capsule.get('source_mode', 'mount') not in ('mount', 'embedded'):
        raise ValueError('Runtime capsule source materialization is unsupported.')
    limits = capsule.get('limits', {'memory_bytes': 512 * 1024 * 1024, 'nano_cpus': 1000000000, 'pids': 64})
    if not isinstance(limits, dict) or set(limits) != {'memory_bytes', 'nano_cpus', 'pids'} or any(type(value) is not int for value in limits.values()):
        raise ValueError('Runtime capsule resource limits are invalid.')
    if not (16 * 1024 * 1024 <= limits['memory_bytes'] <= 8 * 1024**3 and 100000000 <= limits['nano_cpus'] <= 4000000000 and 16 <= limits['pids'] <= 4096):
        raise ValueError('Recorded resource requirements exceed the bounded replay policy.')
    root = capsule.get('source_root')
    if not isinstance(root, str) or not re.fullmatch(r'/(?:app|workspace|src)(?:/[a-zA-Z0-9_-]+)*', root):
        raise ValueError('Runtime capsule source mount must be a recorded application directory.')
    if capsule.get('working_dir') != root:
        raise ValueError('Runtime capsule working directory must match its source mount.')
    for key in ('entrypoint', 'command'):
        values = capsule.get(key)
        if not isinstance(values, list) or len(values) > 32 or any(not isinstance(v, str) or len(v) > 4096 or '\x00' in v for v in values):
            raise ValueError('Runtime capsule requires bounded recorded entrypoint and command argument arrays.')
    if not capsule['entrypoint'] or not capsule['entrypoint'][0].startswith('/'):
        raise ValueError('Runtime capsule entrypoint must name its recorded absolute executable.')
    if set(capsule) - {'schema_version', 'provider', 'target_tree_hash', 'lab_run_id', 'image', 'dependencies', 'network', 'user', 'source_root', 'working_dir', 'entrypoint', 'command', 'source_mode', 'source_archive_hash', 'limits'}:
        raise ValueError('Runtime capsule has unsupported configuration; no settings were silently omitted.')
    return dict(capsule, capsule_hash=expected)


async def _docker(*args, timeout=30, binary=False, output_limit=OUTPUT_LIMIT):
    executable = shutil.which('docker')
    if not executable:
        raise ValueError('Docker CLI is unavailable on this API worker.')
    spawn = asyncio.create_task(asyncio.create_subprocess_exec(executable, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE))
    interrupted = False
    try:
        proc = await asyncio.shield(spawn)
    except asyncio.CancelledError:
        # A process can already exist while its transport setup is awaiting.
        # Resolve ownership before propagating cancellation and reaping it.
        proc = await asyncio.shield(spawn)
        interrupted = True
    buffers = [bytearray(), bytearray()]
    truncated = False
    async def read(stream, buffer):
        nonlocal truncated
        while True:
            chunk = await stream.read(8192)
            if not chunk:
                return
            available = max(0, output_limit - len(buffer))
            buffer.extend(chunk[:available])
            truncated = truncated or len(chunk) > available
    readers = [asyncio.create_task(read(proc.stdout, buffers[0])), asyncio.create_task(read(proc.stderr, buffers[1]))]
    try:
        if interrupted:
            raise asyncio.CancelledError()
        await asyncio.wait_for(asyncio.gather(proc.wait(), *readers), timeout)
        return {'returncode': proc.returncode, 'stdout': bytes(buffers[0]) if binary else buffers[0].decode(errors='replace'), 'stderr': buffers[1].decode(errors='replace'), 'output_truncated': truncated}
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        await proc.wait()
        for task in readers:
            if not task.done():
                task.cancel()
        await asyncio.gather(*readers, return_exceptions=True)


async def _allocate(*args, **kwargs):
    """Finish daemon allocation before cleanup can declare a resource absent."""
    task = asyncio.create_task(_docker(*args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await asyncio.shield(task)
        raise


def _archive_tree_hash(payload):
    """Inspect bounded Docker source archives without extracting archive paths."""
    from backend.proof_receipts import content_tree_digest
    if len(payload) > 16 * 1024 * 1024:
        raise ValueError('Runtime source archive exceeds the capture budget.')
    with tempfile.TemporaryDirectory(prefix='lotus-capsule-source-') as temp:
        base = Path(temp)
        count = total = 0
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:') as archive:
            for member in archive:
                count += 1
                parts = PurePosixPath(member.name).parts
                if count > 20000 or not parts or '..' in parts or member.name.startswith('/'):
                    raise ValueError('Runtime source archive has unsafe or excessive entries.')
                # Docker cp wraps the copied directory in its basename.
                relative = parts[1:]
                if not relative:
                    if not member.isdir(): raise ValueError('Runtime source archive root is invalid.')
                    continue
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError('Runtime source archive contains links or special files; capture is unavailable.')
                total += member.size
                if total > 16 * 1024 * 1024:
                    raise ValueError('Runtime source archive exceeds the capture budget.')
                path = base.joinpath(*relative)
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.exists():
                    raise ValueError('Runtime source archive contains duplicate files.')
                stream = archive.extractfile(member)
                with path.open('wb') as output:
                    shutil.copyfileobj(stream, output, length=65536)
        return content_tree_digest(base)


async def _resolve_recorded_executable(container_id, executable, environment):
    """Resolve image PATH using read-only archive metadata, never target exec."""
    import posixpath
    if executable.startswith('/'):
        return executable
    if not re.fullmatch('[a-zA-Z0-9._-]+', executable):
        raise ValueError('Original startup executable cannot be resolved from image metadata.')
    path = next((value[5:] for value in environment if isinstance(value, str) and value.startswith('PATH=')), '')
    for directory in path.split(':')[:16]:
        if not directory.startswith('/') or '..' in directory.split('/'):
            continue
        candidate = directory.rstrip('/') + '/' + executable
        for _ in range(8):
            result = await _docker('cp', container_id + ':' + candidate, '-', binary=True, output_limit=1024 * 1024, timeout=5)
            if result['returncode']:
                break
            with tarfile.open(fileobj=io.BytesIO(result['stdout']), mode='r:') as archive:
                member = archive.next()
                if member and member.issym():
                    candidate = posixpath.normpath(posixpath.join(posixpath.dirname(candidate), member.linkname))
                    continue
                if member and member.isfile() and member.mode & 0o111:
                    return candidate
                break
    raise ValueError('Original startup executable was not found in the recorded image PATH.')


async def capture_runtime_capsule(repo_id, target_snapshot, target_tree_hash):
    """Capture supported normal Docker labs using read-only daemon operations.

    This runs at the existing lab-ready audit boundary. It does not run target
    code, mutate the current lab or create an image. Unsupported layouts return
    a durable gap; only complete source/image/recipe checks yield a capsule.
    """
    try:
        from backend.lab import get_lab_state
        from backend.target_snapshots import load_snapshot
        state = dict(get_lab_state(repo_id) or {})
        if state.get('provider') == 'k8s-job' or state.get('pod_uid'):
            raise ValueError('Kubernetes dependency volumes are not retained as replay capsules.')
        snapshot = await asyncio.to_thread(load_snapshot, target_snapshot.get('path') or target_snapshot.get('source_path') or target_snapshot.get('key') or '')
        if not target_tree_hash or snapshot['tree_hash'] != target_tree_hash or state.get('target_tree_hash') != target_tree_hash:
            raise ValueError('Original lab and source snapshot do not share a verified target hash.')
        name = state.get('container')
        if not name or not state.get('lab_run_id'):
            raise ValueError('No exact original Docker lab run is registered.')
        async def inspect_original():
            result = await _docker('inspect', name, timeout=10)
            if result['returncode'] or result['output_truncated']:
                raise ValueError('Original lab identity inspection is unavailable.')
            info = json.loads(result['stdout'])[0]
            labels = (info.get('Config') or {}).get('Labels') or {}
            if labels.get('lotus.audit.repo_id') != str(repo_id) or labels.get('lotus.audit.run_id') != state['lab_run_id'] or labels.get('lotus.audit.target_tree_hash') != target_tree_hash:
                raise ValueError('Original lab labels do not match this audit source and run.')
            if not (info.get('State') or {}).get('Running'):
                raise ValueError('Original lab stopped before capsule capture.')
            return info
        info = await inspect_original()
        config, host = info.get('Config') or {}, info.get('HostConfig') or {}
        root = config.get('WorkingDir') or ''
        if not host.get('ReadonlyRootfs') or config.get('User') not in ('65532:65532', '65534:65534'):
            raise ValueError('Only an immutable root filesystem and recorded unprivileged runtime are supported.')
        if not re.fullmatch(r'/(?:app|workspace|src)(?:/[a-zA-Z0-9_-]+)*', root):
            raise ValueError('Original runtime has no supported application source directory.')
        mounts = info.get('Mounts') or []
        if any(m.get('Type') != 'tmpfs' or m.get('Destination') not in ('/tmp', '/run') for m in mounts):
            raise ValueError('Original runtime uses mutable dependencies or application volumes that were not captured.')
        image_result = await _docker('image', 'inspect', info['Image'], timeout=10)
        if image_result['returncode'] or image_result['output_truncated']:
            raise ValueError('Original immutable image metadata is unavailable.')
        image = json.loads(image_result['stdout'])[0]
        image_config = image.get('Config') or {}
        if image['Id'] != info['Image'] or image_config.get('Volumes') or config.get('Env') != image_config.get('Env'):
            raise ValueError('Original runtime requires unretained image volumes or environment overrides.')
        entrypoint, command = config.get('Entrypoint') or [], config.get('Cmd') or []
        if not entrypoint:
            entrypoint, command = command[:1], command[1:]
        if not entrypoint:
            raise ValueError('Original image does not record a startup executable.')
        entrypoint = [await _resolve_recorded_executable(info['Id'], entrypoint[0], config.get('Env') or [])] + entrypoint[1:]
        network = host.get('NetworkMode')
        if network != 'none':
            network_result = await _docker('network', 'inspect', network, timeout=10)
            if network_result['returncode']:
                raise ValueError('Original network isolation could not be inspected.')
            net = json.loads(network_result['stdout'])[0]
            if not net.get('Internal') or set((net.get('Containers') or {})) != {info['Id']}:
                raise ValueError('Original runtime relies on an external or shared service network.')
            network = 'internal'
        copied = await _docker('cp', info['Id'] + ':' + root, '-', timeout=15, binary=True, output_limit=16 * 1024 * 1024)
        if copied['returncode'] or copied['output_truncated']:
            raise ValueError('Complete original source archive was unavailable within the 16 MiB capture budget.')
        if await asyncio.to_thread(_archive_tree_hash, copied['stdout']) != target_tree_hash:
            raise ValueError('Runtime application source differs from the immutable audit snapshot.')
        again = await inspect_original()
        if again['Id'] != info['Id'] or again['Image'] != info['Image'] or again['State'].get('StartedAt') != info['State'].get('StartedAt'):
            raise ValueError('Original runtime changed during capsule capture.')
        capsule = {'schema_version': 1, 'provider': 'docker', 'target_tree_hash': target_tree_hash, 'lab_run_id': state['lab_run_id'],
                   'image': image['Id'], 'dependencies': 'in_image', 'network': network, 'user': config['User'],
                   'source_root': root, 'working_dir': root, 'source_mode': 'embedded',
                   'source_archive_hash': 'sha256:' + hashlib.sha256(copied['stdout']).hexdigest(), 'entrypoint': entrypoint, 'command': command,
                   'limits': {'memory_bytes': host.get('Memory'), 'nano_cpus': host.get('NanoCpus'), 'pids': host.get('PidsLimit')}}
        capsule['capsule_hash'] = digest(capsule)
        context = {'binding': {'repo_id': repo_id, 'scan_job_id': 1, 'target_identity': {'tree_hash': target_tree_hash}, 'lab': {'lab_run_id': state['lab_run_id'], 'image_digest': image['Id']}}, 'runtime_capsule': capsule}
        capsule_for_context(context)
        return {'status': 'captured', 'capsule': capsule, 'lab_run_id': state['lab_run_id'], 'image_digest': image['Id'],
                'reason': 'Read-only image source matches the complete retained snapshot; runtime recipe and dependency image recorded.'}
    except (ValueError, OSError, KeyError, IndexError, tarfile.TarError) as exc:
        return {'status': 'unavailable', 'reason': str(exc)[:500]}


async def record_runtime_capsule(repo_id, target_snapshot, target_tree_hash, lab_status, recon_summary):
    """Shared normal-audit boundary; capture gaps are durable report context."""
    try:
        result = await asyncio.wait_for(capture_runtime_capsule(repo_id, target_snapshot, target_tree_hash), timeout=30)
    except asyncio.TimeoutError:
        result = {'status': 'unavailable', 'reason': 'Immutable runtime capsule inspection exceeded the 30 second capture budget.'}
    recon_summary['runtime_capsule_capture'] = {k: v for k, v in result.items() if k != 'capsule'}
    if result.get('status') == 'captured':
        lab_status.update({key: result[key] for key in ('lab_run_id', 'image_digest')})
        lab_status['runtime_capsule'] = result['capsule']
        recon_summary['runtime_capsule'] = result['capsule']
    return result


def _db():
    from backend import main
    return main, main.get_db()


def _row(attachment_id, context=None, report_id=None):
    if not isinstance(attachment_id, str) or not re.fullmatch(r'[a-f0-9-]{36}', attachment_id):
        raise ValueError('Runtime attachment identity is invalid.')
    main, db = _db()
    try:
        row = db.query(main.NotebookRuntime).filter(main.NotebookRuntime.id == attachment_id).first()
        if not row or (report_id is not None and row.report_id != report_id):
            raise ValueError('Runtime attachment does not belong to this report.')
        if context and (row.context_hash != context.get('context_hash') or row.scan_job_id != context['binding']['scan_job_id'] or row.repo_id != context['binding']['repo_id']):
            raise ValueError('Runtime attachment does not match the original report context.')
        return {c.name: getattr(row, c.name) for c in main.NotebookRuntime.__table__.columns}
    finally:
        db.close()


def _update(attachment_id, **fields):
    main, db = _db()
    try:
        row = db.query(main.NotebookRuntime).filter(main.NotebookRuntime.id == attachment_id).first()
        if not row:
            raise ValueError('Runtime attachment was removed; execution is unavailable.')
        for key, value in fields.items():
            setattr(row, key, value)
        row.updated_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()


def public_row(row):
    return {key: row[key] for key in ('id', 'repo_id', 'report_id', 'scan_job_id', 'context_hash', 'status', 'execution_binding_hash', 'error', 'created_at', 'updated_at')} | {'binding': json.loads(row['binding_json']), 'evidence_scope': 'new_runtime_observation'}


def list_attachments(report_id):
    main, db = _db()
    try:
        ids = [r.id for r in db.query(main.NotebookRuntime).filter(main.NotebookRuntime.report_id == report_id).order_by(main.NotebookRuntime.created_at.desc()).limit(20).all()]
    finally:
        db.close()
    return [public_row(_row(i, report_id=report_id)) for i in ids]


def _labels(row):
    return {'lotus.notebook.attachment': row['id'], 'lotus.notebook.context': row['context_hash'],
            'lotus.notebook.report': str(row['report_id']), 'lotus.notebook.recipe': digest(json.loads(row['recipe_json']))}


async def _inspect_owned(row, missing_ok=False):
    identity = row['container_id'] or 'lotus-notebook-' + row['id']
    result = await _docker('inspect', identity, timeout=10)
    if result['returncode']:
        # Docker unavailable/permission failures must not be mistaken for a
        # removed container, otherwise reset could erase its ownership row.
        if missing_ok and ('No such object:' in result['stderr'] or 'No such container:' in result['stderr']):
            if row.get('error', '').startswith('Allocation outcome uncertain:'):
                raise ValueError('Allocation outcome remains uncertain; ownership records must be retained until the daemon resource can be reconciled.')
            return None
        raise ValueError('Owned runtime inspection failed; ownership records were retained.')
    try:
        info = json.loads(result['stdout'])[0]
    except (ValueError, IndexError, KeyError):
        raise ValueError('Owned runtime inspection returned an invalid identity.')
    labels = (info.get('Config') or {}).get('Labels') or {}
    if any(labels.get(k) != v for k, v in _labels(row).items()) or (row['container_id'] and row['container_id'] != info.get('Id')):
        raise ValueError('Runtime ownership labels or immutable container ID changed; operation refused.')
    recipe = json.loads(row['recipe_json'])
    if info.get('Image') != recipe['image_id']:
        raise ValueError('Runtime image identity changed; operation refused.')
    return info


async def stop_attachment(attachment_id, context=None, report_id=None):
    row = _row(attachment_id, context, report_id)
    if row['status'] == 'stopped':
        return public_row(row)
    _update(attachment_id, status='stopping')
    info = await _inspect_owned(row, missing_ok=True)
    if info:
        result = await _docker('rm', '-f', info['Id'], timeout=20)
        if result['returncode']:
            raise ValueError('Owned runtime cleanup failed; attachment remains tracked for retry.')
    if json.loads(row['recipe_json']).get('network') == 'internal':
        network = await _inspect_network(row, missing_ok=True)
        if network:
            result = await _docker('network', 'rm', network['Id'], timeout=10)
            if result['returncode']:
                raise ValueError('Owned runtime network cleanup failed; ownership records were retained.')
    _update(attachment_id, status='stopped', active_key=None)
    return public_row(_row(attachment_id))


async def _inspect_network(row, missing_ok=False):
    result = await _docker('network', 'inspect', row.get('network_id') or 'lotus-notebook-' + row['id'], timeout=10)
    if result['returncode']:
        if missing_ok and ('not found' in result['stderr'].lower() or 'no such network' in result['stderr'].lower()):
            return None
        raise ValueError('Owned attachment network could not be inspected.')
    network = json.loads(result['stdout'])[0]
    if any((network.get('Labels') or {}).get(key) != value for key, value in _labels(row).items()) or not network.get('Internal'):
        raise ValueError('Attachment network ownership or isolation changed; operation refused.')
    if row.get('network_id') and row['network_id'] != network.get('Id'):
        raise ValueError('Attachment network immutable ID changed; operation refused.')
    return network


async def create_attachment(report_id, context):
    from backend.target_snapshots import load_snapshot
    capsule = capsule_for_context(context)
    snapshot = await asyncio.to_thread(load_snapshot, context['binding']['snapshot']['snapshot_ref'])
    if snapshot['tree_hash'] != capsule['target_tree_hash']:
        raise ValueError('Original snapshot content differs from the runtime capsule.')
    # Bind mounts must not expose source symlinks to image/host paths. An
    # unsupported tree fails explicitly instead of silently modifying source.
    entries = 0
    for root, dirs, files in os.walk(snapshot['source_path'], followlinks=False):
        entries += len(dirs) + len(files)
        if entries > 20000:
            raise ValueError('Runtime replay source exceeds the bounded file inventory limit.')
        if any(os.path.islink(os.path.join(root, name)) for name in dirs + files):
            raise ValueError('Runtime replay cannot mount snapshots containing symbolic links.')
    image_result = await _docker('image', 'inspect', capsule['image'], timeout=10)
    if image_result['returncode']:
        raise ValueError('Original immutable runtime image is unavailable locally. Replay never pulls a replacement.')
    try:
        image = json.loads(image_result['stdout'])[0]
        if not re.fullmatch('sha256:[a-f0-9]{64}', image['Id']):
            raise ValueError()
    except (ValueError, KeyError, IndexError):
        raise ValueError('Original immutable runtime image could not be verified.')
    if (image.get('Config') or {}).get('Volumes'):
        raise ValueError('Image declares mutable volumes not retained by the runtime capsule.')
    recipe = dict(capsule, image_id=image['Id'], snapshot_manifest_hash=snapshot['manifest_hash'])
    main, db = _db()
    attachment_id = str(uuid.uuid4())
    try:
        existing = db.query(main.NotebookRuntime).filter(main.NotebookRuntime.active_key == 'report:' + str(report_id)).first()
        if existing:
            return public_row(_row(existing.id, context, report_id))
        row = main.NotebookRuntime(id=attachment_id, repo_id=context['binding']['repo_id'], report_id=report_id,
                                   scan_job_id=context['binding']['scan_job_id'], context_hash=context['context_hash'],
                                   active_key='report:' + str(report_id), status='starting', recipe_json=json.dumps(recipe, sort_keys=True))
        db.add(row)
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise ValueError('Another runtime attachment is being admitted. Reload attachment status.')
    finally:
        db.close()
    row = _row(attachment_id)
    try:
        limits = capsule.get('limits', {'memory_bytes': 512 * 1024 * 1024, 'nano_cpus': 1000000000, 'pids': 64})
        network_id = 'none'
        if capsule['network'] == 'internal':
            network_args = ['network', 'create', '--internal']
            for key, value in _labels(row).items():
                network_args.extend(['--label', key + '=' + value])
            network_args.append('lotus-notebook-' + attachment_id)
            result = await _allocate(*network_args, timeout=15)
            if result['returncode']:
                raise ValueError('Owned isolated attachment network could not be created.')
            network = await _inspect_network(row)
            network_id = network['Id']
            _update(attachment_id, network_id=network_id)
        args = ['create', '--pull=never', '--name', 'lotus-notebook-' + attachment_id,
                '--network=' + network_id, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--user=' + capsule['user'], '--pids-limit=' + str(limits['pids']), '--memory=' + str(limits['memory_bytes']), '--cpus=' + str(limits['nano_cpus'] / 1000000000),
                '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m', '--tmpfs=/run:rw,nosuid,nodev,noexec,size=32m', '--workdir', capsule['working_dir'],
                '--entrypoint', capsule['entrypoint'][0]]
        if capsule.get('source_mode', 'mount') == 'mount':
            args.extend(['--mount', 'type=bind,src=' + snapshot['source_path'] + ',dst=' + capsule['source_root'] + ',readonly'])
        for key, value in _labels(row).items():
            args.extend(['--label', key + '=' + value])
        args.extend([image['Id']] + capsule['entrypoint'][1:] + capsule['command'])
        result = await _allocate(*args)
        if result['returncode']:
            raise ValueError('Recorded runtime creation failed; verify its image, source mount and recorded recipe.')
        info = await _inspect_owned(row)
        _update(attachment_id, container_id=info['Id'])
        result = await _docker('start', info['Id'])
        if result['returncode']:
            raise ValueError('Recorded runtime could not start.')
        info = await _inspect_owned(_row(attachment_id))
        if not (info.get('State') or {}).get('Running'):
            raise ValueError('Recorded runtime exited during startup; no execution binding was issued.')
        binding = {'schema_version': 1, 'attachment_id': attachment_id, 'original_context_hash': context['context_hash'],
                   'repo_id': row['repo_id'], 'report_id': report_id, 'scan_job_id': row['scan_job_id'],
                   'target_tree_hash': snapshot['tree_hash'], 'snapshot_manifest_hash': snapshot['manifest_hash'],
                   'capsule_hash': capsule['capsule_hash'], 'provider': 'docker', 'container_id': info['Id'], 'image_id': image['Id'],
                   'runtime_started_at': (info.get('State') or {}).get('StartedAt', ''), 'network_id': network_id}
        _update(attachment_id, status='ready', binding_json=json.dumps(binding, sort_keys=True), execution_binding_hash=digest(binding))
        return public_row(_row(attachment_id))
    except BaseException as exc:
        error = ('Allocation outcome uncertain: Docker timed out during reconstruction.' if isinstance(exc, asyncio.TimeoutError)
                 else str(exc)[:300] or 'Runtime creation interrupted.')
        _update(attachment_id, error=error)
        try:
            await asyncio.shield(stop_attachment(attachment_id))
        except Exception:
            _update(attachment_id, status='cleanup_failed')
        raise


async def require_attachment(attachment_id, execution_binding_hash, context, report_id):
    row = _row(attachment_id, context, report_id)
    if row['status'] != 'ready' or not execution_binding_hash or execution_binding_hash != row['execution_binding_hash']:
        raise ValueError('Runtime attachment is not ready or execution binding has changed. Reload this report.')
    if digest(json.loads(row['binding_json'])) != execution_binding_hash:
        raise ValueError('Runtime attachment provenance is invalid.')
    info = await _inspect_owned(row)
    if not (info.get('State') or {}).get('Running'):
        raise ValueError('Runtime attachment stopped. Stop this attachment before creating a new one.')
    if (info.get('State') or {}).get('StartedAt', '') != json.loads(row['binding_json']).get('runtime_started_at', ''):
        raise ValueError('Runtime attachment restarted after its execution binding was issued. Stop it and reconstruct a new attachment.')
    if json.loads(row['recipe_json']).get('network') == 'internal':
        network = await _inspect_network(row)
        if set((network.get('Containers') or {})) != {row['container_id']}:
            raise ValueError('Attachment network has an unexpected peer; command execution refused.')
    return row


async def execute(attachment_id, execution_binding_hash, context, report_id, code, language):
    if not isinstance(attachment_id, str):
        raise ValueError('Runtime attachment identity is invalid.')
    if attachment_id in EXECUTION_TASKS:
        raise ValueError('Another cell is running in this attachment; wait for it to finish before executing another.')
    EXECUTION_TASKS[attachment_id] = asyncio.current_task()
    try:
        return await _execute_one(attachment_id, execution_binding_hash, context, report_id, code, language)
    finally:
        EXECUTION_TASKS.pop(attachment_id, None)


async def _execute_one(attachment_id, execution_binding_hash, context, report_id, code, language):
    row = await require_attachment(attachment_id, execution_binding_hash, context, report_id)
    interpreters = {'python': ['python3', '-c'], 'bash': ['bash', '-c'], 'sh': ['sh', '-c'],
                    'php': ['php', '-r'], 'ruby': ['ruby', '-e'], 'node': ['node', '-e'], 'javascript': ['node', '-e']}
    try:
        result = await _docker('exec', '--user=' + json.loads(row['recipe_json'])['user'], row['container_id'], *interpreters[language], code, timeout=30)
        await require_attachment(attachment_id, execution_binding_hash, context, report_id)
        return {'success': result['returncode'] == 0, 'stdout': result['stdout'], 'stderr': result['stderr'],
                'exit_code': result['returncode'], 'output_truncated': result['output_truncated'], 'mode': 'lab', 'isolation_type': 'owned_docker_capsule'}
    except BaseException:
        # Killing docker exec alone leaves the remote process running. Retire
        # the exclusively owned attachment on interruption or identity failure.
        await asyncio.shield(stop_attachment(attachment_id, context, report_id))
        raise


async def cleanup_all_owned(reason='platform-reset', repo_id=None):
    """Caller drains RUNTIME_TASKS on their owner loops before this hook."""
    main, db = _db()
    try:
        query = db.query(main.NotebookRuntime).filter(main.NotebookRuntime.status != 'stopped')
        if repo_id is not None:
            query = query.filter(main.NotebookRuntime.repo_id == repo_id)
        ids = [row.id for row in query.all()]
    finally:
        db.close()
    for attachment_id in ids:
        await stop_attachment(attachment_id)
