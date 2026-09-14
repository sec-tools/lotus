"""Align an owned single-node kind fixture with its measured container limits.

The default is read-only. --apply changes only kubelet reservations after idle,
identity, and capacity checks, retaining a private original configuration backup.
It never resizes/recreates a node, restarts containerd, or grants permissions.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from decimal import Decimal, ROUND_CEILING
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

import yaml

CONFIG_PATH = '/var/lib/kubelet/config.yaml'
MIB = 1024 ** 2


def quantity(value, *, cpu=False):
    text = str(value).strip()
    match = re.fullmatch(r'(\d+(?:\.\d+)?)([KMGTPE]i|[kKMGTPE]|m|n|u)?', text)
    if not match:
        raise ValueError('Invalid nonnegative Kubernetes resource quantity')
    number, unit = Decimal(match[1]), match[2] or ''
    units = {'': 1, 'm': Decimal('.001'), 'u': Decimal('.000001'), 'n': Decimal('.000000001')}
    for index, prefix in enumerate('KMGTPE', 1):
        units[prefix] = 1000 ** index
        units[prefix + 'i'] = 1024 ** index
    units['k'] = 1000
    amount = number * units[unit]
    if cpu:
        return int((amount * 1000).to_integral_value(rounding=ROUND_CEILING))
    return int(amount.to_integral_value(rounding=ROUND_CEILING))


def capacity_plan(config, *, capacity_memory, capacity_cpu, memory_limit, cpu_limit, headroom_mib=512):
    """Preserve existing settings and top up only a reservation deficit."""
    if (not isinstance(config, dict) or config.get('kind') != 'KubeletConfiguration'
            or config.get('apiVersion') != 'kubelet.config.k8s.io/v1beta1'):
        raise ValueError('Unknown kubelet configuration schema')
    if config.get('cgroupsPerQOS', True) is not True or config.get('enforceNodeAllocatable', ['pods']) != ['pods']:
        raise ValueError('Only default Pod allocatable enforcement is supported; do not alter system daemon cgroups')
    if not isinstance(headroom_mib, int) or not 128 <= headroom_mib <= 4096:
        raise ValueError('Memory headroom must be between 128 and 4096 MiB')
    host_mem, host_cpu = quantity(capacity_memory), quantity(capacity_cpu, cpu=True)
    if host_mem <= 0 or host_cpu <= 0 or memory_limit <= 0 or cpu_limit <= 0:
        raise ValueError('Measured node capacities and limits must be positive')
    target_mem = min(host_mem, memory_limit) - headroom_mib * MIB
    target_cpu = min(host_cpu, cpu_limit)
    if target_mem <= 0:
        raise ValueError('Node memory is smaller than the requested headroom')
    existing = {}
    for name in ('systemReserved', 'kubeReserved'):
        value = config.get(name) or {}
        if not isinstance(value, dict):
            raise ValueError('Invalid existing kubelet reservation map')
        existing[name] = value
    hard = config.get('evictionHard')
    if not isinstance(hard, dict):
        raise ValueError('Explicit kind evictionHard configuration is required for reliable capacity calculation')
    eviction = hard.get('memory.available')
    if eviction is None:
        eviction_mem = 100 * MIB if config.get('mergeDefaultEvictionSettings') is True else 0
    elif str(eviction).endswith('%'):
        percent = Decimal(str(eviction)[:-1])
        if not 0 <= percent <= 100:
            raise ValueError('Invalid memory eviction threshold')
        eviction_mem = int((host_mem * percent / 100).to_integral_value(rounding=ROUND_CEILING))
    else:
        eviction_mem = quantity(eviction)
    sys_mem = quantity(existing['systemReserved'].get('memory', '0'))
    kube_mem = quantity(existing['kubeReserved'].get('memory', '0'))
    sys_cpu = quantity(existing['systemReserved'].get('cpu', '0'), cpu=True)
    kube_cpu = quantity(existing['kubeReserved'].get('cpu', '0'), cpu=True)
    extra_mem = max(0, host_mem - target_mem - sys_mem - kube_mem - eviction_mem)
    extra_cpu = max(0, host_cpu - target_cpu - sys_cpu - kube_cpu)
    merged = deepcopy(config)
    reserved = deepcopy(existing['systemReserved'])
    if extra_mem:
        reserved['memory'] = f'{(sys_mem + extra_mem + MIB - 1) // MIB}Mi'
    if extra_cpu:
        reserved['cpu'] = f'{sys_cpu + extra_cpu}m'
    if reserved != existing['systemReserved']:
        merged['systemReserved'] = reserved
    expected_mem = host_mem - quantity(reserved.get('memory', '0')) - kube_mem - eviction_mem
    expected_cpu = host_cpu - quantity(reserved.get('cpu', '0'), cpu=True) - kube_cpu
    if expected_mem <= 0 or expected_cpu <= 0:
        raise ValueError('Existing reservations leave no Pod capacity; refusing to reduce them automatically')
    return merged, {'target_allocatable_memory_bytes': target_mem, 'target_allocatable_cpu_millicores': target_cpu,
                    'expected_allocatable_memory_bytes': expected_mem, 'expected_allocatable_cpu_millicores': expected_cpu,
                    'reported_capacity_memory_bytes': host_mem, 'reported_capacity_cpu_millicores': host_cpu,
                    'measured_memory_limit_bytes': memory_limit, 'measured_cpu_limit_millicores': cpu_limit,
                    'system_reserved': reserved, 'headroom_mib': headroom_mib, 'config_changed': merged != config}


def run(argv, *, input=None, timeout=30):
    return subprocess.run(argv, input=input, text=True, capture_output=True, check=True, timeout=timeout).stdout


def validate_identity(record, directory, network, containers, nodes):
    name = record.get('cluster', '')
    if not re.fullmatch(r'lotus-netpol-[a-z0-9][a-z0-9-]{0,35}[a-z0-9]', name):
        raise ValueError('Unknown cluster ownership')
    expected = name + '-control-plane'
    if (record.get('context') != 'kind-' + name or record.get('docker_network') != name
            or record.get('node') != expected or Path(record.get('kubeconfig', '')).resolve() != directory / 'kubeconfig'):
        raise ValueError('Inconsistent private cluster ownership record')
    labels = network.get('Labels') or {}
    if (network.get('Name') != name or labels.get('app.kubernetes.io/managed-by') != 'lotus'
            or labels.get('lotus.io/purpose') != 'network-policy-verification'):
        raise ValueError('Docker network ownership mismatch')
    if len(containers) != 1 or len(nodes) != 1:
        raise ValueError('Capacity alignment requires exactly one unambiguous owned node')
    container, node = containers[0], nodes[0]
    if (container.get('Name', '').lstrip('/') != expected
            or container.get('Config', {}).get('Labels', {}).get('io.x-k8s.kind.cluster') != name
            or not container.get('State', {}).get('Running')
            or set(network.get('Containers') or {}) != {container.get('Id')}
            or node.get('metadata', {}).get('name') != expected or not node.get('metadata', {}).get('uid')):
        raise ValueError('Node/container identity mismatch')
    return container, node


def read_state(directory, runner=run):
    directory = directory.resolve()
    record = json.loads((directory / 'ownership.json').read_text())
    # Validate path/name before using them as command arguments.
    name = record.get('cluster', '')
    if not re.fullmatch(r'lotus-netpol-[a-z0-9][a-z0-9-]{0,35}[a-z0-9]', name):
        raise ValueError('Unknown cluster ownership')
    kube = ['kubectl', '--kubeconfig', str(directory / 'kubeconfig'), '--context', 'kind-' + name]
    network = json.loads(runner(['docker', 'network', 'inspect', name]))[0]
    ids = runner(['docker', 'ps', '-aq', '--filter', 'label=io.x-k8s.kind.cluster=' + name]).split()
    if len(ids) != 1:
        raise ValueError('Expected one owned kind node')
    containers = json.loads(runner(['docker', 'inspect', ids[0]]))
    nodes = json.loads(runner(kube + ['get', 'nodes', '-o', 'json']))['items']
    container, node = validate_identity(record, directory, network, containers, nodes)
    docker = ['docker', 'exec', container['Id']]
    pid = runner(docker + ['systemctl', 'show', 'kubelet', '--property=MainPID', '--value']).strip()
    if not pid.isdigit() or int(pid) <= 0:
        raise ValueError('No running kubelet configuration source')
    argv = runner(docker + ['cat', '/proc/' + pid + '/cmdline']).split('\0')
    configs = [arg.split('=', 1)[1] for arg in argv if arg.startswith('--config=')]
    if configs != [CONFIG_PATH] or any(arg.startswith(('--kube-reserved', '--system-reserved', '--eviction-hard', '--enforce-node-allocatable')) for arg in argv):
        raise ValueError('Unknown or overridden kubelet configuration source')
    runner(docker + ['test', '!', '-L', CONFIG_PATH])
    raw = runner(docker + ['cat', CONFIG_PATH])
    if len(raw.encode()) > 512 * 1024:
        raise ValueError('Kubelet configuration is unexpectedly large')
    config = yaml.safe_load(raw)
    cap = node['status']['capacity']
    mem_raw = runner(docker + ['cat', '/sys/fs/cgroup/memory.max']).strip()
    cpu_raw = runner(docker + ['cat', '/sys/fs/cgroup/cpu.max']).strip().split()
    memory_current = int(runner(docker + ['cat', '/sys/fs/cgroup/memory.current']).strip())
    if memory_current < 0:
        raise ValueError('Invalid current memory measurement')
    if len(cpu_raw) != 2 or not cpu_raw[1].isdigit() or int(cpu_raw[1]) <= 0:
        raise ValueError('Unrecognized CPU cgroup measurement')
    memory_limit = quantity(cap['memory']) if mem_raw == 'max' else int(mem_raw)
    cpu_limit = quantity(cap['cpu'], cpu=True) if cpu_raw[0] == 'max' else int(Decimal(cpu_raw[0]) * 1000 // int(cpu_raw[1]))
    host = container.get('HostConfig') or {}
    if host.get('Memory', 0) and memory_limit != host['Memory']:
        raise ValueError('Docker and cgroup memory limits disagree')
    if host.get('NanoCpus', 0) and cpu_limit != host['NanoCpus'] // 1_000_000:
        raise ValueError('Docker and cgroup CPU limits disagree')
    return {'record': record, 'node': node, 'container': container, 'config': config, 'raw': raw,
            'kube': kube, 'docker': docker, 'memory_limit': memory_limit, 'cpu_limit': cpu_limit,
            'memory_current': memory_current,
            'config_sha256': hashlib.sha256(raw.encode()).hexdigest()}


def pod_requests(pod, key):
    parse = lambda v: quantity(v, cpu=key == 'cpu')
    spec = pod.get('spec') or {}
    regular = sum(parse(c.get('resources', {}).get('requests', {}).get(key, '0')) for c in spec.get('containers', []))
    sidecars, initial = 0, 0
    for container in spec.get('initContainers', []):
        value = parse(container.get('resources', {}).get('requests', {}).get(key, '0'))
        if container.get('restartPolicy') == 'Always':
            sidecars += value
            initial = max(initial, sidecars)
        else:
            initial = max(initial, sidecars + value)
    pod_level = parse(spec.get('resources', {}).get('requests', {}).get(key, '0'))
    return max(regular + sidecars, initial, pod_level) + parse(spec.get('overhead', {}).get(key, '0'))


class InfrastructureNotReady(ValueError):
    def __init__(self, reason, inventory):
        super().__init__(reason)
        self.inventory = inventory


def idle_inventory(state, plan, runner=run):
    readiness_reason = ''
    if not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in state['node']['status'].get('conditions', [])):
        readiness_reason = 'Owned Node must be Ready before capacity maintenance; finish CNI setup first'
    # Root-cgroup usage includes daemons and reclaimable cache, so this is a
    # conservative check; never reclaim cache or force workloads out to fit.
    if state['memory_current'] >= plan['expected_allocatable_memory_bytes']:
        raise ValueError('Current node memory usage does not fit the reduced Pod budget; wait for reclaim/idle capacity')
    kube = state['kube']
    jobs = json.loads(runner(kube + ['get', 'jobs', '-A', '-o', 'json']))['items']
    if any(not any(c.get('type') in ('Complete', 'Failed') and c.get('status') == 'True' for c in j.get('status', {}).get('conditions', [])) for j in jobs):
        raise ValueError('A tool/build/lab Job is unfinished; wait for the tool boundary')
    pods = json.loads(runner(kube + ['get', 'pods', '-A', '-o', 'json']))['items']
    active = [p for p in pods if p.get('status', {}).get('phase') not in ('Succeeded', 'Failed')]
    for p in active:
        meta = p['metadata']; namespace = meta['namespace']; labels = meta.get('labels') or {}
        status = p.get('status') or {}
        containers = status.get('containerStatuses') or []
        if meta.get('deletionTimestamp'):
            raise ValueError('Pod is terminating during maintenance: ' + namespace + '/' + meta['name'])
        if (status.get('phase') != 'Running'
                or not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in status.get('conditions', []))
                or len(containers) != len(p.get('spec', {}).get('containers', []))
                or not containers or not all(c.get('ready') is True for c in containers)):
            readiness_reason = readiness_reason or 'Infrastructure/workload Pod is not stably Ready: ' + namespace + '/' + meta['name']
        if namespace in ('kube-system', 'local-path-storage'):
            continue
        if (namespace, labels.get('app')) not in {('lotus', 'lotus'), ('lotus-build', 'lotus-registry')}:
            raise ValueError('Non-infrastructure Pod remains active: ' + namespace + '/' + meta['name'])
        if namespace == 'lotus':
            # Read only counts from the local SQLite profile, never credentials.
            probe = """import os,sqlite3,json
from datetime import datetime,timezone
from sqlalchemy.engine import make_url
url=make_url(os.environ['DATABASE_URL'])
assert url.drivername.startswith('sqlite'), 'Capacity maintenance requires the local SQLite profile'
db=sqlite3.connect('file:'+url.database+'?mode=ro',uri=True)
active=db.execute("SELECT count(*) FROM scan_jobs WHERE status NOT IN ('completed','failed','cancelled','interrupted')").fetchone()[0]
values=[r[0] for r in db.execute('SELECT expires_at FROM scan_leases')]+[r[0] for r in db.execute('SELECT lease_expires_at FROM scan_jobs')]
now=datetime.now(timezone.utc)
leases=sum(bool(v) and datetime.fromisoformat(v).replace(tzinfo=timezone.utc)>now for v in values)
db.close();print(json.dumps({'active':active,'leases':leases}))"""
            counts = json.loads(runner(kube + ['-n', namespace, 'exec', meta['name'], '--', 'python3', '-c', probe]))
            if counts['active'] or counts['leases']:
                raise ValueError('Audit jobs or worker leases remain active')
    selected = [p for p in active if p.get('spec', {}).get('nodeName') == state['node']['metadata']['name']]
    for key, bound in [('memory', 'expected_allocatable_memory_bytes'), ('cpu', 'expected_allocatable_cpu_millicores')]:
        if sum(pod_requests(p, key) for p in selected) >= plan[bound]:
            raise ValueError('Existing Pod requests do not fit reduced allocatable ' + key)
    inventory = {p['metadata']['uid']: {'namespace': p['metadata']['namespace'], 'name': p['metadata']['name'],
            'restarts': {c['name']: c.get('restartCount', 0) for c in p.get('status', {}).get('containerStatuses', [])}}
            for p in selected}
    if readiness_reason:
        raise InfrastructureNotReady(readiness_reason, inventory)
    return inventory


def same_inventory(baseline, observed):
    """Missing status can converge; observed identity/restart changes cannot."""
    if set(baseline) != set(observed):
        raise ValueError('Pod identities changed; node remains cordoned')
    complete = True
    for uid, before in baseline.items():
        after = observed[uid]
        if any(before[key] != after[key] for key in ('namespace', 'name')):
            raise ValueError('Pod identities changed; node remains cordoned')
        if any(before['restarts'].get(name) != count for name, count in after['restarts'].items()):
            raise ValueError('Pod restart counts changed; node remains cordoned')
        complete = complete and before['restarts'] == after['restarts']
    return complete


def node_patch(state, node, unschedulable, runner=run):
    patch = [{'op': 'test', 'path': '/metadata/uid', 'value': state['node']['metadata']['uid']},
             {'op': 'test', 'path': '/metadata/resourceVersion', 'value': node['metadata']['resourceVersion']},
             {'op': 'add', 'path': '/spec/unschedulable', 'value': unschedulable}]
    runner(state['kube'] + ['patch', 'node', node['metadata']['name'], '--type=json', '-p', json.dumps(patch)])


def align(directory, *, apply=False, runner=run, sleeper=time.sleep):
    directory = directory.resolve()
    state = read_state(directory, runner)
    cap = state['node']['status']['capacity']
    merged, plan = capacity_plan(state['config'], capacity_memory=cap['memory'], capacity_cpu=cap['cpu'],
                                memory_limit=state['memory_limit'], cpu_limit=state['cpu_limit'])
    plan.update(node=state['node']['metadata']['name'], node_uid=state['node']['metadata']['uid'],
                container_id=state['container']['Id'], config_sha256=state['config_sha256'], applied=False)
    try:
        inventory = idle_inventory(state, plan, runner)
    except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        if apply:
            raise
        plan['apply_blocked'] = str(exc)
        return plan
    if not apply:
        return plan
    observed = state['node']['status']['allocatable']
    if not plan['config_changed'] and quantity(observed['memory']) <= plan['target_allocatable_memory_bytes'] and quantity(observed['cpu'], cpu=True) <= plan['target_allocatable_cpu_millicores']:
        plan['already_aligned'] = True
        return plan
    original = bool(state['node'].get('spec', {}).get('unschedulable', False))
    plan['original_unschedulable'] = original
    plan['baseline_pods'] = deepcopy(inventory)
    # Backup precedes all mutations and uses exclusive, private creation.
    backup = directory / ('kubelet-capacity-backup-' + uuid.uuid4().hex + '.yaml')
    fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(state['raw'])
    plan['backup_path'] = str(backup)
    receipt = backup.with_suffix('.json')
    plan['receipt_path'] = str(receipt)
    def checkpoint(stage):
        plan['maintenance_stage'] = stage
        flags = os.O_WRONLY | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        if not receipt.exists():
            flags |= os.O_CREAT | os.O_EXCL
        handle = os.open(receipt, flags, 0o600)
        with os.fdopen(handle, 'w') as stream:
            json.dump(plan, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
    checkpoint('prepared')
    try:
        current = read_state(directory, runner)
        for key in ('config_sha256', 'memory_limit', 'cpu_limit'):
            if current[key] != state[key]:
                raise ValueError('Node configuration/capacity changed during preparation')
        if current['node']['status']['capacity'] != state['node']['status']['capacity']:
            raise ValueError('Advertised node capacity changed during preparation')
        if current['node']['metadata']['uid'] != plan['node_uid'] or current['container']['Id'] != plan['container_id']:
            raise ValueError('Node identity changed during preparation')
        if idle_inventory(current, plan, runner) != inventory:
            raise ValueError('Pod identities/restart counts changed before cordoning')
        node_patch(state, current['node'], True, runner)
        checkpoint('cordoned')
        # Once cordoned, failure deliberately leaves the node cordoned for review.
        if idle_inventory(current, plan, runner) != inventory:
            raise ValueError('Pod identities/restart counts changed before maintenance')
        script = '''set -eu
    target=/var/lib/kubelet/config.yaml
    test -f "$target" && test ! -L "$target"
    actual=$(sha256sum "$target"); test "${actual%% *}" = "$1"
    tmp=$(mktemp /var/lib/kubelet/.lotus-capacity.XXXXXX)
    trap 'rm -f "$tmp"' EXIT
    cat > "$tmp"
    chmod --reference="$target" "$tmp"
    chown --reference="$target" "$tmp"
    mv -T "$tmp" "$target"
    '''
        runner(['docker', 'exec', '-i', state['container']['Id'], 'sh', '-c', script, 'lotus-capacity', state['config_sha256']], input=yaml.safe_dump(merged, sort_keys=False))
        checkpoint('configuration-written')
        runner(state['docker'] + ['systemctl', 'restart', 'kubelet'], timeout=60)
        checkpoint('kubelet-restarted')
        matched = None
        for _ in range(60):
            try:
                node = json.loads(runner(state['kube'] + ['get', 'node', plan['node'], '-o', 'json']))
                if node['metadata']['uid'] != plan['node_uid']:
                    raise ValueError('Node replaced during verification')
                alloc = node['status']['allocatable']
                ready = any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in node['status'].get('conditions', []))
                if (ready and quantity(alloc['memory']) <= plan['target_allocatable_memory_bytes']
                        and abs(quantity(alloc['memory']) - plan['expected_allocatable_memory_bytes']) <= MIB
                        and quantity(alloc['cpu'], cpu=True) == plan['expected_allocatable_cpu_millicores']):
                    matched = node
                    break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            sleeper(1)
        if matched is None:
            raise ValueError('Kubelet capacity read-back failed; node remains cordoned; inspect private backup')
        # Node Ready can precede Calico/controller readiness after kubelet
        # restart. Wait at most 60s/60 observations, checking original identity
        # and every observed restart count throughout; never reapply/restart.
        convergence_deadline = time.monotonic() + 60
        final = None
        def convergence_run(argv, **kwargs):
            remaining = convergence_deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, 60)
            kwargs['timeout'] = min(kwargs.get('timeout', 30), remaining)
            return runner(argv, **kwargs)
        for _ in range(60):
            if time.monotonic() >= convergence_deadline:
                break
            try:
                candidate = read_state(directory, convergence_run)
                if (candidate['node']['metadata']['uid'] != plan['node_uid']
                        or candidate['container']['Id'] != plan['container_id'] or candidate['config'] != merged
                        or candidate['memory_limit'] != state['memory_limit'] or candidate['cpu_limit'] != state['cpu_limit']
                        or candidate['node']['status']['capacity'] != state['node']['status']['capacity']):
                    raise ValueError('Original node/container/configuration/capacity identity changed after maintenance')
                final_alloc = candidate['node']['status']['allocatable']
                if (quantity(final_alloc['memory']) > plan['target_allocatable_memory_bytes']
                        or abs(quantity(final_alloc['memory']) - plan['expected_allocatable_memory_bytes']) > MIB
                        or quantity(final_alloc['cpu'], cpu=True) != plan['expected_allocatable_cpu_millicores']):
                    raise ValueError('Node allocatable changed after successful read-back; node remains cordoned')
                try:
                    observed_inventory = idle_inventory(candidate, plan, convergence_run)
                    ready = True
                except InfrastructureNotReady as pending:
                    observed_inventory = pending.inventory
                    ready = False
                complete = same_inventory(inventory, observed_inventory)
                if ready and complete:
                    final = candidate
                    break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            sleeper(min(1, max(0, convergence_deadline - time.monotonic())))
        if final is None:
            raise ValueError('Infrastructure readiness did not converge with unchanged Pod identities/restarts within 60s; node remains cordoned')
        node_patch(state, final['node'], original, runner)
        plan.update(applied=True, pod_identities_and_restarts_preserved=True,
                    observed_allocatable=matched['status']['allocatable'], original_unschedulable_restored=True)
        checkpoint('complete')
        return plan
    except Exception as exc:
        plan['failure_type'] = type(exc).__name__
        checkpoint('needs-review')
        raise ValueError(f"{exc}; inspect private maintenance receipt {receipt}; node may remain cordoned") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--apply', action='store_true', help='Apply only to the exact idle owned node; default prints a read-only plan')
    args = parser.parse_args()
    try:
        print(json.dumps(align(args.directory, apply=args.apply), indent=2))
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
