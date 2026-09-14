"""Bounded GET observations in a disposable, destination-scoped Kubernetes Pod.

The controller resolves names but never connects to an observation target. A
NetworkPolicy-enforcing CNI is required; policy read-back alone is not evidence
that the cluster enforces traffic rules. Docker has no equivalent destination
firewall here and therefore cannot silently replace this transport.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import os
import re
import socket
import time
import uuid
from urllib.parse import urlsplit

from backend.deployment_passive import _command

MAX_BYTES = 128 * 1024
MAX_PATHS = 16
OWNER_LABEL = "lotus.io/identity-owner"

# This exact standard-library program is supplied inline to an inspected worker.
# Each request uses a fresh connection: no cookie jar, proxies, redirects, body,
# authentication, retry, or target-provided URL is ever interpreted.
WORKER_SCRIPT = r'''
import http.client, ipaddress, json, os, signal, socket, ssl, sys
http.client._MAXLINE = 8192
http.client._MAXHEADERS = 32
spec = json.loads(sys.argv[1])
if os.environ.get('LOTUS_IDENTITY_POD_UID') != spec['pod_uid']:
    raise ValueError('Identity worker Pod UID changed before execution')
rows = []
def expired(*args):
    raise TimeoutError('identity request exceeded its wall-clock budget')
signal.signal(signal.SIGALRM, expired)
control = spec['denied_control']
signal.setitimer(signal.ITIMER_REAL, 3)
probe = socket.socket(socket.AF_INET6 if ipaddress.ip_address(control['ip']).version == 6 else socket.AF_INET, socket.SOCK_STREAM)
probe.settimeout(1)
try:
    probe.connect((control['ip'], control['port']))
except (OSError, TimeoutError):
    pass
else:
    raise ValueError('Network isolation failed: worker reached the protected control')
finally:
    probe.close()
    signal.setitimer(signal.ITIMER_REAL, 0)
class PinnedHTTP(http.client.HTTPConnection):
    def connect(self):
        address = ipaddress.ip_address(spec['ip'])
        self.sock = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(spec['timeout'])
        self.sock.connect((str(address), spec['port']))
class PinnedHTTPS(PinnedHTTP):
    def connect(self):
        super().connect()
        self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=spec['host'])
for path in spec['paths']:
    row = {'method': 'GET', 'path': path}
    connection = None
    try:
        signal.setitimer(signal.ITIMER_REAL, spec['timeout'])
        connection = (PinnedHTTPS if spec['scheme'] == 'https' else PinnedHTTP)(spec['host'], spec.get('origin_port', spec['port']), timeout=spec['timeout'])
        connection.request('GET', path, headers={'User-Agent': 'Lotus-Deployment-Identity/3', 'Accept': '*/*', 'Accept-Encoding': 'identity', 'Connection': 'close'})
        response = connection.getresponse()
        if response.getheader('Content-Encoding', 'identity').lower().strip() not in ('', 'identity'):
            raise ValueError('compressed identity response refused')
        body = response.read(131073)
        row.update(status=response.status, headers={name: str(response.getheader(name) or '')[:512] for name in ('content-type', 'server', 'location')},
                   body=body[:131072].decode('utf-8', 'replace'), body_bytes=min(len(body), 131072), truncated=len(body)>131072)
    except Exception as exc:
        row.update(status=0, error=str(exc)[:180])
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if connection is not None:
            connection.close()
    rows.append(row)
print(json.dumps({'requests': rows, 'control_denied': True}, ensure_ascii=True))
'''


def _paths(paths):
    values = list(paths)
    if any(not isinstance(value, str) for value in values) or len(set(values)) != len(values):
        raise ValueError('Identity paths must be distinct strings')
    if not values or len(values) > MAX_PATHS:
        raise ValueError("Identity plan must contain between one and sixteen proven GET paths")
    for value in values:
        if (not isinstance(value, str) or len(value) > 256 or not value.startswith('/')
                or value.startswith('//') or not re.fullmatch(r'/[A-Za-z0-9/_.~-]*', value)
                or any(part in {'.', '..'} for part in value.split('/'))):
            raise ValueError("Identity requests require literal paths without queries or parameters")
    return values


def _base(value):
    if not isinstance(value, str) or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("Identity endpoint must be an ASCII HTTP origin")
    parsed = urlsplit(value)
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in {'', '/'} or parsed.query or parsed.fragment):
        raise ValueError("Identity endpoint must be an HTTP origin without credentials or a path")
    host = parsed.hostname.rstrip('.')
    if '%' in host or not re.fullmatch(r'[A-Za-z0-9.:-]+', host):
        raise ValueError("Invalid identity hostname")
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid identity port")
    return parsed.scheme, host, port


def _public(address):
    ip = ipaddress.ip_address(address)
    return ip.is_global and not (ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local) and not getattr(ip, 'ipv4_mapped', None)


async def resolve_public(host, port, timeout):
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=min(5, timeout))
        addresses = sorted({row[4][0] for row in infos})
    else:
        addresses = [str(literal)]
    if not addresses or len(addresses) > 16 or any(not _public(value) for value in addresses):
        raise ValueError("Public identity DNS must resolve only to globally routable unicast addresses")
    return addresses


def _prefix(namespace):
    from backend import k8s_lab
    return [k8s_lab.kubectl_binary(), *k8s_lab._context_args(), '--request-timeout=10s', '-n', namespace]


async def _read(namespace, kind, name):
    output, rc, error = await _command([*_prefix(namespace), 'get', kind, name, '-o', 'json'], timeout=12, limit=2_000_000)
    if rc:
        if 'NotFound' in error:
            return None
        raise ValueError("Identity runtime could not be read: " + (error or output)[-250:])
    return json.loads(output)


def _selected(selector, labels):
    if any(labels.get(key) != value for key, value in selector.get('matchLabels', {}).items()):
        return False
    for expression in selector.get('matchExpressions', []):
        key, op, values = expression['key'], expression['operator'], expression.get('values', [])
        if op == 'In' and labels.get(key) not in values: return False
        if op == 'NotIn' and key in labels and labels[key] in values: return False
        if op == 'Exists' and key not in labels: return False
        if op == 'DoesNotExist' and key in labels: return False
        if op not in {'In', 'NotIn', 'Exists', 'DoesNotExist'}:
            raise ValueError('Unsupported NetworkPolicy selector')
    return True


def manifests(namespace, name, owner, image, spec, deadline):
    labels = {'app.kubernetes.io/managed-by': 'lotus', 'lotus.io/purpose': 'deployment-observation', OWNER_LABEL: owner}
    container = {'name': 'identity', 'image': image, 'imagePullPolicy': 'IfNotPresent',
                 'command': ['python3', '-c', 'import time; time.sleep(180)'],
                 'env': [{'name': 'LOTUS_IDENTITY_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}}],
                 'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                 'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'cpu': '500m', 'memory': '128Mi'}},
                 'volumeMounts': [{'name': 'tmp', 'mountPath': '/tmp'}]}
    pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace, 'labels': labels},
           'spec': {'restartPolicy': 'Never', 'activeDeadlineSeconds': deadline, 'terminationGracePeriodSeconds': 1,
                    'automountServiceAccountToken': False, 'enableServiceLinks': False, 'hostNetwork': False,
                    'hostPID': False, 'hostIPC': False, 'dnsPolicy': 'None', 'dnsConfig': {'nameservers': ['127.0.0.1']},
                    'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001, 'seccompProfile': {'type': 'RuntimeDefault'}},
                    'containers': [container], 'volumes': [{'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '8Mi'}}]}}
    ip = ipaddress.ip_address(spec['ip'])
    policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
              'metadata': {'name': name, 'namespace': namespace, 'labels': labels},
              'spec': {'podSelector': {'matchLabels': {OWNER_LABEL: owner}}, 'policyTypes': ['Ingress', 'Egress'],
                       'ingress': [], 'egress': [{'to': [{'ipBlock': {'cidr': str(ip) + ('/32' if ip.version == 4 else '/128')}}],
                                                 'ports': [{'protocol': 'TCP', 'port': spec['port']}]}]}}
    return pod, policy


def validate_pod(actual, expected, uid):
    meta, spec = actual.get('metadata', {}), actual.get('spec', {})
    if (meta.get('uid') != uid or meta.get('name') != expected['metadata']['name']
            or meta.get('namespace') != expected['metadata']['namespace'] or meta.get('deletionTimestamp')
            or meta.get('labels') != expected['metadata']['labels']):
        raise ValueError('Identity worker ownership changed')
    for key, value in expected['spec'].items():
        if key == 'containers':
            if len(spec.get(key, [])) != 1:
                raise ValueError('Unexpected identity worker containers')
            for field, wanted in value[0].items():
                if spec[key][0].get(field) != wanted:
                    raise ValueError('Identity worker container contract changed: ' + field)
            if any(spec[key][0].get(field) for field in ('envFrom', 'lifecycle', 'ports', 'workingDir')):
                raise ValueError('Identity worker has unapproved configuration')
        elif key in {'hostNetwork', 'hostPID', 'hostIPC'} and value is False:
            if spec.get(key, False) is not False:
                raise ValueError('Identity worker requested host namespace access: ' + key)
        elif spec.get(key) != value:
            raise ValueError('Identity worker contract changed: ' + key)
    if spec.get('initContainers') or spec.get('ephemeralContainers'):
        raise ValueError('Identity worker contains unapproved auxiliary containers')


def _normalized_policy(spec):
    return {**spec, 'ingress': spec.get('ingress') or [], 'egress': spec.get('egress') or []}


async def _policy(namespace, expected, uid, labels):
    current = await _read(namespace, 'networkpolicy', expected['metadata']['name'])
    if (not current or current['metadata'].get('uid') != uid or _normalized_policy(current.get('spec', {})) != _normalized_policy(expected['spec'])
            or current['metadata'].get('labels') != expected['metadata']['labels']):
        raise ValueError('Identity destination NetworkPolicy changed')
    output, rc, error = await _command([*_prefix(namespace), 'get', 'networkpolicies', '-o', 'json'], timeout=12, limit=2_000_000)
    if rc:
        raise ValueError('Cannot verify additive identity NetworkPolicies: ' + error[-250:])
    for item in json.loads(output).get('items', []):
        if item.get('metadata', {}).get('uid') == uid: continue
        spec = item.get('spec', {})
        if _selected(spec.get('podSelector', {}), labels) and (spec.get('egress') or spec.get('ingress')):
            raise ValueError('Another NetworkPolicy widens identity worker isolation')


async def _create(namespace, document):
    output, rc, error = await _command([*_prefix(namespace), 'create', '-f', '-', '-o', 'json'],
                                      input_data=json.dumps(document).encode(), timeout=15, limit=2_000_000)
    if rc:
        raise ValueError('Cannot create isolated identity resource: ' + (error or output)[-250:])
    created = json.loads(output)
    if not created.get('metadata', {}).get('uid'):
        raise ValueError('Identity creation returned no resource UID')
    return created


async def _delete(namespace, kind, name, uid, owner):
    current = await _read(namespace, kind, name)
    if current is None: return
    meta = current.get('metadata', {})
    if meta.get('uid') != uid or meta.get('labels', {}).get(OWNER_LABEL) != owner:
        raise ValueError('Refusing to delete a replacement identity resource')
    base = '/api/v1/namespaces/' if kind == 'pod' else '/apis/networking.k8s.io/v1/namespaces/'
    resource = '/pods/' if kind == 'pod' else '/networkpolicies/'
    body = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}, 'gracePeriodSeconds': 1}
    _, rc, error = await _command([*_prefix(namespace), 'delete', '--raw=' + base + namespace + resource + name, '-f', '-'],
                                  input_data=json.dumps(body).encode(), timeout=12)
    if rc:
        raise ValueError('Identity cleanup was refused: ' + error[-250:])
    deadline = time.monotonic() + 15
    while True:
        current = await _read(namespace, kind, name)
        if current is None: return
        if current.get('metadata', {}).get('uid') != uid:
            return  # Original UID is gone; a replacement is never deleted.
        if time.monotonic() >= deadline:
            raise ValueError('Identity resource did not drain within cleanup budget')
        await asyncio.sleep(.2)


async def _image():
    value = os.environ.get('LOTUS_DEPLOYMENT_IDENTITY_IMAGE', '').strip()
    if not value:
        from backend.lab_selftest import _kubernetes_selftest_image
        value = await _kubernetes_selftest_image(use_explicit_override=False)
    if not re.fullmatch(r'[^\s]+@sha256:[a-fA-F0-9]{64}', value):
        raise ValueError('Identity observations require an immutable installed Python image')
    return value


async def _control(namespace, expected=None):
    """A live, UID-bound control is required for every negative egress test."""
    configured = os.environ.get('LOTUS_DEPLOYMENT_ISOLATION_CONTROL', '').strip()
    if configured:
        selector = json.loads(configured)
        if not isinstance(selector, dict) or set(selector) != {'pod_name', 'pod_uid', 'port'}:
            raise ValueError('Isolation control requires exact Pod name, UID and port')
    else:
        selector = {'pod_name': os.environ.get('LOTUS_POD_NAME') or os.environ.get('HOSTNAME', ''), 'port': 8000}
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', selector.get('pod_name', '')):
        raise ValueError('A ready controller Pod is required to test identity network isolation')
    doc = await _read(namespace, 'pod', selector['pod_name'])
    meta, podspec, status = (doc or {}).get('metadata', {}), (doc or {}).get('spec', {}), (doc or {}).get('status', {})
    if (not meta.get('uid') or meta.get('deletionTimestamp') or podspec.get('hostNetwork')
            or not any(row.get('type') == 'Ready' and row.get('status') == 'True' for row in status.get('conditions', []))
            or (configured and meta.get('uid') != selector['pod_uid'])
            or (not configured and meta.get('labels', {}).get('app') != 'lotus')):
        raise ValueError('Isolation control Pod is absent, not Ready, or has changed ownership')
    port = selector['port']
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('Invalid isolation control TCP port')
    ip = ipaddress.ip_address(status.get('podIP') or '')
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise ValueError('Invalid isolation control Pod IP')
    control = {'ip': str(ip), 'port': port, 'pod_uid': meta['uid']}
    if expected is not None and control != expected:
        raise ValueError('Isolation control changed during the observation')
    # Only this owned control is contacted by the controller, never the user's
    # observation target. A closed/unreachable port cannot prove egress denial.
    reader, writer = await asyncio.wait_for(asyncio.open_connection(str(ip), port), timeout=2)
    writer.close()
    await asyncio.wait_for(writer.wait_closed(), timeout=2)
    return control


async def capture(base_url, paths, timeout=5, trusted_local=False, local_binding=None):
    """Return transient bounded response rows; never persist response bodies."""
    from backend.lab_provider import provider_name
    from backend import k8s_lab
    if provider_name() != 'k8s-job':
        raise ValueError('Deployment observations require Kubernetes destination isolation; Docker backup is unavailable')
    scheme, host, port = _base(base_url)
    selected = _paths(paths)
    timeout = float(timeout)
    if not math.isfinite(timeout) or not .1 <= timeout <= 10:
        raise ValueError('Identity request timeout must be between 0.1 and 10 seconds')
    origin_port = port
    if trusted_local:
        from backend.deployment_local import validate_transport_binding
        binding = await validate_transport_binding(local_binding)
        ip, port = binding['pod_ip'], binding['target_port']
        host, origin_port = binding['authority_host'], binding['authority_port']
    elif local_binding is not None:
        raise ValueError('Local identity binding requires explicit owned-local mode')
    else:
        ip = (await resolve_public(host, port, timeout))[0]
    spec = {'host': host, 'scheme': scheme, 'port': port, 'origin_port': origin_port, 'ip': ip, 'paths': selected, 'timeout': timeout}
    namespace, owner = k8s_lab.namespace(), uuid.uuid4().hex
    name = 'lotus-identity-' + owner[:20]
    control = await _control(namespace)
    if control['ip'] == ip:
        raise ValueError('Identity target must not be the controller isolation control')
    spec['denied_control'] = control
    image = await _image()
    deadline = min(180, math.ceil(timeout * len(selected)) + 60)
    pod, policy = manifests(namespace, name, owner, image, spec, deadline)
    identities = {}
    attempted = []
    result = None
    try:
        attempted.append((namespace, 'networkpolicy', policy))
        created = await _create(namespace, policy)
        identities['networkpolicy'] = created['metadata']['uid']
        await _policy(namespace, policy, identities['networkpolicy'], pod['metadata']['labels'])
        if trusted_local:
            target_policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                'metadata': {'name': name + '-target', 'namespace': binding['namespace'], 'labels': {OWNER_LABEL: owner}},
                'spec': {'podSelector': {'matchLabels': binding['pod_labels']}, 'policyTypes': ['Ingress'],
                         'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': namespace}},
                                               'podSelector': {'matchLabels': {OWNER_LABEL: owner}}}],
                                      'ports': [{'protocol': 'TCP', 'port': port}]}]}}
            attempted.append((binding['namespace'], 'networkpolicy', target_policy))
            created_target = await _create(binding['namespace'], target_policy)
            identities['target-policy'] = created_target['metadata']['uid']
            target_read = await _read(binding['namespace'], 'networkpolicy', name + '-target')
            if not target_read or target_read['metadata'].get('uid') != identities['target-policy'] or _normalized_policy(target_read.get('spec', {})) != _normalized_policy(target_policy['spec']):
                raise ValueError('Target ingress policy could not be verified')
        attempted.append((namespace, 'pod', pod))
        created = await _create(namespace, pod)
        identities['pod'] = created['metadata']['uid']
        end = time.monotonic() + 35
        while True:
            actual = await _read(namespace, 'pod', name)
            if not actual: raise ValueError('Identity worker disappeared')
            validate_pod(actual, pod, identities['pod'])
            status = actual.get('status', {})
            if status.get('phase') in {'Failed', 'Succeeded'}:
                raise ValueError('Identity worker exited before observation')
            statuses = status.get('containerStatuses', [])
            if status.get('phase') == 'Running' and len(statuses) == 1 and statuses[0].get('ready') and statuses[0].get('containerID') and statuses[0].get('imageID'):
                break
            if time.monotonic() >= end: raise TimeoutError('Identity worker did not become ready within 35 seconds')
            await asyncio.sleep(.25)
        await _policy(namespace, policy, identities['networkpolicy'], pod['metadata']['labels'])
        if trusted_local:
            await validate_transport_binding(local_binding)
        spec['pod_uid'] = identities['pod']
        output, rc, error = await _command([*_prefix(namespace), 'exec', name, '-c', 'identity', '--', 'python3', '-c', WORKER_SCRIPT, json.dumps(spec)],
            timeout=timeout * len(selected) + 10, limit=MAX_BYTES * len(selected) * 6 + 65536)
        if rc: raise ValueError('Isolated identity worker failed: ' + error[-250:])
        result = json.loads(output)
        rows = result.get('requests') if isinstance(result, dict) else None
        if (result.get('control_denied') is not True or not isinstance(rows, list) or [row.get('path') for row in rows] != selected
                or any(row.get('method') != 'GET' or len(row.get('body', '').encode('utf-8')) > MAX_BYTES * 3 for row in rows)):
            raise ValueError('Identity worker returned invalid observations')
        actual_after = await _read(namespace, 'pod', name)
        validate_pod(actual_after or {}, pod, identities['pod'])
        if actual_after.get('status', {}).get('containerStatuses') != statuses:
            raise ValueError('Identity worker container changed during observation')
        await _policy(namespace, policy, identities['networkpolicy'], pod['metadata']['labels'])
        if trusted_local: await validate_transport_binding(local_binding)
        await _control(namespace, control)
        result['transport'] = {'runner': 'k8s-identity-pod', 'pod_uid': identities['pod'], 'policy_uid': identities['networkpolicy'],
                               'image': image, 'negative_control': control, 'negative_control_denied': True, 'destination_ip': ip, 'destination_port': port, 'cleanup_verified': False}
    finally:
        # Keep destination isolation until the worker UID has actually gone.
        # A cleanup failure deliberately prevents a successful observation.
        for resource_ns, kind, document in reversed(attempted):
            resource_name = document['metadata']['name']
            key = 'target-policy' if resource_name.endswith('-target') else kind
            uid = identities.get(key)
            if not uid:
                # A create timeout can still have created its object. Recover only
                # this fresh owner, then delete with that observed UID precondition.
                current = await _read(resource_ns, kind, resource_name)
                if current and current.get('metadata', {}).get('labels', {}).get(OWNER_LABEL) == owner:
                    uid = current['metadata'].get('uid')
            if uid:
                await _delete(resource_ns, kind, resource_name, uid, owner)
    result['transport']['cleanup_verified'] = True
    return result
