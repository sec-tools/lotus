#!/usr/bin/env python3
"""Render or deploy Lotus to one explicitly selected Kubernetes context.

Only kubectl is executed. Bootstrap Secret content stays in memory or in an
explicitly requested new mode-0600 manifest; captured tool output is not echoed.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = 'lotus'
SECRET_NAME = 'lotus-bootstrap'
IMAGE_PATTERN = re.compile(
    r'(?:(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?/)?'
    r'[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*'
    r'(?:/[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)*'
    r'(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[a-f0-9]{64}'
)
RUNTIME_ENV = {
    'LOTUS_RUNTIME': 'k8s-job',
    'LOTUS_LAB_PROVIDER': 'k8s-job',
    'LOTUS_LAB_PROVIDER_STRICT': '1',
    'LOTUS_ALLOW_PROVIDER_FALLBACK': '0',
    'LOTUS_REQUIRE_LAB_PROVIDER': '1',
    'LOTUS_REQUIRE_LAB_PROOF': '1',
    'LOTUS_DISABLE_LAB': '0',
    'LOTUS_SKILLS_DIR': '/app/data/skills',
    'LOTUS_MAX_CONCURRENT_SCANS': '1',
    'WEB_CONCURRENCY': '1',
}


class DeploymentError(RuntimeError):
    pass


def validate_image(value):
    if not isinstance(value, str) or len(value) > 2048 or not IMAGE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError('image must be an OCI repository reference pinned with @sha256: and 64 lowercase hexadecimal characters')
    return value


def positive_seconds(value):
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError('rollout timeout must be an integer from 1 to 3600') from None
    if not 1 <= seconds <= 3600:
        raise argparse.ArgumentTypeError('rollout timeout must be an integer from 1 to 3600')
    return seconds


def parse_objects(output):
    """kubectl create -k may print adjacent JSON objects instead of one List."""
    decoder = json.JSONDecoder()
    offset = 0
    objects = []
    while offset < len(output):
        while offset < len(output) and output[offset].isspace():
            offset += 1
        if offset == len(output):
            break
        try:
            value, offset = decoder.raw_decode(output, offset)
        except (json.JSONDecodeError, ValueError):
            raise DeploymentError('kubectl returned invalid JSON; captured output was withheld') from None
        if not isinstance(value, dict):
            raise DeploymentError('kubectl returned a non-object resource')
        if value.get('kind') == 'List':
            items = value.get('items')
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise DeploymentError('kubectl returned an invalid resource List')
            objects.extend(items)
        else:
            objects.append(value)
    if not objects:
        raise DeploymentError('kubectl returned no resources')
    return objects


def kubectl(args, command, *, phase, payload=None, timeout=90, request_timeout=30):
    prefix = ['kubectl', '--context', args.context, f'--request-timeout={request_timeout}s']
    if args.kubeconfig is not None:
        prefix += ['--kubeconfig', str(args.kubeconfig)]
    try:
        result = subprocess.run(prefix + command, input=payload, text=True,
                                capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise DeploymentError(f'kubectl timed out during {phase}; check the selected context and resource readiness') from None
    except OSError:
        raise DeploymentError(f'Unable to execute kubectl during {phase}; ensure kubectl is installed') from None
    if result.returncode:
        # kubectl errors can echo submitted Secret data, including base64 values.
        raise DeploymentError(f'kubectl failed during {phase} (exit {result.returncode}); captured output was withheld to protect bootstrap values')
    return result.stdout


def prepare_manifest(resources, secret, image, *, pull_policy='IfNotPresent'):
    resources = copy.deepcopy(resources)
    secret = copy.deepcopy(secret)
    if secret.get('kind') != 'Secret' or secret.get('metadata', {}).get('name') != SECRET_NAME:
        raise DeploymentError('Bootstrap rendering did not return the expected Secret')
    secret['metadata']['namespace'] = NAMESPACE
    deployments = [r for r in resources if r.get('kind') == 'Deployment'
                   and r.get('metadata', {}).get('name') == 'lotus'
                   and r.get('metadata', {}).get('namespace') == NAMESPACE]
    if len(deployments) != 1:
        raise DeploymentError('Expected exactly one lotus Deployment in namespace lotus')
    deployment = deployments[0]
    deployment['spec']['replicas'] = 1
    deployment['spec']['strategy'] = {'type': 'Recreate'}
    containers = deployment['spec']['template']['spec']['containers']
    selected = [c for c in containers if c.get('name') == 'lotus']
    if len(selected) != 1:
        raise DeploymentError('Expected exactly one lotus application container')
    container = selected[0]
    container['image'], container['imagePullPolicy'] = validate_image(image), pull_policy
    env = [entry for entry in container.get('env', []) if entry.get('name') not in RUNTIME_ENV]
    env.extend({'name': name, 'value': value} for name, value in RUNTIME_ENV.items())
    container['env'] = env
    env_from = [entry for entry in container.get('envFrom', [])
                if entry.get('secretRef', {}).get('name') != SECRET_NAME]
    env_from.append({'secretRef': {'name': SECRET_NAME, 'optional': False}})
    container['envFrom'] = env_from
    namespaces = [r for r in resources if r.get('kind') == 'Namespace']
    if not any(r.get('metadata', {}).get('name') == NAMESPACE for r in namespaces):
        raise DeploymentError('Namespace lotus is missing from the rendered resources')
    remaining = [r for r in resources if r.get('kind') != 'Namespace']
    if any(r.get('kind') == 'Secret' and r.get('metadata', {}).get('name') == SECRET_NAME
           for r in remaining):
        raise DeploymentError('The overlay already defines the bootstrap Secret')
    return {'apiVersion': 'v1', 'kind': 'List', 'items': namespaces + [secret] + remaining}


def write_private_manifest(path, manifest):
    payload = json.dumps(manifest, indent=2) + '\n'
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise DeploymentError('Render destination already exists; it was preserved') from None
    except OSError:
        raise DeploymentError('Unable to create private render destination') from None
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(payload)
    except OSError:
        raise DeploymentError('Unable to finish writing the private render destination') from None


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--context', required=True, help='exact existing kubectl context; never inferred')
    result.add_argument('--image', required=True, type=validate_image, help='immutable application OCI image reference')
    result.add_argument('--kubeconfig', type=Path, help='explicit kubeconfig file; defaults to kubectl configuration')
    result.add_argument('--env-file', type=Path, default=Path('.env'), help='existing bootstrap values; never modified')
    result.add_argument('--render-only', type=Path, metavar='PATH', help='write a new private manifest without applying it')
    result.add_argument('--local-preloaded', action='store_true', help='use pull policy Never for an image already loaded into cluster nodes')
    builders = result.add_mutually_exclusive_group()
    builders.add_argument('--with-builder', dest='with_builder', action='store_true', help='include the builder namespace/RBAC bootstrap (default)')
    builders.add_argument('--without-builder', dest='with_builder', action='store_false', help='omit builder bootstrap when an administrator already installed it')
    result.set_defaults(with_builder=True)
    result.add_argument('--rollout-timeout', type=positive_seconds, default=300, metavar='SECONDS')
    return result


def run(args):
    if not args.context.strip() or args.context.startswith('-'):
        raise DeploymentError('An explicit nonempty context name is required')
    if not args.env_file.is_file():
        raise DeploymentError('Bootstrap env file is missing; create it once with scripts/configure_local.py or select --env-file')
    if args.kubeconfig is not None and not args.kubeconfig.is_file():
        raise DeploymentError('The selected kubeconfig file does not exist')
    if args.render_only is not None and (args.render_only.exists() or args.render_only.is_symlink()):
        raise DeploymentError('Render destination already exists; it was preserved')
    resources = parse_objects(kubectl(args, ['create', '--dry-run=client', '--validate=false', '-k', str(ROOT / 'k8s'), '-o', 'json'], phase='application rendering'))
    if args.with_builder:
        resources += parse_objects(kubectl(args, ['create', '--dry-run=client', '--validate=false', '-k', str(ROOT / 'k8s' / 'builder'), '-o', 'json'], phase='builder rendering'))
    secrets = parse_objects(kubectl(args, ['create', 'secret', 'generic', SECRET_NAME,
                            '--namespace', NAMESPACE, '--from-env-file', str(args.env_file),
                            '--dry-run=client', '-o', 'json'], phase='bootstrap rendering'))
    if len(secrets) != 1:
        raise DeploymentError('Expected exactly one rendered bootstrap Secret')
    manifest = prepare_manifest(resources, secrets[0], args.image,
                                pull_policy='Never' if args.local_preloaded else 'IfNotPresent')
    if args.render_only is not None:
        write_private_manifest(args.render_only, manifest)
        print(f'Private manifest written to {args.render_only}. No cluster resources were changed.')
        return manifest
    print(f'Applying Lotus and bootstrap resources to context {args.context}, namespace {NAMESPACE}.')
    kubectl(args, ['apply', '-f', '-'], phase='resource application', payload=json.dumps(manifest), timeout=120)
    print('Resources submitted. Waiting for the Lotus deployment to become ready.')
    kubectl(args, ['rollout', 'status', 'deployment/lotus', '--namespace', NAMESPACE,
                  '--timeout', f'{args.rollout_timeout}s'], phase='deployment rollout',
            timeout=args.rollout_timeout + 15, request_timeout=args.rollout_timeout + 5)
    print(f'Lotus is ready in context {args.context}, namespace {NAMESPACE}.')
    return manifest


def main(argv=None):
    arguments = parser().parse_args(argv)
    try:
        run(arguments)
    except (DeploymentError, argparse.ArgumentTypeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
