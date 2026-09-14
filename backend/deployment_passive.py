"""Passive public-index collection in an owned disposable container or pod.

Only CT and Wayback are queried. Returned names are inventory, never targets
for requests, DNS enumeration, finding checks, or vulnerability execution.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid

from backend.async_process import terminate_and_reap


PASSIVE_SCRIPT = r'''
import json, re, sys
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

domains = json.loads(sys.argv[1])
opener = build_opener(NoRedirect)
hosts, sources = {}, []
valid_host = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')

def add(value, source, domain):
    host = str(value or '').strip().lower().rstrip('.')
    if host.startswith('*.'):
        host = host[2:]
    if not valid_host.fullmatch(host) or not (host == domain or host.endswith('.' + domain)):
        return
    if len(hosts) < 1000 or host in hosts:
        hosts.setdefault(host, set()).add(source)

for domain in domains:
    for source, url in (
        ('crt.sh', 'https://crt.sh/?q=%25.' + quote(domain, safe='') + '&output=json'),
        ('wayback-cdx', 'https://web.archive.org/cdx/search/cdx?url=*.' + quote(domain, safe='') + '/*&output=json&fl=original&collapse=urlkey&filter=statuscode:200&limit=1000'),
    ):
        record = {'source': source, 'domain': domain, 'status': 'failed', 'records': 0}
        try:
            request = Request(url, headers={'User-Agent': 'Lotus-Passive-Identity/2', 'Accept': 'application/json', 'Accept-Encoding': 'identity'})
            with opener.open(request, timeout=12) as response:
                raw = response.read(2000001)
                if len(raw) > 2000000:
                    raise ValueError('public source response exceeded byte limit')
            rows = json.loads(raw.decode('utf-8'))
            if not isinstance(rows, list):
                raise ValueError('public source did not return a list')
            for row in rows[:5000]:
                if source == 'crt.sh' and isinstance(row, dict):
                    for name in str(row.get('name_value') or '').splitlines()[:100]:
                        add(name, source, domain)
                elif source == 'wayback-cdx' and isinstance(row, list) and row:
                    add(urlsplit(str(row[0])).hostname, source, domain)
            record.update(status='completed', records=min(len(rows), 5000))
        except Exception as exc:
            record['error'] = str(exc)[:200]
        sources.append(record)
ok = sum(record['status'] == 'completed' for record in sources)
print(json.dumps({'schema_version': 2, 'status': 'completed' if ok == len(sources) else 'partial' if ok else 'failed',
 'domains': domains, 'hosts': [{'host': name, 'sources': sorted(values)} for name, values in sorted(hosts.items())],
 'sources': sources, 'source_policy': ['crt.sh', 'wayback-cdx'], 'active_target_requests': 0,
 'host_limit': 1000, 'result_type': 'deployment-observation', 'findings_created': 0}, sort_keys=True))
'''


async def _command(args, *, timeout=30, input_data=None, limit=3_000_000):
    """Cap process output and always retire the child on timeout/cancellation."""
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *args, stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )

        async def read(stream, maximum):
            pieces, size = [], 0
            while True:
                piece = await stream.read(16384)
                if not piece:
                    return b"".join(pieces).decode("utf-8", "replace")
                size += len(piece)
                if size > maximum:
                    raise RuntimeError("isolated recon output exceeded its byte limit")
                pieces.append(piece)

        async def exchange():
            if input_data is not None:
                process.stdin.write(input_data)
                await process.stdin.drain()
                process.stdin.close()
            stdout, stderr = await asyncio.gather(read(process.stdout, limit), read(process.stderr, 65536))
            await process.wait()
            return stdout, int(process.returncode or 0), stderr

        return await asyncio.wait_for(exchange(), timeout=timeout)
    finally:
        await terminate_and_reap(process)


def _pod_manifest(name, owner, namespace, domains, timeout):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": {"app.kubernetes.io/managed-by": "lotus", "lotus.io/purpose": "passive-identity", "lotus.io/owner": owner}},
        "spec": {"restartPolicy": "Never", "activeDeadlineSeconds": timeout,
                 "automountServiceAccountToken": False, "hostNetwork": False,
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [{"name": "passive-identity", "image": os.environ.get("LOTUS_DEPLOYMENT_RECON_IMAGE", "python:3.12-alpine"),
                                 "command": ["python3", "-c", PASSIVE_SCRIPT, json.dumps(domains)],
                                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                     "capabilities": {"drop": ["ALL"]}},
                                 "resources": {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}},
                                 "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}]}],
                 "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}}]},
    }


def _validated_result(text, domains):
    from backend.deployment_recon import validate_domain

    parsed = json.loads(text)
    if not isinstance(parsed, dict) or parsed.get("schema_version") != 2:
        raise ValueError("isolated recon returned an invalid result document")
    hosts = {}
    for row in (parsed.get("hosts") or [])[:1000]:
        if not isinstance(row, dict):
            continue
        try:
            host = validate_domain(row.get("host"))
        except (ValueError, TypeError):
            continue
        if not any(host == domain or host.endswith("." + domain) for domain in domains):
            continue
        allowed = {str(source) for source in row.get("sources", []) if source in {"crt.sh", "wayback-cdx"}}
        if allowed:
            hosts.setdefault(host, set()).update(allowed)
    parsed.update(domains=domains, hosts=[{"host": host, "sources": sorted(sources)} for host, sources in sorted(hosts.items())],
                  result_type="deployment-observation", findings_created=0, active_target_requests=0)
    if parsed.get("status") not in {"completed", "partial", "failed"}:
        raise ValueError("isolated recon returned an invalid completion status")
    return parsed


async def collect_passive(domains, *, run_id, timeout=180):
    timeout = max(30, min(int(timeout), 300))
    owner = uuid.uuid4().hex
    name = f"lotus-deploy-recon-{int(run_id)}-{owner[:10]}"
    from backend.lab_provider import provider_name, _allow_fallback, _strict
    try:
        primary = provider_name()
        override = str(os.environ.get("LOTUS_DEPLOYMENT_RECON_PROVIDER") or "").strip().lower()
        provider = primary
        if override in {"k8s", "k8s-job", "kubernetes", "job"}:
            provider = "k8s-job"
        elif override in {"docker", "local"}:
            if primary != "docker" and (_strict() or not _allow_fallback()):
                raise ValueError("Docker passive backup requires explicit provider fallback opt-in with Kubernetes strict mode off")
            provider = "docker"
        elif override:
            raise ValueError("Unknown passive recon provider; choose k8s-job or an explicitly permitted Docker backup")
    except ValueError as exc:
        return {"status": "blocked", "runner": "none", "hosts": [], "reason": str(exc),
                "result_type": "deployment-observation", "findings_created": 0}
    started = time.monotonic()
    guard = None
    cleanup_errors = []
    result = None
    k8s = provider == "k8s-job"
    namespace, prefix = "", []
    if k8s:
        from backend import k8s_lab
        namespace = k8s_lab.namespace()
        prefix = [k8s_lab.kubectl_binary(), *k8s_lab._context_args(), "-n", namespace]
    elif provider != "docker":
        return {"status": "blocked", "runner": "none", "hosts": [], "reason": "isolated passive recon provider is unavailable",
                "result_type": "deployment-observation", "findings_created": 0}
    try:
        if k8s:
            from backend import k8s_network_guard
            doc = _pod_manifest(name, owner, namespace, domains, timeout)
            guard = await k8s_network_guard.prepare(doc, profile="public")
            doc = guard.manifest
            _, rc, error = await _command([*prefix, "create", "-f", "-"], input_data=json.dumps(doc).encode())
            if rc:
                raise RuntimeError(error or "could not create isolated recon pod")
            await guard.release()
            deadline = time.monotonic() + timeout
            while True:
                text, rc, error = await _command([*prefix, "get", "pod", name, "-o", "json"])
                pod = json.loads(text) if not rc else {}
                if ((pod.get("metadata") or {}).get("labels") or {}).get("lotus.io/owner") != owner:
                    raise RuntimeError("isolated pod ownership could not be verified")
                phase = (pod.get("status") or {}).get("phase")
                if phase in {"Succeeded", "Failed"}:
                    text, rc, error = await _command([*prefix, "logs", name, "--limit-bytes=3000000"])
                    if phase != "Succeeded" or rc:
                        raise RuntimeError(error or "isolated recon pod failed")
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("isolated recon pod exceeded its time budget")
                await asyncio.sleep(.5)
        else:
            args = ["docker", "run", "--name", name, "--label", "lotus.passive-owner=" + owner,
                    "--network", "bridge", "--read-only", "--user", "10001:10001", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                    "--memory", "256m", "--cpus", "0.5", "--pids-limit", "64",
                    os.environ.get("LOTUS_DEPLOYMENT_RECON_IMAGE", "python:3.12-alpine"),
                    "python3", "-c", PASSIVE_SCRIPT, json.dumps(domains)]
            text, rc, error = await _command(args, timeout=timeout)
            if rc:
                raise RuntimeError(error or f"isolated recon container exited {rc}")
        result = _validated_result(text, domains)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        result = {"status": "blocked", "hosts": [], "reason": str(exc)[:500], "result_type": "deployment-observation", "findings_created": 0}
    finally:
        try:
            if k8s:
                from backend import k8s_network_guard
                if guard is not None:
                    # The observation is finished. UID-bound cleanup drains
                    # its Pod even when one temporary control cleanup fails.
                    guard.released = False
                await k8s_network_guard.close(guard)
            else:
                text, rc, _ = await _command(["docker", "inspect", "--format", '{{index .Config.Labels "lotus.passive-owner"}}', name], timeout=10)
                if rc == 0 and text.strip() == owner:
                    _, rc, error = await _command(["docker", "rm", "-f", name], timeout=10)
                    if rc:
                        cleanup_errors.append(error or "owned recon container cleanup failed")
        except Exception as exc:
            cleanup_errors.append(str(exc)[:200])
    result.update(runner="k8s-recon-pod" if k8s else "docker-recon-pod", pod_name=name, namespace=namespace,
                  duration_ms=int((time.monotonic() - started) * 1000), cleanup_errors=cleanup_errors)
    if cleanup_errors:
        result["status"] = "failed"
    return result
