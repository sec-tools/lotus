"""Controller-owned, source-bound HTTP observation of a generated lab adapter.

The target supplies response bytes only. It never supplies the observer program,
Python interpreter, HTTP client, success flag, or Kubernetes inspection address.
A short-lived loopback port-forward targets the exact registered Pod, with its
immutable identity checked before and after the request. This is a component
observation, never proof of full deployment fidelity or vulnerability coverage.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import re
import socket
import threading
import time

from backend import k8s_lab, lab
from backend.async_process import terminate_and_reap

MAX_BODY_BYTES = 65536
FORWARD_TIMEOUT = 10
HTTP_TIMEOUT = 10
MAX_FORWARD_OUTPUT = 32768
HEALTH_CATALOG_PURPOSE = "lotus-observed-local-health-v1"


def _rehydrate_recorded_candidate(source, tree, context, candidate, lab_status):
    """Restore only a built candidate's recorded citations and exact hashes."""
    from backend.lab_adapters import extend_source_context
    from backend.proof_receipts import _canonical
    refs = candidate.get("source_evidence") if isinstance(candidate, dict) else None
    if (not isinstance(refs, list) or not 1 <= len(refs) <= 64
            or any(not isinstance(name, str) for name in refs)):
        return  # Full candidate validation supplies the normal shape error.
    current = {row["file"]: row["sha256"] for row in context["files"]}
    missing = set(refs) - current.keys()
    if not missing:
        return
    artifact = _object(_object(lab_status.get("source_build")).get("adapter"))
    rows = artifact.get("source_evidence")
    if (len(missing) > 16 or artifact.get("target_tree_hash") != tree
            or artifact.get("candidate_sha256") != hashlib.sha256(_canonical(candidate)).hexdigest()
            or not isinstance(rows, list) or len(rows) > 256):
        raise ObservationUnavailable("Recorded adapter source provenance is missing or exceeds the read bound")
    recorded = {}
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"file", "sha256"}
                or not isinstance(row["file"], str) or row["file"] in recorded
                or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise ObservationUnavailable("Recorded adapter source hashes are malformed")
        recorded[row["file"]] = row["sha256"]
    if any(name not in recorded or name in current and current[name] != recorded[name] for name in refs):
        raise ObservationUnavailable("Recorded candidate citations differ from captured source")
    extend_source_context(source, tree, context, list(missing))
    current = {row["file"]: row["sha256"] for row in context["files"]}
    if any(current.get(name) != recorded[name] for name in refs):
        raise ObservationUnavailable("Retrieved candidate citations differ from their recorded hashes")


def _catalog_audit_context(repo_id):
    from backend.ai_runtime import active_audit_context
    context = active_audit_context()
    if (context is not None and context.repo_id == repo_id
            and type(context.job_id) is int and context.job_id > 0):
        return context
    return None


def _bind_health_observation(observation, candidate, context, audit_context):
    """Authenticate a controller observation, never a finding or safe-GET claim.

    An old/unbound smoke can still report its local result, but cannot authorize
    a reusable deployment request. The key is held only by the controller.
    """
    from backend.proof_receipts import _canonical, sign_blob
    if (not observation.get("ok") or observation.get("source_marker_matched") is not True
            or audit_context is None
            or _catalog_audit_context(observation["runtime"]["repo_id"]) is not audit_context[0]
            or audit_context[0].job_id != audit_context[1]):
        return
    cited = candidate.get("source_evidence")
    files = {row["file"]: row["sha256"] for row in context["files"]}
    if (not isinstance(cited, list) or not 1 <= len(cited) <= 64
            or len(set(cited)) != len(cited) or any(name not in files for name in cited)):
        return
    observation.update(scan_job_id=audit_context[1],
                       candidate_sha256=hashlib.sha256(_canonical(candidate)).hexdigest(),
                       source_evidence=[{"file": name, "sha256": files[name]} for name in cited])
    signature = sign_blob(_canonical(observation), purpose=HEALTH_CATALOG_PURPOSE)
    if signature:
        observation["catalog_signature"] = signature


class ObservationUnavailable(ValueError):
    pass


def _object(value):
    return value if isinstance(value, dict) else {}


def _digest(value):
    match = re.search(r"(?:^|@|://)(sha256:[0-9a-f]{64})$", str(value or ""))
    return match.group(1) if match else ""


def _registered_binding(repo_id, lab_status, expected):
    state = deepcopy(lab.get_lab_state(repo_id))
    status = _object(lab_status)
    source = _object(state.get("source_build"))
    receipt = _object(status.get("source_build"))
    pod = state.get("pod") or state.get("container")
    namespace = state.get("namespace")
    tree = str(_object(expected).get("target_tree_hash") or "")
    uid, image = state.get("pod_uid"), _digest(state.get("image_digest"))
    if (state.get("provider") != "k8s-job" or status.get("provider") != "k8s-job"
            or status.get("healthy") is not True or not state.get("source_embedded")
            or not isinstance(pod, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", pod)
            or namespace != k8s_lab.namespace() or not isinstance(uid, str) or not uid
            or not image or not re.fullmatch(r"sha256:[0-9a-f]{64}", tree)):
        raise ObservationUnavailable("Current registered Kubernetes runtime identity is incomplete")
    if ((status.get("pod") or status.get("container")) != pod or status.get("pod_uid") != uid
            or _digest(status.get("image_digest")) != image
            or state.get("target_tree_hash") != tree or source.get("target_tree_hash") != tree
            or receipt.get("target_tree_hash") != tree or not source.get("image")
            or receipt.get("image") != source["image"] or _digest(source["image"]) != image):
        raise ObservationUnavailable("Adapter runtime does not match the registered Pod, image and captured source")
    revision = str(_object(expected).get("target_revision") or "")
    if revision and state.get("target_revision") != revision:
        raise ObservationUnavailable("Adapter runtime revision differs from the selected audit")
    return {"repo_id": int(repo_id), "pod": pod, "namespace": namespace, "pod_uid": uid,
            "image": source["image"], "image_digest": image, "target_tree_hash": tree,
            "target_revision": revision, "lab_run_id": str(state.get("lab_run_id") or "")}


async def _inspect_exact_pod(binding):
    pod, code, _raw = await k8s_lab.get_json("pod", binding["pod"], timeout=10)
    meta, spec, status = (_object(_object(pod).get(key)) for key in ("metadata", "spec", "status"))
    containers = spec.get("containers") or []
    statuses = status.get("containerStatuses") or []
    if (code or meta.get("name") != binding["pod"] or meta.get("namespace") != binding["namespace"]
            or meta.get("uid") != binding["pod_uid"] or meta.get("deletionTimestamp")
            or _object(meta.get("labels")).get("lotus.io/repo-id") != str(binding["repo_id"])
            or _object(meta.get("annotations")).get("lotus.io/target-tree-hash") != binding["target_tree_hash"]
            or status.get("phase") != "Running" or len(containers) != 1 or len(statuses) != 1):
        raise ObservationUnavailable("The exact registered Pod is unavailable or its audit identity changed")
    container, observed = _object(containers[0]), _object(statuses[0])
    if (container.get("name") != "lab" or observed.get("name") != "lab"
            or container.get("image") != binding["image"]
            or _digest(observed.get("imageID")) != binding["image_digest"]
            or observed.get("ready") is not True or "running" not in _object(observed.get("state"))
            or not observed.get("containerID")):
        raise ObservationUnavailable("The registered application container is not running its captured image")
    if binding["target_revision"] and _object(meta.get("annotations")).get("lotus.io/target-revision") != binding["target_revision"]:
        raise ObservationUnavailable("Pod revision annotation differs from the selected audit")
    return {"pod_uid": meta["uid"], "image_digest": binding["image_digest"],
            "container_id": observed["containerID"], "restart_count": observed.get("restartCount", 0)}


async def _read_forward_output(proc, ready, remote_port, errors):
    pending, total = b"", 0
    try:
        while True:
            chunk = await proc.stdout.read(4096)
            if not chunk:
                if not ready.done():
                    ready.set_exception(ObservationUnavailable("Kubernetes port-forward exited before becoming ready"))
                return
            total += len(chunk)
            if total > MAX_FORWARD_OUTPUT:
                errors.append("Kubernetes port-forward exceeded its diagnostic output limit")
                if not ready.done():
                    ready.set_exception(ObservationUnavailable(errors[-1]))
                proc.kill()
                return
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                match = re.fullmatch(rb"Forwarding from 127\.0\.0\.1:([0-9]+) -> " + str(remote_port).encode(), line.strip())
                if match and not ready.done():
                    port = int(match.group(1))
                    if 1 <= port <= 65535:
                        ready.set_result(port)
            if len(pending) > 4096:
                raise ObservationUnavailable("Kubernetes port-forward returned an oversized diagnostic line")
    except Exception:
        errors.append("Kubernetes port-forward diagnostics could not be verified")
        if not ready.done():
            ready.set_exception(ObservationUnavailable(errors[-1]))


class _HTTPState:
    def __init__(self, local_port):
        self.connection = http.client.HTTPConnection("127.0.0.1", local_port, timeout=min(1, HTTP_TIMEOUT))
        self.socket = None
        self.response = None
        self.stopped = threading.Event()

    def stop(self):
        self.stopped.set()
        # HTTPConnection may detach its socket after a Connection: close
        # response. Keep the original socket so cancellation still interrupts
        # the response-owned buffered reader; closing its file happens in the
        # HTTP thread after the read is interrupted.
        stream = self.socket
        if stream is not None:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()


def _http_exchange(state, assertion):
    """Fixed controller HTTP client; no proxies, redirect following or target code."""
    deadline = time.monotonic() + HTTP_TIMEOUT
    connection = state.connection
    try:
        connection.connect()
        state.socket = connection.sock
        if state.stopped.is_set():
            raise ObservationUnavailable("Controller observation was interrupted")
        state.socket.settimeout(max(.001, deadline - time.monotonic()))
        if "probe" in assertion:
            from backend.adapter_local_smoke import request_path
            path = request_path(assertion)
        else:
            path = assertion["path"]
        connection.request("GET", path, headers={"Connection": "close", "Accept-Encoding": "identity"})
        response = state.response = connection.getresponse()
        lengths = response.headers.get_all("Content-Length", [])
        if len(lengths) > 1:
            raise ObservationUnavailable("Application response has ambiguous length metadata")
        expected_length = response.length
        if expected_length is not None and expected_length > MAX_BODY_BYTES:
            raise ObservationUnavailable("Application response exceeded the bounded observation limit")
        chunks, size = [], 0
        # read1 closes the response (and its detached Connection: close socket)
        # when a declared body is exhausted. Do not touch that socket again.
        while not response.isclosed():
            remaining = deadline - time.monotonic()
            if state.stopped.is_set() or remaining <= 0:
                raise TimeoutError()
            state.socket.settimeout(remaining)
            chunk = response.read1(min(4096, MAX_BODY_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                raise ObservationUnavailable("Application response exceeded the bounded observation limit")
        if expected_length is not None and size != expected_length:
            raise ObservationUnavailable("Application response ended before its declared body was complete")
        body = b"".join(chunks)
    finally:
        if state.response is not None:
            state.response.close()
        connection.close()
    if "probe" in assertion:
        from backend.adapter_local_smoke import version_result
        matched = version_result(response.status, body)
        return {"ok": matched, "status_code": response.status, "expected_status_code": 200,
                "response_bytes": len(body), "response_sha256": hashlib.sha256(body).hexdigest(),
                "protocol_probe": assertion["probe"], "protocol_result_matched": matched,
                "reason": "Controller observed the expected read-only version result" if matched else
                          "Application did not return the bounded matching version result"}
    matched = assertion["body_contains"].encode("utf-8") in body
    expected_status = response.status == assertion["status_code"]
    return {"ok": expected_status and matched, "status_code": response.status,
            "expected_status_code": assertion["status_code"], "response_bytes": len(body),
            "response_sha256": hashlib.sha256(body).hexdigest(), "source_marker_matched": matched,
            "reason": "Controller observed the expected application response" if expected_status and matched else
                      "Application HTTP status did not match the captured assertion" if not expected_status else
                      "Captured application response marker was absent"}


async def _observe_http(local_port, assertion):
    state = _HTTPState(local_port)
    task = asyncio.create_task(asyncio.to_thread(_http_exchange, state, assertion))
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=HTTP_TIMEOUT)
    finally:
        state.stop()
        if not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=2)
            except (Exception, asyncio.CancelledError):
                task.add_done_callback(lambda result: result.exception() if not result.cancelled() else None)


async def observe_adapter(repo_id, source, candidate, lab_status, expected_identity, send):
    """Return a smoke-compatible controller observation and always reap forwarding."""
    from backend.lab_adapters import source_context, validate_candidate
    from backend.proof_receipts import content_tree_digest
    started = datetime.now(timezone.utc).isoformat()
    result = {"ran": False, "ok": False, "exit_code": None, "output": "", "observer": "lotus-controller-http-v1"}
    proc, reader, ready = None, None, None
    try:
        candidate = deepcopy(candidate)
        active = _catalog_audit_context(repo_id)
        audit_context = (active, active.job_id) if active is not None else None
        binding = _registered_binding(repo_id, lab_status, expected_identity)
        context = await asyncio.to_thread(source_context, Path(source), binding["target_tree_hash"])
        # Planning can already have read additional indexed source. Restore only
        # those recorded citations under the existing16-file retrieval bound;
        # validation below still rejects malformed, unknown or missing paths.
        await asyncio.to_thread(_rehydrate_recorded_candidate, Path(source), binding["target_tree_hash"],
                                context, candidate, lab_status)
        admitted = validate_candidate(candidate, context)
        if admitted["profile"] != "native-service":
            raise ObservationUnavailable("Adapter does not have an executable native component contract")
        before = await _inspect_exact_pod(binding)
        await send(repo_id, "Checking the captured application from the controller through its exact Kubernetes Pod", level="info")
        # Let kubectl select an ephemeral loopback port; no free-port reservation
        # race or service selector can redirect this observation to another Pod.
        spawn = asyncio.create_task(asyncio.create_subprocess_exec(
            k8s_lab.kubectl_binary(), *k8s_lab._context_args(), "port-forward", "--address=127.0.0.1",
            "--pod-running-timeout=10s", "-n", binding["namespace"], "pod/" + binding["pod"],
            ":" + str(admitted["port"]), stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT))
        try:
            proc = await asyncio.shield(spawn)
        except asyncio.CancelledError:
            proc = await asyncio.shield(spawn)
            raise
        ready = asyncio.get_running_loop().create_future()
        errors = []
        reader = asyncio.create_task(_read_forward_output(proc, ready, admitted["port"], errors))
        local_port = await asyncio.wait_for(ready, timeout=FORWARD_TIMEOUT)
        if proc.returncode is not None or errors:
            raise ObservationUnavailable("Kubernetes port-forward was not available for observation")
        result["ran"] = True
        observation = await _observe_http(local_port, admitted["smoke_test"])
        after = await _inspect_exact_pod(binding)
        if (_registered_binding(repo_id, lab_status, expected_identity) != binding or before != after
                or await asyncio.to_thread(content_tree_digest, Path(source)) != binding["target_tree_hash"]):
            raise ObservationUnavailable("Pod, registered runtime or captured source changed during observation")
        if proc.returncode is not None or errors:
            raise ObservationUnavailable("Kubernetes port-forward ended before identity verification completed")
        assertion = admitted["smoke_test"]
        if "probe" in assertion:
            from backend.adapter_local_smoke import request_path
            observed_path = request_path(assertion)
            assertion_metadata = {"protocol_probe": assertion["probe"]}
            assertion_summary = "version assertion " + ("matched" if observation["protocol_result_matched"] else "failed")
        else:
            observed_path = assertion["path"]
            assertion_metadata = {"source_marker_sha256": hashlib.sha256(assertion["body_contains"].encode()).hexdigest()}
            assertion_summary = "source marker " + ("matched" if observation["source_marker_matched"] else "absent")
        observation.update({"schema_version": 1, "observer": "lotus-controller-http-v1",
            "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
            "runtime": {**binding, **after}, "request": {"method": "GET", "path": observed_path, "port": admitted["port"]},
            **assertion_metadata,
            "evidence_role": "component-observation", "full_deployment_verified": False})
        _bind_health_observation(observation, candidate, context, audit_context)
        result.update(ok=observation["ok"], exit_code=0 if observation["ok"] else 1,
                      reason=observation["reason"], observation=observation,
                      command="Controller GET " + observed_path,
                      output=f"HTTP {observation['status_code']}; {observation['response_bytes']} bytes; {assertion_summary}")
    except (asyncio.TimeoutError, TimeoutError):
        result["reason"] = "Controller application observation timed out; no success was recorded"
    except Exception as error:
        result["reason"] = str(error) if isinstance(error, ObservationUnavailable) else "Controller could not verify the captured application observation"
    finally:
        if reader is not None:
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
        if proc is not None:
            await terminate_and_reap(proc)
        if ready is not None and ready.done() and not ready.cancelled():
            ready.exception()  # consume startup errors even when cancellation won
    await send(repo_id, "Controller application check: " + ("passed" if result["ok"] else result.get("reason", "unavailable")),
               level="success" if result["ok"] else "warning")
    return result
