"""Pluggable lab backends.

Docker remains the explicit single-user fallback.  Kubernetes is the preferred
network deployment: one restricted Job + ClusterIP Service per audit, with
readiness, pod/image identity attestation, and idempotent teardown.  The
provider contract is shared by the pipeline and interactive PoC controls.
"""
from __future__ import annotations

import os
import asyncio
import sys
import shutil
import json
import logging
from pathlib import Path
from typing import Any, Dict, Protocol

_TEMPLATE = Path(__file__).resolve().parent.parent / "k8s" / "lab-job-template.yaml"


_K8S_ALIASES = ("k8s", "k8s-job", "kubernetes", "job")
_DOCKER_ALIASES = ("docker", "local")


def _explicit_runtime() -> str:
    """The operator's explicit runtime choice, if any.

    ``LOTUS_RUNTIME`` is the unified knob; ``LOTUS_LAB_PROVIDER`` remains a
    backward-compatible alias.  An empty string means "not set" -> auto-select.
    """
    for name in ("LOTUS_RUNTIME", "LOTUS_LAB_PROVIDER"):
        value = str(os.environ.get(name) or "").strip().lower()
        if value:
            return value
    return ""


def provider_name() -> str:
    """Select Kubernetes by default; Docker requires an explicit choice.

    Missing Kubernetes prerequisites must remain visible instead of silently
    moving execution to a host daemon. LOTUS_RUNTIME takes precedence over
    the backward-compatible LOTUS_LAB_PROVIDER setting.
    """
    raw = _explicit_runtime()
    if raw in _K8S_ALIASES:
        return "k8s-job"
    if raw in _DOCKER_ALIASES:
        return "docker"
    if raw:
        raise ValueError("Unknown lab runtime; choose k8s-job or explicitly select docker")
    return "k8s-job"


def _strict() -> bool:
    return (os.environ.get("LOTUS_LAB_PROVIDER_STRICT") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _allow_fallback() -> bool:
    return (os.environ.get("LOTUS_ALLOW_PROVIDER_FALLBACK") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


class LabProvider(Protocol):
    name: str

    async def start(
        self,
        repo_id: int,
        dest: Path,
        language: str,
        send,
        app_type: str = "unknown",
    ) -> Dict[str, Any]:
        ...


class DockerLabProvider:
    name = "docker"

    async def start(
        self,
        repo_id: int,
        dest: Path,
        language: str,
        send,
        app_type: str = "unknown",
    ) -> Dict[str, Any]:
        from backend.lab import run_lab, get_lab_state, register_lab_container
        result = await run_lab(repo_id, dest, language, send, app_type=app_type)
        result.setdefault("provider", self.name)
        if result.get("healthy"):
            state = get_lab_state(repo_id)
            # Retain original identity even when this layout cannot be replayed
            # from a capsule. Report reads must never borrow the latest lab.
            if state.get("lab_run_id") and state.get("container") and (
                    not result.get("container") or result["container"] == state["container"]):
                result.update({key: state[key] for key in ("lab_run_id", "container", "target_tree_hash", "target_revision") if state.get(key)})
                try:
                    from backend.notebook_lab import capture_docker_runtime
                    identity = await capture_docker_runtime(repo_id, {"lab_run_id": state["lab_run_id"]},
                        {"tree_hash": state.get("target_tree_hash"), "revision": state.get("target_revision")}, state["container"])
                    if get_lab_state(repo_id) != state:
                        raise ValueError("Docker lab registration changed during identity capture; the replacement was not updated.")
                    fields = {key: identity[key] for key in ("container_id", "container_started_at", "image_digest",
                                                             "container_init_start_ticks", "container_boot_id")}
                    register_lab_container(repo_id, state["container"], **fields)
                    result.update(fields)
                except (ValueError, OSError) as exc:
                    result["notebook_identity_gap"] = str(exc)[:500]
        return result


async def _start_docker_fallback(repo_id, dest, language, send, app_type="unknown"):
    """A remote-Pod admission must not bypass a fallback local build's floor."""
    from backend.pipeline import lab_build_admission
    admission = lab_build_admission(dest, runtime="docker")
    if admission:
        reason = "Explicit Docker fallback was not admitted: " + admission["reason"]
        await send(repo_id, reason, level="warning")
        return {"status": "deferred-resource", "healthy": False, "url": None,
                "provider": "docker", "reason": reason, "resource_admission": admission}
    return await DockerLabProvider().start(repo_id, dest, language, send, app_type=app_type)


class K8sJobLabProvider:
    """Run an isolated, target-bound Kubernetes Job and Service."""

    name = "k8s-job"

    async def start(
        self,
        repo_id: int,
        dest: Path,
        language: str,
        send,
        app_type: str = "unknown",
    ) -> Dict[str, Any]:
        if str(os.environ.get("LOTUS_DISABLE_LAB") or "").strip().lower() in {"1", "true", "yes", "on"}:
            message = "Lab validation is disabled by LOTUS_DISABLE_LAB; no Kubernetes or Docker runtime was started"
            await send(repo_id, message, level="warning")
            return {"status": "disabled", "healthy": False, "url": None, "logs": message, "provider": self.name}
        from backend import k8s_lab
        request = k8s_lab._load_request(Path(dest))
        # Workspace JSON is not controller attestation. Only the verified
        # service-image builder below may assert embedded source or suppress
        # the normal source/bootstrap command in favor of an image entrypoint.
        for key in ("source_embedded", "use_image_entrypoint", "source_build", "runtime_user", "runtime_environment"):
            request.pop(key, None)
        # A provider invocation without a persisted lab request is an old API
        # call (or a workspace that was deleted).  Do not manufacture a Job
        # from defaults; this keeps proof freshness fail-closed and preserves
        # the explicit local Docker break-glass behavior.
        if not request and not os.environ.get("LOTUS_K8S_LAB_IMAGE"):
            msg = "Kubernetes lab request is missing from the enrolled workspace"
            if _allow_fallback() and not _strict():
                await send(repo_id, msg + "; using explicit local Docker break-glass", level="warning")
                try:
                    from backend.pipeline import note_degraded
                    note_degraded(repo_id, "lab-provider", "Lab", msg, state="skipped", extra={"provider": self.name, "fallback": "docker"})
                except Exception:
                    pass
                result = await _start_docker_fallback(repo_id, dest, language, send, app_type=app_type)
                # Keep the attested provider truthful: this run executed in
                # Docker.  ``requested_provider`` records why the break-glass
                # path was selected without making reports claim Kubernetes.
                result.setdefault("requested_provider", self.name)
                result["provider_fallback"] = "docker"
                return result
            await send(repo_id, msg + "; scan remains candidate-only", level="warning")
            try:
                from backend.pipeline import note_degraded
                note_degraded(repo_id, "lab-provider", "Lab", msg, state="skipped", extra={"provider": self.name})
            except Exception:
                pass
            return {"status": "unavailable", "healthy": False, "url": None, "logs": msg, "provider": self.name}
        if not shutil.which(k8s_lab.kubectl_binary()):
            msg = f"Kubernetes lab unavailable: {k8s_lab.kubectl_binary()} is not installed"
            if _allow_fallback() and not _strict():
                await send(repo_id, msg + "; using explicit local Docker break-glass", level="warning")
                try:
                    from backend.pipeline import note_degraded
                    note_degraded(repo_id, "lab-provider", "Lab", msg, state="skipped", extra={"provider": self.name, "fallback": "docker"})
                except Exception:
                    pass
                result = await _start_docker_fallback(repo_id, dest, language, send, app_type=app_type)
                result.setdefault("requested_provider", self.name)
                result["provider_fallback"] = "docker"
                return result
            await send(repo_id, msg + "; scan remains candidate-only", level="warning")
            try:
                from backend.pipeline import note_degraded
                note_degraded(repo_id, "lab-provider", "Lab", msg, state="skipped", extra={"provider": self.name, "fallback_allowed": _allow_fallback()})
            except Exception:
                pass
            return {"status": "unavailable", "healthy": False, "url": None, "logs": msg, "provider": self.name}

        available, diagnostic = await k8s_lab.cluster_available()
        if not available:
            msg = f"Kubernetes lab unavailable: cluster is not reachable ({diagnostic[-500:]})"
            if _allow_fallback() and not _strict():
                await send(repo_id, msg + "; using explicit local Docker break-glass", level="warning")
                try:
                    from backend.pipeline import note_degraded
                    note_degraded(repo_id, "lab-provider", "Lab", msg, state="skipped", extra={"provider": self.name, "fallback": "docker"})
                except Exception:
                    pass
                result = await _start_docker_fallback(repo_id, dest, language, send, app_type=app_type)
                result.setdefault("requested_provider", self.name)
                result["provider_fallback"] = "docker"
                return result
            await send(repo_id, msg + "; scan remains candidate-only", level="warning")
            try:
                from backend.pipeline import note_degraded
                note_degraded(repo_id, "lab-provider", "Lab", msg, state="skipped", extra={"provider": self.name, "diagnostic": diagnostic[-1000:]})
            except Exception:
                pass
            return {"status": "unavailable", "healthy": False, "url": None, "logs": msg, "provider": self.name}

        # Every audit has its own Pod/Service address; large database IDs must
        # never turn a valid application port into an invalid TCP port.
        if "port" not in request:
            request["port"] = 3000
            request["port_source"] = "default"
        request.setdefault("app_type", app_type)
        try:
            if not request.get("image") and not os.environ.get("LOTUS_K8S_LAB_IMAGE"):
                from backend.k8s_service_builder import prepare_service_request
                request = await prepare_service_request(repo_id, dest, request, send)
            manifest = k8s_lab.build_manifest(repo_id, request, app_type=app_type)
            job = next(row for row in manifest["items"] if row.get("kind") == "Job")
            if job["spec"]["template"]["spec"].get("initContainers") or request.get("install_steps"):
                raise ValueError("Direct network-bootstrap labs are unsupported: build a source-embedded image first. Final lab Pods require isolation before repository code starts.")
        except Exception as exc:
            from copy import deepcopy
            from backend.lab_adapters import AdapterUnavailable
            # Workspace source_build was stripped above. Only the builder's
            # returned request or typed failure may carry adapter provenance.
            source_build = deepcopy(request.get("source_build") or {})
            if isinstance(exc, AdapterUnavailable):
                if exc.source_build is not None:
                    source_build = deepcopy(exc.source_build)
                elif exc.artifact is not None:
                    source_build = {"strategy": "ai-native-adapter", "runtime": self.name,
                                    "target_tree_hash": request.get("target_tree_hash"),
                                    "adapter": deepcopy(exc.artifact)}
            adapter = source_build.get("adapter")
            if isinstance(adapter, dict):
                if adapter.get("status") not in {"blocked", "build-failed", "planning-failed", "runtime-failed"}:
                    adapter.update(status="runtime-failed", failure={"stage": "manifest-admission",
                                   "error_type": type(exc).__name__[:80], "detail_id": f"{repo_id}-local-lab-adapter"},
                                   reason=f"Native adapter manifest admission failed ({type(exc).__name__[:80]}); inspect its task diagnostic")
                adapter.update(runtime_verified=False, full_deployment_verified=False)
                diagnostic = str(adapter.get("reason") or "See the adapter task diagnostic")
                msg = "Local lab unavailable for this repository; runtime coverage remains incomplete. View task details."
            else:
                diagnostic = str(exc)
                msg = f"Kubernetes lab request rejected: {diagnostic[:500]}"
            logging.getLogger(__name__).warning("Audit %s local lab admission: %s", repo_id, diagnostic)
            await send(repo_id, msg, level="warning",
                **({"detail_id": f"{repo_id}-local-lab-adapter", "detail": adapter} if isinstance(adapter, dict) else {}))
            try:
                from backend.pipeline import note_degraded
                note_degraded(repo_id, "lab-provider", "Lab", msg, state="failed",
                              extra={"provider": self.name, "diagnostic": diagnostic})
            except Exception:
                pass
            return {"status": "rejected", "healthy": False, "url": None, "logs": diagnostic, "reason": diagnostic, "provider": self.name,
                    **({"source_build": source_build, "image": source_build.get("image") or request.get("image") or ""}
                       if source_build else {})}

        meta = manifest.get("_meta") or {}
        bootstrap_name = ""
        from backend import k8s_network_guard
        guard = None
        lab_started = False
        response = None
        service_uid = None
        service_attempted = False
        async def cleanup_failed_start():
            errors = []
            if guard is not None:
                guard.released = False
                try:
                    await k8s_network_guard.close(guard)
                except Exception as exc:
                    errors.append(str(exc)[:500])
            if service_attempted:
                try:
                    observed = await k8s_network_guard._read(meta["namespace"], "Service", meta["service_name"])
                    if observed is not None:
                        metadata = observed.get("metadata", {})
                        if metadata.get("labels", {}).get(k8s_network_guard.OWNER) != guard.owner or (service_uid and metadata.get("uid") != service_uid):
                            raise k8s_network_guard.NetworkIsolationUnavailable("Lab Service cleanup refused a replacement owner or UID")
                        await k8s_network_guard._delete(meta["namespace"], "Service", meta["service_name"], metadata["uid"])
                except Exception as exc:
                    errors.append(str(exc)[:500])
            complete = not errors
            reason = "; ".join(errors)
            fields = {"namespace": str(meta.get("namespace") or k8s_lab.namespace()),
                      "job_name": meta.get("job_name"), "service_name": meta.get("service_name"),
                      "bootstrap_policy_name": bootstrap_name, "cleanup_complete": complete}
            if not complete:
                fields["cleanup_gap"] = reason + "; verify retained resource ownership before maintenance cleanup"
                await send(repo_id, "Lab startup cleanup incomplete: " + fields["cleanup_gap"], level="warning",
                           detail_id=f"{repo_id}-lab-cleanup",
                           detail={"kind": "lab-cleanup", "status": "blocked", "repo_id": repo_id, **fields})
            return fields
        try:
            guard = await k8s_network_guard.prepare(job, profile="isolated")
            manifest["items"] = [guard.manifest if item.get("kind") == "Job" else item for item in manifest["items"]]
            for item in manifest["items"]:
                if item.get("kind") == "Service":
                    item["metadata"].setdefault("labels", {})[k8s_network_guard.OWNER] = guard.owner
            await send(repo_id, f"Applying Kubernetes lab Job {meta.get('job_name')} (namespace {meta.get('namespace')})", level="info")
            service_attempted = True
            output, rc = await k8s_lab.apply(manifest, timeout=60)
            if rc != 0:
                msg = f"Kubernetes lab Job apply failed: {output[-1500:]}"
                await send(repo_id, msg, level="error")
                try:
                    from backend.pipeline import note_degraded
                    note_degraded(repo_id, "lab-provider", "Lab", msg, state="failed", extra={"provider": self.name, "job": meta.get("job_name")})
                except Exception:
                    pass
                response = {"source_build": request.get("source_build") or {}, "status": "apply-failed", "healthy": False, "url": None, "logs": msg, "reason": msg, "provider": self.name, "job_name": meta.get("job_name"), "service_name": meta.get("service_name"), }
                return response

            observed_service = await k8s_network_guard._read(meta["namespace"], "Service", meta["service_name"])
            if not observed_service or observed_service.get("metadata", {}).get("labels", {}).get(k8s_network_guard.OWNER) != guard.owner:
                raise k8s_network_guard.NetworkIsolationUnavailable("Created lab Service ownership is unavailable")
            service_uid = observed_service["metadata"]["uid"]
            isolation = await guard.release()
            wait = await k8s_lab.wait_ready(meta["job_name"], timeout=int(os.environ.get("LOTUS_K8S_WAIT_TIMEOUT", "900")))
            pod = wait.get("pod") if isinstance(wait, dict) else {}
            if not wait.get("healthy"):
                reason = str(wait.get("reason") or wait.get("status") or "pod did not become ready")
                await send(repo_id, f"Kubernetes lab Job not ready: {reason}", level="warning")
                response = {"source_build": request.get("source_build") or {}, "status": wait.get("status") or "unhealthy", "healthy": False, "url": None, "logs": str(wait.get("raw") or "")[-2000:], "reason": reason, "provider": self.name, "job_name": meta.get("job_name"), "service_name": meta.get("service_name"), "pod": (pod.get("metadata") or {}).get("name") if isinstance(pod, dict) else None, }
                return response

            pod_meta = pod.get("metadata") or {}
            pod_name = str(pod_meta.get("name") or "")
            pod_uid = str(pod_meta.get("uid") or "")
            image_digest = k8s_lab.image_digest(pod)
            if not pod_uid or not image_digest:
                msg = "Kubernetes lab pod has no immutable Pod UID/image digest; proof remains candidate-only"
                await send(repo_id, msg, level="error")
                response = {"source_build": request.get("source_build") or {}, "status": "attestation-unavailable", "healthy": False, "url": None, "logs": msg, "reason": msg, "provider": self.name, "job_name": meta.get("job_name"), "service_name": meta.get("service_name"), }
                return response
            from backend import lab
            owner = next((row for row in pod_meta.get("ownerReferences") or []
                          if row.get("kind") == "Job" and row.get("controller") is True
                          and row.get("name") == meta.get("job_name")), {})
            if pod_uid != isolation["pod_uid"] or owner.get("uid") != isolation["workload_uid"]:
                raise k8s_network_guard.NetworkIsolationUnavailable("The ready lab Pod cannot inherit another Pod's network admission")
            container_status = next((row for row in (pod.get("status") or {}).get("containerStatuses") or []
                                     if row.get("name") == "lab"), {})
            identity = {"lab_run_id": f"k8s:{meta.get('job_name')}:{pod_uid}",
                        "namespace": meta.get("namespace"), "pod_uid": pod_uid, "job_uid": str(owner.get("uid") or ""),
                        "image_digest": image_digest, "container_id": str(container_status.get("containerID") or ""),
                        "container_started_at": str((container_status.get("state") or {}).get("running", {}).get("startedAt") or "")}
            lab.register_lab_container(
                repo_id, pod_name, provider=self.name, lab_kind="k8s-job",
                job_name=meta.get("job_name"), service_name=meta.get("service_name"),
                port=meta.get("port"),
                url=f"http://{meta.get('service_name')}.{meta.get('namespace')}.svc.cluster.local:{meta.get('port')}",
                bootstrap_policy_name=bootstrap_name,
                network_admission=isolation,
                **identity,
                target_revision=str(request.get("target_revision") or ""),
                target_tree_hash=str(request.get("target_tree_hash") or ""),
                source_build=request.get("source_build") or {},
                source_embedded=bool(request.get("source_embedded")),
                dest=str(dest), labels=meta.get("labels") or {},
            )
            url = f"http://{meta.get('service_name')}.{meta.get('namespace')}.svc.cluster.local:{meta.get('port')}"
            await send(repo_id, f"Kubernetes lab pod {pod_name} is Ready at {url}", level="success")
            lab_started = True
            return {
                "status": "running", "healthy": True, "url": url,
                "host": meta.get("service_name"), "port": meta.get("port"),
                "provider": self.name, "lab_kind": "k8s-job", "job_name": meta.get("job_name"),
                "source_build": request.get("source_build") or {}, "source_embedded": bool(request.get("source_embedded")),
                "service_name": meta.get("service_name"), "pod": pod_name,
                **identity, "network_admission": isolation, "logs": output[-500:], "image": request.get("image") or os.environ.get("LOTUS_K8S_LAB_IMAGE") or "",
            }
        except k8s_network_guard.WorkloadAdmissionUnavailable as exc:
            code = exc.code if exc.code in k8s_network_guard.WorkloadAdmissionUnavailable.MESSAGES else "scheduling-unavailable"
            message = k8s_network_guard.WorkloadAdmissionUnavailable.MESSAGES[code]
            await send(repo_id, message, level="warning", detail_id=f"{repo_id}-lab-admission",
                       detail={"type": "lab-admission", "status": "blocked", "code": code,
                               "reason": message, "repository_command_released": False})
            response = {"status": "deferred-resource", "healthy": False, "url": None,
                        "provider": self.name, "logs": message, "reason": message,
                        "source_build": request.get("source_build") or {}, "image": request.get("image") or ""}
            return response
        except k8s_network_guard.NetworkIsolationUnavailable as exc:
            message = "Local lab network isolation is unavailable; no lab proof was authorized. " + str(exc)
            await send(repo_id, message, level="warning", detail_id=f"{repo_id}-network-isolation",
                       detail={"type": "network-isolation", "status": "blocked", "reason": str(exc),
                               "remedy": "Use an enforcing CNI and a source-embedded final lab image; rerun the task after correcting cluster setup."})
            response = {"status": "isolation-blocked", "healthy": False, "url": None, "provider": self.name, "logs": message, "reason": message,
                    "source_build": request.get("source_build") or {}, "image": request.get("image") or ""}
            return response
        finally:
            original = sys.exc_info()[1]
            if guard is not None and not lab_started:
                cleanup_task = asyncio.create_task(cleanup_failed_start())
                try:
                    cleanup_result = await asyncio.shield(cleanup_task)
                except asyncio.CancelledError:
                    cleanup_result = await cleanup_task
                    if original is None:
                        raise
                if response is not None:
                    response.update(cleanup_result)
                if original is not None and not cleanup_result.get("cleanup_complete"):
                    original.cleanup_gap = cleanup_result.get("cleanup_gap")
            else:
                await k8s_network_guard.close(guard)


def get_lab_provider() -> LabProvider:
    if provider_name() == "k8s-job":
        return K8sJobLabProvider()
    return DockerLabProvider()
