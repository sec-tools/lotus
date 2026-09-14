"""Deployment profile: single-user laptop vs team/enterprise.

LOTUS_DEPLOY_PROFILE selects safety defaults. Explicit DATABASE_URL /
LOTUS_AUTH_TOKEN still win. This module refuses silent foot-guns
(SQLite + multiple workers, enterprise without Postgres or a token)
unless LOTUS_ALLOW_UNSAFE_DEPLOY=1.
"""
from __future__ import annotations

import os
import json
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

VALID_PROFILES = ("single", "team", "enterprise")
_PROBE_LOCK = threading.Lock()
_PROBE_CACHE = {}
_K8S_PERMISSIONS = {
    ("batch", "jobs"): ("create", "get", "list", "patch", "delete"),
    ("", "services"): ("create", "get", "patch", "delete"),
    ("", "pods"): ("create", "get", "list", "delete"),
    ("", "pods/log"): ("get",),
    ("", "pods/exec"): ("create", "get"),
    ("", "pods/portforward"): ("create", "get"),
    ("networking.k8s.io", "networkpolicies"): ("create", "get", "list", "patch", "delete"),
}


def _env(*names: str, default: str = "") -> str:
    for name in names:
        raw = os.environ.get(name)
        if raw is not None and str(raw).strip() != "":
            return str(raw).strip()
    return default


def current_profile() -> str:
    raw = _env("LOTUS_DEPLOY_PROFILE", "LOTUS_PROFILE", "LOTUS_ENV", default="single").lower()
    if raw in ("solo", "local", "dev", "laptop"):
        return "single"
    if raw in ("org", "cluster", "k8s", "prod", "production"):
        return "enterprise"
    if raw in ("small-team", "shared"):
        return "team"
    if raw in VALID_PROFILES:
        return raw
    return "single"


def database_url() -> str:
    return _env("DATABASE_URL", default="sqlite:///./data/lotus.db")


def is_sqlite(url: Optional[str] = None) -> bool:
    return (url or database_url()).startswith("sqlite")


def auth_token() -> str:
    return _env("LOTUS_AUTH_TOKEN", "LOTUS_API_TOKEN", "LOTUS_API_KEY", default="")


def worker_count() -> int:
    raw = _env("WEB_CONCURRENCY", "LOTUS_GUNICORN_WORKERS", default="1")
    try:
        return max(1, int(raw))
    except ValueError:
        return 1


def allow_unsafe() -> bool:
    return _env("LOTUS_ALLOW_UNSAFE_DEPLOY", default="").lower() in ("1", "true", "yes", "on")


def _enabled(name):
    return _env(name).lower() in {"1", "true", "yes", "on"}


def lab_provider_required() -> bool:
    """Legacy REQUIRE_DOCKER now refers to the explicitly selected provider."""
    if "LOTUS_REQUIRE_LAB_PROVIDER" in os.environ:
        return _enabled("LOTUS_REQUIRE_LAB_PROVIDER")
    return _enabled("LOTUS_REQUIRE_DOCKER")


def _probe_command(args, *, input_data=None):
    # Readiness never invokes a shell, creates workloads, or returns raw CLI
    # output (which can contain credential-bearing control-plane addresses).
    return subprocess.run(args, input=input_data, capture_output=True, text=True, timeout=2)


def _missing_permissions(rules):
    def permits(rule, group, resource, verb):
        if not isinstance(rule, dict) or rule.get("resourceNames"):
            return False
        if not all(isinstance(rule.get(key), list) for key in ("apiGroups", "resources", "verbs")):
            return False
        resources = {"*", resource}
        if "/" in resource:
            resources.add(resource.split("/", 1)[0] + "/*")
        return (any(value in {"*", group} for value in rule["apiGroups"])
                and any(value in resources for value in rule["resources"])
                and any(value in {"*", verb} for value in rule["verbs"]))

    missing = []
    for (group, resource), verbs in _K8S_PERMISSIONS.items():
        for verb in verbs:
            allowed = any(permits(rule, group, resource, verb) for rule in rules)
            if not allowed:
                missing.append(f"{verb} {resource}" + (f".{group}" if group else ""))
    return missing


def _probe_lab_provider(info):
    result = {**info, "checks": dict(info["checks"]), "warnings": list(info["warnings"])}
    if result["status"] != "not-probed":
        return result
    result["probed"] = True
    try:
        if result["provider"] == "docker":
            response = _probe_command([result["binary"], "info", "--format", "{{json .ServerVersion}}"])
            if response.returncode or not response.stdout.strip():
                result.update(status="daemon-unavailable", message="Selected Docker backup daemon is unavailable; check its endpoint and socket permissions.")
                return result
            result["checks"]["daemon"] = True
        else:
            prefix = [result["binary"], *(["--context", result["context"]] if result["context"] else []), "--request-timeout=2s"]
            response = _probe_command([*prefix, "version", "--output=json"])
            version = json.loads(response.stdout) if response.returncode == 0 else {}
            if not isinstance(version, dict) or not version.get("serverVersion"):
                result.update(status="cluster-unavailable", message="Kubernetes API is unreachable or credentials/context are invalid; check the configured kubectl context or service account.")
                return result
            result["checks"]["cluster"] = True
            namespace = result["namespace"]
            response = _probe_command([*prefix, "get", "namespace", namespace, "-o", "json"])
            if response.returncode:
                diagnostic = (response.stdout + response.stderr).replace(" ", "").lower()
                if "forbidden" in diagnostic:
                    result["warnings"].append("Namespace existence cannot be read by this service account; per-audit admission still verifies it.")
                else:
                    result.update(status="namespace-unavailable", message="Configured Kubernetes namespace is missing or unavailable; check namespace provisioning and access.")
                    return result
            else:
                document = json.loads(response.stdout)
                if document.get("metadata", {}).get("name") != namespace or document.get("status", {}).get("phase") != "Active":
                    result.update(status="namespace-unavailable", message="Configured Kubernetes namespace is not active.")
                    return result
                result["checks"]["namespace"] = True
            # Authorization review is non-persisted and creates no workload.
            review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": {"namespace": namespace}}
            response = _probe_command([*prefix, "create", "--raw=/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "-f", "-"], input_data=json.dumps(review))
            document = json.loads(response.stdout) if response.returncode == 0 else {}
            status = document.get("status", {}) if isinstance(document, dict) else {}
            rules = status.get("resourceRules")
            if not isinstance(rules, list):
                result.update(status="rbac-unverified", message="Kubernetes permissions could not be verified; allow a namespace-scoped self subject rules review.")
                return result
            missing = _missing_permissions(rules)
            if missing:
                result.update(status="rbac-unverified" if status.get("incomplete") else "rbac-denied", missing_permissions=missing,
                              message="Kubernetes lab permissions are incomplete; inspect missing_permissions for the configured namespace.")
                return result
            result["checks"]["rbac"] = True
        result.update(available=True, status="available", message="Configured provider control plane is available; each audit still validates its source, image, runtime readiness and isolation.")
    except subprocess.TimeoutExpired:
        result.update(status="timeout", message="Configured provider readiness check timed out; no alternate runtime was invoked.")
    except (OSError, ValueError, TypeError, AttributeError):
        result.update(status="probe-failed", message="Configured provider returned an invalid or unavailable readiness response; no alternate runtime was invoked.")
    return result


def lab_runtime_status(*, probe=False):
    """Report selected-provider prerequisites without substituting Docker.

    Global readiness does not claim a target image was pulled, a source was
    replayed, or NetworkPolicy is enforced. Those remain per-audit checks.
    """
    from backend import k8s_lab
    from backend.lab_provider import provider_name, _allow_fallback, _strict
    try:
        provider = provider_name()
    except ValueError:
        return {"provider": "invalid", "available": False, "status": "invalid-provider", "probed": False, "checks": {}, "warnings": [],
                "fallback_enabled": False, "message": "Unknown lab runtime; choose k8s-job or explicitly select docker."}
    info = {"provider": provider, "available": False, "status": "not-probed", "probed": False,
            "checks": {"cli": False}, "warnings": [], "fallback_enabled": _allow_fallback() and not _strict(),
            "strict": _strict(), "scope": "selected lab control plane and lab-namespace permissions",
            "per_audit_checks": ["approved target image", "source identity", "pod readiness", "network isolation",
                                 "builder namespace/RBAC, storage and registry when an image must be built"],
            "message": "Provider has not been probed; per-audit runtime checks remain required."}
    if _enabled("LOTUS_DISABLE_LAB"):
        return {**info, "status": "disabled", "message": "Lab validation is disabled by LOTUS_DISABLE_LAB."}
    binary = k8s_lab.kubectl_binary() if provider == "k8s-job" else "docker"
    info["binary"] = shutil.which(binary) or ""
    info["checks"]["cli"] = bool(info["binary"])
    if not info["binary"]:
        return {**info, "status": "cli-missing", "message": "Configured Kubernetes provider requires kubectl; Docker is not required." if provider == "k8s-job" else "Explicit Docker backup requires the Docker CLI and access to its daemon."}
    if provider == "k8s-job":
        namespace = _env("LOTUS_K8S_NAMESPACE", default="lotus")
        info.update(namespace=namespace, context=_env("LOTUS_K8S_CONTEXT"))
        info["checks"].update(cluster=False, namespace=False, rbac=False)
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", namespace):
            return {**info, "status": "invalid-namespace", "message": "LOTUS_K8S_NAMESPACE must be a valid Kubernetes namespace name."}
        image = _env("LOTUS_K8S_LAB_IMAGE")
        info["default_image_configured"] = bool(image)
        if image and (any(character.isspace() for character in image)
                      or (not k8s_lab._immutable_image_ref(image) and not k8s_lab._allow_unpinned_image())):
            return {**info, "status": "invalid-image", "message": "Configured Kubernetes lab image must be pinned by digest; per-audit images must also satisfy the image policy."}
        if not image:
            info["warnings"].append("No global Kubernetes lab image is configured; audits without an explicit image build a source-bound service image per audit.")
    if not probe:
        return info
    # Short-lived cache prevents public readiness polling from repeatedly
    # spawning clients. Include configuration and file changes so a repaired
    # kubeconfig is rechecked without requiring an API restart.
    files = []
    for value in (_env("KUBECONFIG") or str(Path.home() / ".kube" / "config")).split(os.pathsep):
        try:
            metadata = Path(value).stat()
            files.append((value, metadata.st_mtime_ns, metadata.st_size))
        except OSError:
            files.append((value, None, None))
    key = (json.dumps(info, sort_keys=True), tuple(files), _env("DOCKER_HOST"), _env("DOCKER_CONTEXT"))
    with _PROBE_LOCK:
        cached = _PROBE_CACHE.get(key)
        if cached and time.monotonic() - cached[0] < 10:
            return json.loads(json.dumps(cached[1]))
        result = _probe_lab_provider(info)
        _PROBE_CACHE.clear()
        _PROBE_CACHE[key] = (time.monotonic(), result)
        return json.loads(json.dumps(result))


def inspect_runtime() -> Dict[str, Any]:
    profile = current_profile()
    url = database_url()
    sqlite = is_sqlite(url)
    token = bool(auth_token())
    workers = worker_count()
    docker_cli = bool(shutil.which("docker"))
    lab_disabled = _env("LOTUS_DISABLE_LAB", default="").lower() in ("1", "true", "yes", "on")
    host_socket_allowed = _env("LOTUS_ALLOW_HOST_DOCKER_SOCKET", default="").lower() in ("1", "true", "yes", "on")
    proof_key_configured = len(_env("LOTUS_PROOF_SIGNING_KEY", default="")) >= 32
    runtime = lab_runtime_status()
    lab_provider = runtime["provider"]
    warnings: list = []
    blockers: list = []
    if lab_provider == "invalid":
        blockers.append(runtime["message"])
    raw_profile = _env("LOTUS_DEPLOY_PROFILE", "LOTUS_PROFILE", "LOTUS_ENV", default="single").lower()
    known_profiles = set(VALID_PROFILES) | {"solo", "local", "dev", "laptop", "org", "cluster", "k8s", "prod", "production", "small-team", "shared"}
    if raw_profile not in known_profiles:
        blockers.append("Unknown deployment profile; choose single, team, or enterprise.")
    scheme = url.split(":", 1)[0].lower().split("+", 1)[0]
    if scheme not in {"sqlite", "postgresql", "postgres"}:
        blockers.append("Unsupported database scheme; configure SQLite or Postgres.")
    raw_workers = _env("WEB_CONCURRENCY", "LOTUS_GUNICORN_WORKERS", default="1")
    try:
        if int(raw_workers) < 1:
            raise ValueError()
    except ValueError:
        blockers.append("WEB_CONCURRENCY/workers must be a positive integer.")
    if sqlite and workers > 1:
        blockers.append(
            "SQLite is the database but WEB_CONCURRENCY/workers > 1. "
            "Use docker-compose.single.yml (1 worker) or Postgres."
        )
    if profile in ("team", "enterprise") and sqlite:
        blockers.append(f"{profile} profile requires Postgres (set DATABASE_URL).")
    if profile == "enterprise" and not token:
        blockers.append(
            "enterprise profile requires LOTUS_AUTH_TOKEN "
            "(or LOTUS_ALLOW_UNSAFE_DEPLOY=1 for a break-glass start)."
        )
    if profile in ("team",) and not token:
        blockers.append(
            "team profile requires LOTUS_AUTH_TOKEN. Any client that can reach the API "
            "has full control without it (use LOTUS_ALLOW_UNSAFE_DEPLOY=1 only as break-glass)."
        )
    if profile in ("team", "enterprise") and not proof_key_configured:
        blockers.append(
            "shared profiles require LOTUS_PROOF_SIGNING_KEY (at least 32 characters) "
            "so lab evidence cannot be forged."
        )
    if (profile in ("team", "enterprise") and not lab_disabled
            and (lab_provider == "docker" or runtime.get("fallback_enabled")) and not host_socket_allowed):
        blockers.append(
            "shared profiles cannot access the host Docker socket by default. Configure an isolated lab runner "
            "(LOTUS_LAB_PROVIDER=k8s-job) or explicitly acknowledge the host boundary with "
            "LOTUS_ALLOW_HOST_DOCKER_SOCKET=1."
        )
    if not proof_key_configured:
        warnings.append(
            "LOTUS_PROOF_SIGNING_KEY is not configured; dynamic output remains candidate-only "
            "until signed lab receipts can be issued."
        )
    if profile == "single" and not sqlite:
        warnings.append("single profile with Postgres is fine; WAL pragmas apply only to SQLite.")
    if not docker_cli and not lab_disabled and lab_provider == "docker":
        warnings.append(
            "docker CLI not on PATH. Labs cannot be built; scans stay candidate-only. "
            "Install Docker or set LOTUS_DISABLE_LAB=1."
        )
    if lab_provider == "k8s-job":
        warnings.append(
            "LOTUS_LAB_PROVIDER=k8s-job uses dynamically rendered target-bound Jobs. "
            "Docker is not required. Missing Kubernetes CLI, cluster/RBAC, approved image, or pod readiness "
            "keeps runtime evidence unavailable. Docker backup requires explicit fallback opt-in and strict mode off."
        )
        if runtime["status"] not in {"not-probed", "disabled"}:
            warnings.append(runtime["message"])
        warnings.extend(runtime["warnings"])
    return {
        "profile": profile,
        "database": "sqlite" if sqlite else "postgres" if scheme in {"postgres", "postgresql"} else "unsupported",
        "database_url_scheme": url.split(":", 1)[0],
        "auth_required": token,
        "auth_enabled": token,
        "proof_attestation_configured": proof_key_configured,
        "workers": workers,
        "docker_cli": docker_cli,
        "lab_disabled": lab_disabled,
        "lab_provider": lab_provider,
        "lab_runtime": runtime,
        "lab_provider_required": lab_provider_required(),
        "host_docker_socket_allowed": host_socket_allowed,
        "allow_unsafe": allow_unsafe(),
        "warnings": warnings,
        "blockers": blockers,
        "ok": not blockers,
    }


def log_startup(log_fn) -> Dict[str, Any]:
    info = inspect_runtime()
    log_fn(
        f"Deploy profile={info['profile']} db={info['database']} "
        f"auth={'on' if info['auth_enabled'] else 'off'} workers={info['workers']} "
        f"lab_provider={info['lab_provider']} "
        f"provider_cli={'yes' if info['lab_runtime']['checks'].get('cli') else 'no'} "
        f"docker_backup={'enabled' if info['lab_runtime'].get('fallback_enabled') else 'disabled'}",
        "info",
    )
    for w in info["warnings"]:
        log_fn(w, "warn")
    for b in info["blockers"]:
        log_fn(f"DEPLOY BLOCKER: {b}", "error")
    return info


def enforce_or_die(log_fn) -> Dict[str, Any]:
    """Abort process start when the active profile is unsafe.

    Tests and laptops with SQLite + 1 worker pass. Enterprise without
    Postgres/token, or SQLite with multiple workers, raise RuntimeError
    unless LOTUS_ALLOW_UNSAFE_DEPLOY=1.
    """
    info = log_startup(log_fn)
    if info["ok"]:
        return info
    if allow_unsafe():
        log_fn("LOTUS_ALLOW_UNSAFE_DEPLOY=1: starting despite blockers", "warn")
        return info
    raise RuntimeError("Deploy blocked: " + "; ".join(info["blockers"]))
