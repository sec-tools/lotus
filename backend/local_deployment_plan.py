"""Source-only readiness and adaptation scope for restricted Kubernetes labs.

This planner executes no source commands, creates no resources, reads no host
environment or credentials, and never asserts runtime equivalence. Admission
still belongs to k8s_compose_plan and the source-attesting service builder.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile

from backend.k8s_compose_plan import ComposeAdmissionError, plan_compose, read_compose_document


def _identity(value):
    value = value if isinstance(value, dict) else {}
    return {key: str(value[key])[:512] for key in (
        "target_revision", "target_tree", "target_tree_hash",
    ) if value.get(key)}


def _base(identity):
    return {"type": "local-deployment-plan", "schema_version": 1,
            "provider": "k8s-job", "status": "not-assessed",
            "scope": "Source declarations only; no runtime equivalence asserted",
            "target_identity": _identity(identity), "execution_performed": False,
            "runtime_verified": False, "capabilities": [], "coverage_gaps": [],
            "artifacts": [],
            "summary": "No captured Compose contract was selected. The existing source build and runtime checks still apply."}


def unavailable_plan(identity=None):
    """An internal inspection failure cannot look like a successful assessment."""
    state = _base(identity)
    state.update(status="review-required", summary="Local deployment requirements could not be inspected; retry with fresh source evidence.")
    state["coverage_gaps"] = [{"id": "local-deployment-inspection", "dependency": "Deployment contract",
        "reason": state["summary"], "status": "unresolved", "evidence": [],
        "remediation": "Inspect the captured deployment contract and rerun this audit. No replacement runtime was started."}]
    return state


def _select_compose(source):
    # Match the builder's precedence without its README/image heuristics or an
    # unbounded source walk. Only the selected contract creates obligations.
    from backend.lab_builder import COMPOSE_CANDIDATES, NESTED_COMPOSE_DIRS
    for directory in ("", *NESTED_COMPOSE_DIRS):
        for filename in COMPOSE_CANDIDATES:
            candidate = source / directory / filename
            if candidate.is_file() or candidate.is_symlink():
                return candidate
    return None


def inspect_local_deployment(source: Path, *, target_identity=None, request=None) -> dict:
    """Return all recognized adaptation requirements, never a runnable shim.

    Secrets/commands/environment values are deliberately absent from output.
    Unknown or unsupported syntax is retained as a coverage gap rather than
    being silently flattened into an apparently deployable subset.
    """
    source = Path(source).resolve()
    state = _base(target_identity)
    compose = _select_compose(source)
    if compose is None:
        return state
    relative = compose.relative_to(source).as_posix()
    reference = {"file": relative, "sha256": "", "pointer": ""}

    def gap(kind, dependency, reason, strategy, pointer="", affected=()):
        dependency = str(dependency)[:256]
        evidence = [{**reference, "pointer": pointer}]
        key = "deployment-" + hashlib.sha256(json.dumps([relative, kind, pointer]).encode()).hexdigest()[:20]
        state["capabilities"].append({"id": key, "dependency": dependency, "kind": kind,
            "reason": reason, "strategy": strategy, "affected_workflows": list(affected), "evidence": evidence})
        state["coverage_gaps"].append({"id": key, "dependency": dependency, "reason": reason,
            "status": "unresolved", "remediation": strategy, "evidence": evidence})

    try:
        document, raw = read_compose_document(source, compose)
    except (ValueError, OSError, UnicodeError):
        state.update(status="review-required", summary="The selected Compose contract is unreadable, outside the captured source, malformed, or exceeds inspection limits.")
        gap("contract-inspection", "Deployment contract", state["summary"],
            "Provide a bounded, flattened Compose contract within the captured source. No source values were executed or imported.")
        return state
    reference["sha256"] = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    state["artifacts"].append(dict(reference))
    try:
        admitted = plan_compose(source, compose, dict(request or {}))
    except (ComposeAdmissionError, OSError, UnicodeError, TypeError, OverflowError, ValueError):
        state.update(status="requires-adaptation", summary="The declared deployment needs an explicit local adaptation before this restricted Kubernetes lab can run it faithfully.")
    else:
        if admitted["compose_sha256"] != reference["sha256"].removeprefix("sha256:"):
            state.update(status="review-required", summary="The Compose contract changed during inspection; fresh source evidence is required.")
            gap("source-changed", "Deployment contract", state["summary"], "Capture a stable source revision and rerun the audit.")
            return state
        state.update(status="admitted", summary="The captured single-service Compose contract passed static admission. Build, readiness, and behavioral checks are still required.")
        return state

    services = document["services"]
    if len(services) > 1:
        gap("service-topology", "Application dependencies",
            "Multiple declared services need an isolated dependency topology; none may be silently omitted.",
            "Use real, pinned dependency Pods with audit-scoped DNS, readiness checks, bounded storage, and explicit network edges.",
            "/services", ("Cross-service requests", "Dependency startup and failure recovery"))
    if len(services) > 64:
        gap("inventory-limit", "Service inventory", "More than 64 services are declared; remaining services require explicit review.",
            "Split the deployment into source-bound component profiles while retaining all unassessed dependencies as gaps.", "/services")
    for index, (name, service) in enumerate(services.items()):
        if index >= 64:
            break
        prefix = "/services/" + name.replace("~", "~0").replace("/", "~1")
        if not isinstance(service, dict):
            gap("service-contract", name, "Service configuration is not a mapping.", "Correct the captured service contract.", prefix)
            continue
        mounts = service.get("volumes") or []
        env = service.get("environment") or {}
        docker_env = "DOCKER_HOST" in env if isinstance(env, dict) else any(isinstance(v, str) and v.split("=", 1)[0] == "DOCKER_HOST" for v in env) if isinstance(env, list) else False
        has_socket = any(v in json.dumps(mounts) for v in ("docker.sock", "containerd.sock", "podman.sock"))
        if has_socket or docker_env or service.get("use_api_socket"):
            gap("container-daemon", name, "This service declares a container-daemon dependency; the shared host socket is unavailable in a restricted lab.",
                "First inspect the application's native Kubernetes or remote-service backend. Qualify its exact API and lifecycle semantics in a dedicated audit boundary. A Docker API stub cannot prove child-container behavior.",
                prefix, ("Child-container creation and execution", "Image, network, volume and cleanup semantics"))
        if mounts:
            gap("storage", name, "Declared volumes need explicit ownership, initial data, permissions, and persistence semantics.",
                "Use bounded emptyDir storage for disposable data or an audit-owned PVC with a recorded seed. Host paths and daemon sockets remain unavailable.",
                prefix + "/volumes", ("Persistence", "Restart recovery", "Filesystem permissions"))
        if service.get("privileged") or service.get("devices") or service.get("cap_add") or service.get("pid") == "host" or service.get("network_mode") == "host":
            gap("host-capability", name, "The service declares host capabilities that restricted Pods do not provide.",
                "Use an application-supported unprivileged backend. If host-kernel or daemon semantics are essential, retain an incompatible-runtime gap; a stub is not equivalent.", prefix,
                ("Host-dependent behavior",))
        if service.get("ports") or service.get("expose"):
            from backend.k8s_compose_plan import _ports
            try:
                _ports(service)
            except (ValueError, TypeError):
                gap("network-ports", name, "The declared ports exceed the current single-port TCP contract or require explicit binding review.",
                    "Map each required internal protocol and port to an audit-scoped Service and verify real connectivity. Never drop ports or substitute HTTP for another protocol.", prefix,
                    ("Protocol reachability", "Data-plane access"))
        if service.get("depends_on") or service.get("healthcheck"):
            gap("dependency-readiness", name, "Dependency ordering and health semantics are declared but are not translated by the current single-service runner.",
                "Use bounded readiness conditions plus a real application operation and negative control; a Ready Pod alone does not establish dependency correctness.", prefix,
                ("Startup ordering", "Health and recovery"))
        if service.get("env_file"):
            gap("configuration", name, "External environment files need an explicit source-bound configuration contract.",
                "Record required configuration names and secret references without copying controller credentials. Validate the effective configuration inside the local lab.", prefix + "/env_file")
    # A generic obligation preserves unrecognized fields, interpolation,
    # companion overrides and build semantics even when known capabilities
    # above also explain the deployment failure. Do not expose YAML values.
    gap("contract-admission", "Complete deployment contract",
        "The complete selected Compose contract has not passed the current runtime admission rules.",
        "Review every declared field and qualify an explicit adaptation against the original behavior. Re-run source admission and fresh runtime tests; resolving one dependency does not resolve the others.")
    return state


def persist_local_deployment_plan(source: Path, plan: dict) -> Path:
    """Atomically retain a controller-produced diagnostic under audit metadata."""
    source = Path(source).resolve()
    directory = source / ".lotus"
    if directory.is_symlink():
        raise ValueError("Local deployment metadata directory cannot be a symlink")
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "local_deployment_plan.json"
    fd, temporary = tempfile.mkstemp(prefix=".deployment-plan-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(plan, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination


def main(argv=None) -> int:
    """Local preflight without starting Lotus, a cluster, or target code."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="local repository directory to inspect without execution")
    args = parser.parse_args(argv)
    if not args.source.is_dir():
        parser.error("source must be an existing local directory")
    result = inspect_local_deployment(args.source)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result["coverage_gaps"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
