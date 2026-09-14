"""Fail-closed reset cleanup from this database's exact durable runtime records.

Never discover cleanup candidates by repository labels or name prefixes. A
historical name is only an inspection address; Docker deletion uses immutable
IDs after run/source labels are checked. Incomplete ownership retains records.
"""
from datetime import datetime
import asyncio
import json
import re


def _doc(value):
    if isinstance(value, dict):
        return value
    try:
        result = json.loads(value or "{}")
        return result if isinstance(result, dict) else {}
    except (TypeError, ValueError):
        return {}


def assert_no_other_work(db, *, local_scan_ids=(), local_harness_ids=(), local_deployment_ids=()):
    """Task leases detect active other owners, not otherwise idle replicas."""
    from backend.main import ScanLease, ScanJob, HarnessRun, DeploymentReconRun
    from sqlalchemy.orm import load_only
    now = datetime.utcnow()
    for lease in db.query(ScanLease):
        if lease.repo_id not in local_scan_ids:
            raise RuntimeError(f"Scan lease for audit {lease.job_id} is not owned by this reset process; stop other instances and reconcile leases first")
    for model, local_ids, label, active in (
        (ScanJob, (), "audit", {"running", "paused"}),
        (HarnessRun, local_harness_ids, "Auto run", {"running"}),
        (DeploymentReconRun, local_deployment_ids, "deployment operation", {"queued", "running"}),
    ):
        fields = [model.id, model.status, model.lease_owner, model.lease_expires_at]
        if model is ScanJob:
            fields.append(model.repo_id)
        # Owner checks need only these small fields. Loading every historical
        # output here can consume gigabytes before reset has even begun.
        for row in db.query(model).options(load_only(*fields)).yield_per(100):
            local = row.repo_id in local_scan_ids if model is ScanJob else row.id in local_ids
            live = bool(row.lease_owner and row.lease_expires_at and row.lease_expires_at > now)
            if not local and (live or (row.status in active and row.lease_owner)):
                raise RuntimeError(f"Active {label} {row.id} is not owned by this reset process; stop other instances and reconcile its durable owner first")


def _records(db, registry, *, repo_id=None, scan_job_id=None):
    from backend.main import ScanJob
    records = []
    # Legacy ownership may need one full output, but never preload the entire
    # audit history in the reset controller's memory.
    jobs = db.query(ScanJob).yield_per(1)
    if repo_id is not None:
        jobs = jobs.filter(ScanJob.repo_id == int(repo_id))
    if scan_job_id is not None:
        jobs = jobs.filter(ScanJob.id == int(scan_job_id))
    for job in jobs:
        output = _doc(job.output)
        raw = _doc(job.runtime_cleanup_json) or _doc(output.get("lab_status"))
        if not raw:
            continue
        state = {**_doc(raw.get("state")), **raw}
        identity = _doc(output.get("target_identity"))
        state["target_tree_hash"] = state.get("target_tree_hash") or identity.get("target_tree_hash")
        state["lab_run_id"] = state.get("lab_run_id") or _doc(raw.get("runtime_capsule")).get("lab_run_id")
        runtime = any(state.get(key) for key in ("container", "pod", "job_name", "net_name", "service_name"))
        if runtime or raw.get("healthy"):
            if identity.get("target_tree_hash") and state.get("target_tree_hash") != identity["target_tree_hash"]:
                raise RuntimeError(f"Audit {job.id} runtime/source identities conflict; ownership recovery is required before reset")
            records.append({**state, "repo_id": job.repo_id, "scan_job_id": job.id})
    for repo_id, state in registry.items():
        if not any(state.get(key) for key in ("container", "pod", "job_name", "net_name", "service_name")):
            continue
        matches = [record for record in records if record["repo_id"] == repo_id
                   and state.get("lab_run_id") and record.get("lab_run_id") == state.get("lab_run_id")
                   and state.get("target_tree_hash") and record.get("target_tree_hash") == state.get("target_tree_hash")]
        if not matches:
            raise RuntimeError(f"Registered lab for repository {repo_id} has no matching durable audit run/source identity; resolve its ownership before reset")
        # Runtime inventory may have been hydrated by Dashboard after restart.
        # It is never an authority to replace the database's recorded name/ID.
        for key in ("container", "pod", "job_name", "service_name", "net_name", "pod_uid", "container_id"):
            if state.get(key) and matches[-1].get(key) and state[key] != matches[-1][key]:
                raise RuntimeError(f"Registered lab identity conflicts with audit {matches[-1]['scan_job_id']}; reset refused")
    return records


async def _docker_inspect(kind, value):
    from backend import lab
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,200}", value):
        raise RuntimeError("Invalid durable Docker runtime inspection identity")
    args = ["docker", *(["network"] if kind == "network" else []), "inspect", value]
    output, rc = await lab._run_cmd(args, timeout=15)
    if rc:
        if any(message in output.lower() for message in ("no such object", "no such container", "no such network", "network " + value.lower() + " not found")):
            return None
        raise RuntimeError("Runtime ownership inspection failed: " + str(output)[-300:])
    try:
        rows = json.loads(output)
        if len(rows) != 1 or not isinstance(rows[0], dict) or not re.fullmatch(r"[0-9a-f]{64}", rows[0].get("Id", "")):
            raise ValueError()
        return rows[0]
    except (TypeError, ValueError, KeyError):
        raise RuntimeError("Docker returned incomplete immutable runtime identity")


def _check_labels(labels, record, *, source=True):
    expected = {"lotus.audit.repo_id": str(record["repo_id"]), "lotus.audit.run_id": record.get("lab_run_id")}
    if source:
        expected["lotus.audit.target_tree_hash"] = record.get("target_tree_hash")
    if not record.get("lab_run_id") or not record.get("target_tree_hash") or any(not value or labels.get(key) != value for key, value in expected.items()):
        raise RuntimeError(f"Runtime name is not owned by audit {record['scan_job_id']} with the recorded run/source identity; no resources were selected for deletion")


async def plan_cleanup(db, registry, *, repo_id=None, scan_job_id=None, include_source_volumes=True):
    """Preflight every candidate before any deletion, without runtime listing."""
    containers, networks, kubernetes = {}, {}, []
    for record in _records(db, registry, repo_id=repo_id, scan_job_id=scan_job_id):
        if record.get("provider") == "k8s-job" or record.get("lab_kind") == "k8s-job":
            if _doc(record.get("cleanup_identity")).get("schema_version") == 1:
                kubernetes.append(await _plan_k8s_cleanup(record))
                continue
            # Legacy lab records lack Service/NetworkPolicy UIDs. Name deletion
            # cannot safely close that gap across instances or object reuse.
            from backend import k8s_lab
            if record.get("namespace") and record["namespace"] != k8s_lab.namespace():
                raise RuntimeError("Historical Kubernetes runtime belongs to another namespace; reset cannot attest its cleanup")
            addresses = [("pod", record.get("pod") or record.get("container")), ("job", record.get("job_name")),
                         ("service", record.get("service_name"))]
            if record.get("job_name"):
                addresses.append(("networkpolicy", record["job_name"] + "-bootstrap"))
            if not any(name for _, name in addresses):
                raise RuntimeError("Historical Kubernetes lab lacks exact runtime addresses; ownership recovery is required before reset")
            for kind, name in addresses:
                if not name:
                    continue
                doc, rc, raw = await k8s_lab.get_json(kind, name, timeout=15)
                if rc and "notfound" in str(raw).lower().replace(" ", ""):
                    continue
                if rc:
                    raise RuntimeError("Historical Kubernetes ownership inspection failed: " + str(raw)[-200:])
                if doc:
                    raise RuntimeError(f"Historical Kubernetes {kind} {name} still exists; complete UID-bound runtime cleanup before reset (rows retained)")
            continue
        name = record.get("container_id") or record.get("container")
        network = record.get("network_id") or record.get("net_name")
        if not name and not network:
            raise RuntimeError(f"Audit {record['scan_job_id']} records a lab without exact cleanup identities; resolve ownership before reset")
        container = await _docker_inspect("container", name) if name else None
        net = await _docker_inspect("network", network) if network else None
        if record.get("lab_kind") == "compose" or record.get("compose_project"):
            raise RuntimeError(f"Audit {record['scan_job_id']} used Compose without a complete immutable resource inventory; resolve owned project cleanup before reset")
        if container:
            _check_labels(_doc(container.get("Config")).get("Labels") or {}, record)
            expected_id = record.get("container_id")
            if expected_id and container["Id"] != expected_id:
                raise RuntimeError("Container immutable identity changed; reset refused")
            if any(mount.get("Type") in {"volume", "bind"} for mount in container.get("Mounts", [])):
                raise RuntimeError("Lab has unrecorded persistent mounts; resolve ownership before reset")
            attached = _doc(_doc(container.get("NetworkSettings")).get("Networks"))
            attached_ids = {entry.get("NetworkID") for entry in attached.values() if isinstance(entry, dict)}
            if attached_ids and (not net or attached_ids != {net["Id"]}):
                raise RuntimeError("Lab has networks outside its exact durable cleanup identity")
            containers[container["Id"]] = record
        if net:
            _check_labels(net.get("Labels") or {}, record, source=False)
            attached = set((net.get("Containers") or {}).keys())
            if attached - ({container["Id"]} if container else set()):
                raise RuntimeError("Recorded lab network has unrelated attached containers; reset refused")
            networks[net["Id"]] = record
    from backend.source_volume_ownership import list_source_receipts, preflight_source_cleanup
    sources = []
    if include_source_volumes:
        for receipt in list_source_receipts():
            sources.append(await preflight_source_cleanup(receipt))
    return {"containers": containers, "networks": networks, "kubernetes": kubernetes,
            **({"source_volumes": sources} if sources else {})}


async def apply_cleanup(plan, registry, *, assert_owner=None):
    """Reattest immutable IDs, then remove only those IDs (never names)."""
    from backend import lab
    for record in plan.get("kubernetes", []):
        if assert_owner:
            assert_owner()
        await _apply_k8s_cleanup(record, assert_owner=assert_owner)
    from backend.source_volume_ownership import cleanup_owned_source
    for receipt in plan.get("source_volumes", []):
        await cleanup_owned_source(receipt)
    for kind, rows in (("container", plan["containers"]), ("network", plan["networks"])):
        for identity, record in rows.items():
            current = await _docker_inspect(kind, identity)
            if current is None:
                continue
            labels = current.get("Labels") if kind == "network" else _doc(current.get("Config")).get("Labels")
            _check_labels(labels or {}, record, source=kind == "container")
            if kind == "network" and current.get("Containers"):
                raise RuntimeError("Runtime network still has attachments; reset cleanup stopped")
            command = ["docker", "rm", "-f", identity] if kind == "container" else ["docker", "network", "rm", identity]
            if assert_owner:
                assert_owner()
            output, rc = await lab._run_cmd(command, timeout=30)
            if rc:
                raise RuntimeError("Immutable runtime cleanup failed: " + str(output)[-300:])
    for repo_id in list(registry):
        lab._AUDIT_SLUGS.pop(repo_id, None)
        registry.pop(repo_id, None)


_K8S_PATHS = {"job": ("/apis/batch/v1", "jobs"), "pod": ("/api/v1", "pods"),
              "service": ("/api/v1", "services"), "networkpolicy": ("/apis/networking.k8s.io/v1", "networkpolicies"),
              "configmap": ("/api/v1", "configmaps"),
              "persistentvolumeclaim": ("/api/v1", "persistentvolumeclaims")}


async def delete_k8s_uid(kind, name, namespace, uid):
    """Atomic API UID precondition; a reused name can never delete a new object."""
    from backend import k8s_lab
    if kind not in _K8S_PATHS or not all(isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,252}", value) for value in (name, namespace, uid)):
        raise RuntimeError("Invalid immutable Kubernetes cleanup identity")
    prefix, plural = _K8S_PATHS[kind]
    path = f"{prefix}/namespaces/{namespace}/{plural}/{name}"
    body = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid},
            "propagationPolicy": "Foreground", "gracePeriodSeconds": 1}
    output, rc = await k8s_lab._run(["delete", "--raw=" + path, "-f", "-"], input_data=json.dumps(body).encode(), timeout=20)
    if rc and "notfound" not in output.lower().replace(" ", ""):
        raise RuntimeError("Kubernetes UID-precondition cleanup refused: " + output[-400:])


async def _k8s_read(kind, name):
    from backend import k8s_lab
    if kind not in _K8S_PATHS or not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", name):
        raise RuntimeError("Invalid durable Kubernetes resource address")
    doc, rc, raw = await k8s_lab.get_json(kind, name, timeout=15)
    if rc and "notfound" in str(raw).lower().replace(" ", ""):
        return None
    if rc or not isinstance(doc, dict) or not _doc(doc.get("metadata")).get("uid"):
        raise RuntimeError("Kubernetes immutable ownership inspection unavailable: " + str(raw)[-200:])
    return doc


def _recorded_guard_owner(record):
    """Legacy selectors may add only their already recorded admission owner."""
    owner = _doc(record.get("labels")).get("lotus.io/network-owner")
    admission = _doc(record.get("network_admission"))
    if (not isinstance(owner, str) or not re.fullmatch(r"[0-9a-f]{32}", owner)
            or admission.get("status") != "verified" or admission.get("profile") != "isolated"
            or not record.get("pod_uid") or not record.get("job_uid")
            or admission.get("pod_uid") != record["pod_uid"]
            or admission.get("workload_uid") != record["job_uid"]):
        return None
    return owner


def _check_recorded_guard_owner(doc, kind, record):
    owner = _recorded_guard_owner(record)
    if owner and kind in {"job", "pod"}:
        meta = _doc(doc.get("metadata"))
        expected_uid = record["job_uid" if kind == "job" else "pod_uid"]
        if meta.get("uid") != expected_uid or _doc(meta.get("labels")).get("lotus.io/network-owner") != owner:
            raise RuntimeError("Kubernetes workload differs from its recorded network admission owner")


def _k8s_service_selector_matches(doc, expected, record):
    selector = _doc(_doc(doc.get("spec")).get("selector"))
    if selector == expected:
        return True
    owner = _recorded_guard_owner(record)
    return bool(owner and selector == {**expected, "lotus.io/network-owner": owner}
                and _doc(_doc(doc.get("metadata")).get("labels")).get("lotus.io/network-owner") == owner)


def _check_k8s_object(doc, kind, record):
    meta = _doc(doc.get("metadata"))
    labels = _doc(meta.get("labels"))
    expected = {"role": "lab-container", "lotus.io/repo-id": str(record["repo_id"]), "lotus.io/job": record["job_name"]}
    if any(labels.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Kubernetes object does not belong to the exact recorded audit job")
    if kind in {"job", "pod"} and _doc(meta.get("annotations")).get("lotus.io/target-tree-hash") != record.get("target_tree_hash"):
        raise RuntimeError("Kubernetes runtime source identity differs from the selected audit")
    _check_recorded_guard_owner(doc, kind, record)
    if kind == "service" and not _k8s_service_selector_matches(doc, expected, record):
        raise RuntimeError("Kubernetes Service selector no longer selects the exact audit job")


async def capture_k8s_cleanup(record):
    """Read only the provider-created names while their original UIDs exist."""
    from backend import k8s_lab
    if record.get("namespace") != k8s_lab.namespace() or not record.get("pod_uid") or not record.get("target_tree_hash"):
        raise RuntimeError("Kubernetes cleanup requires exact namespace, Pod UID, and source identity")
    resources = []
    for kind, name in (("job", record["job_name"]), ("pod", record.get("pod") or record["container"]),
                       ("service", record["service_name"]), ("networkpolicy", record["job_name"] + "-bootstrap")):
        doc = await _k8s_read(kind, name)
        if not doc:
            if kind != "networkpolicy":
                raise RuntimeError("Created Kubernetes runtime disappeared before cleanup ownership was recorded")
            resources.append({"kind": kind, "name": name, "uid": None})
            continue
        _check_k8s_object(doc, kind, record)
        uid = doc["metadata"]["uid"]
        if kind == "pod":
            job_uid = resources[0]["uid"]
            if uid != record["pod_uid"] or not any(owner.get("uid") == job_uid and owner.get("kind") == "Job" and owner.get("name") == record["job_name"] for owner in doc["metadata"].get("ownerReferences", [])):
                raise RuntimeError("Kubernetes Pod UID/owner changed before cleanup capture")
        resources.append({"kind": kind, "name": name, "uid": uid})
    return {"schema_version": 1, "provider": "k8s-job", "namespace": record["namespace"],
            "context_args": k8s_lab._context_args(), "resources": resources}


async def _plan_k8s_cleanup(record):
    from backend import k8s_lab
    identity = record["cleanup_identity"]
    if not all(record.get(key) for key in ("lab_run_id", "target_tree_hash", "pod_uid")):
        raise RuntimeError("Kubernetes cleanup record lacks its audit run/source/Pod identity")
    if identity.get("namespace") != k8s_lab.namespace() or identity.get("context_args") != k8s_lab._context_args():
        raise RuntimeError("Kubernetes cleanup context/namespace differs from the recorded provider; use its maintenance context")
    resources = identity.get("resources") or []
    expected = {("job", record.get("job_name")), ("pod", record.get("pod") or record.get("container")),
                ("service", record.get("service_name")), ("networkpolicy", str(record.get("job_name")) + "-bootstrap")}
    if len(resources) != 4 or {(row.get("kind"), row.get("name")) for row in resources} != expected:
        raise RuntimeError("Kubernetes cleanup record does not contain the exact complete runtime inventory")
    for row in resources:
        doc = await _k8s_read(row["kind"], row["name"])
        if not doc:
            continue
        if doc["metadata"]["uid"] != row.get("uid"):
            raise RuntimeError("Kubernetes runtime name was reused by another UID; reset refused")
        _check_k8s_object(doc, row["kind"], record)
    return record


async def _apply_k8s_cleanup(record, *, assert_owner=None):
    await _plan_k8s_cleanup(record)
    identity = record["cleanup_identity"]
    for resource in identity["resources"]:
        if resource.get("uid"):
            if assert_owner:
                assert_owner()
            await delete_k8s_uid(resource["kind"], resource["name"], identity["namespace"], resource["uid"])
    # API acknowledgement is not completion (finalizers/Pod shutdown may lag).
    deadline = asyncio.get_running_loop().time() + 30
    while True:
        remaining = []
        for resource in identity["resources"]:
            doc = await _k8s_read(resource["kind"], resource["name"])
            if doc:
                if doc["metadata"]["uid"] != resource.get("uid"):
                    raise RuntimeError("Kubernetes name was reused during reset; replacement retained")
                remaining.append(resource)
        if not remaining:
            return
        if asyncio.get_running_loop().time() >= deadline:
            raise RuntimeError("Kubernetes runtime deletion has not completed; wait for finalizers/shutdown before retrying reset")
        await asyncio.sleep(.25)


async def checkpoint_runtime(repo_id, job_id, result, db_factory, job_cls):
    """Persist provider completion independently of mutable progress/output JSON."""
    from backend import lab
    returned = result if isinstance(result, dict) else {}
    # A prebuild refusal created no runtime. The per-repository registry can
    # still describe an earlier audit; do not attribute that runtime to this one.
    if not any(returned.get(key) for key in ("container", "pod", "job_name", "net_name", "service_name")):
        return result
    state = dict(lab._LAB_STATE.get(repo_id) or {})
    runtime_keys = ("container", "pod", "job_name", "lab_run_id", "container_id", "pod_uid", "job_uid")
    identity_keys = runtime_keys + ("service_name", "net_name", "network_id", "namespace", "provider",
                                    "target_tree_hash", "target_revision", "image_digest")
    immutable_keys = ("lab_run_id", "container_id", "pod_uid", "job_uid")
    same_runtime = any(returned.get(key) and returned[key] == state.get(key) for key in immutable_keys)
    conflicts = any(returned.get(key) and state.get(key) and returned[key] != state[key] for key in identity_keys)
    if (not same_runtime or conflicts or state.get("scan_job_id") not in (None, job_id)
            or state.get("repo_id") not in (None, repo_id)):
        state = {}
    # Current partial-created results are still persisted, with an explicit
    # cleanup gap when they lack authority. Earlier checkpoints stay untouched.
    record = {**state, **returned, "repo_id": repo_id, "scan_job_id": job_id}
    try:
        if not record.get("lab_run_id") or not record.get("target_tree_hash"):
            raise RuntimeError("Provider did not retain a complete runtime run/source identity")
        if record.get("provider") == "k8s-job":
            record["cleanup_identity"] = await capture_k8s_cleanup(record)
        elif record.get("lab_kind") != "compose" and not record.get("compose_project"):
            container = await _docker_inspect("container", record["container"]) if record.get("container") else None
            network = await _docker_inspect("network", record["net_name"]) if record.get("net_name") else None
            if container:
                _check_labels(_doc(container.get("Config")).get("Labels") or {}, record)
                record["container_id"] = container["Id"]
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(container.get("Image") or "")):
                    raise RuntimeError("Docker runtime did not expose an immutable image identity")
                record["image_digest"] = container["Image"]
            if network:
                _check_labels(network.get("Labels") or {}, record, source=False)
                record["network_id"] = network["Id"]
    except Exception as exc:
        record["cleanup_gap"] = str(exc)[:500]
    with db_factory() as db:
        job = db.query(job_cls).filter(job_cls.id == job_id, job_cls.repo_id == repo_id).first()
        if not job:
            raise RuntimeError("Audit no longer exists; runtime cleanup checkpoint cannot be persisted")
        expected_tree = _doc(_doc(job.output).get("target_identity")).get("target_tree_hash")
        if expected_tree and record.get("target_tree_hash") != expected_tree:
            record["cleanup_gap"] = "Provider source identity differs from its audit; ownership recovery is required"
        job.runtime_cleanup_json = json.dumps(record, default=str)
        db.commit()
    return {**(result if isinstance(result, dict) else {}), **{key: record[key] for key in (
        "lab_run_id", "target_tree_hash", "target_revision", "namespace", "cleanup_identity", "cleanup_gap", "container_id", "network_id", "image_digest") if key in record}}
