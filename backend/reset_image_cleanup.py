"""Bounded, optional generated-image cleanup before reset discards audit rows.

A runtime image reference alone never proves that an image is disposable. Only
an immutable image recorded by its audit, matching generated-image labels and no current
consumer authorizes Docker removal. Legacy images are retained. Kubernetes
manifest/blob/node cache collection requires a separate runtime administrator;
this module never opens a Docker socket or runs Docker for Kubernetes.
"""
from __future__ import annotations

import asyncio
import json
import os
import re

_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_RECORDS = 128
_MAX_CONTAINERS = 1024
_IMAGE_LABEL_KEYS = ("lotus.audit.repo_id", "lotus.audit.run_id", "lotus.audit.target_tree_hash",
                     "lotus.audit.generated_image", "lotus.audit.image_purpose")
_IMAGE_PROJECTION = ('{"Id":{{json .Id}},"RepoTags":{{json .RepoTags}},"RepoDigests":{{json .RepoDigests}},'
                     '"Config":{"Labels":{' + ','.join(json.dumps(key) + ':{{json (index .Config.Labels '
                     + json.dumps(key) + ')}}' for key in _IMAGE_LABEL_KEYS) + '}}}')


def _object(value):
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or len(value) > 1024 * 1024:
        return {}
    try:
        result = json.loads(value)
        return result if isinstance(result, dict) else {}
    except (ValueError, RecursionError):
        return {}


def _saved_rows(db):
    from backend.main import ScanJob
    from sqlalchemy import LargeBinary, case, cast, func
    # Bound the scalar in SQL before materialization, not after loading logs.
    size = func.length(cast(ScanJob.runtime_cleanup_json, LargeBinary))
    bounded = case((size <= 1024 * 1024, ScanJob.runtime_cleanup_json), else_=None)
    return db.query(ScanJob.id, ScanJob.repo_id, ScanJob.status,
                    bounded.label("runtime_cleanup_json"),
                    (size > 1024 * 1024).label("image_metadata_oversized")).limit(10001).yield_per(25)


def _inventory(db):
    candidates, retained = [], []
    for count, job in enumerate(_saved_rows(db), 1):
        if count > 10000:
            raise ValueError("audit-inventory-limit")
        if getattr(job, "image_metadata_oversized", False):
            retained.append({"audit_id": job.id, "reason": "durable-image-record-too-large"})
            continue
        raw = _object(job.runtime_cleanup_json)
        if job.runtime_cleanup_json and not raw:
            retained.append({"audit_id": job.id, "reason": "durable-image-record-invalid"})
            continue
        state = {**_object(raw.get("state")), **raw}
        identity = state.get("image_digest")
        image = identity or state.get("image")
        if not image:
            continue
        valid = (state.get("provider", "docker") == "docker"
                 and type(job.repo_id) is int and job.repo_id > 0 and type(job.id) is int and job.id > 0
                 and isinstance(identity, str) and bool(_ID.fullmatch(identity))
                 and isinstance(state.get("lab_run_id"), str) and 0 < len(state["lab_run_id"]) <= 128
                 and isinstance(state.get("target_tree_hash"), str)
                 and bool(_ID.fullmatch(state["target_tree_hash"]))
                 and not state.get("cleanup_gap")
                 and job.status in {"completed", "cancelled", "failed", "interrupted"})
        if not valid:
            retained.append({"audit_id": job.id, "reason": "no-exact-terminal-audit-image-ownership"})
            continue
        candidates.append({"image_id": identity, "repo_id": job.repo_id, "scan_job_id": job.id,
                           "lab_run_id": state["lab_run_id"], "target_tree_hash": state["target_tree_hash"]})
        if len(candidates) > _MAX_RECORDS or len(retained) > 10000:
            raise ValueError("image-inventory-limit")
    return candidates, retained


async def _command(args):
    from backend.lab import _run_cmd
    output, rc = await _run_cmd(["docker", *args], timeout=5)
    if len(output) > 2 * 1024 * 1024:
        raise ValueError("docker-output-limit")
    return output, rc


async def _inspect(identity):
    raw, rc = await _command(["image", "inspect", "--format", _IMAGE_PROJECTION, identity])
    if rc:
        if "no such image" in raw.lower():
            return None
        raise ValueError("image-inspection-unavailable")
    try:
        image = json.loads(raw)
        if not isinstance(image, dict) or image.get("Id") != identity:
            raise ValueError()
        if any(not isinstance(image.get(key), (list, type(None))) or
               any(not isinstance(v, str) for v in (image.get(key) or [])) for key in ("RepoTags", "RepoDigests")):
            raise ValueError()
        return image
    except (ValueError, AttributeError, TypeError):
        raise ValueError("image-inspection-invalid") from None


async def _consumers():
    raw, rc = await _command(["container", "ls", "--all", "--quiet", "--no-trunc"])
    ids = raw.split()
    if rc or len(ids) > _MAX_CONTAINERS or any(not re.fullmatch(r"[0-9a-f]{64}", i) for i in ids):
        raise ValueError("consumer-inventory-unavailable")
    if not ids:
        return set()
    raw, rc = await _command(["container", "inspect", "--format", "{{.Id}} {{.Image}}", *ids])
    if rc:
        raise ValueError("consumer-inventory-changed")
    try:
        rows = [line.split() for line in raw.splitlines()]
        if len(rows) != len(ids) or any(len(r) != 2 for r in rows) or {r[0] for r in rows} != set(ids):
            raise ValueError()
        images = {r[1] for r in rows}
        if any(not isinstance(i, str) or not _ID.fullmatch(i) for i in images):
            raise ValueError()
        return images
    except (ValueError, KeyError, TypeError):
        raise ValueError("consumer-inventory-invalid") from None


def _owned(image, receipt):
    labels = _object(image.get("Config")).get("Labels") or {}
    return (isinstance(labels, dict) and all(labels.get(key) == value for key, value in {
        "lotus.audit.repo_id": str(receipt["repo_id"]),
        "lotus.audit.run_id": receipt["lab_run_id"],
        "lotus.audit.target_tree_hash": receipt["target_tree_hash"],
        "lotus.audit.generated_image": "true",
        "lotus.audit.image_purpose": "audit-lab",
    }.items()))


def _configured_refs(db):
    from backend.main import Settings
    settings = db.query(Settings.default_lab_image).first()
    configured = {value.strip() for key, value in os.environ.items()
                  if key.startswith("LOTUS_") and key.endswith("_IMAGE") and value.strip()}
    configured.add("lotus-lab-ubuntu:26.04")
    configured.add(str(getattr(settings, "default_lab_image", "") or "ubuntu:26.04"))
    return configured


async def _protected_ids(refs):
    if len(refs) > 64:
        raise ValueError("protected-image-inventory-limit")
    identities = set()
    for ref in sorted(refs):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_./:@-]{0,254}", ref):
            raise ValueError("protected-image-reference-invalid")
        raw, rc = await _command(["image", "inspect", "--format", "{{.Id}}", ref])
        if rc:
            if "no such image" in raw.lower():
                continue
            raise ValueError("protected-image-resolution-unavailable")
        identity = raw.strip()
        if not _ID.fullmatch(identity):
            raise ValueError("protected-image-resolution-invalid")
        identities.add(identity)
    return identities


def _protected(image, configured, protected_ids):
    refs = {image["Id"], *(image.get("RepoTags") or []), *(image.get("RepoDigests") or [])}
    return image["Id"] in protected_ids or bool(refs & configured) or any(
        marker in str(ref).split("@", 1)[0]
        for ref in refs for marker in ("service-base", "qualified-autopoint-base"))


async def cleanup_generated_images(db):
    """Return an honest reset summary; caller holds its existing idle fence.

    Call after owned runtime cleanup and before deleting audit rows. This does
    not manufacture ownership for old images and never claims reclaimed bytes.
    The current Kubernetes build ledger/physical-GC lifecycle remains deferred.
    """
    from backend.lab_provider import provider_name
    provider = provider_name()
    result = {"provider": provider, "removed": [], "retained": [], "errors": [],
              "physical_bytes_reclaimed": None,
              "node_cache_cleanup": "runtime-admin-required",
              "registry_cache_cleanup": "runtime-admin-required"}
    if provider != "docker":
        result["retained"].append({"reason": "kubernetes-image-and-build-caches-managed-by-runtime"})
        return result
    try:
        candidates, result["retained"] = _inventory(db)
        if not candidates:
            return result
        async with asyncio.timeout(45):
            configured = _configured_refs(db)
            protected_ids = await _protected_ids(configured)
            seen = set()
            for receipt in candidates:
                identity = receipt["image_id"]
                if identity in seen:
                    continue
                seen.add(identity)
                image = await _inspect(identity)
                if image is None:
                    continue
                reason = ("image-ownership-labels-differ" if not _owned(image, receipt) else
                          "protected-base-or-service-image" if _protected(image, configured, protected_ids) else
                          "image-still-has-container-consumer" if identity in await _consumers() else "")
                if reason:
                    result["retained"].append({"image_id": identity, "reason": reason})
                    continue
                # Re-read immutable image metadata immediately before removal.
                current = await _inspect(identity)
                if current != image:
                    raise ValueError("image-metadata-changed")
                _, rc = await _command(["image", "rm", identity])
                # No force: Docker atomically refuses a newly attached consumer,
                # shared tags or dependent child, including stopped containers.
                if rc or await _inspect(identity) is not None:
                    result["retained"].append({"image_id": identity, "reason": "image-removal-refused"})
                    continue
                result["removed"].append(identity)
    except (ValueError, OSError, TimeoutError):
        result["errors"].append("Generated image cleanup was incomplete; unverified images and runtime caches were retained.")
    return result
