"""Bounded interface discovery in the exact recorded Kubernetes CLI runtime.

Help/version output is an observation, never a vulnerability oracle or credit
for validating a lead. Target code remains inside the admitted Pod.
"""
import asyncio
from copy import deepcopy
import hashlib
import json
from pathlib import Path, PurePosixPath


async def _source_hash(source):
    from backend.proof_receipts import content_tree_digest
    worker = asyncio.create_task(asyncio.to_thread(content_tree_digest, source))
    try:
        return await asyncio.shield(worker)
    finally:
        # A cancellation must not leave a source reader behind the audit lease.
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue


async def discover(repo_id, source, lab_status, send):
    from backend import lab
    from backend.ai_runtime import active_audit_context
    from backend.report_context import build_report_context
    summary = {"status": "failed", "probed": False, "endpoints": [], "traces": [],
               "logs": "", "tools": {"kubectl-exec": False}, "errors": [],
               "evidence_role": "interface-discovery", "runtime_validation": False,
               "coverage_complete": False}
    try:
        owner = active_audit_context()
        if owner is None or owner.repo_id != repo_id or type(owner.job_id) is not int or owner.job_id < 1:
            raise ValueError("Exact active audit identity is unavailable for CLI discovery")
        state = deepcopy(lab.get_lab_state(repo_id))
        required = ("provider", "lab_run_id", "pod_uid", "job_uid", "namespace", "image_digest",
                    "container_id", "container_started_at", "target_tree_hash", "source_build")
        if (state.get("provider") != "k8s-job" or lab_status.get("healthy") is not True
                or lab_status.get("runtime_attested") is not True
                or any(not state.get(key) or state[key] != lab_status.get(key) for key in required)
                or (state.get("pod") or state.get("container")) != (lab_status.get("pod") or lab_status.get("container"))
                or Path(str(state.get("dest") or "")).resolve() != Path(source).resolve()):
            raise ValueError("CLI discovery runtime differs from the selected audit's attested lab")
        build = state["source_build"]
        adapter = build.get("adapter") or {}
        candidate = adapter.get("candidate") or {}
        digest = hashlib.sha256(json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        entrypoint = candidate.get("entrypoint") or []
        if (not state.get("source_embedded") or build.get("target_tree_hash") != state["target_tree_hash"]
                or adapter.get("candidate_sha256") != digest or candidate.get("profile") != "native-service"
                or not isinstance(entrypoint, list) or not entrypoint or not isinstance(entrypoint[0], str)):
            raise ValueError("CLI discovery requires the recorded built native executable contract")
        path = PurePosixPath(entrypoint[0])
        if (not entrypoint[0] or any(c in entrypoint[0] for c in "\x00\r\n\\")
                or ".." in path.parts or len(entrypoint[0]) > 512):
            raise ValueError("Recorded CLI executable path is invalid")
        if not path.is_absolute():
            path = PurePosixPath("/app") / path
        if not path.is_relative_to("/app") or len(path.parts) < 3:
            raise ValueError("CLI discovery has no recorded application executable under /app")
        target = {"tree_hash": state["target_tree_hash"], "revision": state.get("target_revision") or ""}
        context = build_report_context(repo_id, owner.job_id, {"target_identity": target, "lab_status": state})
        if await _source_hash(source) != target["tree_hash"]:
            raise ValueError("Captured CLI source changed before discovery")
        observations = []
        for option in ("--version", "--help"):
            if lab.get_lab_state(repo_id) != state or active_audit_context() is not owner:
                raise ValueError("CLI runtime or active audit changed during discovery")
            # Only these two literal options. In particular no shell-expanded
            # payload can masquerade as output produced by the application.
            import shlex
            result = await lab.exec_in_lab(repo_id, shlex.join([str(path), option]),
                                           timeout=10, expected_context=context)
            summary["probed"] = True
            if lab.get_lab_state(repo_id) != state:
                raise ValueError("CLI runtime changed during discovery")
            output = str(result.get("stdout") or "")
            if (result.get("success") is not True or type(result.get("exit_code")) is not int
                    or result["exit_code"] != 0 or not output.strip()):
                raise ValueError("CLI " + option + " did not return a bounded successful interface response")
            excerpt = output.encode()[:4096].decode("utf-8", errors="ignore")
            observations.append({"path": str(path), "option": option, "exit_code": 0,
                                 "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
                                 "output_bytes": len(output.encode()), "output_excerpt": excerpt,
                                 "output_excerpt_bytes": len(excerpt.encode()),
                                 "output_truncated": bool(result.get("output_truncated")) or excerpt != output,
                                 "output_scope": "Bounded interface response prefix; hash and bytes describe captured output only",
                                 "evidence_role": "interface-discovery"})
        if (await _source_hash(source) != target["tree_hash"] or lab.get_lab_state(repo_id) != state
                or active_audit_context() is not owner):
            raise ValueError("Captured CLI source or runtime changed during discovery")
        summary.update(status="completed", endpoints=observations, tools={"kubectl-exec": True},
                       reason="CLI help/version interface discovery completed; no vulnerability or lead was validated",
                       scan_job_id=owner.job_id)
    except Exception as error:
        summary.update(reason=str(error)[:500], errors=[{"scope": "cli-interface", "error": str(error)[:500]}])
    await send(repo_id, summary["reason"], level="info" if summary["status"] == "completed" else "warning",
               detail_id=f"{repo_id}-cli-interface-discovery",
               detail={"type": "runtime_tool", "tool": "cli-interface-discovery", "title": "CLI interface discovery",
                       "status": summary["status"], "reason": summary["reason"],
                       "result_type": "interface-discovery", "observations": summary["endpoints"],
                       "runtime_validation": False, "coverage_complete": False})
    return [], summary
