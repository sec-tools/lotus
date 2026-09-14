"""Build the captured repository in Kubernetes before starting a restricted lab.

Build/install commands belong to the tokenless image-builder Pod. The lab Pod
runs the resulting immutable image, including its original command and workdir.
No source URL, host bind, or Docker daemon is needed to deliver local checkouts.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from backend import audit_planner, k8s_builder, k8s_compose_plan, lab_builder
from backend.proof_receipts import content_tree_digest
from backend.target_snapshots import MAX_SNAPSHOT_BYTES

_BASE_IMAGES = {}
_BASE_LOCK = asyncio.Lock()


async def prepare_adapter_request(repo_id, source, request, send):
    """Build a newly generated native component through the same Pod boundary."""
    from backend import lab_adapters, adapter_build_repair
    from backend.local_deployment_plan import inspect_local_deployment
    from backend.pipeline import record_task
    expected = str(request.get("target_tree_hash") or "")
    record_task(repo_id, "local-lab-adapter", "Lab", "running",
                summary="Assessing captured source for supported local deployment options")
    deployment = await asyncio.to_thread(inspect_local_deployment, source, target_identity=request, request=request)
    artifact = await lab_adapters.create_adapter(source, repo_id, expected, deployment, send)
    def failure_receipt():
        return {"strategy": "ai-native-adapter", "runtime": "k8s-job",
                "target_tree_hash": expected, "adapter": artifact,
                **{key: artifact[key] for key in ("image", "recipe_sha256", "base_image") if artifact.get(key)}}

    if artifact.get("status") != "generated":
        record_task(repo_id, "local-lab-adapter", "Lab", "blocked",
                    summary="Local lab unavailable; runtime coverage remains incomplete",
                    detail_id=f"{repo_id}-local-lab-adapter")
        raise lab_adapters.AdapterUnavailable(artifact.get("reason", "Local adapter is not executable"),
                                              artifact=artifact, source_build=failure_receipt())
    candidate = artifact["candidate"]
    # One compiler correction only, after exact-owned cleanup and immutable
    # source/recipe checks. Setup/ownership/resource failures never grant retry.
    MAX_BUILD_ATTEMPTS = 2
    build_history = list(artifact.get("build_attempts") or [])
    image = None
    recipe_hash = None
    stage = "base-image"
    try:
        base = await _base_image(repo_id, send)
    except Exception as exc:
        artifact.update(status="build-failed", runtime_verified=False, full_deployment_verified=False,
                        reason=f"Native adapter base-image failed ({type(exc).__name__[:80]}); inspect the image-builder task",
                        failure={"stage": "base-image", "error_type": type(exc).__name__[:80], "detail_id": f"{repo_id}-local-lab-adapter"})
        try:
            lab_adapters.persist_adapter(source, artifact)
        except OSError:
            pass
        record_task(repo_id, "local-lab-adapter", "Lab", "failed", summary=artifact["reason"])
        await send(repo_id, artifact["reason"], level="warning", detail_id=f"{repo_id}-local-lab-adapter", detail=artifact)
        raise lab_adapters.AdapterUnavailable(artifact["reason"], artifact=artifact, source_build=failure_receipt()) from exc

    for build_attempt in range(MAX_BUILD_ATTEMPTS):
        recipe = None
        recipe_hash = None
        stage = "recipe-generation"
        try:
            recipe = lab_adapters.render_recipe(candidate, base, toolchain=artifact.get("toolchain"))
            recipe_hash = hashlib.sha256(recipe.encode()).hexdigest()
            artifact.update(status="building", recipe_sha256=recipe_hash, base_image=base, build_attempts=build_history)
            lab_adapters.persist_adapter(source, artifact)
            with tempfile.TemporaryDirectory(prefix=f"lotus-native-adapter-{int(repo_id)}-") as directory:
                bctx = Path(directory) / "source"
                stage = "source-copy"
                await asyncio.to_thread(_copy_source, source, bctx, expected)
                filename = "Dockerfile.lotus-adapter"
                if (bctx / filename).exists():
                    raise ValueError("Adapter scaffold would overwrite a captured source file")
                (bctx / filename).write_text(recipe)
                stage = "recipe-admission"
                lab_builder.validate_dockerfile_for_lab(bctx / filename, bctx)
                stage = "image-build"
                image = await k8s_builder.build_image(repo_id, "native-adapter", bctx,
                    tag=hashlib.sha256((expected + recipe_hash).encode()).hexdigest()[:20],
                    dockerfile=filename, return_digest=True, send=send, source_tree_hash=expected)
            stage = "image-identity"
            from backend.k8s_lab import _immutable_image_ref
            if not image or not _immutable_image_ref(image):
                raise ValueError("Local adapter did not produce an immutable image; inspect its isolated builder task")
            artifact.update(status="built", image=image, build_attempts=build_history,
                            reason="Native component image built; its target smoke and deployment fidelity remain unverified")
            lab_adapters.persist_adapter(source, artifact)
            break
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Exception messages may embed registry credentials or tool output.
            # Only fixed controller stage/code/reason values are surfaced.
            is_build = isinstance(exc, k8s_builder.BuildImageFailure)
            is_recipe = stage == "recipe-admission" and not is_build
            diagnostic = None
            if is_build:
                diagnostic = k8s_builder.BuildImageFailure.public_diagnostic(exc)
                failure = {"kind": "build", "stage": diagnostic["stage"], "code": diagnostic.get("code", ""), "reason": diagnostic["reason"]}
                reason = f"Native adapter image build failed at {diagnostic['stage']}: {diagnostic['reason']}"
                if diagnostic["cleanup_errors"]:
                    reason += "; owned cleanup remains incomplete"
            elif is_recipe:
                failure = {"kind": "recipe-admission", "stage": stage,
                           "reason": "The generated Dockerfile was rejected by lab build admission; correct the build_steps and entrypoint"}
                reason = "Native adapter recipe-admission failed; the generated Dockerfile was rejected by lab build admission"
            else:
                failure = None
                reason = f"Native adapter {stage} failed ({type(exc).__name__[:80]}); inspect the isolated builder task and console"
            evidence = k8s_builder.BuildImageFailure.repair_evidence(
                exc, source_tree_hash=expected, recipe_sha256=recipe_hash) if is_build else None
            history = {"attempt": build_attempt + 1, "failure": failure or {"stage": stage, "error_type": type(exc).__name__[:80]},
                       "target_tree_hash": expected, "recipe_sha256": recipe_hash,
                       "recipe": recipe if recipe_hash else None, "candidate": candidate}
            if evidence is not None:
                history["owned_build"] = evidence
            build_history.append(history)
            artifact["build_attempts"] = build_history
            # Persist the original attempt before any provider operation. Losing
            # that record blocks repair rather than silently replacing evidence.
            persisted = False
            try:
                lab_adapters.persist_adapter(source, artifact)
                persisted = True
            except OSError as persistence_error:
                artifact["persistence_error_type"] = type(persistence_error).__name__[:80]
            if build_attempt == 0 and evidence is not None and persisted:
                corrected = await adapter_build_repair.correct_candidate(
                    source, repo_id, expected, deployment, artifact, evidence, send)
                if corrected is not None:
                    candidate = corrected
                    artifact["candidate"] = candidate
                    continue
            artifact.update(status="build-failed", runtime_verified=False, full_deployment_verified=False,
                            reason=reason, build_attempts=build_history,
                            failure={"stage": stage, "error_type": type(exc).__name__[:80],
                                     "detail_id": f"{repo_id}-local-lab-adapter", **({"build": diagnostic} if diagnostic else {})})
            try:
                lab_adapters.persist_adapter(source, artifact)
            except OSError as persistence_error:
                artifact["persistence_error_type"] = type(persistence_error).__name__[:80]
            record_task(repo_id, "local-lab-adapter", "Lab", "failed", summary=artifact["reason"])
            await send(repo_id, artifact["reason"], level="warning", detail_id=f"{repo_id}-local-lab-adapter", detail=artifact)
            raise lab_adapters.AdapterUnavailable(artifact["reason"], artifact=artifact,
                                                  source_build=failure_receipt()) from exc
    record_task(repo_id, "local-lab-adapter", "Lab", "running", summary=artifact["reason"])
    await send(repo_id, artifact["reason"], detail_id=f"{repo_id}-local-lab-adapter", detail=artifact)
    receipt = {"image": image, "target_tree_hash": expected, "recipe_sha256": recipe_hash,
               "strategy": "ai-native-adapter", "runtime": "k8s-job", "port": candidate["port"],
               "port_source": "source-bound-adapter", "adapter": artifact,
               "adapter_smoke": lab_adapters.smoke_argv(candidate)}
    try:
        (source / ".lotus" / "service_image.json").write_text(json.dumps(receipt, indent=2))
    except OSError as exc:
        artifact.update(status="runtime-failed", runtime_verified=False, full_deployment_verified=False,
                        reason=f"Native adapter receipt persistence failed ({type(exc).__name__[:80]}); image identity retained in the audit result",
                        failure={"stage": "receipt-persistence", "error_type": type(exc).__name__[:80],
                                 "detail_id": f"{repo_id}-local-lab-adapter"})
        raise lab_adapters.AdapterUnavailable(artifact["reason"], artifact=artifact, source_build=failure_receipt()) from exc
    return {**request, "image": image, "source_url": "", "source": "", "source_embedded": True,
            "use_image_entrypoint": True, "install_steps": [], "start_command": None,
            "source_build": receipt, "runtime_user": {"uid": 1000, "gid": 1000},
            "port": candidate["port"], "port_source": "source-bound-adapter",
            "runtime_environment": candidate["environment"]}


def _source_entries(source: Path):
    """Share receipt/snapshot selection, including captured aliases and modes."""
    from backend.proof_receipts import source_content_files
    from backend.target_snapshots import source_selection_metadata
    source = Path(source).resolve()
    selected = source_content_files(source)
    metadata = source_selection_metadata(source, selected, reject_unsafe=True)
    return ([path.relative_to(source) for path in selected],
            {Path(name): Path(target) for name, target in metadata["aliases"].items()})


def _selected_digest(root: Path, files) -> str:
    """Receipt-compatible path/content digest for a context without Git metadata."""
    digest = hashlib.sha256()
    for relative in files:
        encoded = relative.as_posix().encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        with (root / relative).open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _copy_source(source: Path, context: Path, expected: str) -> None:
    from backend.target_snapshots import source_selection_metadata, copy_source_selection, load_snapshot
    source = Path(source).resolve()
    if context.exists() or context.is_symlink():
        raise ValueError("Kubernetes service build context must be a new private directory")
    if not expected or content_tree_digest(source) != expected:
        raise ValueError("Kubernetes service source is missing its current audit tree identity")
    files, links = _source_entries(source)
    selected = [source / relative for relative in files]
    metadata = source_selection_metadata(source, selected, reject_unsafe=True)
    if {Path(name): Path(target) for name, target in metadata["aliases"].items()} != links:
        raise ValueError("Kubernetes service source aliases changed during inventory")
    if sum(path.stat().st_size for path in selected) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Kubernetes service source exceeds the configured snapshot budget")
    if _selected_digest(source, files) != expected:
        raise ValueError("Kubernetes service source selection does not match its audit tree identity")
    plan_path = source / ".lotus" / "audit_plan.json"
    if plan_path.is_file():
        if plan_path.is_symlink() or plan_path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("Kubernetes service source plan is unsafe or oversized")
        plan = json.loads(plan_path.read_text())
        binding = plan.get("target_snapshot") if isinstance(plan, dict) else None
        if binding:
            if not isinstance(binding, dict) or not binding.get("manifest_hash") or binding.get("tree_hash") != expected:
                raise ValueError("Kubernetes service source snapshot binding is incomplete")
            captured = load_snapshot(str(binding.get("path") or binding.get("source_path") or ""))
            if captured["manifest_hash"] != binding["manifest_hash"] or captured["tree_hash"] != expected:
                raise ValueError("Kubernetes service source snapshot binding changed")
            if captured.get("source_metadata"):
                captured_source = Path(captured["source_path"])
                expected_metadata = source_selection_metadata(captured_source, [captured_source / relative for relative in files])
                # Writable checkouts normalize read/write permissions. The
                # snapshot records originals; executable bits and aliases must
                # retain their exact captured semantics for image building.
                if (metadata["aliases"] != expected_metadata["aliases"]
                        or {name: mode & 0o111 for name, mode in metadata["files"].items()}
                        != {name: mode & 0o111 for name, mode in expected_metadata["files"].items()}):
                    raise ValueError("Kubernetes service aliases or executable modes differ from the audited snapshot")
    copy_source_selection(source, context, selected, metadata=metadata)
    if (_selected_digest(context, files) != expected or content_tree_digest(source) != expected
            or source_selection_metadata(source, selected, reject_unsafe=True) != metadata):
        raise ValueError("Kubernetes service source changed while preparing its build context")


def _runtime_user(recipe: str):
    """Conservatively support literal numeric final-stage image users.

    Named users/ARG expansion require image config and passwd attestation; do
    not guess their UID. Unspecified/root images use the restricted default.
    """
    user, stage = "", None
    stage_users = {}
    for line in re.sub(r"\\\s*\n", " ", recipe).splitlines():
        match = re.match(r"\s*(FROM|USER)\s+(.+?)\s*$", line, re.I)
        if match:
            if match[1].upper() == "FROM":
                tokens = match[2].split()
                base_tokens = [token for token in tokens if not token.startswith("--")]
                user = stage_users.get(base_tokens[0].casefold(), "") if base_tokens else ""
                stage = base_tokens[-1].casefold() if len(base_tokens) >= 3 and base_tokens[-2].upper() == "AS" else None
            else:
                user = match[2].strip()
            if stage:
                stage_users[stage] = user
    if not user or user in {"root", "0", "0:0", "root:root"}:
        return {"uid": 1000, "gid": 1000}
    match = re.fullmatch(r"([0-9]+)(?::([0-9]+))?", user)
    if not match:
        raise ValueError("Kubernetes repository Dockerfile USER must be a literal numeric non-root UID[:GID]; named or dynamic users require an explicit compatible image")
    uid, gid = int(match[1]), int(match[2] or match[1])
    if not 1 <= uid <= 2147483647 or not 1 <= gid <= 2147483647:
        raise ValueError("Kubernetes repository Dockerfile USER must have non-root UID and GID")
    return {"uid": uid, "gid": gid}


def _declared_tcp_port(recipe: str):
    """Infer only one literal TCP exposure inherited by the final image stage.

    Earlier build stages and variable expansion are not application port
    evidence. External base-image configuration remains unknown here.
    """
    # Heredoc bodies can contain instruction-looking text. Without a full
    # Dockerfile AST, require an explicit port instead of treating body text as
    # an image declaration.
    if re.search(r"(?im)^\s*(?:RUN|COPY|ADD)\s+.*<<", recipe):
        raise ValueError("Kubernetes service Dockerfile uses heredocs; supply an explicit target TCP port for this build contract")
    exposed, stage = [], None
    stage_ports = {}
    for line in re.sub(r"\\\s*\n", " ", recipe).splitlines():
        match = re.match(r"\s*(FROM|EXPOSE)\s+(.+?)\s*$", line, re.I)
        if not match:
            continue
        tokens = match[2].split()
        if match[1].upper() == "FROM":
            base_tokens = [token for token in tokens if not token.startswith("--")]
            exposed = list(stage_ports.get(base_tokens[0].casefold(), [])) if base_tokens else []
            stage = base_tokens[-1].casefold() if len(base_tokens) >= 3 and base_tokens[-2].upper() == "AS" else None
        else:
            exposed.extend(tokens)
        if stage:
            stage_ports[stage] = list(exposed)
    if not exposed:
        return None
    ports = set()
    for token in exposed:
        match = re.fullmatch(r"([0-9]+)(?:/tcp)?", token, re.I)
        if not match or not 1 <= int(match[1]) <= 65535:
            raise ValueError("Kubernetes service Dockerfile has a variable, non-TCP, or invalid final-stage EXPOSE; supply an explicit target TCP port")
        ports.add(int(match[1]))
    if len(ports) != 1:
        raise ValueError("Kubernetes service Dockerfile exposes multiple final-stage ports; supply an explicit target TCP port")
    return ports.pop()


async def _base_image(repo_id, send):
    explicit = os.environ.get("LOTUS_K8S_LAB_BASE_IMAGE", "").strip()
    if explicit:
        if not re.fullmatch(r"[^\s]+@sha256:[a-fA-F0-9]{64}", explicit):
            raise ValueError("LOTUS_K8S_LAB_BASE_IMAGE must be an immutable image reference")
        return explicit
    recipe = (Path(__file__).parent / "lab" / "Dockerfile").read_bytes()
    digest = hashlib.sha256(recipe).hexdigest()
    key = (k8s_builder.build_namespace(), os.environ.get("LOTUS_K8S_CONTEXT", ""), digest)
    async with _BASE_LOCK:
        if key in _BASE_IMAGES:
            return _BASE_IMAGES[key]
        with tempfile.TemporaryDirectory(prefix="lotus-k8s-base-") as directory:
            (Path(directory) / "Dockerfile").write_bytes(recipe)
            image = await k8s_builder.build_image(
                repo_id, "service-base", Path(directory), tag=digest[:20],
                return_digest=True, send=send,
            )
        if not image:
            raise ValueError("Kubernetes lab base-image build failed; inspect the image-builder task")
        _BASE_IMAGES[key] = image
        return image


async def prepare_service_request(repo_id, dest, request, send):
    """Return a source-bound, immutable service request or a visible build error."""
    source = Path(dest).resolve()
    expected = str(request.get("target_tree_hash") or "")
    plan_path = source / ".lotus" / "audit_plan.json"
    plan = json.loads(plan_path.read_text()) if plan_path.is_file() else {}
    if not isinstance(plan, dict):
        raise ValueError("Kubernetes service audit plan must be an object")
    language = str(plan.get("language") or request.get("language") or "unknown")
    app_type = str(plan.get("app_type") or request.get("app_type") or "unknown")
    port = int(request.get("port") or 3000)
    port_source = str(request.get("port_source") or ("explicit" if request.get("port") else "default"))
    if not 1 <= port <= 65535:
        raise ValueError("invalid Kubernetes service port")
    artifacts = lab_builder.discover_lab_artifacts(source)
    # Admit every discovered Compose file, even those the older Docker
    # heuristic called impractical. An unsupported dependency/socket must not
    # silently fall through to a different generated launcher.
    compose_plan = None
    if artifacts.get("compose"):
        try:
            compose_plan = await asyncio.to_thread(k8s_compose_plan.plan_compose, source, artifacts["compose"], request)
        except k8s_compose_plan.ComposeAdmissionError:
            from backend.ai_runtime import active_audit_context
            if active_audit_context() is None:
                raise
            return await prepare_adapter_request(repo_id, source, request, send)
        port = compose_plan["port"]
        if compose_plan["port_declared"]:
            port_source = "compose"
        await send(repo_id, "Admitted captured single-service Compose contract; its target port uses an isolated ClusterIP Service, not the declared host binding", level="info")
    if not compose_plan and not (artifacts.get("dockerfile") and artifacts.get("dockerfile_usable")):
        from backend.ai_runtime import active_audit_context
        if active_audit_context() is not None:
            return await prepare_adapter_request(repo_id, source, request, send)
    await send(repo_id, "Building the captured source in a Kubernetes image-builder Pod", level="info")
    with tempfile.TemporaryDirectory(prefix=f"lotus-k8s-service-{int(repo_id)}-") as directory:
        context = Path(directory) / "source"
        await asyncio.to_thread(_copy_source, source, context, expected)
        dockerfile = source / compose_plan["dockerfile"] if compose_plan else artifacts.get("dockerfile")
        if compose_plan:
            copied_plan = await asyncio.to_thread(k8s_compose_plan.plan_compose, context, context / compose_plan["file"], request)
            if copied_plan != compose_plan:
                raise ValueError("Kubernetes Compose contract changed while copying its captured source")
        if dockerfile and (compose_plan or artifacts.get("dockerfile_usable")):
            relative = Path(dockerfile).resolve().relative_to(source)
            lab_builder.validate_dockerfile_for_lab(context / relative, context)
            recipe_path = context / relative
            strategy = "repository-dockerfile"
            if compose_plan:
                recipe = k8s_compose_plan.apply_image_config(recipe_path.read_text(), compose_plan)
                relative = Path("Dockerfile.lotus-compose")
                if (context / relative).exists():
                    raise ValueError("Kubernetes Compose recipe would overwrite captured Dockerfile.lotus-compose")
                recipe_path = context / relative
                recipe_path.write_text(recipe)
                lab_builder.validate_dockerfile_for_lab(recipe_path, context)
                strategy = "repository-compose-single-service"
            if port_source == "default":
                declared_port = _declared_tcp_port(recipe_path.read_text())
                if declared_port is not None:
                    port, port_source = declared_port, "dockerfile-expose"
                    if compose_plan:
                        compose_plan["port"] = port
                    await send(repo_id, f"Using captured Dockerfile's declared TCP port {port}", level="info")
        else:
            requirements = lab_builder.analyze_repo_requirements(context, language, app_type)
            requirements = audit_planner.apply_plan_to_requirements(requirements, plan)
            # Keep analyze_repo_requirements' fail-closed unknown-app policy.
            recipe = lab_builder.generate_dockerfile_from_requirements(requirements, port)
            base = await _base_image(repo_id, send)
            recipe = recipe.replace("FROM lotus-lab-ubuntu:26.04\n", f"FROM {base}\n", 1)
            recipe += "USER root\nRUN chown -R 1000:1000 /app\nUSER 1000:1000\n"
            relative = Path("Dockerfile.lotus")
            if (context / relative).exists():
                raise ValueError("Kubernetes generated recipe would overwrite a tracked Dockerfile.lotus; provide a repository Dockerfile")
            recipe_path = context / relative
            recipe_path.write_text(recipe)
            lab_builder.validate_dockerfile_for_lab(recipe_path, context)
            strategy = "audit-plan"
        runtime_user = _runtime_user(recipe_path.read_text())
        recipe_hash = hashlib.sha256(recipe_path.read_bytes()).hexdigest()
        image = await k8s_builder.build_image(
            repo_id, "service", context, tag=hashlib.sha256((expected + recipe_hash).encode()).hexdigest()[:20],
            dockerfile=relative.as_posix(), return_digest=True, send=send,
        )
        if not image:
            raise ValueError("Kubernetes service image build failed; inspect the image-builder task")
    from backend.k8s_lab import _immutable_image_ref
    if not _immutable_image_ref(image):
        raise ValueError("Kubernetes service builder did not return an immutable image")
    receipt = {"image": image, "target_tree_hash": expected, "recipe_sha256": recipe_hash,
               "strategy": strategy, "runtime": "k8s-job", "port": port, "port_source": port_source}
    if compose_plan:
        receipt["compose"] = {key: compose_plan[key] for key in ("schema_version", "file", "service", "compose_sha256", "port", "published_ports")}
        receipt["compose"]["environment_names"] = sorted(compose_plan["environment"])
    evidence = source / ".lotus" / "service_image.json"
    evidence.parent.mkdir(exist_ok=True)
    evidence.write_text(json.dumps(receipt, indent=2))
    await send(repo_id, "Kubernetes service image is ready; starting its restricted lab Pod", level="info")
    return {**request, "image": image, "source_url": "", "source": "", "source_embedded": True,
            "use_image_entrypoint": True, "install_steps": [], "start_command": None,
            "source_build": receipt, "runtime_user": runtime_user, "port": port, "port_source": port_source,
            "runtime_environment": compose_plan["environment"] if compose_plan else {}}
