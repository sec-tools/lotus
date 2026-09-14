"""Live identity checks for commands bound to a recorded report runtime.

Kubernetes exec is addressed by Pod name. A downward-API UID guard inside the
container closes the replacement window between inspection and exec admission.
Docker commands use the inspected immutable container ID and an in-container
PID 1 lifetime guard, so restarting that same ID cannot redirect a command.
"""
import json
import re
import shlex

from backend.report_context import require_runtime_binding

POD_UID_ENV = "LOTUS_NOTEBOOK_POD_UID"

# Only shell builtins: audited images need neither Python nor procps. The final
# ')' terminates /proc/1/stat's comm field, which may contain spaces or ')'.
# starttime is field 22, or field 20 after removing pid and comm. Keep this in
# a subshell in the execution guard so splitting/options never affect user code.
_DOCKER_LIFETIME_READ = (
    "IFS= read -r lotus_init_stat < /proc/1/stat || exit 125; "
    "case \"$lotus_init_stat\" in '1 ('*') '*) ;; *) exit 125;; esac; "
    "lotus_init_fields=${lotus_init_stat##*) }; "
    "IFS=' '; set -f; set -- $lotus_init_fields; "
    "test \"$#\" -ge 20 || exit 125; shift 19; lotus_init_ticks=$1; "
    "case \"$lotus_init_ticks\" in ''|*[!0-9]*) exit 125;; esac; "
    "IFS= read -r lotus_boot_id < /proc/sys/kernel/random/boot_id || exit 125; "
)
_DOCKER_LIFETIME_CAPTURE = _DOCKER_LIFETIME_READ + "printf '%s\\n%s\\n' \"$lotus_init_ticks\" \"$lotus_boot_id\""


def _require_docker_lifetime(record):
    ticks, boot = record.get("container_init_start_ticks"), record.get("container_boot_id")
    if (not isinstance(ticks, str) or not re.fullmatch(r"[0-9]{1,20}", ticks)
            or not isinstance(boot, str) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot)):
        raise ValueError("The recorded Docker process-lifetime guard is unavailable; run a fresh audit before executing notebook commands.")
    return {"container_init_start_ticks": ticks, "container_boot_id": boot}


async def resolve_runtime(repo_id, context, state):
    from backend import k8s_lab
    binding = context.get("binding") or {}
    if binding.get("repo_id") != repo_id:
        raise ValueError("Notebook repository differs from its recorded runtime.")
    require_runtime_binding(context, state)
    expected = binding.get("lab") or {}
    target = binding.get("target_identity") or {}
    provider = state.get("provider") or "docker"
    if expected.get("provider") and expected["provider"] != provider:
        raise ValueError("Notebook runtime provider differs from the recorded audit.")
    container = str(state.get("container") or "")
    if not container:
        raise ValueError("The original notebook runtime is not registered.")
    if provider == "k8s-job":
        namespace = str(expected.get("namespace") or "")
        if not namespace or not expected.get("pod_uid") or not expected.get("job_uid") or not expected.get("image_digest"):
            raise ValueError("Recorded Kubernetes runtime identity is incomplete; run a fresh audit.")
        raw, rc = await k8s_lab._run(["get", "pod", container, "-n", namespace, "-o", "json"], timeout=10, max_output=None)
        try:
            pod = json.loads(raw) if rc == 0 else {}
            meta, status = pod.get("metadata") or {}, pod.get("status") or {}
            labels, annotations = meta.get("labels") or {}, meta.get("annotations") or {}
            owners = meta.get("ownerReferences") or []
            owner = next((row for row in owners if row.get("kind") == "Job" and row.get("controller") is True), {})
            current = next(row for row in status.get("containerStatuses") or [] if row.get("name") == "lab")
            image = k8s_lab.image_digest({"status": {"containerStatuses": [current]}})
            spec = next(row for row in (pod.get("spec") or {}).get("containers") or [] if row.get("name") == "lab")
            env = [row for row in spec.get("env") or [] if row.get("name") == POD_UID_ENV]
            guard = len(env) == 1 and env[0].get("valueFrom", {}).get("fieldRef", {}).get("fieldPath") == "metadata.uid" and "value" not in env[0]
            valid = (meta.get("name") == container and meta.get("namespace") == namespace
                     and meta.get("uid") == expected["pod_uid"] and not meta.get("deletionTimestamp")
                     and labels.get("role") == "lab-container" and labels.get("lotus.io/repo-id") == str(repo_id)
                     and owner.get("name") == labels.get("lotus.io/job") == state.get("job_name")
                     and bool(owner.get("uid")) and (not expected.get("job_uid") or owner["uid"] == expected["job_uid"])
                     and annotations.get("lotus.io/target-tree-hash") == target["tree_hash"]
                     and (not target.get("revision") or annotations.get("lotus.io/target-revision") == target["revision"])
                     and image == expected["image_digest"] and status.get("phase") == "Running"
                     and (pod.get("spec") or {}).get("restartPolicy") == "Never"
                     and bool((current.get("state") or {}).get("running")) and guard)
            for key, value in (("container_id", current.get("containerID")),
                               ("container_started_at", (current.get("state") or {}).get("running", {}).get("startedAt"))):
                valid = valid and (not expected.get(key) or expected[key] == value)
            if not valid:
                raise ValueError("identity mismatch")
        except (ValueError, TypeError, KeyError, AttributeError, StopIteration):
            raise ValueError("The original Kubernetes Pod identity or UID execution guard is unavailable; no notebook command was executed. Run a fresh audit if this Pod predates the guard.") from None
        return {"provider": provider, "container": container, "namespace": namespace, "pod_uid": expected["pod_uid"],
                "container_id": current.get("containerID"), "container_started_at": (current.get("state") or {}).get("running", {}).get("startedAt")}
    if provider != "docker":
        raise ValueError("Recorded notebook runtime provider is unsupported.")
    lifetime = _require_docker_lifetime(expected)
    if (not re.fullmatch(r"[a-f0-9]{64}", str(expected.get("container_id") or ""))
            or not expected.get("container_started_at")):
        raise ValueError("The recorded Docker container identity is incomplete; run a fresh audit before executing notebook commands.")
    return {**await inspect_docker_runtime(repo_id, expected, target, container), **lifetime}


async def inspect_docker_runtime(repo_id, expected, target, container):
    """Capture/check owned image identity without inventing an audit job."""
    from backend.notebook_runtime import _docker
    result = await _docker("inspect", expected.get("container_id") or container, timeout=10)
    try:
        info = json.loads(result["stdout"])[0] if result["returncode"] == 0 and not result.get("output_truncated") else {}
        labels = (info.get("Config") or {}).get("Labels") or {}
        valid = (re.fullmatch(r"[a-f0-9]{64}", str(info.get("Id") or ""))
                 and (info.get("State") or {}).get("Running") is True
                 and bool((info.get("State") or {}).get("StartedAt"))
                 and labels.get("lotus.audit.repo_id") == str(repo_id)
                 and labels.get("lotus.audit.run_id") == expected["lab_run_id"]
                 and labels.get("lotus.audit.target_tree_hash") == target["tree_hash"]
                 and (not target.get("revision") or labels.get("lotus.audit.target_revision") == target["revision"])
                 and (not expected.get("image_digest") or info.get("Image") == expected["image_digest"])
                 and (not expected.get("container_id") or info.get("Id") == expected["container_id"])
                 and (not expected.get("container_started_at") or (info.get("State") or {}).get("StartedAt") == expected["container_started_at"]))
        if not valid:
            raise ValueError("identity mismatch")
    except (ValueError, TypeError, KeyError, IndexError, AttributeError):
        raise ValueError("The original Docker container identity changed or is unavailable; no notebook command was executed.") from None
    return {"provider": "docker", "container": info["Id"], "container_id": info["Id"], "image_digest": info.get("Image"),
            "container_started_at": (info.get("State") or {}).get("StartedAt")}


async def capture_docker_runtime(repo_id, expected, target, container):
    """Record PID 1/boot identity only inside a stable, owned container start."""
    from backend.notebook_runtime import _docker
    before = await inspect_docker_runtime(repo_id, expected, target, container)
    result = await _docker("exec", before["container_id"], "sh", "-c", _DOCKER_LIFETIME_CAPTURE, timeout=10)
    values = str(result.get("stdout") or "").splitlines()
    if result.get("returncode") != 0 or result.get("output_truncated") or len(values) != 2:
        raise ValueError("Docker PID 1/boot identity could not be captured; notebook execution requires a fresh verifiable runtime.")
    lifetime = _require_docker_lifetime(dict(zip(("container_init_start_ticks", "container_boot_id"), values)))
    after = await inspect_docker_runtime(repo_id, {**expected, **before}, target, before["container_id"])
    if before != after:
        raise ValueError("Docker process lifetime changed during identity capture; notebook execution was not enabled.")
    return {**before, **lifetime}


def guard_command(command, runtime):
    if runtime["provider"] == "docker":
        lifetime = _require_docker_lifetime(runtime)
        return ("( " + _DOCKER_LIFETIME_READ
                + f'test "$lotus_init_ticks" = {shlex.quote(lifetime["container_init_start_ticks"])} && '
                + f'test "$lotus_boot_id" = {shlex.quote(lifetime["container_boot_id"])}'
                + " ) || { printf 'Notebook Docker process lifetime changed; command refused' >&2; exit 125; }; "
                + command)
    if runtime["provider"] != "k8s-job":
        raise ValueError("Notebook runtime has no supported identity execution guard.")
    return (f'test "${{{POD_UID_ENV}:-}}" = {shlex.quote(runtime["pod_uid"])} || '
            "{ printf 'Notebook Pod identity changed; command refused' >&2; exit 125; }; "
            + command)
