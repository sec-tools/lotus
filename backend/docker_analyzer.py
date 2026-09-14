"""Owned lifecycle for explicitly selected Docker analyzer backup jobs.

Stopping the attached Docker client does not stop a daemon-owned container.
Allocate without starting, verify its random ownership label and immutable ID,
and remove that exact container before returning or propagating cancellation.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid


OWNER_LABEL = "lotus.analyzer.owner"
_OUTPUT_LIMIT = 64 * 1024 * 1024
_VALUE_OPTIONS = {
    "--name", "--memory", "--memory-swap", "--cpus", "--pids-limit", "--user", "-u",
    "--tmpfs", "--security-opt", "--cap-drop", "--label", "-l", "--volume", "-v",
    "--mount", "--workdir", "-w", "--network", "--net", "--env", "-e", "--entrypoint",
    "--hostname", "--add-host", "--cpu-shares", "--cpuset-cpus", "--ulimit", "--shm-size", "--pull",
}
_BOOL_OPTIONS = {"--read-only", "--init"}


class DockerAnalyzerCleanupError(RuntimeError):
    """An owned backup resource could not be proven removed."""


def _create_command(command, image, name, owner, *, memory_mb=None):
    if memory_mb is not None and (type(memory_mb) is not int or not 1 <= memory_mb <= 65536):
        raise ValueError("Docker analyzer memory limit must be an integer from 1 to 65536 MiB")
    if (not isinstance(command, list) or command[:2] != ["docker", "run"]
            or any(not isinstance(arg, str) or "\x00" in arg for arg in command)):
        raise ValueError("Docker analyzer requires the generated argument-array run command")
    preserved = []
    index = 2
    while index < len(command):
        arg = command[index]
        if not arg.startswith("-"):
            break
        flag, separator, inline = arg.partition("=")
        if flag == "--rm" and not separator:
            index += 1
            continue
        if flag in _BOOL_OPTIONS and not separator:
            preserved.append(arg)
            index += 1
            continue
        if flag not in _VALUE_OPTIONS:
            raise ValueError("Unsupported Docker analyzer lifecycle option: " + flag)
        if separator:
            value, width = inline, 1
        else:
            if index + 1 >= len(command):
                raise ValueError("Docker analyzer option is missing its value")
            value, width = command[index + 1], 2
        if flag in {"--label", "-l"} and value.split("=", 1)[0] == OWNER_LABEL:
            raise ValueError("Docker analyzer ownership label is reserved")
        if flag != "--name" and not (memory_mb is not None and flag in {"--memory", "--memory-swap"}):
            preserved.extend(command[index:index + width])
        index += width
    if index >= len(command) or command[index] != image:
        raise ValueError("Docker analyzer command image differs from its selected image")
    limits = ["--memory", f"{memory_mb}m", "--memory-swap", f"{memory_mb}m"] if memory_mb is not None else []
    return ["create", "--name", name, "--label", f"{OWNER_LABEL}={owner}",
            *preserved, *limits, *command[index:]]


async def _settle(task):
    """Wait through repeated cancellation until this command owns no process."""
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
        except BaseException:
            break
    return task.result()


async def run_owned(command, *, image, repo_id, tool, timeout, queue_timeout=None,
                    memory_mb=None, diagnostic_sink=None):
    """Return stdout/stderr/exit only after exact-ID cleanup is verified.

    Allocation and cleanup finish despite cancellation. Execution cancellation
    first reaps the attach client and then removes the daemon container. An
    uncertain daemon response is an explicit cleanup error, never absence.
    """
    from backend.notebook_runtime import _docker

    owner = uuid.uuid4().hex
    name = f"lotus-analyzer-{int(repo_id)}-{owner[:16]}"
    create = _create_command(command, image, name, owner, memory_mb=memory_mb)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 7200:
        raise ValueError("Docker analyzer execution timeout must be positive and at most 7200 seconds")
    queue_timeout = min(120, max(15, timeout)) if queue_timeout is None else queue_timeout
    if not isinstance(queue_timeout, (int, float)) or isinstance(queue_timeout, bool) or not 0 < queue_timeout <= 7200:
        raise ValueError("Docker analyzer queue timeout must be positive and at most 7200 seconds")
    container_id = None
    image_id = None
    allocation_returned = False
    receipt = {"provider": "docker", "tool": tool, "tool_id": tool, "repo_id": int(repo_id),
               "owner": owner, "name": name, "image": image, "started": False,
               "ownership_verified": False, "cleanup_verified": False,
               "timeout_seconds": timeout, "queue_timeout_seconds": queue_timeout,
               "memory_limit": f"{memory_mb}Mi" if memory_mb is not None else None}

    def verify_envelope(row):
        host = row.get("HostConfig") or {}
        if memory_mb is not None and (host.get("Memory") != memory_mb * 1024**2
                                      or host.get("MemorySwap") != memory_mb * 1024**2):
            receipt["resource_envelope_verified"] = False
            raise RuntimeError("Docker analyzer daemon memory limit differs from the captured resource policy")
        receipt["resource_envelope_verified"] = memory_mb is not None

    async def call(*args, timeout=30, output_limit=64000, allocation=False):
        task = asyncio.create_task(_docker(*args, timeout=timeout, output_limit=output_limit))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError as interrupted:
            if not allocation:
                task.cancel()
            try:
                await _settle(task)
            except BaseException:
                pass
            raise interrupted

    async def inspect_owned():
        nonlocal container_id, image_id
        observed = await call("container", "inspect", container_id or name, timeout=15)
        if observed["returncode"]:
            raise DockerAnalyzerCleanupError("Docker analyzer identity could not be inspected; absence is unverified")
        if observed.get("output_truncated"):
            raise DockerAnalyzerCleanupError("Docker analyzer identity response was truncated")
        try:
            rows = json.loads(observed["stdout"])
            row = rows[0] if isinstance(rows, list) and len(rows) == 1 else {}
            actual = row.get("Id", "")
            observed_image = row.get("Image", "")
            if (not re.fullmatch(r"[a-f0-9]{64}", actual)
                    or (container_id and actual != container_id)
                    or row.get("Name") != "/" + name
                    or row.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) != owner
                    or row.get("Config", {}).get("Image") != image
                    or not re.fullmatch(r"sha256:[a-f0-9]{64}", observed_image)
                    or (image_id and observed_image != image_id)):
                raise ValueError("ownership mismatch")
        except (ValueError, TypeError, AttributeError):
            raise DockerAnalyzerCleanupError("Docker analyzer immutable identity/ownership mismatch; no unverified container was started or deleted") from None
        container_id, image_id = actual, observed_image
        receipt.update(container_id=container_id, image_id=image_id, ownership_verified=True)
        return row

    async def cleanup():
        row = await inspect_owned()
        try:
            verify_envelope(row)
        except RuntimeError:
            # A bad envelope forbids execution/resource-retry evidence, but
            # does not prevent removal of this exact owned allocation.
            pass
        removed = await call("rm", "--force", "--volumes", container_id, timeout=30)
        if removed["returncode"]:
            raise DockerAnalyzerCleanupError("Owned Docker analyzer removal failed; cleanup remains unverified")
        # Successful exact-ID removal plus an exact no-such-container response
        # establishes absence. A daemon outage or ambiguous inspect is a gap.
        absent = await call("container", "inspect", container_id, timeout=15)
        if (absent["returncode"] == 0 or container_id not in absent["stderr"]
                or not re.search(r"No such (?:container|object):", absent["stderr"], re.I)):
            raise DockerAnalyzerCleanupError("Owned Docker analyzer absence could not be verified after removal")
        receipt["cleanup_verified"] = True

    original_error = None
    try:
        queue_started = time.monotonic()
        try:
            allocated = await call(*create, timeout=queue_timeout, allocation=True)
        except asyncio.TimeoutError:
            receipt["classification"] = "queue_timeout"
            raise
        finally:
            receipt["queue_duration_seconds"] = round(time.monotonic() - queue_started, 3)
        allocation_returned = True
        if allocated["returncode"] or allocated.get("output_truncated"):
            raise RuntimeError("Docker analyzer allocation failed; no target command was started")
        proposed = allocated["stdout"].strip()
        if not re.fullmatch(r"[a-f0-9]{64}", proposed):
            raise RuntimeError("Docker analyzer allocation returned no immutable container identity")
        container_id = proposed
        before = await inspect_owned()
        verify_envelope(before)
        if before.get("State", {}).get("Status") != "created" or before["State"].get("Running") is not False:
            raise RuntimeError("Docker analyzer was not an unstarted owned container")
        receipt["started"] = True
        execution_started = time.monotonic()
        try:
            result = await call("start", "--attach", container_id, timeout=timeout, output_limit=_OUTPUT_LIMIT)
        except asyncio.TimeoutError:
            receipt["classification"] = "execution_timeout"
            return "", "Docker analyzer timed out; incomplete output discarded", -1
        finally:
            receipt["execution_duration_seconds"] = round(time.monotonic() - execution_started, 3)
        after = await inspect_owned()
        verify_envelope(after)
        state = after.get("State") or {}
        if state.get("Running") is not False or type(state.get("ExitCode")) is not int:
            return "", "Docker analyzer has no terminal container exit receipt", -1
        receipt.update(exit_code=state["ExitCode"], oom_killed=state.get("OOMKilled") is True)
        if state.get("OOMKilled") is True:
            receipt["classification"] = "oom_killed"
        if result.get("output_truncated"):
            return "", "Docker analyzer output exceeded its capture budget; coverage is incomplete", -1
        if result["returncode"] not in (0, state["ExitCode"]):
            return "", "Docker analyzer attach and container exit receipts disagree", -1
        return result["stdout"], result["stderr"], state["ExitCode"]
    except BaseException as error:
        original_error = error
        raise
    finally:
        receipt["allocation_returned"] = allocation_returned
        clean = asyncio.create_task(cleanup())
        try:
            await asyncio.shield(clean)
        except asyncio.CancelledError as interrupted:
            try:
                await _settle(clean)
            except Exception as cleanup_error:
                receipt["cleanup_error"] = str(cleanup_error)
                interrupted.cleanup_gap = str(cleanup_error)
            raise
        except Exception as cleanup_error:
            receipt["cleanup_error"] = str(cleanup_error)
            logging.getLogger(__name__).warning("Docker analyzer cleanup remains unverified: %s", cleanup_error)
            if original_error is not None:
                original_error.cleanup_gap = str(cleanup_error)
                if isinstance(original_error, Exception):
                    raise DockerAnalyzerCleanupError(f"{original_error}; {cleanup_error}") from original_error
            else:
                raise
        finally:
            if diagnostic_sink is not None:
                try:
                    diagnostic_sink(dict(receipt))
                except Exception:
                    logging.getLogger(__name__).warning("Docker analyzer diagnostic delivery failed")
