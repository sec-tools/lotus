"""Docker VM memory admission gate.

Root cause this prevents: Lotus caps each container's RAM (``--memory``) but
nothing bounded the *sum* of concurrently-running containers. On a large repo
(e.g. kamaji) several Go analyzers ran at once, each allowed multiple GB, and
their total exceeded the Docker Desktop VM's memory. The VM then OOM'd and the
daemon had to be killed by hand -- taking every in-flight audit with it.

This module enforces a single, process-wide invariant: the total memory
*reserved* by admitted containers never exceeds a safe fraction of the Docker
VM's ``MemTotal``. A container that would push the total over budget waits until
earlier ones finish. Exactly one workload is always admitted (even if it alone
exceeds the budget) so the gate can never deadlock.

The gate is intentionally loop-agnostic: each audit runs on its own asyncio
event loop, so an ``asyncio.Semaphore`` (which binds to one loop) is unusable.
A ``threading.Lock`` protects a shared counter; callers ``await asyncio.sleep``
between attempts, which yields correctly on whichever loop they run on.
"""
from __future__ import annotations

import asyncio
import os
import re
import subprocess
import threading
from contextlib import asynccontextmanager
from typing import Optional

_LOCK = threading.Lock()
_reserved_mb = 0
_budget_mb: Optional[int] = None


def parse_memory_to_mb(value) -> int:
    """Parse a docker memory string ("4g", "512m", "2048") to whole MiB."""
    s = str(value if value is not None else "").strip().lower()
    if not s:
        return 0
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmgt]?)b?", s)
    if not m:
        return 0
    amount = float(m.group(1))
    unit = m.group(2) or "m"
    mult = {"k": 1.0 / 1024.0, "m": 1.0, "g": 1024.0, "t": 1024.0 * 1024.0}[unit]
    return max(0, int(amount * mult))


def _docker_vm_total_mb() -> int:
    """Best-effort Docker VM total memory in MiB (0 if the daemon is unreachable)."""
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.MemTotal}}"],
            capture_output=True, text=True, timeout=10,
        )
        total_bytes = int((proc.stdout or "0").strip() or 0)
        if total_bytes > 0:
            return total_bytes // (1024 * 1024)
    except (subprocess.SubprocessError, ValueError, OSError):
        pass
    return 0


def budget_mb() -> int:
    """Resolve (and cache) the container-memory budget in MiB.

    ``LOTUS_DOCKER_MEM_BUDGET_MB`` pins an explicit ceiling. Otherwise the budget
    is ``LOTUS_DOCKER_MEM_FRACTION`` (default 0.7) of the Docker VM's total, which
    leaves headroom for the daemon and BuildKit. If the daemon can't be queried,
    fall back to ``LOTUS_DOCKER_MEM_BUDGET_FALLBACK_MB`` (default 6144).
    """
    global _budget_mb
    if _budget_mb is not None:
        return _budget_mb
    override = (os.environ.get("LOTUS_DOCKER_MEM_BUDGET_MB") or "").strip()
    if override.isdigit():
        _budget_mb = max(256, int(override))
        return _budget_mb
    total = _docker_vm_total_mb()
    try:
        frac = float(os.environ.get("LOTUS_DOCKER_MEM_FRACTION", "0.7") or 0.7)
    except ValueError:
        frac = 0.7
    frac = min(0.95, max(0.1, frac))
    if total > 0:
        _budget_mb = max(512, int(total * frac))
    else:
        try:
            _budget_mb = max(512, int(os.environ.get("LOTUS_DOCKER_MEM_BUDGET_FALLBACK_MB", "6144") or 6144))
        except ValueError:
            _budget_mb = 6144
    return _budget_mb


def reserved_mb() -> int:
    with _LOCK:
        return _reserved_mb


def reset_for_tests(budget: Optional[int] = None) -> None:
    """Test hook: pin the budget and clear reservations."""
    global _budget_mb, _reserved_mb
    _budget_mb = budget
    _reserved_mb = 0


def _try_reserve(mb: int, budget: int) -> bool:
    global _reserved_mb
    with _LOCK:
        # Always admit one workload even if it alone exceeds the budget, so the
        # gate cannot deadlock on an oversized (but individually capped) run.
        if _reserved_mb == 0 or _reserved_mb + mb <= budget:
            _reserved_mb += mb
            return True
        return False


def _force_reserve(mb: int) -> None:
    global _reserved_mb
    with _LOCK:
        _reserved_mb += mb


def _release(mb: int) -> None:
    global _reserved_mb
    with _LOCK:
        _reserved_mb = max(0, _reserved_mb - mb)


@asynccontextmanager
async def reserve(mem_mb, *, label: str = "container", poll: float = 0.5,
                  timeout: float = 1800.0):
    """Admit a container only when its ``mem_mb`` fits under the global budget.

    A zero/unknown request is not gated. After ``timeout`` seconds of waiting the
    gate fails open (reserves anyway) so a stuck peer can never permanently stall
    an audit; the per-container ``--memory`` cap still bounds the workload.
    """
    mb = max(0, int(mem_mb or 0))
    if mb <= 0:
        yield
        return
    try:
        loop = asyncio.get_event_loop()
        budget = await loop.run_in_executor(None, budget_mb)
    except Exception:
        budget = budget_mb()
    waited = 0.0
    admitted = False
    while True:
        if _try_reserve(mb, budget):
            admitted = True
            break
        if waited >= timeout:
            # Fail open: reserve unconditionally so a stuck peer can never stall
            # an audit forever. The per-container --memory cap still applies.
            _force_reserve(mb)
            admitted = True
            break
        await asyncio.sleep(poll)
        waited += poll
    try:
        yield
    finally:
        if admitted:
            _release(mb)
