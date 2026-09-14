"""Resource governance for Lotus audits.

Lotus runs static analysis, containerized labs, fuzzers and multiple concurrent
scans on whatever host it is deployed to - a laptop, a CI runner, or a large
server. Without governance a single heavy repository can exhaust host RAM or disk
and take down every concurrent audit. This module provides:

* Host detection (``host_resources``) with a graceful fallback when ``psutil`` is
  not installed - it degrades to ``os``/``shutil`` primitives so the platform keeps
  working, just with coarser numbers.
* Adaptive defaults (``recommended_resources``) that scale concurrency and memory
  ceilings to the detected host and deployment environment (respecting cgroup
  limits inside containers).
* Live sampling (``sample``) and limit evaluation (``evaluate``) that classify the
  current pressure as ``ok`` / ``warn`` / ``critical`` against user-configured
  limits, so the caller can notify the operator via the internal message system
  and optionally pause or abort.

The module is intentionally free of any web-framework or database imports so it
can be unit-tested in isolation and reused anywhere.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

try:  # psutil is optional - the module degrades gracefully without it.
    import psutil  # type: ignore

    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover - exercised only where psutil is absent
    psutil = None  # type: ignore
    _HAVE_PSUTIL = False


MB = 1024 * 1024
# Existing *_mb API/settings fields use binary MiB. Keep those numeric contracts.
_DISK_WARN_FREE_MB = 10 * 1024
_DISK_CRITICAL_FREE_MB = 4 * 1024
_DISK_MIN_FREE_MB = 1024


def _human_mib(value: float) -> str:
    """Format a binary MiB value without changing its wire representation."""
    amount = float(value)
    for unit in ("MiB", "GiB", "TiB", "PiB"):
        if abs(amount) < 1024 or unit == "PiB":
            return f"{amount:,.1f}".rstrip("0").rstrip(".") + f" {unit}"
        amount /= 1024
    raise AssertionError("unreachable")


def have_psutil() -> bool:
    return _HAVE_PSUTIL


# ---------------------------------------------------------------------------
# Host detection
# ---------------------------------------------------------------------------

def _cgroup_memory_usage_bytes() -> Optional[int]:
    for path in ("/sys/fs/cgroup/memory.current",
                 "/sys/fs/cgroup/memory/memory.usage_in_bytes"):
        try:
            with open(path, encoding="utf-8") as handle:
                value = int(handle.read().strip())
            if value >= 0:
                return value
        except (OSError, ValueError):
            continue
    return None


def _cgroup_memory_limit_bytes() -> Optional[int]:
    """Return the cgroup memory limit in bytes when running inside a container.

    Supports both cgroup v2 (``memory.max``) and v1 (``memory.limit_in_bytes``).
    Returns ``None`` when unconstrained or unreadable so callers fall back to the
    physical host total.
    """
    candidates = (
        "/sys/fs/cgroup/memory.max",  # cgroup v2
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",  # cgroup v1
    )
    for path in candidates:
        try:
            raw = open(path, "r", encoding="utf-8").read().strip()
        except Exception:
            continue
        if raw in ("max", ""):
            return None
        try:
            val = int(raw)
        except ValueError:
            continue
        # Kernels report "no limit" as a huge sentinel; treat >= 1 PiB as unlimited.
        if val <= 0 or val >= (1 << 50):
            return None
        return val
    return None


def host_resources(workspace: Optional[str] = None) -> Dict[str, Any]:
    """Detect the resources actually available to this process.

    ``workspace`` is the path whose filesystem should be measured for disk (the
    audit workspace); defaults to the current working directory.
    """
    path = workspace or os.getcwd()
    info: Dict[str, Any] = {
        "psutil": _HAVE_PSUTIL,
        "cpu_count": os.cpu_count() or 1,
        "containerized": os.path.exists("/.dockerenv") or _cgroup_memory_limit_bytes() is not None,
    }

    total_mem = 0
    available_mem = 0
    if _HAVE_PSUTIL:
        vm = psutil.virtual_memory()
        total_mem = int(vm.total)
        available_mem = int(vm.available)
    else:
        # POSIX fallback via sysconf; may be unavailable on some platforms.
        try:
            total_mem = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        except (ValueError, OSError, AttributeError):
            total_mem = 0
        available_mem = total_mem  # best effort without psutil

    # Respect a tighter cgroup ceiling when containerized.
    cg = _cgroup_memory_limit_bytes()
    if cg:
        total_mem = min(total_mem, cg) if total_mem else cg
        current = _cgroup_memory_usage_bytes()
        available_mem = max(0, total_mem - current) if current is not None else min(available_mem or cg, cg)

    try:
        du = shutil.disk_usage(path)
        disk_total, disk_free = int(du.total), int(du.free)
    except Exception:
        disk_total, disk_free = 0, 0

    info.update(
        total_mem_mb=total_mem // MB,
        available_mem_mb=available_mem // MB,
        disk_total_mb=disk_total // MB,
        disk_free_mb=disk_free // MB,
    )
    return info


# ---------------------------------------------------------------------------
# Adaptive defaults
# ---------------------------------------------------------------------------

def recommended_resources(host: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Compute sensible, host-scaled defaults for concurrency and ceilings.

    The goal is antifragility: on a small host we throttle hard; on a big host we
    use more, but always leave headroom for the OS and other processes.
    """
    h = host or host_resources()
    cpu = max(1, int(h.get("cpu_count", 1)))
    total_mem_mb = max(0, int(h.get("total_mem_mb", 0)))
    disk_free_mb = max(0, int(h.get("disk_free_mb", 0)))

    # Concurrency scales with cores but is capped to avoid thrashing.
    max_concurrent_scans = max(1, min(8, cpu // 2 or 1))
    max_concurrent_tools = max(2, min(16, cpu * 2))

    # Memory ceiling: 70% of total RAM leaves headroom for the OS + docker daemon.
    # Fall back to a conservative 2 GiB when detection failed.
    if total_mem_mb > 0:
        max_memory_mb = int(total_mem_mb * 0.70)
    else:
        max_memory_mb = 2048

    # Lab container gets at most half the audit memory ceiling, clamped to a
    # usable range so builds have room but can never eat the whole host.
    lab_memory_mb = max(512, min(8192, max_memory_mb // 2)) if max_memory_mb else 2048
    lab_cpus = float(max(1, min(cpu, 4)))

    # Disk ceiling: 80% of free space, capped so we never fully fill the volume.
    max_disk_mb = int(disk_free_mb * 0.80) if disk_free_mb > 0 else 0

    return {
        "max_concurrent_scans": max_concurrent_scans,
        "max_concurrent_tools": max_concurrent_tools,
        "max_memory_mb": max_memory_mb,
        "max_disk_mb": max_disk_mb,
        "lab_memory_mb": lab_memory_mb,
        "lab_cpus": lab_cpus,
    }


def effective_limits(settings: Any, host: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Resolve the *effective* limits used by :func:`evaluate`.

    The primary pressure signal is memory utilisation and filesystem headroom
    (how close the machine is to running out of resources), which causes audits to
    fail. ``max_memory_mb``/``max_disk_mb`` are *optional hard caps*: when set (>0)
    they add a second, tighter constraint (e.g. "audits on this shared box may not
    push total usage past 8 GiB"). ``0`` means no additional hard cap.

    We deliberately do NOT auto-populate the hard caps from adaptive defaults: a
    70%-of-RAM budget compared against system-wide usage would false-trigger on any
    host already above that line. Adaptive values are surfaced for the UI and for
    concurrency via :func:`recommended_resources` instead.
    """
    h = host or host_resources()
    return {
        # 0 = no explicit hard cap; evaluation falls back to host utilisation %.
        "max_memory_mb": int(_attr(settings, "max_memory_mb", 0) or 0),
        "max_disk_mb": int(_attr(settings, "max_disk_mb", 0) or 0),
        "warn_pct": int(_attr(settings, "resource_warn_pct", 80)),
        "critical_pct": int(_attr(settings, "resource_critical_pct", 95)),
        "action": _attr(settings, "resource_action", "notify"),
        "host": h,
    }


# ---------------------------------------------------------------------------
# Live sampling + evaluation
# ---------------------------------------------------------------------------

@dataclass
class ResourceSnapshot:
    used_mem_mb: int
    total_mem_mb: int
    available_mem_mb: int
    disk_used_mb: int
    disk_total_mb: int
    disk_free_mb: int
    proc_rss_mb: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)


def sample(workspace: Optional[str] = None) -> ResourceSnapshot:
    """Take a point-in-time snapshot of memory + disk usage."""
    path = workspace or os.getcwd()
    if _HAVE_PSUTIL:
        vm = psutil.virtual_memory()
        used_mem = int(vm.total - vm.available)
        total_mem = int(vm.total)
        avail_mem = int(vm.available)
        try:
            proc_rss = int(psutil.Process().memory_info().rss)
        except Exception:
            proc_rss = 0
    else:
        h = host_resources(path)
        total_mem = h["total_mem_mb"] * MB
        avail_mem = h["available_mem_mb"] * MB
        used_mem = max(0, total_mem - avail_mem)
        proc_rss = 0

    scope = "host"
    cg = _cgroup_memory_limit_bytes()
    if cg:
        total_mem = min(total_mem, cg)
        # Host utilisation and a Pod's limit are different accounting domains.
        # Use the same cgroup's current usage, including its child processes.
        current = _cgroup_memory_usage_bytes()
        if current is not None:
            used_mem = current
            scope = "cgroup"
        else:
            # An unreadable cgroup counter is explicit incomplete telemetry;
            # never manufacture >100% Pod pressure from the node's usage.
            used_mem = min(total_mem, proc_rss)
            scope = "process-fallback"
        avail_mem = max(0, total_mem - used_mem)

    try:
        du = shutil.disk_usage(path)
        disk_total, disk_free = int(du.total), int(du.free)
        disk_used = int(du.used)
    except Exception:
        disk_total = disk_free = disk_used = 0

    return ResourceSnapshot(
        used_mem_mb=used_mem // MB,
        total_mem_mb=total_mem // MB,
        available_mem_mb=avail_mem // MB,
        disk_used_mb=disk_used // MB,
        disk_total_mb=disk_total // MB,
        disk_free_mb=disk_free // MB,
        proc_rss_mb=proc_rss // MB,
        extra={"memory_scope": scope, "disk_scope": "filesystem"},
    )


def _pct(used: float, limit: float) -> float:
    if limit <= 0:
        return 0.0
    return round(100.0 * used / limit, 1)


def evaluate(snap: ResourceSnapshot, limits: Dict[str, Any]) -> Dict[str, Any]:
    """Classify a snapshot against limits.

    Memory uses its sampled accounting scope. Filesystem percentage thresholds
    also require low available space: warn below 10 GiB, critical below 4 GiB.
    Independently, less than 4 GiB free warns and less than 1 GiB is critical,
    including on a small filesystem whose percentage is low. Explicit caps remain
    independent, stricter signals. Disk capacity includes reserved/unavailable
    space, which is reported separately from measured allocated bytes.

    Returns an overall ``level`` (``ok`` | ``warn`` | ``critical``), per-resource
    detail, and a human-readable ``message`` for the worst offender.
    """
    warn = float(limits.get("warn_pct", 80))
    crit = float(limits.get("critical_pct", 95))
    mem_cap = float(limits.get("max_memory_mb", 0) or 0)
    disk_cap = float(limits.get("max_disk_mb", 0) or 0)

    # Host utilisation (primary signal) + optional hard-cap utilisation (secondary).
    mem_host_pct = _pct(snap.used_mem_mb, snap.total_mem_mb)
    mem_cap_pct = _pct(snap.used_mem_mb, mem_cap) if mem_cap else 0.0
    mem_pct = max(mem_host_pct, mem_cap_pct)

    disk_unavailable = max(snap.disk_used_mb, snap.disk_total_mb - snap.disk_free_mb)
    disk_reserved = max(0, disk_unavailable - snap.disk_used_mb)
    disk_host_pct = _pct(disk_unavailable, snap.disk_total_mb)
    # Preserve the existing cap's conservative total-minus-available accounting.
    disk_cap_pct = _pct(disk_unavailable, disk_cap) if disk_cap else 0.0
    disk_pct = max(disk_host_pct, disk_cap_pct)

    def level_for(pct: float, measurable: bool) -> str:
        if not measurable:
            return "ok"
        if pct >= crit:
            return "critical"
        if pct >= warn:
            return "warn"
        return "ok"

    mem_level = level_for(mem_pct, snap.total_mem_mb > 0)
    order = {"ok": 0, "warn": 1, "critical": 2}
    disk_host_level = "ok"
    if snap.disk_total_mb > 0:
        if snap.disk_free_mb < _DISK_MIN_FREE_MB or (
            disk_host_pct >= crit and snap.disk_free_mb < _DISK_CRITICAL_FREE_MB
        ):
            disk_host_level = "critical"
        elif snap.disk_free_mb < _DISK_CRITICAL_FREE_MB or (
            disk_host_pct >= warn and snap.disk_free_mb < _DISK_WARN_FREE_MB
        ):
            disk_host_level = "warn"
    disk_cap_level = level_for(disk_cap_pct, disk_cap > 0)
    disk_level = max((disk_host_level, disk_cap_level), key=order.__getitem__)
    level = max((mem_level, disk_level), key=lambda l: order[l])
    worst = "memory" if order[mem_level] >= order[disk_level] else "disk"

    cap_note_mem = f", cap {_human_mib(mem_cap)}" if mem_cap else ""
    cap_note_disk = f", cap {_human_mib(disk_cap)}" if disk_cap else ""
    reserved_note = f", {_human_mib(disk_reserved)} reserved/unavailable" if disk_reserved else ""
    scope_note = {
        "cgroup": "container cgroup: ",
        "process-fallback": "process fallback, incomplete container telemetry: ",
        "host": "host: ",
    }.get(snap.extra.get("memory_scope"), "")
    if level == "ok":
        message = "Resources nominal"
    elif worst == "memory":
        message = (
            f"Memory pressure {mem_pct:.0f}% "
            f"({scope_note}{_human_mib(snap.used_mem_mb)} used / {_human_mib(snap.total_mem_mb)}{cap_note_mem}, "
            f"{_human_mib(snap.available_mem_mb)} available)"
        )
    else:
        message = (
            f"Disk pressure {disk_pct:.0f}% "
            f"({_human_mib(snap.disk_used_mb)} allocated / {_human_mib(snap.disk_total_mb)} total{cap_note_disk}, "
            f"{_human_mib(snap.disk_free_mb)} free{reserved_note})"
        )

    return {
        "level": level,
        "worst": worst,
        "message": message,
        "memory": {
            "used_mb": snap.used_mem_mb, "total_mb": snap.total_mem_mb,
            "cap_mb": int(mem_cap), "pct": mem_pct, "level": mem_level,
            "available_mb": snap.available_mem_mb,
            "scope": snap.extra.get("memory_scope", "unknown"),
        },
        "disk": {
            "used_mb": snap.disk_used_mb, "total_mb": snap.disk_total_mb,
            "cap_mb": int(disk_cap), "pct": disk_pct, "level": disk_level,
            "free_mb": snap.disk_free_mb, "unavailable_mb": disk_unavailable,
            "reserved_mb": disk_reserved, "scope": "filesystem",
            "filesystem_pct": disk_host_pct, "cap_pct": disk_cap_pct,
            "filesystem_level": disk_host_level, "cap_level": disk_cap_level,
        },
        "proc_rss_mb": snap.proc_rss_mb,
    }


def _attr(obj: Any, name: str, default: Any) -> Any:
    """Read ``name`` from an object or dict, returning ``default`` if missing/None."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        val = obj.get(name, default)
    else:
        val = getattr(obj, name, default)
    return default if val is None else val
