"""Quiesce owned async work before a synchronous maintenance transaction."""
from __future__ import annotations

import asyncio
from collections import defaultdict


def drain_tasks(tasks, *, timeout=30):
    """Cancel on each task's event loop and wait for its finally blocks.

    Reset routes run in FastAPI's thread pool. Refuse same-loop invocation
    instead of blocking the event loop needed to finish cancellation.
    """
    groups = defaultdict(list)
    for task in set(tasks):
        if not task.done():
            groups[task.get_loop()].append(task)
    try:
        current = asyncio.get_running_loop()
    except RuntimeError:
        current = None
    if any(loop is current or not loop.is_running() for loop in groups):
        raise RuntimeError("owned tasks could not quiesce: reset requires their running event loops from a separate thread")

    async def cancel_and_drain(items):
        for task in items:
            task.cancel()
        await asyncio.gather(*items, return_exceptions=True)

    for loop, items in groups.items():
        future = asyncio.run_coroutine_threadsafe(cancel_and_drain(items), loop)
        try:
            future.result(timeout=max(0.1, timeout))
        except Exception as exc:
            # Do not cancel the cleanup future: subprocess finally blocks
            # still need to finish even though this reset was refused.
            raise RuntimeError("owned tasks did not quiesce before reset; retry after cleanup completes") from exc


def run_cleanup(factory):
    """Execute bounded runtime cleanup from the synchronous reset thread."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())
    raise RuntimeError("runtime cleanup requires the reset thread, not an active event loop")
