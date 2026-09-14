"""Run synchronous analyzers without blocking their audit's control loop.

Cancellation interrupts owned Python work at a trace checkpoint, then waits for
that invocation to unwind before releasing its admission/source ownership. A C
extension or native wait cannot be killed safely as a Python thread: those keep
their existing runtime deadline and remain visibly pending until they return.
"""
import asyncio
import inspect
import logging
from pathlib import Path
import sys
import threading
import time

logger = logging.getLogger("lotus.analyzer_execution")
_OWNED_CODE_ROOT = str(Path(__file__).resolve().parent) + "/"
_TRACE_INTERVAL = 128
_CANCEL_NOTICE_SECONDS = 1.0


class _AnalyzerStopped(BaseException):
    """Private cooperative stop; ordinary scanner Exception handlers cannot hide it."""


def _invoke_sync(runner, stop):
    previous_trace = sys.gettrace()
    remaining = _TRACE_INTERVAL

    def checkpoint(frame, event, arg):
        nonlocal remaining
        remaining -= 1
        if remaining <= 0:
            remaining = _TRACE_INTERVAL
            if stop.is_set():
                raise _AnalyzerStopped()
        return checkpoint

    def trace_calls(frame, event, arg):
        # Filter once when entering a frame, avoiding a path check on every
        # source line. Never interrupt stdlib/SDK condition-lock restoration.
        if frame.f_code.co_filename.startswith(_OWNED_CODE_ROOT):
            return checkpoint(frame, event, arg)
        return None

    try:
        if stop.is_set():
            raise _AnalyzerStopped()
        # This modifies only the executor thread during this invocation, never
        # another audit, the API thread, or a subsequently reused worker.
        sys.settrace(trace_calls)
        return runner()
    finally:
        sys.settrace(previous_trace)


async def _report_cancellation_pending(repo_id, name):
    label = name or "synchronous analyzer"
    message = (f"Cancellation pending for {label}: waiting for owned native/C work "
               "to return and release its source access; cleanup is not complete.")
    logger.warning(message)
    if repo_id is None:
        return
    from backend import pipeline
    await pipeline._send(
        repo_id, message, level="warning", skip_control_check=True,
        detail_id=f"{repo_id}-analyzer-cancellation-{label}",
        detail={"kind": "task-console", "task": label, "status": "cancelling",
                "reason": message, "source_access_released": False},
    )


async def invoke_analyzer(runner, *, repo_id=None, name=None):
    # Coroutine bodies retain their owning loop and cancellation-aware native
    # subprocess/Job cleanup. Lambdas may return a coroutine or execute a full
    # synchronous scanner, so their invocation still needs an owned thread.
    if inspect.iscoroutinefunction(runner):
        return await runner()
    stop = threading.Event()
    invocation = asyncio.create_task(asyncio.to_thread(_invoke_sync, runner, stop))
    try:
        result = await asyncio.shield(invocation)
    except asyncio.CancelledError:
        stop.set()
        started = time.monotonic()
        notified = False
        while not invocation.done():
            try:
                # asyncio.wait never cancels the owned thread's Future on a
                # timeout or a repeated caller cancellation.
                await asyncio.wait([invocation], timeout=.1)
                if not invocation.done() and not notified and time.monotonic() - started >= _CANCEL_NOTICE_SECONDS:
                    notified = True
                    try:
                        await _report_cancellation_pending(repo_id, name)
                    except Exception:
                        logger.exception("Could not publish pending analyzer cancellation")
            except asyncio.CancelledError:
                continue
        try:
            result = invocation.result()
            if inspect.iscoroutine(result):
                result.close()
        except BaseException:
            pass
        raise
    if inspect.isawaitable(result):
        return await result
    return result
