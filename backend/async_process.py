"""Safe lifecycle helpers for asyncio subprocesses.

``asyncio.wait_for(proc.communicate())`` cancels the communicate coroutine on a
timeout, but it does not stop the child process.  Merely awaiting ``proc.wait``
after killing the child can also leave stdout/stderr pipe transports attached to
a loop that is about to close on Python 3.9.  This helper always tries to drain
those pipes before returning and is deliberately best-effort: a cleanup error
must never replace the original tool timeout/error.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from typing import Any


def _close_transport(proc: Any) -> None:
    """Close the subprocess transport before its owning loop is torn down.

    Python 3.9 can leave PIPE transports alive after a cancelled
    ``communicate()`` even when the child has been reaped.  Closing the
    transport here prevents the late ``BaseSubprocessTransport.__del__``
    callback from trying to schedule work on an already-closed event loop.
    """
    try:
        transport = getattr(proc, "_transport", None)
        if transport is not None:
            transport.close()
    except Exception:
        pass


async def terminate_and_reap(proc: Any, *, timeout: float = 5.0, process_group: bool = False) -> None:
    """Kill a child if needed, then wait and drain its pipe transports safely."""
    if proc is None:
        return
    # Opt in only for a child created with start_new_session=True. Its process
    # group also owns ordinary descendants that inherited output pipes, even
    # when the original leader has already exited. Container daemon workloads
    # require their separate container/Pod ownership cleanup.
    pid = getattr(proc, "pid", None)
    if process_group and os.name == "posix" and type(pid) is int and pid > 1:
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            logging.getLogger(__name__).warning("Owned process group cleanup failed for %s: %s", pid, error)
    try:
        running = getattr(proc, "returncode", None) is None
    except Exception:
        running = False
    if running:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        except Exception:
            # Keep trying to wait/drain: another owner may have already ended
            # the child between the return-code check and kill call.
            pass

    # `communicate()` consumes stdout/stderr and lets asyncio retire the pipe
    # transports.  This is stronger than `wait()` alone for a timed-out child.
    communicate = getattr(proc, "communicate", None)
    try:
        if callable(communicate):
            try:
                await asyncio.wait_for(communicate(), timeout=max(0.1, float(timeout)))
                return
            except Exception:
                pass

        waiter = getattr(proc, "wait", None)
        if callable(waiter):
            try:
                await asyncio.wait_for(waiter(), timeout=max(0.1, float(timeout)))
            except Exception:
                pass
    finally:
        _close_transport(proc)
