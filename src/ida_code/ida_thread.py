"""Single-threaded worker for serializing all idalib calls.

idalib's ``idapro`` module fixes thread affinity at import time and hangs when
called from any other thread. The MCP server runs on an asyncio event loop
(the main thread); fastmcp v3 dispatches sync ``def`` tools to a worker pool,
which would put each idalib call on a different thread.

This module provides one dedicated worker thread that owns idalib. Submit work
via ``submit()`` (sync) or ``on_ida_thread()`` (async). The worker starts
lazily on first submit and is joined at interpreter exit via ``atexit``.
"""

import asyncio
import atexit
import logging
import queue
import threading
from concurrent.futures import Future
from typing import Callable, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")

_SHUTDOWN = object()

_thread: threading.Thread | None = None
_queue: queue.Queue = queue.Queue()
_lock = threading.Lock()


def _worker_loop() -> None:
    log.debug("ida-thread worker started: tid=%d", threading.get_ident())
    while True:
        item = _queue.get()
        if item is _SHUTDOWN:
            log.debug("ida-thread shutdown sentinel received")
            return
        fn, args, kwargs, fut = item
        if not fut.set_running_or_notify_cancel():
            continue
        try:
            result = fn(*args, **kwargs)
        except BaseException as exc:
            fut.set_exception(exc)
        else:
            fut.set_result(result)


def _ensure_worker() -> None:
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    with _lock:
        if _thread is not None and _thread.is_alive():
            return
        _thread = threading.Thread(
            target=_worker_loop, name="ida-thread", daemon=True,
        )
        _thread.start()


def submit(fn: Callable[..., T], *args, **kwargs) -> Future:
    """Submit ``fn(*args, **kwargs)`` to the ida-thread.

    Returns a ``concurrent.futures.Future`` that resolves to the return value
    or raised exception. The worker is started lazily on the first call.
    """
    _ensure_worker()
    fut: Future = Future()
    _queue.put((fn, args, kwargs, fut))
    return fut


async def on_ida_thread(fn: Callable[..., T], *args, **kwargs) -> T:
    """Async equivalent of ``submit(...).result()`` — awaits on the asyncio loop."""
    return await asyncio.wrap_future(submit(fn, *args, **kwargs))


def get_thread_ident() -> int | None:
    """Return the worker thread's ident, or ``None`` if not started."""
    return _thread.ident if _thread is not None else None


@atexit.register
def _shutdown() -> None:
    if _thread is None:
        return
    _queue.put(_SHUTDOWN)
    _thread.join(timeout=10)
    if _thread.is_alive():
        log.warning("ida-thread did not shut down cleanly within 10s")
