"""Unit tests for the ida_thread worker primitive.

No idalib involved — these test the threading mechanics in isolation.
"""

import asyncio
import threading
import time

import pytest

from ida_code import ida_thread


def test_runs_on_distinct_worker_thread():
    """Submitted tasks run on a thread that's not the test/main thread."""
    main_tid = threading.get_ident()
    worker_tid = ida_thread.submit(threading.get_ident).result(timeout=5)
    assert worker_tid != main_tid
    assert worker_tid == ida_thread.get_thread_ident()


def test_serializes_calls_to_one_thread():
    """Multiple submits all run on the same worker."""
    tids = [
        ida_thread.submit(threading.get_ident).result(timeout=5)
        for _ in range(5)
    ]
    assert len(set(tids)) == 1, f"tasks ran on multiple threads: {set(tids)}"


def test_propagates_return_value():
    fut = ida_thread.submit(lambda x, y: x * y, 6, 7)
    assert fut.result(timeout=5) == 42


def test_propagates_exception():
    fut = ida_thread.submit(lambda: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        fut.result(timeout=5)


def test_kwargs_pass_through():
    def add(*, a, b):
        return a + b
    assert ida_thread.submit(add, a=10, b=32).result(timeout=5) == 42


def test_async_helper():
    async def call():
        return await ida_thread.on_ida_thread(threading.get_ident)
    main_tid = threading.get_ident()
    worker_tid = asyncio.run(call())
    assert worker_tid != main_tid


def test_failure_does_not_kill_worker():
    """A task that raises shouldn't bring down the worker — subsequent
    tasks must still run."""
    bad = ida_thread.submit(lambda: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        bad.result(timeout=5)
    assert ida_thread.submit(lambda: "ok").result(timeout=5) == "ok"


def test_cancelled_future_is_skipped():
    """A future cancelled before the worker picks it up is skipped, not run."""
    # Block the worker briefly so the next submit stays in queue.
    block = ida_thread.submit(time.sleep, 0.3)
    target = ida_thread.submit(lambda: pytest.fail("should not run"))
    assert target.cancel()
    block.result(timeout=5)
    assert target.cancelled()
    # And the worker is still healthy.
    assert ida_thread.submit(lambda: "alive").result(timeout=5) == "alive"


def test_shutdown_then_resubmit_creates_new_worker():
    """After ``_shutdown()`` is called, the next submit spawns a fresh worker."""
    ida_thread.submit(lambda: 1).result(timeout=5)
    old_thread = ida_thread._thread

    ida_thread._shutdown()
    assert old_thread is not None and not old_thread.is_alive()

    assert ida_thread.submit(lambda: 2).result(timeout=5) == 2
    new_thread = ida_thread._thread
    assert new_thread is not None
    assert new_thread is not old_thread
    assert new_thread.is_alive()
