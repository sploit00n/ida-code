"""End-to-end test exercising the MCP server through fastmcp's in-process
client. Regression guard: any change that pushes idalib calls onto a
worker thread (e.g. a future fastmcp version doing async-hygiene
dispatch of sync tools) hangs idalib and trips the asyncio timeout
below — failing fast instead of hanging CI indefinitely.

Auto-skipped when idalib isn't loadable.
"""

import asyncio
import shutil
import time
from pathlib import Path

import pytest

# Importing ida_code.session has the side effect of inserting idalib's
# python dir into sys.path and `import idapro`. If idalib isn't present
# the import fails — skip the whole module instead of erroring.
try:
    from ida_code import session
    from ida_code.server import mcp
except ImportError as exc:
    pytest.skip(f"idalib not available: {exc}", allow_module_level=True)

from fastmcp.client import Client  # noqa: E402
from fastmcp.client.transports import FastMCPTransport  # noqa: E402


def _venv_binary() -> Path:
    """A small native extension shipped in the venv — analyzes in ~2s cold."""
    import charset_normalizer.md as _md
    return Path(_md.__file__)


@pytest.fixture
def target(tmp_path):
    src = _venv_binary()
    if not src.is_file():
        pytest.skip(f"venv binary not found: {src}")
    dst = tmp_path / "target.so"
    shutil.copy(src, dst)
    yield str(dst)
    # Make sure no database stays open across tests.
    if session.get_state() == session.State.DATABASE_OPEN:
        try:
            session.close()
        except Exception:
            pass


async def _open_call_and_close(target_path: str) -> float:
    async with Client(FastMCPTransport(mcp)) as client:
        t0 = time.monotonic()
        r = await asyncio.wait_for(
            client.call_tool("open_database", {"path": target_path}),
            timeout=30,
        )
        elapsed = time.monotonic() - t0

        data = r.data if hasattr(r, "data") else r
        assert isinstance(data, dict), f"unexpected result type: {type(data)}"
        assert data.get("function_count", 0) > 0, f"no functions analyzed: {data}"

        # Regression guard for the "wrong thread" failure mode: any tool that
        # touches idalib via ida_funcs / idautils must dispatch correctly.
        # Pre-Phase-3 server.py would raise
        # ``RuntimeError: Function can be called from the main thread only``
        # because the tool body ran on whatever thread fastmcp dispatched it
        # to, not the ida-thread.
        r = await asyncio.wait_for(
            client.call_tool("list_functions", {"limit": 5}),
            timeout=10,
        )
        funcs = r.data if hasattr(r, "data") else r
        assert isinstance(funcs, dict)
        assert funcs.get("total", 0) > 0
        assert len(funcs.get("functions", [])) > 0

        await asyncio.wait_for(
            client.call_tool("close_database", {}),
            timeout=10,
        )
    return elapsed


def test_open_call_and_close_via_in_process_client(target):
    """Open a binary, call a non-open idalib tool, then close — through the
    fastmcp in-process client. Two regressions this guards against:

    1. idalib calls dispatched off the ida-thread hang or raise
       ``RuntimeError: Function can be called from the main thread only``.
    2. A future fastmcp version that routes sync tools through a worker
       pool would trip the 30s ``wait_for`` on open instead of hanging CI.
    """
    elapsed = asyncio.run(_open_call_and_close(target))
    # 16KB binary opens cold in ~2s standalone. Anything near 30s = dispatch
    # is broken, not just slow.
    assert elapsed < 15, f"open took {elapsed:.1f}s — possible thread regression"
