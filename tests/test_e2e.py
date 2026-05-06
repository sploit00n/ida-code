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


async def _open_and_close(target_path: str) -> float:
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

        await asyncio.wait_for(
            client.call_tool("close_database", {}),
            timeout=10,
        )
    return elapsed


def test_open_database_via_in_process_client(target):
    """Open a real binary through the MCP tool surface and verify it returns
    a populated summary in well under the timeout. A future regression that
    routes idalib off the main thread would hit the 30s ``wait_for``."""
    elapsed = asyncio.run(_open_and_close(target))
    # Generous bound: 16KB binary, ~2s cold standalone. Anything near the
    # 30s ceiling means dispatch is wrong, not just slow.
    assert elapsed < 15, f"open took {elapsed:.1f}s — possible thread regression"
