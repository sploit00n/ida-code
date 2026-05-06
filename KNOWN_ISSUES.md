# Known issues

Caveats and gotchas worth knowing before debugging — for humans and AI agents working on this repo.

## fastmcp v3 hangs every idalib tool call

**Status:** worked around by pinning `fastmcp>=2.0,<3` in `pyproject.toml`.

**Symptom:** Any tool that calls into idalib (`open_database`, `decompile`, `list_functions`, etc.) hangs indefinitely under fastmcp v3 (3.2.4). Tools that don't touch idalib (`get_server_status`, `list_architectures`, `search_docs`, `search_examples`) work fine. After a user-cancel, fastmcp v3 also drops the stdio connection and Claude Code reports `[Tool result missing due to internal error]` until `/mcp` reconnect.

**Cause:** idalib hangs when called from any thread other than the one that imported `idapro` — verified standalone with `threading.Thread(target=session.open).start()`, no MCP involved. fastmcp v3 dispatches sync `def` tools via `anyio.to_thread.run_sync`, putting every call on a worker thread. fastmcp v2 runs sync tools on the asyncio main thread (blocking the event loop during the call), which keeps idalib happy.

**Workaround:** stay on fastmcp v2. Verified: a call that hung indefinitely on v3 returns in 710ms on v2.14.7.

**Future v3+ migration path:** spawn a dedicated worker thread at server startup that owns idalib, route every idalib-touching tool through it via callable + Future. The same thread must also be the one that runs `import idapro` (currently at the top of `session.py`).

## `open_database` returns `code -1` after partial unpacking

**Status:** fixed in 0.2.x by `overwrite=True` cleaning `.id0/.id1/.id2/.nam/.til` (commit `4ae6e24`).

If you still see this, a previous open created unpacked database fragments and a later open is refusing to overwrite them. Re-call with `overwrite=True` to clear them, or delete them manually.

## idalib state corruption after user-cancel

**Symptom:** after cancelling an in-flight `open_database`, subsequent opens return `-1` instantly with no I/O — the server process is permanently broken.

**Cause:** Python can't kill a thread mid-syscall, so a cancelled `idapro.open_database` leaves an executor thread stuck inside the C call. Even after the cancel propagates back through asyncio, idalib's internal state stays partly initialized.

**Workaround:** kill the MCP server process and reconnect. There is no in-process recovery.
