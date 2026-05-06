# Known issues

Caveats and gotchas worth knowing before debugging — for humans and AI agents working on this repo.

## fastmcp v3 — checklist before migrating

We pin `fastmcp>=2.0,<3` in `pyproject.toml`. Don't bump past v2 without first addressing every item below. The root cause of all three is the same: v3 dispatches sync `def` tools via `anyio.to_thread.run_sync` (worker pool), but idalib only works on the thread that imported `idapro`. v2 runs sync tools on the asyncio main thread, sidestepping this.

Verified standalone with no MCP involved: `threading.Thread(target=session.open).start()` hangs the same way under both versions. The thread regression test in `tests/test_e2e.py` will catch a future bump that reintroduces this.

### 1. Sync-tool dispatch hangs idalib

Under v3, every tool that calls into idalib (`open_database`, `decompile`, `list_functions`, etc.) hangs indefinitely. Tools that don't touch idalib (`list_architectures`, `search_docs`, `search_examples`) work fine.

**Fix path:** spawn a dedicated worker thread at server startup that owns idalib. Route every idalib-touching tool through it via callable + Future. The same thread must run `import idapro` (currently at the top of `session.py`).

### 2. User-cancel tears down stdio

After the user cancels a hung tool call, fastmcp v3 drops the stdio connection. Claude Code does not auto-reconnect, so every subsequent tool call returns `[Tool result missing due to internal error]` until `/mcp` reconnect. v2 keeps stdio alive across cancels.

**Fix path:** likely resolves itself once #1 is addressed (no more hangs to cancel). If not, configure fastmcp to keep stdio across cancels, or wrap the transport.

### 3. User-cancel corrupts idalib state

If a user cancels an in-flight `open_database` call under v3, subsequent opens return `-1` instantly with no I/O — the server process stays broken until killed. Mechanism: Python can't kill a thread mid-syscall, so the cancelled C call leaves the worker stuck inside `idapro.open_database`; even after asyncio handles the cancel, idalib's internal state stays partly initialized. Doesn't manifest under v2 because the call runs on the main thread (blocking the loop) and either completes or doesn't start.

**Fix path:** also resolves with #1 — running idalib on a dedicated thread we own means we can decline to dispatch a new call while the previous one is still executing, and we never hand idalib to a thread that disappears mid-call.
