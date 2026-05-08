# Known issues

Caveats and gotchas worth knowing before debugging — for humans and AI agents working on this repo.

## `execute` and `execute_file` have no timeout enforcement

The `timeout` parameter was removed in 0.2.3 along with the SIGALRM-based interrupt. SIGALRM only delivers to the process main thread, but user IDAPython code now runs on the dedicated ida-thread, so there is no portable cross-thread interrupt that's safe with idalib's C-level locks (`ctypes.PyThreadState_SetAsyncExc` is undefined behavior here).

If user code goes into an infinite loop or hangs inside an idalib call, the ida-thread stays busy until that call returns naturally; subsequent tool calls queue up. The asyncio event loop (and other transports) remain responsive, but no MCP client can extract idalib until the runaway call finishes. Practical recovery: kill the server process.

A future re-introduction could use `sys.settrace` line counting for pure-Python user code, but that won't help for the most common case (stuck inside one `ida_*` call), so it was deferred.
