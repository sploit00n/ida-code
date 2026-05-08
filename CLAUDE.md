# ida-code

MCP server for AI-assisted IDAPython scripting via idalib.

## Build & Run

```bash
uv sync                    # install dependencies
uv run ida-code            # run the server (stdio transport)
```

idalib is loaded automatically from `IDA_INSTALL_DIR/idalib/python/` at startup.

```bash
uv sync --extra dev         # install dev dependencies (pytest)
uv run pytest               # run unit tests
```

## Transport Modes

```bash
uv run ida-code                          # stdio (default)
uv run ida-code --http                   # streamable-http on 127.0.0.1:8080
uv run ida-code --http 0.0.0.0:9090     # streamable-http on custom host:port
uv run ida-code --sse                    # SSE on 127.0.0.1:8080
uv run ida-code --sse :9090             # SSE on 127.0.0.1:9090
```

HTTP/SSE modes require bearer token auth. Set `MCP_AUTH_TOKEN` env var or let the server generate one (printed to stderr on startup).

## Architecture

- `config.py` — env-based config (`IDA_INSTALL_DIR`)
- `ida_thread.py` — single dedicated worker thread that owns idalib. All idalib calls (open/close/decompile/etc.) dispatch through it via `submit()` or `await on_ida_thread()`. Lazy-started on first submit, joined at interpreter exit
- `session.py` — idalib lifecycle (imports `idapro` lazily inside `_ensure_idalib_loaded()` on the ida-thread); `require_open()` validates state + database file existence; `open/close/info` auto-dispatch to the ida-thread
- `macho.py` — fat Mach-O architecture listing and slice extraction via `lief`
- `executor.py` — `exec()` with persistent namespace and stdout/stderr capture
- `_search_utils.py` — shared search helpers: word-boundary matching (`term_matches`)
- `doc_search.py` — keyword search over IDA docs + Python API sources; field-weighted scoring, cross-links to examples
- `example_search.py` — AST-based search over 125 official IDAPython example scripts
- `guidelines.py` — coding guideline templates (standalone scripts, plugins, IDAPython scripts)
- `prompts.py` — MCP prompt templates (reverse engineering workflow, script creation guide)
- `snapshots.py` — database snapshot create/restore/delete via `ida_loader` + `ida_kernwin`
- `undo.py` — undo/redo status, perform undo/redo via `ida_undo`
- `comments.py` — comment get/set/delete (regular, repeatable, function, anterior, posterior)
- `structures.py` — struct/union list/get/create/edit/delete via `ida_typeinf` + `idc.parse_decls`
- `variables.py` — variable get/set (local via `ida_hexrays`, global via `ida_name` + `ida_typeinf`)
- `server.py` — FastMCP server with 35 tools, 3 resources, and 2 prompts

`__init__.py` imports `session` first; `idapro` itself is imported lazily on the ida-thread when an idalib call is first made.

## Documentation

When adding or changing tools/features, update **all** docs files:
- `CLAUDE.md` — architecture list and tool count
- `README.md` — tool documentation, architecture tree, and tool count
- `CHANGELOG.md` — entry under the current unreleased version
- `TODO.md` — check off completed items or add new ones

## Key Constraints

- **Single-threaded**: idalib only supports one database at a time, all calls from the thread that imported `idapro`. We pin that thread by routing every idalib call through `ida_thread.submit()` / `await ida_thread.on_ida_thread(...)`. Calling idalib from any other thread hangs indefinitely.
- **idapro import order**: `import idapro` happens lazily on the ida-thread (inside `_ensure_idalib_loaded()`); subsequent `ida_*` imports must happen on the same thread (i.e., inside functions dispatched through `ida_thread`).
- **Runtime dependency**: `idapro` is not in pyproject.toml — it's auto-imported from `IDA_INSTALL_DIR/idalib/python/` at startup
- **fastmcp**: Using the community `fastmcp` package (`from fastmcp import FastMCP`), not the official SDK's `mcp.server.fastmcp`. Range `>=2.0,<4`. v3 works because every idalib-touching tool is `async def` and dispatches through `ida_thread`.

Before chasing a hang/crash bug, check `KNOWN_ISSUES.md` first.
