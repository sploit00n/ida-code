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
- `session.py` — idalib lifecycle (imports `idapro` at module level — must be first)
- `executor.py` — `exec()` with persistent namespace and stdout/stderr capture
- `doc_search.py` — keyword search over IDA docs + Python API sources
- `example_search.py` — AST-based search over 125 official IDAPython example scripts
- `guidelines.py` — coding guideline templates (standalone scripts, plugins, IDAPython scripts)
- `snapshots.py` — database snapshot create/restore/remove via `ida_loader` + `ida_kernwin`
- `undo.py` — undo/redo status, perform undo/redo via `ida_undo`
- `comments.py` — comment get/set/delete (regular, repeatable, function, anterior, posterior)
- `structures.py` — struct/union list/get/create/edit/delete via `ida_typeinf` + `idc.parse_decls`
- `variables.py` — variable get/set (local via `ida_hexrays`, global via `ida_name` + `ida_typeinf`)
- `server.py` — FastMCP server with 26 tools and 3 resources (`guidelines://{target}`)

`__init__.py` imports `session` first to ensure `idapro` is loaded before any `ida_*` modules.

## Documentation

When adding or changing tools/features, update **all** docs files:
- `CLAUDE.md` — architecture list and tool count
- `README.md` — tool documentation, architecture tree, and tool count
- `CHANGELOG.md` — entry under the current unreleased version
- `TODO.md` — check off completed items or add new ones

## Key Constraints

- **Single-threaded**: idalib only supports one database at a time, all calls from the same thread
- **idapro import order**: `import idapro` must happen before any `ida_*` imports
- **Runtime dependency**: `idapro` is not in pyproject.toml — it's auto-imported from `IDA_INSTALL_DIR/idalib/python/` at startup
- **fastmcp**: Using the community `fastmcp` package (`from fastmcp import FastMCP`), not the official SDK's `mcp.server.fastmcp`
