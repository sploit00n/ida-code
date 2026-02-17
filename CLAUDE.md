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

## Architecture

- `config.py` — env-based config (`IDA_INSTALL_DIR`)
- `session.py` — idalib lifecycle (imports `idapro` at module level — must be first)
- `executor.py` — `exec()` with persistent namespace and stdout/stderr capture
- `doc_search.py` — keyword search over IDA docs + Python API sources
- `example_search.py` — AST-based search over 125 official IDAPython example scripts
- `guidelines.py` — coding guideline templates (standalone scripts, plugins, IDAPython scripts)
- `server.py` — FastMCP server with 9 tools and 3 resources (`guidelines://{target}`)

`__init__.py` imports `session` first to ensure `idapro` is loaded before any `ida_*` modules.

## Key Constraints

- **Single-threaded**: idalib only supports one database at a time, all calls from the same thread
- **idapro import order**: `import idapro` must happen before any `ida_*` imports
- **Runtime dependency**: `idapro` is not in pyproject.toml — it's auto-imported from `IDA_INSTALL_DIR/idalib/python/` at startup
- **fastmcp**: Using the community `fastmcp` package (`from fastmcp import FastMCP`), not the official SDK's `mcp.server.fastmcp`
