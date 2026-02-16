# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - Unreleased

### Added

- **`open_database` `overwrite` flag** — Delete existing `.i64`/`.idb` database files before opening, forcing a fresh analysis from the original binary.
- **`close_database` tool** — Explicitly close the current database and free resources. Clears the executor namespace.
- **`execute_file` tool** — Run IDAPython script files directly by path. Optional `args` parameter for inline follow-up code in the same namespace.
- **Coding guidelines resources** — Three MCP Resources (`guidelines://standalone_script`, `guidelines://plugin`, `guidelines://idapython_script`) providing architecture templates and best practices for writing standalone idalib scripts, IDA plugins, and classic IDAPython scripts.
- **Execution timeout** — `execute` and `execute_file` now enforce a wall-clock timeout (default 30s, configurable via `timeout` parameter, 0 = unlimited). Prevents infinite loops from hanging the server.
- **Process-killing exception guard** — `SystemExit` and `KeyboardInterrupt` raised by user code are now intercepted and returned as error text instead of killing the server process.
- **`decompile` tool** — Decompile a function by name or address. Resolves names via `ida_name`, accepts hex/decimal addresses, returns pseudocode with a header comment. Requires Hex-Rays.
- **Structured logging** — All modules now use Python `logging`. Output goes to stderr (won't interfere with stdio MCP transport). Controlled via `LOG_LEVEL` env var (default `WARNING`).
- **Unit tests** — 35 tests covering executor (output capture, timeout, exception handling, namespace persistence, truncation) and doc_search (HTML stripping, scoring, excerpt extraction). Run with `uv run pytest`.
- **`open_database` timeout** — New `timeout` parameter (default 0 = unlimited) limits auto-analysis wait time. When the timeout expires, the database stays open with partial analysis and a warning is appended. Progress (function count) is logged during analysis.

### Changed

- **Auto-import idalib on startup** — `idapro` is now loaded automatically from `IDA_INSTALL_DIR/idalib/python/` and `IDADIR` is set via `os.environ.setdefault`. No manual `pip install` or `py-activate-idalib.py` needed.

## [0.1.0] - 2026-02-10

Initial release.

### Added

- **`open_database` tool** — Open binaries and IDA databases via idalib with auto-analysis support. Returns summary info: processor type, bitness, segments, entry points, function count.
- **`execute` tool** — Run arbitrary IDAPython code with persistent namespace across calls. Pre-imports common `ida_*` modules. Captures stdout/stderr with 50K character truncation.
- **`search_docs` tool** — Keyword search over IDA's HTML documentation (2628 indexed pages) and IDAPython API source files (`ida_*.py` signatures and docstrings).
- Implicit database lifecycle management (close-on-open, atexit cleanup).
- stdio MCP transport via fastmcp.
- Claude Code `.mcp.json` configuration template.
