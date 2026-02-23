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
- **`get_database_info` tool** — Read-only tool returning current database summary (processor, segments, entry points, function count) without opening or closing anything.
- **`list_functions` tool** — Paginated function listing with address, size, and name. Supports `offset`/`limit` pagination and case-insensitive name `filter`.
- **REPL-like expression output** — `execute` now returns the `repr()` of the last expression if it's a bare expression (not an assignment or statement), just like the interactive Python prompt. No need to wrap everything in `print()`.
- **Database snapshots** — Four new tools for checkpointing and rolling back database state: `list_snapshots`, `create_snapshot`, `restore_snapshot`, `remove_snapshot`. Built on `ida_loader.snapshot_t` and `ida_kernwin.take_database_snapshot` / `restore_database_snapshot`.
- **`search_examples` tool** — Search 125 official IDAPython example scripts. Indexes metadata from `index.md` (title, description, keywords, APIs used, level, category) and AST-parses each `.py` file for imports, definitions, and `ida_*` API call patterns. Weighted scoring ranks API matches highest. Supports `category` and `level` filters.
- **Structure management tools** — Five new tools for managing IDA structs and unions: `list_structures` (paginated listing with filter), `get_structure` (detailed info with C definition), `create_structure` (from C definition string via `idc.parse_decls`), `edit_structure` (replace existing definition), `delete_structure` (remove from type library).
- **Variable management tools** — Two new tools for inspecting and modifying variables: `get_variable` (read local or global variable info) and `set_variable` (rename and/or retype). Local variables use Hex-Rays decompiler APIs (`ida_hexrays`); globals use `ida_name` and `ida_typeinf`.
- **Comment management tools** — Three new tools for managing comments: `get_comment` (read one or all comment types at an address), `set_comment` (write a comment), `delete_comment` (remove a comment). Supports all five IDA comment types: regular, repeatable, function, anterior, and posterior.
- **Undo/redo tools** — Three new tools for undoing and redoing database changes: `get_undo_status` (check availability and next action labels), `perform_undo` (undo one or more steps), `perform_redo` (redo one or more steps). Built on `ida_undo`. Multi-step undo/redo in a single call with partial success support.

### Changed

- **`execute` behavior** — Last-expression values are now auto-printed. `None` results are suppressed. Explicit `print()` calls still work as before.

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
