# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.1] - 2026-05-05

### Added

- **PyPI publish workflow** — `.github/workflows/publish-pypi.yml` builds with `uv build` and publishes to PyPI via Trusted Publishing on every push to `main` whose `pyproject.toml` version differs from the latest released version. No-op when versions match.
- **Credits section** in README thanking [@p41l](https://github.com/p41l) for ideas and cross-LLM testing.

### Changed

- **fastmcp v3** — Bumped dependency from `fastmcp>=2.0,<3` to `fastmcp>=3.0,<4`. No code changes required: the `FastMCP` constructor, `@mcp.tool` / `@mcp.resource` / `@mcp.prompt` decorators, `fastmcp.exceptions.ToolError`, `fastmcp.server.auth.DebugTokenVerifier`, and `mcp.run(transport="streamable-http"|"sse", host=..., port=...)` are all still supported in v3.
- **README polish** — Compressed install to a single primary path (`uv tool install ida-code`, with `pip` fallback), added a per-OS `IDA_INSTALL_DIR` table, moved the tool inventory above transport/env sections, and pushed source-install + fastmcp note to the bottom.

## [0.2.0] - 2026-04-30

### Added

- **PyPI release prep** — Full PEP 639 metadata in `pyproject.toml` (license expression, classifiers, urls, authors, keywords, readme). Hatchling sdist allowlist excludes dev-only files (`.claude/`, `.mcp.json`, `CLAUDE.md`, `TODO.md`, `uv.lock`). README rewritten as a slim user-facing reference (~130 lines, table-of-tools instead of 30 per-tool sections).
- **Friendlier `idapro` import error** — When `IDA_INSTALL_DIR` doesn't point at a valid IDA Pro install, the server now exits with a clear message naming the directory it tried instead of an opaque `ModuleNotFoundError`.
- **`.mcp.json.example`** — Committed configuration template with placeholder paths. The real `.mcp.json` is now gitignored to avoid leaking local paths.
- **Word-boundary matching** — `search_docs` and `search_examples` now use word-boundary-aware matching. Searching for "set" matches `set_name` and `ida_name.set_name` but not "reset", "offset", or "unset". Boundaries are start-of-string, underscore, dot, and whitespace.
- **Field-weighted scoring in `search_docs`** — Title matches now score 4x higher than body matches, and Python API name matches score 5x higher. Previously all matches scored equally. Includes all-terms-match bonus (1.5x multiplier).
- **Cross-linking docs → examples** — `search_docs` now includes a `related_examples` key with up to 2 matching example scripts. Controlled via `include_examples` parameter (default `True`).
- **Server instructions** — Added `instructions` parameter to FastMCP server with workflow guidance (open → list → decompile → annotate → iterate). Visible to LLMs in the MCP `initialize` response.
- **Literal types for enum parameters** — `comment_type`, `category`, and `level` parameters now use `Literal` types, exposing valid values in the JSON schema `enum` field instead of only in docstrings.
- **`rename_function` tool** — Rename a function by name or address. Returns old and new names.
- **`retype_function` tool** — Change a function's type signature with a C type string.
- **`get_xrefs_to` tool** — Get cross-references to an address (who calls/references this?). Returns typed xref list with human-readable type names.
- **`get_xrefs_from` tool** — Get cross-references from an address (what does this call/reference?).
- **`get_strings` tool** — List strings in the database with min-length and filter options.
- **`get_imports` tool** — List all imported functions grouped by module.
- **`get_exports` tool** — List all exported functions/symbols with ordinals.
- **Database file guard** — Before every IDA API call, `session.require_open()` now checks that the `.i64`/`.idb` database file still exists on disk. If the file has been moved or deleted, the server resets internal state and returns a clean `ToolError` instead of letting idalib segfault and crash the process. All tools that require an open database use this centralized check.
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
- **MCP prompts** — Two new MCP prompts for guided workflows: `reverse_engineer` (comprehensive five-phase binary analysis workflow covering reconnaissance, triage, deep analysis, annotation, and iteration) and `create_script` (coding guidelines for standalone scripts, plugins, or IDAPython scripts plus IDAPython best practices for error handling, performance, naming conventions, and common pitfalls).

### Changed

- **`remove_snapshot` → `delete_snapshot`** — Renamed for consistency with `delete_structure` and `delete_comment`.
- **`filter` → `name_filter`** — Renamed in `list_functions` and `list_structures` to avoid shadowing the Python builtin and clarify semantics.
- **`id` → `snapshot_id`** — Renamed in `restore_snapshot` and `delete_snapshot` to avoid shadowing the Python builtin and be self-documenting.
- **`function` → `scope`** — Renamed in `get_variable` and `set_variable` to clarify it's the containing scope, not the target variable.
- **Tool descriptions** — All 30 tools that require an open database now say "Requires an open database" in the first line. Added `Returns:` lines listing dict keys. Enriched `execute` description with exhaustive pre-imported module list. Improved `search_docs` and `search_examples` descriptions to clarify when and why to use them.
- **`reverse_engineer` prompt** — Updated to reference new dedicated tools (`get_strings`, `get_imports`, `get_exports`, `get_xrefs_to`, `get_xrefs_from`, `rename_function`, `retype_function`) instead of raw `execute` boilerplate. Recommends dedicated tools over `execute` where available.
- **`execute` behavior** — Last-expression values are now auto-printed. `None` results are suppressed. Explicit `print()` calls still work as before.
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
