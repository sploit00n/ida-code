# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Indirect-branch tools (Pass 1)** — `list_indirect_branches`, `get_indirect_branch`, `set_indirect_branch`. Enumerate indirect call/jump sites via IDA's CFG (`ida_idp.is_call_insn`, basic-block `fcb_indjump`), then record per-target resolutions as manual code xrefs plus an `@RESOLVED_V1` block in the site's comment. Persistence rides on the `.i64`; resolved targets show up through the existing `get_xrefs_from` tool.
- **Indirect-branch microcode heuristics (Pass 2)** — `get_indirect_branch` now also returns `target_microcode_op`, `target_backward_slice`, `from_arg`, `inferred_type`, and `candidates`. Backward slice walks Hex-Rays microcode at `MMAT_GLBOPT3` def-use chains; arg-index inference matches the source operand's mreg against the function's prototype via `reg2mreg`; caller-arg candidate generation walks callers and inspects the relevant arg slot in each. All arch-agnostic — Hex-Rays handles the PCS mapping.
- **Indirect-branch arch helpers (Pass 3)** — new `indirect_branch/arch/` subpackage. `arch.get_helper()` selects the right module by detected arch; each helper exposes hooks (default no-op in `arch/base.py`) for arch-specific evidence. First helper: `arch/arm64e.py` — extracts the PAC discriminator from BLRAA/BLRAB/BRAA/BRAB by backward-scanning the basic block for the `MOV Xdisc, #imm` that loads the discriminator register, and surfaces it under `discriminator: {register, value, source_addr}`. The ALF.kext BLRAA at `0x8e9c` reports disc 0x2ABE in X17 set at 0x8e98.

## [0.2.4] - 2026-05-19

### Added

- **`get_guideline` tool** — tool-form companion to the `guidelines://*` resources. Same content, but tool listings are read more reliably than resource listings by cold LLM clients.

### Changed

- `search_docs` snippet cap is word-based (`max_snippet_length` → `max_snippet_words`, default 25). Avoids mid-word truncation and lines up better with token cost.
- `search_docs` / `search_code` docstrings and the server `instructions` paragraph rewritten as discovery steers — `search_code` for API lookups, `search_docs` narrowed to HTML prose, both pointing at `get_guideline` / `get_source`.

## [0.2.3] - 2026-05-10

### Added

- **Dedicated ida-thread** — new `src/ida_code/ida_thread.py`: a single daemon worker thread that owns idalib. Submit work via `submit()` (sync) or `await on_ida_thread()` (async). idalib hangs when called from any thread other than the one that imported `idapro`; pinning all idalib calls to one thread we control unblocks fastmcp v3 compatibility.
- **`get_source` tool** — companion to `search_code`. When a search result is truncated (`snippet_start_line` + `total_lines` set), the LLM fetches more lines via `get_source(file, start_line, line_count)`. Sandboxed to the indexed corpora (`python/`, `python/examples/`, `idalib/python/`, `idalib/examples/`); paths outside those roots can't be read.

### Changed

- **fastmcp pin lifted to `>=2.0,<4`** — the ida-thread refactor lets v3 work as well as v2. Verified end-to-end on v3.2.4 with both stdio and in-process transports: `open_database` + `list_functions` + `close_database` complete in <1s on a warm `.i64` cache.
- **All idalib-touching tools are now `async def`** — every `@mcp.tool` that touches idalib (28 tools) dispatches its body via `await on_ida_thread(_impl, ...)`. The 3 non-idalib tools (`list_architectures`, `search_docs`, `search_code`) stay plain sync `def`. Keeps the asyncio event loop free during idalib work and is transport-agnostic across fastmcp v2 / v3.
- **`session.py` lazy idapro import** — `import idapro` moved off module top into `_ensure_idalib_loaded()` which runs on the ida-thread on first use. A targeted `signal.signal` monkey-patch silences the `SIGINT, SIG_DFL` install in `idapro/__init__.py:179` that raises `ValueError` on non-main threads (other signal calls pass through). `session.idapro` is the module-level handle, replacing the prior import.
- **Guidelines refresh** — each `guidelines://` resource now carries (a) Hex-Rays' own IDAPython conventions extracted from `python/examples/README.md` (avoid `idc.py` / `idaapi` / `from X import Y` re-exports; double-quote strings; example docstring header), (b) a "Discovering APIs and examples" footer pointing at `search_docs` / `search_code` / `get_source` so callers know the chain. The standalone-script guideline additionally references the `py-activate-idalib.py` setup path from `idalib/README.txt` for users who'd rather `pip install` than bootstrap manually.

### Changed (BREAKING)

- **`search_examples` → `search_code`** — unified Python-source search that indexes library APIs (formerly under `search_docs`) plus example scripts. New corpora included in the index: the `idapro` Python package (`idalib/python/idapro/*.py`) so signatures like `open_database(file_path, run_auto)` surface from the actual Python wrapper, and `idalib/examples/` so the canonical standalone-idalib example (`idacli.py`) is findable. Adds `kind` filter (`""|"library"|"example"`), `imports` filter (e.g. `imports="idapro"` finds standalone-idalib scripts), `docstring_only: bool` flag to restrict scoring to docstring text for semantic queries, and `include_docs: bool = True` for a `related_docs` cross-link to HTML docs. Library entries weight docstrings at 3x (between name 5x and body 1x) so docstring matches outrank coincidental code-comment matches. Snippet shaping: `max_snippet_lines` caps height, `max_snippet_line_chars` (default 200) truncates each line with `...`, and when a snippet doesn't cover the full source the result includes `snippet_start_line` (1-based, file-absolute) plus `total_lines` so a follow-up read can fetch the rest at the right offset. Result objects are tuned for token efficiency: `score` and `apis` are never emitted, empty fields (level/category/summary/imports) are dropped, `title` is dropped when it equals the filename, and `kind` is dropped when the caller filtered to one. `search_docs` is now HTML-only; its `include_examples` cross-link goes through `search_code(kind="example")` internally.

### Removed

- **`execute` / `execute_file` `timeout` parameter** — the prior implementation used `signal.SIGALRM`, which only delivers to the process main thread. With user code now running on the ida-thread there's no portable way to interrupt it mid-call, so the parameter was removed rather than left as a silently-ignored knob.

## [0.2.2] - 2026-05-07

### Added

- **End-to-end regression test** — `tests/test_e2e.py` opens a real binary through fastmcp's in-process `Client` + `FastMCPTransport`, asserting the call returns within 15s. Catches future regressions that route idalib off the main thread (which would hang). Auto-skips when idalib isn't available.

### Changed

- **Pin fastmcp back to `>=2.0,<3`** — v3 dispatches sync tool functions to `anyio.to_thread.run_sync`, but idalib hangs indefinitely when called from a non-main thread, so every idalib-touching tool wedged. v2 runs sync tools on the main thread and works in 0.7s on the same call. Reverts the v2→v3 bump from 0.2.1.
- **`open_database` refuses paths with unpacked fragments present** — if `.id0`/`.id1`/`.id2`/`.nam`/`.til` files exist for the target and `overwrite=False`, raise a clear `ToolError` listing them instead of letting idalib return an opaque `-1`. The message warns that the fragments may belong to another active IDA instance and only suggests `overwrite=True` if nothing else owns them.

### Fixed

- **`open_database` overwrite cleans up unpacked fragments** — `overwrite=True` now also deletes `.id0`, `.id1`, `.id2`, `.nam`, and `.til` files, not just `.i64`/`.idb`. A failed open could leave these partial fragments behind, after which every subsequent attempt would fail immediately with a generic `-1` because IDA refused to overwrite the half-written unpacked database.

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
