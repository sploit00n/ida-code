# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - Unreleased

### Added

- **`open_database` `overwrite` flag** — Delete existing `.i64`/`.idb` database files before opening, forcing a fresh analysis from the original binary.
- **`close_database` tool** — Explicitly close the current database and free resources. Clears the executor namespace.
- **`execute_file` tool** — Run IDAPython script files directly by path. Optional `args` parameter for inline follow-up code in the same namespace.
- **Coding guidelines resources** — Three MCP Resources (`guidelines://standalone_script`, `guidelines://plugin`, `guidelines://idapython_script`) providing architecture templates and best practices for writing standalone idalib scripts, IDA plugins, and classic IDAPython scripts.

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
