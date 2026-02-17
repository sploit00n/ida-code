# TODO

## High Priority

- [x] Add `close_database` as an explicit tool (currently only implicit close-on-open)
- [x] Handle `open_database` timeout — large binaries with auto-analysis can take minutes
- [x] Add progress feedback during auto-analysis (idalib callbacks or polling)
- [ ] Test with `.i64` / `.idb` files (not just raw binaries)

## Tools

- [x] Add `get_database_info` tool — return current state without opening/closing anything
- [ ] Add `list_functions` tool — paginated function listing (common enough to be its own tool)
- [x] Add `decompile` tool — dedicated decompilation with address/name input (wraps ida_hexrays)
- [ ] Support `execute` returning the repr of the last expression (like a REPL, not just print output)

## Doc Search

- [ ] Rank title matches higher than body matches
- [ ] Support quoted phrases in search queries
- [ ] Index C++ SDK headers (`$IDA_INSTALL_DIR/sdk/include/*.hpp`) for cross-referencing
- [ ] Add search result pagination (offset parameter)

## Robustness

- [x] Add timeout to `execute` — infinite loops in user code will hang the server
- [x] Catch `SystemExit` / `KeyboardInterrupt` in executor so user code can't kill the server
- [ ] Handle idalib crash recovery — if IDA segfaults, the whole process dies
- [x] Add structured logging (currently silent)
- [ ] Validate file paths in `open_database` before passing to idalib

## Testing

- [x] Unit tests for `executor.py` (mock ida_* imports)
- [x] Unit tests for `doc_search.py` (can run without idalib)
- [ ] Integration test: open binary, execute code, verify output
- [ ] CI pipeline (needs IDA license — may need to be local-only)

## Packaging

- [ ] Publish to PyPI
- [ ] Add Docker image with IDA + idalib pre-configured
- [ ] Support SSE transport for remote usage

## Future Ideas

- [ ] MCP Resources for browsing IDA's type libraries
- [ ] Annotation/bookmark tools — let the agent mark up the database
- [ ] Multi-database support if idalib ever supports it
- [ ] Stream `execute` output incrementally for long-running scripts
- [ ] Vector search over docs (overkill now, but useful if corpus grows)
