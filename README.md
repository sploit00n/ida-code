# ida-code

MCP server that lets AI coding agents interact with IDA Pro. Open binaries, decompile, run IDAPython, search the API docs — all through tool calls.

Built on [idalib](https://docs.hex-rays.com/developer-guide/idalib) for headless in-process operation and [fastmcp](https://github.com/jlowin/fastmcp) for the MCP transport.

> **Requires** a licensed IDA Pro 9.2+ with idalib support. `ida-code` does not install or replace IDA Pro — it loads `idapro` from your existing install at startup.

## Install

```bash
uv tool install ida-code
```

This puts the `ida-code` CLI on your `PATH` (via `uv`'s tool dir) so MCP clients can launch it directly. Don't have uv? `pip install ida-code` works too.

Then point `IDA_INSTALL_DIR` at your IDA Pro install (the directory that contains `idalib/python/`):

| OS | Typical path |
|---|---|
| Linux | `/opt/ida-pro-9.3` |
| macOS | `/Applications/IDA Professional 9.3.app/Contents/MacOS` |
| Windows | `C:\Program Files\IDA Professional 9.3` |

## Use with Claude Code

Add `ida-code` to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "ida-code": {
      "command": "ida-code",
      "env": {
        "IDA_INSTALL_DIR": "/opt/ida-pro-9.3"
      }
    }
  }
}
```

Restart Claude Code; the server is picked up automatically. You can confirm it's wired up by asking Claude to open a binary — it should call `open_database` and report architecture, entry point, and load address.

For other MCP clients, run the server directly:

```bash
IDA_INSTALL_DIR=/opt/ida-pro-9.3 ida-code   # stdio transport
```

## Tools (37)

Full parameter docs live in each tool's docstring — surfaced automatically to MCP clients via `tools/list`.

| Domain | Tools |
|---|---|
| Database | `open_database`, `close_database`, `get_database_info`, `list_architectures` |
| Code execution | `execute`, `execute_file` |
| Navigation | `list_functions`, `decompile`, `get_disassembly`, `get_xrefs_to`, `get_xrefs_from` |
| Annotation | `rename_function`, `retype_function`, `get_comment`, `set_comment`, `delete_comment`, `get_variable`, `set_variable` |
| Structures | `list_structures`, `get_structure`, `create_structure`, `edit_structure`, `delete_structure` |
| Snapshots | `list_snapshots`, `create_snapshot`, `restore_snapshot`, `delete_snapshot` |
| Undo/redo | `get_undo_status`, `perform_undo`, `perform_redo` |
| Inventory | `get_strings`, `get_imports`, `get_exports` |
| Search | `search_docs`, `search_code`, `get_source`, `get_guideline` |

## Resources & prompts

| Type | URI / name | Purpose |
|---|---|---|
| Resource | `guidelines://standalone_script` | Boilerplate for standalone idalib scripts |
| Resource | `guidelines://plugin` | Boilerplate for IDA plugins (`plugin_t`) |
| Resource | `guidelines://idapython_script` | Boilerplate for IDAPython scripts run inside IDA GUI |
| Prompt | `reverse_engineer` | Five-phase RE workflow (recon, triage, analysis, annotation, iteration) |
| Prompt | `create_script` | Coding guidelines for a chosen target script type |

## Transport modes

```bash
ida-code                          # stdio (default)
ida-code --http                   # streamable-http on 127.0.0.1:8080
ida-code --http 0.0.0.0:9090      # custom host:port
ida-code --sse                    # SSE on 127.0.0.1:8080
ida-code --sse :9090              # SSE on 127.0.0.1:9090
```

HTTP/SSE require bearer token auth. Set `MCP_AUTH_TOKEN` or let the server generate one (printed to stderr on startup).

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `IDA_INSTALL_DIR` | `/opt/ida-pro-9.3` | IDA Pro installation directory (must contain `idalib/python/`) |
| `LOG_LEVEL` | `WARNING` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `MCP_AUTH_TOKEN` | (auto-generated) | Bearer token for HTTP/SSE transports |

Doc and example paths are derived from `IDA_INSTALL_DIR` (`docs/`, `python/`, `python/examples/`).

## Install from source

```bash
git clone https://github.com/Dil4rd/ida-code
cd ida-code
uv sync
uv run ida-code
```

When wiring a source checkout into `.mcp.json`, use `uv` as the command:

```json
{
  "mcpServers": {
    "ida-code": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/ida-code", "ida-code"],
      "env": { "IDA_INSTALL_DIR": "/opt/ida-pro-9.3" }
    }
  }
}
```

> **Note:** the `fastmcp` dependency is the [community fastmcp](https://github.com/jlowin/fastmcp) package, not the official `mcp` SDK. Don't install `mcp` by mistake.

## Development

```bash
uv sync --extra dev
uv run pytest
```

## Known issues

See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for caveats and workarounds (e.g. why we pin `fastmcp<3`).

The test suite covers the executor, doc/example search, comments, snapshots, structures, undo, variables, and Mach-O parsing. Tests that need idalib are skipped if it's not available.

## Credits

Thanks to [@p41l](https://github.com/p41l) for ideas and for testing the tool across different LLMs.

## License

MIT — see `LICENSE`.
