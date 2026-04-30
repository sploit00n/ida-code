# ida-code

MCP server that lets AI coding agents interact with IDA Pro. Open binaries, decompile, run IDAPython, search the API docs — all through tool calls.

Built on [idalib](https://docs.hex-rays.com/developer-guide/idalib) for headless in-process operation and [fastmcp](https://github.com/jlowin/fastmcp) for the MCP transport.

## You need IDA Pro

`ida-code` does **not** install IDA Pro. You need a licensed **IDA Pro 9.2+** with idalib support. The server imports `idapro` from `$IDA_INSTALL_DIR/idalib/python/` at startup and will exit with an error if it can't find it.

## Install

From PyPI:

```bash
uv add ida-code
# or
pip install ida-code
```

From source:

```bash
git clone https://github.com/Dil4rd/ida-code
cd ida-code
uv sync
```

> **Note:** the `fastmcp` dependency is the [community fastmcp](https://github.com/jlowin/fastmcp) package, not the official `mcp` SDK. Don't install `mcp` by mistake.

## Quick start

```bash
export IDA_INSTALL_DIR=/opt/ida-pro-9.2     # or wherever IDA Pro lives
uv run ida-code                              # stdio transport (default)
```

Then point an MCP client at the running command.

## Configuration

### Claude Code

Copy `.mcp.json.example` to `.mcp.json` in your project and adjust the paths:

```json
{
  "mcpServers": {
    "ida-code": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/ida-code", "ida-code"],
      "env": {
        "IDA_INSTALL_DIR": "/opt/ida-pro-9.2"
      }
    }
  }
}
```

If you installed via `pip install ida-code` you can drop the `--directory` arg and use `"command": "ida-code"` directly (provided `IDA_INSTALL_DIR` is in the environment).

### Other MCP clients

Run the server with stdio (default) and connect:

```bash
IDA_INSTALL_DIR=/opt/ida-pro-9.2 ida-code
```

## Transport modes

```bash
ida-code                          # stdio (default)
ida-code --http                   # streamable-http on 127.0.0.1:8080
ida-code --http 0.0.0.0:9090      # custom host:port
ida-code --sse                    # SSE on 127.0.0.1:8080
ida-code --sse :9090              # SSE on 127.0.0.1:9090
```

HTTP/SSE require bearer token auth. Set `MCP_AUTH_TOKEN` or let the server generate one (printed to stderr on startup).

## Tools (35)

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
| Search | `search_docs`, `search_examples` |

## Resources & prompts

| Type | URI / name | Purpose |
|---|---|---|
| Resource | `guidelines://standalone_script` | Boilerplate for standalone idalib scripts |
| Resource | `guidelines://plugin` | Boilerplate for IDA plugins (`plugin_t`) |
| Resource | `guidelines://idapython_script` | Boilerplate for IDAPython scripts run inside IDA GUI |
| Prompt | `reverse_engineer` | Five-phase RE workflow (recon, triage, analysis, annotation, iteration) |
| Prompt | `create_script` | Coding guidelines for a chosen target script type |

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `IDA_INSTALL_DIR` | `/opt/ida-pro-9.2` | IDA Pro installation directory (must contain `idalib/python/`) |
| `LOG_LEVEL` | `WARNING` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `MCP_AUTH_TOKEN` | (auto-generated) | Bearer token for HTTP/SSE transports |

Doc and example paths are derived from `IDA_INSTALL_DIR` (`docs/`, `python/`, `python/examples/`).

## Development

```bash
git clone https://github.com/Dil4rd/ida-code
cd ida-code
uv sync --extra dev
uv run pytest
```

The test suite covers the executor, doc/example search, comments, snapshots, structures, undo, variables, and Mach-O parsing. Tests that need idalib are skipped if it's not available.

## License

MIT — see `LICENSE`.
