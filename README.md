# ida-code

MCP server that lets AI coding agents interact with IDA Pro. Open binaries, run IDAPython scripts, search the API docs — all through tool calls.

Built on [idalib](https://docs.hex-rays.com/developer-guide/idalib) for headless in-process operation and [fastmcp](https://github.com/jlowin/fastmcp) for the MCP transport.

## Prerequisites

- **IDA Pro 9.2+** with idalib support
- **Python 3.12+**
- **uv** (recommended) or pip

## Installation

```bash
cd /path/to/ida-code
uv sync
```

idalib is loaded automatically from `IDA_INSTALL_DIR/idalib/python/` at startup — no manual `pip install` or `py-activate-idalib.py` needed.

## Configuration

### Claude Code

Copy the provided `.mcp.json` to your project root, or add to your existing config:

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

### Other MCP clients

ida-code uses stdio transport. Run the server directly:

```bash
IDA_INSTALL_DIR=/opt/ida-pro-9.2 uv run --directory /path/to/ida-code ida-code
```

## Tools

### `open_database`

Opens a binary or existing IDA database. If a database is already open, it's closed first (idalib is single-threaded — one database at a time).

**Parameters:**
- `path` (str) — Path to binary or `.i64`/`.idb` file
- `auto_analysis` (bool, default `True`) — Wait for auto-analysis to complete

**Returns:** Summary with processor type, bitness, segment list, entry points, and function count.

**Example output:**
```
Database opened: /tmp/hello
Processor: ARM (64-bit)
Functions: 142
Segments (4):
  HEADER: 0x0-0x100
  __TEXT: 0x100-0x8000
  __DATA: 0x8000-0xc000
  __LINKEDIT: 0xc000-0x10000
Entry points (1):
  _main: 0x3f08
```

### `execute`

Runs arbitrary IDAPython code and returns captured stdout + stderr. This is the core feedback loop — the agent writes analysis code, sees the output, and iterates.

**Parameters:**
- `code` (str) — IDAPython code to execute

**Key behaviors:**
- **Persistent namespace** — Variables and functions defined in one call carry over to the next. Build up helper functions incrementally.
- **Pre-imported modules** — `ida_funcs`, `ida_bytes`, `ida_name`, `ida_segment`, `idautils`, `idc`, `ida_hexrays`, and more. No boilerplate needed.
- **Tracebacks as output** — Errors are returned as text, not MCP errors. They're useful feedback for the agent to self-correct.
- **Output truncation** — Capped at 50K characters with a note when truncated.

**Example calls:**

List all functions:
```python
for ea in idautils.Functions():
    print(f"{ea:#x} {ida_funcs.get_func_name(ea)}")
```

Decompile a function (requires Hex-Rays):
```python
import ida_hexrays
cfunc = ida_hexrays.decompile(0x3f08)
print(cfunc)
```

Build up state across calls:
```python
# Call 1: define a helper
def xrefs_to(name):
    ea = ida_name.get_name_ea(0, name)
    return [ref.frm for ref in idautils.XrefsTo(ea)]

# Call 2: use it
for caller in xrefs_to("_objc_msgSend"):
    print(f"{caller:#x} {ida_funcs.get_func_name(caller)}")
```

### `search_docs`

Searches IDA's bundled documentation and Python API source files. Useful for looking up API signatures, finding the right function for a task, or reading usage examples.

**Parameters:**
- `query` (str) — Search terms (space-separated, case-insensitive)
- `max_results` (int, default `10`) — Maximum results to return

**Searches two corpora:**
- **IDA HTML docs** — Developer guide, user guide, SDK examples (2628 indexed pages)
- **IDAPython sources** — All `ida_*.py`, `idautils.py`, `idc.py` function signatures and docstrings

**Example output** for query `"get_func_name"`:
```
[docs: developer-guide/idapython/idapython-getting-started.html] Get the name of a function
ida_funcs.get_func_name(ea)

[python: ida_funcs.py] get_func_name
def get_func_name(ea: ida_idaapi.ea_t) ->str:
    """Get function name.
    :param ea: any address in the function
    :returns: length of the function name"""
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `IDA_INSTALL_DIR` | `/opt/ida-pro-9.2` | IDA Pro installation directory |

Documentation and Python API paths are derived automatically (`$IDA_INSTALL_DIR/docs`, `$IDA_INSTALL_DIR/python`).

## Architecture

```
server.py          FastMCP server — 3 tool definitions, stdio transport
    ├── session.py     idalib lifecycle — open/close database, state machine
    ├── executor.py    exec() engine — persistent namespace, output capture
    ├── doc_search.py  keyword search — HTML docs + Python API sources
    └── config.py      environment-based configuration
```

The server runs idalib in-process (no IPC, no batch mode). This gives persistent state and fast iteration — the agent can open a binary once and run hundreds of analysis commands against it.

## License

MIT
