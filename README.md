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
- `overwrite` (bool, default `False`) — Delete any existing `.i64`/`.idb` database before opening, forcing a fresh analysis from the original binary
- `timeout` (int, default `0`) — Maximum seconds to wait for auto-analysis (0 = unlimited). When the timeout expires, the database stays open with partial analysis and a warning is appended to the summary

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

### `close_database`

Closes the current database and frees resources. The executor namespace is cleared. Safe to call when no database is open (returns a no-op message).

**Parameters:** None.

### `execute`

Runs arbitrary IDAPython code and returns captured stdout + stderr. This is the core feedback loop — the agent writes analysis code, sees the output, and iterates.

**Parameters:**
- `code` (str) — IDAPython code to execute
- `timeout` (int, default `30`) — Maximum wall-clock seconds (0 = unlimited)

**Key behaviors:**
- **Persistent namespace** — Variables and functions defined in one call carry over to the next. Build up helper functions incrementally.
- **Pre-imported modules** — `ida_funcs`, `ida_bytes`, `ida_name`, `ida_segment`, `idautils`, `idc`, `ida_hexrays`, and more. No boilerplate needed.
- **Tracebacks as output** — Errors are returned as text, not MCP errors. They're useful feedback for the agent to self-correct.
- **Output truncation** — Capped at 50K characters with a note when truncated.
- **Timeout protection** — Code that runs longer than the timeout is interrupted and an error message is returned instead of hanging the server.

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

### `execute_file`

Runs an IDAPython script file by path. Useful for executing existing analysis scripts without pasting their contents.

**Parameters:**
- `path` (str) — Path to the `.py` script file
- `args` (str, optional) — Inline code to run after the file, in the same namespace
- `timeout` (int, default `30`) — Maximum wall-clock seconds (0 = unlimited)

**Key behaviors:**
- Same persistent namespace and pre-imported modules as `execute`
- File is read with lenient encoding (undecodable bytes replaced)
- When `args` is provided, it runs after the file — useful for calling functions the script defines

**Example calls:**

Run a script:
```python
# Executes /path/to/enumerate_strings.py
```

Run a script then call a function it defines:
```python
# path: /path/to/helpers.py
# args: print(analyze_function(0x3f08))
```

### `decompile`

Decompiles a function by name or address and returns pseudocode. This is the most common single operation in reverse engineering — having it as a dedicated tool saves round-trips compared to writing Hex-Rays boilerplate via `execute`.

**Parameters:**
- `function` (str) — Function name (e.g. `"main"`, `"_objc_msgSend"`) or hex address (e.g. `"0x3f08"`, `"3f08"`)

**Returns:** Pseudocode prefixed with a comment showing the resolved function name and address range.

**Example output:**
```c
// _main @ 0x3f08 (size: 0x120)

int __fastcall main(int argc, const char **argv, const char **envp)
{
  puts("Hello, world!");
  return 0;
}
```

**Error cases:**
- Name/address not found
- Address not within a recognized function
- Hex-Rays decompiler not available or decompilation failure

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

## Resources

MCP Resources provide coding guidelines and templates for writing IDAPython code. Read them via your MCP client's resource browsing capability.

| URI | Description |
|-----|-------------|
| `guidelines://standalone_script` | Standalone idalib scripts — bootstrap, lifecycle, patterns |
| `guidelines://plugin` | IDA plugins — `plugin_t` subclass, actions, hooks |
| `guidelines://idapython_script` | Classic IDAPython scripts — in-GUI scripts via File > Script File |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `IDA_INSTALL_DIR` | `/opt/ida-pro-9.2` | IDA Pro installation directory |
| `LOG_LEVEL` | `WARNING` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

Documentation and Python API paths are derived automatically (`$IDA_INSTALL_DIR/docs`, `$IDA_INSTALL_DIR/python`).

## Architecture

```
server.py          FastMCP server — 7 tools + 3 resources, stdio transport
    ├── session.py     idalib lifecycle — open/close database, state machine
    ├── executor.py    exec() engine — persistent namespace, output capture
    ├── doc_search.py  keyword search — HTML docs + Python API sources
    ├── guidelines.py  coding templates — standalone scripts, plugins, IDAPython scripts
    └── config.py      environment-based configuration
```

The server runs idalib in-process (no IPC, no batch mode). This gives persistent state and fast iteration — the agent can open a binary once and run hundreds of analysis commands against it.

## License

MIT
