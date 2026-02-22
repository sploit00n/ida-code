import argparse
import hmac
import logging
import secrets
import sys
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from ida_code import guidelines as _guidelines
from ida_code import macho as _macho
from ida_code import session
from ida_code.config import LOG_LEVEL, MCP_AUTH_TOKEN
from ida_code.executor import execute as _execute
from ida_code.doc_search import search as _search_docs
from ida_code.example_search import search as _search_examples

mcp = FastMCP("ida-code")


@mcp.tool
def list_architectures(path: str) -> list[str]:
    """List architecture slices in a fat (universal) Mach-O binary.

    Returns e.g. ["x86_64", "arm64e"]. Returns an empty list if the file
    is not a fat Mach-O. No database needs to be open.

    Use this to discover available slices before calling open_database
    with the *arch* parameter.
    """
    return _macho.list_architectures(path)


@mcp.tool
def open_database(
    path: str,
    auto_analysis: bool = True,
    overwrite: bool = False,
    timeout: int = 0,
    arch: str | None = None,
) -> dict:
    """Open a binary or IDA database via idalib.

    Returns summary info (architecture, segments, entry points, function count).
    If a database is already open, it is closed first.

    Set overwrite=True to delete any existing .i64/.idb database and force
    a fresh analysis from the original binary.

    *timeout* limits auto-analysis wait time in seconds (default 0 = unlimited).
    When the timeout expires the database stays open with partial analysis
    and a warning is appended to the summary.

    *arch* selects a specific architecture slice from a fat (universal) Mach-O
    binary (e.g. "arm64e", "x86_64"). Use list_architectures to discover
    available slices. Ignored for non-fat binaries.
    """
    return session.open(path, auto_analysis, overwrite, timeout=timeout, arch=arch)


@mcp.tool
def get_database_info() -> dict:
    """Return summary info about the current database.

    Returns processor type, bitness, segments, entry points, and function count
    without opening or closing anything. If no database is open, says so.
    """
    return session.info()


@mcp.tool
def close_database() -> dict:
    """Close the current database and free resources.

    The executor namespace is cleared. No database will be open after this call.
    """
    if session.get_state() == session.State.NO_DATABASE:
        raise ToolError("No database is currently open.")
    session.close()
    return {"status": "closed"}


@mcp.tool
def execute(code: str, timeout: int = 30) -> dict:
    """Execute IDAPython code and return captured output.

    The execution namespace persists across calls — variables and functions defined
    in one call are available in subsequent calls. Common ida_* modules are
    pre-imported (ida_funcs, ida_bytes, ida_name, idautils, idc, etc.).

    Python tracebacks are returned as normal output for debugging.

    *timeout* sets the maximum wall-clock seconds (default 30, 0 = unlimited).
    """
    if session.get_state() == session.State.NO_DATABASE:
        raise ToolError("No database is open. Call open_database first.")
    text = _execute(code, timeout=timeout)
    return {"output": text, "truncated": len(text) >= 50000}


@mcp.tool
def execute_file(path: str, args: str | None = None, timeout: int = 30) -> dict:
    """Execute an IDAPython script file and return captured output.

    Reads the file at `path` and executes it. Optionally, `args` provides
    inline code that runs after the file in the same namespace — useful for
    calling functions defined in the script or inspecting results.

    The execution namespace persists across calls, same as `execute`.

    *timeout* sets the maximum wall-clock seconds (default 30, 0 = unlimited).
    """
    if session.get_state() == session.State.NO_DATABASE:
        raise ToolError("No database is open. Call open_database first.")

    p = Path(path)
    if not p.is_file():
        raise ToolError(f"File not found: {path}")
    try:
        code = p.read_text(errors="replace")
    except OSError as e:
        raise ToolError(f"Could not read file: {e}")

    if args:
        code = code + "\n" + args

    text = _execute(code, timeout=timeout)
    return {"output": text, "truncated": len(text) >= 50000}


def _resolve_address(identifier: str) -> int:
    """Resolve a name or numeric string to an address.

    Tries hex (with or without ``0x``), then decimal, then IDA name lookup.
    Returns ``ida_idaapi.BADADDR`` on failure.
    """
    import ida_idaapi
    import ida_name

    ea = ida_idaapi.BADADDR
    s = identifier.strip()

    # Try as hex address first (with or without 0x prefix).
    try:
        ea = int(s, 16)
    except ValueError:
        pass

    # Try as decimal address.
    if ea == ida_idaapi.BADADDR:
        try:
            ea = int(s, 10)
        except ValueError:
            pass

    # Try as a name.
    if ea == ida_idaapi.BADADDR:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, s)

    return ea


@mcp.tool
def decompile(function: str, max_length: int = 10000, offset: int = 0) -> dict:
    """Decompile a function and return pseudocode.

    *function* can be a name (e.g. "main", "_objc_msgSend") or a hex address
    (e.g. "0x3f08", "3f08"). The address must fall within a recognized function.

    Requires the Hex-Rays decompiler.

    *max_length* caps the pseudocode returned (default 10000 chars).
    *offset* starts from this character position (for paging).
    If ``truncated`` is true, call again with ``offset=<offset + max_length>``
    to get the next page.
    """
    if session.get_state() == session.State.NO_DATABASE:
        raise ToolError("No database is open. Call open_database first.")

    import ida_funcs
    import ida_hexrays
    import ida_idaapi

    ea = _resolve_address(function)
    if ea == ida_idaapi.BADADDR:
        raise ToolError(f"Could not resolve '{function}' to an address.")

    # Ensure ea is within a function.
    pfn = ida_funcs.get_func(ea)
    if pfn is None:
        raise ToolError(f"Address {ea:#x} is not within a recognized function.")

    try:
        cfunc = ida_hexrays.decompile(pfn.start_ea)
    except ida_hexrays.DecompilationFailure as e:
        raise ToolError(f"Decompilation failed: {e}")
    except Exception as e:
        raise ToolError(f"{type(e).__name__}: {e}")

    if cfunc is None:
        raise ToolError("Decompilation returned no result.")

    func_name = ida_funcs.get_func_name(pfn.start_ea) or f"sub_{pfn.start_ea:x}"
    pseudocode = str(cfunc)
    total_length = len(pseudocode)
    chunk = pseudocode[offset:offset + max_length]
    return {
        "name": func_name,
        "address": f"{pfn.start_ea:#x}",
        "size": f"{pfn.end_ea - pfn.start_ea:#x}",
        "pseudocode": chunk,
        "offset": offset,
        "total_length": total_length,
        "truncated": offset + max_length < total_length,
    }


@mcp.tool
def get_disassembly(start: str, length: int = 0x100) -> dict:
    """Get disassembly for an address range.

    *start* can be a name (e.g. "main") or address (hex "0x3f08" / "3f08",
    decimal "16136"). *length* is the number of bytes from start to disassemble
    (default 256, capped at 64 KB).
    """
    if session.get_state() == session.State.NO_DATABASE:
        raise ToolError("No database is open. Call open_database first.")

    import ida_idaapi
    import idc
    import idautils

    ea = _resolve_address(start)
    if ea == ida_idaapi.BADADDR:
        raise ToolError(f"Could not resolve '{start}' to an address.")

    length = max(1, min(length, 0x10000))
    end_ea = ea + length

    instructions: list[dict] = []
    for head in idautils.Heads(ea, end_ea):
        instructions.append({"address": f"{head:#x}", "disasm": idc.GetDisasm(head)})

    if not instructions:
        raise ToolError(f"No instructions found in range {ea:#x}\u2013{end_ea:#x}.")

    return {
        "start": f"{ea:#x}",
        "end": f"{end_ea:#x}",
        "count": len(instructions),
        "instructions": instructions,
    }


@mcp.tool
def list_functions(offset: int = 0, limit: int = 50, filter: str = "") -> dict:
    """List functions in the database with pagination.

    Returns one line per function: address, size, and name.

    *offset* skips the first N functions (for pagination).
    *limit* caps the number of functions returned (default 50, max 1000).
    *filter* if non-empty, only includes functions whose name contains
    this substring (case-insensitive).

    If more results exist, increase *offset* by *limit* to get the next page.
    """
    if session.get_state() == session.State.NO_DATABASE:
        raise ToolError("No database is open. Call open_database first.")

    import ida_funcs
    import idautils

    limit = min(limit, 1000)
    all_funcs = list(idautils.Functions())
    total = len(all_funcs)

    functions: list[dict] = []
    skipped = 0
    for ea in all_funcs:
        name = ida_funcs.get_func_name(ea) or f"sub_{ea:x}"
        if filter and filter.lower() not in name.lower():
            continue
        if skipped < offset:
            skipped += 1
            continue
        pfn = ida_funcs.get_func(ea)
        size = pfn.end_ea - pfn.start_ea if pfn else 0
        functions.append({"address": f"{ea:#x}", "size": f"{size:#x}", "name": name})
        if len(functions) >= limit:
            break

    return {
        "functions": functions,
        "total": total,
        "showing": len(functions),
        "offset": offset,
        "filter": filter,
    }


@mcp.tool
def search_docs(query: str, max_results: int = 5, max_snippet_length: int = 150) -> dict:
    """Search IDA documentation and Python API sources.

    Searches two corpora:
    - IDA HTML documentation (developer guide, user guide, etc.)
    - IDAPython API source files (ida_*.py function signatures and docstrings)

    Returns matching snippets with source attribution.

    *max_snippet_length* caps each snippet (default 150 chars).
    """
    return _search_docs(query, max_results, max_snippet_length)


@mcp.tool
def search_examples(
    query: str,
    max_results: int = 5,
    max_snippet_lines: int = 10,
    category: str = "",
    level: str = "",
) -> dict:
    """Search 125 official IDAPython example scripts.

    Searches example metadata (title, description, keywords, APIs used)
    and source code (imports, function definitions, API call patterns).

    *category* filters: ui, disassembler, decompiler, debugger, types, misc.
    *level* filters: beginner, intermediate, advanced.

    *max_snippet_lines* caps source snippets (default 10 lines).
    """
    return _search_examples(query, max_results, category, level, max_snippet_lines)


@mcp.resource("guidelines://standalone_script")
def standalone_script_guidelines() -> str:
    """Architecture and boilerplate for standalone idalib scripts."""
    return _guidelines.get("standalone_script")


@mcp.resource("guidelines://plugin")
def plugin_guidelines() -> str:
    """Architecture and boilerplate for IDA plugins (idaapi.plugin_t)."""
    return _guidelines.get("plugin")


@mcp.resource("guidelines://idapython_script")
def idapython_script_guidelines() -> str:
    """Architecture and boilerplate for IDAPython scripts run inside IDA GUI."""
    return _guidelines.get("idapython_script")


def _parse_host_port(value: str) -> tuple[str, int]:
    """Parse a ``host:port`` string, defaulting to ``127.0.0.1:8080``."""
    if not value:
        return "127.0.0.1", 8080
    # Split on the *last* colon so IPv6 addresses work if quoted.
    if ":" in value:
        host, _, port_str = value.rpartition(":")
        host = host or "127.0.0.1"
        return host, int(port_str)
    # Bare hostname / IP with no port.
    return value, 8080


def main():
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.WARNING),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    parser = argparse.ArgumentParser(prog="ida-code", description="MCP server for IDAPython scripting via idalib")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--http", nargs="?", const="127.0.0.1:8080", metavar="HOST:PORT",
                       help="Run with streamable-http transport (default: 127.0.0.1:8080)")
    group.add_argument("--sse", nargs="?", const="127.0.0.1:8080", metavar="HOST:PORT",
                       help="Run with SSE transport (default: 127.0.0.1:8080)")
    args = parser.parse_args()

    if args.http or args.sse:
        transport = "streamable-http" if args.http else "sse"
        host, port = _parse_host_port(args.http or args.sse)

        auth_token = MCP_AUTH_TOKEN
        if not auth_token:
            auth_token = secrets.token_urlsafe(32)
            print(f"Generated auth token: {auth_token}", file=sys.stderr)

        from fastmcp.server.auth import DebugTokenVerifier

        mcp.auth = DebugTokenVerifier(
            validate=lambda token: hmac.compare_digest(token, auth_token),
            client_id="ida-code-client",
        )
        mcp.run(transport=transport, host=host, port=port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
