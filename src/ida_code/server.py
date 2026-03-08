import argparse
import hmac
import logging
import secrets
import sys
from pathlib import Path
from typing import Literal

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from ida_code import guidelines as _guidelines
from ida_code import macho as _macho
from ida_code import session
from ida_code.config import LOG_LEVEL, MCP_AUTH_TOKEN
from ida_code.executor import execute as _execute
from ida_code.doc_search import search as _search_docs
from ida_code.example_search import search as _search_examples
from ida_code import comments as _comments
from ida_code import snapshots as _snapshots
from ida_code import structures as _structures
from ida_code import undo as _undo
from ida_code import variables as _variables
from ida_code import prompts as _prompts

CommentType = Literal["regular", "repeatable", "function", "anterior", "posterior"]
CommentTypeOrAll = Literal["regular", "repeatable", "function", "anterior", "posterior", ""]
ExampleCategory = Literal["ui", "disassembler", "decompiler", "debugger", "types", "misc", ""]
ExampleLevel = Literal["beginner", "intermediate", "advanced", ""]

mcp = FastMCP(
    "ida-code",
    instructions=(
        "IDA Pro reverse engineering server. Open binaries, decompile functions, "
        "annotate code, and run IDAPython scripts.\n\n"
        "Typical workflow: open_database → list_functions → decompile → "
        "annotate (rename_function, set_comment, set_variable) → iterate.\n\n"
        "Only one database can be open at a time. Most tools require an open database."
    ),
)


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
    """Close the current database and free resources. Requires an open database.

    The executor namespace is cleared. No database will be open after this call.
    """
    session.require_open()
    session.close()
    return {"status": "closed"}


@mcp.tool
def execute(code: str, timeout: int = 30) -> dict:
    """Execute IDAPython code and return captured output. Requires an open database.

    The execution namespace persists across calls — variables and functions defined
    in one call are available in subsequent calls. Pre-imported modules:
    ``ida_funcs``, ``ida_bytes``, ``ida_name``, ``ida_segment``, ``ida_auto``,
    ``ida_idaapi``, ``ida_nalt``, ``ida_xref``, ``ida_ua``, ``ida_entry``,
    ``ida_lines``, ``ida_typeinf``, ``ida_hexrays``, ``idautils``, ``idc``.

    Python tracebacks are returned as normal output for debugging.

    *timeout* sets the maximum wall-clock seconds (default 30, 0 = unlimited).

    Returns: ``{"output", "truncated"}``
    """
    session.require_open()
    text = _execute(code, timeout=timeout)
    return {"output": text, "truncated": len(text) >= 50000}


@mcp.tool
def execute_file(path: str, args: str | None = None, timeout: int = 30) -> dict:
    """Execute an IDAPython script file and return captured output. Requires an open database.

    Reads the file at `path` and executes it. Optionally, `args` provides
    inline code that runs after the file in the same namespace — useful for
    calling functions defined in the script or inspecting results.

    The execution namespace persists across calls, same as `execute`.

    *timeout* sets the maximum wall-clock seconds (default 30, 0 = unlimited).

    Returns: ``{"output", "truncated"}``
    """
    session.require_open()

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
    """Decompile a function and return pseudocode. Requires an open database.

    *function* can be a name (e.g. "main", "_objc_msgSend") or a hex address
    (e.g. "0x3f08", "3f08"). The address must fall within a recognized function.

    Requires the Hex-Rays decompiler.

    *max_length* caps the pseudocode returned (default 10000 chars).
    *offset* starts from this character position (for paging).
    If ``truncated`` is true, call again with ``offset=<offset + max_length>``
    to get the next page.
    """
    session.require_open()

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
    """Get disassembly for an address range. Requires an open database.

    *start* can be a name (e.g. "main") or address (hex "0x3f08" / "3f08",
    decimal "16136"). *length* is the number of bytes from start to disassemble
    (default 256, capped at 64 KB).

    Returns: ``{"start", "end", "count", "instructions": [{"address", "disasm"}]}``
    """
    session.require_open()

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
def list_functions(offset: int = 0, limit: int = 50, name_filter: str = "") -> dict:
    """List functions in the database with pagination. Requires an open database.

    Returns address, size, and name for each function.

    *offset* skips the first N functions (for pagination).
    *limit* caps the number of functions returned (default 50, max 1000).
    *name_filter* if non-empty, only includes functions whose name contains
    this substring (case-insensitive).

    If more results exist, increase *offset* by *limit* to get the next page.

    Returns: ``{"functions": [{"address", "size", "name"}], "total", "showing", "offset", "name_filter"}``
    """
    session.require_open()

    import ida_funcs
    import idautils

    limit = min(limit, 1000)
    all_funcs = list(idautils.Functions())
    total = len(all_funcs)

    functions: list[dict] = []
    skipped = 0
    for ea in all_funcs:
        name = ida_funcs.get_func_name(ea) or f"sub_{ea:x}"
        if name_filter and name_filter.lower() not in name.lower():
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
        "name_filter": name_filter,
    }


@mcp.tool
def search_docs(query: str, max_results: int = 5, max_snippet_length: int = 150) -> dict:
    """Look up IDA API functions, constants, and usage. No database needs to be open.

    Use this to find the right API for a task, check function signatures,
    or understand parameter meanings.

    Searches two corpora:
    - IDA HTML documentation (developer guide, user guide, etc.)
    - IDAPython API source files (ida_*.py function signatures and docstrings)

    *max_snippet_length* caps each snippet (default 150 chars).
    """
    return _search_docs(query, max_results, max_snippet_length)


@mcp.tool
def search_examples(
    query: str,
    max_results: int = 5,
    max_snippet_lines: int = 10,
    category: ExampleCategory = "",
    level: ExampleLevel = "",
) -> dict:
    """Find working IDAPython code examples for common tasks. No database needs to be open.

    Use this to find code patterns (e.g. "list strings", "decompile",
    "enumerate imports") or see how specific IDA APIs are used in practice.

    Searches example titles, descriptions, keywords, APIs used, and source code.
    For API signatures and documentation, use `search_docs` instead.

    *max_snippet_lines* caps source snippets (default 10 lines).
    """
    return _search_examples(query, max_results, category, level, max_snippet_lines)


@mcp.tool
def list_snapshots() -> dict:
    """List all database snapshots. Requires an open database.

    Returns snapshot IDs, descriptions, and filenames for the current database.

    Returns: ``{"snapshots": [{"id", "desc", "filename"}], "count"}``
    """
    return _snapshots.list_snapshots()


@mcp.tool
def create_snapshot(desc: str = "") -> dict:
    """Create a database snapshot to checkpoint the current state. Requires an open database.

    Snapshots let you save the database state before making destructive changes
    (renaming, patching, type changes) and roll back if needed.

    *desc* is an optional short description (max 128 chars).

    Returns: ``{"id", "desc", "filename"}``
    """
    return _snapshots.create_snapshot(desc)


@mcp.tool
def restore_snapshot(snapshot_id: str) -> dict:
    """Restore the database to a previous snapshot. Requires an open database.

    *snapshot_id* is the snapshot ID from list_snapshots or create_snapshot.
    The executor namespace is reset after restore since the database state changed.
    """
    return _snapshots.restore_snapshot(snapshot_id)


@mcp.tool
def delete_snapshot(snapshot_id: str) -> dict:
    """Delete a database snapshot by removing its file from disk. Requires an open database.

    *snapshot_id* is the snapshot ID from list_snapshots or create_snapshot.
    """
    return _snapshots.remove_snapshot(snapshot_id)


@mcp.tool
def get_undo_status() -> dict:
    """Check what undo/redo actions are available. Requires an open database.

    Returns whether undo and redo are possible, along with labels describing
    the next undo/redo actions. IDA only exposes the *next* action in each
    direction, not the full history stack.

    Returns: ``{"can_undo", "undo_action", "can_redo", "redo_action"}``
    """
    return _undo.get_status()


@mcp.tool
def perform_undo(steps: int = 1) -> dict:
    """Undo the last database action(s). Requires an open database.

    *steps* is how many undo steps to perform (default 1). If fewer steps
    are available than requested, performs as many as possible (partial success).

    The executor namespace is reset after undo since the database state changed.

    Returns: ``{"status", "steps_requested", "steps_performed", "actions", "next_undo", "next_redo"}``
    """
    return _undo.perform_undo(steps)


@mcp.tool
def perform_redo(steps: int = 1) -> dict:
    """Redo the last undone database action(s). Requires an open database.

    *steps* is how many redo steps to perform (default 1). If fewer steps
    are available than requested, performs as many as possible (partial success).

    The executor namespace is reset after redo since the database state changed.

    Returns: ``{"status", "steps_requested", "steps_performed", "actions", "next_undo", "next_redo"}``
    """
    return _undo.perform_redo(steps)


@mcp.tool
def list_structures(offset: int = 0, limit: int = 50, name_filter: str = "") -> dict:
    """List structures (structs/unions) in the database with pagination. Requires an open database.

    Returns name, size, alignment, and member count for each structure.

    *offset* skips the first N matching structures (for pagination).
    *limit* caps the number returned (default 50, max 1000).
    *name_filter* if non-empty, only includes structures whose name contains
    this substring (case-insensitive).

    Returns: ``{"structures": [{"name", "size", "alignment", "member_count"}], "total", "showing", "offset", "name_filter"}``
    """
    return _structures.list_structures(offset, min(limit, 1000), name_filter)


@mcp.tool
def get_structure(name: str) -> dict:
    """Get detailed info about a structure (struct/union) by name. Requires an open database.

    Returns name, size, alignment, is_union flag, member count, and the full
    C definition with ``/* offset */`` comments on each field.

    Returns: ``{"name", "size", "is_union", "alignment", "member_count", "definition"}``
    """
    return _structures.get_structure(name)


@mcp.tool
def create_structure(definition: str) -> dict:
    """Create a new structure from a C definition string. Requires an open database.

    *definition* is a valid C struct or union definition, e.g.:
    ``struct foo { int x; char *y; };``

    Fails if a structure with the same name already exists.
    Returns the newly created structure details.
    """
    return _structures.create_structure(definition)


@mcp.tool
def edit_structure(definition: str) -> dict:
    """Edit an existing structure by replacing its C definition. Requires an open database.

    *definition* is a valid C struct or union definition with the same name
    as an existing structure. The old definition is fully replaced.

    Fails if the structure does not exist.
    Returns the updated structure details.
    """
    return _structures.edit_structure(definition)


@mcp.tool
def delete_structure(name: str) -> dict:
    """Delete a structure (struct/union) by name. Requires an open database.

    Removes the named type from the database type library.
    Fails if the structure does not exist.
    """
    return _structures.delete_structure(name)


@mcp.tool
def get_variable(name: str, scope: str | None = None) -> dict:
    """Get info about a variable by name. Requires an open database.

    If *scope* is provided, looks up a **local** (decompiler) variable
    within that function.  *scope* can be a function name (e.g. "main") or hex
    address (e.g. "0x3f08").

    If *scope* is omitted, resolves *name* as a **global** variable
    (symbol name or address).

    Local variables require Hex-Rays.

    Returns (local): ``{"name", "type", "width", "is_arg", "function", "scope": "local"}``
    Returns (global): ``{"name", "type", "address", "scope": "global"}``
    """
    session.require_open()

    import ida_idaapi

    if scope is not None:
        func_ea = _resolve_address(scope)
        if func_ea == ida_idaapi.BADADDR:
            raise ToolError(f"Could not resolve function '{scope}' to an address.")
        return _variables.get_local_variable(func_ea, name)
    else:
        ea = _resolve_address(name)
        if ea == ida_idaapi.BADADDR:
            raise ToolError(f"Could not resolve '{name}' to an address.")
        return _variables.get_global_variable(ea)


@mcp.tool
def set_variable(
    name: str,
    scope: str | None = None,
    new_name: str | None = None,
    new_type: str | None = None,
) -> dict:
    """Rename and/or retype a variable. Requires an open database.

    If *scope* is provided, modifies a **local** (decompiler) variable
    within that function.  *scope* can be a function name or hex address.

    If *scope* is omitted, modifies a **global** variable.
    *name* is resolved as a symbol name or address.

    At least one of *new_name* or *new_type* must be provided.
    Local variables require Hex-Rays.
    """
    session.require_open()

    if new_name is None and new_type is None:
        raise ToolError("At least one of new_name or new_type must be provided.")

    import ida_idaapi

    if scope is not None:
        func_ea = _resolve_address(scope)
        if func_ea == ida_idaapi.BADADDR:
            raise ToolError(f"Could not resolve function '{scope}' to an address.")
        return _variables.set_local_variable(func_ea, name, new_name, new_type)
    else:
        ea = _resolve_address(name)
        if ea == ida_idaapi.BADADDR:
            raise ToolError(f"Could not resolve '{name}' to an address.")
        return _variables.set_global_variable(ea, new_name, new_type)


@mcp.tool
def get_comment(address: str, comment_type: CommentTypeOrAll = "") -> dict:
    """Get comment(s) at an address. Requires an open database.

    *address* can be a name (e.g. "main") or hex address (e.g. "0x3f08").

    *comment_type* selects which comment to read, or empty string (default)
    to return all non-empty comment types at once.

    - **regular** — inline comment on a disassembly line
    - **repeatable** — inline comment that propagates to cross-references
    - **function** — comment on the function header (ea must be in a function)
    - **anterior** — multi-line block before the address
    - **posterior** — multi-line block after the address
    """
    session.require_open()

    import ida_idaapi

    ea = _resolve_address(address)
    if ea == ida_idaapi.BADADDR:
        raise ToolError(f"Could not resolve '{address}' to an address.")
    return _comments.get_comment(ea, comment_type)


@mcp.tool
def set_comment(address: str, comment: str, comment_type: CommentType = "regular") -> dict:
    """Set a comment at an address. Requires an open database.

    *address* can be a name or hex address.
    *comment* is the comment text (use ``\\n`` for multi-line anterior/posterior).

    Returns: ``{"address", "comment_type", "comment", "status": "updated"}``
    """
    session.require_open()

    import ida_idaapi

    ea = _resolve_address(address)
    if ea == ida_idaapi.BADADDR:
        raise ToolError(f"Could not resolve '{address}' to an address.")
    return _comments.set_comment(ea, comment, comment_type)


@mcp.tool
def delete_comment(address: str, comment_type: CommentType = "regular") -> dict:
    """Delete a comment at an address. Requires an open database.

    *address* can be a name or hex address.

    Returns: ``{"address", "comment_type", "status": "deleted"}``
    """
    session.require_open()

    import ida_idaapi

    ea = _resolve_address(address)
    if ea == ida_idaapi.BADADDR:
        raise ToolError(f"Could not resolve '{address}' to an address.")
    return _comments.delete_comment(ea, comment_type)


@mcp.tool
def rename_function(function: str, new_name: str) -> dict:
    """Rename a function. Requires an open database.

    *function* can be a name (e.g. "sub_3f08") or hex address (e.g. "0x3f08").
    *new_name* is the new function name.

    Returns: ``{"address", "old_name", "new_name", "status": "renamed"}``
    """
    session.require_open()

    import ida_funcs
    import ida_idaapi
    import ida_name

    ea = _resolve_address(function)
    if ea == ida_idaapi.BADADDR:
        raise ToolError(f"Could not resolve '{function}' to an address.")

    pfn = ida_funcs.get_func(ea)
    if pfn is None:
        raise ToolError(f"Address {ea:#x} is not within a recognized function.")

    old_name = ida_funcs.get_func_name(pfn.start_ea) or f"sub_{pfn.start_ea:x}"
    ok = ida_name.set_name(pfn.start_ea, new_name, ida_name.SN_NOCHECK)
    if not ok:
        raise ToolError(f"Failed to rename function at {pfn.start_ea:#x} to '{new_name}'.")

    return {
        "address": f"{pfn.start_ea:#x}",
        "old_name": old_name,
        "new_name": new_name,
        "status": "renamed",
    }


@mcp.tool
def retype_function(function: str, new_type: str) -> dict:
    """Change a function's type signature. Requires an open database.

    *function* can be a name (e.g. "main") or hex address (e.g. "0x3f08").
    *new_type* is a C function type string (e.g. "int __fastcall(int argc, char **argv)").

    Returns: ``{"address", "name", "old_type", "new_type", "status": "retyped"}``
    """
    session.require_open()

    import ida_funcs
    import ida_idaapi
    import ida_typeinf
    import idc

    ea = _resolve_address(function)
    if ea == ida_idaapi.BADADDR:
        raise ToolError(f"Could not resolve '{function}' to an address.")

    pfn = ida_funcs.get_func(ea)
    if pfn is None:
        raise ToolError(f"Address {ea:#x} is not within a recognized function.")

    func_name = ida_funcs.get_func_name(pfn.start_ea) or f"sub_{pfn.start_ea:x}"

    # Get old type.
    old_type = idc.get_type(pfn.start_ea) or ""

    # Apply new type.
    ok = idc.SetType(pfn.start_ea, new_type)
    if not ok:
        raise ToolError(
            f"Failed to apply type '{new_type}' to function '{func_name}' at {pfn.start_ea:#x}. "
            "Check C syntax."
        )

    return {
        "address": f"{pfn.start_ea:#x}",
        "name": func_name,
        "old_type": old_type,
        "new_type": new_type,
        "status": "retyped",
    }


def _xref_type_name(xref_type: int) -> str:
    """Convert an IDA xref type constant to a human-readable name."""
    import ida_xref

    _NAMES = {
        ida_xref.fl_CF: "call_far",
        ida_xref.fl_CN: "call_near",
        ida_xref.fl_JF: "jump_far",
        ida_xref.fl_JN: "jump_near",
        ida_xref.fl_F: "ordinary_flow",
        ida_xref.dr_O: "data_offset",
        ida_xref.dr_W: "data_write",
        ida_xref.dr_R: "data_read",
        ida_xref.dr_T: "data_text",
        ida_xref.dr_I: "data_info",
    }
    return _NAMES.get(xref_type, f"unknown_{xref_type}")


@mcp.tool
def get_xrefs_to(address: str, max_results: int = 100) -> dict:
    """Get cross-references to an address (who references this?). Requires an open database.

    *address* can be a name (e.g. "main") or hex address (e.g. "0x3f08").
    *max_results* caps the number of xrefs returned (default 100).

    Returns: ``{"address", "xrefs": [{"from", "type"}], "count", "truncated"}``
    """
    session.require_open()

    import ida_idaapi
    import idautils

    ea = _resolve_address(address)
    if ea == ida_idaapi.BADADDR:
        raise ToolError(f"Could not resolve '{address}' to an address.")

    xrefs = []
    truncated = False
    for xref in idautils.XrefsTo(ea):
        if len(xrefs) >= max_results:
            truncated = True
            break
        xrefs.append({"from": f"{xref.frm:#x}", "type": _xref_type_name(xref.type)})

    return {
        "address": f"{ea:#x}",
        "xrefs": xrefs,
        "count": len(xrefs),
        "truncated": truncated,
    }


@mcp.tool
def get_xrefs_from(address: str, max_results: int = 100) -> dict:
    """Get cross-references from an address (what does this reference?). Requires an open database.

    *address* can be a name (e.g. "main") or hex address (e.g. "0x3f08").
    *max_results* caps the number of xrefs returned (default 100).

    Returns: ``{"address", "xrefs": [{"to", "type"}], "count", "truncated"}``
    """
    session.require_open()

    import ida_idaapi
    import idautils

    ea = _resolve_address(address)
    if ea == ida_idaapi.BADADDR:
        raise ToolError(f"Could not resolve '{address}' to an address.")

    xrefs = []
    truncated = False
    for xref in idautils.XrefsFrom(ea):
        if len(xrefs) >= max_results:
            truncated = True
            break
        xrefs.append({"to": f"{xref.to:#x}", "type": _xref_type_name(xref.type)})

    return {
        "address": f"{ea:#x}",
        "xrefs": xrefs,
        "count": len(xrefs),
        "truncated": truncated,
    }


@mcp.tool
def get_strings(min_length: int = 5, max_results: int = 200, name_filter: str = "") -> dict:
    """List strings found in the database. Requires an open database.

    *min_length* minimum string length to include (default 5).
    *max_results* caps the number of strings returned (default 200).
    *name_filter* if non-empty, only includes strings containing this
    substring (case-insensitive).

    Returns: ``{"strings": [{"address", "value", "length", "type"}], "count", "truncated"}``
    """
    session.require_open()

    import ida_nalt
    import idautils

    _TYPE_NAMES = {0: "C", 1: "C_16", 2: "C_32", 3: "PASCAL", 4: "PASCAL_16", 5: "LEN2", 6: "LEN4", 7: "LEN2_16"}

    sc = idautils.Strings()
    sc.setup(
        strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16],
        minlen=min_length,
    )

    strings = []
    truncated = False
    for s in sc:
        value = str(s)
        if name_filter and name_filter.lower() not in value.lower():
            continue
        if len(strings) >= max_results:
            truncated = True
            break
        strings.append({
            "address": f"{s.ea:#x}",
            "value": value,
            "length": s.length,
            "type": _TYPE_NAMES.get(s.strtype, f"type_{s.strtype}"),
        })

    return {
        "strings": strings,
        "count": len(strings),
        "truncated": truncated,
    }


@mcp.tool
def get_imports() -> dict:
    """List all imported functions grouped by module. Requires an open database.

    Returns: ``{"modules": [{"name", "imports": [{"address", "name", "ordinal"}]}], "total_imports"}``
    """
    session.require_open()

    import ida_nalt

    modules = []
    total_imports = 0

    for i in range(ida_nalt.get_import_module_qty()):
        mod_name = ida_nalt.get_import_module_name(i) or f"module_{i}"
        imports = []

        def _cb(ea, name, ordinal):
            imports.append({
                "address": f"{ea:#x}",
                "name": name or "",
                "ordinal": ordinal,
            })
            return True  # Continue enumeration.

        ida_nalt.enum_import_names(i, _cb)
        total_imports += len(imports)
        modules.append({"name": mod_name, "imports": imports})

    return {"modules": modules, "total_imports": total_imports}


@mcp.tool
def get_exports() -> dict:
    """List all exported functions/symbols. Requires an open database.

    Returns: ``{"exports": [{"address", "name", "ordinal"}], "count"}``
    """
    session.require_open()

    import idautils

    exports = []
    for ordinal, ea, name in idautils.Entries():
        exports.append({
            "address": f"{ea:#x}",
            "name": name or "",
            "ordinal": ordinal,
        })

    return {"exports": exports, "count": len(exports)}


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


@mcp.prompt
def reverse_engineer() -> str:
    """Comprehensive workflow for reverse engineering a binary with ida-code.

    Covers reconnaissance, triage, deep analysis, annotation, and iteration
    using the full set of MCP tools.
    """
    return _prompts.reverse_engineer()


@mcp.prompt
def create_script(target: str, description: str | None = None) -> str:
    """Coding guidelines and best practices for writing IDAPython scripts.

    *target* is one of: ``standalone_script``, ``plugin``, ``idapython_script``.
    *description* is an optional description of what the script should do.
    """
    return _prompts.create_script(target, description)


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
