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
from ida_code.code_search import search as _search_code
from ida_code.ida_thread import on_ida_thread
from ida_code import comments as _comments
from ida_code import indirect_branch as _indirect_branch
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
        "Only one database can be open at a time. Most tools require an open database.\n\n"
        "Discovery: `guidelines://standalone_script`, `guidelines://plugin`, and "
        "`guidelines://idapython_script` resources hold code templates and Hex-Rays "
        "coding conventions — read whichever matches your task before writing. The "
        "`reverse_engineer` and `create_script` prompts walk through full workflows. "
        "For Python API signatures, idapro module, or example scripts use `search_code` "
        "(then `get_source` to fetch more lines from any file it returns); "
        "`search_docs` is HTML prose only (user-guide, developer-guide)."
    ),
)


# Tools that don't touch idalib stay as plain sync def. Everything else is
# `async def` and dispatches its body to the ida-thread via `on_ida_thread()`.
# idalib only works on the thread that imported `idapro`; pinning all idalib
# calls to a single dedicated worker keeps the asyncio loop free and is
# transport-agnostic across fastmcp v2 / v3.


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
async def open_database(
    path: str,
    auto_analysis: bool = True,
    overwrite: bool = False,
    timeout: int = 0,
    arch: str | None = None,
) -> dict:
    """Open a binary or IDA database via idalib.

    Returns summary info (architecture, segments, entry points, function count).
    If a database is already open, it is closed first.

    Set overwrite=True to delete any existing .i64/.idb database (and any
    unpacked .id0/.id1/.id2/.nam/.til fragments left by a failed open)
    and force a fresh analysis from the original binary.

    *timeout* limits auto-analysis wait time in seconds (default 0 = unlimited).
    When the timeout expires the database stays open with partial analysis
    and a warning is appended to the summary.

    *arch* selects a specific architecture slice from a fat (universal) Mach-O
    binary (e.g. "arm64e", "x86_64"). Use list_architectures to discover
    available slices. Ignored for non-fat binaries.

    Writing a standalone idalib script that calls this? First call
    ``get_guideline("standalone_script")`` for the bootstrap template
    (sys.path / IDADIR setup) and Hex-Rays coding conventions — those aren't
    in this docstring.
    """
    open_path, original_path = session._prepare_open(path, arch, overwrite)
    return await on_ida_thread(
        session._open_on_worker,
        open_path, auto_analysis, timeout, arch, original_path,
    )


@mcp.tool
async def get_database_info() -> dict:
    """Return summary info about the current database.

    Returns processor type, bitness, segments, entry points, and function count
    without opening or closing anything. If no database is open, says so.
    """
    return await on_ida_thread(session._info_on_worker)


@mcp.tool
async def close_database() -> dict:
    """Close the current database and free resources. Requires an open database.

    The executor namespace is cleared. No database will be open after this call.
    """
    def _impl():
        session.require_open()
        session._close_on_worker()
        return {"status": "closed"}
    return await on_ida_thread(_impl)


@mcp.tool
async def execute(code: str) -> dict:
    """Execute IDAPython code and return captured output. Requires an open database.

    The execution namespace persists across calls — variables and functions defined
    in one call are available in subsequent calls. Pre-imported modules:
    ``ida_funcs``, ``ida_bytes``, ``ida_name``, ``ida_segment``, ``ida_auto``,
    ``ida_idaapi``, ``ida_nalt``, ``ida_xref``, ``ida_ua``, ``ida_entry``,
    ``ida_lines``, ``ida_typeinf``, ``ida_hexrays``, ``idautils``, ``idc``.

    Python tracebacks are returned as normal output for debugging.

    Returns: ``{"output", "truncated"}``
    """
    def _impl():
        session.require_open()
        text = _execute(code)
        return {"output": text, "truncated": len(text) >= 50000}
    return await on_ida_thread(_impl)


@mcp.tool
async def execute_file(path: str, args: str | None = None) -> dict:
    """Execute an IDAPython script file and return captured output. Requires an open database.

    Reads the file at `path` and executes it. Optionally, `args` provides
    inline code that runs after the file in the same namespace — useful for
    calling functions defined in the script or inspecting results.

    The execution namespace persists across calls, same as `execute`.

    Returns: ``{"output", "truncated"}``
    """
    p = Path(path)
    if not p.is_file():
        raise ToolError(f"File not found: {path}")
    try:
        code = p.read_text(errors="replace")
    except OSError as e:
        raise ToolError(f"Could not read file: {e}")
    if args:
        code = code + "\n" + args

    def _impl():
        session.require_open()
        text = _execute(code)
        return {"output": text, "truncated": len(text) >= 50000}
    return await on_ida_thread(_impl)


def _resolve_address(identifier: str | int) -> int:
    """Resolve a name or numeric string to an address.

    Tries hex (with or without ``0x``), then decimal, then IDA name lookup.
    Returns ``ida_idaapi.BADADDR`` on failure. Must be called on the ida-thread.
    """
    import ida_idaapi
    import ida_name

    if isinstance(identifier, int): return identifier

    ea = ida_idaapi.BADADDR
    s = identifier.strip()

    try:
        ea = int(s, 16)
    except ValueError:
        pass

    if ea == ida_idaapi.BADADDR:
        try:
            ea = int(s, 10)
        except ValueError:
            pass

    if ea == ida_idaapi.BADADDR:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, s)

    return ea


@mcp.tool
async def decompile(function: str | int, max_length: int = 10000, offset: int = 0) -> dict:
    """Decompile a function and return pseudocode. Requires an open database.

    *function* can be a name (e.g. "main", "_objc_msgSend") or a hex address
    (e.g. "0x3f08", "3f08"). The address must fall within a recognized function.

    Requires the Hex-Rays decompiler.

    *max_length* caps the pseudocode returned (default 10000 chars).
    *offset* starts from this character position (for paging).
    If ``truncated`` is true, call again with ``offset=<offset + max_length>``
    to get the next page.
    """
    def _impl():
        session.require_open()
        import ida_funcs
        import ida_hexrays
        import ida_idaapi

        ea = _resolve_address(function)
        if ea == ida_idaapi.BADADDR:
            raise ToolError(f"Could not resolve '{function}' to an address.")

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
    return await on_ida_thread(_impl)


@mcp.tool
async def get_disassembly(start: str | int, length: int = 0x100) -> dict:
    """Get disassembly for an address range. Requires an open database.

    *start* can be a name (e.g. "main") or address (hex "0x3f08" / "3f08",
    decimal "16136"). *length* is the number of bytes from start to disassemble
    (default 256, capped at 64 KB).

    Returns: ``{"start", "end", "count", "instructions": [{"address", "disasm"}]}``
    """
    def _impl():
        session.require_open()
        import ida_idaapi
        import idc
        import idautils

        ea = _resolve_address(start)
        if ea == ida_idaapi.BADADDR:
            raise ToolError(f"Could not resolve '{start}' to an address.")

        capped_length = max(1, min(length, 0x10000))
        end_ea = ea + capped_length

        instructions: list[dict] = []
        for head in idautils.Heads(ea, end_ea):
            instructions.append({"address": f"{head:#x}", "disasm": idc.GetDisasm(head)})

        if not instructions:
            raise ToolError(f"No instructions found in range {ea:#x}–{end_ea:#x}.")

        return {
            "start": f"{ea:#x}",
            "end": f"{end_ea:#x}",
            "count": len(instructions),
            "instructions": instructions,
        }
    return await on_ida_thread(_impl)


@mcp.tool
async def list_functions(offset: int = 0, limit: int = 50, name_filter: str = "") -> dict:
    """List functions in the database with pagination. Requires an open database.

    Returns address, size, and name for each function.

    *offset* skips the first N functions (for pagination).
    *limit* caps the number of functions returned (default 50, max 1000).
    *name_filter* if non-empty, only includes functions whose name contains
    this substring (case-insensitive).

    If more results exist, increase *offset* by *limit* to get the next page.

    Returns: ``{"functions": [{"address", "size", "name"}], "total", "showing", "offset", "name_filter"}``
    """
    def _impl():
        session.require_open()
        import ida_funcs
        import idautils

        capped_limit = min(limit, 1000)
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
            if len(functions) >= capped_limit:
                break

        return {
            "functions": functions,
            "total": total,
            "showing": len(functions),
            "offset": offset,
            "name_filter": name_filter,
        }
    return await on_ida_thread(_impl)


GuidelineTarget = Literal["standalone_script", "plugin", "idapython_script"]


@mcp.tool
def get_guideline(target: GuidelineTarget) -> str:
    """Return the coding guideline for an IDA script type. No database needed.

    Read this BEFORE writing any IDA Python code. Covers the bootstrap
    template, key constraints (import order, single-thread, single-database),
    Hex-Rays coding conventions (avoid `idc.py`/`idaapi`/`from X import Y`,
    double-quote strings), and the search_code / search_docs / get_source
    workflow for finding APIs and examples.

    Targets:
      - ``standalone_script`` — uses idalib outside IDA. sys.path setup,
        ``import idapro`` first, ``open_database`` / ``close_database``.
      - ``plugin`` — IDA plugin loaded inside the GUI. Subclass of
        ``idaapi.plugin_t``, ``PLUGIN_ENTRY`` factory, hooks, actions.
      - ``idapython_script`` — classic IDAPython script run via File >
        Script File or the Python console. No bootstrap needed.

    Identical content is also available as the MCP resource
    ``guidelines://<target>``; the tool form is offered because tool listings
    are read more reliably than resource listings by most MCP clients.
    """
    return _guidelines.get(target)


CodeKind = Literal["library", "example", ""]


@mcp.tool
def search_code(
    query: str,
    kind: CodeKind = "",
    imports: str = "",
    category: ExampleCategory = "",
    level: ExampleLevel = "",
    docstring_only: bool = False,
    max_results: int = 5,
    max_snippet_lines: int = 10,
    max_snippet_line_chars: int = 200,
    include_docs: bool = True,
) -> dict:
    """Find Python source — API signatures, idapro module, and example scripts.

    **Primary tool for "what's the signature of X?" or "show me code that does Y"**
    queries — covers `ida_*.py`, `idautils.py`, `idc.py`, the standalone idalib
    `idapro` package, plus all in-IDA and idalib example scripts. No database
    needs to be open.

    Unified search over:

    - **Library** API definitions: top-level ``def``/``class`` from ``ida_*.py``,
      ``idautils.py``, ``idc.py``, and the standalone idalib ``idapro`` package.
      Result fields: ``kind`` (omitted when *kind* is set), ``title``,
      ``file``, ``snippet``, plus ``snippet_start_line`` + ``total_lines``
      when truncated.
    - **Example** scripts: the in-IDA examples in ``python/examples`` plus
      the standalone idalib examples in ``idalib/examples``. Result fields:
      ``kind``, ``file``, ``snippet``, plus optional ``title``, ``level``,
      ``category``, ``summary``, ``imports`` when set.

    Filters:

    - *kind*: empty string (default) returns both. ``"library"`` and
      ``"example"`` restrict to one kind.
    - *imports*: hard filter — only include results whose imports list
      contains the given module (e.g. ``imports="idapro"`` finds standalone
      idalib scripts; ``imports="lief"`` finds LIEF-based scripts).
    - *category*: example-only filter (``ui``, ``disassembler``, etc.).
      Library results pass through unconditionally.
    - *level*: example-only filter (``beginner``, etc.).
    - *docstring_only*: when ``True``, scoring restricts to docstring
      text only (library: docstring; example: summary + description).
      Useful for "find a function that DOES X" semantic queries that
      should ignore identifier-noise hits. Default ``False``.

    Snippet sizing:

    - *max_snippet_lines* caps the snippet's vertical height (default 10).
    - *max_snippet_line_chars* truncates each line at this width with
      ``...`` (default 200; set 0 to disable). Avoids one ultra-long
      docstring line bloating the response.
    - When the snippet doesn't cover the full source, the result includes
      ``snippet_start_line`` (1-based, file-absolute) and ``total_lines``.
      These let a follow-up read fetch the rest at the right offset.

    When *include_docs* is True (default), the response carries
    ``related_docs`` with up to 2 matching HTML documentation hits — useful
    for "show me everything about func X" in one call.
    """
    return _search_code(
        query,
        max_results=max_results,
        kind=kind,
        imports=imports,
        category=category,
        level=level,
        docstring_only=docstring_only,
        max_snippet_lines=max_snippet_lines,
        max_snippet_line_chars=max_snippet_line_chars,
        include_docs=include_docs,
    )


@mcp.tool
def search_docs(
    query: str,
    max_results: int = 5,
    max_snippet_words: int = 25,
    include_examples: bool = True,
) -> dict:
    """Look up IDA *HTML prose* documentation (user-guide / developer-guide).

    **For Python API signatures, idapro module, or example scripts, use
    `search_code` instead** — this tool only indexes the HTML docs, not
    Python source. No database needs to be open.

    Use this for conceptual context and chapter-style explanations:
    "what is auto-analysis", "how does the structure editor work", etc.

    Uses word-boundary matching: "set" matches "set_name" but not "reset".

    When *include_examples* is True (default), also returns up to 2 matching
    example scripts in the ``related_examples`` key (cross-linked from
    ``search_code`` with ``kind="example"``).

    *max_snippet_words* caps each snippet at this many whitespace-separated
    words (default 25). Word-based cap avoids mid-word truncation and aligns
    more closely with LLM token cost than character cap.
    """
    return _search_docs(query, max_results, max_snippet_words, include_examples)


@mcp.tool
def get_source(file: str, start_line: int = 1, line_count: int = 200) -> dict:
    """Read a slice of a Python file from the indexed corpora. No database needed.

    Companion to ``search_code``. When a search result includes
    ``snippet_start_line`` and ``total_lines`` (set when the snippet
    doesn't cover the full source), call ``get_source`` with the same
    ``file`` to fetch additional lines.

    *file* is the relative path returned by ``search_code`` (e.g.
    ``"idapro/__init__.py"``, ``"decompiler/vds_xrefs.py"``,
    ``"idacli.py"``). Sandboxed to the indexed corpora only —
    ``python/``, ``python/examples/``, ``idalib/python/``,
    ``idalib/examples/``. Files outside these roots cannot be read.

    *start_line* is 1-based (default 1).
    *line_count* caps the number of lines returned (default 200).

    Returns: ``{"file", "start_line", "end_line", "total_lines", "content"}``.
    ``end_line`` is inclusive. ``content`` is the joined slice; empty when
    ``start_line`` is past the end of the file.
    """
    from ida_code.code_search import resolve_file

    abs_path = resolve_file(file)
    if abs_path is None:
        raise ToolError(
            f"File not found in indexed corpora: {file!r}. "
            "Pass a `file` from a search_code or search_docs result."
        )

    try:
        text = abs_path.read_text(errors="replace")
    except OSError as exc:
        raise ToolError(f"Could not read {file!r}: {exc}")

    lines = text.splitlines()
    total = len(lines)

    start_line = max(1, start_line)
    line_count = max(0, line_count)
    end_line = min(total, start_line + line_count - 1)

    if start_line > total:
        return {
            "file": file,
            "start_line": start_line,
            "end_line": start_line - 1,
            "total_lines": total,
            "content": "",
        }

    return {
        "file": file,
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": total,
        "content": "\n".join(lines[start_line - 1 : end_line]),
    }


@mcp.tool
async def list_snapshots() -> dict:
    """List all database snapshots. Requires an open database.

    Returns snapshot IDs, descriptions, and filenames for the current database.

    Returns: ``{"snapshots": [{"id", "desc", "filename"}], "count"}``
    """
    return await on_ida_thread(_snapshots.list_snapshots)


@mcp.tool
async def create_snapshot(desc: str = "") -> dict:
    """Create a database snapshot to checkpoint the current state. Requires an open database.

    Snapshots let you save the database state before making destructive changes
    (renaming, patching, type changes) and roll back if needed.

    *desc* is an optional short description (max 128 chars).

    Returns: ``{"id", "desc", "filename"}``
    """
    return await on_ida_thread(_snapshots.create_snapshot, desc)


@mcp.tool
async def restore_snapshot(snapshot_id: str) -> dict:
    """Restore the database to a previous snapshot. Requires an open database.

    *snapshot_id* is the snapshot ID from list_snapshots or create_snapshot.
    The executor namespace is reset after restore since the database state changed.
    """
    return await on_ida_thread(_snapshots.restore_snapshot, snapshot_id)


@mcp.tool
async def delete_snapshot(snapshot_id: str) -> dict:
    """Delete a database snapshot by removing its file from disk. Requires an open database.

    *snapshot_id* is the snapshot ID from list_snapshots or create_snapshot.
    """
    return await on_ida_thread(_snapshots.remove_snapshot, snapshot_id)


@mcp.tool
async def get_undo_status() -> dict:
    """Check what undo/redo actions are available. Requires an open database.

    Returns whether undo and redo are possible, along with labels describing
    the next undo/redo actions. IDA only exposes the *next* action in each
    direction, not the full history stack.

    Returns: ``{"can_undo", "undo_action", "can_redo", "redo_action"}``
    """
    return await on_ida_thread(_undo.get_status)


@mcp.tool
async def perform_undo(steps: int = 1) -> dict:
    """Undo the last database action(s). Requires an open database.

    *steps* is how many undo steps to perform (default 1). If fewer steps
    are available than requested, performs as many as possible (partial success).

    The executor namespace is reset after undo since the database state changed.

    Returns: ``{"status", "steps_requested", "steps_performed", "actions", "next_undo", "next_redo"}``
    """
    return await on_ida_thread(_undo.perform_undo, steps)


@mcp.tool
async def perform_redo(steps: int = 1) -> dict:
    """Redo the last undone database action(s). Requires an open database.

    *steps* is how many redo steps to perform (default 1). If fewer steps
    are available than requested, performs as many as possible (partial success).

    The executor namespace is reset after redo since the database state changed.

    Returns: ``{"status", "steps_requested", "steps_performed", "actions", "next_undo", "next_redo"}``
    """
    return await on_ida_thread(_undo.perform_redo, steps)


@mcp.tool
async def list_structures(offset: int = 0, limit: int = 50, name_filter: str = "") -> dict:
    """List structures (structs/unions) in the database with pagination. Requires an open database.

    Returns name, size, alignment, and member count for each structure.

    *offset* skips the first N matching structures (for pagination).
    *limit* caps the number returned (default 50, max 1000).
    *name_filter* if non-empty, only includes structures whose name contains
    this substring (case-insensitive).

    Returns: ``{"structures": [{"name", "size", "alignment", "member_count"}], "total", "showing", "offset", "name_filter"}``
    """
    return await on_ida_thread(
        _structures.list_structures, offset, min(limit, 1000), name_filter,
    )


@mcp.tool
async def get_structure(name: str) -> dict:
    """Get detailed info about a structure (struct/union) by name. Requires an open database.

    Returns name, size, alignment, is_union flag, member count, and the full
    C definition with ``/* offset */`` comments on each field.

    Returns: ``{"name", "size", "is_union", "alignment", "member_count", "definition"}``
    """
    return await on_ida_thread(_structures.get_structure, name)


@mcp.tool
async def create_structure(definition: str) -> dict:
    """Create a new structure from a C definition string. Requires an open database.

    *definition* is a valid C struct or union definition, e.g.:
    ``struct foo { int x; char *y; };``

    Fails if a structure with the same name already exists.
    Returns the newly created structure details.
    """
    return await on_ida_thread(_structures.create_structure, definition)


@mcp.tool
async def edit_structure(definition: str) -> dict:
    """Edit an existing structure by replacing its C definition. Requires an open database.

    *definition* is a valid C struct or union definition with the same name
    as an existing structure. The old definition is fully replaced.

    Fails if the structure does not exist.
    Returns the updated structure details.
    """
    return await on_ida_thread(_structures.edit_structure, definition)


@mcp.tool
async def delete_structure(name: str) -> dict:
    """Delete a structure (struct/union) by name. Requires an open database.

    Removes the named type from the database type library.
    Fails if the structure does not exist.
    """
    return await on_ida_thread(_structures.delete_structure, name)


@mcp.tool
async def get_variable(name: str, scope: str | None = None) -> dict:
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
    def _impl():
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
    return await on_ida_thread(_impl)


@mcp.tool
async def set_variable(
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
    if new_name is None and new_type is None:
        raise ToolError("At least one of new_name or new_type must be provided.")

    def _impl():
        session.require_open()
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
    return await on_ida_thread(_impl)


@mcp.tool
async def get_comment(address: str | int, comment_type: CommentTypeOrAll = "") -> dict:
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
    def _impl():
        session.require_open()
        import ida_idaapi
        ea = _resolve_address(address)
        if ea == ida_idaapi.BADADDR:
            raise ToolError(f"Could not resolve '{address}' to an address.")
        return _comments.get_comment(ea, comment_type)
    return await on_ida_thread(_impl)


@mcp.tool
async def set_comment(address: str | int, comment: str, comment_type: CommentType = "regular") -> dict:
    """Set a comment at an address. Requires an open database.

    *address* can be a name or hex address.
    *comment* is the comment text (use ``\\n`` for multi-line anterior/posterior).

    Returns: ``{"address", "comment_type", "comment", "status": "updated"}``
    """
    def _impl():
        session.require_open()
        import ida_idaapi
        ea = _resolve_address(address)
        if ea == ida_idaapi.BADADDR:
            raise ToolError(f"Could not resolve '{address}' to an address.")
        return _comments.set_comment(ea, comment, comment_type)
    return await on_ida_thread(_impl)


@mcp.tool
async def delete_comment(address: str | int, comment_type: CommentType = "regular") -> dict:
    """Delete a comment at an address. Requires an open database.

    *address* can be a name or hex address.

    Returns: ``{"address", "comment_type", "status": "deleted"}``
    """
    def _impl():
        session.require_open()
        import ida_idaapi
        ea = _resolve_address(address)
        if ea == ida_idaapi.BADADDR:
            raise ToolError(f"Could not resolve '{address}' to an address.")
        return _comments.delete_comment(ea, comment_type)
    return await on_ida_thread(_impl)


@mcp.tool
async def rename_function(function: str | int, new_name: str) -> dict:
    """Rename a function. Requires an open database.

    *function* can be a name (e.g. "sub_3f08") or hex address (e.g. "0x3f08").
    *new_name* is the new function name.

    Returns: ``{"address", "old_name", "new_name", "status": "renamed"}``
    """
    def _impl():
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
    return await on_ida_thread(_impl)


@mcp.tool
async def retype_function(function: str | int, new_type: str) -> dict:
    """Change a function's type signature. Requires an open database.

    *function* can be a name (e.g. "main") or hex address (e.g. "0x3f08").
    *new_type* is a C function type string (e.g. "int __fastcall(int argc, char **argv)").

    Returns: ``{"address", "name", "old_type", "new_type", "status": "retyped"}``
    """
    def _impl():
        session.require_open()
        import ida_funcs
        import ida_idaapi
        import ida_typeinf  # noqa: F401  # ensures the typeinf module is loaded
        import idc

        ea = _resolve_address(function)
        if ea == ida_idaapi.BADADDR:
            raise ToolError(f"Could not resolve '{function}' to an address.")

        pfn = ida_funcs.get_func(ea)
        if pfn is None:
            raise ToolError(f"Address {ea:#x} is not within a recognized function.")

        func_name = ida_funcs.get_func_name(pfn.start_ea) or f"sub_{pfn.start_ea:x}"
        old_type = idc.get_type(pfn.start_ea) or ""
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
    return await on_ida_thread(_impl)


def _xref_type_name(xref_type: int) -> str:
    """Convert an IDA xref type constant to a human-readable name. ida-thread only."""
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
async def get_xrefs_to(address: str | int, max_results: int = 100) -> dict:
    """Get cross-references to an address (who references this?). Requires an open database.

    *address* can be a name (e.g. "main") or hex address (e.g. "0x3f08").
    *max_results* caps the number of xrefs returned (default 100).

    Returns: ``{"address", "xrefs": [{"from", "type"}], "count", "truncated"}``
    """
    def _impl():
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
    return await on_ida_thread(_impl)


@mcp.tool
async def get_xrefs_from(address: str | int, max_results: int = 100) -> dict:
    """Get cross-references from an address (what does this reference?). Requires an open database.

    *address* can be a name (e.g. "main") or hex address (e.g. "0x3f08").
    *max_results* caps the number of xrefs returned (default 100).

    Returns: ``{"address", "xrefs": [{"to", "type"}], "count", "truncated"}``
    """
    def _impl():
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
    return await on_ida_thread(_impl)


IndirectBranchStatus = Literal["any", "resolved", "unresolved"]


@mcp.tool
async def list_indirect_branches(
    function: str | None = None,
    status: IndirectBranchStatus = "unresolved",
) -> dict:
    """List indirect-branch sites (calls/jumps via register) with a digest.

    Requires an open database. Use this to triage which branches need
    LLM resolution; then call ``get_indirect_branch`` on individual
    sites for details, and ``set_indirect_branch`` to record your
    judgment.

    *function* — restrict to one function (name or hex address). None = whole db.
    *status*   — ``unresolved`` (default), ``resolved``, or ``any``.

    Returns: ``{"scope", "status", "count", "sites": [{"addr", "kind",
    "containing_function", "has_resolution", "num_targets"}]}``.
    """
    return await on_ida_thread(lambda: _indirect_branch.list_indirect_branches(function, status))


@mcp.tool
async def get_indirect_branch(addr: str) -> dict:
    """Get what we know about a single indirect-branch site. Requires an open database.

    *addr* — name or hex address of the branch instruction.

    Returns at minimum: ``{"addr", "kind": "call"|"jmp",
    "containing_function", "existing_resolution"}``. Later passes add
    backward-slice, candidates, and arm64e PAC discriminator fields.

    ``existing_resolution`` is the parsed ``@RESOLVED_V1`` block from
    the site's comment (or null if not yet resolved).
    """
    return await on_ida_thread(lambda: _indirect_branch.get_indirect_branch(addr))


@mcp.tool
async def set_indirect_branch(
    addr: str,
    targets: list[dict] | None = None,
    unresolvable_reason: str = "",
) -> dict:
    """Record your resolution for an indirect-branch site. Requires an open database.

    Either pass non-empty *targets* — list of ``{"addr", "confidence",
    "reason"}`` per-target dicts with confidence in
    ``{"certain", "likely", "speculative"}`` — OR pass a non-empty
    *unresolvable_reason* to mark the site as a dead-end.

    Persists in the .i64 via two mechanisms:
      - One manual code xref per target (visible to ``get_xrefs_from``).
      - An ``@RESOLVED_V1`` block in the site's regular comment.

    Returns: ``{"addr", "status", "targets_recorded", "xrefs_added",
    "unresolvable"}``.
    """
    return await on_ida_thread(
        lambda: _indirect_branch.set_indirect_branch(addr, targets, unresolvable_reason)
    )


@mcp.tool
async def get_strings(min_length: int = 5, max_results: int = 200, name_filter: str = "") -> dict:
    """List strings found in the database. Requires an open database.

    *min_length* minimum string length to include (default 5).
    *max_results* caps the number of strings returned (default 200).
    *name_filter* if non-empty, only includes strings containing this
    substring (case-insensitive).

    Returns: ``{"strings": [{"address", "value", "length", "type"}], "count", "truncated"}``
    """
    def _impl():
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
    return await on_ida_thread(_impl)


@mcp.tool
async def get_imports() -> dict:
    """List all imported functions grouped by module. Requires an open database.

    Returns: ``{"modules": [{"name", "imports": [{"address", "name", "ordinal"}]}], "total_imports"}``
    """
    def _impl():
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
                return True

            ida_nalt.enum_import_names(i, _cb)
            total_imports += len(imports)
            modules.append({"name": mod_name, "imports": imports})

        return {"modules": modules, "total_imports": total_imports}
    return await on_ida_thread(_impl)


@mcp.tool
async def get_exports() -> dict:
    """List all exported functions/symbols. Requires an open database.

    Returns: ``{"exports": [{"address", "name", "ordinal"}], "count"}``
    """
    def _impl():
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
    return await on_ida_thread(_impl)


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
    if ":" in value:
        host, _, port_str = value.rpartition(":")
        host = host or "127.0.0.1"
        return host, int(port_str)
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
