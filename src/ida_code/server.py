from pathlib import Path

from fastmcp import FastMCP

from ida_code import session
from ida_code.executor import execute as _execute
from ida_code.doc_search import search as _search_docs

mcp = FastMCP("ida-code")


@mcp.tool
def open_database(path: str, auto_analysis: bool = True) -> str:
    """Open a binary or IDA database via idalib.

    Returns summary info (architecture, segments, entry points, function count).
    If a database is already open, it is closed first.
    """
    return session.open(path, auto_analysis)


@mcp.tool
def execute(code: str) -> str:
    """Execute IDAPython code and return captured output.

    The execution namespace persists across calls — variables and functions defined
    in one call are available in subsequent calls. Common ida_* modules are
    pre-imported (ida_funcs, ida_bytes, ida_name, idautils, idc, etc.).

    Python tracebacks are returned as normal output for debugging.
    """
    if session.get_state() == session.State.NO_DATABASE:
        return "Error: No database is open. Call open_database first."
    return _execute(code)


@mcp.tool
def execute_file(path: str, args: str | None = None) -> str:
    """Execute an IDAPython script file and return captured output.

    Reads the file at `path` and executes it. Optionally, `args` provides
    inline code that runs after the file in the same namespace — useful for
    calling functions defined in the script or inspecting results.

    The execution namespace persists across calls, same as `execute`.
    """
    if session.get_state() == session.State.NO_DATABASE:
        return "Error: No database is open. Call open_database first."

    p = Path(path)
    if not p.is_file():
        return f"Error: File not found: {path}"
    try:
        code = p.read_text(errors="replace")
    except OSError as e:
        return f"Error: Could not read file: {e}"

    if args:
        code = code + "\n" + args

    return _execute(code)


@mcp.tool
def search_docs(query: str, max_results: int = 10) -> str:
    """Search IDA documentation and Python API sources.

    Searches two corpora:
    - IDA HTML documentation (developer guide, user guide, etc.)
    - IDAPython API source files (ida_*.py function signatures and docstrings)

    Returns matching snippets with source attribution.
    """
    return _search_docs(query, max_results)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
