import atexit
import enum
import logging
import os
import sys

from ida_code.config import IDA_INSTALL_DIR

log = logging.getLogger(__name__)

# Add idalib's Python package to sys.path so `idapro` can be imported
# without requiring manual `pip install`.
_idalib_python = IDA_INSTALL_DIR / "idalib" / "python"
if _idalib_python.is_dir() and str(_idalib_python) not in sys.path:
    sys.path.insert(0, str(_idalib_python))

# Set IDADIR so idapro finds the IDA install directory
# without requiring `py-activate-idalib.py`.
os.environ.setdefault("IDADIR", str(IDA_INSTALL_DIR))

import idapro


class State(enum.Enum):
    NO_DATABASE = "no_database"
    DATABASE_OPEN = "database_open"


_state = State.NO_DATABASE
_db_path: str | None = None
_db_file_path: str | None = None  # actual .i64/.idb path on disk
_orphaned: bool = False  # True when database file vanished from disk


def get_state() -> State:
    return _state


def _find_database_file(path: str) -> str | None:
    """Find the .i64/.idb database file for *path*.

    Checks both naming conventions IDA uses: replace-suffix and append.
    Returns the path if found, else None.
    """
    from pathlib import Path
    p = Path(path)
    for ext in (".i64", ".idb"):
        for candidate in (p.with_suffix(ext), Path(str(p) + ext)):
            if candidate.is_file():
                return str(candidate)
    return None


def require_open() -> None:
    """Raise ``ToolError`` if no database is usable.

    Checks both the state enum *and* that the database file still exists
    on disk. If the file has been moved or deleted, resets state to
    ``NO_DATABASE`` and raises a descriptive error instead of letting
    idalib segfault.
    """
    from fastmcp.exceptions import ToolError

    global _state, _db_file_path, _orphaned

    if _state == State.NO_DATABASE:
        raise ToolError("No database is open. Call open_database first.")

    if _db_file_path is not None and not os.path.isfile(_db_file_path):
        log.warning(
            "Database file missing: %s — resetting state", _db_file_path
        )
        _state = State.NO_DATABASE
        _orphaned = True
        _db_file_path = None
        from ida_code.executor import reset
        reset()
        raise ToolError(
            "The database file has been moved or deleted. "
            "Call open_database with the new path."
        )


def info() -> dict:
    """Return a summary dict of the current database.

    Raises ``ToolError`` if no database is open.
    """
    require_open()
    return _collect_summary(_db_path or "<unknown>")


def open(
    path: str,
    auto_analysis: bool = True,
    overwrite: bool = False,
    timeout: int = 0,
    arch: str | None = None,
) -> dict:
    """Open a binary/database via idalib. Returns a summary dict.

    *timeout* limits auto-analysis wait time in seconds (0 = unlimited).
    When the timeout expires, the database remains open with partial analysis.

    *arch* selects a specific architecture slice from a fat (universal) Mach-O
    binary (e.g. "arm64e", "x86_64"). The slice is extracted to a temporary
    thin file before opening. Ignored for non-fat binaries.

    Raises ``ToolError`` on failure.
    """
    from fastmcp.exceptions import ToolError

    from ida_code import macho

    global _state, _db_path, _db_file_path, _orphaned

    _orphaned = False

    # Close any existing database first.
    if _state == State.DATABASE_OPEN:
        close()

    # If an architecture is requested, extract the slice from a fat Mach-O.
    open_path = path
    if arch:
        try:
            open_path = macho.extract_slice(path, arch)
        except ValueError:
            # Not a fat binary or arch not found.
            available = macho.list_architectures(path)
            if available:
                raise ToolError(
                    f"Architecture '{arch}' not found. "
                    f"Available: {available}"
                )
            log.warning(
                "arch='%s' requested but %s is not a fat Mach-O; "
                "opening as-is",
                arch, path,
            )

    if overwrite:
        _remove_existing_databases(open_path)

    use_polling = auto_analysis and timeout > 0
    run_auto = auto_analysis and not use_polling

    log.info(
        "Opening database: %s (auto_analysis=%s, overwrite=%s, timeout=%d, arch=%s)",
        open_path, auto_analysis, overwrite, timeout, arch,
    )
    rc = idapro.open_database(open_path, run_auto)
    if rc != 0:
        log.error("open_database failed with code %d for %s", rc, open_path)
        raise ToolError(f"open_database returned code {rc}")

    _state = State.DATABASE_OPEN
    _db_path = open_path
    _db_file_path = _find_database_file(open_path)

    timed_out = False
    if use_polling:
        timed_out = _wait_for_analysis(timeout)

    log.info("Database opened successfully: %s", open_path)

    # Reset executor namespace for the new database.
    from ida_code.executor import reset
    reset()

    summary = _collect_summary(open_path)
    if arch:
        summary["arch"] = arch
        summary["original_path"] = path
    summary["warning"] = (
        "Auto-analysis timed out \u2014 results may be incomplete."
        if timed_out
        else None
    )
    return summary


def _wait_for_analysis(timeout: int) -> bool:
    """Poll until auto-analysis finishes or *timeout* seconds elapse.

    Returns True if the timeout expired (analysis incomplete).
    """
    import time
    import ida_auto
    import ida_funcs

    deadline = time.monotonic() + timeout
    interval = 0.5  # seconds between polls
    last_count = 0

    while not ida_auto.auto_is_ok():
        now = time.monotonic()
        if now >= deadline:
            log.warning("Auto-analysis timed out after %ds", timeout)
            return True

        count = ida_funcs.get_func_qty()
        if count != last_count:
            log.info("Auto-analysis in progress: %d functions so far", count)
            last_count = count

        remaining = deadline - now
        time.sleep(min(interval, remaining))

    log.info("Auto-analysis completed")
    return False


def _collect_summary(path: str) -> dict:
    import ida_ida
    import ida_entry
    import ida_segment
    import idautils

    processor = ida_ida.inf_get_procname()
    bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit() else 16)

    # Segments
    segments = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        name = ida_segment.get_segm_name(seg)
        segments.append({
            "name": name,
            "start": f"{seg.start_ea:#x}",
            "end": f"{seg.end_ea:#x}",
        })

    # Entry points (capped to avoid huge responses for symbol-heavy binaries)
    entry_count = ida_entry.get_entry_qty()
    max_entries = 20
    entry_points = []
    for i in range(min(entry_count, max_entries)):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        entry_points.append({"name": name, "address": f"{ea:#x}"})

    # Function count
    func_count = sum(1 for _ in idautils.Functions())

    return {
        "path": path,
        "processor": processor,
        "bits": bits,
        "function_count": func_count,
        "segments": segments,
        "entry_point_count": entry_count,
        "entry_points": entry_points,
    }


def _remove_existing_databases(path: str) -> None:
    """Remove existing IDA database files so a fresh analysis starts."""
    from pathlib import Path
    p = Path(path)
    for ext in (".i64", ".idb"):
        for candidate in {p.with_suffix(ext), Path(str(p) + ext)}:
            if candidate.is_file():
                candidate.unlink()


def close() -> None:
    """Close the current database."""
    global _state, _db_path, _db_file_path, _orphaned
    if _state == State.DATABASE_OPEN:
        log.info("Closing database")
        if not _orphaned:
            idapro.close_database()
        _state = State.NO_DATABASE
        _db_path = None
        _db_file_path = None
        _orphaned = False
        from ida_code.executor import reset
        reset()


@atexit.register
def _cleanup():
    close()
