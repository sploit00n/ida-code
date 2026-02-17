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


def get_state() -> State:
    return _state


def info() -> str:
    """Return a summary of the current database, or a no-database message."""
    if _state == State.NO_DATABASE:
        return "No database is currently open."
    return _collect_summary(_db_path or "<unknown>")


def open(
    path: str,
    auto_analysis: bool = True,
    overwrite: bool = False,
    timeout: int = 0,
) -> str:
    """Open a binary/database via idalib. Returns a summary string.

    *timeout* limits auto-analysis wait time in seconds (0 = unlimited).
    When the timeout expires, the database remains open with partial analysis.
    """
    global _state, _db_path

    # Close any existing database first.
    if _state == State.DATABASE_OPEN:
        close()

    if overwrite:
        _remove_existing_databases(path)

    use_polling = auto_analysis and timeout > 0
    run_auto = auto_analysis and not use_polling

    log.info(
        "Opening database: %s (auto_analysis=%s, overwrite=%s, timeout=%d)",
        path, auto_analysis, overwrite, timeout,
    )
    rc = idapro.open_database(path, run_auto)
    if rc != 0:
        log.error("open_database failed with code %d for %s", rc, path)
        return f"Error: open_database returned code {rc}"

    _state = State.DATABASE_OPEN
    _db_path = path

    timed_out = False
    if use_polling:
        timed_out = _wait_for_analysis(timeout)

    log.info("Database opened successfully: %s", path)

    # Reset executor namespace for the new database.
    from ida_code.executor import reset
    reset()

    summary = _collect_summary(path)
    if timed_out:
        summary += "\n\nWarning: Auto-analysis timed out — results may be incomplete."
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


def _collect_summary(path: str) -> str:
    import ida_ida
    import ida_entry
    import ida_segment
    import idautils

    info = ida_ida.inf_get_procname()
    bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit() else 16)

    # Segments
    segments = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        name = ida_segment.get_segm_name(seg)
        segments.append(f"  {name}: {seg.start_ea:#x}-{seg.end_ea:#x}")

    # Entry points
    entries = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        entries.append(f"  {name}: {ea:#x}")

    # Function count
    func_count = sum(1 for _ in idautils.Functions())

    lines = [
        f"Database opened: {path}",
        f"Processor: {info} ({bits}-bit)",
        f"Functions: {func_count}",
        f"Segments ({len(segments)}):",
        *segments,
    ]
    if entries:
        lines.append(f"Entry points ({len(entries)}):")
        lines.extend(entries[:20])
        if len(entries) > 20:
            lines.append(f"  ... and {len(entries) - 20} more")

    return "\n".join(lines)


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
    global _state, _db_path
    if _state == State.DATABASE_OPEN:
        log.info("Closing database")
        idapro.close_database()
        _state = State.NO_DATABASE
        _db_path = None
        from ida_code.executor import reset
        reset()


@atexit.register
def _cleanup():
    close()
