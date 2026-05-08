"""idalib session lifecycle: import, open/close/info, state.

All idalib calls must run on the ida-thread (see ``ida_thread.py``). idalib
fixes thread affinity at ``import idapro`` time and hangs on any other
thread. The public ``open()``, ``close()``, ``info()`` here auto-dispatch
to the ida-thread when called from elsewhere; the actual idapro calls live
in private ``_*_on_worker`` helpers.

Module globals (``_state``, ``_db_path``, ``_db_file_path``, ``_orphaned``,
``idapro``) are mutated only by the ida-thread. CPython attribute reads are
atomic, so reads from other threads are safe without locking.
"""

import enum
import logging
import os
import sys
import threading

from ida_code.config import IDA_INSTALL_DIR
from ida_code import ida_thread

log = logging.getLogger(__name__)

# Add idalib's Python package to sys.path so `import idapro` works on the
# ida-thread without manual `pip install`. Path setup is thread-safe.
_idalib_python = IDA_INSTALL_DIR / "idalib" / "python"
if _idalib_python.is_dir() and str(_idalib_python) not in sys.path:
    sys.path.insert(0, str(_idalib_python))

# Set IDADIR so idapro finds the IDA install dir without `py-activate-idalib.py`.
os.environ.setdefault("IDADIR", str(IDA_INSTALL_DIR))


# Populated by `_ensure_idalib_loaded()` on the ida-thread on first use.
# Tests can pre-set this to a Mock to bypass the real import.
idapro = None


class State(enum.Enum):
    NO_DATABASE = "no_database"
    DATABASE_OPEN = "database_open"


_state = State.NO_DATABASE
_db_path: str | None = None
_db_file_path: str | None = None  # actual .i64/.idb path on disk
_orphaned: bool = False  # True when database file vanished from disk


def _ensure_idalib_loaded() -> None:
    """Import ``idapro`` on the current thread (must be the ida-thread).

    Idempotent: subsequent calls return immediately. Targets a known quirk:
    ``idapro/__init__.py`` calls ``signal.signal(SIGINT, SIG_DFL)`` at module
    top, which raises ``ValueError`` on non-main threads. We monkey-patch
    ``signal.signal`` for *only* that exact call so the rest of init runs
    cleanly without printing a noisy traceback.
    """
    global idapro
    if idapro is not None:
        return

    import signal as _signal
    _real_signal_signal = _signal.signal

    def _patched(signum, handler):
        # Silence init.py's `signal.signal(SIGINT, SIG_DFL)` on non-main thread.
        # Pass everything else through so other signal hookers in idalib's init
        # behave normally.
        on_main = threading.current_thread() is threading.main_thread()
        if not on_main and signum == _signal.SIGINT and handler == _signal.SIG_DFL:
            return _signal.SIG_DFL
        return _real_signal_signal(signum, handler)

    _signal.signal = _patched
    try:
        import idapro as _imported_idapro
    except ImportError as exc:
        raise ImportError(
            f"Could not import idapro from {_idalib_python}. "
            f"Set IDA_INSTALL_DIR to your IDA Pro 9.2+ installation directory "
            f"(currently {IDA_INSTALL_DIR}). Original error: {exc}"
        ) from exc
    finally:
        _signal.signal = _real_signal_signal

    idapro = _imported_idapro
    log.debug("idapro imported on ida-thread tid=%d", threading.get_ident())


def _on_ida_thread() -> bool:
    return threading.current_thread() is ida_thread._thread


def _dispatch(fn, *args, **kwargs):
    """Run ``fn`` on the ida-thread, blocking until it returns.

    If already on the ida-thread, runs inline (no submit). Used by the
    public sync entry points (``open``, ``close``, ``info``) so they're
    callable from any thread; for async callers prefer
    ``await ida_thread.on_ida_thread(_impl, ...)`` directly.
    """
    if _on_ida_thread():
        return fn(*args, **kwargs)
    return ida_thread.submit(fn, *args, **kwargs).result()


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
    """Return a summary dict of the current database. Auto-dispatches."""
    return _dispatch(_info_on_worker)


def _info_on_worker() -> dict:
    require_open()
    return _collect_summary(_db_path or "<unknown>")


def open(
    path: str,
    auto_analysis: bool = True,
    overwrite: bool = False,
    timeout: int = 0,
    arch: str | None = None,
) -> dict:
    """Open a binary/database via idalib. Auto-dispatches to the ida-thread.

    *timeout* limits auto-analysis wait time in seconds (0 = unlimited).
    When the timeout expires, the database remains open with partial analysis.

    *arch* selects a specific architecture slice from a fat (universal) Mach-O
    binary (e.g. "arm64e", "x86_64"). The slice is extracted before opening.

    Raises ``ToolError`` on failure.
    """
    open_path, original_path = _prepare_open(path, arch, overwrite)
    return _dispatch(
        _open_on_worker, open_path, auto_analysis, timeout, arch, original_path,
    )


def _prepare_open(path: str, arch: str | None, overwrite: bool) -> tuple[str, str]:
    """Asyncio-safe pre-work: resolve arch slice, clean or precheck fragments.

    Returns ``(open_path, original_path)``. Does no idalib calls — runs on
    whatever thread invokes ``open()``.
    """
    from fastmcp.exceptions import ToolError
    from ida_code import macho

    open_path = path
    if arch:
        try:
            open_path = macho.extract_slice(path, arch)
        except ValueError:
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
    else:
        fragments = _list_unpacked_fragments(open_path)
        if fragments:
            raise ToolError(
                f"Unpacked database fragments exist: {fragments}. "
                f"This usually means another IDA instance has this database "
                f"open, or a previous open failed and left them behind. "
                f"If no other IDA process is using this database, re-call "
                f"with overwrite=True to clean them up — but doing so while "
                f"another IDA has it open will destroy that session's work."
            )

    return open_path, path


def _open_on_worker(
    open_path: str,
    auto_analysis: bool,
    timeout: int,
    arch: str | None,
    original_path: str,
) -> dict:
    """Runs on the ida-thread: closes any existing DB, opens, collects summary."""
    from fastmcp.exceptions import ToolError

    global _state, _db_path, _db_file_path, _orphaned

    _ensure_idalib_loaded()
    _orphaned = False

    if _state == State.DATABASE_OPEN:
        _close_on_worker()

    use_polling = auto_analysis and timeout > 0
    run_auto = auto_analysis and not use_polling

    log.info(
        "Opening database: %s (auto_analysis=%s, timeout=%d, arch=%s)",
        open_path, auto_analysis, timeout, arch,
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

    from ida_code.executor import reset
    reset()

    summary = _collect_summary(open_path)
    if arch:
        summary["arch"] = arch
        summary["original_path"] = original_path
    summary["warning"] = (
        "Auto-analysis timed out — results may be incomplete."
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
    interval = 0.5
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

    segments = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        name = ida_segment.get_segm_name(seg)
        segments.append({
            "name": name,
            "start": f"{seg.start_ea:#x}",
            "end": f"{seg.end_ea:#x}",
        })

    entry_count = ida_entry.get_entry_qty()
    max_entries = 20
    entry_points = []
    for i in range(min(entry_count, max_entries)):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        entry_points.append({"name": name, "address": f"{ea:#x}"})

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


_DB_EXTENSIONS = (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til")
_UNPACKED_FRAGMENT_EXTS = (".id0", ".id1", ".id2", ".nam", ".til")


def _list_unpacked_fragments(path: str) -> list[str]:
    """Return any unpacked database fragments existing for *path*.

    These exist while a database is open in IDA, and can also be left
    behind when a previous open failed mid-unpacking. Their presence
    makes ``idapro.open_database`` refuse the path with rc=-1.
    """
    from pathlib import Path
    p = Path(path)
    found = []
    for ext in _UNPACKED_FRAGMENT_EXTS:
        for candidate in {p.with_suffix(ext), Path(str(p) + ext)}:
            if candidate.is_file():
                found.append(str(candidate))
    return found


def _remove_existing_databases(path: str) -> None:
    """Remove existing IDA database files and unpacked fragments."""
    from pathlib import Path
    p = Path(path)
    for ext in _DB_EXTENSIONS:
        for candidate in {p.with_suffix(ext), Path(str(p) + ext)}:
            if candidate.is_file():
                candidate.unlink()


def close() -> None:
    """Close the current database. Auto-dispatches to the ida-thread."""
    _dispatch(_close_on_worker)


def _close_on_worker() -> None:
    global _state, _db_path, _db_file_path, _orphaned
    if _state == State.DATABASE_OPEN:
        log.info("Closing database")
        if not _orphaned and idapro is not None:
            idapro.close_database()
        _state = State.NO_DATABASE
        _db_path = None
        _db_file_path = None
        _orphaned = False
        from ida_code.executor import reset
        reset()
