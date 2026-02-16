import io
import logging
import signal
import sys
import traceback

log = logging.getLogger(__name__)

_MAX_OUTPUT = 50_000
_DEFAULT_TIMEOUT = 30  # seconds; 0 = no timeout

# Modules to pre-populate in the execution namespace.
_PRELOADED_MODULES = [
    "ida_funcs",
    "ida_bytes",
    "ida_name",
    "ida_segment",
    "ida_auto",
    "ida_idaapi",
    "ida_nalt",
    "ida_xref",
    "ida_ua",
    "ida_entry",
    "ida_lines",
    "ida_typeinf",
    "ida_hexrays",
    "idautils",
    "idc",
]

_namespace: dict = {}


def _build_namespace() -> dict:
    ns = {"__builtins__": __builtins__}
    for mod_name in _PRELOADED_MODULES:
        try:
            ns[mod_name] = __import__(mod_name)
        except ImportError:
            pass  # Some modules (e.g. ida_hexrays) may not be available.
    return ns


def reset() -> None:
    """Clear the execution namespace (called when the database changes)."""
    global _namespace
    _namespace = _build_namespace()


class _Timeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise _Timeout()


def execute(code: str, timeout: int = _DEFAULT_TIMEOUT) -> str:
    """Execute IDAPython code and return captured output.

    *timeout* sets the maximum wall-clock seconds (0 = unlimited).
    On expiry the code is interrupted and an error message is returned.
    """
    global _namespace

    # Lazy-init namespace on first call.
    if not _namespace:
        _namespace = _build_namespace()

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr
    old_handler = None

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        if timeout > 0:
            old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
            signal.alarm(timeout)

        log.debug("Executing code (%d chars, timeout=%ds)", len(code), timeout)
        exec(code, _namespace)
    except _Timeout:
        log.warning("Execution timed out after %ds", timeout)
        stderr_capture.write(f"\n\nExecution timed out after {timeout} seconds.")
    except (KeyboardInterrupt, SystemExit) as exc:
        log.warning("%s intercepted from user code", type(exc).__name__)
        stderr_capture.write(f"\n\n{type(exc).__name__} intercepted — the server is still running.\n")
        stderr_capture.write(traceback.format_exc())
    except Exception:
        log.debug("User code raised exception", exc_info=True)
        stderr_capture.write(traceback.format_exc())
    finally:
        if timeout > 0:
            signal.alarm(0)  # Cancel any pending alarm.
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    output = stdout_capture.getvalue() + stderr_capture.getvalue()

    if len(output) > _MAX_OUTPUT:
        output = output[:_MAX_OUTPUT] + f"\n\n[Output truncated at {_MAX_OUTPUT} characters]"

    return output
