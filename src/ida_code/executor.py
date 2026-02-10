import io
import sys
import traceback

_MAX_OUTPUT = 50_000

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


def execute(code: str) -> str:
    """Execute IDAPython code and return captured output."""
    global _namespace

    # Lazy-init namespace on first call.
    if not _namespace:
        _namespace = _build_namespace()

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture
        exec(code, _namespace)
    except Exception:
        stderr_capture.write(traceback.format_exc())
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    output = stdout_capture.getvalue() + stderr_capture.getvalue()

    if len(output) > _MAX_OUTPUT:
        output = output[:_MAX_OUTPUT] + f"\n\n[Output truncated at {_MAX_OUTPUT} characters]"

    return output
