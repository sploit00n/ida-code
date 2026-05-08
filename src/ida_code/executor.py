import ast
import io
import logging
import sys
import traceback

log = logging.getLogger(__name__)

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


def _exec_repl(code: str, namespace: dict, stdout: io.StringIO) -> None:
    """Execute *code* with REPL-like last-expression printing.

    If the last statement is a bare expression (not an assignment, not a
    function call used for side-effects via print, etc.), its repr is
    written to *stdout* — just like the interactive Python prompt.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        exec(code, namespace)
        return

    if not tree.body:
        return

    last = tree.body[-1]
    if not isinstance(last, ast.Expr):
        exec(code, namespace)
        return

    if len(tree.body) > 1:
        head = ast.Module(body=tree.body[:-1], type_ignores=tree.type_ignores)
        ast.fix_missing_locations(head)
        exec(compile(head, "<exec>", "exec"), namespace)

    expr_code = compile(ast.Expression(body=last.value), "<eval>", "eval")
    result = eval(expr_code, namespace)  # noqa: S307
    if result is not None:
        stdout.write(repr(result) + "\n")


def execute(code: str) -> str:
    """Execute IDAPython code and return captured output.

    Must run on the ida-thread (the namespace pre-loads ida_* modules).
    No timeout enforcement: prior versions used ``signal.SIGALRM``, which
    only works on the process main thread. Once idalib is pinned to the
    ida-thread there's no portable way to interrupt the worker mid-call,
    so the ``timeout`` parameter was removed from the public ``execute``
    and ``execute_file`` tools.
    """
    global _namespace

    if not _namespace:
        _namespace = _build_namespace()

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        log.debug("Executing code (%d chars)", len(code))
        _exec_repl(code, _namespace, stdout_capture)
    except (KeyboardInterrupt, SystemExit) as exc:
        log.warning("%s intercepted from user code", type(exc).__name__)
        stderr_capture.write(f"\n\n{type(exc).__name__} intercepted — the server is still running.\n")
        stderr_capture.write(traceback.format_exc())
    except Exception:
        log.debug("User code raised exception", exc_info=True)
        stderr_capture.write(traceback.format_exc())
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    output = stdout_capture.getvalue() + stderr_capture.getvalue()

    if len(output) > _MAX_OUTPUT:
        output = output[:_MAX_OUTPUT] + f"\n\n[Output truncated at {_MAX_OUTPUT} characters]"

    return output
