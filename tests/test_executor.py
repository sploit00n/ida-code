"""Unit tests for ida_code.executor.

These tests work without idalib — the ida_* modules simply won't be
present in the namespace, which is fine since _build_namespace() silently
skips ImportErrors.
"""

import pytest

from ida_code import executor


@pytest.fixture(autouse=True)
def _reset_namespace():
    """Reset the executor namespace before each test."""
    executor._namespace = {}
    yield
    executor._namespace = {}


class TestExecute:
    def test_print_output(self):
        assert executor.execute("print('hello')") == "hello\n"

    def test_expression_no_output(self):
        assert executor.execute("x = 1 + 2") == ""

    def test_stderr_capture(self):
        result = executor.execute("import sys; sys.stderr.write('err')")
        assert "err" in result

    def test_exception_returns_traceback(self):
        result = executor.execute("1 / 0")
        assert "ZeroDivisionError" in result

    def test_syntax_error(self):
        result = executor.execute("def")
        assert "SyntaxError" in result

    def test_namespace_persistence(self):
        executor.execute("x = 42")
        assert executor.execute("print(x)") == "42\n"

    def test_function_definition_persists(self):
        executor.execute("def double(n): return n * 2")
        assert executor.execute("print(double(5))") == "10\n"

    def test_reset_clears_namespace(self):
        executor.execute("x = 42")
        executor.reset()
        result = executor.execute("print(x)")
        assert "NameError" in result

    def test_output_truncation(self):
        code = f"print('x' * {executor._MAX_OUTPUT + 1000})"
        result = executor.execute(code)
        assert len(result) < executor._MAX_OUTPUT + 200
        assert "Output truncated" in result

    def test_multiline_code(self):
        assert executor.execute("for i in range(3):\n    print(i)") == "0\n1\n2\n"


class TestProcessKillingExceptions:
    def test_system_exit_intercepted(self):
        result = executor.execute("import sys; sys.exit(1)")
        assert "SystemExit" in result
        assert "intercepted" in result

    def test_keyboard_interrupt_intercepted(self):
        result = executor.execute("raise KeyboardInterrupt()")
        assert "KeyboardInterrupt" in result
        assert "intercepted" in result

    def test_quit_intercepted(self):
        result = executor.execute("raise SystemExit(0)")
        assert "SystemExit" in result


class TestReplOutput:
    """Test REPL-like last-expression printing."""

    def test_bare_expression_returns_repr(self):
        assert executor.execute("1 + 2") == "3\n"

    def test_string_expression_returns_repr(self):
        assert executor.execute('"hello"') == "'hello'\n"

    def test_none_expression_suppressed(self):
        assert executor.execute("None") == ""

    def test_assignment_no_output(self):
        assert executor.execute("x = 42") == ""

    def test_expression_after_statements(self):
        assert executor.execute("x = 10\ny = 20\nx + y") == "30\n"

    def test_print_and_expression(self):
        assert executor.execute('print("before")\n42') == "before\n42\n"

    def test_function_call_expression(self):
        assert executor.execute("len([1, 2, 3])") == "3\n"

    def test_for_loop_no_expr_output(self):
        assert executor.execute("for i in range(3):\n    pass") == ""


class TestBuildNamespace:
    def test_builtins_present(self):
        ns = executor._build_namespace()
        assert "__builtins__" in ns

    def test_missing_modules_skipped(self):
        """ida_* modules won't be available in test env — should not raise."""
        ns = executor._build_namespace()
        assert "__builtins__" in ns
