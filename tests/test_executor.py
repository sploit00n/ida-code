"""Unit tests for ida_code.executor.

These tests work without idalib — the ida_* modules simply won't be
present in the namespace, which is fine since _build_namespace() silently
skips ImportErrors.
"""

import signal

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
        result = executor.execute("print('hello')", timeout=0)
        assert result == "hello\n"

    def test_expression_no_output(self):
        result = executor.execute("x = 1 + 2", timeout=0)
        assert result == ""

    def test_stderr_capture(self):
        result = executor.execute("import sys; sys.stderr.write('err')", timeout=0)
        assert "err" in result

    def test_exception_returns_traceback(self):
        result = executor.execute("1 / 0", timeout=0)
        assert "ZeroDivisionError" in result

    def test_syntax_error(self):
        result = executor.execute("def", timeout=0)
        assert "SyntaxError" in result

    def test_namespace_persistence(self):
        executor.execute("x = 42", timeout=0)
        result = executor.execute("print(x)", timeout=0)
        assert result == "42\n"

    def test_function_definition_persists(self):
        executor.execute("def double(n): return n * 2", timeout=0)
        result = executor.execute("print(double(5))", timeout=0)
        assert result == "10\n"

    def test_reset_clears_namespace(self):
        executor.execute("x = 42", timeout=0)
        executor.reset()
        result = executor.execute("print(x)", timeout=0)
        assert "NameError" in result

    def test_output_truncation(self):
        code = f"print('x' * {executor._MAX_OUTPUT + 1000})"
        result = executor.execute(code, timeout=0)
        assert len(result) < executor._MAX_OUTPUT + 200  # some room for suffix
        assert "Output truncated" in result

    def test_multiline_code(self):
        code = "for i in range(3):\n    print(i)"
        result = executor.execute(code, timeout=0)
        assert result == "0\n1\n2\n"


class TestTimeout:
    def test_timeout_fires(self):
        result = executor.execute("import time; time.sleep(5)", timeout=1)
        assert "timed out" in result

    def test_no_timeout_when_zero(self):
        """timeout=0 should not set an alarm."""
        result = executor.execute("print('ok')", timeout=0)
        assert result == "ok\n"
        # Verify no pending alarm.
        assert signal.alarm(0) == 0

    def test_alarm_restored_after_execution(self):
        """The previous SIGALRM handler should be restored."""
        original = signal.getsignal(signal.SIGALRM)
        executor.execute("print('ok')", timeout=5)
        restored = signal.getsignal(signal.SIGALRM)
        assert restored is original


class TestProcessKillingExceptions:
    def test_system_exit_intercepted(self):
        result = executor.execute("import sys; sys.exit(1)", timeout=0)
        assert "SystemExit" in result
        assert "intercepted" in result

    def test_keyboard_interrupt_intercepted(self):
        result = executor.execute("raise KeyboardInterrupt()", timeout=0)
        assert "KeyboardInterrupt" in result
        assert "intercepted" in result

    def test_quit_intercepted(self):
        result = executor.execute("raise SystemExit(0)", timeout=0)
        assert "SystemExit" in result


class TestBuildNamespace:
    def test_builtins_present(self):
        ns = executor._build_namespace()
        assert "__builtins__" in ns

    def test_missing_modules_skipped(self):
        """ida_* modules won't be available in test env — should not raise."""
        ns = executor._build_namespace()
        # At least builtins should be there; ida_* are optional.
        assert "__builtins__" in ns
