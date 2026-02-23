"""Unit tests for ida_code.variables.

These tests work without idalib — they test session.require_open delegation
(mocked).
"""

from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError

from ida_code import variables


class TestRequireOpen:
    @patch("ida_code.variables.session")
    def test_get_local_variable_calls_require_open(self, mock_session):
        mock_session.require_open.side_effect = ToolError("No database is open.")
        with pytest.raises(ToolError, match="No database is open"):
            variables.get_local_variable(0x1000, "var")
        mock_session.require_open.assert_called_once()

    @patch("ida_code.variables.session")
    def test_get_global_variable_calls_require_open(self, mock_session):
        mock_session.require_open.side_effect = ToolError("No database is open.")
        with pytest.raises(ToolError, match="No database is open"):
            variables.get_global_variable(0x1000)
        mock_session.require_open.assert_called_once()

    @patch("ida_code.variables.session")
    def test_set_local_variable_calls_require_open(self, mock_session):
        mock_session.require_open.side_effect = ToolError("No database is open.")
        with pytest.raises(ToolError, match="No database is open"):
            variables.set_local_variable(0x1000, "var", new_name="x")
        mock_session.require_open.assert_called_once()

    @patch("ida_code.variables.session")
    def test_set_global_variable_calls_require_open(self, mock_session):
        mock_session.require_open.side_effect = ToolError("No database is open.")
        with pytest.raises(ToolError, match="No database is open"):
            variables.set_global_variable(0x1000, new_name="x")
        mock_session.require_open.assert_called_once()
