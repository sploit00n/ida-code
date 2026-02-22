"""Unit tests for ida_code.variables.

These tests work without idalib — they only test the _require_open guard
(mocked).
"""

from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError

from ida_code import variables


class TestRequireOpen:
    @patch("ida_code.variables.session")
    def test_raises_when_no_db(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.NO_DATABASE
        with pytest.raises(ToolError, match="No database is open"):
            variables._require_open()

    @patch("ida_code.variables.session")
    def test_passes_when_db_open(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.OPEN
        # Should not raise.
        variables._require_open()
