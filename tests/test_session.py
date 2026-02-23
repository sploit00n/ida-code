"""Unit tests for ida_code.session.require_open().

These tests work without idalib — they mock the session module globals
and os.path.isfile to test the file-existence guard logic.
"""

from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError

from ida_code import session


class TestRequireOpen:
    def setup_method(self):
        """Save and restore session module globals around each test."""
        self._orig_state = session._state
        self._orig_db_file_path = session._db_file_path
        self._orig_orphaned = session._orphaned

    def teardown_method(self):
        session._state = self._orig_state
        session._db_file_path = self._orig_db_file_path
        session._orphaned = self._orig_orphaned

    def test_raises_when_no_database(self):
        session._state = session.State.NO_DATABASE
        with pytest.raises(ToolError, match="No database is open"):
            session.require_open()

    @patch("ida_code.session.os.path.isfile", return_value=True)
    def test_passes_when_open_and_file_exists(self, mock_isfile):
        session._state = session.State.DATABASE_OPEN
        session._db_file_path = "/tmp/test.i64"
        session.require_open()  # should not raise
        mock_isfile.assert_called_once_with("/tmp/test.i64")

    @patch("ida_code.session.os.path.isfile", return_value=False)
    @patch("ida_code.executor.reset")
    def test_resets_state_when_file_missing(self, mock_reset, mock_isfile):
        session._state = session.State.DATABASE_OPEN
        session._db_file_path = "/tmp/gone.i64"
        session._orphaned = False

        with pytest.raises(ToolError, match="moved or deleted"):
            session.require_open()

        assert session._state == session.State.NO_DATABASE
        assert session._orphaned is True
        assert session._db_file_path is None
        mock_reset.assert_called_once()

    def test_passes_when_db_file_path_is_none(self):
        """Graceful degradation: if _db_file_path was never set, skip the
        file check and rely only on the state enum."""
        session._state = session.State.DATABASE_OPEN
        session._db_file_path = None
        session.require_open()  # should not raise
