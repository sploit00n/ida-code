"""Unit tests for ida_code.session.

These tests work without idalib — they mock the session module globals
and os.path.isfile to test the file-existence guard logic.
"""

import os
import tempfile
from unittest.mock import MagicMock, patch

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


class TestUnpackedFragmentPrecheck:
    """`open()` must refuse paths with leftover unpacked fragments unless
    overwrite=True — calling idapro on such a path returns rc=-1 and can
    leave idalib's internal state corrupted."""

    def setup_method(self):
        self._orig_state = session._state

    def teardown_method(self):
        session._state = self._orig_state

    def test_lists_unpacked_fragments(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "x.so")
            open(binary, "w").close()
            for ext in (".id0", ".id1", ".nam"):
                open(binary + ext, "w").close()
            found = session._list_unpacked_fragments(binary)
            assert sorted(found) == sorted(binary + ext for ext in (".id0", ".id1", ".nam"))

    def test_returns_empty_for_clean_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "x.so")
            open(binary, "w").close()
            assert session._list_unpacked_fragments(binary) == []

    def test_does_not_flag_packed_databases(self):
        """A `.i64` next to the binary is a valid warm cache, not a fragment."""
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "x.so")
            open(binary, "w").close()
            open(binary + ".i64", "w").close()
            assert session._list_unpacked_fragments(binary) == []

    def test_open_raises_with_fragments_no_overwrite(self):
        """Precheck runs in `_prepare_open` on the calling thread; idapro
        is never reached, so we don't need to mock it."""
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "x.so")
            open(binary, "w").close()
            open(binary + ".id0", "w").close()

            session._state = session.State.NO_DATABASE
            with pytest.raises(ToolError, match="Unpacked database fragments"):
                session.open(binary, auto_analysis=False)

    def test_open_proceeds_with_fragments_when_overwrite_true(self):
        """overwrite=True clears fragments and proceeds with the open.

        Pre-set ``session.idapro`` to a MagicMock so ``_ensure_idalib_loaded``
        short-circuits — otherwise the worker would attempt the real import.
        """
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "x.so")
            open(binary, "w").close()
            open(binary + ".id0", "w").close()

            session._state = session.State.NO_DATABASE
            mock_idapro = MagicMock()
            mock_idapro.open_database.return_value = 0
            with patch.object(session, "idapro", mock_idapro), \
                 patch("ida_code.session._collect_summary", return_value={"path": binary}), \
                 patch("ida_code.executor.reset"):
                session.open(binary, auto_analysis=False, overwrite=True)
            assert not os.path.isfile(binary + ".id0")
            session._state = session.State.NO_DATABASE  # reset for teardown
