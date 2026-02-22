"""Unit tests for ida_code.comments.

These tests work without idalib — they only test the _require_open guard
and comment_type validation (mocked).
"""

from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError

from ida_code import comments


class TestRequireOpen:
    @patch("ida_code.comments.session")
    def test_raises_when_no_db(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.NO_DATABASE
        with pytest.raises(ToolError, match="No database is open"):
            comments._require_open()

    @patch("ida_code.comments.session")
    def test_passes_when_db_open(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.OPEN
        # Should not raise.
        comments._require_open()


class TestValidateCommentType:
    def test_valid_types(self):
        for ct in ("regular", "repeatable", "function", "anterior", "posterior"):
            comments._validate_comment_type(ct)  # should not raise

    def test_empty_rejected_by_default(self):
        with pytest.raises(ToolError, match="Invalid comment_type"):
            comments._validate_comment_type("")

    def test_empty_accepted_when_allowed(self):
        comments._validate_comment_type("", allow_empty=True)  # should not raise

    def test_invalid_type_rejected(self):
        with pytest.raises(ToolError, match="Invalid comment_type 'bogus'"):
            comments._validate_comment_type("bogus")

    def test_invalid_type_with_allow_empty(self):
        with pytest.raises(ToolError, match="Invalid comment_type 'bad'"):
            comments._validate_comment_type("bad", allow_empty=True)
