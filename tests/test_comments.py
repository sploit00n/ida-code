"""Unit tests for ida_code.comments.

These tests work without idalib — they test session.require_open delegation
and comment_type validation (mocked).
"""

from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError

from ida_code import comments


class TestRequireOpen:
    @patch("ida_code.comments.session")
    def test_get_comment_calls_require_open(self, mock_session):
        mock_session.require_open.side_effect = ToolError("No database is open.")
        with pytest.raises(ToolError, match="No database is open"):
            comments.get_comment(0x1000)
        mock_session.require_open.assert_called_once()

    @patch("ida_code.comments.session")
    def test_set_comment_calls_require_open(self, mock_session):
        mock_session.require_open.side_effect = ToolError("No database is open.")
        with pytest.raises(ToolError, match="No database is open"):
            comments.set_comment(0x1000, "test")
        mock_session.require_open.assert_called_once()

    @patch("ida_code.comments.session")
    def test_delete_comment_calls_require_open(self, mock_session):
        mock_session.require_open.side_effect = ToolError("No database is open.")
        with pytest.raises(ToolError, match="No database is open"):
            comments.delete_comment(0x1000)
        mock_session.require_open.assert_called_once()


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
