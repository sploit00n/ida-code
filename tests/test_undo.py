"""Unit tests for ida_code.undo.

These tests work without idalib — they mock ida_undo and session.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError

from ida_code import undo


class TestRequireOpen:
    @patch("ida_code.undo.session")
    def test_raises_when_no_db(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.NO_DATABASE
        with pytest.raises(ToolError, match="No database is open"):
            undo._require_open()

    @patch("ida_code.undo.session")
    def test_passes_when_db_open(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN
        undo._require_open()


class TestGetStatus:
    @patch("ida_code.undo.session")
    def test_returns_status(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN

        mock_ida_undo = MagicMock()
        mock_ida_undo.get_undo_action_label.return_value = "Rename"
        mock_ida_undo.get_redo_action_label.return_value = ""

        with patch.dict("sys.modules", {"ida_undo": mock_ida_undo}):
            result = undo.get_status()

        assert result == {
            "can_undo": True,
            "undo_action": "Rename",
            "can_redo": False,
            "redo_action": "",
        }

    @patch("ida_code.undo.session")
    def test_both_available(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN

        mock_ida_undo = MagicMock()
        mock_ida_undo.get_undo_action_label.return_value = "Set type"
        mock_ida_undo.get_redo_action_label.return_value = "Rename"

        with patch.dict("sys.modules", {"ida_undo": mock_ida_undo}):
            result = undo.get_status()

        assert result["can_undo"] is True
        assert result["can_redo"] is True

    @patch("ida_code.undo.session")
    def test_neither_available(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN

        mock_ida_undo = MagicMock()
        mock_ida_undo.get_undo_action_label.return_value = ""
        mock_ida_undo.get_redo_action_label.return_value = ""

        with patch.dict("sys.modules", {"ida_undo": mock_ida_undo}):
            result = undo.get_status()

        assert result["can_undo"] is False
        assert result["can_redo"] is False


class TestPerformUndo:
    @patch("ida_code.undo.session")
    def test_raises_when_steps_less_than_1(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN

        mock_ida_undo = MagicMock()
        mock_ida_undo.get_undo_action_label.return_value = "Rename"

        with patch.dict("sys.modules", {"ida_undo": mock_ida_undo}):
            with pytest.raises(ToolError, match="steps must be at least 1"):
                undo.perform_undo(steps=0)

    @patch("ida_code.undo.session")
    def test_raises_when_nothing_to_undo(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN

        mock_ida_undo = MagicMock()
        mock_ida_undo.get_undo_action_label.return_value = ""

        with patch.dict("sys.modules", {"ida_undo": mock_ida_undo}):
            with pytest.raises(ToolError, match="Nothing to undo"):
                undo.perform_undo()

    @patch("ida_code.executor.reset")
    @patch("ida_code.undo.session")
    def test_single_step(self, mock_session, mock_reset):
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN

        mock_ida_undo = MagicMock()
        # Initial guard check, then loop label check, then post-loop status
        labels = iter(["Rename", "Rename", ""])
        mock_ida_undo.get_undo_action_label.side_effect = lambda: next(labels, "")
        mock_ida_undo.get_redo_action_label.return_value = "Rename"

        with patch.dict("sys.modules", {"ida_undo": mock_ida_undo}):
            result = undo.perform_undo(steps=1)

        assert result["status"] == "undone"
        assert result["steps_requested"] == 1
        assert result["steps_performed"] == 1
        assert result["actions"] == ["Rename"]
        mock_ida_undo.perform_undo.assert_called_once()
        mock_reset.assert_called_once()

    @patch("ida_code.executor.reset")
    @patch("ida_code.undo.session")
    def test_partial_undo(self, mock_session, mock_reset):
        """Request 3 steps but only 1 is available — partial success."""
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN

        mock_ida_undo = MagicMock()
        # Initial guard, loop iter 1 (label), loop iter 2 (empty), post-loop status
        labels = iter(["Rename", "Rename", ""])
        mock_ida_undo.get_undo_action_label.side_effect = lambda: next(labels, "")
        mock_ida_undo.get_redo_action_label.return_value = "Rename"

        with patch.dict("sys.modules", {"ida_undo": mock_ida_undo}):
            result = undo.perform_undo(steps=3)

        assert result["steps_requested"] == 3
        assert result["steps_performed"] == 1
        assert result["actions"] == ["Rename"]


class TestPerformRedo:
    @patch("ida_code.undo.session")
    def test_raises_when_steps_less_than_1(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN

        mock_ida_undo = MagicMock()
        mock_ida_undo.get_redo_action_label.return_value = "Rename"

        with patch.dict("sys.modules", {"ida_undo": mock_ida_undo}):
            with pytest.raises(ToolError, match="steps must be at least 1"):
                undo.perform_redo(steps=0)

    @patch("ida_code.undo.session")
    def test_raises_when_nothing_to_redo(self, mock_session):
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN

        mock_ida_undo = MagicMock()
        mock_ida_undo.get_redo_action_label.return_value = ""

        with patch.dict("sys.modules", {"ida_undo": mock_ida_undo}):
            with pytest.raises(ToolError, match="Nothing to redo"):
                undo.perform_redo()

    @patch("ida_code.executor.reset")
    @patch("ida_code.undo.session")
    def test_single_step(self, mock_session, mock_reset):
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN

        mock_ida_undo = MagicMock()
        # Initial guard check, then loop label check, then post-loop status
        redo_labels = iter(["Rename", "Rename", ""])
        mock_ida_undo.get_redo_action_label.side_effect = lambda: next(redo_labels, "")
        mock_ida_undo.get_undo_action_label.return_value = "Rename"

        with patch.dict("sys.modules", {"ida_undo": mock_ida_undo}):
            result = undo.perform_redo(steps=1)

        assert result["status"] == "redone"
        assert result["steps_requested"] == 1
        assert result["steps_performed"] == 1
        assert result["actions"] == ["Rename"]
        mock_ida_undo.perform_redo.assert_called_once()
        mock_reset.assert_called_once()

    @patch("ida_code.executor.reset")
    @patch("ida_code.undo.session")
    def test_partial_redo(self, mock_session, mock_reset):
        """Request 3 steps but only 2 are available — partial success."""
        mock_session.get_state.return_value = mock_session.State.DATABASE_OPEN

        mock_ida_undo = MagicMock()
        # Initial guard, loop iter 1, loop iter 2, loop iter 3 (empty), post-loop
        redo_labels = iter(["Set type", "Set type", "Rename", ""])
        mock_ida_undo.get_redo_action_label.side_effect = lambda: next(redo_labels, "")
        mock_ida_undo.get_undo_action_label.return_value = "Rename"

        with patch.dict("sys.modules", {"ida_undo": mock_ida_undo}):
            result = undo.perform_redo(steps=3)

        assert result["steps_requested"] == 3
        assert result["steps_performed"] == 2
        assert result["actions"] == ["Set type", "Rename"]
