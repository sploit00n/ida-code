import logging

from fastmcp.exceptions import ToolError

from ida_code import session

log = logging.getLogger(__name__)


def _require_open() -> None:
    """Raise ToolError if no database is open."""
    if session.get_state() == session.State.NO_DATABASE:
        raise ToolError("No database is open. Call open_database first.")


def get_status() -> dict:
    """Return current undo/redo availability and action labels."""
    _require_open()

    import ida_undo

    undo_label = ida_undo.get_undo_action_label() or ""
    redo_label = ida_undo.get_redo_action_label() or ""

    return {
        "can_undo": bool(undo_label),
        "undo_action": undo_label,
        "can_redo": bool(redo_label),
        "redo_action": redo_label,
    }


def perform_undo(steps: int = 1) -> dict:
    """Undo the last action(s). Returns details of what was undone."""
    _require_open()

    if steps < 1:
        raise ToolError("steps must be at least 1.")

    import ida_undo

    undo_label = ida_undo.get_undo_action_label() or ""
    if not undo_label:
        raise ToolError("Nothing to undo.")

    actions: list[str] = []
    for _ in range(steps):
        label = ida_undo.get_undo_action_label() or ""
        if not label:
            break
        ida_undo.perform_undo()
        actions.append(label)

    # Database state changed — reset executor namespace.
    from ida_code.executor import reset
    reset()

    undo_next = ida_undo.get_undo_action_label() or ""
    redo_next = ida_undo.get_redo_action_label() or ""

    log.info("Undo %d/%d steps: %s", len(actions), steps, actions)
    return {
        "status": "undone",
        "steps_requested": steps,
        "steps_performed": len(actions),
        "actions": actions,
        "next_undo": undo_next,
        "next_redo": redo_next,
    }


def perform_redo(steps: int = 1) -> dict:
    """Redo the last undone action(s). Returns details of what was redone."""
    _require_open()

    if steps < 1:
        raise ToolError("steps must be at least 1.")

    import ida_undo

    redo_label = ida_undo.get_redo_action_label() or ""
    if not redo_label:
        raise ToolError("Nothing to redo.")

    actions: list[str] = []
    for _ in range(steps):
        label = ida_undo.get_redo_action_label() or ""
        if not label:
            break
        ida_undo.perform_redo()
        actions.append(label)

    # Database state changed — reset executor namespace.
    from ida_code.executor import reset
    reset()

    undo_next = ida_undo.get_undo_action_label() or ""
    redo_next = ida_undo.get_redo_action_label() or ""

    log.info("Redo %d/%d steps: %s", len(actions), steps, actions)
    return {
        "status": "redone",
        "steps_requested": steps,
        "steps_performed": len(actions),
        "actions": actions,
        "next_undo": undo_next,
        "next_redo": redo_next,
    }
