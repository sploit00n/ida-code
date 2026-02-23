import logging
import os

from fastmcp.exceptions import ToolError

from ida_code import session

log = logging.getLogger(__name__)


def _build_snapshot_list():
    """Return list of snapshot_t from the snapshot tree."""
    import ida_loader

    root = ida_loader.snapshot_t()
    ida_loader.build_snapshot_tree(root)
    return list(root.children)


def _find_by_id(snapshots, id_str: str):
    """Find a snapshot by its string ID. Raises ToolError if not found."""
    for ss in snapshots:
        if str(ss.id) == id_str:
            return ss
    raise ToolError(f"Snapshot with id '{id_str}' not found.")


def _to_dict(ss) -> dict:
    """Convert a snapshot_t to a plain dict."""
    return {
        "id": str(ss.id),
        "desc": ss.desc,
        "filename": ss.filename,
    }


def list_snapshots() -> dict:
    """List all snapshots for the current database."""
    session.require_open()
    snapshots = _build_snapshot_list()
    return {
        "snapshots": [_to_dict(ss) for ss in snapshots],
        "count": len(snapshots),
    }


def create_snapshot(desc: str = "") -> dict:
    """Create a new database snapshot."""
    session.require_open()

    import ida_kernwin
    import ida_loader

    ss = ida_loader.snapshot_t()
    ss.desc = desc[:ida_loader.MAX_DATABASE_DESCRIPTION]

    ok, err = ida_kernwin.take_database_snapshot(ss)
    if not ok:
        raise ToolError(f"Failed to create snapshot: {err}")

    log.info("Created snapshot id=%s desc=%r", ss.id, ss.desc)
    return _to_dict(ss)


def restore_snapshot(snapshot_id: str) -> dict:
    """Restore the database to a previous snapshot."""
    session.require_open()

    import ida_kernwin

    snapshots = _build_snapshot_list()
    ss = _find_by_id(snapshots, snapshot_id)

    # restore_database_snapshot takes (snapshot, callback, userdata).
    # In idalib headless mode the restore is synchronous; the callback
    # receives (error_msg_or_empty, userdata).
    restore_err = []

    def _cb(err_msg, ud):
        if err_msg:
            restore_err.append(err_msg)

    ida_kernwin.restore_database_snapshot(ss, _cb, None)

    if restore_err:
        raise ToolError(f"Failed to restore snapshot: {restore_err[0]}")

    # Database state changed — reset executor namespace.
    from ida_code.executor import reset
    reset()

    log.info("Restored snapshot id=%s", snapshot_id)
    return {"status": "restored", "id": snapshot_id}


def remove_snapshot(snapshot_id: str) -> dict:
    """Remove a snapshot by deleting its file from disk."""
    session.require_open()

    snapshots = _build_snapshot_list()
    ss = _find_by_id(snapshots, snapshot_id)

    filename = ss.filename
    try:
        os.remove(filename)
    except OSError as e:
        raise ToolError(f"Failed to remove snapshot file '{filename}': {e}")

    log.info("Removed snapshot id=%s file=%s", snapshot_id, filename)
    return {"status": "removed", "id": snapshot_id, "filename": filename}
