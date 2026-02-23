"""Comment management (regular, repeatable, function, anterior, posterior)."""

import logging

from fastmcp.exceptions import ToolError

from ida_code import session

log = logging.getLogger(__name__)

_COMMENT_TYPES = {"regular", "repeatable", "function", "anterior", "posterior"}


def _validate_comment_type(comment_type: str, allow_empty: bool = False) -> None:
    """Raise ToolError if comment_type is not recognized."""
    if allow_empty and comment_type == "":
        return
    if comment_type not in _COMMENT_TYPES:
        allowed = ", ".join(sorted(_COMMENT_TYPES))
        if allow_empty:
            allowed += ', or "" for all types'
        raise ToolError(
            f"Invalid comment_type '{comment_type}'. Must be one of: {allowed}"
        )


def _get_func(ea: int):
    """Resolve address to func_t, raise ToolError if not in a function."""
    import ida_funcs

    pfn = ida_funcs.get_func(ea)
    if pfn is None:
        raise ToolError(f"Address {ea:#x} is not within a recognized function.")
    return pfn


def _get_anterior(ea: int) -> str:
    """Collect all anterior extra comment lines at ea."""
    import ida_lines

    lines = []
    idx = 0
    while True:
        line = ida_lines.get_extra_cmt(ea, ida_lines.E_PREV + idx)
        if line is None:
            break
        lines.append(line)
        idx += 1
    return "\n".join(lines)


def _get_posterior(ea: int) -> str:
    """Collect all posterior extra comment lines at ea."""
    import ida_lines

    lines = []
    idx = 0
    while True:
        line = ida_lines.get_extra_cmt(ea, ida_lines.E_NEXT + idx)
        if line is None:
            break
        lines.append(line)
        idx += 1
    return "\n".join(lines)


def get_comment(ea: int, comment_type: str = "") -> dict:
    """Get comment(s) at an address.

    When *comment_type* is empty, returns all non-empty comment types.
    When a specific type is given, returns just that type.
    """
    session.require_open()
    _validate_comment_type(comment_type, allow_empty=True)

    import idc
    import ida_funcs

    if comment_type == "":
        result: dict = {"address": f"{ea:#x}"}

        regular = idc.get_cmt(ea, 0) or ""
        if regular:
            result["regular"] = regular

        repeatable = idc.get_cmt(ea, 1) or ""
        if repeatable:
            result["repeatable"] = repeatable

        pfn = ida_funcs.get_func(ea)
        if pfn is not None:
            func_cmt = ida_funcs.get_func_cmt(pfn, 0) or ""
            if func_cmt:
                result["function"] = func_cmt

        anterior = _get_anterior(ea)
        if anterior:
            result["anterior"] = anterior

        posterior = _get_posterior(ea)
        if posterior:
            result["posterior"] = posterior

        return result

    # Specific type requested.
    if comment_type == "regular":
        comment = idc.get_cmt(ea, 0) or ""
    elif comment_type == "repeatable":
        comment = idc.get_cmt(ea, 1) or ""
    elif comment_type == "function":
        pfn = _get_func(ea)
        comment = ida_funcs.get_func_cmt(pfn, 0) or ""
    elif comment_type == "anterior":
        comment = _get_anterior(ea)
    else:  # posterior
        comment = _get_posterior(ea)

    return {"address": f"{ea:#x}", "comment_type": comment_type, "comment": comment}


def set_comment(ea: int, comment: str, comment_type: str = "regular") -> dict:
    """Set a comment at an address."""
    session.require_open()
    _validate_comment_type(comment_type)

    import idc
    import ida_funcs
    import ida_lines

    if comment_type == "regular":
        idc.set_cmt(ea, comment, 0)
    elif comment_type == "repeatable":
        idc.set_cmt(ea, comment, 1)
    elif comment_type == "function":
        pfn = _get_func(ea)
        ida_funcs.set_func_cmt(pfn, comment, 0)
    elif comment_type == "anterior":
        lines = comment.split("\n")
        for i, line in enumerate(lines):
            ida_lines.update_extra_cmt(ea, ida_lines.E_PREV + i, line)
    else:  # posterior
        lines = comment.split("\n")
        for i, line in enumerate(lines):
            ida_lines.update_extra_cmt(ea, ida_lines.E_NEXT + i, line)

    log.info("Set %s comment at %#x", comment_type, ea)
    return {
        "address": f"{ea:#x}",
        "comment_type": comment_type,
        "comment": comment,
        "status": "updated",
    }


def delete_comment(ea: int, comment_type: str = "regular") -> dict:
    """Delete a comment at an address."""
    session.require_open()
    _validate_comment_type(comment_type)

    import idc
    import ida_funcs
    import ida_lines

    if comment_type == "regular":
        idc.set_cmt(ea, "", 0)
    elif comment_type == "repeatable":
        idc.set_cmt(ea, "", 1)
    elif comment_type == "function":
        pfn = _get_func(ea)
        ida_funcs.set_func_cmt(pfn, "", 0)
    elif comment_type == "anterior":
        # Count existing lines first, then delete all.
        count = 0
        while ida_lines.get_extra_cmt(ea, ida_lines.E_PREV + count) is not None:
            count += 1
        for i in range(count):
            ida_lines.del_extra_cmt(ea, ida_lines.E_PREV + i)
    else:  # posterior
        count = 0
        while ida_lines.get_extra_cmt(ea, ida_lines.E_NEXT + count) is not None:
            count += 1
        for i in range(count):
            ida_lines.del_extra_cmt(ea, ida_lines.E_NEXT + i)

    log.info("Deleted %s comment at %#x", comment_type, ea)
    return {
        "address": f"{ea:#x}",
        "comment_type": comment_type,
        "status": "deleted",
    }
