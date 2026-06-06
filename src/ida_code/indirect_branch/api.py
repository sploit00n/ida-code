"""Public API for the three indirect-branch MCP tools.

Each function here is invoked from server.py inside an ``on_ida_thread``
dispatch, so all IDA imports stay lazy.
"""

from __future__ import annotations

import logging

from fastmcp.exceptions import ToolError

from ida_code import session
from ida_code.indirect_branch import persist, scan

log = logging.getLogger(__name__)


_STATUS_VALUES = ("any", "resolved", "unresolved")


def list_indirect_branches(
    function: str | None = None,
    status: str = "unresolved",
) -> dict:
    """Enumerate indirect-branch sites with a small per-site digest.

    *function* — restrict to one function (name or hex address). None = whole db.
    *status*   — ``unresolved`` | ``resolved`` | ``any``.
    """
    session.require_open()
    if status not in _STATUS_VALUES:
        raise ToolError(
            f"Invalid status '{status}'. Must be one of: {', '.join(_STATUS_VALUES)}"
        )

    import ida_funcs

    if function is None:
        sites = scan.scan_all()
        scope = "database"
    else:
        ea = _resolve(function)
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ToolError(f"Could not find a function containing {function!r}.")
        sites = scan.scan_function(func.start_ea)
        scope = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"

    out = []
    for site in sites:
        digest = _digest(site)
        if status == "resolved" and not digest["has_resolution"]:
            continue
        if status == "unresolved" and digest["has_resolution"]:
            continue
        out.append(digest)

    return {"scope": scope, "status": status, "count": len(out), "sites": out}


def get_indirect_branch(addr: str) -> dict:
    """Return what we know about the indirect branch at *addr*.

    Pass 1 returns the structural minimum: addr, kind, containing
    function, and any stored ``@RESOLVED_V1`` block. Microcode-derived
    fields (backward slice, candidates, inferred type) and arch
    specifics (PAC discriminator) land in later passes.
    """
    session.require_open()
    import ida_funcs

    ea = _resolve(addr)
    kind = _classify(ea)
    if kind is None:
        raise ToolError(f"Address {addr!r} is not an indirect-branch site.")

    func = ida_funcs.get_func(ea)
    func_name = ida_funcs.get_func_name(func.start_ea) if func else None

    return {
        "addr": f"{ea:#x}",
        "kind": kind,
        "containing_function": func_name,
        "containing_function_addr": f"{func.start_ea:#x}" if func else None,
        "existing_resolution": _read_resolution(ea),
    }


def set_indirect_branch(
    addr: str,
    targets: list[dict] | None = None,
    unresolvable_reason: str = "",
) -> dict:
    """Record the caller's resolution for the branch at *addr*.

    Either pass a non-empty ``targets`` list — each item ``{addr,
    confidence, reason}`` with confidence in {"certain", "likely",
    "speculative"} — or pass a non-empty ``unresolvable_reason`` to
    record a dead-end.

    Writes:
      - manual code xrefs (one per target) — visible to get_xrefs_from.
      - an ``@RESOLVED_V1`` block appended to the branch site's regular
        comment, carrying per-target confidence and reason.
    """
    session.require_open()
    import idc

    ea = _resolve(addr)
    kind = _classify(ea)
    if kind is None:
        raise ToolError(f"Address {addr!r} is not an indirect-branch site.")

    # Validate and format (will raise ValueError on bad input).
    try:
        block = persist.format_resolution(targets=targets, unresolvable_reason=unresolvable_reason)
    except ValueError as e:
        raise ToolError(str(e))

    # Merge into existing comment (replacing any prior @RESOLVED_V1 block).
    existing = idc.get_cmt(ea, 0) or ""
    new_cmt = persist.merge_resolution_into_comment(existing, block)
    idc.set_cmt(ea, new_cmt, 0)

    # Create manual code xrefs for each target.
    xref_count = 0
    if targets:
        for t in targets:
            target_ea = _coerce_addr(t["addr"])
            if _add_manual_cref(ea, target_ea):
                xref_count += 1

    log.info(
        "Recorded indirect-branch resolution at %#x: %d targets, %d xrefs",
        ea,
        len(targets or []),
        xref_count,
    )
    return {
        "addr": f"{ea:#x}",
        "status": "recorded",
        "targets_recorded": len(targets or []),
        "xrefs_added": xref_count,
        "unresolvable": bool(unresolvable_reason),
    }


# ---------- internals ----------


def _resolve(identifier: str) -> int:
    """Resolve a name or hex/decimal string to an EA, raise ToolError on fail."""
    import ida_idaapi
    import ida_name

    s = str(identifier).strip()
    ea = ida_idaapi.BADADDR

    try:
        ea = int(s, 16)
    except ValueError:
        pass
    if ea == ida_idaapi.BADADDR:
        try:
            ea = int(s, 10)
        except ValueError:
            pass
    if ea == ida_idaapi.BADADDR:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, s)
    if ea == ida_idaapi.BADADDR:
        raise ToolError(f"Could not resolve {identifier!r} to an address.")
    return ea


def _coerce_addr(value) -> int:
    """Accept int or hex/decimal string."""
    if isinstance(value, int):
        return value
    s = str(value).strip()
    try:
        return int(s, 16)
    except ValueError:
        return int(s, 10)


def _classify(ea: int) -> str | None:
    """Return 'call' | 'jmp' if *ea* is an indirect-branch site, else None."""
    import ida_funcs

    func = ida_funcs.get_func(ea)
    if func is None:
        return None

    sites = scan.scan_function(func.start_ea)
    for s in sites:
        if s["ea"] == ea:
            return s["kind"]
    return None


def _read_resolution(ea: int) -> dict | None:
    import idc

    cmt = idc.get_cmt(ea, 0) or ""
    parsed = persist.parse_resolution(cmt)
    return parsed.to_dict() if parsed else None


def _digest(site: dict) -> dict:
    import ida_funcs
    import idc

    ea = site["ea"]
    func_ea = site["containing_function_ea"]
    func_name = ida_funcs.get_func_name(func_ea)
    cmt = idc.get_cmt(ea, 0) or ""
    parsed = persist.parse_resolution(cmt)
    has_resolution = parsed is not None
    num_targets = 0
    if parsed and not parsed.unresolvable:
        num_targets = len(parsed.targets)
    return {
        "addr": f"{ea:#x}",
        "kind": site["kind"],
        "containing_function": func_name,
        "has_resolution": has_resolution,
        "num_targets": num_targets,
    }


def _add_manual_cref(frm: int, to: int) -> bool:
    """Create a USER manual code xref. Returns True if it was new."""
    import ida_xref
    import idautils

    # Skip if an identical user xref already exists.
    for x in idautils.XrefsFrom(frm, ida_xref.XREF_FAR):
        if x.to == to and x.user:
            return False
    ida_xref.add_cref(frm, to, ida_xref.fl_CN | ida_xref.XREF_USER)
    return True
