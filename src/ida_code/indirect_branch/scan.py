"""CFG-based indirect-branch site enumeration.

Pass 1 strategy — leverage IDA's existing analysis only:
  - Indirect calls: ``ida_idaapi.is_call_insn(insn)`` + no resolved
    code-flow xref from the instruction.
  - Indirect jumps: basic blocks whose ``type == fcb_indjump``; the
    indirect jump is the last instruction of that block.

Tail calls are not separately distinguished in Pass 1 (would require
checking whether the indirect jump is the last instruction of the
function). They are classified as ``"jmp"``.

Returns sites as plain dicts so this module has no IDA-imports at
top level — callers do session.require_open() before invoking.
"""

from __future__ import annotations


def _is_indirect_call(ea: int) -> bool:
    """True if *ea* is a call instruction with no resolved code-xref out."""
    import ida_idp
    import ida_ua
    import ida_xref
    import idautils

    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0:
        return False
    if not ida_idp.is_call_insn(insn):
        return False

    for x in idautils.XrefsFrom(ea, ida_xref.XREF_FAR):
        if x.iscode and x.type in (ida_xref.fl_CN, ida_xref.fl_CF):
            # Skip xrefs we created ourselves (XREF_USER) so user-recorded
            # resolutions don't downgrade the site to "direct."
            if x.user:
                continue
            return False
    return True


def _containing_function(ea: int):
    import ida_funcs

    return ida_funcs.get_func(ea)


def _scan_function_calls(func) -> list[dict]:
    """Indirect calls within a single function."""
    import idautils

    sites = []
    for ea in idautils.FuncItems(func.start_ea):
        if _is_indirect_call(ea):
            sites.append({"ea": ea, "kind": "call"})
    return sites


def _scan_function_jumps(func) -> list[dict]:
    """Indirect jumps within a single function (basic-block type-based)."""
    import ida_gdl

    sites = []
    fc = ida_gdl.FlowChart(func, flags=ida_gdl.FC_PREDS)
    for bb in fc:
        if bb.type == ida_gdl.fcb_indjump:
            # Last instruction of the block is the indirect jump.
            ea = _last_insn_ea(bb)
            if ea is not None:
                sites.append({"ea": ea, "kind": "jmp"})
    return sites


def _last_insn_ea(bb) -> int | None:
    """Address of the last instruction in basic block *bb*."""
    import ida_ua

    # Walk forward from start, tracking last successfully decoded EA.
    ea = bb.start_ea
    last = None
    while ea < bb.end_ea:
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if size <= 0:
            break
        last = ea
        ea += size
    return last


def scan_function(func_ea: int) -> list[dict]:
    """Indirect-branch sites in the function starting at *func_ea*.

    Returns a list of ``{ea, kind, containing_function_ea}`` dicts
    sorted by ea.
    """
    import ida_funcs

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return []

    sites = _scan_function_calls(func) + _scan_function_jumps(func)
    for s in sites:
        s["containing_function_ea"] = func.start_ea
    sites.sort(key=lambda s: s["ea"])
    return sites


def scan_all() -> list[dict]:
    """Indirect-branch sites across all functions in the database."""
    import idautils

    out = []
    for func_ea in idautils.Functions():
        out.extend(scan_function(func_ea))
    return out
