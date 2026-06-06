"""arm64e helpers: Pointer Authentication (PAC) discriminator extraction.

On arm64e, indirect branches with PAC authentication
(``BLRAA Xn, Xm``, ``BLRAB``, ``BRAA``, ``BRAB``) take a discriminator
register ``Xm`` whose value at the branch is the call-site type tag.
This tag is derived from the target function's prototype and is stable
across builds — so extracting it lets the LLM filter candidate targets
to those signed with the same discriminator.

The ``...Z`` variants (``BLRAAZ`` etc.) use a zero discriminator —
returned with ``register=None`` and ``value="0x0"``.

The discriminator register is usually loaded with a constant
``MOV Xdisc, #imm`` 1-3 instructions before the branch, in the same
basic block. We do a single-BB backward walk; cross-BB cases are
deferred until they're observed in the wild.
"""

from __future__ import annotations


_PAC_BRANCH_MNEMONICS = {
    "BLRAA", "BLRAB", "BRAA", "BRAB", "BLRAAZ", "BLRABZ", "BRAAZ", "BRABZ",
}
_MOV_MNEMONICS = {"MOV", "MOVZ"}
_BACKWARD_SCAN_INSNS = 32  # generous cap; the constant is usually within 4


def pac_discriminator(ea: int) -> dict | None:
    """Return ``{"register", "value", "source_addr"}`` for the discriminator
    of the PAC-signed branch at *ea*, or None if not applicable.
    """
    import ida_ua
    import idc

    # IDA arm processor module surfaces the variant suffix (AA/AB/AAZ/ABZ)
    # via ``print_insn_mnem`` — ``insn_t.get_canon_mnem`` returns the base
    # ("BLR") and would mis-identify PAC branches as plain ones.
    mnem = (idc.print_insn_mnem(ea) or "").upper()
    if mnem not in _PAC_BRANCH_MNEMONICS:
        return None

    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0:
        return None

    if mnem.endswith("Z"):
        return {"register": None, "value": "0x0", "source_addr": None}

    # Operand 1 is the discriminator register on BLRAA/BLRAB/BRAA/BRAB.
    disc_op = insn.ops[1]
    if disc_op.type != ida_ua.o_reg:
        return None
    disc_reg = disc_op.reg

    reg_name = _reg_name(disc_reg)
    found = _backward_find_const_assignment(ea, disc_reg)
    if found is None:
        return {"register": reg_name, "value": None, "source_addr": None}
    source_ea, value = found
    return {
        "register": reg_name,
        "value": f"{value:#x}",
        "source_addr": f"{source_ea:#x}",
    }


# ---------- internals ----------


def _backward_find_const_assignment(ea: int, reg: int):
    """Walk back within the basic block looking for ``MOV reg, #imm``."""
    import ida_funcs
    import ida_gdl
    import ida_ua

    func = ida_funcs.get_func(ea)
    if func is None:
        return None

    bb_start = _block_start(func, ea)
    if bb_start is None:
        return None

    cursor = ea - 4  # arm64 fixed instruction width
    steps = 0
    while cursor >= bb_start and steps < _BACKWARD_SCAN_INSNS:
        ins = ida_ua.insn_t()
        size = ida_ua.decode_insn(ins, cursor)
        if size <= 0:
            cursor -= 4
            steps += 1
            continue
        mnem = ins.get_canon_mnem().upper()
        if mnem in _MOV_MNEMONICS:
            if (
                ins.ops[0].type == ida_ua.o_reg
                and ins.ops[0].reg == reg
                and ins.ops[1].type == ida_ua.o_imm
            ):
                return cursor, ins.ops[1].value
            # MOVK/MOVZ pieces or non-immediate source — give up.
            if ins.ops[0].type == ida_ua.o_reg and ins.ops[0].reg == reg:
                return None
        cursor -= 4
        steps += 1

    return None


def _block_start(func, ea: int) -> int | None:
    import ida_gdl

    fc = ida_gdl.FlowChart(func)
    for bb in fc:
        if bb.start_ea <= ea < bb.end_ea:
            return bb.start_ea
    return None


def _reg_name(reg: int) -> str:
    import ida_idp

    name = ida_idp.get_reg_name(reg, 8)
    return name or f"reg{reg}"
