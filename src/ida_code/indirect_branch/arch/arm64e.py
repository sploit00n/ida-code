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
    """Return discriminator evidence for the PAC-signed branch at *ea*.

    Response shape::

      {
        "register": "X17",
        "value": "0x3c68000000000000",        // best-effort 64-bit value
        "value_mask": "0xffff000000000000",   // which bits are known (set)
        "source_addr": "0x4318",
        "kind": "imm" | "movk" | "dynamic" | "zero",
      }

    The Apple-Silicon vtable PAC pattern builds the discriminator across
    multiple instructions — typically ``MOV X17, X9 ; MOVK X17, #imm,LSL#48``
    — so the low 48 bits are dynamic and only the MOVK constant tag is
    fixed. ``value_mask`` lets the caller distinguish fixed-bit positions
    from "we don't know yet" bits.

    Returns None if *ea* isn't a PAC-signed branch.
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
        return {
            "register": None,
            "value": "0x0",
            "value_mask": "0xffffffffffffffff",
            "source_addr": None,
            "kind": "zero",
        }

    # Operand 1 is the discriminator register on BLRAA/BLRAB/BRAA/BRAB.
    disc_op = insn.ops[1]
    if disc_op.type != ida_ua.o_reg:
        return None
    disc_reg = disc_op.reg

    reg_name = _reg_name(disc_reg)
    built = _build_discriminator_value(ea, disc_reg)
    return {
        "register": reg_name,
        "value": f"{built['value']:#x}",
        "value_mask": f"{built['mask']:#x}",
        "source_addr": f"{built['source_ea']:#x}" if built["source_ea"] is not None else None,
        "kind": built["kind"],
    }


# ---------- internals ----------


def _build_discriminator_value(branch_ea: int, reg: int) -> dict:
    """Walk back from a PAC branch and reconstruct the discriminator value.

    Returns ``{value, mask, source_ea, kind}``::
      - ``kind == "imm"``  — fully known via a single ``MOV/MOVZ reg, #imm``.
      - ``kind == "movk"`` — known only in the bit positions set by one or
        more ``MOVK reg, #imm, LSL #n`` instructions; the rest is dynamic.
      - ``kind == "dynamic"`` — neither found before basic-block start.
    """
    import ida_funcs
    import ida_ua

    func = ida_funcs.get_func(branch_ea)
    if func is None:
        return {"value": 0, "mask": 0, "source_ea": None, "kind": "dynamic"}
    bb_start = _block_start(func, branch_ea)
    if bb_start is None:
        return {"value": 0, "mask": 0, "source_ea": None, "kind": "dynamic"}

    value = 0
    mask = 0
    earliest_source = None  # the most-trailing MOVK/MOV we used

    cursor = branch_ea - 4
    steps = 0
    while cursor >= bb_start and steps < _BACKWARD_SCAN_INSNS:
        ins = ida_ua.insn_t()
        size = ida_ua.decode_insn(ins, cursor)
        if size <= 0:
            cursor -= 4
            steps += 1
            continue

        mnem = ins.get_canon_mnem().upper()
        op0 = ins.ops[0]
        op1 = ins.ops[1]

        # Only care about defs of `reg`.
        if op0.type != ida_ua.o_reg or op0.reg != reg:
            cursor -= 4
            steps += 1
            continue

        if mnem == "MOVK" and op1.type == ida_ua.o_imm:
            # specval carries the LSL shift amount on IDA's arm proc module.
            shift = op1.specval & 0xFF
            mask16 = 0xFFFF << shift
            value = (value & ~mask16) | ((op1.value & 0xFFFF) << shift)
            mask |= mask16
            if earliest_source is None:
                earliest_source = cursor
        elif mnem in _MOV_MNEMONICS and op1.type == ida_ua.o_imm:
            # MOV/MOVZ with immediate establishes the base; we're done.
            base_shift = (op1.specval & 0xFF) if mnem == "MOVZ" else 0
            base_value = (op1.value & 0xFFFF) << base_shift
            base_mask = 0xFFFFFFFFFFFFFFFF if mnem == "MOV" else (0xFFFF << base_shift)
            # MOVKs we already saw take precedence in their bit ranges.
            value = (value & mask) | (base_value & ~mask)
            mask |= base_mask
            earliest_source = cursor
            break
        else:
            # Some other def of `reg` (e.g. MOV from another register).
            # Whatever MOVKs we collected stay valid; below those bits is dynamic.
            break

        cursor -= 4
        steps += 1

    if mask == 0:
        return {"value": 0, "mask": 0, "source_ea": None, "kind": "dynamic"}

    kind = "imm" if mask == 0xFFFFFFFFFFFFFFFF else "movk"
    return {"value": value, "mask": mask, "source_ea": earliest_source, "kind": kind}


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
