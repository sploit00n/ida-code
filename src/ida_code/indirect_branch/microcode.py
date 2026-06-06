"""Arch-agnostic microcode heuristics (Pass 2).

Adds the data-flow half of ``get_indirect_branch``:

  - target_microcode_op  — kind of mop driving the icall target (mop_r / mop_S / ...)
  - target_backward_slice — last few defs of the target operand
  - from_arg             — when the slice terminates at a function arg, which one
  - inferred_type        — C prototype Hex-Rays inferred for the call
  - candidates           — when from_arg is set, what callers pass into that slot

All built on Hex-Rays microcode at ``MMAT_GLBOPT3`` (SSA + globally
optimized). One implementation works for every arch with a decompiler —
the only arch-specific layer is calling-convention-driven arg slot
matching, which is handled here via ``mba.vars[].is_arg_var`` (Hex-Rays
already knows the PCS).

If Hex-Rays isn't available or microcode generation fails for the
containing function, the enrichment returns an empty dict — Pass 1
fields remain valid on their own.
"""

from __future__ import annotations

import logging
from typing import Iterable

log = logging.getLogger(__name__)


SLICE_MAX_DEFS = 5
SLICE_MAX_BLOCKS = 4  # current block + predecessors, BFS
CALLER_CANDIDATE_LIMIT = 16


def enrich_with_microcode(ea: int) -> dict:
    """Return the microcode-derived fields for the indirect branch at *ea*.

    Empty dict on any failure (decompiler missing, function lookup failed,
    EA isn't an indirect call/jump in the microcode view, etc.).
    """
    try:
        import ida_funcs
        import ida_hexrays
    except ImportError:
        return {}

    func = ida_funcs.get_func(ea)
    if func is None:
        return {}

    mba = _build_mba(func)
    if mba is None:
        return {}

    located = _locate_icall(mba, ea)
    if located is None:
        return {}
    block_idx, icall = located

    out: dict = {}

    target_mop = icall.r
    out["target_microcode_op"] = _mop_kind_name(target_mop)

    slice_defs = _backward_slice(mba, block_idx, target_mop)

    arg_idx = _infer_arg_index(mba, target_mop, slice_defs, func)
    if arg_idx is not None:
        out["from_arg"] = arg_idx

    # Strip internal fields before surfacing the slice.
    if slice_defs:
        out["target_backward_slice"] = [
            {k: v for k, v in d.items() if not k.startswith("_")}
            for d in slice_defs
        ]

    proto = _inferred_type(icall)
    if proto:
        out["inferred_type"] = proto

    if arg_idx is not None:
        candidates = _caller_arg_candidates(func.start_ea, arg_idx)
        if candidates:
            out["candidates"] = candidates

    return out


# ---------- mba building ----------


def _build_mba(func):
    """Generate microcode at MMAT_GLBOPT3.

    Triggers full decompilation first as a side effect — that populates
    the function's tinfo (arg locations) which we need for from-arg
    inference. Fresh auto-analysis alone often leaves args unset.
    """
    import ida_hexrays
    import ida_range

    try:
        ida_hexrays.decompile(func.start_ea)
    except Exception:
        pass  # Decompiler failure is fine; gen_microcode below may still work.

    mbr = ida_hexrays.mba_ranges_t()
    mbr.ranges.push_back(ida_range.range_t(func.start_ea, func.end_ea))
    hf = ida_hexrays.hexrays_failure_t()
    try:
        mba = ida_hexrays.gen_microcode(
            mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_GLBOPT3
        )
    except Exception as e:  # pragma: no cover — defensive
        log.warning("gen_microcode raised at %#x: %s", func.start_ea, e)
        return None
    if mba is None or hf.code != 0:
        return None
    return mba


# ---------- icall location ----------


def _locate_icall(mba, ea: int):
    """Find the m_icall microinstruction whose EA matches *ea*.

    Hex-Rays often nests m_icall inside an m_mov when the return value
    is bound to a destination — we recurse through nested instructions.
    Returns (block_idx, icall_minsn) or None.
    """
    import ida_hexrays

    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        insn = blk.head
        while insn:
            if insn.ea == ea:
                icall = _find_nested_icall(insn)
                if icall is not None:
                    return blk_idx, icall
            insn = insn.next
    return None


def _find_nested_icall(insn):
    """Recursively descend through nested minsns looking for an m_icall."""
    import ida_hexrays

    if insn.opcode in (ida_hexrays.m_icall, ida_hexrays.m_ijmp):
        return insn
    for mop in (insn.l, insn.r, insn.d):
        if mop.t == ida_hexrays.mop_d and mop.d is not None:
            nested = _find_nested_icall(mop.d)
            if nested is not None:
                return nested
    return None


# ---------- backward slice ----------


def _backward_slice(mba, start_block_idx: int, target_mop) -> list[dict]:
    """Walk back from the icall, collecting defs of *target_mop*.

    Single function, ≤SLICE_MAX_BLOCKS predecessors visited, ≤SLICE_MAX_DEFS
    defs returned. Each entry is ``{ea, op_dest, op_source, note}``.
    """
    import ida_hexrays

    if target_mop.t != ida_hexrays.mop_r:
        return []

    target_mreg = target_mop.r
    target_size = target_mop.size

    visited_blocks: set[int] = set()
    defs: list[dict] = []
    queue: list[tuple[int, object | None]] = [(start_block_idx, None)]

    while queue and len(defs) < SLICE_MAX_DEFS and len(visited_blocks) < SLICE_MAX_BLOCKS:
        blk_idx, stop_at = queue.pop(0)
        if blk_idx in visited_blocks or blk_idx < 0 or blk_idx >= mba.qty:
            continue
        visited_blocks.add(blk_idx)

        blk = mba.get_mblock(blk_idx)
        block_defs = _scan_block_for_defs(blk, target_mreg, target_size, stop_at)
        if block_defs:
            defs.extend(block_defs[: SLICE_MAX_DEFS - len(defs)])
            # Stop walking up this branch once we found a def in this block.
            continue

        # No def in this block — queue predecessors.
        for pred_idx in blk.predset:
            queue.append((pred_idx, None))

    return defs


def _scan_block_for_defs(blk, target_mreg: int, target_size: int, stop_at) -> list[dict]:
    """Walk *blk* end-to-start collecting defs of (target_mreg, target_size).

    *stop_at* — start scanning at this minsn (exclusive), or None for the tail.
    """
    import ida_hexrays

    insns = []
    insn = blk.head
    while insn:
        insns.append(insn)
        insn = insn.next

    if stop_at is not None:
        try:
            cutoff = insns.index(stop_at)
            insns = insns[:cutoff]
        except ValueError:
            pass

    found: list[dict] = []
    for insn in reversed(insns):
        if insn.opcode == ida_hexrays.m_nop:
            continue
        d = insn.d
        if d.t == ida_hexrays.mop_r and d.r == target_mreg and d.size == target_size:
            src_mop = (insn.l.r, insn.l.size) if insn.l.t == ida_hexrays.mop_r else (None, None)
            found.append({
                "ea": f"{insn.ea:#x}",
                "op_dest": d.dstr(),
                "op_source": insn.l.dstr() if insn.l.t != ida_hexrays.mop_z else "",
                "note": _classify_def_note(insn),
                "_source_mop": src_mop,  # stripped before returning to caller
            })
            if len(found) >= SLICE_MAX_DEFS:
                break
    return found


def _classify_def_note(insn) -> str:
    """One-line hint about the kind of definition this minsn represents."""
    import ida_hexrays

    opc = insn.opcode
    if opc == ida_hexrays.m_mov:
        if insn.l.t == ida_hexrays.mop_r:
            return f"mov from register {insn.l.dstr()}"
        if insn.l.t == ida_hexrays.mop_v:
            return f"mov from global {insn.l.dstr()}"
        if insn.l.t == ida_hexrays.mop_n:
            return f"mov from constant {insn.l.dstr()}"
        if insn.l.t == ida_hexrays.mop_a:
            return f"mov from address-of {insn.l.dstr()}"
        return f"mov from {insn.l.dstr()}"
    if opc == ida_hexrays.m_ldx:
        return f"load from memory {insn.l.dstr()}+{insn.r.dstr()}"
    return f"opcode {opc}"


# ---------- arg-index inference ----------


def _infer_arg_index(mba, target_mop, slice_defs: list[dict], func) -> int | None:
    """When the slice terminates at a function arg, return its index.

    Reads the function's tinfo (``mba.idb_type`` first, falling back to
    ``ida_nalt.get_tinfo``) and for each arg with ``argloc.is_reg1()`` we
    convert the IDA processor register number to a microreg via
    ``ida_hexrays.reg2mreg``. Match by mreg + size against either the
    target operand or the source operand of the slice's earliest def.

    All arch-agnostic — Hex-Rays handles the PCS mapping.
    """
    import ida_hexrays
    import ida_typeinf

    arg_mregs = _function_arg_mregs(mba, func)
    if not arg_mregs:
        return None

    # Source mreg = source of the deepest def, else the target itself.
    source_mreg = None
    source_size = None
    if slice_defs:
        deepest = slice_defs[-1].get("_source_mop")
        if deepest is not None and deepest[0] is not None:
            source_mreg, source_size = deepest
    if source_mreg is None and target_mop.t == ida_hexrays.mop_r:
        source_mreg, source_size = target_mop.r, target_mop.size

    if source_mreg is None:
        return None

    for idx, (a_mreg, a_size) in enumerate(arg_mregs):
        if a_mreg == source_mreg and (a_size == source_size or source_size is None):
            return idx
    return None


def _function_arg_mregs(mba, func) -> list[tuple[int, int]]:
    """Return list of (mreg, size) for each register-passed function arg."""
    import ida_hexrays
    import ida_nalt
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    got = False
    # Prefer the type the decompiler already has on the mba.
    try:
        idb_type = mba.idb_type
        if idb_type and idb_type.is_func():
            tif = idb_type
            got = True
    except Exception:
        pass
    if not got:
        got = ida_nalt.get_tinfo(tif, func.start_ea)
    if not got or not tif.is_func():
        # Last resort — ask IDA to guess based on the disassembly.
        tif2 = ida_typeinf.tinfo_t()
        try:
            if ida_typeinf.guess_tinfo(tif2, func.start_ea) == ida_typeinf.GUESS_FUNC_OK:
                tif = tif2
                got = True
        except Exception:
            pass
    if not got or not tif.is_func():
        return []

    fd = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(fd):
        return []

    out: list[tuple[int, int]] = []
    for i in range(fd.size()):
        arg = fd[i]
        argloc = arg.argloc
        if not argloc.is_reg1():
            continue
        proc_reg = argloc.reg1()
        try:
            mreg = ida_hexrays.reg2mreg(proc_reg)
        except Exception:
            continue
        size = arg.type.get_size() if arg.type else 8
        out.append((mreg, size))
    return out


# ---------- inferred type ----------


def _inferred_type(icall) -> str:
    import ida_hexrays

    try:
        ci = icall.d.f if icall.d.t == ida_hexrays.mop_f else None
    except Exception:
        return ""
    if ci is None:
        return ""

    try:
        ret = ci.return_type.dstr() if ci.return_type else "void"
    except Exception:
        ret = "?"

    arg_types: list[str] = []
    try:
        for arg in ci.args:
            try:
                t = arg.type.dstr() if hasattr(arg, "type") and arg.type else ""
            except Exception:
                t = ""
            arg_types.append(t or "?")
    except Exception:
        pass

    return f"{ret} (*)({', '.join(arg_types) or 'void'})"


# ---------- caller-arg candidates ----------


def _caller_arg_candidates(func_ea: int, arg_idx: int) -> list[dict]:
    """For each direct caller of *func_ea*, extract the value at *arg_idx*."""
    import ida_funcs
    import ida_hexrays
    import ida_xref
    import idautils

    candidates: list[dict] = []
    seen_targets: set[int] = set()

    for xref in idautils.XrefsTo(func_ea, 0):
        if not xref.iscode:
            continue
        if len(candidates) >= CALLER_CANDIDATE_LIMIT:
            break
        caller_ea = xref.frm
        caller_func = ida_funcs.get_func(caller_ea)
        if caller_func is None:
            continue
        caller_mba = _build_mba(caller_func)
        if caller_mba is None:
            continue

        arg_mop = _arg_at_call_site(caller_mba, caller_ea, func_ea, arg_idx)
        if arg_mop is None:
            continue
        cand = _classify_arg_mop(arg_mop, caller_ea, caller_func)
        if cand is None:
            continue

        # Dedup on target_addr (a function reused as N callbacks is one candidate).
        key_addr = cand.get("target_addr_int")
        if key_addr in seen_targets:
            # Augment existing candidate with another caller site.
            for existing in candidates:
                if existing.get("_key") == key_addr:
                    existing["callers"].append(_format_caller(caller_func, caller_ea))
                    break
            continue
        cand["_key"] = key_addr
        cand["callers"] = [_format_caller(caller_func, caller_ea)]
        candidates.append(cand)
        if key_addr is not None:
            seen_targets.add(key_addr)

    # Strip internal keys.
    for c in candidates:
        c.pop("_key", None)
        c.pop("target_addr_int", None)
    return candidates


def _arg_at_call_site(mba, call_ea: int, callee_ea: int, arg_idx: int):
    """Find the *arg_idx*-th argument mop at *call_ea*'s call to *callee_ea*."""
    import ida_hexrays

    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        insn = blk.head
        while insn:
            if insn.ea == call_ea:
                call = _find_call_or_icall(insn, callee_ea)
                if call is not None:
                    return _nth_arg_mop(call, arg_idx)
            insn = insn.next
    return None


def _find_call_or_icall(insn, callee_ea: int):
    """Look for m_call to *callee_ea* (or any m_call/m_icall at this EA)."""
    import ida_hexrays

    if insn.opcode == ida_hexrays.m_call:
        return insn
    for mop in (insn.l, insn.r, insn.d):
        if mop.t == ida_hexrays.mop_d and mop.d is not None:
            nested = _find_call_or_icall(mop.d, callee_ea)
            if nested is not None:
                return nested
    return None


def _nth_arg_mop(call_insn, arg_idx: int):
    import ida_hexrays

    if call_insn.d.t != ida_hexrays.mop_f:
        return None
    ci = call_insn.d.f
    try:
        if arg_idx >= len(ci.args):
            return None
        return ci.args[arg_idx]
    except Exception:
        return None


def _classify_arg_mop(mop, caller_ea: int, caller_func) -> dict | None:
    """Render an arg mop as a candidate dict, or None if it doesn't resolve."""
    import ida_funcs
    import ida_hexrays
    import ida_name

    addr = None
    source = None
    if mop.t == ida_hexrays.mop_a and mop.a is not None:
        # Address-of operand. Look at the inner mop.
        inner = mop.a
        if inner.t == ida_hexrays.mop_v:
            addr = inner.g
            source = "address_of_global"
        elif inner.t == ida_hexrays.mop_n:
            addr = inner.nnn.value
            source = "address_of_const"
    elif mop.t == ida_hexrays.mop_v:
        addr = mop.g
        source = "global_pointer"
    elif mop.t == ida_hexrays.mop_n:
        addr = mop.nnn.value
        source = "constant"
    elif mop.t == ida_hexrays.mop_h:
        # Helper call — likely PAC-signed pointer through __auth_stubs.
        return {
            "source": "auth_helper",
            "evidence": mop.dstr(),
            "target_addr": None,
            "target_name": None,
        }

    if addr is None:
        return None

    name = ida_name.get_ea_name(addr) or None
    return {
        "target_addr": f"{addr:#x}",
        "target_addr_int": addr,
        "target_name": name,
        "source": source,
    }


def _format_caller(caller_func, caller_ea: int) -> str:
    import ida_funcs

    name = ida_funcs.get_func_name(caller_func.start_ea) or f"sub_{caller_func.start_ea:x}"
    return f"{name}@{caller_ea:#x}"


# ---------- misc ----------


def _mop_kind_name(mop) -> str:
    """Symbolic name for ``mop.t`` ('mop_r', 'mop_S', etc.)."""
    import ida_hexrays

    for attr in dir(ida_hexrays):
        if attr.startswith("mop_") and getattr(ida_hexrays, attr) == mop.t:
            return attr
    return f"mop_{mop.t}"
