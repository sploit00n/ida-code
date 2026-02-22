"""Variable inspection and modification (local/decompiler and global)."""

import logging

from fastmcp.exceptions import ToolError

from ida_code import session

log = logging.getLogger(__name__)


def _require_open() -> None:
    """Raise ToolError if no database is open."""
    if session.get_state() == session.State.NO_DATABASE:
        raise ToolError("No database is open. Call open_database first.")


def _decompile_func(func_ea: int):
    """Decompile the function at *func_ea*, returning a cfunc_t.

    Raises ToolError if Hex-Rays is unavailable or decompilation fails.
    """
    try:
        import ida_hexrays
    except ImportError:
        raise ToolError("Hex-Rays decompiler is not available.")

    import ida_funcs

    pfn = ida_funcs.get_func(func_ea)
    if pfn is None:
        raise ToolError(f"Address {func_ea:#x} is not within a recognized function.")

    try:
        cfunc = ida_hexrays.decompile(pfn.start_ea)
    except ida_hexrays.DecompilationFailure as e:
        raise ToolError(f"Decompilation failed: {e}")
    except Exception as e:
        raise ToolError(f"{type(e).__name__}: {e}")

    if cfunc is None:
        raise ToolError("Decompilation returned no result.")
    return cfunc


def _find_lvar(cfunc, name: str):
    """Find a local variable by name in *cfunc*.lvars.

    Raises ToolError if not found, listing available names.
    """
    for lv in cfunc.lvars:
        if lv.name == name:
            return lv

    available = [lv.name for lv in cfunc.lvars if lv.name]
    raise ToolError(
        f"Local variable '{name}' not found. "
        f"Available: {available}"
    )


def _lvar_to_dict(lv, func_ea: int) -> dict:
    """Convert a local variable (lvar_t) to a result dict."""
    import ida_funcs

    func_name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
    return {
        "name": lv.name,
        "type": str(lv.type()),
        "width": lv.width,
        "is_arg": lv.is_arg_var,
        "function": func_name,
        "scope": "local",
    }


def _global_to_dict(ea: int) -> dict:
    """Convert a global address to a result dict."""
    import ida_name
    import ida_nalt
    import ida_typeinf
    import idc

    name = ida_name.get_name(ea) or f"unk_{ea:x}"

    # Try to get type info.
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, ea):
        type_str = str(tif)
    else:
        type_str = idc.get_type(ea) or ""

    return {
        "name": name,
        "type": type_str,
        "address": f"{ea:#x}",
        "scope": "global",
    }


def _parse_type(type_str: str):
    """Parse a C type string into a tinfo_t.

    Raises ToolError if parsing fails.
    """
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()
    decl = f"{type_str} __dummy;"
    if not ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL):
        raise ToolError(f"Failed to parse type: '{type_str}'")
    return tif


def get_local_variable(func_ea: int, name: str) -> dict:
    """Get info about a local (decompiler) variable."""
    _require_open()

    cfunc = _decompile_func(func_ea)
    lv = _find_lvar(cfunc, name)
    return _lvar_to_dict(lv, func_ea)


def get_global_variable(ea: int) -> dict:
    """Get info about a global variable/name at *ea*."""
    _require_open()
    return _global_to_dict(ea)


def set_local_variable(
    func_ea: int,
    name: str,
    new_name: str | None = None,
    new_type: str | None = None,
) -> dict:
    """Rename and/or retype a local (decompiler) variable."""
    _require_open()

    import ida_hexrays
    import ida_funcs

    pfn = ida_funcs.get_func(func_ea)
    if pfn is None:
        raise ToolError(f"Address {func_ea:#x} is not within a recognized function.")
    start_ea = pfn.start_ea

    # Verify the variable exists first.
    cfunc = _decompile_func(func_ea)
    _find_lvar(cfunc, name)

    if new_name is not None:
        ok = ida_hexrays.rename_lvar(start_ea, name, new_name)
        if not ok:
            raise ToolError(f"Failed to rename local variable '{name}' to '{new_name}'.")
        log.info("Renamed local variable '%s' -> '%s' in func at %#x", name, new_name, start_ea)

    if new_type is not None:
        tif = _parse_type(new_type)
        lsi = ida_hexrays.lvar_saved_info_t()
        current_name = new_name if new_name is not None else name
        lsi.name = current_name
        lsi.type = tif
        lsi.size = tif.get_size()
        lsi.flags = ida_hexrays.LVINF_TYPE

        # Find the lvar to get its location info.
        cfunc2 = _decompile_func(func_ea)
        lv = _find_lvar(cfunc2, current_name)
        lsi.ll = lv.location

        ok = ida_hexrays.modify_user_lvar_info(start_ea, ida_hexrays.MLI_TYPE, lsi)
        if not ok:
            raise ToolError(f"Failed to retype local variable '{current_name}' to '{new_type}'.")
        log.info("Retyped local variable '%s' to '%s' in func at %#x", current_name, new_type, start_ea)

    # Re-decompile and return updated info.
    final_name = new_name if new_name is not None else name
    cfunc_final = _decompile_func(func_ea)
    lv_final = _find_lvar(cfunc_final, final_name)
    result = _lvar_to_dict(lv_final, func_ea)
    result["status"] = "modified"
    return result


def set_global_variable(
    ea: int,
    new_name: str | None = None,
    new_type: str | None = None,
) -> dict:
    """Rename and/or retype a global variable/name."""
    _require_open()

    import ida_name
    import ida_typeinf

    if new_name is not None:
        ok = ida_name.set_name(ea, new_name, ida_name.SN_CHECK)
        if not ok:
            raise ToolError(f"Failed to rename global at {ea:#x} to '{new_name}'.")
        log.info("Renamed global at %#x -> '%s'", ea, new_name)

    if new_type is not None:
        tif = _parse_type(new_type)
        ok = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
        if not ok:
            raise ToolError(f"Failed to retype global at {ea:#x} to '{new_type}'.")
        log.info("Retyped global at %#x to '%s'", ea, new_type)

    result = _global_to_dict(ea)
    result["status"] = "modified"
    return result
