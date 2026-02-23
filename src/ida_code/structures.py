"""Structure (struct/union) management via IDA type info library."""

import logging
import re

from fastmcp.exceptions import ToolError

from ida_code import session

log = logging.getLogger(__name__)

_NAME_RE = re.compile(r"(?:struct|union)\s+(\w+)\s*\{")


def _extract_name(c_code: str) -> str:
    """Extract the struct/union name from a C definition string.

    Raises ToolError if no name can be found.
    """
    m = _NAME_RE.search(c_code)
    if not m:
        raise ToolError(
            "Could not extract struct/union name from definition. "
            "Expected format: 'struct name { ... };' or 'union name { ... };'"
        )
    return m.group(1)


def _get_struct_tinfo(name: str):
    """Look up a struct/union by name, returning (tinfo, ordinal).

    Raises ToolError if the type is not found.
    """
    import ida_typeinf

    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name):
        raise ToolError(f"Structure '{name}' not found.")
    ordinal = ida_typeinf.get_type_ordinal(til, name)
    return tif, ordinal


def _annotated_definition(tif, ordinal: int) -> str:
    """Build a C definition with ``/* offset */`` comments on each member."""
    import ida_typeinf
    import idc

    # Get base definition from IDA.
    if ordinal <= 0:
        return ""
    raw = idc.print_decls(ordinal, 0) or ""
    raw = raw.strip()
    if not raw:
        return ""

    # Extract member offsets.
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return raw

    offsets = {}  # member name -> offset in bytes
    for i in range(udt.size()):
        udm = udt.at(i)
        offsets[udm.name] = udm.offset // 8

    # Annotate each member line inside the braces.
    lines = raw.split("\n")
    out = []
    for line in lines:
        stripped = line.strip()
        # Skip opening/closing braces and empty lines.
        if stripped in ("{", "};", "") or stripped.startswith("struct ") or stripped.startswith("union "):
            out.append(line)
            continue
        # Try to match a member name in this line.
        for mname, off in offsets.items():
            if mname in stripped:
                line = f"{line}  /* {off:#x} */"
                break
        out.append(line)
    return "\n".join(out)


def _struct_to_dict(name: str) -> dict:
    """Convert a named struct/union to a result dict with C definition."""
    import ida_typeinf

    tif, ordinal = _get_struct_tinfo(name)
    size = tif.get_size()
    is_union = tif.is_union()
    member_count = tif.get_udt_nmembers()

    # Get alignment from UDT details.
    alignment = 0
    udt = ida_typeinf.udt_type_data_t()
    if tif.get_udt_details(udt):
        alignment = udt.effalign

    definition = _annotated_definition(tif, ordinal)

    return {
        "name": name,
        "size": size,
        "is_union": is_union,
        "alignment": alignment,
        "member_count": member_count,
        "definition": definition,
    }


def list_structures(offset: int = 0, limit: int = 50, filter: str = "") -> dict:
    """List structures in the database with pagination."""
    session.require_open()

    import ida_typeinf
    import idautils

    all_structs = list(idautils.Structs())
    til = ida_typeinf.get_idati()
    structures = []
    skipped = 0

    for ordinal, sid, name in all_structs:
        if filter and filter.lower() not in name.lower():
            continue
        if skipped < offset:
            skipped += 1
            continue

        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(til, name):
            size = tif.get_size()
            member_count = tif.get_udt_nmembers()
            udt = ida_typeinf.udt_type_data_t()
            alignment = udt.effalign if tif.get_udt_details(udt) else 0
        else:
            size = 0
            member_count = 0
            alignment = 0

        structures.append({
            "name": name,
            "size": size,
            "alignment": alignment,
            "member_count": member_count,
        })
        if len(structures) >= limit:
            break

    return {
        "structures": structures,
        "total": len(all_structs),
        "showing": len(structures),
        "offset": offset,
        "filter": filter,
    }


def get_structure(name: str) -> dict:
    """Get detailed info about a structure by name."""
    session.require_open()
    return _struct_to_dict(name)


def create_structure(definition: str) -> dict:
    """Create a new structure from a C definition string."""
    session.require_open()

    import ida_typeinf
    import idc

    name = _extract_name(definition)

    # Check it doesn't already exist.
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(til, name):
        raise ToolError(f"Structure '{name}' already exists. Use edit_structure to modify it.")

    result = idc.parse_decls(definition, idc.PT_SIL)
    if result != 0:
        raise ToolError(f"Failed to parse definition (error code {result}). Check C syntax.")

    log.info("Created structure '%s'", name)
    return _struct_to_dict(name)


def edit_structure(definition: str) -> dict:
    """Edit an existing structure by replacing its definition."""
    session.require_open()

    import ida_typeinf
    import idc

    name = _extract_name(definition)

    # Check it exists.
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name):
        raise ToolError(f"Structure '{name}' not found. Use create_structure to create it.")

    result = idc.parse_decls(definition, idc.PT_SIL | idc.PT_REPLACE)
    if result != 0:
        raise ToolError(f"Failed to parse definition (error code {result}). Check C syntax.")

    log.info("Edited structure '%s'", name)
    return _struct_to_dict(name)


def delete_structure(name: str) -> dict:
    """Delete a structure by name."""
    session.require_open()

    import ida_typeinf

    # Check it exists.
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name):
        raise ToolError(f"Structure '{name}' not found.")

    ida_typeinf.del_named_type(til, name, ida_typeinf.NTF_TYPE)

    log.info("Deleted structure '%s'", name)
    return {"status": "deleted", "name": name}
