"""MCP prompt templates for common IDA workflows."""

from ida_code import guidelines

_REVERSE_ENGINEER = """\
# Reverse Engineering Workflow

A structured approach to analyzing an unknown binary using ida-code MCP tools.

## Phase 1: Reconnaissance

Start by opening the binary and gathering high-level information.

1. **Open the binary** — Use `open_database` with the path to the binary. \
For fat (universal) Mach-O binaries, call `list_architectures` first to discover \
available slices, then pass the desired `arch` to `open_database`.
2. **Survey the database** — Call `get_database_info` to see the processor type, \
bitness, segments, and entry points.
3. **List functions** — Use `list_functions` to browse the function table. Start \
with a small `limit` to get an overview, then paginate or `filter` by name.
4. **Enumerate strings** — Run string enumeration via `execute`:
```python
for s in idautils.Strings():
    print(f"{s.ea:#x}  {ida_bytes.get_strlit_contents(s.ea, s.length, s.strtype)}")
```
5. **Check imports/exports** — Use `execute` to list imported and exported symbols:
```python
import ida_nalt, ida_entry
# Imports
nimps = ida_nalt.get_import_module_qty()
for i in range(nimps):
    name = ida_nalt.get_import_module_name(i)
    print(f"Module: {name}")

# Exports
for i in range(ida_entry.get_entry_qty()):
    ordinal = ida_entry.get_entry_ordinal(i)
    ea = ida_entry.get_entry(ordinal)
    name = ida_entry.get_entry_name(ordinal)
    print(f"  {ea:#x}  {name}")
```

## Phase 2: Triage

Prioritize which functions to analyze first.

- **Name-based filtering** — Use `list_functions` with `filter` to find functions \
related to security (`auth`, `crypt`, `hash`, `verify`, `sign`, `key`), parsing \
(`parse`, `decode`, `deserialize`, `read`, `load`), networking (`send`, `recv`, \
`connect`, `socket`, `http`), or file I/O (`open`, `write`, `fopen`, `mmap`).
- **Size-based prioritization** — Large functions often contain the most logic. \
Sort by size to find the most complex code.
- **String cross-references** — Interesting strings (error messages, format \
strings, URLs, file paths) often lead to important code. Use `execute` to trace \
xrefs from strings to functions:
```python
for xref in idautils.XrefsTo(string_ea):
    fname = ida_funcs.get_func_name(xref.frm)
    print(f"  referenced from {xref.frm:#x} ({fname})")
```

## Phase 3: Deep Analysis

Dive into individual functions.

1. **Decompile** — Use `decompile` with the function name or address. Read the \
pseudocode to understand the logic.
2. **Cross-reference tracing** — Follow data and code references via `execute`:
```python
# Who calls this function?
for xref in idautils.XrefsTo(func_ea):
    print(f"Called from {xref.frm:#x} ({ida_funcs.get_func_name(xref.frm)})")

# What does this function call?
for xref in idautils.XrefsFrom(func_ea, 0):
    if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
        print(f"Calls {xref.to:#x} ({ida_name.get_name(xref.to)})")
```
3. **Disassembly** — Use `get_disassembly` for instruction-level detail when the \
decompiler output is unclear or for analyzing data sections.
4. **Structure recovery** — When you identify structured data, use \
`create_structure` to define it and `set_variable` to apply the type to variables.

## Phase 4: Annotation

Document your findings directly in the database.

- **Rename variables** — Use `set_variable` to give meaningful names to local \
and global variables (e.g., rename `v12` to `buffer_size`).
- **Retype variables** — Use `set_variable` with `new_type` to apply correct C \
types (e.g., `"struct my_header *"`).
- **Add comments** — Use `set_comment` to annotate key addresses with your \
findings. Use `function` type for function-level summaries, `regular` for \
inline notes.
- **Define structures** — Use `create_structure` and `edit_structure` to build \
type definitions that match the binary's data layouts.

## Phase 5: Iteration

Reverse engineering is iterative — each pass reveals more.

1. **Re-decompile** — After renaming and retyping, call `decompile` again. The \
pseudocode will be dramatically more readable with proper names and types.
2. **Verify with disassembly** — Use `get_disassembly` to confirm the decompiler's \
interpretation matches the actual instructions.
3. **Expand scope** — Follow cross-references to related functions and repeat \
the analysis cycle.

## Best Practices

- **Snapshot before bulk changes** — Call `create_snapshot` before renaming or \
retyping many symbols. Use `restore_snapshot` to roll back if something goes wrong.
- **Work incrementally** — Rename and retype a few variables, re-decompile, \
verify, then continue. Small batches are easier to validate.
- **Use `execute` for custom analysis** — The `execute` tool gives you full \
IDAPython access. Write custom scripts for pattern matching, data extraction, \
or anything the dedicated tools don't cover.
- **Search docs and examples** — Use `search_docs` to look up unfamiliar APIs \
and `search_examples` to find IDAPython patterns for common tasks.
- **Namespace persistence** — Variables and functions defined via `execute` \
persist across calls. Build up helper functions incrementally.
- **Close when done** — Call `close_database` when analysis is complete to free \
resources and save the database.
"""

_SCRIPT_BEST_PRACTICES = """\

## IDAPython Best Practices

### Error Handling
- Always check return values: `ida_funcs.get_func()` returns `None` if no \
function exists at the address.
- Wrap `ida_hexrays.decompile()` in try/except — it raises \
`DecompilationFailure` for functions the decompiler can't handle.
- Call `ida_hexrays.init_hexrays_plugin()` before using any Hex-Rays APIs \
and check the return value.

### Performance
- Cache `ida_name.get_name_ea()` lookups — name resolution is not free.
- Use `ida_bytes.get_bytes(ea, size)` for bulk reads instead of reading \
byte-by-byte with `ida_bytes.get_byte()`.
- Prefer `idautils.Functions()`, `idautils.Heads()`, `idautils.XrefsTo()` \
iterators over manual linked-list traversal.

### Naming Conventions
- `ea` — effective address (an integer, not a pointer)
- `pfn` — pointer to `func_t` (from `ida_funcs.get_func()`)
- `cfunc` — `cfunc_t` object (from `ida_hexrays.decompile()`)
- `tif` — `tinfo_t` object (type information)
- `ti` — `ida_typeinf` module

### Common Pitfalls
- **`idc` vs `ida_funcs`** — `idc` functions are thin wrappers with less \
control. Prefer `ida_funcs`, `ida_bytes`, etc. for new code.
- **String encoding** — `ida_bytes.get_strlit_contents()` returns `bytes`, \
not `str`. Decode with `.decode('utf-8', errors='replace')` if needed.
- **Address arithmetic** — Addresses are plain integers. Use `& 0xFFFFFFFF` \
(32-bit) or `& 0xFFFFFFFFFFFFFFFF` (64-bit) to handle overflow, or better, \
use the database's bitness from `ida_ida.inf_get_app_bitness()`.
- **Segment boundaries** — Don't assume contiguous address space. Check \
segment membership with `ida_segment.getseg(ea)` before accessing data.

### MCP Tool Usage for Testing
- Use `execute` to test script snippets interactively before assembling \
the final script.
- The execution namespace persists — define helpers in one call and use \
them in the next.
- Use `search_docs` and `search_examples` to find API patterns.
"""


def reverse_engineer() -> str:
    """Return a comprehensive reverse engineering workflow guide."""
    return _REVERSE_ENGINEER


def create_script(target: str, description: str | None = None) -> str:
    """Return coding guidelines for the given script type plus best practices.

    *target* is one of: ``standalone_script``, ``plugin``, ``idapython_script``.
    *description* is an optional description of what the script should do.
    """
    try:
        text = guidelines.get(target)
    except KeyError:
        available = ", ".join(guidelines.list_targets())
        raise ValueError(
            f"Unknown target {target!r}. Available targets: {available}"
        )

    parts = [text, _SCRIPT_BEST_PRACTICES]
    if description:
        parts.append(f"\n## Task\n\n{description}\n")

    return "\n".join(parts)
