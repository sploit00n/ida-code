"""Coding guidelines and templates for IDAPython development."""

_STANDALONE_SCRIPT = """\
# Standalone idalib Script

## Overview

A standalone script uses idalib to analyze binaries outside the IDA GUI.
It runs as a normal Python program and loads IDA's analysis engine in-process
via the `idapro` package. Use this when you need batch processing, CI
integration, or headless analysis.

## Template

```python
#!/usr/bin/env python3
\"\"\"Standalone idalib analysis script.\"\"\"

import os
import sys
from pathlib import Path

# --- idalib bootstrap (must happen before any ida_* imports) ---
IDA_DIR = os.environ.get("IDA_INSTALL_DIR")
if not IDA_DIR:
    print("Error: IDA_INSTALL_DIR env is not set")
    sys.exit(1)
IDA_DIR = Path(IDA_DIR)
sys.path.insert(0, str(IDA_DIR / "idalib" / "python"))
os.environ.setdefault("IDADIR", str(IDA_DIR))

import idapro  # Must be first — before any ida_* modules

# --- Now safe to import ida_* ---
import ida_funcs
import ida_bytes
import ida_name
import idautils
import idc
# import ida_hexrays  # Only if Hex-Rays decompiler is available


def analyze(binary_path: str) -> None:
    \"\"\"Main analysis logic.\"\"\"
    rc = idapro.open_database(binary_path, True)  # True = wait for auto-analysis
    if rc != 0:
        print(f"Error: open_database returned {rc}")
        return

    try:
        # --- Your analysis code here ---
        for ea in idautils.Functions():
            name = ida_funcs.get_func_name(ea)
            print(f"{ea:#x}  {name}")
    finally:
        idapro.close_database()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)
    analyze(sys.argv[1])
```

## Key Constraints

1. **Import order** — `import idapro` MUST come before any `ida_*` imports.
   Violating this causes segfaults or ImportError.
2. **Single database** — idalib supports only one open database at a time.
   Close before opening another.
3. **Single thread** — All `ida_*` calls must come from the thread that opened
   the database.
4. **auto_analysis** — Pass `True` to `open_database` to wait for IDA's
   auto-analysis to finish. Pass `False` for pre-analyzed databases (.i64/.idb).
5. **Cleanup** — Always call `idapro.close_database()` in a `try/finally` block.

## Common Patterns

### Iterate functions
```python
for ea in idautils.Functions():
    func = ida_funcs.get_func(ea)
    name = ida_funcs.get_func_name(ea)
    size = func.size()
```

### Read bytes
```python
data = ida_bytes.get_bytes(ea, size)
```

### Cross-references to an address
```python
for xref in idautils.XrefsTo(ea):
    print(f"  referenced from {xref.frm:#x}")
```

### Decompile (requires Hex-Rays)
```python
import ida_hexrays
cfunc = ida_hexrays.decompile(ea)
if cfunc:
    print(cfunc)
```
"""

_PLUGIN = """\
# IDA Plugin

## Overview

An IDA plugin is loaded inside the IDA GUI. It subclasses `idaapi.plugin_t`
and is placed in IDA's `plugins/` directory. Plugins can add menu items,
register hotkeys, hook into events, and extend the UI.

## Template

```python
\"\"\"My IDA Plugin — brief description.\"\"\"

import idaapi
import ida_kernwin


class MyPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC   # Loaded at startup, stays resident
    comment = "Brief description"
    help = "Extended help text"
    wanted_name = "My Plugin"     # Shown in Edit > Plugins
    wanted_hotkey = "Ctrl-Alt-M"  # Hotkey to trigger run()

    def init(self):
        \"\"\"Called when IDA loads the plugin. Return PLUGIN_KEEP to stay loaded.\"\"\"
        print(f"[{self.wanted_name}] Loaded")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        \"\"\"Called when the user activates the plugin (hotkey or menu).\"\"\"
        print(f"[{self.wanted_name}] Running")

    def term(self):
        \"\"\"Called when IDA shuts down or unloads the plugin.\"\"\"
        print(f"[{self.wanted_name}] Unloaded")


def PLUGIN_ENTRY():
    \"\"\"Required entry point — IDA calls this to instantiate the plugin.\"\"\"
    return MyPlugin()
```

## Plugin Flags

| Flag | Meaning |
|------|---------|
| `PLUGIN_PROC` | Load when a processor module is loaded (most common) |
| `PLUGIN_FIX`  | Load at startup, never unload |
| `PLUGIN_HIDE` | Don't show in the Plugins menu |
| `PLUGIN_UNL`  | Unload after each `run()` call |
| `PLUGIN_MULTI` | Can have multiple instances (IDA 7.4+) |

## init() Return Values

| Return | Meaning |
|--------|---------|
| `PLUGIN_KEEP` | Keep the plugin loaded |
| `PLUGIN_OK`   | Keep loaded, can be unloaded by IDA if needed |
| `PLUGIN_SKIP` | Do not load (wrong file type, missing dependency, etc.) |

## Adding Menu Items (Action-Based)

```python
class MyActionHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        print("Action triggered!")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# In init():
action_desc = idaapi.action_desc_t(
    "my_plugin:my_action",   # Unique action name
    "My Action",              # Display text
    MyActionHandler(),        # Handler instance
    "Ctrl-Shift-M",          # Hotkey (optional)
    "Tooltip text",           # Tooltip (optional)
)
idaapi.register_action(action_desc)
idaapi.attach_action_to_menu(
    "Edit/Plugins/",          # Menu path
    "my_plugin:my_action",    # Action name
    idaapi.SETMENU_APP,
)

# In term():
idaapi.unregister_action("my_plugin:my_action")
```

## Hooks

### UI Hooks
```python
class MyUIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        idaapi.attach_action_to_popup(
            widget, popup_handle, "my_plugin:my_action",
        )

# In init():  hooks = MyUIHooks(); hooks.hook()
# In term():  hooks.unhook()
```

### IDB Hooks (database events)
```python
import ida_idp

class MyIDBHooks(ida_idp.IDB_Hooks):
    def auto_empty_finally(self):
        # Called when auto-analysis completes
        return 0

# In init():  hooks = MyIDBHooks(); hooks.hook()
# In term():  hooks.unhook()
```

## Key Constraints

1. **`PLUGIN_ENTRY()`** — Required top-level function. IDA calls it to get the
   plugin instance.
2. **File location** — Place the `.py` file in `$IDA_DIR/plugins/` for auto-load,
   or use `ida_loader.load_plugin(path)` for dynamic loading.
3. **GUI thread** — All UI operations must run on IDA's main thread. Use
   `idaapi.execute_sync()` if calling from another thread.
4. **init() gating** — Return `PLUGIN_SKIP` if the plugin doesn't apply to the
   current database (e.g., wrong architecture).
5. **Cleanup in term()** — Unhook all hooks, unregister all actions, free
   resources. Failing to do so causes crashes on exit or reload.
"""

_IDAPYTHON_SCRIPT = """\
# IDAPython Script (In-GUI)

## Overview

A classic IDAPython script runs inside the IDA GUI via File > Script File,
the output window's Python console, or Alt-F7. All `ida_*` modules are
already available — no bootstrap needed. Use this for quick analysis tasks,
one-off automation, and interactive exploration.

## Template

```python
\"\"\"IDAPython script — brief description.

Run via File > Script File (Alt-F7) or the Python console.
\"\"\"

import ida_funcs
import ida_bytes
import ida_name
import idautils
import idc
import ida_kernwin


def main():
    \"\"\"Main script logic.\"\"\"
    ea = ida_kernwin.get_screen_ea()  # Current cursor address
    func = ida_funcs.get_func(ea)
    if not func:
        print(f"No function at {ea:#x}")
        return

    name = ida_funcs.get_func_name(func.start_ea)
    print(f"Current function: {name} ({func.start_ea:#x} - {func.end_ea:#x})")

    # --- Your analysis code here ---
    for head in idautils.Heads(func.start_ea, func.end_ea):
        disasm = idc.GetDisasm(head)
        print(f"  {head:#x}  {disasm}")


if __name__ == "__main__":
    main()
```

## Key Differences from Standalone Scripts

- **No bootstrap** — `ida_*` modules are pre-loaded by IDA. No `import idapro`,
  no `sys.path` manipulation, no `open_database`/`close_database`.
- **Database is already open** — the script operates on whichever database the
  user has open in IDA.
- **GUI available** — `ida_kernwin` functions work: dialogs, choosers, forms,
  `get_screen_ea()`, etc.
- **Output goes to IDA's Output window** — `print()` writes there, not to a
  terminal.

## Common Patterns

### Get current cursor position
```python
ea = ida_kernwin.get_screen_ea()
```

### Ask the user for input
```python
val = ida_kernwin.ask_str("default", 0, "Enter a value:")
ea = ida_kernwin.ask_addr(0, "Enter an address:")
```

### Show a chooser (list dialog)
```python
class MyChooser(ida_kernwin.Choose):
    def __init__(self, items):
        super().__init__("Title", [["Address", 16], ["Name", 30]])
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

chooser = MyChooser([
    [f"{ea:#x}", name]
    for ea, name in my_results
])
chooser.Show()
```

### Color an address
```python
idc.set_color(ea, idc.CIC_ITEM, 0x00FF00)  # Green
```

### Add a comment
```python
idc.set_cmt(ea, "my comment", 0)       # Regular comment
idc.set_cmt(ea, "my comment", 1)       # Repeatable comment
```

### Iterate all strings
```python
import ida_bytes
for s in idautils.Strings():
    print(f"{s.ea:#x}  {ida_bytes.get_strlit_contents(s.ea, s.length, s.strtype)}")
```
"""

_GUIDELINES: dict[str, str] = {
    "standalone_script": _STANDALONE_SCRIPT,
    "plugin": _PLUGIN,
    "idapython_script": _IDAPYTHON_SCRIPT,
}


def get(target: str) -> str:
    """Return coding guidelines for the given target type."""
    text = _GUIDELINES.get(target)
    if text is None:
        available = ", ".join(_GUIDELINES)
        raise KeyError(f"Unknown target {target!r}. Available: {available}")
    return text


def list_targets() -> list[str]:
    """Return all available guideline target names."""
    return list(_GUIDELINES)
