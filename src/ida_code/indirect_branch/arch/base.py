"""Base arch helper — every hook is a no-op.

Importing this module and calling its hooks is always safe; arch
specifics are added by sibling modules that shadow these names.
"""

from __future__ import annotations


def pac_discriminator(ea: int) -> dict | None:
    """No PAC (Pointer Authentication) machinery on this arch — return None."""
    return None
