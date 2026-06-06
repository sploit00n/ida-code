"""Arch-specific helpers for indirect-branch evidence (Pass 3).

Each helper module exposes a small set of hooks; ``get_helper()``
returns the right module based on the current database's processor.

Adding a new arch:
  1. Create ``arch/<name>.py`` exposing the relevant hook functions
     (each defaults to no-op if absent — see ``base.py``).
  2. Register it in ``_lookup()`` below.

Hook surface (so far):
  - ``pac_discriminator(ea) -> dict | None`` — PAC-signed branches
    (BLRAA/BLRAB/BRAA/BRAB on arm64e). Returns
    ``{"register", "value", "source_addr"}`` or None.
"""

from __future__ import annotations

from ida_code.indirect_branch.arch import base


def get_helper():
    """Return the arch helper module for the currently open database.

    Falls back to ``base`` (no-op) when no arch-specific helper matches.
    """
    helper = _lookup()
    return helper or base


def _lookup():
    import ida_ida
    import ida_idp

    procname = (ida_idp.get_idp_name() or "").lower()
    is_64 = ida_ida.inf_is_64bit()

    if is_64 and "arm" in procname:
        # arm64 and arm64e share enough that arm64e helpers degrade
        # gracefully on plain arm64 (no BLRAA/PAC means no discriminator
        # gets returned — same as not having a helper at all).
        from ida_code.indirect_branch.arch import arm64e
        return arm64e

    return None
