"""Indirect-branch evidence tools.

Three-pass design:
  Pass 1 (this commit): IDA-Python CFG only — site enumeration via
    is_call_insn + fcb_indjump, no disassembly or microcode. Persistence
    via manual xrefs + tagged @RESOLVED_V1 comment in the .i64.
  Pass 2: arch-agnostic microcode heuristics — backward-slice, from-argN
    inference, caller-arg pattern matcher.
  Pass 3: arch helpers (e.g. arm64e PAC discriminator).

Each pass adds fields to get_indirect_branch's response. The set/list
verbs and persistence layer stay stable across passes.
"""

from ida_code.indirect_branch.api import (
    get_indirect_branch,
    list_indirect_branches,
    set_indirect_branch,
)

__all__ = [
    "get_indirect_branch",
    "list_indirect_branches",
    "set_indirect_branch",
]
