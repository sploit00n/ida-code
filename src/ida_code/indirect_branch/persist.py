"""Persistence for indirect-branch resolutions.

Two complementary mechanisms in the .i64:
  - Manual code xrefs (one per target) — so get_xrefs_from sees them.
  - A tagged @RESOLVED_V1 block in the branch site's regular comment —
    carries per-target confidence + reason, plus the unresolvable form.

Comment format::

  @RESOLVED_V1
  1/N <hex_addr> <confidence> <reason text>
  ...

  or:

  @RESOLVED_V1 unresolvable
  <reason text spanning one or more lines>

The marker block is always appended to the end of the existing comment.
parse/format here are pure string ops — unit-testable without idalib.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MARKER = "@RESOLVED_V1"
MARKER_UNRESOLVABLE = f"{MARKER} unresolvable"

CONFIDENCE_VALUES = ("certain", "likely", "speculative")

_TARGET_LINE_RE = re.compile(
    r"^\s*(\d+)/(\d+)\s+(0x[0-9a-fA-F]+)\s+(\w+)\s+(.+?)\s*$"
)


@dataclass
class Target:
    addr: int
    confidence: str
    reason: str

    def to_dict(self) -> dict:
        return {
            "addr": f"{self.addr:#x}",
            "confidence": self.confidence,
            "reason": self.reason,
        }


@dataclass
class Resolution:
    unresolvable: bool = False
    targets: list[Target] = field(default_factory=list)
    reason: str = ""  # only used for unresolvable

    def to_dict(self) -> dict:
        if self.unresolvable:
            return {"unresolvable": True, "reason": self.reason, "targets": []}
        return {
            "unresolvable": False,
            "targets": [t.to_dict() for t in self.targets],
        }


def format_resolution(
    targets: list[dict] | None = None,
    unresolvable_reason: str = "",
) -> str:
    """Build the @RESOLVED_V1 block text.

    Either pass a non-empty ``targets`` list (resolved case) or a
    non-empty ``unresolvable_reason`` (dead-end case). Raises
    ``ValueError`` on invalid input.
    """
    if unresolvable_reason:
        if targets:
            raise ValueError("Pass either targets or unresolvable_reason, not both.")
        reason = unresolvable_reason.strip()
        if not reason:
            raise ValueError("unresolvable_reason must not be empty.")
        return f"{MARKER_UNRESOLVABLE}\n{reason}"

    if not targets:
        raise ValueError("Pass at least one target or set unresolvable_reason.")

    total = len(targets)
    lines = [MARKER]
    for i, t in enumerate(targets, start=1):
        addr = t.get("addr")
        conf = t.get("confidence", "")
        reason = (t.get("reason") or "").strip()
        if addr is None:
            raise ValueError(f"Target {i}: missing 'addr'.")
        if conf not in CONFIDENCE_VALUES:
            raise ValueError(
                f"Target {i}: confidence must be one of {CONFIDENCE_VALUES}, got {conf!r}."
            )
        if not reason:
            raise ValueError(f"Target {i}: reason must not be empty.")
        addr_int = _coerce_int(addr)
        lines.append(f"{i}/{total} {addr_int:#x} {conf} {reason}")
    return "\n".join(lines)


def parse_resolution(comment: str) -> Resolution | None:
    """Extract the @RESOLVED_V1 block from a comment, or return None.

    The marker is expected to be on its own line; everything from the
    marker line to the end of the comment is the block.
    """
    if not comment or MARKER not in comment:
        return None

    # Find the marker line.
    lines = comment.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == MARKER:
            return _parse_resolved_block(lines[i + 1:])
        if stripped == MARKER_UNRESOLVABLE:
            return _parse_unresolvable_block(lines[i + 1:])

    return None


def strip_marker_block(comment: str) -> str:
    """Return *comment* with the @RESOLVED_V1 block removed (trailing only)."""
    if not comment or MARKER not in comment:
        return comment
    lines = comment.splitlines()
    for i, line in enumerate(lines):
        if line.strip() in (MARKER, MARKER_UNRESOLVABLE):
            # Drop from i onward; also drop a single trailing blank line if it
            # immediately precedes the marker.
            head = lines[:i]
            while head and head[-1].strip() == "":
                head.pop()
            return "\n".join(head)
    return comment


def merge_resolution_into_comment(existing: str, block: str) -> str:
    """Append *block* to *existing* comment, replacing any prior block."""
    stripped = strip_marker_block(existing or "")
    if not stripped:
        return block
    return f"{stripped}\n\n{block}"


# ---------- internals ----------


def _parse_resolved_block(body_lines: list[str]) -> Resolution:
    targets: list[Target] = []
    for line in body_lines:
        if not line.strip():
            continue
        m = _TARGET_LINE_RE.match(line)
        if not m:
            # Malformed line — stop parsing further targets but keep what we have.
            break
        idx, total, addr_s, conf, reason = m.groups()
        if conf not in CONFIDENCE_VALUES:
            continue
        try:
            addr = int(addr_s, 16)
        except ValueError:
            continue
        targets.append(Target(addr=addr, confidence=conf, reason=reason))
    return Resolution(unresolvable=False, targets=targets)


def _parse_unresolvable_block(body_lines: list[str]) -> Resolution:
    # Reason is the body until first blank line (if any).
    body: list[str] = []
    for line in body_lines:
        if line.strip() == "":
            break
        body.append(line.rstrip())
    return Resolution(unresolvable=True, reason="\n".join(body).strip())


def _coerce_int(value) -> int:
    if isinstance(value, int):
        return value
    s = str(value).strip()
    try:
        return int(s, 16)
    except ValueError:
        return int(s, 10)
