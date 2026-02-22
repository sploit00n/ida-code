"""Fat Mach-O architecture listing and slice extraction using LIEF."""

from __future__ import annotations

import logging

import lief

log = logging.getLogger(__name__)


def _arch_name(binary: lief.MachO.Binary) -> str:
    """Derive a human-friendly architecture name from a Mach-O binary header."""
    name = binary.header.cpu_type.name.lower()
    # ARM64 subtype 2 is arm64e (pointer authentication).
    if name == "arm64" and binary.header.cpu_subtype == 2:
        return "arm64e"
    return name


def list_architectures(path: str) -> list[str]:
    """List architecture names in a fat Mach-O binary.

    Returns e.g. ["x86_64", "arm64e"]. Returns an empty list if *path*
    is not a fat (universal) Mach-O.
    """
    fat = lief.MachO.parse(path)
    if fat is None:
        return []
    # A single-slice FatBinary is effectively a thin binary.
    if len(fat) <= 1:
        return []
    return [_arch_name(binary) for binary in fat]


def extract_slice(path: str, arch: str) -> str:
    """Extract a single architecture slice to ``{path}.{arch}`` and return that path.

    Raises ``ValueError`` if *path* is not a fat Mach-O or the requested
    architecture is not found.
    """
    fat = lief.MachO.parse(path)
    if fat is None or len(fat) <= 1:
        raise ValueError(f"Not a fat Mach-O: {path}")

    # Try exact match first, then fall back to base cpu_type match.
    exact: lief.MachO.Binary | None = None
    base_match: lief.MachO.Binary | None = None
    for binary in fat:
        name = _arch_name(binary)
        if name == arch:
            exact = binary
            break
        if binary.header.cpu_type.name.lower() == arch:
            base_match = binary

    chosen = exact or base_match
    if chosen is None:
        available = [_arch_name(b) for b in fat]
        raise ValueError(
            f"Architecture '{arch}' not found. Available: {available}"
        )

    output_path = f"{path}.{arch}"
    log.info("Extracting %s slice from %s -> %s", arch, path, output_path)
    chosen.write(output_path)
    return output_path
