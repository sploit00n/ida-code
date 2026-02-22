"""Unit tests for ida_code.macho — fat Mach-O architecture helpers."""

import os
import struct
import tempfile

import lief
import pytest

from ida_code import macho


# ---------------------------------------------------------------------------
# Helpers to build minimal Mach-O binaries for testing
# ---------------------------------------------------------------------------

# Mach-O magic numbers
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE

# CPU types
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C

# CPU subtypes
CPU_SUBTYPE_ALL = 0
CPU_SUBTYPE_ARM64E = 2

# Mach-O header commands
LC_SEGMENT_64 = 0x19


def _make_thin_macho(cpu_type: int, cpu_subtype: int = CPU_SUBTYPE_ALL) -> bytes:
    """Build a minimal valid thin 64-bit Mach-O (header + one empty segment)."""
    # mach_header_64: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
    header = struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        cpu_type,
        cpu_subtype,
        2,  # MH_EXECUTE
        1,  # ncmds (one LC_SEGMENT_64)
        72, # sizeofcmds
        0,  # flags
        0,  # reserved
    )
    # LC_SEGMENT_64: cmd, cmdsize, segname(16), vmaddr, vmsize, fileoff, filesize,
    #                maxprot, initprot, nsects, flags
    segment = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64,
        72,             # cmdsize
        b"__TEXT\x00" + b"\x00" * 9,
        0x100000000,    # vmaddr
        0x1000,         # vmsize
        0,              # fileoff
        0,              # filesize
        7,              # maxprot (rwx)
        5,              # initprot (rx)
        0,              # nsects
        0,              # flags
    )
    return header + segment


def _make_fat_macho(slices: list[tuple[int, int, bytes]]) -> bytes:
    """Build a minimal fat Mach-O from a list of (cpu_type, cpu_subtype, thin_bytes)."""
    nfat_arch = len(slices)
    # fat_header: magic(4) + nfat_arch(4)
    # fat_arch: cputype(4) + cpusubtype(4) + offset(4) + size(4) + align(4)
    header_size = 8 + nfat_arch * 20
    # Align each slice to 4096 bytes for realism.
    align_val = 12  # 2^12 = 4096

    # Calculate offsets for each slice.
    offsets = []
    current = header_size
    for _, _, data in slices:
        # Align up to 4096.
        current = (current + 0xFFF) & ~0xFFF
        offsets.append(current)
        current += len(data)

    # Build fat header (big-endian).
    buf = struct.pack(">II", FAT_MAGIC, nfat_arch)
    for i, (cpu_type, cpu_subtype, data) in enumerate(slices):
        buf += struct.pack(">IIIII", cpu_type, cpu_subtype, offsets[i], len(data), align_val)

    # Pad and append each slice.
    result = bytearray(buf)
    for i, (_, _, data) in enumerate(slices):
        # Pad to the slice offset.
        if len(result) < offsets[i]:
            result += b"\x00" * (offsets[i] - len(result))
        result += data
    return bytes(result)


@pytest.fixture
def fat_binary(tmp_path):
    """Create a fat Mach-O with x86_64 and arm64e slices."""
    x86 = _make_thin_macho(CPU_TYPE_X86_64)
    arm64e = _make_thin_macho(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E)
    data = _make_fat_macho([
        (CPU_TYPE_X86_64, CPU_SUBTYPE_ALL, x86),
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, arm64e),
    ])
    p = tmp_path / "test_fat"
    p.write_bytes(data)
    return str(p)


@pytest.fixture
def thin_binary(tmp_path):
    """Create a thin (non-fat) arm64e Mach-O."""
    data = _make_thin_macho(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E)
    p = tmp_path / "test_thin"
    p.write_bytes(data)
    return str(p)


@pytest.fixture
def non_macho(tmp_path):
    """Create a non-Mach-O file."""
    p = tmp_path / "test_elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 100)
    return str(p)


# ---------------------------------------------------------------------------
# Tests for list_architectures
# ---------------------------------------------------------------------------

class TestListArchitectures:
    def test_fat_binary_lists_slices(self, fat_binary):
        archs = macho.list_architectures(fat_binary)
        assert "x86_64" in archs
        assert "arm64e" in archs
        assert len(archs) == 2

    def test_thin_binary_returns_empty(self, thin_binary):
        assert macho.list_architectures(thin_binary) == []

    def test_non_macho_returns_empty(self, non_macho):
        assert macho.list_architectures(non_macho) == []


# ---------------------------------------------------------------------------
# Tests for extract_slice
# ---------------------------------------------------------------------------

class TestExtractSlice:
    def test_extract_x86_64(self, fat_binary):
        out = macho.extract_slice(fat_binary, "x86_64")
        assert out == f"{fat_binary}.x86_64"
        assert os.path.isfile(out)
        # The extracted file should be parseable as a thin Mach-O.
        parsed = lief.MachO.parse(out)
        assert parsed is not None
        binary = parsed.at(0)
        assert binary.header.cpu_type.name.lower() == "x86_64"

    def test_extract_arm64e(self, fat_binary):
        out = macho.extract_slice(fat_binary, "arm64e")
        assert out == f"{fat_binary}.arm64e"
        assert os.path.isfile(out)
        parsed = lief.MachO.parse(out)
        assert parsed is not None
        binary = parsed.at(0)
        assert binary.header.cpu_type.name.lower() == "arm64"
        assert binary.header.cpu_subtype == CPU_SUBTYPE_ARM64E

    def test_base_cpu_type_fallback(self, fat_binary):
        # "arm64" should match the arm64e slice via base cpu_type fallback.
        out = macho.extract_slice(fat_binary, "arm64")
        assert os.path.isfile(out)

    def test_missing_arch_raises(self, fat_binary):
        with pytest.raises(ValueError, match="not found"):
            macho.extract_slice(fat_binary, "ppc")

    def test_thin_binary_raises(self, thin_binary):
        with pytest.raises(ValueError, match="Not a fat"):
            macho.extract_slice(thin_binary, "arm64e")

    def test_non_macho_raises(self, non_macho):
        with pytest.raises(ValueError, match="Not a fat"):
            macho.extract_slice(non_macho, "x86_64")


# ---------------------------------------------------------------------------
# Tests for _arch_name
# ---------------------------------------------------------------------------

class TestArchName:
    def test_arm64e_detection(self, fat_binary):
        """arm64 subtype 2 should be reported as arm64e."""
        archs = macho.list_architectures(fat_binary)
        assert "arm64e" in archs

    def test_plain_arm64(self, tmp_path):
        """arm64 subtype 0 should be reported as arm64 (not arm64e)."""
        arm64 = _make_thin_macho(CPU_TYPE_ARM64, CPU_SUBTYPE_ALL)
        x86 = _make_thin_macho(CPU_TYPE_X86_64)
        data = _make_fat_macho([
            (CPU_TYPE_X86_64, CPU_SUBTYPE_ALL, x86),
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ALL, arm64),
        ])
        p = tmp_path / "fat_arm64"
        p.write_bytes(data)
        archs = macho.list_architectures(str(p))
        assert "arm64" in archs
        assert "arm64e" not in archs
