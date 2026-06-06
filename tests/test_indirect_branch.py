"""Tests for ida_code.indirect_branch.

Unit tests for the comment parser/formatter run without idalib.
Integration tests against ALF.kext arm64 (KDK install required) are
skipped when the binary isn't available.
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import pytest

from ida_code.indirect_branch import persist


# ---------------- unit: comment parser/formatter ----------------


class TestFormatResolution:
    def test_single_target(self):
        block = persist.format_resolution(
            targets=[{"addr": "0x69dc", "confidence": "certain", "reason": "Caller PACIAs target."}]
        )
        assert block.splitlines()[0] == persist.MARKER
        assert "1/1 0x69dc certain Caller PACIAs target." in block

    def test_multiple_targets_indices(self):
        block = persist.format_resolution(
            targets=[
                {"addr": "0x4000", "confidence": "likely", "reason": "passed to qsort in main"},
                {"addr": "0x4100", "confidence": "speculative", "reason": "fallback comparator"},
            ]
        )
        lines = block.splitlines()
        assert lines[1].startswith("1/2 0x4000 likely ")
        assert lines[2].startswith("2/2 0x4100 speculative ")

    def test_accepts_int_addr(self):
        block = persist.format_resolution(
            targets=[{"addr": 0x69DC, "confidence": "certain", "reason": "ok"}]
        )
        assert "0x69dc" in block

    def test_unresolvable(self):
        block = persist.format_resolution(unresolvable_reason="No static candidates")
        assert block.startswith(persist.MARKER_UNRESOLVABLE)
        assert "No static candidates" in block

    def test_rejects_both_targets_and_unresolvable(self):
        with pytest.raises(ValueError):
            persist.format_resolution(
                targets=[{"addr": "0x10", "confidence": "certain", "reason": "x"}],
                unresolvable_reason="and unresolvable",
            )

    def test_rejects_neither(self):
        with pytest.raises(ValueError):
            persist.format_resolution()

    def test_rejects_bad_confidence(self):
        with pytest.raises(ValueError):
            persist.format_resolution(
                targets=[{"addr": "0x10", "confidence": "definite", "reason": "x"}]
            )

    def test_rejects_missing_reason(self):
        with pytest.raises(ValueError):
            persist.format_resolution(
                targets=[{"addr": "0x10", "confidence": "certain", "reason": ""}]
            )

    def test_rejects_missing_addr(self):
        with pytest.raises(ValueError):
            persist.format_resolution(
                targets=[{"confidence": "certain", "reason": "x"}]
            )


class TestParseResolution:
    def test_round_trip_single(self):
        block = persist.format_resolution(
            targets=[{"addr": "0x69dc", "confidence": "certain", "reason": "Caller PACIAs target."}]
        )
        r = persist.parse_resolution(block)
        assert r is not None
        assert not r.unresolvable
        assert len(r.targets) == 1
        assert r.targets[0].addr == 0x69DC
        assert r.targets[0].confidence == "certain"
        assert r.targets[0].reason == "Caller PACIAs target."

    def test_round_trip_multi(self):
        block = persist.format_resolution(
            targets=[
                {"addr": "0x4000", "confidence": "likely", "reason": "qsort in main"},
                {"addr": "0x4100", "confidence": "speculative", "reason": "fallback"},
            ]
        )
        r = persist.parse_resolution(block)
        assert r is not None
        assert [t.addr for t in r.targets] == [0x4000, 0x4100]
        assert [t.confidence for t in r.targets] == ["likely", "speculative"]

    def test_unresolvable_round_trip(self):
        block = persist.format_resolution(unresolvable_reason="No candidates found")
        r = persist.parse_resolution(block)
        assert r is not None
        assert r.unresolvable
        assert r.reason == "No candidates found"

    def test_no_marker_returns_none(self):
        assert persist.parse_resolution("just a regular comment") is None
        assert persist.parse_resolution("") is None
        assert persist.parse_resolution(None) is None

    def test_marker_after_existing_text(self):
        comment = (
            "Hand-written note about this branch.\n"
            "\n"
            f"{persist.MARKER}\n"
            "1/1 0x69dc certain Caller PACIAs target."
        )
        r = persist.parse_resolution(comment)
        assert r is not None
        assert r.targets[0].addr == 0x69DC


class TestMergeAndStrip:
    def test_strip_no_marker_is_identity(self):
        text = "just a note"
        assert persist.strip_marker_block(text) == text

    def test_strip_removes_marker_and_trailing_blank(self):
        text = (
            "Hand-written note.\n"
            "\n"
            f"{persist.MARKER}\n"
            "1/1 0x69dc certain ok"
        )
        assert persist.strip_marker_block(text) == "Hand-written note."

    def test_merge_into_empty(self):
        block = persist.format_resolution(
            targets=[{"addr": "0x10", "confidence": "certain", "reason": "x"}]
        )
        assert persist.merge_resolution_into_comment("", block) == block

    def test_merge_replaces_existing_block(self):
        block_v1 = persist.format_resolution(
            targets=[{"addr": "0x10", "confidence": "certain", "reason": "v1 reason"}]
        )
        block_v2 = persist.format_resolution(
            targets=[{"addr": "0x20", "confidence": "likely", "reason": "v2 reason"}]
        )
        existing = f"Note here\n\n{block_v1}"
        merged = persist.merge_resolution_into_comment(existing, block_v2)
        assert "0x10" not in merged
        assert "0x20" in merged
        assert merged.startswith("Note here")


# ---------------- integration: ALF.kext via idalib ----------------

# Probe for idalib availability — same pattern as test_e2e.
try:
    from ida_code import session
    from ida_code import ida_thread
    from ida_code.indirect_branch import api as ib_api
    _HAVE_IDALIB = True
except ImportError:
    _HAVE_IDALIB = False


def _on_ida(fn, *args, **kwargs):
    """Synchronous helper: dispatch a callable to the ida-thread and return result."""
    return ida_thread.submit(fn, *args, **kwargs).result(timeout=60)


def _kdk_alf_path() -> Path | None:
    """Find the ALF.kext arm64 slice binary, or None if not installed."""
    candidates = [
        Path("/home/user/research/mac-crash/updates/kdk/26.3_25D5087f/Extensions/ALF.kext/Contents/MacOS/ALF"),
    ]
    for p in candidates:
        if p.is_file():
            return p
    # Allow env-var override for other systems.
    env = os.environ.get("ALF_KEXT")
    if env and Path(env).is_file():
        return Path(env)
    return None


@pytest.fixture
def alf_db(tmp_path):
    """Copy ALF.kext to tmp_path and open as arm64 slice. Skip if KDK absent."""
    if not _HAVE_IDALIB:
        pytest.skip("idalib not available")
    src = _kdk_alf_path()
    if src is None:
        pytest.skip("ALF.kext not found (set ALF_KEXT env var to override)")
    dst = tmp_path / "ALF"
    shutil.copy(src, dst)

    from ida_code import session as _s
    if _s.get_state() == _s.State.DATABASE_OPEN:
        _s.close()
    _s.open(str(dst), auto_analysis=True, arch="arm64")
    yield dst
    if _s.get_state() == _s.State.DATABASE_OPEN:
        try:
            _s.close()
        except Exception:
            pass


KNOWN_SITE = 0x8E9C  # BLRAA X19,X17 in _sw_proc_entry_list_apply_func


def test_scan_finds_known_sites(alf_db):
    result = _on_ida(ib_api.list_indirect_branches, status="any")
    addrs = {int(s["addr"], 16) for s in result["sites"]}
    assert KNOWN_SITE in addrs, f"expected 0x{KNOWN_SITE:x} in scan; got {sorted(hex(a) for a in addrs)}"


def test_get_returns_minimal_evidence(alf_db):
    r = _on_ida(ib_api.get_indirect_branch, f"{KNOWN_SITE:#x}")
    assert r["kind"] == "call"
    assert "sw_proc_entry_list_apply_func" in (r["containing_function"] or "")
    assert r["existing_resolution"] is None


def test_set_then_get_round_trip(alf_db):
    targets = [{"addr": "0x69dc", "confidence": "certain", "reason": "Both callers PACIA &_rslog_flush_func with disc 0x2ABE."}]
    rec = _on_ida(ib_api.set_indirect_branch, f"{KNOWN_SITE:#x}", targets=targets)
    assert rec["status"] == "recorded"
    assert rec["targets_recorded"] == 1
    assert rec["xrefs_added"] == 1

    r = _on_ida(ib_api.get_indirect_branch, f"{KNOWN_SITE:#x}")
    res = r["existing_resolution"]
    assert res is not None
    assert res["unresolvable"] is False
    assert res["targets"][0]["addr"] == "0x69dc"
    assert res["targets"][0]["confidence"] == "certain"

    # Manual xref must now show up via the standard xrefs API surface.
    def _check_xref():
        import idautils, ida_xref
        return [x.to for x in idautils.XrefsFrom(KNOWN_SITE, ida_xref.XREF_FAR) if x.user]
    user_targets = _on_ida(_check_xref)
    assert 0x69DC in user_targets


def test_list_status_filter_after_resolve(alf_db):
    _on_ida(
        ib_api.set_indirect_branch,
        f"{KNOWN_SITE:#x}",
        targets=[{"addr": "0x69dc", "confidence": "certain", "reason": "ok"}],
    )

    unresolved = _on_ida(ib_api.list_indirect_branches, status="unresolved")
    resolved = _on_ida(ib_api.list_indirect_branches, status="resolved")
    any_ = _on_ida(ib_api.list_indirect_branches, status="any")

    unresolved_addrs = {s["addr"] for s in unresolved["sites"]}
    resolved_addrs = {s["addr"] for s in resolved["sites"]}
    any_addrs = {s["addr"] for s in any_["sites"]}

    assert f"{KNOWN_SITE:#x}" not in unresolved_addrs
    assert f"{KNOWN_SITE:#x}" in resolved_addrs
    assert f"{KNOWN_SITE:#x}" in any_addrs


def test_set_unresolvable_round_trip(alf_db):
    site = 0xA264
    rec = _on_ida(
        ib_api.set_indirect_branch,
        f"{site:#x}",
        unresolvable_reason="Backward slice terminates at runtime IOKit thunk.",
    )
    assert rec["unresolvable"] is True
    assert rec["xrefs_added"] == 0

    r = _on_ida(ib_api.get_indirect_branch, f"{site:#x}")
    res = r["existing_resolution"]
    assert res["unresolvable"] is True
    assert "IOKit" in res["reason"]
