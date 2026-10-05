"""L1: the Windows event-log (evtx) header analyzer -- F4."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

from skuggi.forensics.analyzers import evtx


def _evtx(flags: int, chunks: int = 4, next_record: int = 101) -> bytes:
    data = bytearray(4096)
    data[:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", data, 8, 0, chunks - 1, next_record)
    struct.pack_into(
        "<IHHHH", data, 32, 128, 1, 3, 4096, chunks
    )  # size, minor, major...
    struct.pack_into("<I", data, 120, flags)
    return bytes(data)


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "log.evtx"
    p.write_bytes(data)
    return p


def test_clean_evtx_header(tmp_path: Path) -> None:
    [obs] = [o for o in evtx.analyze(_write(tmp_path, _evtx(0))) if o.kind == "evtx"]
    assert obs.attributes["version"] == "3.1"
    assert obs.attributes["chunks"] == "4"
    assert obs.attributes["next_record_id"] == "101"
    assert obs.attributes["state"] == "clean"


def test_dirty_and_full_flags(tmp_path: Path) -> None:
    [obs] = [o for o in evtx.analyze(_write(tmp_path, _evtx(0x3))) if o.kind == "evtx"]
    assert obs.attributes["state"] == "dirty, full"


def test_non_evtx_yields_nothing(tmp_path: Path) -> None:
    assert evtx.analyze(_write(tmp_path, b"not an evtx file")) == []


def test_enrichment_absent_dep_degrades_to_header_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "Evtx", None)
    monkeypatch.setitem(sys.modules, "Evtx.Evtx", None)
    obs = evtx.analyze(_write(tmp_path, _evtx(0)))
    assert [o.kind for o in obs] == ["evtx"]


def test_enrichment_on_a_malformed_log_does_not_raise(tmp_path: Path) -> None:
    # python-evtx (if installed) cannot parse a header-only file; the analyzer must
    # still return the header summary rather than raising.
    obs = evtx.analyze(_write(tmp_path, _evtx(0)))
    assert any(o.kind == "evtx" for o in obs)
