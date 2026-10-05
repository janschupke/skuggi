"""L1: the Windows registry-hive (regf) header analyzer -- F3."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

from skuggi.forensics.analyzers import registry


def _regf(seq_primary: int, seq_secondary: int, filetime: int = 0) -> bytes:
    data = bytearray(4096)
    data[:4] = b"regf"
    struct.pack_into("<II", data, 4, seq_primary, seq_secondary)
    struct.pack_into("<Q", data, 12, filetime)
    struct.pack_into("<IIII", data, 20, 1, 5, 0, 1)  # major, minor, file_type, format
    name = "\\SystemRoot\\System32\\Config\\SAM".encode("utf-16-le")
    data[48 : 48 + len(name)] = name
    return bytes(data)


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "hive.dat"
    p.write_bytes(data)
    return p


def test_clean_hive_header(tmp_path: Path) -> None:
    # A FILETIME value (100-ns ticks since 1601) -> a concrete UTC timestamp.
    ft = 133_776_576_000_000_000
    [obs] = [
        o
        for o in registry.analyze(_write(tmp_path, _regf(7, 7, ft)))
        if o.kind == "registry"
    ]
    assert obs.attributes["version"] == "1.5"
    assert obs.attributes["state"] == "clean"
    assert obs.attributes["file_type"] == "primary"
    assert obs.attributes["embedded_path"].endswith("SAM")
    assert obs.attributes["last_written"] == "2024-12-03T00:00:00+00:00"


def test_dirty_hive_is_flagged(tmp_path: Path) -> None:
    [obs] = [
        o
        for o in registry.analyze(_write(tmp_path, _regf(9, 8)))
        if o.kind == "registry"
    ]
    assert "dirty" in obs.attributes["state"]


def test_non_hive_yields_nothing(tmp_path: Path) -> None:
    assert registry.analyze(_write(tmp_path, b"not a hive")) == []


def test_enrichment_absent_dep_degrades_to_header_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "Registry", None)
    obs = registry.analyze(_write(tmp_path, _regf(1, 1)))
    assert [o.kind for o in obs] == ["registry"]  # no registry-keys enrichment row


def test_enrichment_on_a_malformed_hive_does_not_raise(tmp_path: Path) -> None:
    # python-registry (if installed) cannot parse a header-only hive; the analyzer
    # must still return the header summary, never raise.
    obs = registry.analyze(_write(tmp_path, _regf(1, 1)))
    assert any(o.kind == "registry" for o in obs)
