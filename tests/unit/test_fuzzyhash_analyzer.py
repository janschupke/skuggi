"""L1: the fuzzy (similarity) hash analyzer -- TLSH, degrade-to-note -- E19/F1."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from skuggi.forensics.analyzers import fuzzyhash


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "artifact.bin"
    p.write_bytes(data)
    return p


def test_tlsh_hashes_a_varied_file_and_is_similarity_comparable(tmp_path: Path) -> None:
    tlsh = pytest.importorskip("tlsh")
    # TLSH needs enough data with byte variation to produce a stable digest.
    base = bytes(range(256)) * 64
    near = bytearray(base)
    near[0:16] = b"a small tweak!!!"
    file_a, file_b = tmp_path / "a.bin", tmp_path / "b.bin"
    file_a.write_bytes(base)
    file_b.write_bytes(bytes(near))
    [obs_a] = [o for o in fuzzyhash.analyze(file_a) if o.kind == "fuzzyhash"]
    [obs_b] = [o for o in fuzzyhash.analyze(file_b) if o.kind == "fuzzyhash"]
    assert obs_a.attributes["algorithm"] == "tlsh"
    # a small edit yields a small TLSH distance (similarity preserved)
    assert tlsh.diff(obs_a.value, obs_b.value) < 100


def test_tlsh_insufficient_data_degrades_to_a_note(tmp_path: Path) -> None:
    pytest.importorskip("tlsh")
    [obs] = fuzzyhash.analyze(_write(tmp_path, b"too small"))
    assert obs.kind == "note"
    assert "insufficient data" in obs.value


def test_no_backend_available_yields_a_single_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Make `import tlsh` / `import ssdeep` raise ImportError inside the analyzer.
    monkeypatch.setitem(sys.modules, "tlsh", None)
    monkeypatch.setitem(sys.modules, "ssdeep", None)
    [obs] = fuzzyhash.analyze(_write(tmp_path, bytes(range(256)) * 64))
    assert obs.kind == "note"
    assert "fuzzy hashing unavailable" in obs.value
