"""L1: the pure-Python executable-format analyzer (ELF/PE/Mach-O headers) — E19."""

from __future__ import annotations

import struct
from pathlib import Path

from skuggi.forensics.analyzers import executable


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "artifact.bin"
    p.write_bytes(data)
    return p


def test_identifies_a_64bit_elf_executable(tmp_path: Path) -> None:
    # ELF magic, 64-bit, little-endian; e_type=2 (exec) at 16, e_machine=0x3E at 18
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little-endian
    struct.pack_into("<H", header, 16, 2)  # e_type: executable
    struct.pack_into("<H", header, 18, 0x3E)  # e_machine: x86-64
    [obs] = executable.analyze(_write(tmp_path, bytes(header)))
    assert obs.value == "elf"
    assert obs.attributes["bitness"] == "64-bit"
    assert obs.attributes["arch"] == "x86-64"
    assert obs.attributes["type"] == "executable"


def test_identifies_a_pe_with_machine_and_section_count(tmp_path: Path) -> None:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", data, 0x3C, pe_off)
    data[pe_off : pe_off + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, pe_off + 4, 0x8664)  # machine: x86-64
    struct.pack_into("<H", data, pe_off + 6, 5)  # 5 sections
    [obs] = executable.analyze(_write(tmp_path, bytes(data)))
    assert obs.value == "pe"
    assert obs.attributes["arch"] == "x86-64"
    assert obs.attributes["sections"] == "5"


def test_identifies_a_macho(tmp_path: Path) -> None:
    data = struct.pack(">I", 0xFEEDFACF) + b"\x00" * 60
    [obs] = executable.analyze(_write(tmp_path, data))
    assert obs.value == "mach-o"
    assert obs.attributes["bitness"] == "64-bit"


def test_a_plain_file_yields_no_executable_observation(tmp_path: Path) -> None:
    assert executable.analyze(_write(tmp_path, b"just some text, not a binary")) == []
