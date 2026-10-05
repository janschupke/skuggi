"""Structured header analysis for executable artifacts (ELF / PE / Mach-O).

A pure-Python, dependency-free step up from byte-level triage (audit E19): it reads
only the file header -- so it is unaffected by the whole-file read cap and handles a
multi-gigabyte binary cheaply -- and reports the format, bitness, architecture and
object type as structured observations. A non-executable (or a truncated header)
yields nothing, so the battery can run it over every binary unconditionally.
"""

from __future__ import annotations

import struct
from pathlib import Path

from skuggi.forensics.analyzers.base import Observation

_HEADER_BYTES = 4096  # enough for the ELF/PE/Mach-O headers we read

_ELF_TYPE = {1: "relocatable", 2: "executable", 3: "shared-object", 4: "core"}
_ELF_MACHINE = {
    0x03: "x86",
    0x3E: "x86-64",
    0x28: "arm",
    0xB7: "aarch64",
    0xF3: "riscv",
}
_PE_MACHINE = {
    0x14C: "x86",
    0x8664: "x86-64",
    0x1C0: "arm",
    0xAA64: "aarch64",
}
_MACHO_MAGICS = {
    0xFEEDFACE: ("32-bit", False),
    0xFEEDFACF: ("64-bit", False),
    0xCEFAEDFE: ("32-bit", True),
    0xCFFAEDFE: ("64-bit", True),
}


def _obs(fmt: str, **attrs: str) -> list[Observation]:
    return [Observation(kind="executable", value=fmt, attributes=attrs)]


def _elf(data: bytes) -> list[Observation]:
    if len(data) < 20:  # noqa: PLR2004 -- the fixed ELF prefix we read
        return _obs("elf")
    bitness = "64-bit" if data[4] == 2 else "32-bit"  # noqa: PLR2004 -- EI_CLASS
    endian = "little" if data[5] == 1 else "big"
    order = "<" if endian == "little" else ">"
    (e_type,) = struct.unpack_from(f"{order}H", data, 16)
    (e_machine,) = struct.unpack_from(f"{order}H", data, 18)
    return _obs(
        "elf",
        bitness=bitness,
        endianness=endian,
        type=_ELF_TYPE.get(e_type, str(e_type)),
        arch=_ELF_MACHINE.get(e_machine, hex(e_machine)),
    )


def _pe(data: bytes) -> list[Observation]:
    if len(data) < 0x40:  # noqa: PLR2004 -- need the e_lfanew pointer
        return _obs("pe")
    (offset,) = struct.unpack_from("<I", data, 0x3C)
    if offset + 8 > len(data) or data[offset : offset + 4] != b"PE\x00\x00":
        return _obs("pe")
    (machine,) = struct.unpack_from("<H", data, offset + 4)
    (sections,) = struct.unpack_from("<H", data, offset + 6)
    return _obs(
        "pe",
        arch=_PE_MACHINE.get(machine, hex(machine)),
        sections=str(sections),
    )


def _macho(magic: int) -> list[Observation]:
    bitness, swapped = _MACHO_MAGICS[magic]
    return _obs("mach-o", bitness=bitness, byte_swapped=str(swapped))


def analyze(path: Path) -> list[Observation]:
    """Return one structured observation for an ELF/PE/Mach-O header, else nothing."""
    try:
        with path.open("rb") as fh:
            data = fh.read(_HEADER_BYTES)
    except OSError:
        return []
    if data[:4] == b"\x7fELF":
        return _elf(data)
    if data[:2] == b"MZ":
        return _pe(data)
    if len(data) >= 4:  # noqa: PLR2004 -- a 4-byte Mach-O magic
        (magic,) = struct.unpack_from(">I", data, 0)
        if magic in _MACHO_MAGICS:
            return _macho(magic)
        if magic in (0xCAFEBABE, 0xBEBAFECA):  # a fat (universal) Mach-O
            return _obs("mach-o", universal="true")
    return []
