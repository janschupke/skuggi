"""Structured summary of a Windows registry hive (``regf`` base block) -- audit F3.

Reads only the hive's base-block header (the first bytes), so it is unaffected by
file size: the hive type, format version, the primary/secondary sequence numbers
(unequal => the hive was dirty / mid-transaction when captured -- a forensically
relevant state), the last-written timestamp, and the hive's own embedded path.
When ``python-registry`` is installed (the ``forensics`` extra, pure-Python) the
root key is additionally opened to report its name and immediate subkey/value
counts; absent -- or on a malformed/partial hive -- the header summary still
stands. Both paths degrade to a note rather than raising (runs under F0 anyway).
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

from skuggi.forensics.analyzers.base import Observation

_SIGNATURE = b"regf"
_MIN_HEADER = 48  # through the file-format field; the name follows at offset 48
_NAME_LEN = 64  # the UTF-16LE embedded hive path
_FILE_TYPES = {0: "primary", 1: "transaction-log", 2: "external"}
# FILETIME epoch: 100-nanosecond intervals since 1601-01-01 UTC.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _filetime(value: int) -> str:
    """A Windows FILETIME (100-ns ticks since 1601) as an ISO-8601 string, or ''."""
    if value <= 0:
        return ""
    try:
        return (_FILETIME_EPOCH + timedelta(microseconds=value / 10)).isoformat()
    except (OverflowError, OSError):
        return ""


def analyze(path: Path) -> list[Observation]:
    """Summarise a regf hive at `path`; empty list when it is not a registry hive."""
    with path.open("rb") as fh:
        data = fh.read(512)
    if data[:4] != _SIGNATURE:
        return []
    if len(data) < _MIN_HEADER:
        return [Observation(kind="note", value="registry: truncated base block")]
    seq_primary, seq_secondary = struct.unpack_from("<II", data, 4)
    (filetime,) = struct.unpack_from("<Q", data, 12)
    major, minor, file_type, _file_format = struct.unpack_from("<IIII", data, 20)
    name = data[48 : 48 + _NAME_LEN].decode("utf-16-le", "replace").split("\x00", 1)[0]
    attrs = {
        "version": f"{major}.{minor}",
        "sequence_primary": str(seq_primary),
        "sequence_secondary": str(seq_secondary),
        "state": "clean" if seq_primary == seq_secondary else "dirty (in-transaction)",
        "last_written": _filetime(filetime),
        "file_type": _FILE_TYPES.get(file_type, str(file_type)),
        "embedded_path": name,
    }
    out = [
        Observation(kind="registry", value="Windows registry hive", attributes=attrs)
    ]
    out.extend(_enrich(path))
    return out


def _enrich(path: Path) -> list[Observation]:
    """Open the hive's root key for its name + subkey/value counts (best effort)."""
    try:
        from Registry import Registry  # noqa: PLC0415 -- optional, `forensics` extra
    except ImportError:
        return []
    try:
        reg = Registry.Registry(str(path))
        root = reg.root()
        return [
            Observation(
                kind="registry-keys",
                value=root.name(),
                attributes={
                    "hive_name": reg.hive_name() or "",
                    "root_subkeys": str(root.subkeys_number()),
                    "root_values": str(root.values_number()),
                },
            )
        ]
    except Exception:  # noqa: BLE001 -- a malformed/partial hive: the header stands
        return []
