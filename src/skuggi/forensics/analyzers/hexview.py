"""A classic hexdump of the leading bytes of an evidence file.

Bounded to a prefix (``default_bytes``): a triage view of headers/magic/padding,
not a full dump of a large artifact. Each line is ``offset  hex  |ascii|``.
"""

from __future__ import annotations

from pathlib import Path

from skuggi.forensics.analyzers.base import Observation

_DEFAULT_BYTES = 256
_WIDTH = 16
_PRINTABLE_LO = 0x20
_PRINTABLE_HI = 0x7F


def _dump(data: bytes) -> str:
    lines: list[str] = []
    for off in range(0, len(data), _WIDTH):
        chunk = data[off : off + _WIDTH]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(_WIDTH * 3 - 1)
        ascii_part = "".join(
            chr(b) if _PRINTABLE_LO <= b < _PRINTABLE_HI else "." for b in chunk
        )
        lines.append(f"{off:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def analyze(path: Path, *, default_bytes: int = _DEFAULT_BYTES) -> list[Observation]:
    """A hexdump of the first `default_bytes` bytes of `path`."""
    with path.open("rb") as fh:
        data = fh.read(default_bytes)
    return [
        Observation(
            kind="hexdump",
            value=_dump(data),
            attributes={"bytes": str(len(data))},
        )
    ]
