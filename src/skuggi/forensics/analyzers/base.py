"""Shared types + bounded IO for the forensic analyzers.

An ``Observation`` is one datum an analyzer extracted, shaped so the loop can wrap
it into an ``intel.IntelItem`` without the analyzers depending on the intel schema
(they stay pure leaves, trivially unit-testable). Every analyzer reads through
``read_capped`` so a multi-gigabyte artifact is examined only up to a fixed cap --
the forensic analogue of ``common.execution``'s 256 KiB capture limit.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

# Analyzers that materialise bytes in memory (strings/hex/entropy/encoding) read at
# most this much; a cap note is attached so a truncated read is never silent.
MAX_READ_BYTES = 8 * 1024 * 1024
# Hashing streams the whole file in these chunks (no full-file buffer needed).
_HASH_CHUNK = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Observation:
    """One extracted datum: a kind, a value, and free-form string attributes."""

    kind: str
    value: str
    attributes: dict[str, str] = field(default_factory=dict)


def read_capped(path: Path, *, limit: int = MAX_READ_BYTES) -> tuple[bytes, bool]:
    """Read up to `limit` bytes of `path`; return ``(data, truncated)``.

    ``truncated`` is True when the file is larger than `limit`, so a caller can
    note that its analysis covered only a prefix.
    """
    with path.open("rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        return data[:limit], True
    return data, False


def sha256_of(path: Path) -> tuple[str, int]:
    """Stream `path` and return ``(sha256_hexdigest, size_in_bytes)``.

    Streamed in chunks so the integrity pin never needs the whole file in memory,
    and it always covers the ENTIRE file (unlike the capped analysis reads).
    """
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(_HASH_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size
