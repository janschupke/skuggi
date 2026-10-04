"""Shannon entropy -- overall and per-block -- to flag packed/encrypted regions.

High, flat entropy (close to 8.0 bits/byte) across a region is the classic signal
of compression or encryption; a report can point at the offending blocks. Pure
arithmetic over the capped read, no model judgement.
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from skuggi.forensics.analyzers.base import Observation, read_capped

_BLOCK = 4096
# Bits/byte at or above which a block is flagged as likely compressed/encrypted.
_HIGH = 7.5


def shannon(data: bytes) -> float:
    """Shannon entropy of `data` in bits/byte (0.0 for empty input)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def analyze(path: Path) -> list[Observation]:
    """Overall entropy plus a flag for each high-entropy block, with its offset."""
    data, truncated = read_capped(path)
    overall = shannon(data)
    out = [
        Observation(
            kind="entropy",
            value=f"{overall:.3f}",
            attributes={
                "scope": "overall",
                "bytes": str(len(data)),
                "read_truncated": str(truncated),
                "high": str(overall >= _HIGH),
            },
        )
    ]
    for off in range(0, len(data), _BLOCK):
        block = data[off : off + _BLOCK]
        if len(block) < _BLOCK:
            break  # a short trailing block skews the signal; ignore it
        e = shannon(block)
        if e >= _HIGH:
            out.append(
                Observation(
                    kind="entropy",
                    value=f"{e:.3f}",
                    attributes={"scope": "block", "offset": hex(off), "high": "True"},
                )
            )
    return out
