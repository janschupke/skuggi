"""Printable-string extraction (ASCII + UTF-16LE), each with its byte offset."""

from __future__ import annotations

from pathlib import Path

from skuggi.forensics.analyzers.base import Observation, read_capped

_DEFAULT_MIN_LEN = 4
# Keep the result bounded: a binary can hold tens of thousands of strings, and the
# model-facing capture is capped anyway. The loop/report shows the first slice.
_MAX_STRINGS = 500
_PRINTABLE = frozenset(range(0x20, 0x7F))


def _ascii_runs(data: bytes, min_len: int) -> list[tuple[int, str]]:
    """``(offset, text)`` for each run of >= `min_len` printable ASCII bytes."""
    out: list[tuple[int, str]] = []
    start = -1
    run: list[int] = []
    for i, byte in enumerate(data):
        if byte in _PRINTABLE:
            if not run:
                start = i
            run.append(byte)
            continue
        if len(run) >= min_len:
            out.append((start, bytes(run).decode("ascii")))
        run = []
    if len(run) >= min_len:
        out.append((start, bytes(run).decode("ascii")))
    return out


def _utf16le_runs(data: bytes, min_len: int) -> list[tuple[int, str]]:
    r"""``(offset, text)`` for printable-ASCII runs in UTF-16LE (``x\x00`` pairs)."""
    out: list[tuple[int, str]] = []
    start = -1
    run: list[int] = []
    for i in range(0, len(data) - 1, 2):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and lo in _PRINTABLE:
            if not run:
                start = i
            run.append(lo)
            continue
        if len(run) >= min_len:
            out.append((start, bytes(run).decode("ascii")))
        run = []
    if len(run) >= min_len:
        out.append((start, bytes(run).decode("ascii")))
    return out


def analyze(path: Path, *, min_len: int = _DEFAULT_MIN_LEN) -> list[Observation]:
    """Extract ASCII + UTF-16LE strings of at least `min_len` chars, with offsets."""
    data, truncated = read_capped(path)
    found = [(off, text, "ascii") for off, text in _ascii_runs(data, min_len)]
    found += [(off, text, "utf-16le") for off, text in _utf16le_runs(data, min_len)]
    found.sort(key=lambda t: t[0])
    observations = [
        Observation(
            kind="string",
            value=text,
            attributes={"offset": hex(off), "encoding": enc},
        )
        for off, text, enc in found[:_MAX_STRINGS]
    ]
    if truncated or len(found) > _MAX_STRINGS:
        observations.append(
            Observation(
                kind="note",
                value="string extraction truncated",
                attributes={
                    "read_truncated": str(truncated),
                    "shown": str(min(len(found), _MAX_STRINGS)),
                    "total": str(len(found)),
                },
            )
        )
    return observations
