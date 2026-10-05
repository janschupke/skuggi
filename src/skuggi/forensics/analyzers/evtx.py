"""Structured summary of a Windows event log (``ElfFile`` evtx header) -- audit F4.

Reads the evtx file header (the first 128 bytes), so file size is irrelevant: the
format version, chunk count, next-record identifier, and the dirty/full state flags
(a dirty log was not cleanly closed -- forensically relevant). When ``python-evtx``
is installed (the ``forensics`` extra, pure-Python) the records are additionally
iterated over a bounded prefix to report a record count and the event-time span;
absent -- or on a malformed/partial log -- the header summary still stands. For
rule-based evtx triage at scale the gated ``chainsaw`` tool is the heavier
alternative; this analyzer is the dependency-light inline view.
"""

from __future__ import annotations

import struct
from pathlib import Path

from skuggi.forensics.analyzers.base import Observation

_SIGNATURE = b"ElfFile\x00"
_MIN_HEADER = 128
_FLAG_DIRTY = 0x0001
_FLAG_FULL = 0x0002
# Enrichment iterates at most this many records -- bounded work on a large log.
_MAX_RECORDS = 5000


def analyze(path: Path) -> list[Observation]:
    """Summarise an evtx log at `path`; empty list when it is not an evtx file."""
    with path.open("rb") as fh:
        data = fh.read(_MIN_HEADER)
    if data[:8] != _SIGNATURE:
        return []
    if len(data) < _MIN_HEADER:
        return [Observation(kind="note", value="evtx: truncated file header")]
    _first, _last, next_record = struct.unpack_from("<QQQ", data, 8)
    _hdr_size, minor, major, _block, chunk_count = struct.unpack_from(
        "<IHHHH", data, 32
    )
    (flags,) = struct.unpack_from("<I", data, 120)
    state = "dirty" if flags & _FLAG_DIRTY else "clean"
    if flags & _FLAG_FULL:
        state += ", full"
    attrs = {
        "version": f"{major}.{minor}",
        "chunks": str(chunk_count),
        "next_record_id": str(next_record),
        "state": state,
    }
    out = [Observation(kind="evtx", value="Windows event log", attributes=attrs)]
    out.extend(_enrich(path))
    return out


def _enrich(path: Path) -> list[Observation]:
    """Iterate records (bounded) for a count + event-time span (best effort)."""
    try:
        from Evtx.Evtx import Evtx  # noqa: PLC0415 -- optional, `forensics` extra
    except ImportError:
        return []
    try:
        count = 0
        first_ts = last_ts = None
        with Evtx(str(path)) as log:
            for record in log.records():
                if count >= _MAX_RECORDS:
                    break
                ts = record.timestamp()
                first_ts = ts if first_ts is None else first_ts
                last_ts = ts
                count += 1
        if count == 0:
            return []
        attrs = {"records": str(count)}
        if first_ts is not None and last_ts is not None:
            attrs["event_start"] = first_ts.isoformat()
            attrs["event_end"] = last_ts.isoformat()
        return [
            Observation(kind="evtx-records", value=f"{count} events", attributes=attrs)
        ]
    except Exception:  # noqa: BLE001 -- a malformed/partial log: the header stands
        return []
