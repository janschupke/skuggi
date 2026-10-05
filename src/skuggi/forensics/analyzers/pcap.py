"""Structural summary of a packet capture (classic pcap and pcapng).

A dependency-light, streaming parser (audit F2): it reads the capture's headers
and walks the record/block framing by *seeking* over packet payloads, so a
multi-gigabyte capture is summarised without ever buffering it (the ``read_capped``
8 MiB cap would be wrong here -- a capture summary must see the whole file). It
reports the format, version, link type, packet count, captured bytes and -- for
classic pcap -- the capture time span. When ``dpkt`` is installed (the ``forensics``
extra) an Ethernet capture is additionally decoded over a bounded prefix to report
the top L3/L4 protocols and talkers; absent, the structural summary still stands.
Both magics (little/big endian, micro/nanosecond) are handled.
"""

from __future__ import annotations

import socket
import struct
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from skuggi.forensics.analyzers.base import Observation

# Classic pcap global-header magics -> (endianness struct prefix, ts divisor).
_CLASSIC_MAGICS: dict[bytes, tuple[str, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),  # microsecond, little-endian
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),  # microsecond, big-endian
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # nanosecond, little-endian
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # nanosecond, big-endian
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_LINKTYPE_ETHERNET = 1
# Enrichment (optional dpkt decode) reads at most this many packets -- bounded work.
_MAX_DECODE = 2000
# pcapng framing constants.
_SHB_PREFIX = 12  # block_type + block_total_length + byte_order_magic
_BLOCK_HEADER = 8  # block_type + block_total_length
_MIN_BLOCK = 12  # the smallest well-formed block
_IDB = 0x00000001  # Interface Description Block
_IDB_MIN_BODY = 2  # the 2-byte LinkType field at the body's start
_PACKET_BLOCK_TYPES = (0x00000006, 0x00000003, 0x00000002)  # EPB, SPB, obsolete Packet


def analyze(path: Path) -> list[Observation]:
    """Summarise the capture at `path`; empty list when it is not a pcap/pcapng."""
    with path.open("rb") as fh:
        head = fh.read(4)
    if head in _CLASSIC_MAGICS:
        return _classic(path, *_CLASSIC_MAGICS[head])
    if head == _PCAPNG_MAGIC:
        return _pcapng(path)
    return []


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


def _classic(path: Path, order: str, ts_div: int) -> list[Observation]:
    """Parse a classic pcap: global header + a seek-over-payloads record walk."""
    with path.open("rb") as fh:
        header = fh.read(24)
        if len(header) < 24:  # noqa: PLR2004 -- the fixed 24-byte global header
            return [Observation(kind="note", value="pcap: truncated global header")]
        major, minor = struct.unpack_from(f"{order}HH", header, 4)
        # global header: ... snaplen @16, network/linktype @20.
        snaplen, linktype = struct.unpack_from(f"{order}II", header, 16)
        packets = 0
        captured = 0
        first_ts = last_ts = None
        while rec := fh.read(16):
            if len(rec) < 16:  # noqa: PLR2004 -- the fixed 16-byte record header
                break
            ts_sec, ts_frac, incl_len, _orig = struct.unpack_from(
                f"{order}IIII", rec, 0
            )
            ts = ts_sec + ts_frac / ts_div
            first_ts = ts if first_ts is None else first_ts
            last_ts = ts
            packets += 1
            captured += incl_len
            fh.seek(incl_len, 1)
    attrs = {
        "format": "pcap",
        "version": f"{major}.{minor}",
        "linktype": str(linktype),
        "snaplen": str(snaplen),
        "packets": str(packets),
        "captured_bytes": str(captured),
    }
    if first_ts is not None and last_ts is not None:
        attrs["capture_start"] = _iso(first_ts)
        attrs["capture_end"] = _iso(last_ts)
    out = [
        Observation(
            kind="pcap", value=f"pcap capture, {packets} packets", attributes=attrs
        )
    ]
    if linktype == _LINKTYPE_ETHERNET:
        out.extend(_enrich(path, order))
    return out


def _pcapng(path: Path) -> list[Observation]:
    """Walk a pcapng section: count packet blocks, collect interface link types."""
    with path.open("rb") as fh:
        prefix = fh.read(_SHB_PREFIX)
        if len(prefix) < _SHB_PREFIX:
            return [Observation(kind="note", value="pcapng: truncated section header")]
        order = "<" if prefix[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
        (major, minor) = struct.unpack_from(f"{order}HH", fh.read(4), 0)
        fh.seek(0)
        packets = 0
        linktypes: list[int] = []
        while btype_raw := fh.read(_BLOCK_HEADER):
            if len(btype_raw) < _BLOCK_HEADER:
                break
            btype, total = struct.unpack_from(f"{order}II", btype_raw, 0)
            if total < _MIN_BLOCK:
                break
            body = fh.read(total - _SHB_PREFIX)
            fh.read(4)  # trailing block_total_length
            if btype == _IDB and len(body) >= _IDB_MIN_BODY:
                linktypes.append(struct.unpack_from(f"{order}H", body, 0)[0])
            elif btype in _PACKET_BLOCK_TYPES:
                packets += 1
    attrs = {
        "format": "pcapng",
        "version": f"{major}.{minor}",
        "packets": str(packets),
        "interfaces": str(len(linktypes)),
        "linktypes": ",".join(str(lt) for lt in linktypes) or "—",
    }
    return [
        Observation(
            kind="pcap", value=f"pcapng capture, {packets} packets", attributes=attrs
        )
    ]


def _enrich(path: Path, order: str) -> list[Observation]:
    """Optional dpkt decode of an Ethernet pcap: top protocols + talkers (bounded)."""
    try:
        import dpkt  # noqa: PLC0415 -- optional, the `forensics` extra
    except ImportError:
        return []
    protos: Counter[str] = Counter()
    talkers: Counter[str] = Counter()
    seen = 0
    with path.open("rb") as fh:
        fh.seek(24)  # past the global header
        while rec := fh.read(16):
            if len(rec) < 16 or seen >= _MAX_DECODE:  # noqa: PLR2004 -- record header
                break
            _ts, _tf, incl_len, _orig = struct.unpack_from(f"{order}IIII", rec, 0)
            buf = fh.read(incl_len)
            seen += 1
            _tally(dpkt, buf, protos, talkers)
    if not protos:
        return []
    top_proto = ", ".join(f"{p}:{n}" for p, n in protos.most_common(5))
    top_talk = ", ".join(f"{h}:{n}" for h, n in talkers.most_common(5))
    return [
        Observation(
            kind="pcap-protocols",
            value=top_proto,
            attributes={"decoded_packets": str(seen), "top_talkers": top_talk},
        )
    ]


def _tally(
    dpkt: object, buf: bytes, protos: Counter[str], talkers: Counter[str]
) -> None:
    """Decode one Ethernet frame best-effort, tallying L3/L4 protocol + src/dst."""
    try:
        eth = dpkt.ethernet.Ethernet(buf)  # type: ignore[attr-defined]
        ip = eth.data
        if isinstance(ip, dpkt.ip.IP):  # type: ignore[attr-defined]
            talkers[socket.inet_ntoa(ip.src)] += 1
            talkers[socket.inet_ntoa(ip.dst)] += 1
            protos[type(ip.data).__name__] += 1
        elif isinstance(ip, dpkt.ip6.IP6):  # type: ignore[attr-defined]
            protos["IP6"] += 1
        else:
            protos[type(ip).__name__] += 1
    except Exception:  # noqa: BLE001 -- a malformed frame is skipped, never fatal
        return
