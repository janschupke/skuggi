"""L1: the packet-capture analyzer -- classic pcap + pcapng, dpkt enrichment (F2)."""

from __future__ import annotations

import socket
import struct
from pathlib import Path

import pytest

from skuggi.forensics.analyzers import pcap


def _classic_pcap(records: list[bytes], linktype: int = 1) -> bytes:
    """A little-endian microsecond pcap: global header + raw record payloads."""
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    body = b""
    for i, payload in enumerate(records):
        body += struct.pack("<IIII", 1_700_000_000 + i, 0, len(payload), len(payload))
        body += payload
    return hdr + body


def test_classic_pcap_structural_summary(tmp_path: Path) -> None:
    p = tmp_path / "cap.pcap"
    p.write_bytes(_classic_pcap([b"\x00" * 40, b"\x11" * 60]))
    obs = pcap.analyze(p)
    summary = next(o for o in obs if o.kind == "pcap")
    assert summary.attributes["format"] == "pcap"
    assert summary.attributes["packets"] == "2"
    assert summary.attributes["captured_bytes"] == "100"
    assert summary.attributes["linktype"] == "1"
    assert "capture_start" in summary.attributes


def test_classic_pcap_dpkt_enrichment_reports_talkers(tmp_path: Path) -> None:
    dpkt = pytest.importorskip("dpkt")
    frames = []
    for dst in ("10.0.0.2", "10.0.0.3"):
        ip = dpkt.ip.IP(
            src=socket.inet_aton("10.0.0.1"),
            dst=socket.inet_aton(dst),
            p=dpkt.ip.IP_PROTO_TCP,
            data=dpkt.tcp.TCP(sport=1234, dport=80),
        )
        eth = dpkt.ethernet.Ethernet(
            src=b"\x00" * 6, dst=b"\xff" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip
        )
        frames.append(bytes(eth))
    p = tmp_path / "cap.pcap"
    p.write_bytes(_classic_pcap(frames))
    obs = pcap.analyze(p)
    proto = next(o for o in obs if o.kind == "pcap-protocols")
    assert "TCP" in proto.value
    assert "10.0.0.1" in proto.attributes["top_talkers"]


def test_pcapng_block_walk_counts_packets(tmp_path: Path) -> None:
    shb = struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack(
        "<I", 28
    )
    idb = struct.pack("<IIHHI", 0x00000001, 20, 1, 0, 65535) + struct.pack("<I", 20)
    epb = struct.pack("<IIIIIII", 0x00000006, 32, 0, 0, 0, 0, 0) + struct.pack("<I", 32)
    p = tmp_path / "cap.pcapng"
    p.write_bytes(shb + idb + epb + epb)
    [summary] = [o for o in pcap.analyze(p) if o.kind == "pcap"]
    assert summary.attributes["format"] == "pcapng"
    assert summary.attributes["packets"] == "2"
    assert summary.attributes["interfaces"] == "1"
    assert summary.attributes["linktypes"] == "1"


def test_not_a_capture_yields_nothing(tmp_path: Path) -> None:
    p = tmp_path / "plain.bin"
    p.write_bytes(b"not a capture at all")
    assert pcap.analyze(p) == []
