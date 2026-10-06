"""L1: the shared IP/CIDR scope primitives -- deny-by-default on any bad input."""

from __future__ import annotations

import ipaddress

import pytest

from skuggi.common.netscope import in_cidr, is_ip


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("10.0.0.1", True),
        ("::1", True),
        ("2001:db8::1", True),
        ("example.com", False),
        ("10.0.0.0/24", False),  # a network is not a bare address
        ("", False),
        ("999.0.0.1", False),
        ("not an ip", False),
    ],
)
def test_is_ip(token: str, expected: bool) -> None:
    assert is_ip(token) is expected


def test_in_cidr_membership() -> None:
    assert in_cidr("10.0.0.5", "10.0.0.0/24") is True
    assert in_cidr("10.0.1.5", "10.0.0.0/24") is False


def test_in_cidr_accepts_parsed_objects() -> None:
    addr = ipaddress.ip_address("10.0.0.5")
    net = ipaddress.ip_network("10.0.0.0/24")
    assert in_cidr(addr, net) is True
    assert in_cidr("10.0.0.5", net) is True
    assert in_cidr(addr, "10.0.0.0/24") is True


def test_in_cidr_cross_version_is_false_not_an_error() -> None:
    assert in_cidr("10.0.0.1", "::/0") is False
    assert in_cidr("::1", "10.0.0.0/8") is False


def test_in_cidr_denies_malformed_input() -> None:
    assert in_cidr("not-an-ip", "10.0.0.0/24") is False
    assert in_cidr("10.0.0.5", "not-a-cidr") is False
    assert in_cidr("", "") is False


def test_in_cidr_allows_host_bits_in_the_network() -> None:
    # non-strict parse: a CIDR carrying host bits (10.0.0.5/24) still works.
    assert in_cidr("10.0.0.9", "10.0.0.5/24") is True
