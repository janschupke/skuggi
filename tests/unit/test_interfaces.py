"""L1: local interface enumeration for the `set listener` lhost picker."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from skuggi.common.execution import CommandResult
from skuggi.tooling.probe import Runner, local_interfaces, preferred_interface_index

_IP_OUTPUT = (
    "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
    "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\\   x\n"
    "3: tun0    inet 10.8.0.2/24 scope global tun0\\       valid_lft forever\n"
)

_IFCONFIG_OUTPUT = (
    "en0: flags=8863<UP> mtu 1500\n"
    "\tinet 192.168.0.25 netmask 0xffffff00 broadcast 192.168.0.255\n"
    "lo0: flags=8049<UP,LOOPBACK> mtu 16384\n"
    "\tinet 127.0.0.1 netmask 0xff000000\n"
    "utun4: flags=8051<UP,POINTOPOINT> mtu 1400\n"
    "\tinet 10.9.0.3 --> 10.9.0.3 netmask 0xffffff00\n"
)


def _runner_for(by_binary: Mapping[str, str]) -> Runner:
    def runner(
        argv: Sequence[str],
        *,
        timeout: float,
        cwd: Path,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        now = datetime.now(UTC)
        out = by_binary.get(argv[0])
        return CommandResult(
            command=" ".join(argv),
            exit_code=0 if out is not None else 127,
            stdout=out or "",
            stderr="",
            started_at=now,
            finished_at=now,
        )

    return runner


def test_parses_ip_output() -> None:
    pairs = local_interfaces(_runner_for({"ip": _IP_OUTPUT}))
    assert pairs == [
        ("lo", "127.0.0.1"),
        ("eth0", "192.168.1.10"),
        ("tun0", "10.8.0.2"),
    ]


def test_falls_back_to_ifconfig_when_ip_is_absent() -> None:
    pairs = local_interfaces(_runner_for({"ifconfig": _IFCONFIG_OUTPUT}))
    assert pairs == [
        ("en0", "192.168.0.25"),
        ("lo0", "127.0.0.1"),
        ("utun4", "10.9.0.3"),
    ]


def test_empty_when_neither_tool_is_available() -> None:
    assert local_interfaces(_runner_for({})) == []


def test_prefers_a_vpn_tunnel_interface_for_the_default() -> None:
    # tun0 is the third entry but the preferred default (reverse shells bind the VPN).
    pairs = local_interfaces(_runner_for({"ip": _IP_OUTPUT}))
    assert preferred_interface_index(pairs) == 2
    # With no tunnel, the first interface is the default.
    assert preferred_interface_index([("eth0", "192.168.1.10")]) == 0
