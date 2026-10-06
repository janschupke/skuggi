"""L3: the `cmd` cheatsheet verb over the wrapped-shell daemon.

Split from test_daemon.py to stay under the file-size cap: the cheatsheet's
scope resolution, listing, search and match-highlighting are one cohesive
concern, exercised here without a real socket.
"""

from __future__ import annotations

from skuggi.engagement.runtime_env import EngagementEnv
from skuggi.frontend.daemon import Daemon
from skuggi.tooling.commands import CommandAlias, CommandRegistry
from tests.harness.conftest import chunks


def test_cmd_resolve_in_scope(daemon: Daemon) -> None:
    daemon.core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-network", argv=("nmap", "-sn")),)
    )
    out = chunks(daemon, {"op": "input", "text": "cmd nmap-network"})
    assert "$ nmap -sn ${target}" in out  # rendered command, literal placeholder
    assert "scope" in out


def test_cmd_resolve_out_of_scope(daemon: Daemon) -> None:
    daemon.core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-host", argv=("nmap", "-sV", "-sC")),)
    )
    assert daemon.core.engagement is not None
    daemon.core.engagement = daemon.core.engagement.model_copy(
        update={"allowed_hosts": frozenset(), "target_networks": ()}
    )
    # A manual env target outside the (now empty) scope -> out of scope.
    daemon.core.engagement_mgr.apply_env(EngagementEnv(target="8.8.8.8"))
    out = chunks(daemon, {"op": "input", "text": "cmd nmap-host"})
    assert "$ nmap -sV -sC ${target}" in out
    assert "OUT OF SCOPE" in out


def test_cmd_list_search_and_miss(daemon: Daemon) -> None:
    assert "no command aliases" in chunks(daemon, {"op": "input", "text": "cmd"})
    daemon.core.commands = CommandRegistry(
        commands=(CommandAlias(name="nmap-host", argv=("nmap", "-sV")),)
    )
    assert "nmap-host" in chunks(daemon, {"op": "input", "text": "cmd nmap"})
    assert "no cheatsheet entry matches" in chunks(
        daemon, {"op": "input", "text": "cmd bogus"}
    )


def _raw(daemon: Daemon, msg: dict[str, object]) -> str:
    """Like `chunks`, but WITHOUT stripping SGR -- so highlighting is visible."""
    return "".join(str(r.get("chunk", "")) for r in daemon.handle_request(msg))


_REVERSE = "\x1b[7m"  # the SGR introducer Rich emits for the `reverse` match style


def test_cmd_search_highlights_the_matched_substring(daemon: Daemon) -> None:
    daemon.core.commands = CommandRegistry(
        commands=(
            CommandAlias(name="nmap-host", argv=("nmap", "-sV"), description="scan it"),
            CommandAlias(name="web-dir", argv=("curl",), description="d"),
        )
    )
    out = _raw(daemon, {"op": "input", "text": "cmd nmap"})
    # the query is reverse-video, and the full name survives (compact = name + desc)
    assert _REVERSE in out
    assert f"{_REVERSE}nmap" in out
    assert "nmap-host" in chunks(daemon, {"op": "input", "text": "cmd nmap"})
    assert "scan it" in out  # the description rides the compact entry
    assert "${target}" not in out  # the rendered command is a `-v` detail only
    # the listing stays filtered to the hit
    assert "web-dir" not in out
    # `-v` adds the rendered command between the name and the description
    verbose = _raw(daemon, {"op": "input", "text": "cmd -v nmap"})
    assert "${target}" in verbose


def test_cmd_list_has_nothing_to_highlight(daemon: Daemon) -> None:
    daemon.core.commands = CommandRegistry(
        commands=(
            CommandAlias(name="nmap-host", argv=("nmap", "-sV"), description="d"),
        )
    )
    out = _raw(daemon, {"op": "input", "text": "cmd list"})
    assert _REVERSE not in out  # blank query -> no match style
    # alignment/content preserved (ANSI-stripped)
    assert "nmap-host" in chunks(daemon, {"op": "input", "text": "cmd list"})
