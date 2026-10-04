"""L3: the wrapped-shell daemon's persistent attach session (no real socket).

The attach-session tests split from ``test_daemon`` (verb dispatch), mirroring the
daemon <-> attach split in the code; both share the ``daemon`` fixture and the
response helpers from ``tests/harness/conftest.py``.
"""

from __future__ import annotations

import pytest

from skuggi.frontend.daemon import Daemon
from skuggi.tooling.registry import InstallPlan
from tests.harness.conftest import chunks


def test_attach_routes_multiple_lines_over_one_session(daemon: Daemon) -> None:
    """One attach session dispatches successive lines against the warm core."""
    lines = iter(["/show findings", "ask what is exposed?", "exit"])
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(lines, None), emitted.append)
    text = "".join(str(f.get("chunk", "")) for f in emitted)
    assert "no findings" in text  # first line routed as a control
    assert "the answer" in text  # second line reached the agent
    assert emitted[-1] == {"end": True, "exit": True}  # `exit` closed the session


def test_attach_stops_when_client_disconnects(daemon: Daemon) -> None:
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: None, emitted.append)  # immediate EOF
    # The loop emits the one "your turn" handshake frame, then the client
    # disconnects before sending a line, so nothing else follows.
    assert len(emitted) == 1
    assert "prompt" in emitted[0]
    assert "ready" in emitted[0]


def test_attach_continues_after_a_non_exit_turn(daemon: Daemon) -> None:
    """A non-exit line ends its turn (`exit` False) but keeps the session open."""
    lines = iter(["/findings", None])
    ends = []
    daemon.run_attached(
        lambda: next(lines, None),
        lambda r: ends.append(r) if r.get("end") else None,
    )
    assert ends == [{"end": True, "exit": False}]  # session stayed open, then EOF


def test_engagement_setup_one_shot_guides_to_the_loop(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "engagement setup"})
    assert "interactive" in out  # one-shot cannot prompt; points at the loop


def test_cmd_add_one_shot_guides_to_the_loop(daemon: Daemon) -> None:
    out = chunks(daemon, {"op": "input", "text": "cmd add"})
    assert "interactive" in out  # the editor needs the attach loop


def test_attach_install_missing_prompts_and_can_cancel(
    daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`doctor install missing` round-trips a confirm; declining installs nothing."""
    plan = InstallPlan(
        argv=("brew", "install", "nmap"), target="host", installer="brew"
    )
    monkeypatch.setattr(
        daemon.core.doctor, "propose_installs", lambda: [("nmap", plan)]
    )
    installed: list[str] = []

    def _fake_install(binary: str) -> None:
        installed.append(binary)

    monkeypatch.setattr(daemon.core.doctor, "install", _fake_install)
    answers = iter(["doctor install missing", "no"])  # open the flow, decline
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(answers, None), emitted.append)
    assert any("choose" in f for f in emitted)  # the confirm menu reached the client
    assert installed == []  # declined -> no system write


def test_attach_cmd_editor_adds_an_alias(daemon: Daemon) -> None:
    answers = iter(
        [
            "cmd add",
            "scan-sweep",  # name
            "nmap -sn",  # command template
            "",  # description
            "",  # tool -> argv[0]
            "",  # label -> name sans prefix
            "",  # output_dir -> tool default
            "",  # output_flag -> tool default
            "",  # output -> keep default (True)
        ]
    )
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(answers, None), emitted.append)
    asks = [f["ask"] for f in emitted if "ask" in f]
    assert len(asks) == 8  # one prompt per alias field over the socket
    alias = daemon.core.commands.alias_for("scan-sweep")
    assert alias is not None  # hot-loaded into the warm core
    assert alias.argv == ("nmap", "-sn")
    assert "saved alias 'scan-sweep'" in "".join(
        str(f.get("chunk", "")) for f in emitted
    )


def test_attach_engagement_wizard_creates_and_hot_loads(daemon: Daemon) -> None:
    answers = iter(
        [
            "engagement setup",
            "acme",  # name (ask)
            "UTC",  # timezone (ask -- autocomplete degrades over the socket)
            "2026-01-01T00:00:00+00:00",  # authorized_start
            "2026-12-31T23:59:59+00:00",  # authorized_end
            "",  # daily windows -> any
            "10.0.0.0/24",  # target networks
            "",  # hosts
            "nmap",  # allowed tools
            '["scan"]',  # allowed methods (multiselect -> JSON list)
            "ptes",  # methodology (choose)
            '["wstg"]',  # taxonomies (multiselect)
            "cautious",  # stance (choose)
            "no",  # autonomous (confirm -> yes/no choose)
            "active",  # autonomous_ceiling (choose)
            "no",  # threat model: decline CVSS environmental scoring
        ]
    )
    emitted: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(answers, None), emitted.append)
    asks = [f["ask"] for f in emitted if "ask" in f]
    assert len(asks) == 8  # the text + (degraded) autocomplete fields
    assert any("multiselect" in f for f in emitted)  # the checklists
    assert any("choose" in f for f in emitted)  # methodology/stance/confirm
    assert daemon.core.engagement is not None
    assert daemon.core.engagement.name == "acme"  # hot-loaded into the warm core
    assert daemon.core.engagement.allowed_methods == frozenset({"scan"})
    assert "loaded" in "".join(str(f.get("chunk", "")) for f in emitted)
