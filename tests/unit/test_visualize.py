"""L1: the engagement HTML dashboard -- view model, log windowing, rendering."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from skuggi.common import home
from skuggi.common.execution import CommandResult
from skuggi.persistence.ledger import Ledger, open_ledger
from skuggi.persistence.visualize import (
    collect_engagement,
    main,
    render_html,
    write_visualization,
)
from skuggi.tooling.registry import ToolRegistry, ToolSpec

_BASE = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
_REGISTRY = ToolRegistry(
    tools=(
        ToolSpec(name="nmap", binary="nmap", method="scan"),
        ToolSpec(name="gobuster", binary="gobuster", method="enumerate"),
    )
)


def _seed(led: Ledger) -> None:
    led.start_session("s1", engagement_name="acme ext", mode="pentest")
    eid = led.record_event(
        session_id="s1", thread_id="t1", kind="prompt", text="scan it"
    )
    led.record_event(session_id="s1", thread_id="t1", kind="response", text="on it")
    # Two executed nmap runs, 5 minutes apart -> a real gap; one gobuster failure.
    led.record_command(
        session_id="s1",
        thread_id="t1",
        command="nmap 10.0.0.5",
        binary="nmap",
        method="scan",
        status="executed",
        result=CommandResult(
            "nmap 10.0.0.5", 0, "22/tcp open", "", _BASE, _BASE + timedelta(seconds=30)
        ),
        turn_event_id=eid,
    )
    led.record_command(
        session_id="s1",
        thread_id="t1",
        command="nmap -sV 10.0.0.5",
        binary="nmap",
        method="scan",
        status="executed",
        result=CommandResult(
            "nmap -sV 10.0.0.5",
            0,
            "ssh OpenSSH",
            "",
            _BASE + timedelta(seconds=300),
            _BASE + timedelta(seconds=330),
        ),
    )
    led.record_command(
        session_id="s1",
        thread_id="t1",
        command="gobuster dir -u http://10.0.0.5",
        binary="gobuster",
        method="enumerate",
        status="executed",
        result=CommandResult(
            "gobuster",
            1,
            "",
            "connection refused",
            _BASE + timedelta(seconds=340),
            _BASE + timedelta(seconds=341),
        ),
    )
    # A second session proves the engagement-level union across sessions.
    led.start_session("s2", engagement_name="acme ext", mode="pentest")
    led.record_finding(
        session_id="s2",
        title="SSH exposed",
        severity="high",
        description="Port 22 open to the internet",
        evidence="22/tcp open",
    )


def _log_text() -> str:
    """A log with one in-window line (+ a traceback continuation) and one outside."""
    local_tz = datetime.now().astimezone().tzinfo
    inside = (
        (_BASE + timedelta(seconds=100))
        .astimezone(local_tz)
        .strftime("%Y-%m-%d %H:%M:%S")
    )
    outside = (
        (_BASE - timedelta(hours=2)).astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S")
    )
    return (
        f"{outside},000 INFO skuggi.boot: starting up\n"
        f"{inside},123 ERROR skuggi.agent.core: provider failed\n"
        "Traceback (most recent call last):\n"
        "  File 'core.py', line 1, in turn\n"
    )


def _collect(led: Ledger) -> dict[str, Any]:
    return collect_engagement(
        led,
        engagement=None,
        registry=_REGISTRY,
        notes_text=f"- `{_BASE.isoformat()}`  looks juicy\n",
        loot_text=f"- `{_BASE.isoformat()}`  admin:hunter2\n",
        log_text=_log_text(),
    )


def test_counts_and_union_across_sessions(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        _seed(led)
        vm = _collect(led)
    assert vm["counts"] == {
        "sessions": 2,
        "commands": 3,
        "findings": 1,
        "notes": 1,
        "loot": 1,
    }
    # The conversation panel carries the prompt/response text, kept separate.
    kinds = [(t["kind"], t["text"]) for t in vm["conversation"]]
    assert kinds == [("prompt", "scan it"), ("response", "on it")]


def test_durations_and_gaps_are_derived(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        _seed(led)
        vm = _collect(led)
    cmds = [e for e in vm["timeline"] if e["type"] == "command"]
    assert cmds[0]["duration_s"] == 30.0
    assert cmds[0]["gap_before_s"] is None  # first command
    # second nmap: started 300s after base, previous finished at base+30 -> 270s gap
    assert cmds[1]["gap_before_s"] == 270.0


def test_usage_counts_aggregate_by_binary(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        _seed(led)
        vm = _collect(led)
    usage = {u["binary"]: u for u in vm["tools"]["usage"]}
    assert usage["nmap"]["count"] == 2
    assert usage["nmap"]["executed"] == 2
    assert usage["gobuster"]["count"] == 1
    assert usage["gobuster"]["failed"] == 1  # exit 1 on an executed command
    assert usage["gobuster"]["method"] == "enumerate"


def test_journals_parse_into_timeline(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        _seed(led)
        vm = _collect(led)
    note = next(e for e in vm["timeline"] if e["type"] == "note")
    loot = next(e for e in vm["timeline"] if e["type"] == "loot")
    assert note["text"] == "looks juicy"
    assert loot["text"] == "admin:hunter2"


def test_log_is_windowed_and_continuations_attach(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        _seed(led)
        vm = _collect(led)
    entries = vm["log_entries"]
    assert len(entries) == 1  # the pre-engagement INFO line is excluded
    assert entries[0]["level"] == "ERROR"
    assert "provider failed" in entries[0]["message"]
    assert "Traceback" in entries[0]["message"]  # continuation line attached


def test_render_escapes_script_breakout() -> None:
    html = render_html({"payload": "</script><b>pwned"})
    assert "\\u003c/script\\u003e" in html  # < and > both escaped (S8)
    assert "</script><b>pwned" not in html  # the raw breakout never survives


def test_write_visualization_creates_html(tmp_path: Path) -> None:
    out = tmp_path / "reports"
    with open_ledger(tmp_path / "l.db") as led:
        _seed(led)
        path = write_visualization(
            led,
            out,
            engagement=None,
            registry=_REGISTRY,
            engagement_name="acme ext",
        )
    assert path.parent == out
    assert path.suffix == ".html"
    text = path.read_text(encoding="utf-8")
    assert "skuggi engagement" in text
    assert "__SKUGGI_DATA__" not in text  # the sentinel was replaced
    assert "22/tcp open" in text


def _redirect_homes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(home.CONFIG_HOME_ENV, str(tmp_path / "config-home"))
    monkeypatch.setenv(home.DATA_HOME_ENV, str(tmp_path / "data-home"))


def test_main_writes_for_an_engagement_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _redirect_homes(monkeypatch, tmp_path)
    root = tmp_path / "acme"
    root.mkdir(parents=True)
    out = tmp_path / "out"
    rc = main([str(root), "-o", str(out)])
    assert rc == 0
    assert list(out.glob("acme-*.html"))  # named from the root dir when no scope


def test_main_rejects_a_missing_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _redirect_homes(monkeypatch, tmp_path)
    rc = main([str(tmp_path / "ghost")])  # no such directory
    assert rc == 2


# --- S6/S8: no secret bleed into the dashboard; the JSON blob cannot break out


def test_collect_redacts_known_secret_and_auth_header(tmp_path: Path) -> None:
    secret = "sk-ant-verysecretvalue123"
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="acme", mode="pentest")
        eid = led.record_event(
            session_id="s1", thread_id="t1", kind="prompt", text="go"
        )
        led.record_command(
            session_id="s1",
            thread_id="t1",
            command="curl -v https://api",
            binary="curl",
            method="recon",
            status="executed",
            result=CommandResult(
                "curl -v https://api",
                0,
                f"> Authorization: Bearer {secret}\n< HTTP/1.1 200 OK",
                "",
                _BASE,
                _BASE,
            ),
            turn_event_id=eid,
        )
        vm = collect_engagement(
            led, engagement=None, registry=_REGISTRY, secrets=frozenset({secret})
        )
    blob = render_html(vm)
    assert secret not in blob
    assert "***REDACTED***" in blob


def test_render_html_escapes_a_script_breakout() -> None:
    model = {"x": "</script><img src=x onerror=alert(1)>", "y": "a & b"}
    out = render_html(model)
    assert "</script><img" not in out
    assert "\\u003c" in out
    assert "\\u003e" in out
    assert "\\u0026" in out
