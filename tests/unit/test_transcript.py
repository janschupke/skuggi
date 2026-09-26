"""L1: the session transcript renderer (replay), seeded from a real ledger."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from skuggi.execution import CommandResult
from skuggi.ledger import (
    CommandRow,
    EventRow,
    FindingRow,
    Ledger,
    SessionRow,
    open_ledger,
)
from skuggi.transcript import render_transcript

_Views = tuple[
    "SessionRow | None", list[EventRow], dict[int, CommandRow], dict[int, FindingRow]
]


def _views(led: Ledger, sid: str) -> _Views:
    session = led.session(sid)
    events = led.events_for(sid)
    commands = {c.id: c for c in led.commands_for(sid)}
    findings = {f.id: f for f in led.findings_for(sid)}
    return session, events, commands, findings


def test_render_orders_prompt_command_finding_response(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="acme", mode="pentest")
        prompt = led.record_event(
            session_id="s1", thread_id="t1", kind="prompt", text="scan the host"
        )
        now = datetime.now(UTC)
        cid = led.record_command(
            session_id="s1",
            thread_id="t1",
            command="nmap 10.0.0.5",
            binary="nmap",
            method="scan",
            status="executed",
            result=CommandResult("nmap 10.0.0.5", 0, "22/tcp open", "", now, now),
            turn_event_id=prompt,
        )
        led.record_finding(
            session_id="s1",
            title="ssh exposed",
            severity="medium",
            description="port 22 open",
            command_id=cid,
        )
        led.record_event(
            session_id="s1", thread_id="t1", kind="response", text="found ssh"
        )
        session, events, commands, findings = _views(led, "s1")

    out = render_transcript(session, events, commands, findings)  # type: ignore[arg-type]
    assert "scan the host" in out
    assert f"cmd:{cid}" in out
    assert "22/tcp open" in out  # captured output is replayed
    assert "ssh exposed" in out
    assert f"from cmd:{cid}" in out  # finding cites its command
    assert "found ssh" in out
    # ordering: prompt precedes command precedes finding precedes response
    assert (
        out.index("scan the host") < out.index(f"cmd:{cid}") < out.index("ssh exposed")
    )


def test_output_is_capped_for_review(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        now = datetime.now(UTC)
        led.record_command(
            session_id="s1",
            thread_id="t1",
            command="cat big",
            binary="cat",
            method=None,
            status="executed",
            result=CommandResult("cat big", 0, "A" * 5000, "", now, now),
        )
        session, events, commands, findings = _views(led, "s1")

    out = render_transcript(session, events, commands, findings, max_output=100)  # type: ignore[arg-type]
    assert "more chars]" in out
    assert "A" * 5000 not in out


def test_fallback_renders_a_pre_events_ledger(tmp_path: Path) -> None:
    """A session with commands/findings but no events still reconstructs."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        cid = led.record_command(
            session_id="s1",
            thread_id="t1",
            command="nmap 10.0.0.5",
            binary="nmap",
            method="scan",
            status="proposed",
        )
        led.record_finding(
            session_id="s1",
            title="open",
            severity="low",
            description="d",
            command_id=cid,
        )
        session = led.session("s1")
        commands = {c.id: c for c in led.commands_for("s1")}
        findings = {f.id: f for f in led.findings_for("s1")}

    # events omitted -> the timestamp-ordered fallback
    out = render_transcript(session, [], commands, findings)  # type: ignore[arg-type]
    assert f"cmd:{cid}" in out
    assert "open" in out


def test_empty_session_renders_a_placeholder(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        session, events, commands, findings = _views(led, "s1")
    out = render_transcript(session, events, commands, findings)  # type: ignore[arg-type]
    assert "No activity recorded" in out
