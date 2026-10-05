"""L1: the shared presenters -- one source of wording for both front-ends."""

from __future__ import annotations

from skuggi.agent.readiness import Readiness
from skuggi.frontend import outcomes, presenters
from skuggi.frontend.render import Styled, to_markup
from skuggi.persistence.ledger import CommandRow, FindingRow, ThreadSummary


def _texts(lines: Styled) -> list[str]:
    return [line.text for line in lines]


def _cmd(status: str) -> CommandRow:
    return CommandRow(
        id=1,
        session_id="s1",
        thread_id="t1",
        command="nmap 10.0.0.5",
        binary="nmap",
        method="scan",
        status=status,
        exit_code=0,
        stdout="",
        stderr="",
        reason="",
        started_at="2026-10-03T00:00:00+00:00",
        finished_at="2026-10-03T00:00:01+00:00",
        turn_event_id=None,
    )


def _finding(severity: str) -> FindingRow:
    return FindingRow(
        id=1,
        session_id="s1",
        command_id=None,
        title="t",
        severity=severity,
        description="d",
        evidence="",
        cvss_version=None,
        cvss_vector=None,
        cvss_base=None,
        cvss_temporal=None,
        cvss_environmental=None,
        cvss_score=None,
        cvss_severity=None,
        author="operator",
        status="approved",
        review_reason="",
        reviewed_at=None,
        cvss_tm_version=None,
        cvss_scored_at=None,
        impact="",
        remediation="",
        affected_host="",
        affected_port="",
        affected_url="",
        affected_param="",
        created_at="2026-10-03T00:00:00+00:00",
    )


def _stats(**over: object) -> outcomes.SessionStats:
    base: dict[str, object] = {
        "elapsed_s": None,
        "turns": 0,
        "commands": [],
        "findings": [],
        "notes": 0,
        "loot": 0,
    }
    base.update(over)
    return outcomes.SessionStats(**base)  # type: ignore[arg-type]


def test_present_provider_switched() -> None:
    lines = presenters.present_provider(
        outcomes.ProviderSwitched("ollama", "qwen3"), "repl"
    )
    assert _texts(lines) == ["switched to ollama/qwen3"]


def test_present_autonomous_keeps_the_scope_warning() -> None:
    [line] = presenters.present_autonomous(state=True)
    assert "EXECUTE within scope" in line.text
    assert line.style == "danger"


def _readiness(**over: object) -> Readiness:
    base: dict[str, object] = {
        "provider": "ollama",
        "model": "qwen3",
        "has_llm": True,
        "provider_configured": True,
        "engagement": "acme",
        "autonomous": False,
        "mode": "pentest",
        "warnings": (),
    }
    base.update(over)
    return Readiness(**base)  # type: ignore[arg-type]


def test_present_status_ready_vs_pending() -> None:
    ready = presenters.present_status(_readiness(), _stats(), "repl")
    assert any("mode pentest" in line.text for line in ready)
    assert _texts(ready)[-1] == "ready"  # quiet session: no stat block, "ready" stays

    pending = presenters.present_status(_readiness(engagement=None), _stats(), "repl")
    assert any("scope an engagement" in line.text for line in pending)
    assert "ready" not in _texts(pending)


def test_present_status_surfaces_config_drift() -> None:
    # Drift is off the passive banner but kept on the explicit `show status`.
    drifted = presenters.present_status(
        _readiness(stale_configs=("tools.json",)), _stats(), "repl"
    )
    assert any("behind the packaged" in line.text for line in drifted)
    assert "ready" not in _texts(drifted)


def test_present_status_shows_activity_stats_when_the_session_did_something() -> None:
    stats = _stats(
        elapsed_s=842,
        turns=7,
        commands=[_cmd("executed"), _cmd("blocked")],
        findings=[_finding("high"), _finding("high"), _finding("medium")],
        notes=2,
        loot=1,
    )
    lines = presenters.present_status(_readiness(), stats, "repl")
    texts = _texts(lines)
    assert "ready" not in texts  # the stat block takes the place of the sign-off
    assert any("ran for" in t and "14m 02s" in t for t in texts)
    assert any("turns" in t and "7" in t for t in texts)
    assert any(
        "commands  2" in t and "1 executed" in t and "1 blocked" in t for t in texts
    )
    assert any("notes 2 · loot 1" in t for t in texts)
    # The finding breakdown is painted per severity via spans.
    finding_line = next(ln for ln in lines if "findings  3" in ln.text)
    assert finding_line.spans is not None
    assert "2 high" in finding_line.text
    assert "1 medium" in finding_line.text
    markup = to_markup(finding_line)
    assert "2 high" in markup
    assert markup != finding_line.text  # colour applied


def test_present_sessions_empty_and_rows() -> None:
    assert _texts(presenters.present_sessions([])) == ["(no sessions yet)"]
    row = outcomes.SessionCount(
        session_id="abcdef1234",
        started_at="2026-10-03T10:00:00",
        mode="pentest",
        turns=2,
        commands=1,
        findings=0,
        current=True,
    )
    lines = presenters.present_sessions([row])
    assert any("turns" in ln.text for ln in lines)  # a legend heading precedes rows
    row_line = lines[-1]
    assert row_line.text.startswith("abcdef12")
    assert "2t 1c 0f" in row_line.text
    assert row_line.text.endswith("*")


def test_present_threads_snippet_and_marker() -> None:
    rows = [
        ThreadSummary(
            thread_id="abc12345-xyz",
            turns=3,
            first_prompt="enumerate the whole host " * 5,  # long -> truncated
            last_activity="2026-10-03T10:00:00",
        )
    ]
    lines = presenters.present_threads(rows, current="abc12345-xyz")
    row_line = lines[-1]
    assert row_line.text.startswith("abc12345")
    assert "…" in row_line.text  # snippet capped
    assert row_line.text.endswith("*")  # current marker
    assert _texts(presenters.present_threads([], current="x")) == ["(no threads yet)"]


def _column_start(line: str, marker: str) -> int:
    return line.index(marker)


def test_present_sessions_columns_align_across_rows() -> None:
    rows = [
        outcomes.SessionCount(
            session_id="aaaaaaaa1",
            started_at="2026-10-03T10:00:00+00:00",
            mode="recon",  # shorter than "pentest" -> must be padded
            turns=4,
            commands=0,
            findings=0,
            current=True,
        ),
        outcomes.SessionCount(
            session_id="bbbbbbbb2",
            started_at="2026-10-03T09:00:00+00:00",
            mode="pentest",
            turns=12,  # wider turn count -> others right-justify to match
            commands=2,
            findings=0,
            current=False,
        ),
    ]
    row_lines = [ln.text for ln in presenters.present_sessions(rows)[1:]]
    # The mode column (and everything after) starts at the same offset on every row.
    assert _column_start(row_lines[0], "recon") == _column_start(
        row_lines[1], "pentest"
    )
    # The count group starts at the same offset too.
    assert row_lines[0].index(" 4t") == row_lines[1].index("12t")
    assert not any(ln != ln.rstrip() for ln in row_lines)  # no trailing whitespace


def test_present_threads_columns_align_across_rows() -> None:
    rows = [
        ThreadSummary(
            thread_id="aaaaaaaa1",
            turns=3,
            first_prompt="scan the host",
            last_activity="2026-10-03T10:00:00+00:00",
        ),
        ThreadSummary(
            thread_id="bbbbbbbb2",
            turns=100,
            first_prompt="enumerate services",
            last_activity="2026-10-03T09:00:00+00:00",
        ),
    ]
    row_lines = [ln.text for ln in presenters.present_threads(rows, current="x")[1:]]
    # The turn counts right-justify so the last-activity column aligns across rows.
    assert row_lines[0].index("2026") == row_lines[1].index("2026")


def test_present_unknown_points_at_help() -> None:
    [line] = presenters.present_unknown("bogus", "shell")
    assert "unknown command" in line.text
    assert "/skuggi help" in line.text
