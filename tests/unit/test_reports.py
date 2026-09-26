"""L1: Markdown report rendering and writing."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from skuggi.execution import CommandResult
from skuggi.ledger import Ledger, open_ledger
from skuggi.reports import render_report, write_report


def _seed(led: Ledger) -> None:
    led.start_session("s1", engagement_name="acme ext", mode="pentest")
    now = datetime.now(UTC)
    result = CommandResult("nmap 10.0.0.5", 0, "22/tcp open", "", now, now)
    cid = led.record_command(
        session_id="s1",
        thread_id="t1",
        command="nmap 10.0.0.5",
        binary="nmap",
        method="scan",
        status="executed",
        result=result,
    )
    led.record_finding(
        session_id="s1",
        title="SSH exposed",
        severity="high",
        description="Port 22 open to the internet",
        evidence="22/tcp open",
        command_id=cid,
    )
    led.record_finding(
        session_id="s1",
        title="Banner leak",
        severity="low",
        description="Server banner reveals version",
        command_id=cid,
    )


def test_render_groups_findings_by_severity(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        _seed(led)
        session = led.session("s1")
        assert session is not None
        report = render_report(session, led.commands_for("s1"), led.findings_for("s1"))
    assert "# Engagement report: acme ext" in report
    # HIGH must be rendered before LOW.
    assert report.index("HIGH") < report.index("LOW")
    assert "22/tcp open" in report
    assert "nmap 10.0.0.5" in report


def test_write_report_creates_a_markdown_file(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    with open_ledger(tmp_path / "l.db") as led:
        _seed(led)
        path = write_report("s1", led, reports, engagement=None)
    assert isinstance(path, Path)  # md-only when pdf is not requested
    assert path.parent == reports
    assert path.suffix == ".md"
    assert "SSH exposed" in path.read_text(encoding="utf-8")


def test_write_report_without_a_session_raises(tmp_path: Path) -> None:
    with (
        open_ledger(tmp_path / "l.db") as led,
        pytest.raises(ValueError, match="no session"),
    ):
        write_report("missing", led, tmp_path / "reports")
