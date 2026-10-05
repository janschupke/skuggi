"""L1: Markdown report rendering and writing."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from weasyprint.urls import URLFetchingError

from skuggi.common.execution import CommandResult
from skuggi.engagement.engagement import EngagementConfig
from skuggi.persistence import pdf as pdf_mod
from skuggi.persistence.ledger import FindingRefInput, Ledger, open_ledger
from skuggi.persistence.pdf import _no_network_fetcher
from skuggi.persistence.reports import (
    _fenced,
    _local_stamp,
    append_changelog,
    render_report,
    write_report,
)


def _engagement(timezone: str = "Europe/Helsinki") -> EngagementConfig:
    return EngagementConfig.model_validate(
        {
            "name": "acme ext",
            "timezone": timezone,
            "authorized_start": datetime(2026, 1, 1, tzinfo=UTC),
            "authorized_end": datetime(2026, 12, 31, 23, 59, tzinfo=UTC),
            "allowed_hosts": frozenset({"scanme.example.com"}),
            "allowed_tools": frozenset({"nmap"}),
            "allowed_methods": frozenset({"scan"}),
        }
    )


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
    high = led.record_finding(
        session_id="s1",
        title="SSH exposed",
        severity="high",
        description="Port 22 open to the internet",
        evidence="22/tcp open",
        command_id=cid,
    )
    low = led.record_finding(
        session_id="s1",
        title="Banner leak",
        severity="low",
        description="Server banner reveals version",
        command_id=cid,
    )
    # A report shows only approved findings, so approve both for the content tests.
    led.set_finding_status(high, "approved")
    led.set_finding_status(low, "approved")


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


def test_local_stamp_converts_a_utc_string_to_the_engagement_zone() -> None:
    eng = _engagement("Europe/Helsinki")
    # Summer: Helsinki is EEST, UTC+3. 11:30Z -> 14:30 local.
    summer = _local_stamp("2026-07-01T11:30:00+00:00", eng)
    assert summer == "2026-07-01 14:30:00 EEST (+03:00)"
    # Winter: Helsinki is EET, UTC+2. 11:30Z -> 13:30 local.
    winter = _local_stamp("2026-01-15T11:30:00+00:00", eng)
    assert winter == "2026-01-15 13:30:00 EET (+02:00)"


def test_local_stamp_stays_utc_without_an_engagement() -> None:
    stamp = _local_stamp("2026-07-01T11:30:00+00:00", None)
    assert stamp == "2026-07-01 11:30:00 UTC (+00:00)"


def test_local_stamp_treats_a_naive_string_as_utc() -> None:
    # The ledger never writes a naive string; the display must still be total.
    stamp = _local_stamp("2026-07-01T11:30:00", None)
    assert stamp == "2026-07-01 11:30:00 UTC (+00:00)"


def test_report_renders_timestamps_in_the_engagement_timezone(tmp_path: Path) -> None:
    eng = _engagement("Europe/Helsinki")
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="acme ext", mode="pentest")
        moment = datetime(2026, 7, 1, 11, 30, tzinfo=UTC)
        result = CommandResult("nmap 10.0.0.5", 0, "open", "", moment, moment)
        led.record_command(
            session_id="s1",
            thread_id="t1",
            command="nmap 10.0.0.5",
            binary="nmap",
            method="scan",
            status="executed",
            result=result,
        )
        session = led.session("s1")
        assert session is not None
        report = render_report(
            session,
            led.commands_for("s1"),
            led.findings_for("s1"),
            engagement=eng,
            generated_label=_local_stamp("2026-07-01T12:00:00+00:00", eng),
        )
    assert "Times shown in: Europe/Helsinki" in report
    # The command-log "when" column is converted to Helsinki summer time.
    assert "2026-07-01 14:30:00 EEST (+03:00)" in report
    assert "Generated: 2026-07-01 15:00:00 EEST (+03:00)" in report


def test_write_report_shares_one_generated_stamp_with_the_pdf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The Markdown body and the PDF footer must carry the SAME generated-at label,
    # so a later re-render cannot drift. We capture what reaches markdown_to_pdf.
    captured: dict[str, object] = {}

    def _fake_pdf(md_text: str, out: Path, *, title: str, generated_label: str) -> Path:
        captured["label"] = generated_label
        captured["body"] = md_text
        out.write_bytes(b"%PDF-1.4 fake")
        return out

    monkeypatch.setattr(pdf_mod, "markdown_to_pdf", _fake_pdf)
    reports = tmp_path / "reports"
    eng = _engagement("Europe/Helsinki")
    with open_ledger(tmp_path / "l.db") as led:
        _seed(led)
        result = write_report("s1", led, reports, engagement=eng, pdf=True)
    assert isinstance(result, tuple)
    label = captured["label"]
    assert isinstance(label, str)
    # Footer label is "Generated <stamp>"; the body carries the same <stamp>.
    body = captured["body"]
    assert isinstance(body, str)
    assert label.startswith("Generated ")
    assert f"- Generated: {label.removeprefix('Generated ')}" in body


def test_write_report_without_a_session_raises(tmp_path: Path) -> None:
    with (
        open_ledger(tmp_path / "l.db") as led,
        pytest.raises(ValueError, match="no session"),
    ):
        write_report("missing", led, tmp_path / "reports")


def test_report_renders_cvss_and_linked_classifications(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="acme ext", mode="pentest")
        fid = led.record_finding(
            session_id="s1",
            title="Reflected XSS",
            description="unencoded reflection",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # 6.1
            refs=[FindingRefInput("wstg", "WSTG-CLNT-01", is_primary=True)],
        )
        led.set_finding_status(fid, "approved")
        result = write_report("s1", led, tmp_path / "reports")
    body = (result if isinstance(result, Path) else result[0]).read_text()
    assert "CVSS 3.1 6.1 (MEDIUM)" in body
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" in body
    # The classification is a Markdown link, primary marked with a star.
    assert "[WSTG-CLNT-01*](https://owasp.org/" in body


def test_report_excludes_non_approved_and_versions_revisions(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="acme ext", mode="pentest")
        keep = led.record_finding(
            session_id="s1", title="real", severity="high", description="d"
        )
        led.record_finding(
            session_id="s1", title="draft one", severity="low", description="d"
        )
        led.set_finding_status(keep, "approved")

        first = write_report("s1", led, reports_dir)
        assert isinstance(first, Path)
        body = first.read_text()
        assert "real" in body
        assert "draft one" not in body  # only approved reach the report
        assert "1 draft/rejected excluded" in body
        assert "Revision: 1" in body
        assert not first.with_suffix(".diff").exists()  # nothing to diff against yet

        # A second report is a new revision with a diff against the first.
        led.set_finding_status(
            led.record_finding(
                session_id="s1", title="added later", severity="medium", description="d"
            ),
            "approved",
        )
        second = write_report("s1", led, reports_dir)
        assert isinstance(second, Path)
        assert second != first
        body2 = second.read_text()
        assert "Revision: 2" in body2
        assert first.name in body2  # cites the previous report
        diff = second.with_suffix(".diff")
        assert diff.exists()
        assert "added later" in diff.read_text()


def test_report_changelog_note(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    path = append_changelog(reports_dir, "re-scoped after client call")
    assert path.name == "CHANGELOG.md"
    assert "re-scoped after client call" in path.read_text()
    # A subsequent report references the changelog in its header.
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="acme ext", mode="pentest")
        out = write_report("s1", led, reports_dir)
    assert isinstance(out, Path)
    assert "Changelog: `CHANGELOG.md`" in out.read_text()


def test_fenced_evidence_cannot_break_out_with_backticks() -> None:
    """Evidence containing a code-fence line must not escape its block (B4)."""
    evidence = "line one\n```\n# injected heading\n```\nline two"
    fenced = _fenced(evidence)
    opening = fenced.strip().splitlines()[0]
    assert len(opening) >= 4  # a fence longer than the inner ``` run
    assert opening.strip("`") == ""  # the fence is only backticks
    # the inner ``` is now shorter than the wrapping fence, so it cannot close it
    assert fenced.count(opening) == 2


def test_no_network_fetcher_refuses_http_and_file_but_serves_data() -> None:
    with pytest.raises(URLFetchingError, match="refusing to fetch"):
        _no_network_fetcher("http://attacker.example/leak.png")
    with pytest.raises(URLFetchingError, match="refusing to fetch"):
        _no_network_fetcher("file:///etc/passwd")
    served = _no_network_fetcher("data:text/plain;base64,aGk=")
    assert served["string"] == b"hi"


def test_report_renders_impact_remediation_affected_and_summary(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="acme ext", mode="pentest")
        fid = led.record_finding(
            session_id="s1",
            title="SQLi in login",
            severity="high",
            description="unparameterized query",
            impact="full database read",
            remediation="use parameterized queries",
            affected_host="10.0.0.5",
            affected_port="443",
            affected_url="/login",
            affected_param="user",
        )
        led.set_finding_status(fid, "approved")
        result = write_report("s1", led, tmp_path / "reports")
    body = (result if isinstance(result, Path) else result[0]).read_text()
    assert "**Impact:** full database read" in body
    assert "**Remediation:** use parameterized queries" in body
    assert "_Affected:_" in body
    assert "10.0.0.5:443" in body
    assert "/login" in body
    assert "parameter `user`" in body
    assert "## Summary" in body
    assert "| HIGH | 1 |" in body
    assert "Methodology & limitations" in body
