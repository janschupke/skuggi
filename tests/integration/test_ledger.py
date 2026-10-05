"""L2: the ledger against a real SQLite file, incl. FK linkage and reopen."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skuggi.common.execution import CommandResult
from skuggi.frameworks import cvss
from skuggi.persistence import ledger_schema
from skuggi.persistence.ledger import FindingRefInput, open_ledger


def test_command_and_finding_round_trip(tmp_path: Path) -> None:
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
        fid = led.record_finding(
            session_id="s1",
            title="open",
            severity="high",
            description="d",
            command_id=cid,
        )
        assert led.latest_command_id("s1") == cid
        [finding] = led.findings_for("s1")
        assert finding.id == fid
        assert finding.command_id == cid


def test_executed_command_stores_output(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        now = datetime.now(UTC)
        result = CommandResult("echo hi", 0, "hi\n", "", now, now)
        led.record_command(
            session_id="s1",
            thread_id="t1",
            command="echo hi",
            binary="echo",
            method="recon",
            status="executed",
            result=result,
        )
        row = led.commands_for("s1")[0]
        assert row.exit_code == 0
        assert row.stdout == "hi\n"
        assert row.finished_at is not None


def test_foreign_key_blocks_orphan_command(tmp_path: Path) -> None:
    """A command for a non-existent session must be rejected (FK enforced)."""
    with open_ledger(tmp_path / "l.db") as led, pytest.raises(sqlite3.IntegrityError):
        led.record_command(
            session_id="ghost",
            thread_id="t1",
            command="x",
            binary="x",
            method=None,
            status="proposed",
        )


def test_reopening_sees_persisted_rows(tmp_path: Path) -> None:
    db = tmp_path / "nested" / "l.db"
    with open_ledger(db) as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        led.record_command(
            session_id="s1",
            thread_id="t1",
            command="nmap 10.0.0.5",
            binary="nmap",
            method="scan",
            status="proposed",
        )
    assert db.is_file()
    with open_ledger(db) as led:
        assert led.session("s1") is not None
        assert len(led.commands_for("s1")) == 1


# --- timeline events + audit log --------------------------------------------


def test_command_and_finding_emit_timeline_events(tmp_path: Path) -> None:
    """Every command / finding write also lands on the ordered events spine."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        prompt = led.record_event(
            session_id="s1", thread_id="t1", kind="prompt", text="scan it"
        )
        cid = led.record_command(
            session_id="s1",
            thread_id="t1",
            command="nmap 10.0.0.5",
            binary="nmap",
            method="scan",
            status="proposed",
            turn_event_id=prompt,
        )
        led.record_finding(
            session_id="s1",
            title="open",
            severity="high",
            description="d",
            command_id=cid,
        )
        led.record_event(session_id="s1", thread_id="t1", kind="response", text="done")
        kinds = [(e.kind, e.ref_id) for e in led.events_for("s1")]
        assert kinds == [
            ("prompt", None),
            ("command", cid),
            ("finding", 1),
            ("response", None),
        ]
        # the command links back to the prompt that drove it
        assert led.commands_for("s1")[0].turn_event_id == prompt
        assert led.command(cid) is not None
        assert led.finding(1) is not None


def test_audit_log_is_separate_from_the_timeline(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        led.record_audit(
            session_id="s1", kind="control", verb="mode", detail="blueteam"
        )
        led.record_audit(session_id="s1", kind="review", detail="you rushed recon")
        rows = led.audit_for("s1")
        assert [(r.kind, r.verb) for r in rows] == [("control", "mode"), ("review", "")]
        assert led.events_for("s1") == []  # audit never touches the timeline


def test_sessions_lists_newest_first(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("old", engagement_name="e", mode="pentest")
        led.start_session("new", engagement_name="e", mode="pentest")
        ids = [s.session_id for s in led.sessions()]
        assert set(ids) == {"old", "new"}
        assert len(ids) == 2


def test_reopening_is_idempotent_after_migration(tmp_path: Path) -> None:
    """Opening a ledger twice must not fail re-adding the migrated column."""
    db = tmp_path / "l.db"
    with open_ledger(db) as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
    with open_ledger(db) as led:  # ADD COLUMN guard makes this a no-op
        assert led.session("s1") is not None


def test_migration_adds_turn_event_id_to_a_legacy_ledger(tmp_path: Path) -> None:
    """A ledger created before turn_event_id existed is upgraded in place."""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE sessions (
            session_id TEXT PRIMARY KEY, engagement_name TEXT NOT NULL,
            mode TEXT NOT NULL, started_at TEXT NOT NULL);
        CREATE TABLE commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL, thread_id TEXT NOT NULL, command TEXT NOT NULL,
            binary TEXT NOT NULL, method TEXT, status TEXT NOT NULL, exit_code INTEGER,
            stdout TEXT NOT NULL DEFAULT '', stderr TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL,
            finished_at TEXT);
        INSERT INTO sessions VALUES ('s1', 'e', 'pentest', '2026-01-01T00:00:00+00:00');
        """
    )
    conn.commit()
    conn.close()
    with open_ledger(db) as led:
        row = led.commands_for("s1")  # unpacking CommandRow needs the new column
        assert row == []
        cid = led.record_command(
            session_id="s1",
            thread_id="t1",
            command="x",
            binary="x",
            method=None,
            status="passthrough",
            turn_event_id=None,
        )
        assert led.commands_for("s1")[0].turn_event_id is None
        assert led.command(cid) is not None


def test_cvss_finding_stores_full_breakdown_and_refs(tmp_path: Path) -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # reflected XSS, 6.1
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        fid = led.record_finding(
            session_id="s1",
            title="Reflected XSS in /search",
            description="user input reflected unencoded",
            cvss_vector=vector,  # no severity passed -> derived from CVSS
            refs=[
                FindingRefInput("wstg", "WSTG-CLNT-01", is_primary=True),
                FindingRefInput("attack", "T1189"),
            ],
        )
        [finding] = led.findings_for("s1")
        assert finding.id == fid
        assert finding.severity == "medium"  # derived from the 6.1 band
        assert finding.cvss_version == "3.1"
        assert finding.cvss_base == 6.1
        assert finding.cvss_score == 6.1
        assert finding.cvss_severity == "medium"
        # Reproducible from the stored row alone -- no turn context.
        assert cvss.score(finding.cvss_vector).overall == finding.cvss_score  # type: ignore[arg-type]

        refs = led.finding_refs_for(fid)
        assert [(r.framework, r.ref_id, r.is_primary) for r in refs] == [
            ("wstg", "WSTG-CLNT-01", 1),  # primary first
            ("attack", "T1189", 0),
        ]
        wstg = refs[0]
        assert wstg.title  # resolved from the vendored taxonomy
        assert wstg.url.startswith("https://owasp.org/")


def test_finding_without_severity_or_vector_is_rejected(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        with pytest.raises(ValueError, match="severity or a cvss_vector"):
            led.record_finding(session_id="s1", title="x", description="d")


def test_migrates_a_pre_cvss_ledger(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE sessions (session_id TEXT PRIMARY KEY, engagement_name TEXT
            NOT NULL, mode TEXT NOT NULL, started_at TEXT NOT NULL);
        CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT
            NOT NULL, command_id INTEGER, title TEXT NOT NULL, severity TEXT NOT NULL,
            description TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL);
        INSERT INTO sessions VALUES ('s1', 'e', 'pentest', 't');
        INSERT INTO findings (session_id, title, severity, description, evidence,
            created_at) VALUES ('s1', 'old finding', 'low', 'd', '', 't');
        """
    )
    conn.commit()
    conn.close()

    # Opening it migrates in place: the old row reads back with NULL cvss fields,
    # and new CVSS findings + refs work against the upgraded DB.
    with open_ledger(path) as led:
        [old] = led.findings_for("s1")
        assert old.title == "old finding"
        assert old.severity == "low"
        assert old.cvss_vector is None
        assert old.cvss_score is None
        new = led.record_finding(
            session_id="s1",
            title="new",
            description="d",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        assert led.finding(new).cvss_score == 9.8  # type: ignore[union-attr]


def test_findings_are_born_draft_with_author_and_review_transitions(
    tmp_path: Path,
) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        agent_fid = led.record_finding(
            session_id="s1", title="agent one", severity="high", description="d"
        )
        op_fid = led.record_finding(
            session_id="s1",
            title="operator one",
            severity="low",
            description="d",
            author="operator",
        )
        a, o = led.finding(agent_fid), led.finding(op_fid)
        assert (a.author, a.status) == ("agent", "draft")  # type: ignore[union-attr]
        assert (o.author, o.status) == ("operator", "draft")  # type: ignore[union-attr]

        # Nothing approved yet -> reports would be empty.
        assert led.approved_findings_for("s1") == []

        led.set_finding_status(agent_fid, "approved")
        led.set_finding_status(op_fid, "rejected", reason="duplicate of F-1")
        approved = led.approved_findings_for("s1")
        assert [f.id for f in approved] == [agent_fid]
        rejected = led.finding(op_fid)
        assert rejected is not None
        assert rejected.status == "rejected"
        assert rejected.review_reason == "duplicate of F-1"
        assert rejected.reviewed_at is not None


def test_evidence_and_procedure_round_trip(tmp_path: Path) -> None:
    """Forensics evidence + procedure rows persist and read back in order."""
    with open_ledger(tmp_path / "case.db") as led:
        led.start_session("c1", engagement_name="case:demo", mode="forensics")
        eid = led.record_evidence(
            session_id="c1",
            source_path="evidence/a.bin",
            sha256="abc123",
            size=42,
            media_type="application/octet-stream",
            note="handed over",
        )
        led.record_procedure(
            session_id="c1",
            step=2,
            operation="strings",
            actor="tool",
            argv="strings evidence/a.bin",
            input_sha256="abc123",
            output_digest="out1",
        )
        led.record_procedure(
            session_id="c1",
            step=1,
            operation="hash",
            actor="in-process",
            input_sha256="abc123",
        )
    with open_ledger(tmp_path / "case.db") as led:
        ev = led.evidence_for("c1")
        assert [(e.id, e.source_path, e.sha256, e.size) for e in ev] == [
            (eid, "evidence/a.bin", "abc123", 42)
        ]
        # ordered by step, so the in-process hash (step 1) precedes the tool op
        procs = led.procedure_for("c1")
        assert [(p.step, p.operation, p.actor) for p in procs] == [
            (1, "hash", "in-process"),
            (2, "strings", "tool"),
        ]


def test_forensics_ledger_does_not_see_engagement_rows(tmp_path: Path) -> None:
    """A separate case ledger file never commingles with an engagement ledger."""
    with open_ledger(tmp_path / "ledger.db") as eng:
        eng.start_session("s1", engagement_name="e", mode="pentest")
        eng.record_finding(session_id="s1", title="t", severity="high", description="d")
    with open_ledger(tmp_path / "case.db") as case:
        case.start_session("c1", engagement_name="case:demo", mode="forensics")
        case.record_evidence(
            session_id="c1", source_path="evidence/a", sha256="z", size=1
        )
        assert case.findings_for("c1") == []
        assert len(case.evidence_for("c1")) == 1
    with open_ledger(tmp_path / "ledger.db") as eng:
        assert eng.evidence_for("s1") == []
        assert len(eng.findings_for("s1")) == 1


def test_severity_only_finding_needs_no_cvss(tmp_path: Path) -> None:
    """A forensic finding carries a plain severity and no CVSS vector."""
    with open_ledger(tmp_path / "case.db") as led:
        led.start_session("c1", engagement_name="case:demo", mode="forensics")
        fid = led.record_finding(
            session_id="c1",
            title="suspicious string at 0x20",
            severity="medium",
            description="embedded /bin/sh",
            evidence="offset 0x20",
        )
        row = led.finding(fid)
        assert row is not None
        assert row.severity == "medium"
        assert row.cvss_vector is None


def test_finding_stores_impact_remediation_affected_and_cve_ref(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        fid = led.record_finding(
            session_id="s1",
            title="Log4Shell",
            severity="critical",
            description="d",
            impact="RCE on the app server",
            remediation="upgrade log4j to 2.17+",
            affected_host="10.0.0.5",
            affected_port="8080",
            affected_url="/api",
            affected_param="q",
            refs=[FindingRefInput("cve", "CVE-2021-44228")],
        )
        [finding] = led.findings_for("s1")
        assert finding.impact == "RCE on the app server"
        assert finding.remediation == "upgrade log4j to 2.17+"
        assert finding.affected_host == "10.0.0.5"
        assert finding.affected_port == "8080"
        assert finding.affected_url == "/api"
        assert finding.affected_param == "q"
        [ref] = led.finding_refs_for(fid)
        assert ref.framework == "cve"
        assert ref.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"


def test_record_finding_rolls_back_on_a_mid_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure between the finding insert and its refs must leave no row (B10).

    record_finding writes the finding, then each ref, then the timeline event as
    one unit. If a ref write raises partway through, the whole unit must roll back
    so the ledger never holds a half-written finding without its refs.
    """
    calls = {"n": 0}
    real = ledger_schema._ref_display

    def flaky(framework: str, ref_id: str) -> tuple[str, str]:
        calls["n"] += 1
        if calls["n"] == 2:  # the second ref insert fails mid-unit
            msg = "boom"
            raise ValueError(msg)
        return real(framework, ref_id)

    monkeypatch.setattr("skuggi.persistence.ledger._ref_display", flaky)
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        with pytest.raises(ValueError, match="boom"):
            led.record_finding(
                session_id="s1",
                title="half-written",
                severity="high",
                description="d",
                refs=[
                    FindingRefInput("wstg", "WSTG-CLNT-01", is_primary=True),
                    FindingRefInput("attack", "T1189"),
                ],
            )
        assert led.findings_for("s1") == []  # fully rolled back, not half-written


def test_approved_findings_for_engagement_aggregates_and_dedupes(
    tmp_path: Path,
) -> None:
    """Approved findings join across an engagement's sessions, deduped (E5)."""
    with open_ledger(tmp_path / "l.db") as led:
        for sid in ("s1", "s2"):
            led.start_session(sid, engagement_name="acme", mode="pentest")
        # same issue proven in both sessions -> one row; a distinct one -> kept.
        for sid in ("s1", "s2"):
            dup = led.record_finding(
                session_id=sid,
                title="Weak TLS",
                severity="medium",
                description="d",
                affected_host="web01",
            )
            led.set_finding_status(dup, "approved")
        other = led.record_finding(
            session_id="s2",
            title="Open redirect",
            severity="low",
            description="d",
            affected_host="web02",
        )
        led.set_finding_status(other, "approved")
        # a draft in another session is excluded (not approved).
        led.record_finding(
            session_id="s1", title="Draft only", severity="low", description="d"
        )

        rolled = led.approved_findings_for_engagement("acme")
        titles = sorted(f.title for f in rolled)
        assert titles == ["Open redirect", "Weak TLS"]  # dup collapsed, draft excluded


def test_findings_for_engagement_spans_sessions_and_all_statuses(
    tmp_path: Path,
) -> None:
    """The model-facing recall spans every session and keeps all statuses.

    Unlike the report-facing aggregate, this feeds the agent's memory: a draft lead
    and a rejected finding from an earlier session must still surface (the brief
    renders their status), and a finding under a different engagement must not.
    """
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="acme", mode="pentest")
        led.start_session("s2", engagement_name="acme", mode="pentest")
        led.start_session("o1", engagement_name="other", mode="pentest")
        led.record_finding(
            session_id="s1", title="Open lead", severity="low", description="d"
        )
        rej = led.record_finding(
            session_id="s1", title="Not real", severity="info", description="d"
        )
        led.set_finding_status(rej, "rejected", reason="false positive")
        approved = led.record_finding(
            session_id="s2", title="Real bug", severity="high", description="d"
        )
        led.set_finding_status(approved, "approved")
        led.record_finding(
            session_id="o1", title="Elsewhere", severity="low", description="d"
        )

        rows = led.findings_for_engagement("acme")
        assert [f.title for f in rows] == ["Open lead", "Not real", "Real bug"]
        assert {f.title: f.status for f in rows} == {
            "Open lead": "draft",
            "Not real": "rejected",
            "Real bug": "approved",
        }


def test_credentials_for_engagement_spans_sessions_and_dedupes(
    tmp_path: Path,
) -> None:
    """Credential recall spans the engagement's sessions, deduped, others excluded."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="acme", mode="pentest")
        led.start_session("s2", engagement_name="acme", mode="pentest")
        led.start_session("o1", engagement_name="other", mode="pentest")
        # Same credential captured in both sessions -> one row.
        for sid in ("s1", "s2"):
            led.record_credential(
                session_id=sid,
                host="web01",
                service="ssh",
                username="admin",
                secret_ref="«CRED:aa11»",
            )
        led.record_credential(
            session_id="s2",
            host="db1",
            service="psql",
            username="root",
            secret_ref="«CRED:bb22»",
        )
        led.record_credential(
            session_id="o1", host="elsewhere", username="x", secret_ref="«CRED:cc33»"
        )

        rows = led.credentials_for_engagement("acme")
        assert sorted(c.host for c in rows) == ["db1", "web01"]


def test_loot_and_notes_for_engagement_span_sessions_and_dedupe(
    tmp_path: Path,
) -> None:
    """Loot/notes recall spans the engagement's sessions, deduped, others excluded."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="acme", mode="pentest")
        led.start_session("s2", engagement_name="acme", mode="pentest")
        led.start_session("o1", engagement_name="other", mode="pentest")
        for sid in ("s1", "s2"):  # same loot item twice -> one row
            led.record_loot(session_id=sid, kind="hash", host="web01", label="ntlm")
        led.record_loot(session_id="s2", kind="key", host="db1", label="id_rsa")
        led.record_loot(session_id="o1", kind="x", host="z", label="elsewhere")
        for sid in ("s1", "s2"):  # same note twice -> one row
            led.record_note(session_id=sid, subject="recon", text="telnet open")
        led.record_note(session_id="o1", subject="x", text="elsewhere")

        loot = led.loot_for_engagement("acme")
        assert sorted(item.label for item in loot) == ["id_rsa", "ntlm"]
        notes = led.notes_for_engagement("acme")
        assert [n.text for n in notes] == ["telnet open"]


def test_recording_a_finding_marks_its_refs_exercised(tmp_path: Path) -> None:
    """A finding's framework refs auto-record methodology coverage (audit E7)."""
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        led.record_finding(
            session_id="s1",
            title="auth bypass",
            severity="high",
            description="d",
            refs=[
                FindingRefInput("wstg", "WSTG-ATHN-01", is_primary=True),
                FindingRefInput("attack", "T1110"),
            ],
        )
        cov = led.coverage_for("s1")
        assert {(c.framework, c.ref_id, c.status) for c in cov} == {
            ("wstg", "WSTG-ATHN-01", "exercised"),
            ("attack", "T1110", "exercised"),
        }


def test_record_coverage_is_idempotent(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "l.db") as led:
        led.start_session("s1", engagement_name="e", mode="pentest")
        led.record_coverage(session_id="s1", framework="wstg", ref_id="WSTG-INFO-01")
        led.record_coverage(session_id="s1", framework="wstg", ref_id="WSTG-INFO-01")
        assert len(led.coverage_for("s1")) == 1  # UNIQUE collapses the repeat


# --- E20: tamper-evident, append-only chain of custody ------------------------


def test_custody_chain_verifies_when_intact(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "case.db") as led:
        led.custody_key = b"k" * 32
        led.start_session("c1", engagement_name="case:x", mode="forensics")
        eid = led.record_evidence(
            session_id="c1", source_path="a.bin", sha256="ab", size=10, note="E1"
        )
        led.record_procedure(
            session_id="c1", step=1, operation="hash", actor="in-process", note="E1"
        )
        assert eid > 0
        verdict = led.verify_custody("c1")
        assert verdict.ok
        assert verdict.checked == 2


def test_custody_chain_detects_a_tampered_row(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "case.db") as led:
        led.custody_key = b"k" * 32
        led.start_session("c1", engagement_name="case:x", mode="forensics")
        led.record_evidence(
            session_id="c1", source_path="a.bin", sha256="ab", size=10, note="E1"
        )
        # Drop the append-only trigger to simulate an attacker editing the file.
        led._conn.execute("DROP TRIGGER evidence_no_update")
        led._conn.execute("UPDATE evidence SET sha256 = 'forged' WHERE session_id='c1'")
        led._conn.commit()
        verdict = led.verify_custody("c1")
        assert not verdict.ok
        assert "evidence" in verdict.broken_at


def test_custody_tables_reject_update_and_delete(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "case.db") as led:
        led.custody_key = b"k" * 32
        led.start_session("c1", engagement_name="case:x", mode="forensics")
        led.record_evidence(
            session_id="c1", source_path="a.bin", sha256="ab", size=10, note="E1"
        )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            led._conn.execute("UPDATE evidence SET note = 'x'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            led._conn.execute("DELETE FROM evidence")
