"""The ``show`` list filters: flag parsing + pure row filtering (G7)."""

from __future__ import annotations

from skuggi.frontend.show_filters import (
    ShowFilters,
    filter_findings,
    filter_loot,
    filter_notes,
    parse_filters,
)
from skuggi.persistence.ledger import FindingRow, LootRow, NoteRow


def _finding(**kw: object) -> FindingRow:
    base: dict[str, object] = dict.fromkeys(FindingRow.__dataclass_fields__, "")
    base.update(
        id=1,
        command_id=None,
        cvss_version=None,
        cvss_vector=None,
        cvss_base=None,
        cvss_temporal=None,
        cvss_environmental=None,
        cvss_score=None,
        cvss_severity=None,
        reviewed_at=None,
        cvss_tm_version=None,
        cvss_scored_at=None,
    )
    base.update(kw)
    return FindingRow(**base)  # type: ignore[arg-type]


def _loot(**kw: object) -> LootRow:
    base = {
        "id": 1,
        "session_id": "s",
        "kind": "",
        "host": "",
        "label": "",
        "secret_ref": "",
        "source": "",
        "created_at": "",
    }
    base.update(kw)
    return LootRow(**base)  # type: ignore[arg-type]


def _note(**kw: object) -> NoteRow:
    base = {
        "id": 1,
        "session_id": "s",
        "subject": "",
        "host": "",
        "text": "",
        "source": "",
        "created_at": "",
    }
    base.update(kw)
    return NoteRow(**base)  # type: ignore[arg-type]


def test_parse_flags_and_bare_words() -> None:
    f = parse_filters("--severity high --host web01 --limit 5 sqli login")
    assert f.severity == "high"
    assert f.host == "web01"
    assert f.limit == 5
    assert f.grep == "sqli login"  # bare words collect into grep


def test_parse_bad_limit_is_ignored() -> None:
    assert parse_filters("--limit nope").limit is None
    assert parse_filters("--limit 0").limit is None


def test_filter_findings_by_severity_and_limit() -> None:
    rows = [
        _finding(id=1, severity="low", title="a", affected_host="h1"),
        _finding(id=2, severity="high", title="sqli", affected_host="web01"),
        _finding(id=3, severity="high", title="xss", affected_host="web02"),
    ]
    high = filter_findings(rows, ShowFilters(severity="high"))
    assert [r.id for r in high] == [2, 3]
    assert [r.id for r in filter_findings(rows, ShowFilters(host="web01"))] == [2]
    assert [r.id for r in filter_findings(rows, ShowFilters(grep="sqli"))] == [2]
    assert [r.id for r in filter_findings(rows, ShowFilters(limit=1))] == [3]


def test_filter_loot_and_notes() -> None:
    loot = [
        _loot(id=1, kind="hash", host="web01", label="ntlm"),
        _loot(id=2, kind="key", host="db1", label="id_rsa"),
    ]
    assert [r.id for r in filter_loot(loot, ShowFilters(kind="key"))] == [2]
    assert [r.id for r in filter_loot(loot, ShowFilters(grep="ntlm"))] == [1]

    notes = [
        _note(id=1, subject="recon", host="web01", text="telnet open"),
        _note(id=2, subject="idea", host="", text="try default creds"),
    ]
    assert [r.id for r in filter_notes(notes, ShowFilters(host="web01"))] == [1]
    assert [r.id for r in filter_notes(notes, ShowFilters(grep="default"))] == [2]
