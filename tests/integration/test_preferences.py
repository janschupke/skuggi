"""L2: the preferences store against a real SQLite file, incl. reopen."""

from __future__ import annotations

from pathlib import Path

from skuggi.persistence.preferences import open_preferences


def test_add_list_and_render_round_trip(tmp_path: Path) -> None:
    with open_preferences(tmp_path / "p.db") as prefs:
        row = prefs.add("Prefer ffuf over gobuster", source="manual")
        assert row is not None
        assert row.id == 1
        assert row.source == "manual"
        assert [r.text for r in prefs.all()] == ["Prefer ffuf over gobuster"]
        assert prefs.render_block() == "- Prefer ffuf over gobuster"


def test_blank_and_duplicate_are_ignored(tmp_path: Path) -> None:
    with open_preferences(tmp_path / "p.db") as prefs:
        assert prefs.add("   ", source="manual") is None
        assert prefs.add("Keep answers terse", source="manual") is not None
        # case-insensitive duplicate of the trimmed text is a no-op
        assert prefs.add("  keep answers TERSE  ", source="auto") is None
        assert len(prefs.all()) == 1


def test_render_block_groups_by_category_when_mixed(tmp_path: Path) -> None:
    with open_preferences(tmp_path / "p.db") as prefs:
        prefs.add("Prefer ffuf over gobuster", source="manual")
        prefs.add("Write helper scripts in Python", source="auto", category="scripting")
        block = prefs.render_block()
        assert "general:" in block
        assert "scripting:" in block
        assert "- Prefer ffuf over gobuster" in block
        assert "- Write helper scripts in Python" in block


def test_render_block_is_empty_when_nothing_remembered(tmp_path: Path) -> None:
    with open_preferences(tmp_path / "p.db") as prefs:
        assert prefs.render_block() == ""


def test_forget_and_clear(tmp_path: Path) -> None:
    with open_preferences(tmp_path / "p.db") as prefs:
        prefs.add("one", source="manual")
        prefs.add("two", source="manual")
        assert prefs.forget(1) is True
        assert prefs.forget(999) is False  # nothing to remove
        assert [r.text for r in prefs.all()] == ["two"]
        assert prefs.clear() == 1
        assert prefs.all() == []


def test_count_tracks_the_stored_rows(tmp_path: Path) -> None:
    with open_preferences(tmp_path / "p.db") as prefs:
        assert prefs.count() == 0
        prefs.add("one", source="manual")
        prefs.add("two", source="auto")
        assert prefs.count() == 2
        prefs.forget(1)
        assert prefs.count() == 1


def test_reopening_sees_persisted_rows(tmp_path: Path) -> None:
    db = tmp_path / "nested" / "p.db"
    with open_preferences(db) as prefs:
        prefs.add("Prefer ffuf over gobuster", source="manual")
    assert db.is_file()
    with open_preferences(db) as prefs:
        assert [r.text for r in prefs.all()] == ["Prefer ffuf over gobuster"]
