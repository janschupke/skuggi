"""L1: the timestamped append-only note/loot journals."""

from __future__ import annotations

from pathlib import Path

from skuggi.engagement import journal


def test_read_missing_file_is_empty(tmp_path: Path) -> None:
    assert journal.read_entries(tmp_path / "absent.md") == ""


def test_append_creates_the_file_and_parent(tmp_path: Path) -> None:
    path = tmp_path / "notes" / "notes.md"
    stamp = journal.append_entry(
        path, "found an open redirect", timestamp="2026-10-02T00:00:00+00:00"
    )
    assert stamp == "2026-10-02T00:00:00+00:00"
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    assert "2026-10-02T00:00:00+00:00" in body
    assert "found an open redirect" in body
    assert body.endswith("\n")


def test_append_accumulates_in_order(tmp_path: Path) -> None:
    path = tmp_path / "loot.md"
    journal.append_entry(
        path, "cred: admin:hunter2", timestamp="2026-10-02T01:00:00+00:00"
    )
    journal.append_entry(
        path, "ssh key for box2", timestamp="2026-10-02T02:00:00+00:00"
    )
    body = journal.read_entries(path)
    assert body.count("- `") == 2
    assert body.index("hunter2") < body.index("ssh key")


def test_append_stamps_when_no_timestamp_given(tmp_path: Path) -> None:
    path = tmp_path / "notes.md"
    stamp = journal.append_entry(path, "a note")
    # An ISO-8601 UTC stamp, echoed into the file.
    assert stamp.endswith("+00:00")
    assert stamp in journal.read_entries(path)
