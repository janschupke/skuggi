"""L3: the skuggi-ingest console script."""

from __future__ import annotations

from importlib import metadata
from pathlib import Path

import pytest
from tests.fakes import CountingFakeEmbeddings

from skuggi import ingest


@pytest.fixture(autouse=True)
def offline_embeddings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ingest.providers, "get_embeddings", lambda _settings: CountingFakeEmbeddings()
    )


def test_indexes_and_persists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.md").write_text("alpha", encoding="utf-8")
    (docs / "b.txt").write_text("beta", encoding="utf-8")
    index = tmp_path / "idx"
    monkeypatch.setenv("SKUGGI_FAISS_PATH", str(index))
    monkeypatch.setattr("sys.argv", ["skuggi-ingest", str(docs)])

    assert ingest.main() == 0

    assert "indexed 2 chunk(s)" in capsys.readouterr().out
    assert (index / "index.faiss").is_file()


def test_requires_at_least_one_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["skuggi-ingest"])
    with pytest.raises(SystemExit) as excinfo:
        ingest.main()
    assert excinfo.value.code == 2


def test_unknown_path_indexes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SKUGGI_FAISS_PATH", str(tmp_path / "idx"))
    monkeypatch.setattr("sys.argv", ["skuggi-ingest", str(tmp_path / "absent")])

    assert ingest.main() == 0
    assert "indexed 0 chunk(s)" in capsys.readouterr().out


def test_both_console_scripts_resolve() -> None:
    """Catches a broken [project.scripts] before a user does."""
    entries = {
        entry.name: entry
        for entry in metadata.entry_points(group="console_scripts")
        if entry.name.startswith("skuggi")
    }
    assert set(entries) == {"skuggi", "skuggi-ingest"}
    for entry in entries.values():
        assert callable(entry.load())
