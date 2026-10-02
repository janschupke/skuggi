"""L2: the FAISS store, with real indexing over deterministic fake embeddings."""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.persistence import vectorstore
from skuggi.persistence.vectorstore import Store, VectorStoreError, format_hits
from tests.fakes import CountingFakeEmbeddings


def _corpus(tmp_path: Path) -> Path:
    docs = tmp_path / "docs"
    (docs / "nested").mkdir(parents=True)
    (docs / "a.md").write_text("alpha content about badgers", encoding="utf-8")
    (docs / "b.txt").write_text("beta content about otters", encoding="utf-8")
    (docs / "nested" / "c.md").write_text("gamma content", encoding="utf-8")
    (docs / "skip.py").write_text("print('not ingested')", encoding="utf-8")
    return docs


def test_lazy_store_embeds_nothing_until_ingest(
    tmp_path: Path, fake_embeddings: CountingFakeEmbeddings
) -> None:
    """The TUI must boot with no embedding credentials, so nothing is eager."""
    store = Store(tmp_path / "idx", fake_embeddings)

    assert store.search("anything") == []
    assert fake_embeddings.embed_documents_calls == 0


def test_ingest_walks_directories_and_honours_globs(
    tmp_path: Path, store: Store
) -> None:
    added = store.ingest([_corpus(tmp_path)])

    assert added >= 3
    hits = store.search("content", k=10)
    sources = {hit.metadata["source"] for hit in hits}
    assert any(s.endswith("nested/c.md") for s in sources), "should recurse"
    assert not any(s.endswith(".py") for s in sources), "globs exclude .py"


def test_ingest_single_file(tmp_path: Path, store: Store) -> None:
    path = tmp_path / "one.md"
    path.write_text("solo document", encoding="utf-8")
    assert store.ingest([path]) == 1


def test_ingest_missing_path_is_a_noop(tmp_path: Path, store: Store) -> None:
    assert store.ingest([tmp_path / "absent"]) == 0


def test_ingest_tolerates_undecodable_bytes(tmp_path: Path, store: Store) -> None:
    """One stray byte must not fail the whole ingest."""
    path = tmp_path / "bad.md"
    path.write_bytes(b"\xff\xfe readable tail")
    assert store.ingest([path]) == 1


def test_long_document_is_chunked_with_metadata(tmp_path: Path) -> None:
    store = Store(
        tmp_path / "idx", CountingFakeEmbeddings(), chunk_size=100, chunk_overlap=10
    )
    path = tmp_path / "long.md"
    path.write_text(" ".join(f"word{i}" for i in range(400)), encoding="utf-8")

    assert store.ingest([path]) > 1
    assert all(hit.metadata["source"] == str(path) for hit in store.search("word", k=5))


def test_persist_then_reload_in_a_fresh_store(tmp_path: Path) -> None:
    index = tmp_path / "idx"
    first = Store(index, CountingFakeEmbeddings())
    first.ingest([_corpus(tmp_path)])
    first.persist()

    assert (index / "index.faiss").is_file()
    assert (index / "index.pkl").is_file()

    reloaded = Store(index, CountingFakeEmbeddings())
    assert reloaded.search("content", k=1), "a fresh Store should load from disk"


def test_persist_with_no_index_creates_nothing(tmp_path: Path, store: Store) -> None:
    store.persist()
    assert not (tmp_path / "faiss_index").exists()


def test_format_hits_renders_source_and_separator(tmp_path: Path, store: Store) -> None:
    store.ingest([_corpus(tmp_path)])
    rendered = format_hits(store.search("content", k=2))
    assert rendered.count("---") == 1
    assert rendered.startswith("[")


# --- S9: the mandatory dangerous-deserialization load must refuse a symlink --


def test_refuses_a_symlinked_index(
    tmp_path: Path, fake_embeddings: CountingFakeEmbeddings
) -> None:
    """A planted symlink would redirect the pickle load to an attacker file."""
    idx = tmp_path / "idx"
    idx.mkdir()
    outside = tmp_path / "evil.faiss"
    outside.write_text("x", encoding="utf-8")
    (idx / "index.faiss").symlink_to(outside)
    with pytest.raises(VectorStoreError, match="symlink"):
        Store(idx, fake_embeddings)


# --- F6: the second-ingest (add to an existing index) branch ----------------


def test_second_ingest_extends_the_live_index(tmp_path: Path, store: Store) -> None:
    store.ingest([_corpus(tmp_path)])
    more = tmp_path / "more"
    more.mkdir()
    (more / "d.md").write_text("delta content about owls", encoding="utf-8")
    assert store.ingest([more]) >= 1  # takes the add_documents branch
    assert store.search("owls", k=1)


# --- F2: an oversized source file is skipped, not read whole ----------------


def test_oversized_source_is_skipped(
    tmp_path: Path, store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(vectorstore, "MAX_FILE_BYTES", 10)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "small.md").write_text("tiny", encoding="utf-8")
    (docs / "big.md").write_text("x" * 100, encoding="utf-8")
    assert store.ingest([docs]) == 1  # only the small file
    hits = store.search("tiny", k=5)
    assert all("big.md" not in h.metadata["source"] for h in hits)
