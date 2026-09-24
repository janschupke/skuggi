"""FAISS-backed embeddings storage, persisted to a local directory.

A small ``Store`` class wraps a *lazy* FAISS index: nothing is embedded until
the first ``ingest`` call. This lets the TUI boot without working embeddings
credentials and only fail if/when the user actually calls ``/ingest``.

The ``allow_dangerous_deserialization=True`` flag on load_local is mandatory
in current langchain-community because the on-disk format is pickle-based;
that's fine for a single-user local store.
"""

from __future__ import annotations

from pathlib import Path
from collections.abc import Iterable, Sequence

from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

_SPLITTER = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=120)

_HIT_SEPARATOR = "\n\n---\n\n"


def format_hits(hits: Sequence[Document]) -> str:
    """Render retrieved documents for a prompt.

    Shared so a snippet reads identically whether it arrives as tool output or
    is inlined into the worker prompt for a provider that cannot bind tools.
    """
    return _HIT_SEPARATOR.join(
        f"[{hit.metadata.get('source', '?')}]\n{hit.page_content}" for hit in hits
    )


class Store:
    def __init__(self, path: str, embeddings: Embeddings) -> None:
        self.path = Path(path).expanduser()
        self.embeddings = embeddings
        self._vs: FAISS | None = self._try_load()

    def _try_load(self) -> FAISS | None:
        if (self.path / "index.faiss").exists():
            return FAISS.load_local(
                str(self.path),
                self.embeddings,
                allow_dangerous_deserialization=True,
            )
        return None

    def search(self, query: str, k: int = 4) -> list[Document]:
        if self._vs is None:
            return []
        return self._vs.similarity_search(query, k=k)

    def ingest(self, paths: Iterable[Path]) -> int:
        docs: list[Document] = []
        for raw in paths:
            p = Path(raw).expanduser()
            if p.is_dir():
                files = [*p.rglob("*.md"), *p.rglob("*.txt")]
            elif p.is_file():
                files = [p]
            else:
                continue
            for f in files:
                text = f.read_text(encoding="utf-8", errors="replace")
                for chunk in _SPLITTER.split_text(text):
                    docs.append(
                        Document(page_content=chunk, metadata={"source": str(f)})
                    )
        if not docs:
            return 0
        if self._vs is None:
            self._vs = FAISS.from_documents(docs, self.embeddings)
        else:
            self._vs.add_documents(docs)
        return len(docs)

    def persist(self) -> None:
        if self._vs is None:
            return
        self.path.mkdir(parents=True, exist_ok=True)
        self._vs.save_local(str(self.path))
