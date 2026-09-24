"""FAISS-backed embeddings storage, persisted to a local directory.

A small ``Store`` class wraps a *lazy* FAISS index: nothing is embedded until
the first ``ingest`` call. This lets the TUI boot without working embeddings
credentials and only fail if/when the user actually calls ``/ingest``.

The ``allow_dangerous_deserialization=True`` flag on load_local is mandatory
in current langchain-community because the on-disk format is pickle-based;
that's fine for a single-user local store.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

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
    """A lazily-loaded FAISS index over local markdown and text files."""

    def __init__(
        self,
        path: Path,
        embeddings: Embeddings,
        *,
        chunk_size: int = 800,
        chunk_overlap: int = 120,
        globs: Sequence[str] = ("**/*.md", "**/*.txt"),
    ) -> None:
        self.path = path.expanduser()
        self.embeddings = embeddings
        self.globs = tuple(globs)
        self._splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size, chunk_overlap=chunk_overlap
        )
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
        """Return the top-k matches, or nothing when no index exists yet."""
        if self._vs is None:
            return []
        return self._vs.similarity_search(query, k=k)

    def _files(self, paths: Iterable[Path]) -> list[Path]:
        """Expand the given files and directories into readable source files."""
        found: list[Path] = []
        for raw in paths:
            candidate = Path(raw).expanduser()
            if candidate.is_dir():
                for pattern in self.globs:
                    found.extend(sorted(candidate.glob(pattern)))
            elif candidate.is_file():
                found.append(candidate)
        return found

    def ingest(self, paths: Iterable[Path]) -> int:
        """Embed the given files or directories, returning the chunk count.

        `errors="replace"` is kept deliberately over a document loader: ingest
        must never fail the whole run because one file has a stray byte.
        """
        sources = [
            Document(
                page_content=path.read_text(encoding="utf-8", errors="replace"),
                metadata={"source": str(path)},
            )
            for path in self._files(paths)
        ]
        docs = self._splitter.split_documents(sources)
        if not docs:
            return 0
        if self._vs is None:
            self._vs = FAISS.from_documents(docs, self.embeddings)
        else:
            self._vs.add_documents(docs)
        return len(docs)

    def persist(self) -> None:
        """Write the index to disk; a no-op when nothing has been ingested."""
        if self._vs is None:
            return
        self.path.mkdir(parents=True, exist_ok=True)
        self._vs.save_local(str(self.path))
