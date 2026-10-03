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

from skuggi.common.logs import get_logger
from skuggi.common.paths import ensure_dir
from skuggi.config.config import Settings
from skuggi.persistence import documents

log = get_logger(__name__)

# A single source file larger than this is skipped at ingest rather than read
# whole into memory -- a stray multi-hundred-MB recon artifact or log must not
# be able to blow up the embedding step.
MAX_FILE_BYTES = 5 * 1024 * 1024

_HIT_SEPARATOR = "\n\n---\n\n"


def format_hits(hits: Sequence[Document]) -> str:
    """Render retrieved documents for a prompt.

    Shared so a snippet reads identically whether it arrives as tool output or
    is inlined into the worker prompt for a provider that cannot bind tools.
    """
    return _HIT_SEPARATOR.join(
        f"[{hit.metadata.get('source', '?')}]\n{hit.page_content}" for hit in hits
    )


class VectorStoreError(RuntimeError):
    """Raised when a FAISS index on disk cannot be trusted to load."""


class Store:
    """A lazily-loaded FAISS index over local markdown and text files."""

    def __init__(
        self,
        path: Path,
        embeddings: Embeddings,
        *,
        chunk_size: int = 800,
        chunk_overlap: int = 120,
        globs: Sequence[str] = (
            "**/*.md",
            "**/*.txt",
            "**/*.pdf",
            "**/*.docx",
            "**/*.xlsx",
        ),
    ) -> None:
        self.path = path.expanduser()
        self.embeddings = embeddings
        self.globs = tuple(globs)
        self._splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size, chunk_overlap=chunk_overlap
        )
        self._vs: FAISS | None = self._try_load()

    @classmethod
    def from_settings(cls, settings: Settings, embeddings: Embeddings) -> Store:
        """Build a Store from settings (path + chunking) and an embeddings model."""
        return cls(
            settings.faiss_path,
            embeddings,
            chunk_size=settings.chunk_size,
            chunk_overlap=settings.chunk_overlap,
        )

    def _try_load(self) -> FAISS | None:
        if not (self.path / "index.faiss").exists():
            return None
        # `allow_dangerous_deserialization` is mandatory (FAISS persists its
        # docstore as a pickle), so the trust boundary is that only the operator
        # can write the index dir. Refuse a symlinked index file -- a planted
        # symlink would otherwise redirect the pickle load to an attacker file.
        self._reject_symlinked_index()
        return FAISS.load_local(
            str(self.path),
            self.embeddings,
            allow_dangerous_deserialization=True,
        )

    def _reject_symlinked_index(self) -> None:
        for name in ("index.faiss", "index.pkl"):
            member = self.path / name
            if member.is_symlink():
                msg = (
                    f"refusing to load FAISS index: {name} in {self.path} is a "
                    "symlink, not a regular file"
                )
                raise VectorStoreError(msg)

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
        sources: list[Document] = []
        for path in self._files(paths):
            content = self._read_source(path)
            if content is None:
                continue
            sources.append(
                Document(page_content=content, metadata={"source": str(path)})
            )
        docs = self._splitter.split_documents(sources)
        if not docs:
            return 0
        if self._vs is None:
            self._vs = FAISS.from_documents(docs, self.embeddings)
        else:
            self._vs.add_documents(docs)
        return len(docs)

    def _read_source(self, path: Path) -> str | None:
        """The text of one ingest source, or None to skip it.

        A binary document (pdf/docx/xlsx) is parsed through the safe extractor
        (no execution, macros refused, bomb/size-capped); a refused document is
        skipped with a warning rather than failing the whole run. A plain-text
        source is read directly, with ``errors="replace"`` kept so one stray byte
        does not abort ingest, under the non-document size cap.
        """
        if documents.is_supported(path):
            try:
                return documents.extract_text(path)
            except documents.DocumentError as exc:
                log.warning("skipping document: %s", exc)
                return None
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            log.warning("skipping oversized ingest source (%d bytes): %s", size, path)
            return None
        return path.read_text(encoding="utf-8", errors="replace")

    def persist(self) -> None:
        """Write the index to disk; a no-op when nothing has been ingested."""
        if self._vs is None:
            return
        ensure_dir(self.path)
        self._vs.save_local(str(self.path))
