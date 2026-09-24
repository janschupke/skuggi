"""Standalone CLI ingester.

Usage:
    skuggi-ingest ./docs
    skuggi-ingest file1.md file2.md
"""

from __future__ import annotations

import argparse
from pathlib import Path

from skuggi import providers
from skuggi.config import Settings
from skuggi.vectorstore import Store


def main() -> int:
    """Embed the given files or directories into the local FAISS index."""
    ap = argparse.ArgumentParser(description="Ingest markdown/text into FAISS.")
    ap.add_argument("paths", nargs="+", help="files or directories to ingest")
    args = ap.parse_args()

    settings = Settings()
    faiss_path = settings.faiss_path
    store = Store(
        faiss_path,
        providers.get_embeddings(settings),
        chunk_size=settings.chunk_size,
        chunk_overlap=settings.chunk_overlap,
    )
    added = store.ingest([Path(p) for p in args.paths])
    store.persist()
    print(f"indexed {added} chunk(s) into {faiss_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
