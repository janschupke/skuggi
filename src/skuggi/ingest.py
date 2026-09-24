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
    store = Store.from_settings(settings, providers.get_embeddings(settings))
    added = store.ingest([Path(p) for p in args.paths])
    store.persist()
    print(f"indexed {added} chunk(s) into {settings.faiss_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
