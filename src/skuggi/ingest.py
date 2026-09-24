"""Standalone CLI ingester.

Usage:
    skuggi-ingest ./docs
    skuggi-ingest file1.md file2.md
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from dotenv import load_dotenv

from skuggi import providers
from skuggi.vectorstore import Store


def main() -> int:
    """Embed the given files or directories into the local FAISS index."""
    load_dotenv()
    ap = argparse.ArgumentParser(description="Ingest markdown/text into FAISS.")
    ap.add_argument("paths", nargs="+", help="files or directories to ingest")
    args = ap.parse_args()

    faiss_path = os.environ.get("SKUGGI_FAISS_PATH", "./data/faiss_index")
    store = Store(faiss_path, providers.get_embeddings())
    added = store.ingest([Path(p) for p in args.paths])
    store.persist()
    print(f"indexed {added} chunk(s) into {faiss_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
