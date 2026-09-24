"""Standalone CLI ingester. Usage:

    python scripts/ingest.py ./docs
    python scripts/ingest.py file1.md file2.md
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from skuggi import providers  # noqa: E402
from skuggi.vectorstore import Store  # noqa: E402


def main() -> int:
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
