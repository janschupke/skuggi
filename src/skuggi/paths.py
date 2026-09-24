"""Tiny filesystem helpers shared across the storage layers.

Every store in skuggi -- the checkpointer, the ledger, the FAISS index, the
reports directory, the workspace tree -- has to make sure a directory exists
before it writes. These two helpers state the two shapes of that once (ensure a
file's *parent*, or ensure a *directory* itself) so no module hand-rolls
``expanduser().mkdir(parents=True, exist_ok=True)`` again.
"""

from __future__ import annotations

from pathlib import Path


def ensure_parent(path: Path) -> Path:
    """Create the parent directory of `path` (for a file about to be written).

    Returns the expanded path so the caller can use it directly.
    """
    expanded = path.expanduser()
    expanded.parent.mkdir(parents=True, exist_ok=True)
    return expanded


def ensure_dir(path: Path) -> Path:
    """Create the directory `path` itself (idempotent). Returns the expanded path."""
    expanded = path.expanduser()
    expanded.mkdir(parents=True, exist_ok=True)
    return expanded
