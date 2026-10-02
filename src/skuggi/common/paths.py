"""Tiny filesystem helpers shared across the storage layers.

Every store in skuggi -- the checkpointer, the ledger, the FAISS index, the
reports directory, the workspace tree -- has to make sure a directory exists
before it writes. Two helpers state the two shapes of that once (ensure a
file's *parent*, or ensure a *directory* itself) so no module hand-rolls
``expanduser().mkdir(parents=True, exist_ok=True)`` again.

``packaged_template`` is here for the same reason: locating a shipped asset is a
path concern, and doing it through ``importlib.resources`` in one place keeps a
cwd-relative ``Path("configs/...")`` -- which only ever resolved when the process
happened to start in the repo root -- from reappearing.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

# Shipped assets inside the package: the report stylesheet/template and the
# `*.example.json` config templates `skuggi-init` seeds a config home from.
TEMPLATE_DIR = "templates"


def packaged_template(name: str) -> Path:
    """Filesystem path to a packaged asset under ``skuggi/templates/``.

    Works for both install shapes: a wheel has the file under its installed
    package directory, and an editable install resolves it back into the source
    tree. Never derive this from ``__file__`` arithmetic or the working directory
    -- ``skuggi`` runs from anywhere, and neither survives that.
    """
    return Path(str(files("skuggi") / TEMPLATE_DIR / name))


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
