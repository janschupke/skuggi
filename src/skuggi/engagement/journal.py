"""Timestamped append-only text journals for an engagement workspace.

Notes and loot are both the same shape: a free-form line the operator records
by hand, stamped with when they recorded it, appended to one Markdown file in
the workspace. The structured, report-bound records live in the ledger (see
``AgentCore.record_finding``); these files are the operator's running log.

Kept tiny and path-based so ``Workspace`` stays a pure path resolver -- the two
callers (notes, loot) pass the file they own. ``append_entry`` is the only thing
here that writes, and it creates the parent the same way ``ensure_parent`` does
everywhere else in the harness.
"""

from __future__ import annotations

from pathlib import Path

from skuggi.common.clock import now_iso
from skuggi.common.paths import ensure_parent


def append_entry(path: Path, text: str, *, timestamp: str | None = None) -> str:
    """Append ``text`` to ``path`` as a timestamped Markdown bullet.

    Creates the file (and its parent) on first use. Returns the timestamp
    written, so the caller can confirm it. ``timestamp`` is injectable for tests.
    """
    stamp = timestamp or now_iso()
    target = ensure_parent(path)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(f"- `{stamp}`  {text.strip()}\n")
    return stamp


def read_entries(path: Path) -> str:
    """The journal's current contents, or ``""`` when nothing is recorded yet."""
    expanded = path.expanduser()
    if not expanded.is_file():
        return ""
    return expanded.read_text(encoding="utf-8")
