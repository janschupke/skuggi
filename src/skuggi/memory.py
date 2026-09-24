"""SQLite-backed session history.

Thin wrapper around langgraph-checkpoint-sqlite. The ``checkpoints`` table is
created automatically by ``SqliteSaver`` on first use; ``list_threads`` queries
it directly with stdlib sqlite3 (no extra deps).
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from langgraph.checkpoint.sqlite import SqliteSaver


def _ensure_parent(path: str) -> None:
    Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def open_checkpointer(path: str) -> Iterator[SqliteSaver]:
    """Open a ``SqliteSaver`` over the given .db path; auto-creates the file
    and the parent directory. Hold this open for the TUI lifetime."""
    _ensure_parent(path)
    with SqliteSaver.from_conn_string(path) as saver:
        yield saver


def list_threads(path: str) -> list[str]:
    """Return distinct thread_ids stored in the checkpoints table.

    Reads the table SqliteSaver auto-creates. Returns ``[]`` if the file or
    table does not yet exist.
    """
    p = Path(path).expanduser()
    if not p.exists():
        return []
    with sqlite3.connect(str(p)) as conn:
        try:
            rows = conn.execute(
                "SELECT DISTINCT thread_id FROM checkpoints ORDER BY thread_id"
            ).fetchall()
        except sqlite3.OperationalError:
            return []
    return [r[0] for r in rows]
