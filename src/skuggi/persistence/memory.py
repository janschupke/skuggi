"""SQLite-backed session history.

Thin wrapper around langgraph-checkpoint-sqlite. Thread enumeration goes through
the checkpointer's own ``list`` API rather than querying its tables directly, so
this module is not coupled to a private schema.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.sqlite import SqliteSaver

from skuggi.common.paths import ensure_parent


@contextmanager
def open_checkpointer(path: Path) -> Iterator[SqliteSaver]:
    """Open a `SqliteSaver` over `path`, creating the file and its parent.

    Hold this open for the lifetime of the session.
    """
    ensure_parent(path)
    with SqliteSaver.from_conn_string(str(path)) as saver:
        yield saver


def list_threads(saver: BaseCheckpointSaver[str]) -> list[str]:
    """Return the distinct thread ids the checkpointer holds.

    Order follows the checkpointer's own enumeration, which is *not* a
    cross-implementation contract: SqliteSaver yields newest-first while
    InMemorySaver yields oldest-first. Callers should not rely on it.

    Takes the live saver rather than a path: the previous version opened a
    second sqlite connection to the same file the session already had open, and
    read `SELECT DISTINCT thread_id FROM checkpoints` -- a private table whose
    layout is not ours to depend on. Passing the saver also means a test can use
    an in-memory one.

    This walks every checkpoint, not every thread, so cost grows with history
    length. Fine for an interactive command (0.1 ms at 9 checkpoints); note that
    the saver's own `limit` caps checkpoints rather than threads, so it is not a
    useful way to bound this.
    """
    ids = (tuple_.config["configurable"]["thread_id"] for tuple_ in saver.list(None))
    return list(dict.fromkeys(str(thread_id) for thread_id in ids))
