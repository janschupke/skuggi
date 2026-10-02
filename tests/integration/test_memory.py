"""L2: thread enumeration against a real SqliteSaver."""

from __future__ import annotations

from pathlib import Path

from langgraph.checkpoint.base import empty_checkpoint
from langgraph.checkpoint.memory import InMemorySaver

from skuggi.persistence.memory import list_threads, open_checkpointer


def _write(saver: object, thread_id: str, times: int = 1) -> None:
    for _ in range(times):
        cfg = {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}
        saver.put(cfg, empty_checkpoint(), {}, {})  # type: ignore[attr-defined]


def test_empty_saver_has_no_threads() -> None:
    assert list_threads(InMemorySaver()) == []


def test_threads_are_deduplicated() -> None:
    """Three checkpoints per thread must collapse to one id each."""
    saver = InMemorySaver()
    for thread_id in ("th0", "th1", "th2"):
        _write(saver, thread_id, times=3)

    listed = list_threads(saver)

    assert sorted(listed) == ["th0", "th1", "th2"]
    assert len(listed) == 3, "ids should be deduplicated, not repeated per checkpoint"


def test_sqlite_saver_orders_newest_first(tmp_path: Path) -> None:
    """Documents the sqlite ordering, which differs from InMemorySaver's.

    Pinned because it is what the /thread list output looks like, not because
    list_threads promises an order.
    """
    with open_checkpointer(tmp_path / "s.db") as saver:
        for thread_id in ("th0", "th1", "th2"):
            _write(saver, thread_id)
        assert list_threads(saver) == ["th2", "th1", "th0"]


def test_real_sqlite_saver_round_trip(tmp_path: Path) -> None:
    db = tmp_path / "nested" / "sessions.db"
    with open_checkpointer(db) as saver:
        _write(saver, "alpha", times=2)
        _write(saver, "beta")
        assert set(list_threads(saver)) == {"alpha", "beta"}
    assert db.is_file(), "open_checkpointer should create the file and its parent"


def test_reopening_sees_persisted_threads(tmp_path: Path) -> None:
    db = tmp_path / "sessions.db"
    with open_checkpointer(db) as saver:
        _write(saver, "kept")
    with open_checkpointer(db) as saver:
        assert list_threads(saver) == ["kept"]
