"""SQLite store for the operator's operational preferences -- harness memory.

A third store beside the LangGraph checkpointer (``memory.py``) and the
per-engagement ``Ledger`` (``ledger.py``): the operator's standing directives
about *how* to work -- which tool to reach for when several would do, the
language to write helper scripts in, how terse a reply should be, reporting
conventions. Learned once and applied to every session.

It is deliberately **global** -- one file at ``settings.preferences_path``
(default ``./data/preferences.db``), never per-engagement -- because a
preference is about the operator, not the target. ``AgentCore`` renders it into
the planner/worker/critic prompts every turn, and writes to it two ways: the
manual ``memory`` verb and the post-turn automatic capture.

``open_preferences`` mirrors ``ledger.open_ledger``: a context manager that
creates the file and its parent and yields a lock-guarded handle for the
session (graph nodes run on a worker-thread pool, so every access is
serialised).
"""

from __future__ import annotations

import re
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, fields
from pathlib import Path

from skuggi.common.clock import now_iso
from skuggi.common.paths import ensure_parent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS preferences (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    category   TEXT NOT NULL DEFAULT 'general',
    text       TEXT NOT NULL,
    source     TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

# The cheap pre-filter for the automatic-capture path: an operator turn only
# reaches the extraction LLM when it *reads like* a standing instruction, so an
# ordinary question never spends a model call. This is a gate, never the final
# decision -- the LLM still gets to answer "nothing durable to remember". Kept
# to unambiguous standing-instruction cues to avoid firing on plain requests.
_DIRECTIVE_CUES = (
    r"always",
    r"never",
    r"prefer",
    r"from now on",
    r"in future",
    r"going forward",
    r"by default",
    r"default to",
    r"stick to",
    r"remember",
    r"don'?t",
    r"do not",
    # "use X over/instead of/not Y" -- an explicit tool/approach choice.
    r"use .+ (?:over|instead|not)\b",
)
_DIRECTIVE_RE = re.compile(r"\b(?:" + "|".join(_DIRECTIVE_CUES) + r")", re.IGNORECASE)


def looks_like_directive(text: str) -> bool:
    """Whether `text` reads like a standing operator instruction worth capturing.

    A deliberately cheap heuristic gate for automatic capture -- see the module
    docstring. False negatives are fine (the operator can ``memory add``); the
    point is only to keep an ordinary question from spending a model call.
    """
    return bool(_DIRECTIVE_RE.search(text))


@dataclass(frozen=True, slots=True)
class PreferenceRow:
    """One remembered operator preference."""

    id: int
    category: str
    text: str
    source: str
    created_at: str


# Column list derived from the row dataclass, so SELECT order (and the positional
# PreferenceRow(*row) unpacking) can never drift from the field order.
_PREF_COLS = tuple(f.name for f in fields(PreferenceRow))


class PreferenceStore:
    """A thin, typed, lock-guarded wrapper over the preferences database."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        # Opened with check_same_thread=False (see open_preferences); every
        # access is guarded by this lock, which is what makes cross-thread use
        # safe (the graph runs nodes on a worker-thread pool).
        self._conn = conn
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def add(
        self, text: str, *, source: str, category: str = "general"
    ) -> PreferenceRow | None:
        """Insert a preference and return its row; ``None`` on blank or duplicate.

        Duplicates are matched case-insensitively on the trimmed text, so the
        automatic path is idempotent: the same directive restated is a no-op.
        `source` is ``manual`` or ``auto``.
        """
        cleaned = text.strip()
        if not cleaned:
            return None
        with self._lock:
            duplicate = self._conn.execute(
                "SELECT 1 FROM preferences WHERE lower(text) = lower(?) LIMIT 1",
                (cleaned,),
            ).fetchone()
            if duplicate:
                return None
            created = now_iso()
            cur = self._conn.execute(
                "INSERT INTO preferences (category, text, source, created_at)"
                " VALUES (?, ?, ?, ?)",
                (category, cleaned, source, created),
            )
            self._conn.commit()
            return PreferenceRow(
                int(cur.lastrowid or 0), category, cleaned, source, created
            )

    def forget(self, pref_id: int) -> bool:
        """Delete one preference by id; ``True`` if a row was removed."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM preferences WHERE id = ?", (pref_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def clear(self) -> int:
        """Delete every preference; returns how many were removed."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM preferences")
            self._conn.commit()
            return cur.rowcount

    def all(self) -> list[PreferenceRow]:
        """Every preference, grouped by category then insertion order."""
        with self._lock:
            rows = self._conn.execute(
                _select_all_sql(),
            ).fetchall()
        return [PreferenceRow(*row) for row in rows]

    def render_block(self) -> str:
        """The active preferences as a bullet list for prompt injection.

        Empty string when nothing is remembered (``text.labeled`` then elides
        the block entirely). A category sub-heading is shown only when more than
        one category is present, so the common single-category case is a flat
        list.
        """
        rows = self.all()
        if not rows:
            return ""
        if len({row.category for row in rows}) == 1:
            return "\n".join(f"- {row.text}" for row in rows)
        lines: list[str] = []
        current: str | None = None
        for row in rows:
            if row.category != current:
                current = row.category
                lines.append(f"{row.category}:")
            lines.append(f"- {row.text}")
        return "\n".join(lines)


# The column names are code-defined dataclass field names (never user input), so
# the S608 string-building warning does not apply.
def _select_all_sql() -> str:
    return f"SELECT {', '.join(_PREF_COLS)} FROM preferences ORDER BY category, id"  # noqa: S608


@contextmanager
def open_preferences(path: Path) -> Iterator[PreferenceStore]:
    """Open a `PreferenceStore` over `path`, creating the file and its parent.

    Hold this open for the lifetime of the session, like the ledger.
    """
    resolved = ensure_parent(path)
    # check_same_thread=False because graph nodes run on a worker-thread pool;
    # PreferenceStore serializes every access with a lock.
    conn = sqlite3.connect(str(resolved), check_same_thread=False)
    try:
        yield PreferenceStore(conn)
    finally:
        conn.close()
