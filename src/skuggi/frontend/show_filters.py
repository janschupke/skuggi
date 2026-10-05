"""Filtering + paging for the growable ``show`` lists (findings / loot / notes).

An engagement accumulates these without bound, so ``show findings``/``loot``/``notes``
take optional flags -- ``--host``, ``--severity``, ``--status``, ``--kind``,
``--grep``, ``--limit`` -- parsed here and applied as pure row filters. Kept out of
the frontends (and free of I/O) so both the REPL and the daemon filter identically
and the logic is unit-testable without a console.

Unknown flags and bare words are collected into ``grep`` (a free-text contains
match), so ``show findings sqli`` works without the operator reaching for a flag.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from skuggi.persistence.ledger import FindingRow, LootRow, NoteRow

_FLAGS = ("host", "severity", "status", "kind", "grep", "limit")


@dataclass(frozen=True, slots=True)
class ShowFilters:
    """Parsed ``show`` filters; every field empty/None means 'no constraint'."""

    host: str = ""
    severity: str = ""
    status: str = ""
    kind: str = ""
    grep: str = ""
    limit: int | None = None


@dataclass
class _Acc:
    values: dict[str, str] = field(default_factory=dict)
    grep: list[str] = field(default_factory=list)


def parse_filters(rest: str) -> ShowFilters:
    """Parse ``--flag value`` pairs (and bare words -> grep) from a show argument."""
    acc = _Acc()
    tokens = rest.split()
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        flag = tok[2:] if tok.startswith("--") else ""
        if flag in _FLAGS and i + 1 < len(tokens):
            acc.values[flag] = tokens[i + 1]
            i += 2
            continue
        acc.grep.append(tok)
        i += 1
    limit_raw = acc.values.get("limit", "")
    limit = int(limit_raw) if limit_raw.isdigit() and int(limit_raw) > 0 else None
    grep = acc.values.get("grep", "") or " ".join(acc.grep)
    return ShowFilters(
        host=acc.values.get("host", ""),
        severity=acc.values.get("severity", ""),
        status=acc.values.get("status", ""),
        kind=acc.values.get("kind", ""),
        grep=grep,
        limit=limit,
    )


def _has(text: str, needle: str) -> bool:
    return needle.lower() in text.lower()


def _tail(rows: list, limit: int | None) -> list:  # type: ignore[type-arg]
    return rows[-limit:] if limit else rows


def filter_findings(rows: Sequence[FindingRow], f: ShowFilters) -> list[FindingRow]:
    """Filter findings: severity/status exact, host/grep contains."""
    out = list(rows)
    if f.severity:
        out = [r for r in out if r.severity.lower() == f.severity.lower()]
    if f.status:
        out = [r for r in out if r.status.lower() == f.status.lower()]
    if f.host:
        out = [r for r in out if _has(r.affected_host, f.host)]
    if f.grep:
        out = [r for r in out if _has(r.title, f.grep) or _has(r.affected_host, f.grep)]
    return _tail(out, f.limit)


def filter_loot(rows: Sequence[LootRow], f: ShowFilters) -> list[LootRow]:
    """Apply the parsed filters to loot (kind exact, host/grep contains over label)."""
    out = list(rows)
    if f.kind:
        out = [r for r in out if r.kind.lower() == f.kind.lower()]
    if f.host:
        out = [r for r in out if _has(r.host, f.host)]
    if f.grep:
        out = [r for r in out if _has(r.label, f.grep) or _has(r.kind, f.grep)]
    return _tail(out, f.limit)


def filter_notes(rows: Sequence[NoteRow], f: ShowFilters) -> list[NoteRow]:
    """Apply the parsed filters to notes (host contains, grep over subject + text)."""
    out = list(rows)
    if f.host:
        out = [r for r in out if _has(r.host, f.host)]
    if f.grep:
        out = [r for r in out if _has(r.text, f.grep) or _has(r.subject, f.grep)]
    return _tail(out, f.limit)
