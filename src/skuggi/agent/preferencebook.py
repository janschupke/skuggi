"""Harness memory -- operator preferences -- for the ``memory`` verb (``core.memory``).

A sub-component of :class:`~skuggi.agent.core.AgentCore`. Preferences are
snapshotted into ``GraphDeps`` at build time, so any change must rebuild the
core's graph for the next turn to see it; that is the one private-kernel reach
(``_rebuild``). It reads the live ``prefs`` store, ``llm`` and ``settings`` off
the core each call.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from langchain_core.messages import HumanMessage, SystemMessage

from skuggi.agent import prompts
from skuggi.agent.protocol import MemoryExtraction, structured_invoke
from skuggi.common import logs
from skuggi.persistence import preferences

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

log = logs.get_logger(__name__)


def _summarize_capture(
    stored: list[preferences.PreferenceRow],
    refused: list[str],
    maximum: int,
) -> str:
    """The operator-facing line after an approved capture: what was and wasn't kept."""
    parts: list[str] = []
    if stored:
        ids = ", ".join(f"[{row.id}] {row.text}" for row in stored)
        parts.append(f"remembered: {ids}")
    if refused:
        skipped = "; ".join(refused)
        parts.append(
            f"memory at capacity ({maximum}); not remembered: {skipped} "
            "-- make room with `remove memory`"
        )
    if not parts:  # everything was a duplicate of something already stored
        return "nothing new to remember"
    return "\n".join(parts)


class PreferenceBook:
    """Lists, edits and auto-captures the operator's standing preferences."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core

    def _rebuild(self) -> None:
        """Rebuild the core's graph so the next turn sees the preference change."""
        self._core.rebuild_graph()

    def entries(self) -> list[preferences.PreferenceRow]:
        """Every remembered operator preference (grouped by category)."""
        return self._core.prefs.all()

    def add(
        self, text: str, *, source: str = "manual"
    ) -> preferences.PreferenceRow | None:
        """Remember one preference, rebuilding the graph so the next turn sees it.

        Returns the stored row, or ``None`` if it was blank or a duplicate.
        """
        row = self._core.prefs.add(text, source=source)
        if row is not None:
            self._rebuild()
        return row

    def forget(self, pref_id: int) -> bool:
        """Drop one preference by id; ``True`` if it existed. Rebuilds the graph."""
        removed = self._core.prefs.forget(pref_id)
        if removed:
            self._rebuild()
        return removed

    def clear(self) -> int:
        """Drop every preference; returns how many. Rebuilds the graph if any."""
        removed = self._core.prefs.clear()
        if removed:
            self._rebuild()
        return removed

    def propose_capture(self, user_text: str) -> list[str]:
        """Extract any standing directive in `user_text` -- WITHOUT persisting it.

        The in-loop evaluator's first half, run post-turn: gated first by the cheap
        `preferences.looks_like_directive` heuristic (so an ordinary request never
        spends a model call), then by a one-shot structured extraction (a strict
        ``MemoryExtraction``, which works on every provider including the tool-less
        chatgpt one via the JSON-contract fallback). Returns the candidate directive
        strings (normalized, deduped against each other) for a front-end to preview
        and gate; writing is :meth:`apply_capture`, only after the operator approves.
        Never raises -- a capture failure must not break the turn.
        """
        core = self._core
        if not core.settings.memory_auto or not preferences.looks_like_directive(
            user_text
        ):
            return []
        if core.llm is None:  # no model configured; nothing to extract with
            return []
        try:
            extraction = structured_invoke(
                core.llm,
                MemoryExtraction,
                [
                    SystemMessage(content=prompts.MEMORY_EXTRACTION_INSTRUCTION),
                    HumanMessage(content=user_text),
                ],
                native=core.settings.supports_structured_output(),
            )
        except Exception:  # best-effort; a failure is not fatal
            log.exception("preference extraction failed; capturing nothing this turn")
            return []
        seen: set[str] = set()
        candidates: list[str] = []
        for directive in extraction.directives:
            text = directive.strip()
            key = text.lower()
            if text and key not in seen:
                seen.add(key)
                candidates.append(text)
        return candidates

    def apply_capture(self, candidates: list[str]) -> str:
        """Persist approved capture `candidates` (source ``auto``); return a summary.

        Enforces the capacity cap by REFUSING, never evicting: once the store is at
        ``settings.memory_max`` the remaining candidates are reported as skipped so
        the operator can make room with ``remove memory``. Rebuilds the graph if
        anything was stored (so the next turn's snapshot sees it). The returned line
        is what the gated flow shows the operator.
        """
        core = self._core
        maximum = core.settings.memory_max
        stored: list[preferences.PreferenceRow] = []
        refused: list[str] = []
        for text in candidates:
            cleaned = text.strip()
            if not cleaned:
                continue
            if core.prefs.count() >= maximum:
                refused.append(cleaned)
                continue
            row = core.prefs.add(cleaned, source="auto")
            if row is not None:
                stored.append(row)
        if stored:
            self._rebuild()
        return _summarize_capture(stored, refused, maximum)
