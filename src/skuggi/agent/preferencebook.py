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


class PreferenceBook:
    """Lists, edits and auto-captures the operator's standing preferences."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core

    def _rebuild(self) -> None:
        """Rebuild the core's graph so the next turn sees the preference change."""
        self._core.graph = self._core._build()  # noqa: SLF001 -- prefs re-snapshot into GraphDeps

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

    def maybe_capture(self, user_text: str) -> list[preferences.PreferenceRow]:
        """Automatically capture any standing directive in `user_text`.

        Harness-side automatic memory, run post-turn: gated first by the cheap
        `preferences.looks_like_directive` heuristic (so an ordinary request never
        spends a model call), then by a one-shot structured extraction (a strict
        ``MemoryExtraction``, which works on every provider including the tool-less
        chatgpt one via the JSON-contract fallback). Persists each captured
        directive with source ``auto`` and returns the rows actually stored
        (deduped). Never raises -- a capture failure must not break the turn.
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
        captured: list[preferences.PreferenceRow] = []
        for directive in extraction.directives:
            text = directive.strip()
            if not text:
                continue
            row = core.prefs.add(text, source="auto")
            if row is not None:
                captured.append(row)
        if captured:
            self._rebuild()
        return captured
