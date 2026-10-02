"""Session replay and private review for the ``replay``/``review`` verbs.

A sub-component of :class:`~skuggi.agent.core.AgentCore` (``core.archive``). It
reads the live ledger off the core each call -- important because
``load_engagement`` hot-swaps the ledger, and a cached handle would render or
review the pre-swap database.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skuggi.agent import prompts
from skuggi.common.text import join_blocks, labeled
from skuggi.persistence import transcript as transcript_mod
from skuggi.providers import providers

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore
    from skuggi.persistence.ledger import SessionRow

# How much captured command output to feed the reviewer per command -- enough to
# judge what happened without blowing the prompt budget on a noisy scan dump.
_REVIEW_OUTPUT_CAP = 2_000


class SessionArchive:
    """Lists, renders and reviews recorded sessions from the live ledger."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core

    def sessions(self) -> list[SessionRow]:
        """Every session recorded in this engagement's ledger, newest first."""
        return self._core.ledger.sessions()

    def _resolve(self, ref: str | None) -> str | None:
        """Resolve a session reference (full id or short prefix) to a session id.

        An empty reference means the current session; otherwise the first session
        whose id equals or starts with `ref` (the short ids ``replay list`` shows).
        ``None`` when nothing matches.
        """
        core = self._core
        if not ref:
            return core.session_id
        for row in core.ledger.sessions():
            if row.session_id == ref or row.session_id.startswith(ref):
                return row.session_id
        return None

    def _render(
        self, session_ref: str | None, *, max_output: int | None
    ) -> tuple[str | None, str]:
        """Resolve a session and render its transcript; shared by replay + review.

        Returns ``(session_id, text)``; ``session_id`` is ``None`` (and `text` an
        error message) when the reference matches no session.
        """
        core = self._core
        sid = self._resolve(session_ref)
        if sid is None:
            return None, f"no session found for {session_ref!r}"
        session = core.ledger.session(sid)
        if session is None:  # pragma: no cover -- a resolved id always has a row
            return None, f"no session recorded for {sid!r}"
        events = core.ledger.events_for(sid)
        commands = {c.id: c for c in core.ledger.commands_for(sid)}
        findings = {f.id: f for f in core.ledger.findings_for(sid)}
        text = transcript_mod.render_transcript(
            session, events, commands, findings, max_output=max_output
        )
        return sid, text

    def transcript(self, session_ref: str | None = None) -> str:
        """The ordered, replayable transcript of a session (default: current)."""
        return self._render(session_ref, max_output=None)[1]

    def review(self, session_ref: str | None = None) -> str:
        """Ask the LLM for private feedback on a session, and audit-log it.

        Reads the session timeline, prompts the model (one-shot ``invoke``, so it
        works on every provider, including the tool-less chatgpt one), records the
        critique to the audit log (never the client-facing report), and returns
        it. ``settings.review_model`` overrides the model used.
        """
        core = self._core
        sid, timeline = self._render(session_ref, max_output=_REVIEW_OUTPUT_CAP)
        if sid is None:
            return timeline  # the "no session" message
        prompt = join_blocks(
            prompts.REVIEW_INSTRUCTION,
            labeled("Session timeline", timeline, heading=True),
        )
        llm = (
            core._ensure_llm()  # noqa: SLF001 -- sub-component drives the core's model kernel
            if core.settings.review_model is None
            else providers.get_chat_model(
                core.settings, model=core.settings.review_model
            )
        )
        reply = llm.invoke(prompt)
        content = str(getattr(reply, "content", reply))
        core.ledger.record_audit(
            session_id=core.session_id, kind="review", detail=content
        )
        return content
