"""The agent turn loop and its transient per-turn state.

Owns the one-turn lifecycle: stream the compiled graph, translate each superstep
into operator-facing ``TurnEvent``s, and guarantee a bad turn yields an error event
rather than killing the front-end loop. Holds the in-flight turn's ledger event id
(so a proposed command links back to the prompt that drove it) and the full labeled
response (recorded to the timeline while the terminal sees only the clean answer).
A sibling sub-component: it reads the graph/ledger/session through ``core``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast

from langchain_core.messages import HumanMessage

from skuggi.agent.graph import recursion_limit
from skuggi.agent.protocol import render_answer
from skuggi.common.logs import get_logger
from skuggi.config.configs import ConfigError
from skuggi.engagement.engagement import parse_command

if TYPE_CHECKING:
    from collections.abc import Iterator

    from langchain_core.runnables import RunnableConfig

    from skuggi.agent.core import AgentCore
    from skuggi.agent.state import AgentState

log = get_logger(__name__)

EventKind = Literal["reset", "status", "token", "final"]


@dataclass(frozen=True, slots=True)
class TurnEvent:
    """One item streamed out of a turn.

    ``reset`` clears the draft buffer (a new pass or tool round begins),
    ``status`` is a one-line node update, ``token`` is an incremental worker
    token, ``final`` is the critic-approved draft that supersedes the buffer.
    """

    kind: EventKind
    text: str = ""
    node: str = ""


class TurnRunner:
    """Runs agent turns and session-audit writes for one session."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core
        # The prompt event id of the turn in flight, so commands the agent runs
        # link back to the directive that drove them. None between turns.
        self._current_turn_event_id: int | None = None
        # The full, labeled render of the turn in flight -- recorded to the ledger
        # (replay/review keep every field) while the terminal gets only the clean
        # answer. Set by ``_turn_updates`` when the worker answers; "" otherwise.
        self._last_full_response: str = ""

    @property
    def current_turn_event_id(self) -> int | None:
        """The ledger event id of the in-flight turn (``None`` between turns)."""
        return self._current_turn_event_id

    # ----- session logging ---------------------------------------------------

    def note_interaction(self, verb: str, detail: str = "") -> None:
        """Record a harness-control interaction to the audit log (not the timeline).

        Called by both front-ends for every ``control`` verb (config, mode,
        doctor, help, replay, review, ...). Engagement verbs (ask/run) are left
        out -- their activity is the timeline itself.
        """
        self._core.ledger.record_audit(
            session_id=self._core.session_id, kind="control", verb=verb, detail=detail
        )

    def record_passthrough(self, cmdline: str) -> None:
        """Log a free-typed shell command the operator ran (the wrapped shell).

        The operator's own commands are not vetoed (scope is not checked -- the
        honest boundary is that skuggi only *proposes* commands, guarded by the
        executor); this simply records what actually ran. Navigation/builtin noise
        (``settings.passthrough_skip``) goes to the audit ``cli`` channel; every
        other command lands on the engagement timeline as ``passthrough``.
        """
        raw = cmdline.strip()
        if not raw:
            return
        if raw.split()[0] in self._core.settings.passthrough_skip:
            self._core.ledger.record_audit(
                session_id=self._core.session_id, kind="cli", detail=raw
            )
            return
        parsed = parse_command(raw, self._core.registry)
        self._core.ledger.record_command(
            session_id=self._core.session_id,
            thread_id=self._core.thread_id,
            command=raw,
            binary=parsed.binary,
            method=parsed.method,
            status="passthrough",
        )

    # ----- the agent turn ----------------------------------------------------

    def _config(self) -> RunnableConfig:
        return {
            "configurable": {"thread_id": self._core.thread_id},
            "recursion_limit": recursion_limit(
                max_revisions=self._core.settings.max_revisions,
                max_command_rounds=self._core.settings.max_tool_rounds,
            ),
        }

    def state(self) -> AgentState:
        """The current graph state for the active thread."""
        values = self._core.graph.get_state(self._config()).values
        if isinstance(values, dict) and values:
            return cast("AgentState", values)
        return {"messages": []}

    def turn(self, user_text: str) -> Iterator[TurnEvent]:
        """Run one agent turn, yielding events as the graph streams.

        A bad turn yields a ``status`` error event rather than raising, so a
        front-end loop (REPL or daemon) is never killed by one failed turn.
        """
        initial: AgentState = {
            "messages": [HumanMessage(content=user_text)],
            "revision_count": 0,
            "max_revisions": self._core.settings.max_revisions,
        }
        # The prompt goes on the timeline first, and its id tags every command
        # this turn records (so a finding traces prompt -> command -> finding).
        self._current_turn_event_id = self._core.ledger.record_event(
            session_id=self._core.session_id,
            thread_id=self._core.thread_id,
            kind="prompt",
            text=user_text,
        )
        log.info("turn start thread=%s prompt=%r", self._core.thread_id, user_text)
        final_text = ""
        self._last_full_response = ""
        try:
            # Build the model on first use. A missing credential raises here and
            # is caught below, surfacing as a clean, actionable error event
            # (pointing at /setup) rather than a dead session.
            self._core.ensure_llm()
            # Structured output is not token-streamed; each node's state update is
            # turned into a status/final event as the graph advances.
            stream: Iterator[Any] = self._core.graph.stream(
                initial, self._config(), stream_mode="updates"
            )
            for payload in stream:
                for ev in self._turn_updates(cast("dict[str, object]", payload)):
                    if ev.kind == "final":
                        final_text = ev.text
                    yield ev
            # The turn is answered; now let the harness remember any standing
            # directive it carried (best-effort, never raises).
            for row in self._core.memory.maybe_capture(user_text):
                yield TurnEvent(
                    "status",
                    f"remembered: {row.text} (forget {row.id} to undo)",
                    node="memory",
                )
        except ConfigError as e:
            # A config/credential problem is already a full, actionable sentence
            # (e.g. "No OpenAI API key configured. Run /setup..."); show it as-is
            # rather than prefixing it with the exception class name.
            log.warning("turn aborted on config error: %s", e)
            final_text = f"[error] {e}"
            yield TurnEvent("status", str(e), node="error")
        except Exception as e:  # a bad turn must not kill the loop
            log.exception("turn failed")
            final_text = f"[error] {type(e).__name__}: {e}"
            yield TurnEvent("status", f"{type(e).__name__}: {e}", node="error")
        finally:
            # Close the turn on the timeline and stop tagging commands with it,
            # so a later /run proposal is recorded unlinked rather than misattributed.
            # This runs OUTSIDE the try above: a storage failure here must degrade
            # to a logged warning, never raise out of `turn` and kill the
            # front-end loop with the response already delivered.
            log.info(
                "turn response thread=%s answer=%r", self._core.thread_id, final_text
            )
            try:
                self._core.ledger.record_event(
                    session_id=self._core.session_id,
                    thread_id=self._core.thread_id,
                    kind="response",
                    # Keep the full, labeled render on the timeline so replay/review
                    # retain every field; the operator only ever saw the clean answer.
                    text=self._last_full_response or final_text,
                )
            except Exception:  # closing the timeline must not crash the loop
                log.exception("failed to record turn-closing response event")
            self._current_turn_event_id = None
            self._last_full_response = ""

    def _planner_events(self, values: dict[str, Any]) -> Iterator[TurnEvent]:
        """Emit the planner superstep's events.

        On a triaged direct answer the worker and critic never run, so this is the
        only place the terminal answer is emitted (``respond`` just commits
        ``draft`` to ``messages``); a conversational reply has no labeled render, so
        the clean answer is also what the turn-closing ledger event records.
        Otherwise the plan is internal scaffolding and only logged.
        """
        yield TurnEvent("reset")
        if values.get("plan_action") == "answer":
            answer = str(values.get("draft") or "")
            self._last_full_response = answer
            yield TurnEvent("final", answer)
            return
        steps = list(values.get("plan") or [])
        if steps:
            log.debug(
                "plan thread=%s steps=%s", self._core.thread_id, json.dumps(steps)
            )

    def _turn_updates(self, payload: dict[str, object]) -> Iterator[TurnEvent]:
        """Turn one graph superstep into operator events, logging the rest.

        Only the worker's answer reaches the terminal (as a ``final`` event); the
        planner plan, retrieval, executor command briefs and critic verdict are
        internal scaffolding -- they are logged to the diagnostic file (the full,
        structured worker object included) but never shown. Errors and the memory
        note stay operator-facing and are yielded by ``turn`` itself.
        """
        for node, update in payload.items():
            values = update if isinstance(update, dict) else {}
            if node == "planner":
                yield from self._planner_events(values)
            elif node == "retriever":
                if values.get("context"):
                    log.debug(
                        "retrieved context inlined thread=%s", self._core.thread_id
                    )
            elif node == "worker":
                yield TurnEvent("reset")
                worker = values.get("worker")
                if worker is not None:
                    log.debug(
                        "worker thread=%s response=%s",
                        self._core.thread_id,
                        worker.model_dump_json(),
                    )
                    # The full, labeled render stays in the ledger/history/critic;
                    # the terminal gets only the clean answer.
                    self._last_full_response = str(values.get("draft") or "")
                    yield TurnEvent("final", render_answer(worker))
                elif values.get("draft"):  # defensive: draft without the object
                    draft = str(values["draft"])
                    self._last_full_response = draft
                    yield TurnEvent("final", draft)
            elif node == "executor":
                commands = values.get("commands") or []
                if commands:
                    last = commands[-1]
                    log.debug(
                        "command thread=%s status=%s command=%r",
                        self._core.thread_id,
                        last.status,
                        last.command,
                    )
            elif node == "critic":
                approved = values.get("approved")
                reason = values.get("critique") or ""
                log.debug(
                    "critic thread=%s approved=%s reason=%r",
                    self._core.thread_id,
                    approved,
                    reason,
                )
