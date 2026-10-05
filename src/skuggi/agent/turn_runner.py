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
import time
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, cast

from langchain_core.messages import HumanMessage

from skuggi.agent.graph import recursion_limit
from skuggi.agent.protocol import render_answer
from skuggi.common.logs import get_logger
from skuggi.common.timing import TurnTiming, collect_turn_timing
from skuggi.config.configs import ConfigError
from skuggi.engagement.engagement import ParsedCommand, check_command, parse_command
from skuggi.engagement.risk import risk_tier

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


@dataclass(frozen=True, slots=True)
class TurnLatency:
    """The latency attribution of one completed turn (for ``show latency``).

    ``total_s`` is the whole turn's wall-clock; ``llm_s`` is the part spent inside
    model calls; ``by_node`` splits the model time across planner/worker/critic;
    ``calls`` and ``repairs`` count the round-trips (a repair is a doubled call on
    the tool-less path). The gap between ``total_s`` and ``llm_s`` is the harness's
    own work (retrieval, scrubbing, the executor).
    """

    total_s: float
    llm_s: float
    by_node: dict[str, float]
    calls: int
    repairs: int

    def summary(self) -> str:
        """A one-line human summary, slowest node first."""
        parts = ", ".join(
            f"{node} {secs:.1f}s"
            for node, secs in sorted(
                self.by_node.items(), key=lambda kv: kv[1], reverse=True
            )
        )
        tail = f" [{self.repairs} repair(s)]" if self.repairs else ""
        return f"{self.total_s:.1f}s total, {self.calls} call(s){tail}" + (
            f" -- {parts}" if parts else ""
        )


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
        # The latency attribution of the most recent turn, for ``show latency``.
        self._last_latency: TurnLatency | None = None

    @property
    def current_turn_event_id(self) -> int | None:
        """The ledger event id of the in-flight turn (``None`` between turns)."""
        return self._current_turn_event_id

    @property
    def last_latency(self) -> TurnLatency | None:
        """The latency breakdown of the most recent turn (``None`` before any)."""
        return self._last_latency

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
        reason, tier = self._attest_passthrough(parsed)
        self._core.ledger.record_command(
            session_id=self._core.session_id,
            thread_id=self._core.thread_id,
            command=raw,
            binary=parsed.binary,
            method=parsed.method,
            status="passthrough",
            reason=reason,
            risk_tier=tier,
            authority="passthrough",
        )

    def _attest_passthrough(self, parsed: ParsedCommand) -> tuple[str, str]:
        """Scope + risk attestation for an operator command (recorded, never blocked).

        The operator's shell is deliberately unguarded, but the trail should still
        say whether what they ran was in scope and how risky it was. Best-effort:
        any failure (no engagement loaded, an unknown binary) degrades to an empty
        note rather than disturbing the record of what actually ran.
        """
        engagement = self._core.engagement
        if engagement is None:
            return "", ""
        try:
            now = datetime.now(engagement.tzinfo())
            verdict = check_command(parsed, engagement, now=now)
            reason = (
                "in scope" if verdict.allowed else f"out of scope: {verdict.reason}"
            )
            spec = self._core.registry.spec_for(parsed.binary)
            return reason, risk_tier(spec, parsed.argv).name
        except Exception:  # noqa: BLE001 -- attestation must never break recording
            log.warning("passthrough attestation failed for %r", parsed.binary)
            return "", ""

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
        self._last_latency = None
        started = time.perf_counter()
        with collect_turn_timing() as timing:
            try:
                # Build the model on first use. A missing credential raises here
                # and is caught below, surfacing as a clean, actionable error event
                # (pointing at /setup) rather than a dead session.
                self._core.ensure_llm()
                # The planner always runs first; announce it up front so the
                # operator sees "planning..." while the first (silent) model call
                # is in flight, not a frozen spinner.
                yield TurnEvent("status", "planning", node="planner")
                # Structured output is not token-streamed; each node's state update
                # is turned into a status/final event as the graph advances.
                stream: Iterator[Any] = self._core.graph.stream(
                    initial, self._config(), stream_mode="updates"
                )
                for payload in stream:
                    for ev in self._turn_updates(cast("dict[str, object]", payload)):
                        if ev.kind == "final":
                            final_text = ev.text
                        yield ev
                # The turn is answered. Capturing any standing directive it carried
                # is a GATED write: the front-end runs the memory-capture flow
                # post-turn (preview + approval), because only it holds the operator
                # round-trip. The turn loop itself never writes memory.
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
                # so a later /run proposal is recorded unlinked, not misattributed.
                # This runs OUTSIDE the try above: a storage failure here must
                # degrade to a logged warning, never raise out of `turn` and kill
                # the front-end loop with the response already delivered.
                self._record_latency(time.perf_counter() - started, timing)
                log.info(
                    "turn response thread=%s answer=%r",
                    self._core.thread_id,
                    final_text,
                )
                try:
                    self._core.ledger.record_event(
                        session_id=self._core.session_id,
                        thread_id=self._core.thread_id,
                        kind="response",
                        # Keep the full, labeled render on the timeline so
                        # replay/review retain every field; the operator only ever
                        # saw the clean answer.
                        text=self._last_full_response or final_text,
                    )
                except Exception:  # closing the timeline must not crash the loop
                    log.exception("failed to record turn-closing response event")
                self._current_turn_event_id = None
                self._last_full_response = ""

    def _record_latency(self, total_s: float, timing: TurnTiming) -> None:
        """Summarise the turn's latency: store it, log it, and persist a metric.

        The per-node breakdown is the audit deliverable -- it says where a 20s
        turn spent its time (which model call, how many, how many repairs). Both
        the store and the ledger write must never raise out of the turn's
        ``finally`` (the answer is already delivered), so each is guarded.
        """
        latency = TurnLatency(
            total_s=total_s,
            llm_s=timing.llm_s,
            by_node=timing.by_node(),
            calls=timing.call_count,
            repairs=timing.repair_count,
        )
        self._last_latency = latency
        log.info("turn latency thread=%s %s", self._core.thread_id, latency.summary())
        try:
            self._core.ledger.record_audit(
                session_id=self._core.session_id,
                kind="metric",
                verb="latency",
                detail=json.dumps(
                    {
                        "total_s": round(latency.total_s, 3),
                        "llm_s": round(latency.llm_s, 3),
                        "calls": latency.calls,
                        "repairs": latency.repairs,
                        "by_node": {k: round(v, 3) for k, v in latency.by_node.items()},
                    }
                ),
            )
        except Exception:  # a metric write must never crash the loop
            log.exception("failed to record turn latency metric")

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

    def _turn_updates(  # noqa: PLR0912 -- one branch per graph node, each mapping a superstep to its event
        self, payload: dict[str, object]
    ) -> Iterator[TurnEvent]:
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
                # A plan (not a direct answer) means the worker call is the next
                # wait; label the spinner for it now rather than after it finishes.
                if values.get("plan_action") == "plan":
                    yield TurnEvent("status", "working", node="worker")
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
                # The critic vets a command or finding next; a pure advice reply
                # skips it (see route_after_executor), so only announce a review
                # that will actually happen rather than flashing a dead label.
                if worker is not None and (worker.command or worker.findings):
                    yield TurnEvent("status", "reviewing", node="critic")
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
                # A rejected draft loops back to the planner for another pass;
                # tell the operator a revision is starting rather than stalling.
                if approved is False:
                    yield TurnEvent("status", "revising", node="planner")
