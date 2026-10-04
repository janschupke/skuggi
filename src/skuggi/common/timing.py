"""Per-turn LLM latency accounting, collected without threading an accumulator.

A chat turn runs several structured LLM calls in sequence (planner, worker,
critic -- plus a repair retry on the tool-less chatgpt path), and the operator's
complaint is that a turn takes 20+ seconds with no idea *where* the time goes.
This module is the measurement seam: :func:`structured_invoke` records each call
here, and :class:`~skuggi.agent.turn_runner.TurnRunner` opens a collector around
the turn and reads the attribution back out at the end.

The collector is held in a :class:`~contextvars.ContextVar` rather than passed
through the ``ask`` -> ``requests.ask`` -> ``structured_invoke`` call chain: the
timing is pure cross-cutting diagnostics, so it must not change those return
types, and a context var is the right tool for a value scoped to one in-flight
turn. Turns are serialized under the daemon lock (one at a time against the warm
core), and a context var is per-thread besides, so there is no cross-turn
contamination. :func:`record_call` is a no-op when no collector is active, so the
eval harness, the OSINT graph and unit tests that call the model outside a turn
pay nothing and see nothing.
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class CallTiming:
    """One structured LLM call: its node label, wall-clock, and repair flag."""

    label: str
    elapsed_s: float
    repaired: bool


@dataclass(slots=True)
class TurnTiming:
    """The LLM calls made during one turn, in order, for per-node attribution."""

    calls: list[CallTiming] = field(default_factory=list)

    def record(self, label: str, elapsed_s: float, *, repaired: bool) -> None:
        """Append one call's timing."""
        self.calls.append(CallTiming(label or "llm", elapsed_s, repaired))

    def by_node(self) -> dict[str, float]:
        """Total LLM seconds per node label (summed over repeats/revisions)."""
        totals: dict[str, float] = {}
        for call in self.calls:
            totals[call.label] = totals.get(call.label, 0.0) + call.elapsed_s
        return totals

    @property
    def llm_s(self) -> float:
        """Total wall-clock spent inside LLM calls this turn."""
        return sum(call.elapsed_s for call in self.calls)

    @property
    def call_count(self) -> int:
        """How many model round-trips the turn made (repairs included)."""
        return len(self.calls)

    @property
    def repair_count(self) -> int:
        """How many of those calls were JSON-contract repair retries."""
        return sum(1 for call in self.calls if call.repaired)


_current: contextvars.ContextVar[TurnTiming | None] = contextvars.ContextVar(
    "skuggi_turn_timing", default=None
)


@contextmanager
def collect_turn_timing() -> Iterator[TurnTiming]:
    """Activate a fresh collector for the duration of one turn.

    The token is reset on exit so a turn can never leak its collector to the next
    (or, under the threading daemon, to another connection's turn).
    """
    timing = TurnTiming()
    token = _current.set(timing)
    try:
        yield timing
    finally:
        _current.reset(token)


def record_call(label: str, elapsed_s: float, *, repaired: bool) -> None:
    """Record one LLM call against the active turn collector, if any.

    A no-op outside a turn (no collector set), so callers that invoke the model
    off the turn path -- the eval harness, tests -- are unaffected.
    """
    timing = _current.get()
    if timing is not None:
        timing.record(label, elapsed_s, repaired=repaired)
