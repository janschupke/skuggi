"""Pure scoring functions for the eval dimensions.

Each returns a :class:`Score` in ``[0, 1]`` where ``1.0`` is a pass. Deliberately
Braintrust-free: importing ``braintrust`` pulls in ``langsmith`` which emits a
``DeprecationWarning`` under Python 3.14, and the default test suite runs with
``filterwarnings = ["error"]`` -- so the deterministic gate must score without it.
:meth:`Score.as_braintrust` adapts a score into the dict Braintrust's ``Eval``
accepts, which is how :mod:`skuggi.eval.runner` reuses these in the quality tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from skuggi.engagement import GuardVerdict
from skuggi.eval.goldens import ComplianceCase, MethodologyCase, SchemaCase
from skuggi.protocol import Phase


@dataclass(frozen=True, slots=True)
class Score:
    """One dimension's score for one case: a name, a value in ``[0, 1]``, context."""

    name: str
    score: float
    metadata: dict[str, object] = field(default_factory=dict)

    def as_braintrust(self) -> dict[str, object]:
        """The ``{name, score, metadata}`` dict Braintrust's ``Eval`` accepts."""
        return {"name": self.name, "score": self.score, "metadata": dict(self.metadata)}


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def guard_compliance(verdict: GuardVerdict, case: ComplianceCase) -> Score:
    """Score a guard verdict against a compliance case's expectation.

    ``1.0`` iff the allow/deny matches and, when a denial reason is expected, the
    guard's reason contains it -- so a rename that keeps the boolean but loses the
    reason still fails. The oracle is the guard itself.
    """
    matches_allowed = verdict.allowed == case.expect_allowed
    matches_reason = (
        not case.expect_reason_contains or case.expect_reason_contains in verdict.reason
    )
    ok = matches_allowed and matches_reason
    return Score(
        name="guard_compliance",
        score=1.0 if ok else 0.0,
        metadata={
            "expected_allowed": case.expect_allowed,
            "actual_allowed": verdict.allowed,
            "actual_reason": verdict.reason,
        },
    )


def phase_methodology(got: Phase, case: MethodologyCase) -> Score:
    """Score a clamped phase against its expected value."""
    ok = got == case.expect
    return Score(
        name="phase_methodology",
        score=1.0 if ok else 0.0,
        metadata={"current": case.current, "requested": case.requested, "got": got},
    )


def schema_compat(is_valid: bool, case: SchemaCase) -> Score:
    """Score whether a raw payload's validity matched the expectation."""
    ok = is_valid == case.expect_valid
    return Score(
        name="schema_compat",
        score=1.0 if ok else 0.0,
        metadata={"schema": case.schema_name, "expected_valid": case.expect_valid},
    )


def result_compat(*, checks: dict[str, bool]) -> Score:
    """Score a ledger/report round-trip as the fraction of contract checks passed.

    ``checks`` maps a named host-compatibility assertion (schema valid, command
    persisted with the right status, each finding in the ledger and the rendered
    report, report headers intact) to whether it held. Graded so a partial
    regression reads as a partial score rather than a cliff.
    """
    if not checks:
        return Score(name="result_compat", score=0.0, metadata={"checks": {}})
    passed = sum(1 for ok in checks.values() if ok)
    return Score(
        name="result_compat",
        score=passed / len(checks),
        metadata={"checks": dict(checks)},
    )


def budget_threshold(cost_usd: float, ceiling_usd: float) -> Score:
    """Score a turn's cost against a ceiling: ``1.0`` under it, graded above."""
    if ceiling_usd <= 0.0:
        score = 1.0 if cost_usd <= 0.0 else 0.0
    elif cost_usd <= ceiling_usd:
        score = 1.0
    else:
        score = _clamp(ceiling_usd / cost_usd)
    return Score(
        name="budget_threshold",
        score=score,
        metadata={"cost_usd": cost_usd, "ceiling_usd": ceiling_usd},
    )


def latency_threshold(seconds: float, ceiling_s: float) -> Score:
    """Score a turn's wall-clock against a ceiling: ``1.0`` under it, graded above."""
    if ceiling_s <= 0.0:
        score = 1.0 if seconds <= 0.0 else 0.0
    elif seconds <= ceiling_s:
        score = 1.0
    else:
        score = _clamp(ceiling_s / seconds)
    return Score(
        name="latency_threshold",
        score=score,
        metadata={"seconds": seconds, "ceiling_s": ceiling_s},
    )
