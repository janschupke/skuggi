"""Deterministic CVSS v3.1 scoring.

A faithful, dependency-free implementation of the FIRST CVSS v3.1 specification
(https://www.first.org/cvss/v3.1/specification-document, section 7 formulae). The
whole point of this module is that **scoring is arithmetic, not judgement**: given
a vector string, the Base / Temporal / Environmental scores are fully determined,
so a stored ``(version, vector)`` pair reconstructs every number without any model
turn or network. The only judgement is choosing the metric *values* -- done by the
worker or the operator -- and that choice is captured verbatim in the vector.

Scope of the metric groups (see :class:`skuggi.engagement.engagement`):
- **Base** is always computable from the eight mandatory metrics.
- **Temporal** applies when any of E/RL/RC is set (on demand).
- **Environmental** applies when a per-engagement threat model sets the security
  requirements (CR/IR/AR) and/or modified base metrics.

``overall`` reports the most specific group that carries non-default metrics, which
is what a CVSS calculator shows as *the* score.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Final

VERSION: Final = "3.1"
_PREFIX: Final = f"CVSS:{VERSION}/"

# Qualitative severity rating scale (spec 5, table 14): the lower bound of each band.
_LOW_MIN: Final = 0.1
_MEDIUM_MIN: Final = 4.0
_HIGH_MIN: Final = 7.0
_CRITICAL_MIN: Final = 9.0


class CvssError(ValueError):
    """Raised for a malformed or incomplete CVSS v3.1 vector."""


# --- metric value tables (spec section 7.4) ---------------------------------

_AV: Final = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC: Final = {"L": 0.77, "H": 0.44}
_UI: Final = {"N": 0.85, "R": 0.62}
# Privileges Required is scope-dependent: a changed scope raises the weight of the
# low/high levels because crossing a boundary with some privilege is worth more.
_PR_UNCHANGED: Final = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED: Final = {"N": 0.85, "L": 0.68, "H": 0.50}
_CIA: Final = {"H": 0.56, "L": 0.22, "N": 0.00}

_E: Final = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
_RL: Final = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
_RC: Final = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}
_REQ: Final = {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5}  # CR / IR / AR

# metric code -> the set of value codes it accepts. Modified base metrics (M*)
# accept their base values plus "X" (= "use the base metric").
_BASE: Final = {
    "AV": set(_AV),
    "AC": set(_AC),
    "PR": {"N", "L", "H"},
    "UI": set(_UI),
    "S": {"U", "C"},
    "C": set(_CIA),
    "I": set(_CIA),
    "A": set(_CIA),
}
_TEMPORAL: Final = {"E": set(_E), "RL": set(_RL), "RC": set(_RC)}
_ENVIRONMENTAL: Final = {
    "CR": set(_REQ),
    "IR": set(_REQ),
    "AR": set(_REQ),
    "MAV": set(_AV) | {"X"},
    "MAC": set(_AC) | {"X"},
    "MPR": {"N", "L", "H", "X"},
    "MUI": set(_UI) | {"X"},
    "MS": {"U", "C", "X"},
    "MC": set(_CIA) | {"X"},
    "MI": set(_CIA) | {"X"},
    "MA": set(_CIA) | {"X"},
}
_ALL: Final = {**_BASE, **_TEMPORAL, **_ENVIRONMENTAL}
# Preserves the canonical metric order for re-serialising a vector.
_ORDER: Final = (
    "AV", "AC", "PR", "UI", "S", "C", "I", "A",
    "E", "RL", "RC",
    "CR", "IR", "AR",
    "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
)  # fmt: skip


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest one-decimal number >= value.

    Implemented on integers scaled by 1e5 exactly as the spec's reference code, so
    floating-point noise (e.g. 4.0000000001) cannot push a score up a tenth. The
    ``floor(x + 0.5)`` matches the reference ``Math.round`` (half-up) rather than
    Python's bankers' rounding.
    """
    scaled = math.floor(value * 100_000 + 0.5)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


@dataclass(frozen=True, slots=True)
class Score:
    """The computed scores for a vector; ``overall`` is the applicable one."""

    version: str
    vector: str
    base: float
    temporal: float | None
    environmental: float | None
    overall: float
    severity: str


@dataclass(frozen=True, slots=True)
class Cvss:
    """A parsed, validated CVSS v3.1 vector.

    Construct via :func:`parse`. The metric map holds only the codes present in the
    vector; ``get`` falls back to ``"X"`` (Not Defined) for any absent optional
    metric, which is how the formulae treat them.
    """

    metrics: dict[str, str]

    def get(self, code: str) -> str:
        """The vector's value for ``code``, or ``"X"`` (Not Defined) when absent."""
        return self.metrics.get(code, "X")

    # -- subscore helpers ----------------------------------------------------

    def _pr(self, *, scope: str, metric: str, value: str) -> float:
        table = _PR_CHANGED if scope == "C" else _PR_UNCHANGED
        return table[value if value != "X" else self.metrics[metric]]

    def base_score(self) -> float:
        """Base score from the eight mandatory metrics (spec 7.1)."""
        scope = self.metrics["S"]
        iss = 1 - (1 - _CIA[self.metrics["C"]]) * (1 - _CIA[self.metrics["I"]]) * (
            1 - _CIA[self.metrics["A"]]
        )
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        exploitability = (
            8.22
            * _AV[self.metrics["AV"]]
            * _AC[self.metrics["AC"]]
            * self._pr(scope=scope, metric="PR", value=self.metrics["PR"])
            * _UI[self.metrics["UI"]]
        )
        if impact <= 0:
            return 0.0
        raw = (
            impact + exploitability
            if scope == "U"
            else 1.08 * (impact + exploitability)
        )
        return _roundup(min(raw, 10.0))

    def _temporal_mult(self) -> float:
        return _E[self.get("E")] * _RL[self.get("RL")] * _RC[self.get("RC")]

    def temporal_score(self) -> float:
        """Temporal score: base dampened by exploit-maturity/remediation/confidence."""
        return _roundup(self.base_score() * self._temporal_mult())

    def environmental_score(self) -> float:
        """Environmental score (spec 7.3): the modified base, under the threat model."""
        ms = self.get("MS")
        scope = self.metrics["S"] if ms == "X" else ms
        cr, ir, ar = _REQ[self.get("CR")], _REQ[self.get("IR")], _REQ[self.get("AR")]
        mc = _CIA[self._mod("MC", "C")]
        mi = _CIA[self._mod("MI", "I")]
        ma = _CIA[self._mod("MA", "A")]
        miss = min(1 - (1 - cr * mc) * (1 - ir * mi) * (1 - ar * ma), 0.915)
        if scope == "U":
            modified_impact = 6.42 * miss
        else:
            modified_impact = (
                7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
            )
        modified_expl = (
            8.22
            * _AV[self._mod("MAV", "AV")]
            * _AC[self._mod("MAC", "AC")]
            * self._pr(scope=scope, metric="PR", value=self.get("MPR"))
            * _UI[self._mod("MUI", "UI")]
        )
        if modified_impact <= 0:
            return 0.0
        combined = (
            modified_impact + modified_expl
            if scope == "U"
            else 1.08 * (modified_impact + modified_expl)
        )
        return _roundup(_roundup(min(combined, 10.0)) * self._temporal_mult())

    def _mod(self, modified: str, base: str) -> str:
        """A modified metric's effective code: itself, or the base when Not Defined."""
        value = self.get(modified)
        return self.metrics[base] if value == "X" else value

    def has_temporal(self) -> bool:
        """Whether any temporal metric (E/RL/RC) is set, so a temporal score applies."""
        return any(self.get(m) != "X" for m in _TEMPORAL)

    def has_environmental(self) -> bool:
        """Whether any environmental metric is set, enabling an environmental score."""
        return any(self.get(m) != "X" for m in _ENVIRONMENTAL)

    def score(self) -> Score:
        """Every score plus the applicable ``overall`` and its severity band."""
        base = self.base_score()
        temporal = self.temporal_score() if self.has_temporal() else None
        environmental = self.environmental_score() if self.has_environmental() else None
        overall = (
            environmental
            if environmental is not None
            else temporal
            if temporal is not None
            else base
        )
        return Score(
            version=VERSION,
            vector=serialize(self),
            base=base,
            temporal=temporal,
            environmental=environmental,
            overall=overall,
            severity=severity_band(overall),
        )


def severity_band(score: float) -> str:
    """Map a 0.0-10.0 score to its qualitative band (spec 5, table 14)."""
    if score < _LOW_MIN:
        return "none"
    if score < _MEDIUM_MIN:
        return "low"
    if score < _HIGH_MIN:
        return "medium"
    if score < _CRITICAL_MIN:
        return "high"
    return "critical"


def parse(vector: str) -> Cvss:
    """Parse and validate a ``CVSS:3.1/...`` vector string.

    Rejects a wrong/absent version prefix, an unknown metric or value, a repeated
    metric, and any missing mandatory base metric -- so a vector that parses is one
    the formulae can score.
    """
    text = vector.strip()
    if not text.startswith(_PREFIX):
        msg = f"vector must start with {_PREFIX!r}: {vector!r}"
        raise CvssError(msg)
    metrics: dict[str, str] = {}
    for part in text[len(_PREFIX) :].split("/"):
        if not part:
            msg = f"empty metric segment in {vector!r}"
            raise CvssError(msg)
        code, sep, value = part.partition(":")
        if not sep:
            msg = f"malformed metric {part!r} in {vector!r}"
            raise CvssError(msg)
        if code not in _ALL:
            msg = f"unknown metric {code!r} in {vector!r}"
            raise CvssError(msg)
        if code in metrics:
            msg = f"duplicate metric {code!r} in {vector!r}"
            raise CvssError(msg)
        if value not in _ALL[code]:
            msg = f"invalid value {value!r} for metric {code!r} in {vector!r}"
            raise CvssError(msg)
        metrics[code] = value
    missing = [code for code in _BASE if code not in metrics]
    if missing:
        msg = f"missing mandatory base metric(s) {missing} in {vector!r}"
        raise CvssError(msg)
    return Cvss(metrics=metrics)


def serialize(cvss: Cvss) -> str:
    """Re-render a vector in canonical metric order (dropping Not-Defined values)."""
    body = "/".join(
        f"{code}:{cvss.metrics[code]}"
        for code in _ORDER
        if code in cvss.metrics and cvss.metrics[code] != "X"
    )
    return _PREFIX + body


def score(vector: str) -> Score:
    """Parse ``vector`` and return its full :class:`Score` -- the public entry point."""
    return parse(vector).score()
