"""skuggi's evaluation system.

A committed, local-only eval harness over the agent's five quality dimensions.
Two tiers, split by whether a pure oracle can decide the answer:

* **deterministic** -- ``compliance`` (the engagement guard + the phase machine),
  ``schema`` and ``result_compat`` (host-system compatibility). Scored offline
  against skuggi's own pure oracles, so these run in the default test suite and
  hard-gate CI against ``evals/baseline.json``.
* **quality** -- ``factuality`` (an in-house LLM judge, :mod:`skuggi.eval.judge`),
  ``budget`` and ``latency``. Need a real provider, so they are opt-in
  (``skuggi-eval`` / ``make bench``) and never block CI. They run across a
  configurable model matrix (:mod:`skuggi.eval.models`) and treat cross-model
  divergence as a regression (:mod:`skuggi.eval.divergence`).

Every run is local and framework-free: there is no eval SDK, nothing is uploaded,
and no third-party judge service is contacted -- the judge is skuggi's own
provider-agnostic chat model. The scorers (:mod:`skuggi.eval.scorers`) are pure,
so the deterministic gate stays inside the suite's ``filterwarnings = ["error"]``.
"""

from __future__ import annotations

DETERMINISTIC: tuple[str, ...] = (
    "compliance",
    "methodology",
    "schema",
    "result_compat",
)
QUALITY: tuple[str, ...] = ("factuality", "budget", "latency")
DIMENSIONS: tuple[str, ...] = DETERMINISTIC + QUALITY
