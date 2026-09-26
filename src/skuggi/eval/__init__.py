"""skuggi's evaluation system.

A committed, local-only eval harness over the agent's five quality dimensions.
Two tiers, split by whether a pure oracle can decide the answer:

* **deterministic** -- ``compliance`` (the engagement guard + the phase machine),
  ``schema`` and ``result_compat`` (host-system compatibility). Scored offline
  against skuggi's own pure oracles, so these run in the default test suite and
  hard-gate CI against ``evals/baseline.json``.
* **quality** -- ``factuality`` (``autoevals.Factuality`` LLM judge), ``budget``
  and ``latency``. Need a real provider, so they are opt-in (``skuggi-eval`` /
  ``make bench``) and never block CI.

Every run is local: the Braintrust ``Eval`` in :mod:`skuggi.eval.runner` is always
invoked with ``no_send_logs=True`` and no experiment is ever uploaded. The
scorers (:mod:`skuggi.eval.scorers`) are pure and Braintrust-free so the
deterministic gate stays inside the suite's ``filterwarnings = ["error"]``.
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
