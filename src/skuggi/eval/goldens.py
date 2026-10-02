"""Typed golden-set case models and their loader.

The committed corpora live under ``evals/goldens/*.json`` (one file per
dimension, each ``{"dimension", "description", "cases": [...]}``) and the shared
scope table under ``evals/scopes.json``. Every case is validated through a frozen
pydantic model here, so a malformed golden fails loudly at load rather than
mid-eval -- the same discipline ``skuggi.configs`` applies to case files.

Paths default to ``./evals`` (the harness is run from the repo root, like
``make``); a caller that runs from elsewhere passes an explicit ``root``.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from skuggi.engagement import EngagementConfig
from skuggi.protocol import Phase

DEFAULT_EVALS_DIR = Path("evals")


class _Case(BaseModel):
    """Common base: every case has a stable id used in reports and metadata."""

    model_config = ConfigDict(frozen=True)

    id: str


class ComplianceCase(_Case):
    """One (command x scope x time) guard-regression case."""

    scope_ref: str
    command: str
    now: str
    expect_allowed: bool
    expect_reason_contains: str = ""


class MethodologyCase(_Case):
    """One phase-machine case: ``clamp_phase(current, requested)`` must equal expect."""

    current: Phase
    requested: Phase | None = None
    expect: Phase


class SchemaCase(_Case):
    """One host-compatibility case: raw JSON (in)validates against a protocol schema."""

    schema_name: str
    raw: dict[str, object]
    expect_valid: bool


class ResultCompatCase(_Case):
    """One ledger/report round-trip: a scripted worker output driven through a turn."""

    scope_ref: str
    prompt: str
    worker: dict[str, object]
    expect_command_status: str | None = None
    expect_finding_titles: tuple[str, ...] = ()


class _QualityCase(_Case):
    """A quality-tier case: carries suite membership for the fast/full split.

    ``suites`` names the judge suites a case belongs to. ``fast`` is a curated,
    cheap subset; ``full`` is the comprehensive run. A case is run when the
    requested suite is in this list; the default is ``full`` only, so a case is
    opted into ``fast`` explicitly with ``["fast", "full"]``.
    """

    scope_ref: str
    prompt: str
    suites: tuple[str, ...] = ("full",)


class FactualityCase(_QualityCase):
    """One lab-knowledge case scored by an LLM judge against ``expected``."""

    expected: str


class BudgetCase(_QualityCase):
    """One turn whose token cost must stay under ``max_cost_usd``."""

    max_cost_usd: float


class LatencyCase(_QualityCase):
    """One turn whose wall-clock must stay under ``max_latency_s``."""

    max_latency_s: float


_MODELS: dict[str, type[_Case]] = {
    "compliance": ComplianceCase,
    "methodology": MethodologyCase,
    "schema": SchemaCase,
    "result_compat": ResultCompatCase,
    "factuality": FactualityCase,
    "budget": BudgetCase,
    "latency": LatencyCase,
}


class GoldenError(RuntimeError):
    """A golden file is missing or does not validate."""


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        msg = f"cannot read golden file {path}: {exc}"
        raise GoldenError(msg) from exc
    except json.JSONDecodeError as exc:
        msg = f"malformed JSON in golden file {path}: {exc}"
        raise GoldenError(msg) from exc


def load_scopes(root: Path = DEFAULT_EVALS_DIR) -> dict[str, EngagementConfig]:
    """Load the shared scope table (``evals/scopes.json``), name -> config."""
    data = _read_json(root / "scopes.json")
    if not isinstance(data, dict):
        msg = "scopes.json must be an object of name -> scope"
        raise GoldenError(msg)
    try:
        return {
            name: EngagementConfig.model_validate(body) for name, body in data.items()
        }
    except ValueError as exc:
        msg = f"invalid scope in scopes.json: {exc}"
        raise GoldenError(msg) from exc


def load_cases(dimension: str, root: Path = DEFAULT_EVALS_DIR) -> tuple[_Case, ...]:
    """Load and validate every case for ``dimension`` from its golden file."""
    model = _MODELS.get(dimension)
    if model is None:
        msg = f"unknown eval dimension: {dimension!r}"
        raise GoldenError(msg)
    data = _read_json(root / "goldens" / f"{dimension}.json")
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        msg = f"{dimension}.json must be an object with a 'cases' list"
        raise GoldenError(msg)
    try:
        return tuple(model.model_validate(case) for case in data["cases"])
    except ValueError as exc:
        msg = f"invalid case in {dimension}.json: {exc}"
        raise GoldenError(msg) from exc
