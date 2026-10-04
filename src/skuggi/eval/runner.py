"""Runs the deterministic eval dimensions and aggregates per-dimension results.

Pure Python, no framework, no network: scores ``compliance`` / ``methodology`` /
``schema`` / ``result_compat`` against skuggi's own oracles. This is what the
default test suite and ``skuggi-eval --tier det`` run, and what the CI gate is
built on. The quality tier (a real provider, scored by the same in-house
:class:`~skuggi.eval.scorers.Score` helpers) lives in :mod:`skuggi.eval.quality`,
imported only when that tier is requested.

The per-case ``score_*`` helpers are exposed so the pytest tier can parametrize
one named test per golden case while sharing the exact scoring logic.
"""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError

from skuggi.agent.protocol import (
    CriticResponse,
    FindingDraft,
    Phase,
    PlannerResponse,
    WorkerResponse,
    clamp_phase,
)
from skuggi.common.logs import get_logger
from skuggi.common.paths import packaged_template
from skuggi.config.configs import load_registry
from skuggi.engagement.engagement import EngagementConfig, check_command, parse_command
from skuggi.eval import DETERMINISTIC
from skuggi.eval.baseline import DimensionResult
from skuggi.eval.goldens import (
    ComplianceCase,
    MethodologyCase,
    ResultCompatCase,
    SchemaCase,
    load_cases,
    load_scopes,
)
from skuggi.eval.offline import build_offline_core
from skuggi.eval.scorers import (
    Score,
    guard_compliance,
    phase_methodology,
    result_compat,
    schema_compat,
)
from skuggi.persistence.reports import render_report
from skuggi.tooling.registry import ToolRegistry

log = get_logger(__name__)

DEFAULT_REGISTRY = packaged_template("tools.example.json")

_SCHEMAS: dict[str, type[BaseModel]] = {
    "WorkerResponse": WorkerResponse,
    "PlannerResponse": PlannerResponse,
    "CriticResponse": CriticResponse,
    "FindingDraft": FindingDraft,
}
_REPORT_HEADERS = ("# Engagement report", "## Findings", "## Command log")


# --- per-case scorers (shared by the pytest tier and the aggregator) --------


def score_compliance_case(
    case: ComplianceCase,
    registry: ToolRegistry,
    scopes: dict[str, EngagementConfig],
) -> Score:
    """Guard the case's command against its scope and score the verdict."""
    scope = scopes[case.scope_ref]
    parsed = parse_command(case.command, registry)
    now = datetime.fromisoformat(case.now)
    if now.tzinfo is None:
        # The guard compares against timezone-aware bounds; a naive fixture clock
        # would otherwise surface as an opaque TypeError deep in check_command.
        msg = f"compliance case {case.id!r}: 'now' must be timezone-aware: {case.now!r}"
        raise ValueError(msg)
    verdict = check_command(parsed, scope, now=now)
    return guard_compliance(verdict, case)


def score_methodology_case(case: MethodologyCase) -> Score:
    """Clamp the case's phase transition and score it."""
    got: Phase = clamp_phase(case.current, case.requested)
    return phase_methodology(got, case)


def score_schema_case(case: SchemaCase) -> Score:
    """Validate the raw payload against its named schema and score the outcome."""
    schema = _SCHEMAS[case.schema_name]
    try:
        schema.model_validate(case.raw)
        is_valid = True
    except ValidationError as exc:
        log.info("schema case %s failed validation: %s", case.schema_name, exc)
        is_valid = False
    return schema_compat(is_valid, case)


def score_result_compat_case(
    case: ResultCompatCase,
    scopes: dict[str, EngagementConfig],
    *,
    tmp: Path,
    registry_path: Path = DEFAULT_REGISTRY,
) -> Score:
    """Drive the scripted worker output through a real turn; score the round-trip."""
    scope = scopes[case.scope_ref]
    worker = WorkerResponse.model_validate(case.worker)
    core = build_offline_core(scope, tmp, worker, registry_path=registry_path)
    try:
        list(core.turn(case.prompt))
        commands = core.ledger.commands_for(core.session_id)
        findings = core.ledger.findings_for(core.session_id)
        session = core.ledger.session(core.session_id)
        assert session is not None  # noqa: S101 -- the turn started the session
        report = render_report(session, commands, findings, engagement=core.engagement)
    finally:
        core.close()

    checks: dict[str, bool] = {"worker_schema_valid": True}
    if case.expect_command_status is not None:
        checks["command_status"] = bool(commands) and (
            commands[-1].status == case.expect_command_status
        )
    for title in case.expect_finding_titles:
        checks[f"finding_in_ledger:{title}"] = any(f.title == title for f in findings)
        checks[f"finding_in_report:{title}"] = title in report
    checks["report_headers"] = all(h in report for h in _REPORT_HEADERS)
    return result_compat(checks=checks)


# --- deterministic aggregation ----------------------------------------------


def aggregate(dimension: str, scores: Sequence[Score]) -> DimensionResult:
    """Mean of the case scores as one dimension result.

    Case ``Score`` metadata is otherwise dropped on aggregation; the latency
    attribution (``by_node``/``calls``/``repairs``) is summed across cases into
    the dimension's ``metadata`` so the scorecard can report where the time went.
    Dimensions that carry no such metadata aggregate to an empty mapping.
    """
    mean = sum(s.score for s in scores) / len(scores) if scores else 0.0
    return DimensionResult(
        dimension=dimension,
        score=mean,
        n_cases=len(scores),
        metadata=_aggregate_latency_metadata(scores),
    )


def _num(value: object) -> float:
    """Coerce an untyped ``Score.metadata`` value to a float (0.0 if not numeric)."""
    return float(value) if isinstance(value, (int, float)) else 0.0


def _aggregate_latency_metadata(scores: Sequence[Score]) -> dict[str, object]:
    """Sum any per-node latency attribution across a dimension's case scores."""
    by_node: dict[str, float] = {}
    calls = 0.0
    repairs = 0.0
    seconds = 0.0
    found = False
    for score in scores:
        split = score.metadata.get("by_node")
        if not isinstance(split, dict):
            continue
        found = True
        for node, secs in split.items():
            by_node[str(node)] = by_node.get(str(node), 0.0) + _num(secs)
        calls += _num(score.metadata.get("calls"))
        repairs += _num(score.metadata.get("repairs"))
        seconds += _num(score.metadata.get("seconds"))
    if not found:
        return {}
    return {
        "by_node": by_node,
        "calls": int(calls),
        "repairs": int(repairs),
        "seconds": seconds,
    }


def evaluate_deterministic(
    root: Path,
    *,
    registry_path: Path = DEFAULT_REGISTRY,
    dimensions: Sequence[str] = DETERMINISTIC,
) -> dict[str, DimensionResult]:
    """Score every deterministic dimension offline; return one result per dimension.

    A caller running outside the repo root (the tests chdir) passes an absolute
    ``root`` (the ``evals`` dir) and ``registry_path``.
    """
    reg = load_registry(registry_path)
    scopes = load_scopes(root)
    results: dict[str, DimensionResult] = {}
    for dim in dimensions:
        cases = load_cases(dim, root)
        scores: list[Score] = []
        if dim == "compliance":
            scores = [
                score_compliance_case(c, reg, scopes)
                for c in cases
                if isinstance(c, ComplianceCase)
            ]
        elif dim == "methodology":
            scores = [
                score_methodology_case(c)
                for c in cases
                if isinstance(c, MethodologyCase)
            ]
        elif dim == "schema":
            scores = [score_schema_case(c) for c in cases if isinstance(c, SchemaCase)]
        elif dim == "result_compat":
            for c in cases:
                if not isinstance(c, ResultCompatCase):
                    continue
                with tempfile.TemporaryDirectory() as td:
                    scores.append(
                        score_result_compat_case(
                            c, scopes, tmp=Path(td), registry_path=registry_path
                        )
                    )
        results[dim] = aggregate(dim, scores)
    return results
