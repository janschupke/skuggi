"""Each result_compat golden case: a scripted worker output round-trips the host.

Drives the scripted output through a real (offline) AgentCore turn and checks the
command + findings reached the SQLite ledger and the Markdown report contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.engagement import EngagementConfig
from skuggi.eval.goldens import ResultCompatCase, load_cases
from skuggi.eval.runner import score_result_compat_case
from tests.eval_det.conftest import EVALS_ROOT

_CASES = [
    c
    for c in load_cases("result_compat", EVALS_ROOT)
    if isinstance(c, ResultCompatCase)
]


@pytest.mark.parametrize("case", _CASES, ids=lambda c: c.id)
def test_result_compat_case(
    case: ResultCompatCase,
    scopes: dict[str, EngagementConfig],
    registry_path: Path,
    tmp_path: Path,
) -> None:
    score = score_result_compat_case(
        case, scopes, tmp=tmp_path, registry_path=registry_path
    )
    assert score.score == 1.0, score.metadata
