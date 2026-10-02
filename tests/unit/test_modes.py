"""L1: the mode prompt registry.

The role-dispatch phrase is load-bearing: tests.fakes.RoleScriptedChatModel
routes replies by finding "You are the {role}" in the system prompt, so this
pins that a reworded prompt cannot silently desync the whole eval layer.
"""

from __future__ import annotations

import pytest

from skuggi.agent.modes import MODES, prompt_set


def test_modes_are_exactly_the_three() -> None:
    assert set(MODES) == {"pentest", "redteam", "blueteam"}


@pytest.mark.parametrize("mode", MODES)
def test_every_prompt_keeps_its_role_dispatch_phrase(mode: str) -> None:
    ps = prompt_set(mode)  # type: ignore[arg-type]
    assert "You are the planner" in ps.planner
    assert "You are the worker" in ps.worker
    assert "You are the critic" in ps.critic


@pytest.mark.parametrize("mode", MODES)
def test_worker_prompts_describe_the_structured_contract(mode: str) -> None:
    worker = prompt_set(mode).worker  # type: ignore[arg-type]
    assert "`command`" in worker
    assert "`findings`" in worker
    assert "scope" in worker


@pytest.mark.parametrize("mode", MODES)
def test_planner_and_worker_carry_the_phase_stance_clause(mode: str) -> None:
    ps = prompt_set(mode)  # type: ignore[arg-type]
    assert "phase" in ps.planner
    assert "stance" in ps.worker
