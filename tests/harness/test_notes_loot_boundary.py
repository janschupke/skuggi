"""L3: operator notes and loot are model-invisible.

The audit found no code path from the notes/loot journals into an LLM request
(only the operator console and the on-disk dashboard read them). This pins that:
a note and a loot entry containing a secret, then a full offline turn, and the
secret must not appear in any prompt the model received.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from skuggi.agent.core import AgentCore
from skuggi.agent.protocol import CriticResponse, WorkerResponse
from tests.conftest import offline_settings, wire_offline_core
from tests.fakes import RoleScriptedChatModel

SECRET = "ghp_1234567890abcdefABCDEF1234567890abcd"


@pytest.fixture
def core(tmp_path: Path, pentest_configs: Callable[..., Path]) -> Iterator[AgentCore]:
    pentest_configs()
    built = AgentCore(offline_settings(tmp_path, engagement="test-eng"))
    wire_offline_core(
        built,
        worker=RoleScriptedChatModel(
            worker_replies=[WorkerResponse(summary="ok")],
            critic_replies=[CriticResponse(approved=True, reason="ok")],
        ),
    )
    yield built
    built.close()


def test_note_and_loot_secrets_never_reach_a_prompt(core: AgentCore) -> None:
    core.journal.add_note(f"stashed token {SECRET}")
    core.journal.add_loot(f"cred admin:{SECRET}")
    # The journals really do hold the secret (storage is fine)...
    assert SECRET in core.journal.notes()
    assert SECRET in core.journal.loot()

    list(core.turn("what is exposed?"))

    model = core.llm
    assert isinstance(model, RoleScriptedChatModel)
    all_prompts = "\n".join(m.text for _role, msgs in model.calls for m in msgs)
    assert all_prompts, "the model was never invoked"
    assert SECRET not in all_prompts
