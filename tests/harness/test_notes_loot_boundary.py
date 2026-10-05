"""L3: operator notes and loot reach the model by nature, never by value.

Notes and loot are now recalled into the agent's context (so it remembers what was
found), but as structured records whose free text is redacted at storage -- any
secret is vaulted to a ``«KIND:id»`` placeholder. This pins the boundary: a note
and a loot item containing a secret, then a full offline turn, and the secret must
not appear in any prompt the model received, while the item's nature does.
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
    built = AgentCore(offline_settings(tmp_path))
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
    core.journal.add_note(subject="exposure", text=f"stashed token {SECRET}")
    core.journal.add_loot(kind="token", host="web01", label=f"api {SECRET}")
    # Storage is structured and redacted: the secret is vaulted, not kept raw.
    assert SECRET not in core.journal.notes()
    assert SECRET not in core.journal.loot()

    list(core.turn("what is exposed?"))

    model = core.llm
    assert isinstance(model, RoleScriptedChatModel)
    all_prompts = "\n".join(m.text for _role, msgs in model.calls for m in msgs)
    assert all_prompts, "the model was never invoked"
    # The nature of the loot reached the model (recall works)...
    assert "web01" in all_prompts
    # ...but never the secret value itself.
    assert SECRET not in all_prompts
