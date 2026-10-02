"""L3: the session boots without a chat credential and defers the model.

The regression: `skuggi` used to die at construction when no provider was
credentialed, which made every "remedy" in the error (switch provider, run
setup) unreachable. Boot must now degrade to a warning and build the model
lazily, so the operator lands in a usable session where they can fix it.
"""

from __future__ import annotations

from pathlib import Path

from skuggi.core import AgentCore
from tests.conftest import offline_settings


def _openai_without_a_key(tmp_path: Path) -> AgentCore:
    # offline_settings isolates every path under tmp; isolate_credentials (autouse)
    # strips the vendor keys and points auth.json at an absent file. Switching the
    # provider to openai therefore leaves it genuinely uncredentialed.
    settings = offline_settings(tmp_path).model_copy(update={"provider": "openai"})
    return AgentCore(settings)


def test_boot_without_credentials_warns_and_defers(tmp_path: Path) -> None:
    core = _openai_without_a_key(tmp_path)
    try:
        assert core.llm is None
        assert any("/setup" in w for w in core.warnings)
        # The graph is still built (around a deferred model), so state reads work.
        assert core.graph is not None
    finally:
        core.close()


def test_turn_without_a_model_yields_a_clean_error_event(tmp_path: Path) -> None:
    core = _openai_without_a_key(tmp_path)
    try:
        events = list(core.turn("scan the host"))
        # The turn does not raise; it surfaces an actionable error event instead.
        assert any(ev.node == "error" for ev in events)
        assert core.llm is None  # still deferred; nothing silently half-built
    finally:
        core.close()
