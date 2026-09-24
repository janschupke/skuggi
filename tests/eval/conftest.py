"""L4 fixtures. This is the only layer that talks to real providers.

Everything here is marked `eval`, which the default addopts deselect, and which
also exempts these tests from the autouse isolation and network-block fixtures.
Assertions check behavioural *properties*, never exact strings: a real model is
nondeterministic, and a test that demands one wording is a test that fails for
the wrong reason.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.memory import InMemorySaver

from skuggi.config import Provider, Settings
from skuggi.graph import GraphDeps, build_graph, recursion_limit
from skuggi.providers import get_chat_model, get_embeddings, resolve_openai_key
from skuggi.state import AgentState
from skuggi.tools import build_tools
from skuggi.vectorstore import Store


def _ollama_reachable(settings: Settings) -> bool:
    try:
        return httpx.get(f"{settings.ollama_base_url}/api/tags", timeout=2.0).is_success
    except httpx.HTTPError:
        return False


def require(provider: Provider) -> Settings:
    """Return settings for `provider`, skipping if it is not usable here."""
    settings = Settings(provider=provider)
    if provider == "openai" and not resolve_openai_key(settings):
        pytest.skip("no OpenAI API key")
    if provider == "anthropic" and settings.anthropic_api_key is None:
        pytest.skip("ANTHROPIC_API_KEY is not set")
    if provider == "ollama" and not _ollama_reachable(settings):
        pytest.skip(f"no Ollama server at {settings.ollama_base_url}")
    if provider == "chatgpt" and not settings.auth_json().is_file():
        pytest.skip("no ~/.codex/auth.json")
    return settings


# The codex endpoint serves only models the ChatGPT account is licensed for, and
# refuses everything else with this phrase. That is an account-entitlement fact
# about the environment, not a defect, so it skips rather than fails -- matched
# narrowly so any other provider error still surfaces as a failure.
_NOT_ENTITLED = "not supported when using Codex"


@pytest.fixture
def run_turn(tmp_path: Path) -> Callable[..., AgentState]:
    """Run one real agent turn and return the final state."""

    def _run(
        settings: Settings,
        *prompts: str,
        ingest: str | None = None,
        max_revisions: int = 1,
    ) -> AgentState:
        store = Store(tmp_path / "faiss", get_embeddings(settings))
        if ingest is not None:
            doc = tmp_path / "kb.md"
            doc.write_text(ingest, encoding="utf-8")
            store.ingest([doc])
        deps = GraphDeps(
            llm=get_chat_model(settings),
            tools=build_tools(store, root=tmp_path),
            store=store,
            bind_tools=settings.supports_tools(),
            max_tool_rounds=settings.max_tool_rounds,
        )
        app = build_graph(deps, InMemorySaver())
        config = {
            "configurable": {"thread_id": "eval"},
            "recursion_limit": recursion_limit(
                max_revisions=max_revisions,
                max_tool_rounds=settings.max_tool_rounds,
            ),
        }
        state: AgentState = {"messages": [], "scratch": []}
        for prompt in prompts:
            try:
                state = app.invoke(
                    {
                        "messages": [HumanMessage(content=prompt)],
                        "scratch": [],
                        "revision_count": 0,
                        "max_revisions": max_revisions,
                        "tool_rounds": 0,
                    },
                    config,
                )
            except Exception as exc:
                if _NOT_ENTITLED in str(exc):
                    pytest.skip(f"{settings.provider}: {exc}")
                raise
        return state

    return _run


def answer(state: AgentState) -> str:
    """The assistant's final reply, lowercased for tolerant matching."""
    replies = [m for m in state["messages"] if isinstance(m, AIMessage)]
    return replies[-1].text.lower() if replies else ""


def tool_names(state: AgentState) -> list[str]:
    """Tools the worker actually invoked this pass."""
    return [
        call["name"]
        for message in state["scratch"]
        if isinstance(message, AIMessage)
        for call in message.tool_calls
    ]
