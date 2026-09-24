"""The graph's shared state.

Two message channels, deliberately separate:

``messages`` is the user-visible conversation -- real user turns and approved
answers, nothing else. It is what ``/history`` prints and what the planner and
critic read as context.

``scratch`` is the worker's tool-calling working set: its system prompt, the
seeded request, every intermediate assistant message carrying tool calls, and
every tool result. Keeping it in its own channel is what lets the tool loop be
a real graph cycle (so every step is checkpointed) without the worker's own
prompt scaffolding leaking into the conversation -- a seeded HumanMessage is
otherwise indistinguishable from a real user turn.

The reducer keys are always present in a node's input. The ``total=False`` keys
are LastValue channels and are absent until something writes them, so they must
be read with ``.get()``.
"""

from __future__ import annotations

from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class _MessageChannels(TypedDict):
    """Channels with reducers; always present in node input."""

    messages: Annotated[list[BaseMessage], add_messages]
    scratch: Annotated[list[BaseMessage], add_messages]


class AgentState(_MessageChannels, total=False):
    """Full graph state. Non-reducer keys are absent until written."""

    plan: str
    context: str
    draft: str
    critique: str
    revision_count: int
    max_revisions: int
    tool_rounds: int


class PlanUpdate(TypedDict, total=False):
    """Written by the planner, which also resets the worker's scratch."""

    plan: str
    scratch: list[BaseMessage]
    tool_rounds: int


class ContextUpdate(TypedDict, total=False):
    """Written by the retrieval node; empty when it is a no-op."""

    context: str


class WorkerUpdate(TypedDict, total=False):
    """Written by the worker on each pass through the tool cycle."""

    scratch: list[BaseMessage]
    tool_rounds: int


class DraftUpdate(TypedDict, total=False):
    """Written by finalize once the worker stops calling tools."""

    draft: str


class CritiqueUpdate(TypedDict, total=False):
    """Written by the critic."""

    critique: str


class ReplyUpdate(TypedDict, total=False):
    """Written by respond -- the only writer of the visible conversation."""

    messages: list[BaseMessage]


class RevisionUpdate(TypedDict, total=False):
    """Written by bump when the critic asks for another pass."""

    revision_count: int
