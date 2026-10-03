"""The graph's shared state.

One message channel now, not two. ``messages`` is the user-visible conversation
-- real user turns and the approved rendered answer, nothing else -- and it is
what ``/history`` prints and what the planner and critic read as context.

The worker no longer calls tools in a graph cycle, so the old ``scratch`` channel
is gone. Its role is taken by typed scalar channels: the planner writes ``plan``
and ``phase``; the worker writes a validated ``worker`` (a
:class:`skuggi.protocol.WorkerResponse`) and the rendered ``draft``; the executor
guards/records the worker's command and appends a :class:`CommandBrief` to
``commands`` (the worker's memory of what has run this turn, and what ``/trace``
shows); the critic writes ``approved`` + ``critique``. Every one is checkpointed
each superstep, so the worker <-> executor loop stays resumable exactly as the old
tool cycle was.

The reducer key (``messages``) is always present in a node's input. The
``total=False`` keys are LastValue channels, absent until written, so they must be
read with ``.get()``.
"""

from __future__ import annotations

from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

from skuggi.agent.protocol import CommandBrief, Phase, WorkerResponse


class _MessageChannels(TypedDict):
    """Channels with reducers; always present in node input."""

    messages: Annotated[list[BaseMessage], add_messages]


class AgentState(_MessageChannels, total=False):
    """Full graph state. Non-reducer keys are absent until written."""

    phase: Phase
    # "answer" when the planner triaged the turn as a direct reply (routes
    # planner -> respond, skipping the pipeline), "plan" otherwise. Absent until
    # the planner writes it; read with .get().
    plan_action: str
    plan: list[str]
    context: str
    commands: list[CommandBrief]
    worker: WorkerResponse | None
    draft: str
    approved: bool
    critique: str
    revision_count: int
    max_revisions: int
    command_rounds: int


class PlanUpdate(TypedDict, total=False):
    """Written by the planner, which also resets the worker's per-turn channels.

    On a direct-answer turn the planner writes ``plan_action="answer"`` and the
    reply into ``draft`` (reusing the channel ``respond`` already emits), leaving
    ``plan`` empty; on a pipeline turn it writes ``plan_action="plan"`` and ``plan``.
    """

    plan_action: str
    plan: list[str]
    phase: Phase
    draft: str
    commands: list[CommandBrief]
    command_rounds: int


class ContextUpdate(TypedDict, total=False):
    """Written by the retrieval node; empty when it is a no-op."""

    context: str


class WorkerUpdate(TypedDict, total=False):
    """Written by the worker on each pass: the validated response + its render."""

    worker: WorkerResponse | None
    draft: str


class ExecutorUpdate(TypedDict, total=False):
    """Written by the executor: the growing command trail + the round counter."""

    commands: list[CommandBrief]
    command_rounds: int


class CritiqueUpdate(TypedDict, total=False):
    """Written by the critic: a boolean verdict, not a parsed prefix."""

    approved: bool
    critique: str


class ReplyUpdate(TypedDict, total=False):
    """Written by respond -- the only writer of the visible conversation."""

    messages: list[BaseMessage]


class RevisionUpdate(TypedDict, total=False):
    """Written by bump when the critic asks for another pass."""

    revision_count: int
