"""The OSINT loop's LangGraph state.

A separate channel schema from the turn graph's ``AgentState``: the two graphs run
on the same checkpointer but under different thread-id namespaces, so their channel
sets never interleave on one checkpoint. Accumulating channels (``completed`` /
``results``) follow the executor's single-writer-per-superstep discipline -- a node
reads the list, appends, and returns the whole list -- rather than a merge reducer,
so the walk stays checkpoint-resumable and the branches stay testable.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

from skuggi.osint.schema import OsintResult, OsintTask


class _OsintChannels(TypedDict):
    """The one reducer channel; the rest are last-write-wins (see OsintState)."""

    messages: Annotated[Sequence[BaseMessage], add_messages]


class OsintState(_OsintChannels, total=False):
    """The OSINT loop's working state (``total=False`` -- every field optional)."""

    request: str
    plan: list[OsintTask]
    completed: list[str]
    results: list[OsintResult]
    gaps: list[str]
    draft: str
    replan_count: int
    max_replans: int
    done: bool
