"""The research loop's LangGraph state.

A separate channel schema from the OSINT ``OsintState`` and the turn graph's
``AgentState``: all three run on the same checkpointer but under different thread-id
namespaces, so their channel sets never interleave on one checkpoint. The
accumulating channels (``completed`` / ``results``) follow the same single-writer-
per-superstep discipline -- a node reads the list, appends, returns the whole list.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

from skuggi.intel.schema import IntelResult
from skuggi.research.schema import ResearchProfile, ResearchTask


class _ResearchChannels(TypedDict):
    """The one reducer channel; the rest are last-write-wins (see ResearchState)."""

    messages: Annotated[Sequence[BaseMessage], add_messages]


class ResearchState(_ResearchChannels, total=False):
    """The research loop's working state (``total=False`` -- every field optional)."""

    request: str
    plan: list[ResearchTask]
    completed: list[str]
    results: list[IntelResult]
    gaps: list[str]
    draft: str
    profile: ResearchProfile | None
    replan_count: int
    max_replans: int
    done: bool
