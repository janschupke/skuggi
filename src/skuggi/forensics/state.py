"""The forensics loop's LangGraph state.

A distinct channel schema from the OSINT/research states; all run on the same
checkpointer but under a ``forensics:<thread>`` namespace, so their channels never
interleave. Collection is deterministic and exhaustive (the analyzer battery over
the evidence), so there is no plan/replan channel -- just the collected ``results``
and the examiner's ``verdict``/``draft``. Acquisition and the procedure log live in
the case ledger (the source of truth the report reads back), not in state.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

from skuggi.forensics.schema import ForensicsVerdict
from skuggi.intel.schema import IntelResult


class _ForensicsChannels(TypedDict):
    """The one reducer channel; the rest are last-write-wins (see ForensicsState)."""

    messages: Annotated[Sequence[BaseMessage], add_messages]


class ForensicsState(_ForensicsChannels, total=False):
    """The forensics loop's working state (``total=False`` -- every field optional)."""

    request: str
    results: list[IntelResult]
    verdict: ForensicsVerdict | None
    draft: str
    done: bool
