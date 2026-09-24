from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    plan: str | None
    draft: str | None
    critique: str | None
    revision_count: int
    max_revisions: int
