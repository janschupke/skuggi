"""planner -> worker -> critic StateGraph with a critic-driven revision loop.

The worker binds tools when supported (openai/anthropic/ollama) and runs as a
plain generator when not (chatgpt). When tools are unavailable, the planner is
asked to call ``retrieve`` itself by inlining a top-k snippet ahead of work.
"""

from __future__ import annotations

from typing import Literal

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import BaseTool
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from skuggi.state import AgentState

_PLANNER_PROMPT = (
    "You are the planner. Given the user request (and any prior critique), "
    "produce a short numbered plan (3-6 steps) describing exactly what the "
    "worker should do. Reply with the plan only."
)
_WORKER_PROMPT = (
    "You are the worker. Follow the plan and answer the user. "
    "Call tools when useful. Reply with the final draft answer."
)
_CRITIC_PROMPT = (
    "You are the critic. Evaluate the worker's draft against the user's "
    "original request. If it is good, reply exactly:\n"
    "  APPROVED: <one-line reason>\n"
    "Otherwise reply:\n"
    "  REVISE: <specific actionable issue>"
)


def _last_user(messages: list[BaseMessage]) -> str:
    for m in reversed(messages):
        if isinstance(m, HumanMessage):
            return m.content if isinstance(m.content, str) else str(m.content)
    return ""


def build_graph(
    llm: BaseChatModel,
    tools: list[BaseTool],
    checkpointer: BaseCheckpointSaver,
    *,
    bind_tools: bool = True,
):
    """Compile the planner-worker-critic graph.

    ``bind_tools=False`` disables tool calling on the worker (used for the
    chatgpt provider, whose endpoint does not accept LangChain's tool schema).
    """

    worker_llm = llm.bind_tools(tools) if bind_tools and tools else llm
    tool_node = ToolNode(tools) if bind_tools and tools else None

    def plan_node(state: AgentState) -> dict:
        user = _last_user(state["messages"])
        prior = state.get("critique") or ""
        prompt = [
            SystemMessage(content=_PLANNER_PROMPT),
            HumanMessage(content=f"Request: {user}\n\nPrior critique: {prior or '(none)'}"),
        ]
        out = llm.invoke(prompt)
        text = out.content if isinstance(out.content, str) else str(out.content)
        return {"plan": text}

    def work_node(state: AgentState) -> dict:
        user = _last_user(state["messages"])
        plan = state.get("plan") or ""
        msgs: list[BaseMessage] = [
            SystemMessage(content=_WORKER_PROMPT),
            HumanMessage(content=f"Request: {user}\n\nPlan:\n{plan}"),
        ]
        # tool-calling loop (cap to keep things bounded)
        for _ in range(6):
            ai = worker_llm.invoke(msgs)
            msgs.append(ai)
            calls = getattr(ai, "tool_calls", None) or []
            if not calls or tool_node is None:
                draft = ai.content if isinstance(ai.content, str) else str(ai.content)
                return {
                    "draft": draft,
                    "messages": [AIMessage(content=draft)],
                }
            tool_out = tool_node.invoke({"messages": [ai]})
            msgs.extend(tool_out["messages"])
        last = msgs[-1]
        draft = last.content if isinstance(last.content, str) else str(last.content)
        return {"draft": draft, "messages": [AIMessage(content=draft)]}

    def critique_node(state: AgentState) -> dict:
        user = _last_user(state["messages"])
        draft = state.get("draft") or ""
        prompt = [
            SystemMessage(content=_CRITIC_PROMPT),
            HumanMessage(content=f"Request: {user}\n\nDraft:\n{draft}"),
        ]
        out = llm.invoke(prompt)
        text = out.content if isinstance(out.content, str) else str(out.content)
        return {"critique": text}

    def should_revise(state: AgentState) -> Literal["planner", "__end__"]:
        critique = (state.get("critique") or "").strip()
        if critique.startswith("APPROVED"):
            return "__end__"
        if state.get("revision_count", 0) >= state.get("max_revisions", 2):
            return "__end__"
        return "planner"

    def bump_revision(state: AgentState) -> dict:
        # invoked implicitly via the edge back to planner -- we update the
        # counter here through a tiny passthrough node.
        return {"revision_count": state.get("revision_count", 0) + 1}

    graph = StateGraph(AgentState)
    graph.add_node("planner", plan_node)
    graph.add_node("worker", work_node)
    graph.add_node("critic", critique_node)
    graph.add_node("bump", bump_revision)
    graph.add_edge(START, "planner")
    graph.add_edge("planner", "worker")
    graph.add_edge("worker", "critic")
    graph.add_conditional_edges(
        "critic",
        lambda s: "__end__" if should_revise(s) == "__end__" else "bump",
        {"__end__": END, "bump": "bump"},
    )
    graph.add_edge("bump", "planner")
    return graph.compile(checkpointer=checkpointer)
