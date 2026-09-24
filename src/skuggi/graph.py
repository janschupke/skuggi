"""planner -> retriever -> worker <-> tools -> finalize -> critic graph.

The worker's tool calling is a real graph cycle rather than a loop inside one
node, so every intermediate assistant message and tool result is checkpointed
and a crash mid-loop is resumable. Its working set lives in the ``scratch``
channel; see ``skuggi.state`` for why that is separate from ``messages``.

Retrieval happens two ways. Providers that can bind tools get a ``retrieve``
tool. Providers that cannot (chatgpt) get a top-k snippet inlined ahead of the
worker by the ``retriever`` node, so ``/ingest`` is useful on every provider.

``respond`` is the only node that writes to ``messages``, which is what keeps a
revised turn from persisting several drafts for one user question.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    RemoveMessage,
    SystemMessage,
)
from langchain_core.tools import BaseTool
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import REMOVE_ALL_MESSAGES
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode

from skuggi.modes import PromptSet, prompt_set
from skuggi.state import (
    AgentState,
    ContextUpdate,
    CritiqueUpdate,
    DraftUpdate,
    PlanUpdate,
    ReplyUpdate,
    RevisionUpdate,
    WorkerUpdate,
)
from skuggi.text import join_blocks, labeled
from skuggi.vectorstore import Store, format_hits

_APPROVED = "APPROVED"
_BUDGET_EXHAUSTED = (
    "(the worker used its whole tool budget without producing an answer)"
)


@dataclass(frozen=True, slots=True)
class GraphDeps:
    """Everything `build_graph` needs, bundled so the signature stays small."""

    llm: BaseChatModel
    tools: Sequence[BaseTool] = field(default_factory=tuple)
    store: Store | None = None
    bind_tools: bool = True
    max_tool_rounds: int = 4
    retrieve_k: int = 4
    history_messages: int = 8
    history_chars: int = 4_000
    # The mode's prompts. Defaults to pentest so an unset caller still gets a
    # coherent (and role-dispatchable) set; the REPL passes the active mode's.
    prompts: PromptSet = field(default_factory=lambda: prompt_set("pentest"))


# --- prompt assembly --------------------------------------------------------


def last_user_text(messages: Sequence[BaseMessage]) -> str:
    """The most recent user message, as plain text."""
    for message in reversed(messages):
        if isinstance(message, HumanMessage):
            return message.text
    return ""


def prior_turns(messages: Sequence[BaseMessage]) -> list[BaseMessage]:
    """Completed conversation turns, excluding the request being answered.

    The graph is invoked with the new user message already appended, so the
    trailing human turn(s) are dropped. Only human and assistant messages are
    kept, so nothing from the worker's scratch can reach a prompt.
    """
    kept: list[BaseMessage] = [
        m for m in messages if isinstance(m, (HumanMessage, AIMessage))
    ]
    while kept and isinstance(kept[-1], HumanMessage):
        kept.pop()
    return kept


def render_history(
    messages: Sequence[BaseMessage], *, max_messages: int, max_chars: int
) -> str:
    """Render recent turns as text, bounded by both message count and size.

    Both bounds are needed: a turn count alone is unbounded in size (one pasted
    stack trace fills the context), and a character budget alone would slice a
    message mid-sentence. Whole messages are dropped from the oldest end.
    """
    if max_messages <= 0 or max_chars <= 0:
        return ""
    window = list(messages)[-max_messages:]
    lines = [
        f"{'user' if isinstance(m, HumanMessage) else 'assistant'}: {m.text}"
        for m in window
    ]
    while len(lines) > 1 and sum(len(line) + 1 for line in lines) > max_chars:
        lines.pop(0)
    return "\n".join(lines)


def _pick_draft(scratch: Sequence[BaseMessage]) -> str:
    """The last assistant message with real text.

    Walking backwards matters: when the tool budget runs out the final scratch
    entry is a tool result, and returning that would hand raw tool output to the
    critic as though it were the answer.
    """
    for message in reversed(scratch):
        if isinstance(message, AIMessage) and message.text.strip():
            return message.text
    return _BUDGET_EXHAUSTED


# --- routing ----------------------------------------------------------------


def wants_tools(state: AgentState, *, max_tool_rounds: int) -> bool:
    """Whether the worker asked for a tool and still has budget."""
    scratch = state["scratch"]
    last = scratch[-1] if scratch else None
    if not isinstance(last, AIMessage) or not last.tool_calls:
        return False
    return (state.get("tool_rounds") or 0) < max_tool_rounds


def route_after_critic(state: AgentState) -> Literal["bump", "respond"]:
    """Send an approved draft to the user, otherwise spend a revision."""
    critique = (state.get("critique") or "").strip()
    if critique.startswith(_APPROVED):
        return "respond"
    if (state.get("revision_count") or 0) >= (state.get("max_revisions") or 0):
        return "respond"
    return "bump"


# --- graph ------------------------------------------------------------------


def build_graph(
    deps: GraphDeps, checkpointer: BaseCheckpointSaver[str]
) -> CompiledStateGraph[AgentState]:
    """Compile the agent graph.

    `deps.bind_tools=False` removes the tools node entirely, which is the
    chatgpt path: that endpoint does not accept LangChain's tool schema.
    """
    worker_llm = (
        deps.llm.bind_tools(deps.tools) if deps.bind_tools and deps.tools else deps.llm
    )
    tool_node = (
        ToolNode(list(deps.tools), messages_key="scratch")
        if deps.bind_tools and deps.tools
        else None
    )

    def history(state: AgentState, *, divisor: int = 1) -> str:
        return render_history(
            prior_turns(state["messages"]),
            max_messages=deps.history_messages,
            max_chars=deps.history_chars // divisor,
        )

    def plan_node(state: AgentState) -> PlanUpdate:
        prompt = [
            SystemMessage(content=deps.prompts.planner),
            HumanMessage(
                content=join_blocks(
                    labeled("Conversation so far", history(state)),
                    labeled("Request", last_user_text(state["messages"])),
                    labeled("Prior critique", state.get("critique") or ""),
                )
            ),
        ]
        return {
            "plan": deps.llm.invoke(prompt).text,
            # Reset the worker's working set for this pass. `add_messages`
            # ignores an empty list, so clearing requires this sentinel -- which
            # is also the only thing that clears scratch left by a crashed run.
            "scratch": [RemoveMessage(id=REMOVE_ALL_MESSAGES)],
            "tool_rounds": 0,
        }

    def retrieve_node(state: AgentState) -> ContextUpdate:
        """Inline a retrieval snippet for providers that cannot call tools."""
        if tool_node is not None or deps.store is None:
            return {}
        hits = deps.store.search(last_user_text(state["messages"]), k=deps.retrieve_k)
        return {"context": format_hits(hits)} if hits else {}

    def work_node(state: AgentState) -> WorkerUpdate:
        scratch = state["scratch"]
        if not scratch:
            seed: list[BaseMessage] = [
                SystemMessage(content=deps.prompts.worker),
                HumanMessage(
                    content=join_blocks(
                        labeled("Conversation so far", history(state)),
                        labeled("Retrieved context", state.get("context") or ""),
                        labeled("Request", last_user_text(state["messages"])),
                        labeled("Plan", state.get("plan") or ""),
                    )
                ),
            ]
            return {"scratch": [*seed, worker_llm.invoke(seed)]}
        return {
            "scratch": [worker_llm.invoke(scratch)],
            "tool_rounds": (state.get("tool_rounds") or 0) + 1,
        }

    def finalize_node(state: AgentState) -> DraftUpdate:
        return {"draft": _pick_draft(state["scratch"])}

    def critique_node(state: AgentState) -> CritiqueUpdate:
        prompt = [
            SystemMessage(content=deps.prompts.critic),
            HumanMessage(
                content=join_blocks(
                    labeled("Conversation so far", history(state, divisor=2)),
                    labeled("Request", last_user_text(state["messages"])),
                    labeled("Draft", state.get("draft") or ""),
                )
            ),
        ]
        return {"critique": deps.llm.invoke(prompt).text}

    def respond_node(state: AgentState) -> ReplyUpdate:
        return {"messages": [AIMessage(content=state.get("draft") or "")]}

    def bump_node(state: AgentState) -> RevisionUpdate:
        return {"revision_count": (state.get("revision_count") or 0) + 1}

    def route_worker(state: AgentState) -> Literal["tools", "finalize"]:
        return (
            "tools"
            if wants_tools(state, max_tool_rounds=deps.max_tool_rounds)
            else "finalize"
        )

    graph: StateGraph[AgentState, None, AgentState, AgentState] = StateGraph(AgentState)
    graph.add_node("planner", plan_node)
    graph.add_node("retriever", retrieve_node)
    graph.add_node("worker", work_node)
    graph.add_node("finalize", finalize_node)
    graph.add_node("critic", critique_node)
    graph.add_node("respond", respond_node)
    graph.add_node("bump", bump_node)

    graph.add_edge(START, "planner")
    graph.add_edge("planner", "retriever")
    graph.add_edge("retriever", "worker")
    if tool_node is not None:
        graph.add_node("tools", tool_node)
        graph.add_conditional_edges("worker", route_worker)
        graph.add_edge("tools", "worker")
    else:
        graph.add_edge("worker", "finalize")
    graph.add_edge("finalize", "critic")
    graph.add_conditional_edges("critic", route_after_critic)
    graph.add_edge("bump", "planner")
    graph.add_edge("respond", END)
    return graph.compile(checkpointer=checkpointer)


def recursion_limit(*, max_revisions: int, max_tool_rounds: int) -> int:
    """Supersteps needed for the worst-case turn, plus headroom.

    One pass is planner + retriever + worker + 2 per tool round + finalize +
    critic + bump/respond. The default of 25 is not enough for a turn that both
    uses tools and gets revised, which would raise GraphRecursionError.
    """
    per_pass = 2 * max_tool_rounds + 6
    return (max_revisions + 1) * per_pass + 4
