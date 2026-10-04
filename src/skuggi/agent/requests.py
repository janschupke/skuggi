"""Shared request-assembly + the structured-ask egress seam.

Both agent graphs -- the conversational turn graph (``skuggi.agent.graph``) and
the OSINT reconnaissance loop (``skuggi.osint.graph``) -- have to turn a rendered
request block into a validated structured response, under the same redaction
discipline. That seam used to live as a closure inside ``build_graph``; it is
hoisted here so the OSINT graph reuses it without importing the turn graph (the
import edge that would otherwise couple the two subsystems).

Everything here is request-shaping only: the conversation-history helpers (pure
string work over a message list) and the one generic :func:`ask` that scrubs a
rendered request and obtains a validated schema instance. It deliberately does
NOT know about ``GraphDeps``/``OsintDeps`` -- a caller binds the three plumbing
values (llm, policy, native) from whichever deps object it holds. ``scrub`` is
the egress net: ingress redaction already masked the free-text fields, and this
re-scans the whole assembled block so a detector gap degrades to an over-mask,
never a disclosure.
"""

from __future__ import annotations

from collections.abc import Sequence

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
)
from pydantic import BaseModel

from skuggi.agent.protocol import structured_invoke
from skuggi.security.policy import RedactionPolicy
from skuggi.security.tripwire import scrub


def last_user_text(messages: Sequence[BaseMessage]) -> str:
    """The most recent user message, as plain text."""
    for message in reversed(messages):
        if isinstance(message, HumanMessage):
            return message.text
    return ""


def prior_turns(messages: Sequence[BaseMessage]) -> list[BaseMessage]:
    """Completed conversation turns, excluding the request being answered.

    A graph is invoked with the new user message already appended, so the
    trailing human turn(s) are dropped. Only human and assistant messages are
    kept, so nothing but the conversation can reach a prompt.
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


def ask[T: BaseModel](  # noqa: PLR0913 -- the ask seam binds llm + request + policy plumbing
    llm: BaseChatModel | None,
    system: str,
    human_text: str,
    schema: type[T],
    *,
    policy: RedactionPolicy,
    native: bool,
    label: str = "",
) -> T:
    """Obtain a validated ``schema`` instance for one structured request.

    ``human_text`` is the already-rendered request block (e.g.
    ``render_request(ctx)``); it is scrubbed here -- the single egress point --
    before the call. ``native`` selects the provider path inside
    :func:`structured_invoke` (native ``with_structured_output`` vs the JSON
    contract + repair retry on the tool-less chatgpt path). ``label`` names the
    calling node for the per-turn latency breakdown (diagnostics only).
    """
    if llm is None:  # defensive: a caller builds the model before streaming
        msg = "no model provider configured; run /setup"
        raise RuntimeError(msg)
    prompt: list[BaseMessage] = [
        SystemMessage(content=system),
        HumanMessage(content=scrub(human_text, policy)),
    ]
    return structured_invoke(llm, schema, prompt, native=native, label=label)
