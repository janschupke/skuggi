"""Offline stand-ins for the LLM and embedding providers.

Nothing here touches the network. `ScriptedChatModel` is a real
`BaseChatModel` subclass rather than a `Mock` so the graph exercises the
actual LangChain invoke path, and so the type checker holds the fake to the
same interface as a real provider.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Any

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.embeddings import Embeddings
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult

EMBED_DIM = 8


class CountingFakeEmbeddings(Embeddings):
    """Deterministic embeddings derived from character counts.

    Deliberately not based on ``hash()``: that is salted per process via
    PYTHONHASHSEED, so a hash-derived fake produces a FAISS index that is not
    reproducible across runs and the persist/reload test would pass or fail
    depending on the interpreter's mood.
    """

    def __init__(self, dim: int = EMBED_DIM) -> None:
        self.dim = dim
        self.embed_documents_calls = 0
        self.embed_query_calls = 0

    def _vector(self, text: str) -> list[float]:
        buckets = [0.0] * self.dim
        for char in text:
            buckets[ord(char) % self.dim] += 1.0
        norm = sum(value * value for value in buckets) ** 0.5
        if norm == 0.0:
            return [1.0] + [0.0] * (self.dim - 1)
        return [value / norm for value in buckets]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        self.embed_documents_calls += 1
        return [self._vector(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        self.embed_query_calls += 1
        return self._vector(text)


class ScriptedChatModel(BaseChatModel):
    """Returns queued replies in order and records the prompts it was given.

    ``calls`` is what lets a test assert *what reached the prompt* rather than
    only what came out -- which is the only way to prove conversation history
    and retrieved context actually get threaded through.
    """

    replies: list[str | AIMessage] = []
    calls: list[list[BaseMessage]] = []
    tools_bound: list[str] = []

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def _next(self, messages: list[BaseMessage]) -> AIMessage:
        self.calls.append(list(messages))
        if not self.replies:
            msg = "ScriptedChatModel was invoked with no replies queued"
            raise AssertionError(msg)
        index = min(len(self.calls) - 1, len(self.replies) - 1)
        reply = self.replies[index]
        if isinstance(reply, AIMessage):
            return reply
        return AIMessage(content=reply, id=f"scripted-{index}")

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=self._next(messages))])

    def _stream(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> Iterator[ChatGenerationChunk]:
        reply = self._next(messages)
        for piece in reply.text.split(" "):
            chunk = ChatGenerationChunk(
                message=AIMessageChunk(
                    content=piece + " ",
                    id=reply.id,
                    tool_calls=[],
                )
            )
            if run_manager:
                run_manager.on_llm_new_token(piece, chunk=chunk)
            yield chunk

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> BaseChatModel:
        self.tools_bound = [getattr(tool, "name", str(tool)) for tool in tools]
        return self


class RoleScriptedChatModel(BaseChatModel):
    """Replies according to which node is asking, not call order.

    Every node in the graph invokes the same model, and a revision loop revisits
    them an unpredictable number of times, so an ordered reply queue desynchronises
    as soon as a test exercises more than one pass. Dispatching on the system
    prompt keeps multi-pass tests readable. ``calls`` records ``(role, prompt)``
    so a test can assert what actually reached each node.
    """

    plan_reply: str = "1. answer the question"
    worker_replies: list[str | AIMessage] = []
    critic_replies: list[str] = ["APPROVED: fine"]
    calls: list[tuple[str, list[BaseMessage]]] = []

    @property
    def _llm_type(self) -> str:
        return "role-scripted"

    @staticmethod
    def _role(messages: Sequence[BaseMessage]) -> str:
        system = next((m.text for m in messages if m.type == "system"), "")
        for role in ("planner", "worker", "critic"):
            if f"You are the {role}" in system:
                return role
        return "worker"

    def prompts_for(self, role: str) -> list[str]:
        """The human-facing prompt text each `role` invocation received."""
        return [
            "\n".join(m.text for m in messages if m.type != "system")
            for seen, messages in self.calls
            if seen == role
        ]

    def _reply(self, messages: list[BaseMessage]) -> AIMessage:
        role = self._role(messages)
        self.calls.append((role, list(messages)))
        seen = sum(1 for call_role, _ in self.calls if call_role == role)
        if role == "planner":
            return AIMessage(content=self.plan_reply, id=f"plan-{seen}")
        queue: list[str | AIMessage] = (
            list(self.worker_replies) if role == "worker" else list(self.critic_replies)
        )
        if not queue:
            return AIMessage(content="", id=f"{role}-{seen}")
        chosen = queue[min(seen - 1, len(queue) - 1)]
        if isinstance(chosen, AIMessage):
            # Give every reply a fresh id, including the tool-call ids. add_messages
            # treats a repeated id as a REPLACEMENT rather than an append, so
            # returning the same scripted AIMessage object twice would silently
            # overwrite the previous entry and break a multi-round tool cycle.
            calls = [
                {**call, "id": f"call-{role}-{seen}-{i}"}
                for i, call in enumerate(chosen.tool_calls)
            ]
            return chosen.model_copy(
                update={"id": f"{role}-{seen}", "tool_calls": calls}
            )
        return AIMessage(content=chosen, id=f"{role}-{seen}")

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=self._reply(messages))])

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> BaseChatModel:
        return self


class FakePromptSession:
    """Feeds queued lines to the REPL, then signals end-of-input."""

    def __init__(self, lines: Sequence[str]) -> None:
        self._lines = list(lines)
        self.prompts: list[str] = []

    def prompt(self, text: str = "") -> str:
        self.prompts.append(text)
        if not self._lines:
            raise EOFError
        return self._lines.pop(0)
