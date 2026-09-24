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
