"""A no-network AgentCore for the deterministic ``result_compat`` round-trip.

``result_compat`` drives a scripted worker output through a *real* agent turn --
the real guard, executor, ledger and report renderer -- to prove the model's
output round-trips into the host system. That needs a real ``AgentCore`` with its
paid parts (the provider LLM and embeddings) swapped for offline doubles. This
mirrors ``tests/support.engaged_core`` + ``wire_offline_llm``, but lives in shipped
code because ``skuggi.eval`` must not import the test tree.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from langchain_core.embeddings import Embeddings
from langchain_core.language_models import BaseChatModel, LanguageModelInput
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable, RunnableLambda
from pydantic import BaseModel

from skuggi.agent.core import AgentCore
from skuggi.agent.protocol import CriticResponse, PlannerResponse, WorkerResponse
from skuggi.common.paths import ensure_dir, packaged_template
from skuggi.config.config import Settings
from skuggi.engagement.engagement import EngagementConfig
from skuggi.persistence.vectorstore import Store

# The shipped tool registry: the same tool set the operator runs with.
_REGISTRY = packaged_template("tools.example.json")


class _ConstantEmbeddings(Embeddings):
    """Deterministic, no-network embeddings. Retrieval over an empty index only."""

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Return the fixed vector for each text (nothing is ingested in evals)."""
        return [[1.0, 0.0, 0.0, 0.0] for _ in texts]

    def embed_query(self, text: str) -> list[float]:
        """Return the fixed query vector; retrieval runs over an empty index."""
        return [1.0, 0.0, 0.0, 0.0]


class OfflineModel(BaseChatModel):
    """Returns a fixed structured response per node, dispatched by schema type.

    ``result_compat`` cases are single-pass turns (``done=True``, non-autonomous),
    so a schema-keyed lookup is enough -- no revision loop to desynchronise.
    """

    planner: PlannerResponse = PlannerResponse()
    worker: WorkerResponse = WorkerResponse()
    critic: CriticResponse = CriticResponse(approved=True, reason="ok")

    @property
    def _llm_type(self) -> str:
        """The LangChain model-type tag."""
        return "offline-eval"

    def with_structured_output(
        self, schema: Any, **kwargs: Any
    ) -> Runnable[LanguageModelInput, BaseModel]:
        """Return a runnable that yields the scripted response for ``schema``."""
        mapping: dict[type[BaseModel], BaseModel] = {
            PlannerResponse: self.planner,
            WorkerResponse: self.worker,
            CriticResponse: self.critic,
        }
        obj = mapping.get(schema, self.worker)
        return RunnableLambda(lambda _input: obj)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        # The structured graph never calls this; kept to satisfy BaseChatModel.
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=""))])


def build_offline_core(
    scope: EngagementConfig,
    tmp: Path,
    worker: WorkerResponse,
    *,
    registry_path: Path = _REGISTRY,
) -> AgentCore:
    """Build an ``AgentCore`` for ``scope`` with all paid/network parts offline.

    ``scope`` is written to ``<tmp>/engagements/<name>/scope.json`` before the
    core loads it; the store gets constant embeddings and the model is scripted
    to return ``worker``. Every state path is redirected under ``tmp``. A caller
    that runs from another directory (the tests chdir) passes an absolute
    ``registry_path``.
    """
    workspace = tmp / "engagements" / scope.name
    ensure_dir(workspace)
    (workspace / "scope.json").write_text(scope.model_dump_json(), encoding="utf-8")
    settings = Settings(
        provider="ollama",
        engagements_dir=tmp / "engagements",
        engagement=scope.name,
        registry_path=registry_path,
        sqlite_path=tmp / "sessions.db",
        faiss_path=tmp / "faiss",
        history_path=tmp / ".repl_history",
        preferences_path=tmp / "preferences.db",
    )
    core = AgentCore(settings)
    core.store = Store(core.settings.faiss_path, _ConstantEmbeddings())
    core.llm = OfflineModel(worker=worker)
    core.graph = core._build()  # noqa: SLF001 -- the documented rewire seam
    return core
