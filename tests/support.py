"""Shared builder for a real, engagement-loaded :class:`AgentCore`.

The live layers (L4 eval, L5 e2e) both need a core wired exactly as the app
wires it -- real scope, registry, ledger, workspace, checkpointer -- rather than
a hand-assembled ``GraphDeps``/``build_graph`` that drifts from production. This
writes the on-disk ``scope.json`` a real ``AgentCore`` loads and constructs one,
with every state path redirected under ``tmp_path``.

Callers decide what stays live: eval keeps the real provider LLM + store; e2e
swaps them for offline doubles (see ``wire_offline_llm``) so only the execution
pipeline is exercised, not a paid model.
"""

from __future__ import annotations

import json
from pathlib import Path

from skuggi.config import Provider, Settings
from skuggi.core import AgentCore
from skuggi.vectorstore import Store
from tests.fakes import CountingFakeEmbeddings, RoleScriptedChatModel

REPO_ROOT = Path(__file__).resolve().parents[1]
# The shipped registry -- the same tool set the operator runs with.
DEFAULT_REGISTRY = REPO_ROOT / "configs" / "tools.example.json"


def engaged_core(
    tmp_path: Path,
    scope: dict[str, object],
    *,
    provider: Provider = "ollama",
    registry_path: Path = DEFAULT_REGISTRY,
    **settings_overrides: object,
) -> AgentCore:
    """Construct an :class:`AgentCore` for ``scope`` with all state under ``tmp_path``.

    ``scope`` is written to ``<tmp>/engagements/<name>/scope.json`` before the
    core loads it. ``provider="ollama"`` constructs without credentials; pass a
    real provider (eval) to keep a live model.
    """
    name = str(scope["name"])
    workspace = tmp_path / "engagements" / name
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    settings = Settings(
        provider=provider,
        engagements_dir=tmp_path / "engagements",
        engagement=name,
        registry_path=registry_path,
        sqlite_path=tmp_path / "sessions.db",
        faiss_path=tmp_path / "faiss",
        history_path=tmp_path / ".repl_history",
        preferences_path=tmp_path / "preferences.db",
        **settings_overrides,  # type: ignore[arg-type]
    )
    return AgentCore(settings)


def wire_offline_llm(core: AgentCore, worker: RoleScriptedChatModel) -> None:
    """Swap a core's paid parts for offline doubles, keeping the rest real.

    The store gets deterministic fake embeddings (no network on retrieval) and
    the LLM becomes the scripted ``worker``; the guard, registry, ledger and
    ``execution.run`` stay real. The graph is rebuilt so the swap takes effect.
    """
    core.store = Store(core.settings.faiss_path, CountingFakeEmbeddings())
    core.llm = worker
    core.graph = core._build()
