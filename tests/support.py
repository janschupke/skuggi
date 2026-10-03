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
from importlib.resources import files
from pathlib import Path

from skuggi.agent.core import AgentCore
from skuggi.config.config import Provider, Settings
from skuggi.persistence.vectorstore import Store
from tests.fakes import CountingFakeEmbeddings, RoleScriptedChatModel

REPO_ROOT = Path(__file__).resolve().parents[1]


def template(name: str) -> Path:
    """Path to a packaged config template (``src/skuggi/templates/<name>``).

    Resolved through the package rather than as a repo path: these are what
    ``skuggi-init`` seeds a config home from, so they live inside ``skuggi`` and
    travel with an installed wheel. Going through ``importlib.resources`` here
    means a test asserts against the same bytes an operator actually gets.
    """
    return Path(str(files("skuggi") / "templates" / name))


# The shipped registry -- the same tool set the operator runs with.
DEFAULT_REGISTRY = template("tools.example.json")


def engaged_core(
    tmp_path: Path,
    scope: dict[str, object],
    *,
    provider: Provider = "ollama",
    registry_path: Path = DEFAULT_REGISTRY,
    **settings_overrides: object,
) -> AgentCore:
    """Construct an :class:`AgentCore` for ``scope`` with all state under ``tmp_path``.

    ``scope`` is written to ``<tmp>/engagement/scope.json`` before the core loads
    it (the directory IS the engagement). ``provider="ollama"`` constructs without
    credentials; pass a real provider (eval) to keep a live model.
    """
    workspace = tmp_path / "engagement"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    settings = Settings(
        provider=provider,
        engagement_root=workspace,
        registry_path=registry_path,
        sqlite_path=tmp_path / "sessions.db",
        faiss_path=tmp_path / "faiss",
        history_path=tmp_path / ".repl_history",
        preferences_path=tmp_path / "preferences.db",
        # Pinned under tmp_path even though all three are optional: their defaults
        # are in the operator's config home, and the live layers (L4 eval, L5 e2e)
        # are exempt from `isolate_credentials`. Without these, an e2e run would
        # pick up whatever layout or aliases the developer happens to have.
        layout_path=tmp_path / "layout.json",
        commands_path=tmp_path / "commands.json",
        managed_tools_dir=tmp_path / "toolbox",
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
