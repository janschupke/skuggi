"""The headless agent core shared by the REPL and the wrapped-shell daemon.

Everything that is *not* presentation lives here: loading the engagement scope
and tool registry, opening the ledger, building the graph, running a turn, and
the session controls (mode, autonomous, findings, report, doctor). A front-end
-- the Rich REPL (``tui.Tui``) or the socket daemon (``daemon``) -- owns only
rendering. This is the single agent code path; extracting it is what lets the
shell wrapper reuse the graph without duplicating turn logic.

``turn`` yields ``TurnEvent``s (reset / status / token / final) rather than
touching a console, so the same stream drives a Rich ``Live`` pane and a plain
socket alike. Config errors degrade to warnings collected in ``warnings`` (the
front-end shows them) rather than crashing the session.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

from langchain_core.language_models import BaseChatModel
from langgraph.graph.state import CompiledStateGraph

from skuggi.agent.commandbook import CommandBook
from skuggi.agent.config_controller import ConfigController
from skuggi.agent.engagement_manager import EngagementManager
from skuggi.agent.grants import SessionGrants
from skuggi.agent.graph import GraphDeps, build_graph
from skuggi.agent.install_researcher import InstallResearcher
from skuggi.agent.journal import Journal
from skuggi.agent.modes import MODES, Mode, prompt_set
from skuggi.agent.preferencebook import PreferenceBook
from skuggi.agent.provider_kernel import ProviderKernel
from skuggi.agent.reconcile_controller import ReconcileController
from skuggi.agent.scope_controller import ScopeController
from skuggi.agent.session_archive import SessionArchive
from skuggi.agent.state import AgentState
from skuggi.agent.tooldoctor import ToolDoctor
from skuggi.agent.turn_runner import TurnEvent, TurnRunner
from skuggi.common import logs
from skuggi.config.config import (
    Provider,
    Settings,
)
from skuggi.engagement.engagement import (
    EngagementConfig,
    ThreatModel,
)
from skuggi.engagement.workspace import (
    Workspace,
    WorkspaceLayout,
)
from skuggi.install import configdiff, reconcile
from skuggi.install import update as updater
from skuggi.persistence import ledger as ledger_mod
from skuggi.persistence import memory, preferences
from skuggi.persistence.vectorstore import Store
from skuggi.security.policy import RedactionPolicy
from skuggi.security.vault import SecretVault
from skuggi.tooling.commands import CommandRegistry
from skuggi.tooling.registry import ToolRegistry

log = logs.get_logger(__name__)


def parse_toggle(arg: str) -> bool | None:
    """Parse an on/off argument; None (neither) means "flip the current state".

    Shared by the REPL and the daemon so /autonomous parses identically in
    both front-ends.
    """
    return {"on": True, "off": False}.get(arg.strip().lower())


class AgentCore:
    """Owns the agent session; front-ends render its output."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Load config, open the ledger, and build the graph for one session."""
        self.settings = settings or Settings()
        self.mode: Mode = self.settings.mode
        self.thread_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.warnings: list[str] = []

        # The model plane (provider/credentials/llm/store). No engagement dep, so
        # it builds first; _load_chat_model runs before the first graph build.
        self.provider_kernel = ProviderKernel(self)

        # The engagement plane: scope, workspace, registries, and the per-engagement
        # ledger + vault (opened here, with start_session). Needs session_id/mode.
        self.engagement_mgr = EngagementManager(self)

        # Global persistence (keyed by path, not engagement-scoped); both must
        # exist before the first rebuild (the graph needs the saver; _deps reads
        # prefs.render_block()).
        self._saver_ctx = memory.open_checkpointer(self.settings.sqlite_path)
        self.saver = self._saver_ctx.__enter__()
        self._prefs_ctx = preferences.open_preferences(self.settings.preferences_path)
        self.prefs = self._prefs_ctx.__enter__()

        # The turn loop + its transient per-turn state (built before the first
        # rebuild: _deps's turn_id lambda reads current_turn_event_id from here).
        self.turn_runner = TurnRunner(self)

        self.rebuild_graph()

        # Per-session approval grants for gated writes (config/install/scope/cmd).
        self.grants = SessionGrants()

        # ----- sub-components (public; hold a back-ref and read live state) -
        self.doctor = ToolDoctor(self)
        self.archive = SessionArchive(self)
        self.cmds = CommandBook(self)
        self.journal = Journal(self)
        self.memory = PreferenceBook(self)
        self.config = ConfigController(self)
        self.scope = ScopeController(self)
        self.reconciler = ReconcileController(self)
        self.installer = InstallResearcher(self)

    # ----- engagement plane (delegated to EngagementManager) -----------------

    @property
    def engagement(self) -> EngagementConfig | None:
        """The loaded engagement scope (None in agent-only mode)."""
        return self.engagement_mgr.engagement

    @engagement.setter
    def engagement(self, value: EngagementConfig | None) -> None:
        self.engagement_mgr.engagement = value

    @property
    def registry(self) -> ToolRegistry:
        """The loaded tool registry."""
        return self.engagement_mgr.registry

    @registry.setter
    def registry(self, value: ToolRegistry) -> None:
        self.engagement_mgr.registry = value

    @property
    def commands(self) -> CommandRegistry:
        """The loaded command-alias registry."""
        return self.engagement_mgr.commands

    @commands.setter
    def commands(self, value: CommandRegistry) -> None:
        self.engagement_mgr.commands = value

    @property
    def workspace(self) -> Workspace | None:
        """The engagement workspace (None in agent-only mode)."""
        return self.engagement_mgr.workspace

    @property
    def vault(self) -> SecretVault | None:
        """The per-engagement secret vault (None in agent-only mode)."""
        return self.engagement_mgr.vault

    @property
    def layout(self) -> WorkspaceLayout:
        """The workspace directory layout."""
        return self.engagement_mgr.layout

    @property
    def ledger(self) -> ledger_mod.Ledger:
        """The per-engagement ledger (swapped on an engagement adopt)."""
        return self.engagement_mgr.ledger

    @property
    def reports_dir(self) -> Path:
        """Where ``write_report`` writes (delegated)."""
        return self.engagement_mgr.reports_dir

    @property
    def autonomous(self) -> bool:
        """Whether autonomous command execution is armed (delegated)."""
        return self.engagement_mgr.autonomous

    def redaction_policy(self) -> RedactionPolicy:
        """The session's redaction policy, allow-listing in-scope IDs (delegated)."""
        return self.engagement_mgr.redaction_policy()

    def describe_engagement(self) -> str | None:
        """The loaded scope summary, or None when none is loaded (delegated)."""
        return self.engagement_mgr.describe_engagement()

    def create_engagement(
        self, raw: dict[str, object], *, root: Path | None = None
    ) -> EngagementConfig:
        """Validate a scope dict, persist it, and adopt it (delegated)."""
        return self.engagement_mgr.create_engagement(raw, root=root)

    def adopt_engagement(self, root: Path) -> EngagementConfig:
        """Hot-switch the active engagement to the one rooted at `root` (delegated)."""
        return self.engagement_mgr.adopt_engagement(root)

    def update_threat_model(
        self, threat_model: ThreatModel | None, *, note: str = ""
    ) -> int:
        """Set the engagement's threat model, versioning the change (delegated)."""
        return self.engagement_mgr.update_threat_model(threat_model, note=note)

    def apply_engagement_scope(self, engagement: EngagementConfig) -> None:
        """Persist an edited scope in place and hot-reload it (delegated)."""
        self.engagement_mgr.apply_engagement_scope(engagement)

    def set_autonomous(self, want: bool | None) -> bool:
        """Toggle autonomous execution; returns the new state (delegated)."""
        return self.engagement_mgr.set_autonomous(want)

    def reload_registries(self) -> None:
        """Rebuild the registry/commands/graph from disk (delegated)."""
        self.engagement_mgr.reload_registries()

    @property
    def current_turn_event_id(self) -> int | None:
        """The in-flight turn's ledger event id (delegated to the turn runner).

        A sub-component (the command book) links a proposed command to the turn
        that produced it; this read-only seam exposes that link.
        """
        return self.turn_runner.current_turn_event_id

    # ----- properties --------------------------------------------------------

    @property
    def provider(self) -> Provider:
        """The active provider name."""
        return self.settings.provider

    # ----- model plane (delegated to ProviderKernel) -------------------------

    @property
    def llm(self) -> BaseChatModel | None:
        """The live chat model (None until a credential is configured)."""
        return self.provider_kernel.llm

    @llm.setter
    def llm(self, value: BaseChatModel | None) -> None:
        self.provider_kernel.llm = value

    @property
    def store(self) -> Store:
        """The FAISS retrieval store."""
        return self.provider_kernel.store

    @store.setter
    def store(self, value: Store) -> None:
        self.provider_kernel.store = value

    @property
    def model(self) -> str | None:
        """The active model name (None = the provider's persisted default)."""
        return self.provider_kernel.model

    def _deps(self) -> GraphDeps:
        return GraphDeps(
            llm=self.llm,
            store=self.store,
            engagement=self.engagement,
            ledger=self.ledger,
            registry=self.registry,
            redaction_policy=self.redaction_policy(),
            vault=self.vault,
            workspace=self.workspace,
            wordlist_roots=tuple(Path(r) for r in self.settings.wordlist_roots),
            session_id=self.session_id,
            thread_id=lambda: self.thread_id,
            turn_id=lambda: self.current_turn_event_id,
            cwd=self.engagement_mgr.recon_cwd(),
            command_timeout_s=self.settings.command_timeout_s,
            native_structured=self.settings.supports_structured_output(),
            max_command_rounds=self.settings.max_tool_rounds,
            retrieve_k=self.settings.retrieve_k,
            history_messages=self.settings.history_messages,
            history_chars=self.settings.history_chars,
            system_facts=self.engagement_mgr.system_facts_block(),
            harness_catalogue=self.engagement_mgr.harness_catalogue_block(),
            preferences=self.prefs.render_block(),
            data_files=self.engagement_mgr.datafiles_block(),
            prompts=prompt_set(self.mode),
        )

    def _build(self) -> CompiledStateGraph[AgentState]:
        return build_graph(self._deps(), self.saver)

    def rebuild_graph(self) -> None:
        """Recompile the graph so ``GraphDeps`` picks up changed state.

        The compiled graph snapshots config/scope/threat-model/preferences into
        ``GraphDeps`` at build time, so any change to those must be followed by a
        rebuild. This is the one public seam for that: the core calls it itself
        after a session control, and a sub-component (e.g. the preference book)
        calls it after mutating state the deps capture.
        """
        self.graph = self._build()

    def close(self) -> None:
        """Close the ledger, vault, preferences and checkpointer connections."""
        self.engagement_mgr.close()
        self._prefs_ctx.__exit__(None, None, None)
        self._saver_ctx.__exit__(None, None, None)

    # ----- session controls --------------------------------------------------

    def set_provider(self, name: str) -> None:
        """Switch provider (delegated)."""
        self.provider_kernel.set_provider(name)

    def set_model(self, name: str) -> None:
        """Switch model on the current provider (delegated)."""
        self.provider_kernel.set_model(name)

    def set_api_key(self, provider: str, key: str) -> None:
        """Persist an API key and switch to its provider (delegated)."""
        self.provider_kernel.set_api_key(provider, key)

    def use_ollama(self, base_url: str | None = None) -> None:
        """Switch to the local Ollama provider (delegated)."""
        self.provider_kernel.use_ollama(base_url)

    def use_claude_cli(self) -> None:
        """Switch to the local Claude CLI provider (delegated)."""
        self.provider_kernel.use_claude_cli()

    def default_model(self, provider: str) -> str:
        """The persisted default model for `provider` (delegated)."""
        return self.provider_kernel.default_model(provider)

    def set_provider_model(self, provider: str, model: str) -> None:
        """Persist and apply the default model for `provider` (delegated)."""
        self.provider_kernel.set_provider_model(provider, model)

    def login_chatgpt(
        self, notify: Callable[[str], None] = lambda _msg: None
    ) -> str | None:
        """Run the ChatGPT OAuth login and switch provider (delegated)."""
        return self.provider_kernel.login_chatgpt(notify)

    def ensure_llm(self) -> BaseChatModel:
        """Return the chat model, building it on first use (delegated)."""
        return self.provider_kernel.ensure_llm()

    def ingest(self, path: Path) -> int:
        """Index a file or directory into FAISS (delegated)."""
        return self.provider_kernel.ingest(path)

    def set_mode(self, mode: str) -> Mode:
        """Switch operating mode, rebuilding the graph's prompt set."""
        if mode not in MODES:
            msg = f"unknown mode: {mode!r} (choose {', '.join(MODES)})"
            raise ValueError(msg)
        self.mode = mode
        self.rebuild_graph()
        return self.mode

    def new_thread(self) -> str:
        """Start a fresh conversation thread."""
        self.thread_id = str(uuid.uuid4())
        return self.thread_id

    def set_thread(self, thread_id: str) -> None:
        """Switch to an existing thread id."""
        self.thread_id = thread_id

    def list_threads(self) -> list[str]:
        """Every thread id the checkpointer has seen."""
        return memory.list_threads(self.saver)

    # ----- self-update + config reconcile (delegated to ReconcileController) --

    def self_update(self, runner: updater.UpdateRunner | None = None) -> Iterator[str]:
        """Update the install in place, then surface any config drift (delegated)."""
        yield from self.reconciler.self_update(runner)

    def reconcile_status(self) -> tuple[reconcile.FileStatus, ...]:
        """How each installed config compares to its packaged template (delegated)."""
        return self.reconciler.reconcile_status()

    def stale_configs(self) -> tuple[str, ...]:
        """The installed config files that have fallen behind their template."""
        return self.reconciler.stale_configs()

    def reconcile_structured_diff(self, name: str) -> configdiff.StructuredDiff:
        """What an overwrite of `name` would change, per file type (delegated)."""
        return self.reconciler.reconcile_structured_diff(name)

    def reconcile_overwrite(self, name: str) -> Path | None:
        """Overwrite `name` from its template, backing up and reloading (delegated)."""
        return self.reconciler.reconcile_overwrite(name)

    def reconcile_overwrite_all(self) -> tuple[tuple[str, Path | None], ...]:
        """Overwrite every drifted config, reloading once (delegated)."""
        return self.reconciler.reconcile_overwrite_all()

    # ----- turn loop + session logging (delegated to TurnRunner) -------------

    def note_interaction(self, verb: str, detail: str = "") -> None:
        """Record a harness-control interaction to the audit log (delegated)."""
        self.turn_runner.note_interaction(verb, detail)

    def record_passthrough(self, cmdline: str) -> None:
        """Log a free-typed shell command the operator ran (delegated)."""
        self.turn_runner.record_passthrough(cmdline)

    def state(self) -> AgentState:
        """The current graph state for the active thread (delegated)."""
        return self.turn_runner.state()

    def turn(self, user_text: str) -> Iterator[TurnEvent]:
        """Run one agent turn, yielding events as the graph streams (delegated)."""
        yield from self.turn_runner.turn(user_text)
