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
from contextlib import AbstractContextManager
from pathlib import Path

from langchain_core.language_models import BaseChatModel
from langgraph.graph.state import CompiledStateGraph
from pydantic import ValidationError

from skuggi.agent import awareness
from skuggi.agent.commandbook import CommandBook
from skuggi.agent.config_controller import ConfigController
from skuggi.agent.grants import SessionGrants
from skuggi.agent.graph import GraphDeps, build_graph
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
from skuggi.config.configs import (
    ConfigError,
    InvalidScopeError,
    load_commands,
    load_layout,
    load_registry,
    load_scope,
)
from skuggi.engagement import datafiles
from skuggi.engagement.engagement import (
    EngagementConfig,
    ThreatModel,
)
from skuggi.engagement.workspace import (
    Workspace,
    WorkspaceLayout,
    has_engagement,
    safe_engagement_name,
)
from skuggi.install import configdiff, reconcile
from skuggi.install import update as updater
from skuggi.persistence import ledger as ledger_mod
from skuggi.persistence import memory, preferences
from skuggi.persistence.vectorstore import Store
from skuggi.security.policy import RedactionPolicy
from skuggi.security.vault import SecretVault, open_vault
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

        self.layout = self._load_layout()
        self.workspace = self._open_workspace()
        self.engagement = self._load_scope()
        self.registry = self._load_registry()
        self.commands = self._load_commands()

        # The model plane (provider/credentials/llm/store). Built here, before the
        # graph, because _deps() reads its llm/store; it has no engagement dep.
        self.provider_kernel = ProviderKernel(self)

        self._saver_ctx = memory.open_checkpointer(self.settings.sqlite_path)
        self.saver = self._saver_ctx.__enter__()
        self._ledger_ctx = ledger_mod.open_ledger(self._ledger_path())
        self.ledger = self._ledger_ctx.__enter__()
        # The per-engagement secret vault (reversible redaction). Opened with the
        # ledger and torn down with it on a reload; None in agent-only mode.
        self._vault_ctx, self.vault = self._open_vault()
        self.ledger.start_session(
            self.session_id,
            engagement_name=self.engagement.name if self.engagement else "(none)",
            mode=self.mode,
        )
        self._ensure_threat_model_version()
        # Harness memory: global operator preferences, injected into every turn.
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

    # ----- config + workspace ------------------------------------------------

    def _load_layout(self) -> WorkspaceLayout:
        try:
            return load_layout(self.settings.layout_path)
        except ConfigError as exc:
            log.warning("invalid workspace layout, using defaults: %s", exc)
            self.warnings.append(f"invalid workspace layout, using defaults: {exc}")
            return WorkspaceLayout()

    def _open_workspace(self) -> Workspace | None:
        root = self._resolve_engagement_root()
        if root is None:
            # Descriptive only; the front-end appends a grammar-correct hint to
            # create one (an env var is not the operator-facing answer).
            log.info("no engagement selected; running agent-only")
            self.warnings.append("no engagement selected; running agent-only")
            return None
        ws = Workspace.at(root, layout=self.layout)
        ws.ensure()
        return ws

    def _resolve_engagement_root(self) -> Path | None:
        """Which directory is the active engagement: an explicit override, else cwd.

        Nothing is auto-persisted -- an engagement is cwd-scoped. An explicit
        ``engagement_root`` (env/JSON) is honoured when it holds a ``scope.json``;
        otherwise recovery is a probe of the current directory. Returns ``None``
        for agent-only (no override and no scope.json in cwd).
        """
        configured = self.settings.engagement_root
        if configured is not None and has_engagement(configured, self.layout):
            return configured
        cwd = Path.cwd()
        if has_engagement(cwd, self.layout):
            return cwd
        return None

    def _load_scope(self) -> EngagementConfig | None:
        if self.workspace is None:
            return None
        try:
            return load_scope(self.workspace.scope_path)
        except ConfigError as exc:
            log.warning("no engagement loaded: %s", exc)
            self.warnings.append(f"no engagement loaded: {exc}")
            return None

    def _load_registry(self) -> ToolRegistry:
        try:
            return load_registry(self.settings.registry_path)
        except ConfigError as exc:
            log.warning("no tool registry loaded: %s", exc)
            self.warnings.append(f"no tool registry loaded: {exc}")
            return ToolRegistry()

    def _load_commands(self) -> CommandRegistry:
        try:
            return load_commands(self.settings.commands_path)
        except ConfigError as exc:
            log.warning("no command aliases loaded: %s", exc)
            self.warnings.append(f"no command aliases loaded: {exc}")
            return CommandRegistry()

    def _ledger_path(self) -> Path:
        if self.workspace is not None:
            return self.workspace.ledger_path
        return self.settings.sqlite_path.parent / "ledger.db"

    def _open_vault(
        self,
    ) -> tuple[AbstractContextManager[SecretVault] | None, SecretVault | None]:
        """Open the engagement's secret vault, or (None, None) in agent-only mode.

        The vault only makes sense with a workspace: it stores secrets *this
        engagement* discovered, next to its ledger. Agent-only mode has nowhere
        to scope it and no commands to run, so redaction there is one-way.
        """
        if self.workspace is None:
            return None, None
        ctx = open_vault(self.workspace.vault_path)
        return ctx, ctx.__enter__()

    def _datafiles_block(self) -> str:
        """The metadata-only inventory of tool-input/evidence/loot files.

        Lets the agent reference a wordlist or evidence file by path without ever
        seeing its contents. Empty in agent-only mode (no workspace).
        """
        if self.workspace is None:
            return ""
        ws = self.workspace
        files = datafiles.list_datafiles(
            [
                (ws.inputs_dir, "input"),
                (ws.evidence_dir, "evidence"),
                (ws.loot_dir, "loot"),
            ],
            ws.root,
        )
        return datafiles.render_datafiles(files)

    def _system_facts_block(self) -> str:
        """The host-awareness block (OS, installers, scoped tool presence).

        Rebuilt with the graph (on config/engagement changes, not per turn), so a
        mid-session install is reflected on the next rebuild.
        """
        return awareness.system_facts_block(
            self.registry,
            self.engagement,
            source=self.settings.tool_source,
            managed_dir=self.settings.managed_tools_dir,
        )

    def _harness_catalogue_block(self) -> str:
        """The harness command catalogue (verbs/nouns + saved cmd aliases)."""
        return awareness.harness_catalogue_block(self.commands.names())

    @property
    def current_turn_event_id(self) -> int | None:
        """The in-flight turn's ledger event id (delegated to the turn runner).

        A sub-component (the command book) links a proposed command to the turn
        that produced it; this read-only seam exposes that link.
        """
        return self.turn_runner.current_turn_event_id

    def redaction_policy(self) -> RedactionPolicy:
        """The redaction policy for this session, allow-listing in-scope identifiers.

        The agent has to reason about its own targets, so the engagement's name,
        hosts, networks and resolved primary target pass through un-redacted;
        everything else a detector flags is scrubbed.
        """
        if self.engagement is None:
            return RedactionPolicy()
        allow: set[str] = {
            self.engagement.name,
            *self.engagement.allowed_hosts,
            *(str(net) for net in self.engagement.target_networks),
        }
        target = self.engagement.resolve_target()
        if target:
            allow.add(target)
        return RedactionPolicy.from_scope(allow=allow)

    @property
    def reports_dir(self) -> Path:
        """Where ``write_report`` writes -- the workspace, or ./data as fallback."""
        if self.workspace is not None:
            return self.workspace.reports_dir
        return self.settings.sqlite_path.parent / "reports"

    def _recon_cwd(self) -> Path | None:
        return self.workspace.recon_dir if self.workspace is not None else None

    # ----- properties --------------------------------------------------------

    @property
    def provider(self) -> Provider:
        """The active provider name."""
        return self.settings.provider

    @property
    def autonomous(self) -> bool:
        """Whether autonomous command execution is armed."""
        return self.engagement is not None and self.engagement.autonomous

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
            cwd=self._recon_cwd(),
            command_timeout_s=self.settings.command_timeout_s,
            native_structured=self.settings.supports_structured_output(),
            max_command_rounds=self.settings.max_tool_rounds,
            retrieve_k=self.settings.retrieve_k,
            history_messages=self.settings.history_messages,
            history_chars=self.settings.history_chars,
            system_facts=self._system_facts_block(),
            harness_catalogue=self._harness_catalogue_block(),
            preferences=self.prefs.render_block(),
            data_files=self._datafiles_block(),
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
        self._prefs_ctx.__exit__(None, None, None)
        if self._vault_ctx is not None:
            self._vault_ctx.__exit__(None, None, None)
        self._ledger_ctx.__exit__(None, None, None)
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

    def set_autonomous(self, want: bool | None) -> bool:
        """Toggle autonomous execution; returns the new state.

        Raises ValueError when no engagement is loaded (there is nothing to arm).
        """
        if self.engagement is None:
            msg = "no engagement loaded"
            raise ValueError(msg)
        target = (not self.engagement.autonomous) if want is None else want
        self.engagement = self.engagement.model_copy(update={"autonomous": target})
        self.rebuild_graph()
        return target

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

    # ----- engagement data ---------------------------------------------------

    def describe_engagement(self) -> str | None:
        """The loaded scope summary, or None when no engagement is loaded."""
        return self.engagement.describe() if self.engagement is not None else None

    def create_engagement(
        self, raw: dict[str, object], *, root: Path | None = None
    ) -> EngagementConfig:
        """Validate a scope dict, persist it to the engagement's scope.json, adopt it.

        Raises ``ConfigError`` if the scope does not validate (the wizard shows
        the reason and re-asks). The scope is written to ``scope.json`` directly
        inside `root` -- the active engagement root, or the current directory when
        none is open -- and hot-adopted via ``adopt_engagement``.
        """
        try:
            scope = EngagementConfig.model_validate(raw)
        except ValidationError as exc:
            keys = frozenset(
                str(err["loc"][0]) for err in exc.errors() if err.get("loc")
            )
            summary = "; ".join(
                f"{'.'.join(str(p) for p in err.get('loc', ()))}: {err['msg']}"
                for err in exc.errors()
            )
            raise InvalidScopeError(summary or str(exc), keys) from exc
        # Past pydantic, the tree still has to be writable; a disk error must
        # re-ask rather than crash the wizard. The name no longer names a
        # directory, but it is still the ledger/report label, so an unusable one
        # (empty, all-punctuation) is re-asked rather than left to corrupt a slug.
        target = root if root is not None else self._active_root()
        try:
            safe_engagement_name(scope.name)
            workspace = Workspace.at(target, layout=self.layout)
            workspace.ensure()
            workspace.scope_path.write_text(
                scope.model_dump_json(indent=2), encoding="utf-8"
            )
            return self.adopt_engagement(target)
        except (ValueError, OSError) as exc:
            raise InvalidScopeError(str(exc), frozenset({"name"})) from exc

    def _active_root(self) -> Path:
        """The engagement root scope writes target: the open workspace, else cwd."""
        return self.workspace.root if self.workspace is not None else Path.cwd()

    def adopt_engagement(self, root: Path) -> EngagementConfig:
        """Switch the active engagement to the one rooted at `root`, hot-reloading.

        Reopens the workspace and scope, reopens the ledger at the new
        engagement's path under a fresh session, and rebuilds the tool set and
        graph -- so a running session reflects the new boundary with no restart.
        Raises ``ConfigError`` if the scope is missing or invalid.
        """
        # In-memory only, deliberately NOT persisted to config.json: an
        # engagement is cwd-scoped, so a machine-global pointer would be a
        # category error. Restart recovery is a cwd probe in
        # ``_resolve_engagement_root``; an explicit env/JSON ``engagement_root``
        # still overrides.
        self.settings = self.settings.model_copy(update={"engagement_root": root})
        self.workspace = self._open_workspace()
        if self.workspace is None:  # pragma: no cover -- root holds scope here
            msg = f"could not open workspace at {str(root)!r}"
            raise ConfigError(msg)
        self.engagement = load_scope(self.workspace.scope_path)

        self._ledger_ctx.__exit__(None, None, None)
        self._ledger_ctx = ledger_mod.open_ledger(self._ledger_path())
        self.ledger = self._ledger_ctx.__enter__()
        # Swap the vault to the new engagement's, mirroring the ledger reload.
        if self._vault_ctx is not None:
            self._vault_ctx.__exit__(None, None, None)
        self._vault_ctx, self.vault = self._open_vault()
        self.session_id = str(uuid.uuid4())
        self.ledger.start_session(
            self.session_id, engagement_name=self.engagement.name, mode=self.mode
        )
        self._ensure_threat_model_version()

        self.rebuild_graph()
        return self.engagement

    def _threat_model_snapshot(self) -> str:
        """The active engagement's threat model as JSON ('' when none is set)."""
        tm = self.engagement.threat_model if self.engagement else None
        return tm.model_dump_json() if tm else ""

    def _ensure_threat_model_version(self) -> None:
        """Record version 1 of the threat model if the ledger has none yet.

        Later changes are versioned by ``update_threat_model`` (the supported path);
        a hand-edited scope.json is not auto-versioned.
        """
        if self.ledger.current_threat_model_version() == 0:
            self.ledger.record_threat_model(
                self._threat_model_snapshot(), note="(initial)"
            )

    def update_threat_model(
        self, threat_model: ThreatModel | None, *, note: str = ""
    ) -> int:
        """Set the engagement's threat model, version the change, hot-reload scope.

        Persists the new model to scope.json (so it survives a restart), records a
        threat-model version with ``note`` (the change log), and returns the new
        version. Findings scored under an earlier version are now flagged outdated
        until rescored. Requires an active engagement.
        """
        if self.engagement is None:
            msg = "no engagement loaded; cannot set a threat model"
            raise ConfigError(msg)
        # Modify the engagement in place (like set_autonomous) rather than
        # reloading: a threat-model change must not start a new session or orphan
        # this session's findings from the version it bumps.
        self.engagement = self.engagement.model_copy(
            update={"threat_model": threat_model}
        )
        if self.workspace is not None:
            self.workspace.scope_path.write_text(
                self.engagement.model_dump_json(indent=2), encoding="utf-8"
            )
        self.rebuild_graph()  # so GraphDeps carries the new threat model
        return self.ledger.record_threat_model(self._threat_model_snapshot(), note=note)

    def apply_engagement_scope(self, engagement: EngagementConfig) -> None:
        """Persist an edited scope in place and hot-reload it (like the threat model).

        The caller (``ScopeController``) has already re-validated ``engagement``.
        Edited in place -- no new session -- so this session's findings are not
        orphaned; the graph is rebuilt so its guard/brief see the new scope.
        """
        self.engagement = engagement
        if self.workspace is not None:
            self.workspace.scope_path.write_text(
                engagement.model_dump_json(indent=2), encoding="utf-8"
            )
        self.rebuild_graph()

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

    def reload_registries(self) -> None:
        """Rebuild the registry/commands/graph from disk after a template write."""
        self.registry = self._load_registry()
        self.commands = self._load_commands()
        self.rebuild_graph()

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
