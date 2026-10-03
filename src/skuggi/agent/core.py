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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast, get_args

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph
from pydantic import SecretStr, ValidationError

from skuggi.agent.commandbook import CommandBook
from skuggi.agent.config_controller import ConfigController
from skuggi.agent.graph import GraphDeps, build_graph, recursion_limit
from skuggi.agent.journal import Journal
from skuggi.agent.modes import MODES, Mode, prompt_set
from skuggi.agent.preferencebook import PreferenceBook
from skuggi.agent.session_archive import SessionArchive
from skuggi.agent.state import AgentState
from skuggi.agent.tooldoctor import ToolDoctor
from skuggi.common import logs
from skuggi.config.config import (
    Provider,
    Settings,
    config_path,
    write_config,
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
    parse_command,
)
from skuggi.engagement.workspace import Workspace, WorkspaceLayout
from skuggi.install import envfile
from skuggi.install import update as updater
from skuggi.persistence import ledger as ledger_mod
from skuggi.persistence import memory, preferences
from skuggi.persistence.vectorstore import Store
from skuggi.providers import providers
from skuggi.security.policy import RedactionPolicy
from skuggi.security.vault import SecretVault, open_vault
from skuggi.tooling.commands import CommandRegistry
from skuggi.tooling.registry import ToolRegistry

log = logs.get_logger(__name__)

_PROVIDERS = get_args(Provider)

# The API-key providers: provider name -> (env-file key, Settings field). The
# key persists to skuggi's own secret file; the field holds it on the live
# Settings. chatgpt (OAuth) and ollama (no key) are deliberately absent.
_API_KEY_FIELDS: dict[str, tuple[str, str]] = {
    "openai": ("OPENAI_API_KEY", "openai_api_key"),
    "anthropic": ("ANTHROPIC_API_KEY", "anthropic_api_key"),
}


EventKind = Literal["reset", "status", "token", "final"]


def parse_toggle(arg: str) -> bool | None:
    """Parse an on/off argument; None (neither) means "flip the current state".

    Shared by the REPL and the daemon so /autonomous parses identically in
    both front-ends.
    """
    return {"on": True, "off": False}.get(arg.strip().lower())


@dataclass(frozen=True, slots=True)
class TurnEvent:
    """One item streamed out of a turn.

    ``reset`` clears the draft buffer (a new pass or tool round begins),
    ``status`` is a one-line node update, ``token`` is an incremental worker
    token, ``final`` is the critic-approved draft that supersedes the buffer.
    """

    kind: EventKind
    text: str = ""
    node: str = ""


class AgentCore:
    """Owns the agent session; front-ends render its output."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Load config, open the ledger, and build the graph for one session."""
        self.settings = settings or Settings()
        self.model: str | None = None
        self.mode: Mode = self.settings.mode
        self.thread_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.warnings: list[str] = []
        # The prompt event id of the turn in flight, so commands the agent runs
        # link back to the directive that drove them. None between turns.
        self._current_turn_event_id: int | None = None

        self.layout = self._load_layout()
        self.workspace = self._open_workspace()
        self.engagement = self._load_scope()
        self.registry = self._load_registry()
        self.commands = self._load_commands()

        self._embeddings = providers.get_embeddings(self.settings)
        self.store = Store.from_settings(self.settings, self._embeddings)
        self.llm: BaseChatModel | None = self._load_chat_model()

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

        self.graph = self._build()

        # ----- sub-components (public; hold a back-ref and read live state) -
        self.doctor = ToolDoctor(self)
        self.archive = SessionArchive(self)
        self.cmds = CommandBook(self)
        self.journal = Journal(self)
        self.memory = PreferenceBook(self)
        self.config = ConfigController(self)

    # ----- config + workspace ------------------------------------------------

    def _load_layout(self) -> WorkspaceLayout:
        try:
            return load_layout(self.settings.layout_path)
        except ConfigError as exc:
            log.warning("invalid workspace layout, using defaults: %s", exc)
            self.warnings.append(f"invalid workspace layout, using defaults: {exc}")
            return WorkspaceLayout()

    def _open_workspace(self) -> Workspace | None:
        if not self.settings.engagement:
            # Descriptive only; the front-end appends a grammar-correct hint to
            # create one (an env var is not the operator-facing answer).
            log.info("no engagement selected; running agent-only")
            self.warnings.append("no engagement selected; running agent-only")
            return None
        ws = Workspace.for_engagement(
            self.settings.engagements_dir, self.settings.engagement, layout=self.layout
        )
        ws.ensure()
        return ws

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

    def _redaction_policy(self) -> RedactionPolicy:
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

    def _deps(self) -> GraphDeps:
        return GraphDeps(
            llm=self.llm,
            store=self.store,
            engagement=self.engagement,
            ledger=self.ledger,
            registry=self.registry,
            redaction_policy=self._redaction_policy(),
            vault=self.vault,
            workspace=self.workspace,
            wordlist_roots=tuple(Path(r) for r in self.settings.wordlist_roots),
            session_id=self.session_id,
            thread_id=lambda: self.thread_id,
            turn_id=lambda: self._current_turn_event_id,
            cwd=self._recon_cwd(),
            command_timeout_s=self.settings.command_timeout_s,
            native_structured=self.settings.supports_structured_output(),
            max_command_rounds=self.settings.max_tool_rounds,
            retrieve_k=self.settings.retrieve_k,
            history_messages=self.settings.history_messages,
            history_chars=self.settings.history_chars,
            preferences=self.prefs.render_block(),
            data_files=self._datafiles_block(),
            prompts=prompt_set(self.mode),
        )

    def _build(self) -> CompiledStateGraph[AgentState]:
        return build_graph(self._deps(), self.saver)

    def close(self) -> None:
        """Close the ledger, vault, preferences and checkpointer connections."""
        self._prefs_ctx.__exit__(None, None, None)
        if self._vault_ctx is not None:
            self._vault_ctx.__exit__(None, None, None)
        self._ledger_ctx.__exit__(None, None, None)
        self._saver_ctx.__exit__(None, None, None)

    # ----- session controls --------------------------------------------------

    def set_provider(self, name: str) -> None:
        """Switch provider (raises ValueError on an unknown name)."""
        if name not in _PROVIDERS:
            msg = f"unknown provider: {name!r}"
            raise ValueError(msg)
        self.settings = self.settings.model_copy(update={"provider": name})
        self.model = None
        self._rebuild_llm()

    def set_model(self, name: str) -> None:
        """Switch model on the current provider."""
        if not name:
            msg = "model name is required"
            raise ValueError(msg)
        self.model = name
        self._rebuild_llm()

    # ----- guided setup: app-owned credentials (the `setup`/`login` verbs) ----

    def set_api_key(self, provider: str, key: str) -> None:
        """Persist an API key to skuggi's own secret file and use its provider.

        The key goes into ``<config home>/env`` at mode 0600 (via envfile), never
        the environment; the provider goes into ``config.json``. Both are applied
        to the live session so the next turn uses them without a restart.
        """
        try:
            env_name, field = _API_KEY_FIELDS[provider]
        except KeyError:
            msg = f"{provider} is not an API-key provider"
            raise ValueError(msg) from None
        envfile.write_secret(env_name, key)
        write_config(config_path(), {"provider": provider})
        self.settings = self.settings.model_copy(
            update={field: SecretStr(key), "provider": provider}
        )
        self.model = None
        self._rebuild_llm()

    def use_ollama(self, base_url: str | None = None) -> None:
        """Switch to the local Ollama provider (no credential), setting its URL."""
        persist: dict[str, object] = {"provider": "ollama"}
        updates: dict[str, object] = {"provider": "ollama"}
        if base_url:
            persist["ollama_base_url"] = base_url
            updates["ollama_base_url"] = base_url
        write_config(config_path(), persist)
        self.settings = self.settings.model_copy(update=updates)
        self.model = None
        self._rebuild_llm()

    def use_claude_cli(self) -> None:
        """Switch to the local Claude CLI provider (uses the operator's own login).

        No key is stored: the ``claude`` binary carries its own credentials. The
        provider is persisted so the next session starts on it.
        """
        write_config(config_path(), {"provider": "claude-cli"})
        self.settings = self.settings.model_copy(update={"provider": "claude-cli"})
        self.model = None
        self._rebuild_llm()

    def default_model(self, provider: str) -> str:
        """The persisted default model for `provider` (what setup pre-selects)."""
        return self.settings.model_for(cast("Provider", provider))

    def set_provider_model(self, provider: str, model: str) -> None:
        """Persist the default model for `provider` and apply it to this session.

        Writes the non-secret ``model_<provider>`` key to config.json (so it
        survives a restart) and rebuilds the live model. Resetting ``self.model``
        to ``None`` means the session now follows the persisted provider default.
        """
        if not model:
            msg = "model name is required"
            raise ValueError(msg)
        field = f"model_{provider.replace('-', '_')}"
        write_config(config_path(), {field: model})
        self.settings = self.settings.model_copy(update={field: model})
        self.model = None
        self._rebuild_llm()

    def login_chatgpt(
        self, notify: Callable[[str], None] = lambda _msg: None
    ) -> str | None:
        """Run the in-app ChatGPT OAuth login, then switch to the chatgpt provider.

        Writes ``auth.json`` (owned by codex_login/CodexTokenStore), persists the
        provider, and rebuilds the live model. Returns the account id, if any.
        """
        # lazy: pulls the OpenAI SDK, kept out of the module import graph.
        from skuggi.providers import codex_login  # noqa: PLC0415

        account = codex_login.login(auth_path=self.settings.auth_json(), notify=notify)
        write_config(config_path(), {"provider": "chatgpt"})
        self.settings = self.settings.model_copy(update={"provider": "chatgpt"})
        self.model = None
        self._rebuild_llm()
        return account

    def _rebuild_llm(self) -> None:
        self.llm = providers.get_chat_model(self.settings, model=self.model)
        self.graph = self._build()

    def _load_chat_model(self) -> BaseChatModel | None:
        """Build the chat model at boot, or degrade to a warning if uncredentialed.

        Boot must never die for lack of a model: the shell wrapper only needs one
        when the operator actually asks something, and the graph just holds the
        reference until a turn runs. A missing/unusable credential becomes a
        warning (the front-end shows it) and a ``None`` llm; `_ensure_llm` builds
        it on first use, where the operator can fix it with `/setup` or
        `/provider`. Mirrors the credential-free boot of `providers.get_embeddings`.
        """
        try:
            return providers.get_chat_model(self.settings, model=self.model)
        except (RuntimeError, ImportError) as exc:
            log.warning("no chat model configured: %s", exc)
            self.warnings.append(providers.NO_MODEL_CONFIGURED)
            return None

    def _ensure_llm(self) -> BaseChatModel:
        """Return the chat model, building it on first use.

        Deferred from construction so the session boots without credentials.
        Raises ``ConfigError`` (with the provider's specific guidance) when no
        usable credential is configured; callers on the turn path let that
        surface as a clean error event rather than a crash.
        """
        if self.llm is None:
            self.llm = providers.get_chat_model(self.settings, model=self.model)
            self.graph = self._build()
        return self.llm

    def set_mode(self, mode: str) -> Mode:
        """Switch operating mode, rebuilding the graph's prompt set."""
        if mode not in MODES:
            msg = f"unknown mode: {mode!r} (choose {', '.join(MODES)})"
            raise ValueError(msg)
        self.mode = mode
        self.graph = self._build()
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
        self.graph = self._build()
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

    def ingest(self, path: Path) -> int:
        """Index a file or directory into FAISS; returns chunks added."""
        added = self.store.ingest([path])
        self.store.persist()
        return added

    # ----- engagement data ---------------------------------------------------

    def describe_engagement(self) -> str | None:
        """The loaded scope summary, or None when no engagement is loaded."""
        return self.engagement.describe() if self.engagement is not None else None

    def create_engagement(self, raw: dict[str, object]) -> EngagementConfig:
        """Validate a scope dict, persist it to the engagement's scope.json, load it.

        Raises ``ConfigError`` if the scope does not validate (the wizard shows
        the reason and re-asks). On success the scope is written under
        ``engagements/<name>/`` and hot-loaded via ``load_engagement``.
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
        # Past pydantic, the name still has to become a safe directory segment and
        # the tree has to be writable. A bad name (e.g. one that slugifies to
        # nothing) or a disk error must re-ask the name, never crash the wizard.
        try:
            workspace = Workspace.for_engagement(
                self.settings.engagements_dir, scope.name, layout=self.layout
            )
            workspace.ensure()
            workspace.scope_path.write_text(
                scope.model_dump_json(indent=2), encoding="utf-8"
            )
            return self.load_engagement(scope.name)
        except (ValueError, OSError) as exc:
            raise InvalidScopeError(str(exc), frozenset({"name"})) from exc

    def load_engagement(self, name: str) -> EngagementConfig:
        """Switch the active engagement to `name`, hot-reloading scope + tools.

        Reopens the workspace and scope, reopens the ledger at the new
        engagement's path under a fresh session, and rebuilds the tool set and
        graph -- so a running session reflects the new boundary with no restart.
        Raises ``ConfigError`` if the scope is missing or invalid.
        """
        self.settings = self.settings.model_copy(update={"engagement": name})
        self.workspace = self._open_workspace()
        if self.workspace is None:  # pragma: no cover -- name is always truthy here
            msg = f"could not open workspace for engagement {name!r}"
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
        self.ledger.start_session(self.session_id, engagement_name=name, mode=self.mode)
        self._ensure_threat_model_version()

        self.graph = self._build()
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
        self.graph = self._build()  # so GraphDeps carries the new threat model
        return self.ledger.record_threat_model(self._threat_model_snapshot(), note=note)

    # ----- self-update (the `update` verb) -----------------------------------

    def self_update(self, runner: updater.UpdateRunner | None = None) -> Iterator[str]:
        """Update the install in place: ``git pull --ff-only`` then a dependency sync.

        Thin delegator to :func:`skuggi.install.update.perform_update`; ``runner``
        is forwarded so the subprocess path stays injectable and testable.
        """
        return updater.perform_update(runner)

    # ----- session logging, retrieval, replay & review ----------------------

    def note_interaction(self, verb: str, detail: str = "") -> None:
        """Record a harness-control interaction to the audit log (not the timeline).

        Called by both front-ends for every ``control`` verb (config, mode,
        doctor, help, replay, review, ...). Engagement verbs (ask/run) are left
        out -- their activity is the timeline itself.
        """
        self.ledger.record_audit(
            session_id=self.session_id, kind="control", verb=verb, detail=detail
        )

    def record_passthrough(self, cmdline: str) -> None:
        """Log a free-typed shell command the operator ran (the wrapped shell).

        The operator's own commands are not vetoed (scope is not checked -- the
        honest boundary is that skuggi only *proposes* commands, guarded by the
        executor); this simply records what actually ran. Navigation/builtin noise
        (``settings.passthrough_skip``) goes to the audit ``cli`` channel; every
        other command lands on the engagement timeline as ``passthrough``.
        """
        raw = cmdline.strip()
        if not raw:
            return
        if raw.split()[0] in self.settings.passthrough_skip:
            self.ledger.record_audit(session_id=self.session_id, kind="cli", detail=raw)
            return
        parsed = parse_command(raw, self.registry)
        self.ledger.record_command(
            session_id=self.session_id,
            thread_id=self.thread_id,
            command=raw,
            binary=parsed.binary,
            method=parsed.method,
            status="passthrough",
        )

    # ----- the agent turn ----------------------------------------------------

    def _config(self) -> RunnableConfig:
        return {
            "configurable": {"thread_id": self.thread_id},
            "recursion_limit": recursion_limit(
                max_revisions=self.settings.max_revisions,
                max_command_rounds=self.settings.max_tool_rounds,
            ),
        }

    def state(self) -> AgentState:
        """The current graph state for the active thread."""
        values = self.graph.get_state(self._config()).values
        if isinstance(values, dict) and values:
            return cast("AgentState", values)
        return {"messages": []}

    def turn(self, user_text: str) -> Iterator[TurnEvent]:
        """Run one agent turn, yielding events as the graph streams.

        A bad turn yields a ``status`` error event rather than raising, so a
        front-end loop (REPL or daemon) is never killed by one failed turn.
        """
        initial: AgentState = {
            "messages": [HumanMessage(content=user_text)],
            "revision_count": 0,
            "max_revisions": self.settings.max_revisions,
        }
        # The prompt goes on the timeline first, and its id tags every command
        # this turn records (so a finding traces prompt -> command -> finding).
        self._current_turn_event_id = self.ledger.record_event(
            session_id=self.session_id,
            thread_id=self.thread_id,
            kind="prompt",
            text=user_text,
        )
        final_text = ""
        try:
            # Build the model on first use. A missing credential raises here and
            # is caught below, surfacing as a clean, actionable error event
            # (pointing at /setup) rather than a dead session.
            self._ensure_llm()
            # Structured output is not token-streamed; each node's state update is
            # turned into a status/final event as the graph advances.
            stream: Iterator[Any] = self.graph.stream(
                initial, self._config(), stream_mode="updates"
            )
            for payload in stream:
                for ev in self._turn_updates(cast("dict[str, object]", payload)):
                    if ev.kind == "final":
                        final_text = ev.text
                    yield ev
            # The turn is answered; now let the harness remember any standing
            # directive it carried (best-effort, never raises).
            for row in self.memory.maybe_capture(user_text):
                yield TurnEvent(
                    "status",
                    f"remembered: {row.text} (forget {row.id} to undo)",
                    node="memory",
                )
        except ConfigError as e:
            # A config/credential problem is already a full, actionable sentence
            # (e.g. "No OpenAI API key configured. Run /setup..."); show it as-is
            # rather than prefixing it with the exception class name.
            log.warning("turn aborted on config error: %s", e)
            final_text = f"[error] {e}"
            yield TurnEvent("status", str(e), node="error")
        except Exception as e:  # a bad turn must not kill the loop
            log.exception("turn failed")
            final_text = f"[error] {type(e).__name__}: {e}"
            yield TurnEvent("status", f"{type(e).__name__}: {e}", node="error")
        finally:
            # Close the turn on the timeline and stop tagging commands with it,
            # so a later /run proposal is recorded unlinked rather than misattributed.
            # This runs OUTSIDE the try above: a storage failure here must degrade
            # to a logged warning, never raise out of `turn` and kill the
            # front-end loop with the response already delivered.
            try:
                self.ledger.record_event(
                    session_id=self.session_id,
                    thread_id=self.thread_id,
                    kind="response",
                    text=final_text,
                )
            except Exception:  # closing the timeline must not crash the loop
                log.exception("failed to record turn-closing response event")
            self._current_turn_event_id = None

    def _turn_updates(self, payload: dict[str, object]) -> Iterator[TurnEvent]:
        for node, update in payload.items():
            values = update if isinstance(update, dict) else {}
            if node == "planner":
                yield TurnEvent("reset")
                steps = values.get("plan") or []
                if steps:
                    plan = "\n".join(
                        f"{i}. {step}" for i, step in enumerate(steps, start=1)
                    )
                    yield TurnEvent("status", plan, node="planner")
            elif node == "retriever":
                if values.get("context"):
                    yield TurnEvent(
                        "status", "inlined retrieved context", node="retriever"
                    )
            elif node == "worker":
                yield TurnEvent("reset")
                if values.get("draft"):
                    yield TurnEvent("final", str(values["draft"]))
            elif node == "executor":
                commands = values.get("commands") or []
                if commands:
                    last = commands[-1]
                    yield TurnEvent(
                        "status", f"{last.status}: {last.command}", node="executor"
                    )
            elif node == "critic":
                approved = values.get("approved")
                reason = values.get("critique") or ""
                verdict = "approved" if approved else "revise"
                text = f"{verdict}: {reason}" if reason else verdict
                yield TurnEvent("status", text, node="critic")
