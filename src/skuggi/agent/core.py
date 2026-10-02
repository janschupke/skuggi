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

import re
import sys
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast, get_args

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph
from pydantic import SecretStr, TypeAdapter, ValidationError

from skuggi import __version__
from skuggi.agent import prompts
from skuggi.agent.graph import GraphDeps, build_graph, recursion_limit
from skuggi.agent.modes import MODES, Mode, prompt_set
from skuggi.agent.protocol import ConfigProposal, MemoryExtraction, structured_invoke
from skuggi.agent.state import AgentState
from skuggi.common import execution, logs
from skuggi.common.execution import CommandResult
from skuggi.common.text import join_blocks, labeled
from skuggi.config.config import (
    _SECRET_FIELDS,
    Provider,
    Settings,
    config_path,
    write_config,
)
from skuggi.config.configs import (
    ConfigError,
    load_commands,
    load_layout,
    load_registry,
    load_scope,
    write_commands,
)
from skuggi.engagement.engagement import (
    EngagementConfig,
    GuardVerdict,
    check_command,
    parse_command,
)
from skuggi.engagement.workspace import Workspace, WorkspaceLayout
from skuggi.frontend.commands import CommandAlias, CommandRegistry, raw_command, render
from skuggi.install import envfile
from skuggi.persistence import ledger as ledger_mod
from skuggi.persistence import memory, preferences, reports
from skuggi.persistence import transcript as transcript_mod
from skuggi.persistence.ledger import FindingRow, SessionRow
from skuggi.persistence.vectorstore import Store
from skuggi.providers import providers
from skuggi.tooling import probe
from skuggi.tooling.registry import RuntimeStatus, ToolRegistry, ToolStatus

log = logs.get_logger(__name__)

_PROVIDERS = get_args(Provider)

# The API-key providers: provider name -> (env-file key, Settings field). The
# key persists to skuggi's own secret file; the field holds it on the live
# Settings. chatgpt (OAuth) and ollama (no key) are deliberately absent.
_API_KEY_FIELDS: dict[str, tuple[str, str]] = {
    "openai": ("OPENAI_API_KEY", "openai_api_key"),
    "anthropic": ("ANTHROPIC_API_KEY", "anthropic_api_key"),
}

# How much captured command output to feed the reviewer per command -- enough to
# judge what happened without blowing the prompt budget on a noisy scan dump.
_REVIEW_OUTPUT_CAP = 2_000

EventKind = Literal["reset", "status", "token", "final"]

# A subprocess runner for `update`, injectable so the path is captured + tested.
UpdateRunner = Callable[[list[str]], CommandResult]
# Update commands can build wheels; give them far longer than a scan's cap.
_UPDATE_TIMEOUT_S = 600.0


def _checkout_root() -> Path | None:
    """The git checkout this module is running from, or None for a wheel copy.

    ``skuggi`` is installed with ``uv tool install --editable``, whose ``.pth``
    points at the checkout's ``src``, so ``parents[3]`` is the repo root (this
    module lives at ``src/skuggi/agent/core.py``). A non-editable install has no
    checkout at all, and there ``parents[3]`` lands somewhere inside the tool
    environment's ``site-packages`` -- which is why the result is verified rather
    than assumed. Running ``git pull`` in a stranger's directory is the failure
    this guards.
    """
    here = Path(__file__).resolve()
    root = here.parents[3]
    if here.parents[2].name != "src":
        return None
    if not (root / "pyproject.toml").is_file() or not (root / ".git").exists():
        return None
    return root


def _is_uv_tool_env() -> bool:
    """Whether the running interpreter is a ``uv tool`` environment.

    ``uv`` drops a ``uv-receipt.toml`` beside ``pyvenv.cfg`` in a tool env and
    nowhere else, which makes this a one-file check rather than path arithmetic
    against ``uv tool dir``. It decides which command refreshes dependencies:
    ``uv sync`` syncs the *checkout's* ``.venv``, which is the wrong environment
    when skuggi is running from a tool install.
    """
    return (Path(sys.prefix) / "uv-receipt.toml").is_file()


def _installed_version(root: Path) -> str:
    """Read ``__version__`` from the on-disk source (post-pull), or ``?``."""
    try:
        text = (root / "src" / "skuggi" / "__init__.py").read_text(encoding="utf-8")
    except OSError as exc:
        log.debug("could not read installed version from %s: %s", root, exc)
        return "?"
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else "?"


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


@dataclass(frozen=True, slots=True)
class RunPlan:
    """The result of resolving a ``cmd`` alias: the raw command + scope verdict.

    ``raw`` is the fully-rendered command string shown to the operator (the
    transparency invariant). ``cmd`` never executes -- an in-scope command is
    recorded ``proposed`` for the operator to submit; an out-of-scope one is
    recorded ``blocked``.
    """

    alias: str
    raw: str
    known: bool
    verdict: GuardVerdict | None
    command_id: int | None
    note: str


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
        self.ledger.start_session(
            self.session_id,
            engagement_name=self.engagement.name if self.engagement else "(none)",
            mode=self.mode,
        )
        # Harness memory: global operator preferences, injected into every turn.
        self._prefs_ctx = preferences.open_preferences(self.settings.preferences_path)
        self.prefs = self._prefs_ctx.__enter__()

        self.graph = self._build()

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
            prompts=prompt_set(self.mode),
        )

    def _build(self) -> CompiledStateGraph[AgentState]:
        return build_graph(self._deps(), self.saver)

    def close(self) -> None:
        """Close the ledger, preferences and checkpointer connections."""
        self._prefs_ctx.__exit__(None, None, None)
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
            msg = f"invalid scope: {exc}"
            raise ConfigError(msg) from exc
        workspace = Workspace.for_engagement(
            self.settings.engagements_dir, scope.name, layout=self.layout
        )
        workspace.ensure()
        workspace.scope_path.write_text(
            scope.model_dump_json(indent=2), encoding="utf-8"
        )
        return self.load_engagement(scope.name)

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
        self.session_id = str(uuid.uuid4())
        self.ledger.start_session(self.session_id, engagement_name=name, mode=self.mode)

        self.graph = self._build()
        return self.engagement

    # ----- app config (the `config` verb) ------------------------------------

    @staticmethod
    def settable_config_keys() -> frozenset[str]:
        """Config keys the operator may edit -- every setting except secrets."""
        return frozenset(Settings.model_fields) - _SECRET_FIELDS

    def config_summary(self) -> str:
        """Every setting, one per line, with credentials redacted."""
        data = self.settings.model_dump(mode="json")
        lines = []
        for key in sorted(data):
            value = "***" if key in _SECRET_FIELDS and data[key] else data[key]
            lines.append(f"{key} = {value}")
        return "\n".join(lines)

    def config_line(self, arg: str) -> str | None:
        """Handle the mechanical `config` forms; None means "escalate to the LLM".

        ``config`` / ``config show`` prints the settings; ``config <key> <value>``
        for a known setting applies it. A first word that is not a setting is a
        natural-language request, which the interactive front-end escalates.
        """
        key, _, rest = arg.strip().partition(" ")
        if not key or key == "show":
            return self.config_summary()
        if key not in self.settable_config_keys():
            return None
        value = rest.strip()
        if not value:
            return f"usage: config {key} <value>"
        return self.apply_config(key, value)

    def apply_config(self, key: str, value: str) -> str:
        """Validate, persist and (where possible) hot-apply one setting.

        Coerces `value` to the field's type, writes it to ``configs/config.json``
        (never a secret), and applies ``provider``/``mode`` to the live session;
        other keys persist and take effect on restart.
        """
        if key in _SECRET_FIELDS:
            return f"config: {key} is a secret -- set it in the environment"
        if key not in Settings.model_fields:
            return f"config: unknown setting {key!r}"
        adapter: TypeAdapter[object] = TypeAdapter(
            Settings.model_fields[key].annotation
        )
        try:
            coerced = adapter.validate_python(value)
        except ValidationError:
            return f"config: invalid value for {key}: {value!r}"
        json_value = adapter.dump_python(coerced, mode="json")
        write_config(config_path(), {key: json_value})
        try:
            if key == "provider":
                self.set_provider(str(coerced))
                applied = True
            elif key == "mode":
                self.set_mode(str(coerced))
                applied = True
            else:
                self.settings = self.settings.model_copy(update={key: coerced})
                applied = False
        except (ValueError, RuntimeError, ImportError) as exc:
            return f"config: {key} written, but the live switch failed: {exc}"
        tail = "applied live" if applied else "written; restart to apply"
        return f"config: {key} = {json_value} ({tail})"

    def propose_config(self, request: str) -> list[tuple[str, str]]:
        """Ask the LLM to map a natural-language request to config edits.

        Returns only proposals whose key is an editable setting; the front-end
        shows them and applies on confirmation. Never proposes a secret. The reply
        is a strict ``ConfigProposal``, so no free-text key=value parsing.
        """
        keys = ", ".join(sorted(self.settable_config_keys()))
        proposal = structured_invoke(
            self._ensure_llm(),
            ConfigProposal,
            [
                SystemMessage(
                    content=prompts.PROPOSE_CONFIG_INSTRUCTION.format(keys=keys)
                ),
                HumanMessage(content=request),
            ],
            native=self.settings.supports_structured_output(),
        )
        settable = self.settable_config_keys()
        return [
            (edit.key.strip(), edit.value.strip())
            for edit in proposal.edits
            if edit.key.strip() in settable
        ]

    # ----- self-update (the `update` verb) -----------------------------------

    def self_update(self, runner: UpdateRunner | None = None) -> Iterator[str]:
        """Update the install in place: ``git pull --ff-only`` then a dependency sync.

        Yields progress text. `runner` is injected (default ``execution.run``,
        bound to the repo root) so the subprocess path stays captured and
        testable. A non-zero step aborts; code changes take effect on restart.

        Two install shapes, two second steps. From the checkout's own ``.venv``,
        ``uv sync`` is right. From a ``uv tool`` environment it is not -- it would
        sync the checkout's ``.venv`` while skuggi keeps running the tool env's
        dependencies -- so the tool install is refreshed instead. Without a
        checkout at all there is nothing to pull, and we say so rather than
        running git somewhere arbitrary.
        """
        root = _checkout_root()
        if root is None:
            yield (
                f"skuggi {__version__} -- not running from a git checkout, "
                "so there is nothing to pull.\n"
                "Reinstall with: uv tool install --editable <path/to/skuggi> --force\n"
            )
            return
        run_cmd = runner or (
            lambda argv: execution.run(argv, timeout=_UPDATE_TIMEOUT_S, cwd=root)
        )
        sync = (
            ["uv", "tool", "install", "--editable", f"{root}[pdf]", "--force"]
            if _is_uv_tool_env()
            else ["uv", "sync", "--all-groups", "--all-extras"]
        )
        yield f"skuggi {__version__} -- updating in {root}\n"
        for argv in (["git", "pull", "--ff-only"], sync):
            yield f"$ {' '.join(argv)}\n"
            result = run_cmd(list(argv))
            output = (result.stdout + result.stderr).strip()
            if output:
                yield output + "\n"
            if result.exit_code != 0:
                yield f"update aborted: '{' '.join(argv)}' exited {result.exit_code}\n"
                return
        after = _installed_version(root)
        yield f"updated to skuggi {after}; restart skuggi to run the new code\n"

    def findings(self) -> list[FindingRow]:
        """Findings recorded this session."""
        return self.ledger.findings_for(self.session_id)

    def write_report(self, *, pdf: bool = False) -> Path | tuple[Path, Path]:
        """Write the session's Markdown report and return its path.

        With ``pdf=True`` a styled PDF is written alongside the canonical
        Markdown and both paths are returned.
        """
        return reports.write_report(
            self.session_id,
            self.ledger,
            self.reports_dir,
            engagement=self.engagement,
            pdf=pdf,
        )

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

    def list_sessions(self) -> list[SessionRow]:
        """Every session recorded in this engagement's ledger, newest first."""
        return self.ledger.sessions()

    def _resolve_session_id(self, ref: str | None) -> str | None:
        """Resolve a session reference (full id or short prefix) to a session id.

        An empty reference means the current session; otherwise the first
        session whose id equals or starts with `ref` (the short ids shown by
        ``replay list``). ``None`` when nothing matches.
        """
        if not ref:
            return self.session_id
        for row in self.ledger.sessions():
            if row.session_id == ref or row.session_id.startswith(ref):
                return row.session_id
        return None

    def _render_session(
        self, session_ref: str | None, *, max_output: int | None
    ) -> tuple[str | None, str]:
        """Resolve a session and render its transcript; shared by replay + review.

        Returns ``(session_id, text)``; ``session_id`` is ``None`` (and `text` an
        error message) when the reference matches no session.
        """
        sid = self._resolve_session_id(session_ref)
        if sid is None:
            return None, f"no session found for {session_ref!r}"
        session = self.ledger.session(sid)
        if session is None:  # pragma: no cover -- a resolved id always has a row
            return None, f"no session recorded for {sid!r}"
        events = self.ledger.events_for(sid)
        commands = {c.id: c for c in self.ledger.commands_for(sid)}
        findings = {f.id: f for f in self.ledger.findings_for(sid)}
        text = transcript_mod.render_transcript(
            session, events, commands, findings, max_output=max_output
        )
        return sid, text

    def transcript(self, session_ref: str | None = None) -> str:
        """The ordered, replayable transcript of a session (default: current)."""
        return self._render_session(session_ref, max_output=None)[1]

    def review_session(self, session_ref: str | None = None) -> str:
        """Ask the LLM for private feedback on a session, and audit-log it.

        Reads the session timeline, prompts the model (one-shot ``invoke``, so it
        works on every provider, including the tool-less chatgpt one), records the
        critique to the audit log (never the client-facing report), and returns
        it. ``settings.review_model`` overrides the model used.
        """
        sid, timeline = self._render_session(session_ref, max_output=_REVIEW_OUTPUT_CAP)
        if sid is None:
            return timeline  # the "no session" message
        prompt = join_blocks(
            prompts.REVIEW_INSTRUCTION,
            labeled("Session timeline", timeline, heading=True),
        )
        llm = (
            self._ensure_llm()
            if self.settings.review_model is None
            else providers.get_chat_model(
                self.settings, model=self.settings.review_model
            )
        )
        reply = llm.invoke(prompt)
        content = str(getattr(reply, "content", reply))
        self.ledger.record_audit(
            session_id=self.session_id, kind="review", detail=content
        )
        return content

    # ----- harness memory (operator preferences) -----------------------------

    def list_preferences(self) -> list[preferences.PreferenceRow]:
        """Every remembered operator preference (grouped by category)."""
        return self.prefs.all()

    def add_preference(
        self, text: str, *, source: str = "manual"
    ) -> preferences.PreferenceRow | None:
        """Remember one preference, rebuilding the graph so the next turn sees it.

        Returns the stored row, or ``None`` if it was blank or a duplicate.
        """
        row = self.prefs.add(text, source=source)
        if row is not None:
            self.graph = self._build()
        return row

    def forget_preference(self, pref_id: int) -> bool:
        """Drop one preference by id; ``True`` if it existed. Rebuilds the graph."""
        removed = self.prefs.forget(pref_id)
        if removed:
            self.graph = self._build()
        return removed

    def clear_preferences(self) -> int:
        """Drop every preference; returns how many. Rebuilds the graph if any."""
        removed = self.prefs.clear()
        if removed:
            self.graph = self._build()
        return removed

    def maybe_capture_preferences(
        self, user_text: str
    ) -> list[preferences.PreferenceRow]:
        """Automatically capture any standing directive in `user_text`.

        Harness-side automatic memory, run post-turn: gated first by the cheap
        `preferences.looks_like_directive` heuristic (so an ordinary request never
        spends a model call), then by a one-shot structured extraction (a strict
        ``MemoryExtraction``, which works on every provider including the tool-less
        chatgpt one via the JSON-contract fallback). Persists each captured
        directive with source ``auto`` and returns the rows actually stored
        (deduped). Never raises -- a capture failure must not break the turn.
        """
        if not self.settings.memory_auto or not preferences.looks_like_directive(
            user_text
        ):
            return []
        if self.llm is None:  # no model configured; nothing to extract with
            return []
        try:
            extraction = structured_invoke(
                self.llm,
                MemoryExtraction,
                [
                    SystemMessage(content=prompts.MEMORY_EXTRACTION_INSTRUCTION),
                    HumanMessage(content=user_text),
                ],
                native=self.settings.supports_structured_output(),
            )
        except Exception:  # best-effort; a failure is not fatal
            log.exception("preference extraction failed; capturing nothing this turn")
            return []
        captured: list[preferences.PreferenceRow] = []
        for directive in extraction.directives:
            text = directive.strip()
            if not text:
                continue
            row = self.prefs.add(text, source="auto")
            if row is not None:
                captured.append(row)
        if captured:
            self.graph = self._build()
        return captured

    def doctor_statuses(self) -> list[ToolStatus]:
        """Probe the host for every recognized tool."""
        return probe.probe(
            self.registry,
            source=self.settings.tool_source,
            managed_dir=self.settings.managed_tools_dir,
        )

    def runtime_statuses(self) -> list[RuntimeStatus]:
        """Probe the host for the standard runtimes/toolchains."""
        return probe.probe_runtimes()

    def net_tool_statuses(self) -> list[RuntimeStatus]:
        """Probe the host for the standard Unix net tools."""
        return probe.probe_net_tools()

    def install_tool(self, binary: str) -> ToolStatus | None:
        """Install one recognized tool; returns its status, or None if unknown."""
        spec = self.registry.spec_for(binary)
        if spec is None:
            return None
        return probe.install_tool(
            spec,
            source=self.settings.tool_source,
            managed_dir=self.settings.managed_tools_dir,
        )

    def search_commands(self, query: str) -> tuple[CommandAlias, ...]:
        """Cheatsheet aliases matching `query` by substring (blank = all)."""
        return self.commands.search(query)

    def plan_cmd(self, name: str) -> RunPlan:
        """Render a cheatsheet alias, check it against scope, and record it.

        Returns a plan carrying the rendered raw command (base argv + a literal
        ``${target}`` + the tool's timestamped output flag) and the guard
        verdict. Never executes: an in-scope command is recorded ``proposed``,
        an out-of-scope one ``blocked``.

        The displayed/recorded command keeps ``${target}`` literal, so the scope
        check is run against a *clean* parse of the base argv plus the
        engagement's resolved target. When no single target resolves, the target
        rule is skipped (tool/method/time are still enforced) and the note says
        so -- the operator must confirm the host is in scope themselves.
        """
        alias = self.commands.alias_for(name)
        if alias is None:
            avail = ", ".join(self.commands.names()) or "(none configured)"
            return RunPlan(
                alias=name,
                raw="",
                known=False,
                verdict=None,
                command_id=None,
                note=f"unknown alias {name!r}. available: {avail}",
            )
        raw = render(alias, self.registry)
        if self.engagement is None:
            return RunPlan(
                alias=name,
                raw=raw,
                known=True,
                verdict=None,
                command_id=None,
                note="no engagement loaded -- scope not checked; review before running",
            )
        resolved = self.engagement.resolve_target()
        check_argv = [*alias.argv, *([resolved] if resolved else [])]
        parsed = parse_command(raw_command(check_argv), self.registry)
        if resolved is None:
            # No concrete target to check; validate tool/method/time only.
            parsed = replace(parsed, requires_target=False, targets=())
        verdict = check_command(
            parsed, self.engagement, now=datetime.now(self.engagement.tzinfo())
        )
        status = "proposed" if verdict.allowed else "blocked"
        command_id = self.ledger.record_command(
            session_id=self.session_id,
            thread_id=self.thread_id,
            command=raw,
            binary=parsed.binary,
            method=parsed.method,
            status=status,
            reason="" if verdict.allowed else verdict.reason,
            turn_event_id=self._current_turn_event_id,
        )
        if not verdict.allowed:
            note = verdict.reason
        elif resolved is not None:
            note = f"in scope (target {resolved})"
        else:
            note = (
                "tool/method/time in scope -- set 'target' to an in-scope host "
                "before running (${target} is a placeholder)"
            )
        return RunPlan(
            alias=name,
            raw=raw,
            known=True,
            verdict=verdict,
            command_id=command_id,
            note=note,
        )

    def _validate_alias(self, raw: dict[str, object]) -> CommandAlias:
        try:
            return CommandAlias.model_validate(raw)
        except ValidationError as exc:
            msg = f"invalid command alias: {exc}"
            raise ConfigError(msg) from exc

    def _save_commands(self, registry: CommandRegistry) -> None:
        write_commands(self.settings.commands_path, registry)
        self.commands = registry

    def add_command(self, raw: dict[str, object]) -> CommandAlias:
        """Validate and append a new cheatsheet alias, persisting the registry.

        Raises ``ConfigError`` if the alias does not validate or its name is
        already taken (the editor shows the reason and re-asks).
        """
        alias = self._validate_alias(raw)
        if self.commands.alias_for(alias.name) is not None:
            msg = f"command alias {alias.name!r} already exists (use edit)"
            raise ConfigError(msg)
        self._save_commands(CommandRegistry(commands=(*self.commands.commands, alias)))
        return alias

    def update_command(self, name: str, raw: dict[str, object]) -> CommandAlias:
        """Replace the alias named `name`, persisting the registry.

        Raises ``ConfigError`` if `name` is unknown or the new alias is invalid.
        """
        if self.commands.alias_for(name) is None:
            msg = f"unknown command alias {name!r}"
            raise ConfigError(msg)
        alias = self._validate_alias(raw)
        self._save_commands(
            CommandRegistry(
                commands=tuple(
                    alias if a.name == name else a for a in self.commands.commands
                )
            )
        )
        return alias

    def remove_command(self, name: str) -> bool:
        """Drop the alias named `name`; ``True`` if it existed. Persists the change."""
        if self.commands.alias_for(name) is None:
            return False
        self._save_commands(
            CommandRegistry(
                commands=tuple(a for a in self.commands.commands if a.name != name)
            )
        )
        return True

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
            for row in self.maybe_capture_preferences(user_text):
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
