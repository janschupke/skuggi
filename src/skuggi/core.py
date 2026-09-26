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
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast, get_args

from langchain_core.messages import AIMessageChunk, HumanMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import StreamMode
from pydantic import TypeAdapter, ValidationError

from skuggi import (
    __version__,
    execution,
    memory,
    pentest_tools,
    probe,
    providers,
    reports,
    tools,
)
from skuggi import ledger as ledger_mod
from skuggi.commands import CommandRegistry, raw_command
from skuggi.config import (
    _SECRET_FIELDS,
    Provider,
    Settings,
    config_path,
    write_config,
)
from skuggi.configs import (
    ConfigError,
    load_commands,
    load_layout,
    load_registry,
    load_scope,
)
from skuggi.engagement import (
    EngagementConfig,
    GuardVerdict,
    check_command,
    parse_command,
)
from skuggi.execution import CommandResult
from skuggi.graph import GraphDeps, build_graph, recursion_limit
from skuggi.ledger import FindingRow
from skuggi.modes import MODES, Mode, prompt_set
from skuggi.registry import RuntimeStatus, ToolRegistry, ToolStatus
from skuggi.state import AgentState
from skuggi.vectorstore import Store
from skuggi.workspace import Workspace, WorkspaceLayout

_STREAM_MODES: list[StreamMode] = ["updates", "messages"]
_PROVIDERS = get_args(Provider)

EventKind = Literal["reset", "status", "token", "final"]

# A subprocess runner for `update`, injectable so the path is captured + tested.
UpdateRunner = Callable[[list[str]], CommandResult]
# Update commands can build wheels; give them far longer than a scan's cap.
_UPDATE_TIMEOUT_S = 600.0


def _installed_version(root: Path) -> str:
    """Read ``__version__`` from the on-disk source (post-pull), or ``?``."""
    try:
        text = (root / "src" / "skuggi" / "__init__.py").read_text(encoding="utf-8")
    except OSError:
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
    """The result of resolving a ``run`` alias: the raw command + scope verdict.

    ``raw`` is the fully-resolved command string shown to the operator (the
    transparency invariant). ``run`` never executes -- an in-scope command is
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

        self.layout = self._load_layout()
        self.workspace = self._open_workspace()
        self.engagement = self._load_scope()
        self.registry = self._load_registry()
        self.commands = self._load_commands()

        self._embeddings = providers.get_embeddings(self.settings)
        self.store = Store.from_settings(self.settings, self._embeddings)
        self.llm = providers.get_chat_model(self.settings, model=self.model)

        self._saver_ctx = memory.open_checkpointer(self.settings.sqlite_path)
        self.saver = self._saver_ctx.__enter__()
        self._ledger_ctx = ledger_mod.open_ledger(self._ledger_path())
        self.ledger = self._ledger_ctx.__enter__()
        self.ledger.start_session(
            self.session_id,
            engagement_name=self.engagement.name if self.engagement else "(none)",
            mode=self.mode,
        )

        self.tools_list = self.build_tools()
        self.graph = self._build()

    # ----- config + workspace ------------------------------------------------

    def _load_layout(self) -> WorkspaceLayout:
        try:
            return load_layout(self.settings.layout_path)
        except ConfigError as exc:
            self.warnings.append(f"invalid workspace layout, using defaults: {exc}")
            return WorkspaceLayout()

    def _open_workspace(self) -> Workspace | None:
        if not self.settings.engagement:
            self.warnings.append(
                "no engagement selected (set SKUGGI_ENGAGEMENT); running agent-only"
            )
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
            self.warnings.append(f"no engagement loaded: {exc}")
            return None

    def _load_registry(self) -> ToolRegistry:
        try:
            return load_registry(self.settings.registry_path)
        except ConfigError as exc:
            self.warnings.append(f"no tool registry loaded: {exc}")
            return ToolRegistry()

    def _load_commands(self) -> CommandRegistry:
        try:
            return load_commands(self.settings.commands_path)
        except ConfigError as exc:
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

    def build_tools(self) -> list[BaseTool]:
        """Base tools plus the pentest tools when an engagement is loaded."""
        built = tools.build_tools(self.store, k=self.settings.retrieve_k)
        if self.engagement is not None:
            built += pentest_tools.build_pentest_tools(
                engagement=self.engagement,
                registry=self.registry,
                ledger=self.ledger,
                session_id=self.session_id,
                thread_id=lambda: self.thread_id,
                settings=self.settings,
                cwd=self._recon_cwd(),
            )
        return built

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
            tools=self.tools_list,
            store=self.store,
            bind_tools=self.settings.supports_tools(),
            max_tool_rounds=self.settings.max_tool_rounds,
            retrieve_k=self.settings.retrieve_k,
            history_messages=self.settings.history_messages,
            history_chars=self.settings.history_chars,
            prompts=prompt_set(self.mode),
        )

    def _build(self) -> CompiledStateGraph[AgentState]:
        return build_graph(self._deps(), self.saver)

    def close(self) -> None:
        """Close the ledger and checkpointer connections held for the session."""
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

    def _rebuild_llm(self) -> None:
        self.llm = providers.get_chat_model(self.settings, model=self.model)
        self.graph = self._build()

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
        self.tools_list = self.build_tools()
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

        self.tools_list = self.build_tools()
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
        """Ask the LLM to map a natural-language request to ``key=value`` edits.

        Returns only proposals whose key is an editable setting; the front-end
        shows them and applies on confirmation. Never proposes a secret.
        """
        keys = ", ".join(sorted(self.settable_config_keys()))
        prompt = (
            "You edit a JSON application config. Given the request, output only "
            "the settings to change, one per line as `key=value`, choosing keys "
            f"from: {keys}. Output nothing else and never output a secret.\n"
            f"Request: {request}"
        )
        reply = self.llm.invoke(prompt)
        content = getattr(reply, "content", reply)
        settable = self.settable_config_keys()
        proposals: list[tuple[str, str]] = []
        for line in str(content).splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() in settable:
                proposals.append((key.strip(), value.strip()))
        return proposals

    # ----- self-update (the `update` verb) -----------------------------------

    def self_update(self, runner: UpdateRunner | None = None) -> Iterator[str]:
        """Update the install in place: ``git pull --ff-only`` then ``uv sync``.

        Yields progress text. `runner` is injected (default ``execution.run``,
        bound to the repo root) so the subprocess path stays captured and
        testable. A non-zero step aborts; code changes take effect on restart.
        """
        root = Path(__file__).resolve().parents[2]
        run_cmd = runner or (
            lambda argv: execution.run(argv, timeout=_UPDATE_TIMEOUT_S, cwd=root)
        )
        yield f"skuggi {__version__} -- updating in {root}\n"
        for argv in (["git", "pull", "--ff-only"], ["uv", "sync"]):
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

    def write_report(self) -> Path:
        """Write the session's Markdown report and return its path."""
        return reports.write_report(
            self.session_id,
            self.ledger,
            self.reports_dir,
            engagement=self.engagement,
        )

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

    def plan_run(self, name: str, extra: list[str]) -> RunPlan:
        """Resolve a ``run`` alias, check it against scope, and record it.

        Returns a plan carrying the resolved raw command and the guard verdict.
        Never executes: an in-scope command is recorded ``proposed`` (for the
        operator to submit), an out-of-scope one ``blocked``.
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
        raw = raw_command(alias.resolve(extra))
        if self.engagement is None:
            return RunPlan(
                alias=name,
                raw=raw,
                known=True,
                verdict=None,
                command_id=None,
                note="no engagement loaded -- scope not checked; review before running",
            )
        parsed = parse_command(raw, self.registry)
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
        )
        return RunPlan(
            alias=name,
            raw=raw,
            known=True,
            verdict=verdict,
            command_id=command_id,
            note="in scope" if verdict.allowed else verdict.reason,
        )

    # ----- the agent turn ----------------------------------------------------

    def _config(self) -> RunnableConfig:
        return {
            "configurable": {"thread_id": self.thread_id},
            "recursion_limit": recursion_limit(
                max_revisions=self.settings.max_revisions,
                max_tool_rounds=self.settings.max_tool_rounds,
            ),
        }

    def state(self) -> AgentState:
        """The current graph state for the active thread."""
        values = self.graph.get_state(self._config()).values
        if isinstance(values, dict) and values:
            return cast("AgentState", values)
        return {"messages": [], "scratch": []}

    def turn(self, user_text: str) -> Iterator[TurnEvent]:
        """Run one agent turn, yielding events as the graph streams.

        A bad turn yields a ``status`` error event rather than raising, so a
        front-end loop (REPL or daemon) is never killed by one failed turn.
        """
        initial: AgentState = {
            "messages": [HumanMessage(content=user_text)],
            "scratch": [],
            "revision_count": 0,
            "max_revisions": self.settings.max_revisions,
            "tool_rounds": 0,
        }
        run_id: str | None = None
        try:
            # A multi-mode stream is heterogeneous -- (mode, payload) pairs whose
            # payload shape depends on the mode -- so it is typed loosely and
            # narrowed here.
            stream: Iterator[Any] = self.graph.stream(
                initial, self._config(), stream_mode=_STREAM_MODES
            )
            for item in stream:
                event, payload = cast("tuple[str, Any]", item)
                if event == "messages":
                    chunk, meta = payload
                    node = (meta or {}).get("langgraph_node", "")
                    if node == "worker" and isinstance(chunk, AIMessageChunk):
                        if chunk.id != run_id:
                            run_id = chunk.id
                            yield TurnEvent("reset")
                        if chunk.text:
                            yield TurnEvent("token", chunk.text)
                elif event == "updates":
                    yield from self._turn_updates(payload)
        except Exception as e:  # noqa: BLE001 -- a bad turn must not kill the loop
            yield TurnEvent("status", f"{type(e).__name__}: {e}", node="error")

    def _turn_updates(self, payload: dict[str, object]) -> Iterator[TurnEvent]:
        for node, update in payload.items():
            values = update if isinstance(update, dict) else {}
            if node == "planner":
                yield TurnEvent("reset")
                if values.get("plan"):
                    yield TurnEvent("status", str(values["plan"]), node="planner")
            elif node == "retriever":
                if values.get("context"):
                    yield TurnEvent(
                        "status", "inlined retrieved context", node="retriever"
                    )
            elif node == "tools":
                yield TurnEvent("reset")
            elif node == "finalize":
                yield TurnEvent("final", str(values.get("draft") or ""))
            elif node == "critic":
                if values.get("critique"):
                    yield TurnEvent("status", str(values["critique"]), node="critic")
