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
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast, get_args

from langchain_core.messages import AIMessageChunk, HumanMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import StreamMode

from skuggi import ledger as ledger_mod
from skuggi import memory, pentest_tools, probe, providers, reports, tools
from skuggi.config import Provider, Settings
from skuggi.configs import ConfigError, load_layout, load_registry, load_scope
from skuggi.engagement import EngagementConfig
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

        self.layout = self._load_layout()
        self.workspace = self._open_workspace()
        self.engagement = self._load_scope()
        self.registry = self._load_registry()

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
