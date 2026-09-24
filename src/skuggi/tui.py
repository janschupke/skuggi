"""Rich + prompt_toolkit REPL with slash commands.

Non-slash input goes through the agent graph against the current
checkpointed thread; the worker's tokens stream into a `rich.live.Live` pane
while the planner and critic report one line each.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from pathlib import Path

from langchain_core.messages import AIMessage, AIMessageChunk, BaseMessage, HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import StreamMode
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.table import Table

from skuggi import memory, providers, tools
from skuggi.config import Provider, Settings
from skuggi.graph import GraphDeps, build_graph, recursion_limit
from skuggi.state import AgentState
from skuggi.vectorstore import Store

_STREAM_MODES: list[StreamMode] = ["updates", "messages"]
_PROVIDERS = ("openai", "chatgpt", "anthropic", "ollama")


class DraftView:
    """Accumulates the worker's tokens for one LLM run and renders them.

    Two things have to be filtered, and they are different problems:

    `stream_mode="messages"` emits every BaseMessage a node writes to state, not
    just tokens -- so without the AIMessageChunk check the worker's own system
    prompt and seeded request render into the visible answer.

    Within the worker, each tool round is a separate LLM run. A model that
    narrates before calling a tool ("Let me compute that.") would otherwise have
    that preamble concatenated with the final answer, so the buffer resets when
    the run id changes.
    """

    def __init__(self, live: Live) -> None:
        self._live = live
        self._run_id: str | None = None
        self.buffer = ""

    def reset(self) -> None:
        """Start a new run, discarding anything buffered."""
        self._run_id = None
        self.buffer = ""

    def push(self, chunk: BaseMessage, node: str) -> None:
        """Render one streamed item, ignoring anything that is not a token."""
        if node != "worker" or not isinstance(chunk, AIMessageChunk):
            return
        if chunk.id != self._run_id:
            self._run_id = chunk.id
            self.buffer = ""
        text = chunk.text
        if text:
            self.buffer += text
            self._live.update(Markdown(self.buffer))

    def show(self, final: str) -> None:
        """Render the authoritative draft, as judged by the critic."""
        self.buffer = final
        self._live.update(Markdown(final))


class Tui:
    """The interactive REPL."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        console: Console | None = None,
        session: PromptSession[str] | None = None,
    ) -> None:
        """Wire up a session. `console` and `session` are injectable for tests."""
        self.settings = settings or Settings()
        self.console = console or Console()
        self.model: str | None = None
        self.thread_id = str(uuid.uuid4())

        history_file = self.settings.history_path
        history_file.parent.mkdir(parents=True, exist_ok=True)
        self.session: PromptSession[str] = session or PromptSession(
            history=FileHistory(str(history_file))
        )

        self._embeddings = providers.get_embeddings(self.settings)
        self.store = Store(
            self.settings.faiss_path,
            self._embeddings,
            chunk_size=self.settings.chunk_size,
            chunk_overlap=self.settings.chunk_overlap,
        )
        self.tools_list = tools.build_tools(self.store, k=self.settings.retrieve_k)
        self.llm = providers.get_chat_model(self.settings, model=self.model)

        self._saver_ctx = memory.open_checkpointer(self.settings.sqlite_path)
        self.saver = self._saver_ctx.__enter__()
        self.graph = self._build()

        self._commands: dict[str, Callable[[str], bool | None]] = {
            "/help": self._cmd_help,
            "/provider": self._cmd_provider,
            "/model": self._cmd_model,
            "/thread": self._cmd_thread,
            "/history": self._cmd_history,
            "/trace": self._cmd_trace,
            "/clear": self._cmd_clear,
            "/ingest": self._cmd_ingest,
            "/quit": self._cmd_quit,
            "/exit": self._cmd_quit,
        }

    # ----- properties -----

    @property
    def provider(self) -> Provider:
        """The active provider name."""
        return self.settings.provider

    @property
    def max_revisions(self) -> int:
        """Critic revision budget for one turn."""
        return self.settings.max_revisions

    def _deps(self) -> GraphDeps:
        return GraphDeps(
            llm=self.llm,
            tools=self.tools_list,
            store=self.store,
            bind_tools=self.settings.supports_tools(),
            max_tool_rounds=self.settings.max_tool_rounds,
            retrieve_k=self.settings.retrieve_k,
        )

    def _build(self) -> CompiledStateGraph[AgentState]:
        return build_graph(self._deps(), self.saver)

    # ----- lifecycle -----

    def run(self) -> None:
        """Read, dispatch, repeat until the user leaves."""
        self._banner()
        try:
            while True:
                try:
                    line = self.session.prompt(self._prompt())
                except (EOFError, KeyboardInterrupt):
                    break
                except OSError as e:
                    self.console.print(f"[red]input error:[/red] {e}")
                    break
                line = line.strip()
                if not line:
                    continue
                if line.startswith("/"):
                    if self.dispatch(line) is False:
                        break
                else:
                    self.turn(line)
        finally:
            self._saver_ctx.__exit__(None, None, None)
            self.console.print("[dim]bye.[/dim]")

    # ----- UI helpers -----

    def _prompt(self) -> str:
        model = self.model or "(default)"
        return f"[skuggi:{self.provider}/{model} thread={self.thread_id[:8]}] > "

    def _banner(self) -> None:
        self.console.rule("[bold]skuggi[/bold]")
        self.console.print(
            f"provider=[cyan]{self.provider}[/cyan]  "
            f"sqlite=[dim]{self.settings.sqlite_path}[/dim]  "
            f"faiss=[dim]{self.settings.faiss_path}[/dim]  "
            f"max_revisions=[dim]{self.max_revisions}[/dim]"
        )
        self.console.print("type /help for commands\n")

    def _line(self, node: str, text: str | None) -> None:
        if text:
            self.console.print(f"[dim]({node})[/dim] {text.splitlines()[0][:100]}")

    # ----- dispatch -----

    def dispatch(self, line: str) -> bool | None:
        """Run a slash command. Returns False to end the session."""
        parts = line.split(maxsplit=1)
        handler = self._commands.get(parts[0].lower())
        if handler is None:
            self.console.print(f"[red]unknown command:[/red] {parts[0]}")
            return None
        return handler(parts[1].strip() if len(parts) > 1 else "")

    def _cmd_quit(self, _arg: str) -> bool:
        return False

    def _cmd_help(self, _arg: str) -> None:
        table = Table(show_header=False, box=None)
        for command, description in HELP:
            table.add_row(f"[cyan]{command}[/cyan]", description)
        self.console.print(table)

    def _cmd_provider(self, arg: str) -> None:
        if arg not in _PROVIDERS:
            self.console.print(f"[red]unknown provider:[/red] {arg!r}")
            return
        self.settings = self.settings.model_copy(update={"provider": arg})
        self.model = None
        self._rebuild()

    def _cmd_model(self, arg: str) -> None:
        if not arg:
            self.console.print("[red]usage:[/red] /model <name>")
            return
        self.model = arg
        self._rebuild()

    def _rebuild(self) -> None:
        try:
            self.llm = providers.get_chat_model(self.settings, model=self.model)
        except (RuntimeError, ImportError) as e:
            self.console.print(f"[red]provider error:[/red] {e}")
            return
        self.graph = self._build()
        self.console.print(
            f"[dim]switched to[/dim] {self.provider}/{self.model or '(default)'}"
        )

    def _cmd_thread(self, arg: str) -> None:
        if arg in ("new", ""):
            self.thread_id = str(uuid.uuid4())
            self.console.print(f"[dim]new thread:[/dim] {self.thread_id}")
        elif arg == "list":
            ids = memory.list_threads(self.saver)
            if not ids:
                self.console.print("[dim](no threads)[/dim]")
                return
            for thread_id in ids:
                marker = " *" if thread_id == self.thread_id else ""
                self.console.print(f"  {thread_id}{marker}")
        else:
            self.thread_id = arg
            self.console.print(f"[dim]switched to thread:[/dim] {arg}")

    def _state(self) -> AgentState:
        snapshot = self.graph.get_state(self._config())
        return snapshot.values or {"messages": [], "scratch": []}

    def _cmd_history(self, arg: str) -> None:
        count = int(arg) if arg.isdigit() else 20
        labels = {"human": "you", "ai": "bot", "system": "sys", "tool": "tool"}
        for message in self._state().get("messages", [])[-count:]:
            self.console.print(
                f"[bold]{labels.get(message.type, message.type)}:[/bold] {message.text}"
            )

    def _cmd_trace(self, _arg: str) -> None:
        """Show the worker's tool trail, which /history deliberately excludes."""
        shown = False
        for message in self._state().get("scratch", []):
            if isinstance(message, AIMessage) and message.tool_calls:
                for call in message.tool_calls:
                    self.console.print(
                        f"[cyan]call[/cyan] {call['name']}({call['args']})"
                    )
                    shown = True
            elif message.type == "tool":
                self.console.print(f"[green]result[/green] {message.text[:200]}")
                shown = True
        if not shown:
            # Scratch is usually non-empty (the worker's prompt seed lives there),
            # so an emptiness check would print nothing at all on a tool-free turn.
            self.console.print("[dim](no tool activity on this thread)[/dim]")

    def _cmd_clear(self, _arg: str) -> None:
        self.console.clear()

    def _cmd_ingest(self, arg: str) -> None:
        if not arg:
            self.console.print("[red]usage:[/red] /ingest <path>")
            return
        added = self.store.ingest([Path(arg)])
        self.store.persist()
        self.console.print(f"[dim]indexed {added} chunk(s)[/dim]")

    # ----- agent turn -----

    def _config(self) -> RunnableConfig:
        return {
            "configurable": {"thread_id": self.thread_id},
            "recursion_limit": recursion_limit(
                max_revisions=self.settings.max_revisions,
                max_tool_rounds=self.settings.max_tool_rounds,
            ),
        }

    def turn(self, user_text: str) -> None:
        """Run one agent turn, streaming the worker's answer."""
        initial: AgentState = {
            "messages": [HumanMessage(content=user_text)],
            "scratch": [],
            "revision_count": 0,
            "max_revisions": self.settings.max_revisions,
            "tool_rounds": 0,
        }
        try:
            with Live("", console=self.console, refresh_per_second=20) as live:
                view = DraftView(live)
                for event, payload in self.graph.stream(
                    initial, self._config(), stream_mode=_STREAM_MODES
                ):
                    if event == "messages":
                        chunk, meta = payload
                        view.push(chunk, (meta or {}).get("langgraph_node", ""))
                    elif event == "updates":
                        self._handle_update(payload, view)
        except Exception as e:  # noqa: BLE001 -- a bad turn must not kill the REPL
            self.console.print(f"[red]turn error:[/red] {type(e).__name__}: {e}")

    def _handle_update(self, payload: dict[str, object], view: DraftView) -> None:
        for node, update in payload.items():
            values = update if isinstance(update, dict) else {}
            if node == "planner":
                view.reset()
                self._line("planner", values.get("plan"))
            elif node == "retriever":
                if values.get("context"):
                    self._line("retriever", "inlined retrieved context")
            elif node == "tools":
                view.reset()
            elif node == "finalize":
                view.show(str(values.get("draft") or ""))
            elif node == "critic":
                self._line("critic", values.get("critique"))


HELP: list[tuple[str, str]] = [
    ("/help", "show this help"),
    ("/provider <openai|chatgpt|anthropic|ollama>", "switch LLM provider"),
    ("/model <name>", "switch model (current provider)"),
    ("/thread new|list|<id>", "new/list/switch session thread"),
    ("/history [n]", "show last n messages on the current thread"),
    ("/trace", "show the worker's tool calls on the current thread"),
    ("/clear", "clear the screen"),
    ("/ingest <path>", "index a file or directory into FAISS"),
    ("/quit", "exit (alias /exit)"),
]
