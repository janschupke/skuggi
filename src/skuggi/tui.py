"""Rich + prompt_toolkit REPL with slash commands.

Non-slash input goes through the planner-worker-critic graph against the
current SqliteSaver-checkpointed thread; output streams via rich.live.Live.
"""

from __future__ import annotations

import uuid

from langchain_core.messages import HumanMessage
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.table import Table

from skuggi import memory, providers, tools
from skuggi.config import Provider, Settings
from skuggi.graph import build_graph
from skuggi.vectorstore import Store

_HELP = [
    ("/help", "show this help"),
    ("/provider <openai|chatgpt|anthropic|ollama>", "switch LLM provider"),
    ("/model <name>", "switch model (current provider)"),
    ("/thread new|list|<id>", "new/list/switch session thread"),
    ("/history [n]", "show last n messages on the current thread"),
    ("/clear", "clear the screen"),
    ("/ingest <path>", "index a file or directory into FAISS"),
    ("/quit", "exit (alias /exit)"),
]


class Tui:
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

    @property
    def provider(self) -> Provider:
        """The active provider name."""
        return self.settings.provider

    @property
    def max_revisions(self) -> int:
        """Critic revision budget for one turn."""
        return self.settings.max_revisions

    def _build(self) -> object:
        return build_graph(
            self.llm,
            self.tools_list,
            self.saver,
            bind_tools=self.settings.supports_tools(),
        )

    # ----- lifecycle -----

    def run(self) -> None:
        self._banner()
        try:
            while True:
                try:
                    line = self.session.prompt(self._prompt())
                except (EOFError, KeyboardInterrupt):
                    break
                except Exception as e:
                    self.console.print(f"[red]input error:[/red] {e}")
                    break
                line = line.strip()
                if not line:
                    continue
                if line.startswith("/"):
                    if self._dispatch(line) is False:
                        break
                else:
                    self._turn(line)
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

    # ----- slash dispatch -----

    def _dispatch(self, line: str) -> bool | None:
        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("/quit", "/exit"):
            return False
        if cmd == "/help":
            self._show_help()
        elif cmd == "/provider":
            self._set_provider(arg)
        elif cmd == "/model":
            self._set_model(arg)
        elif cmd == "/thread":
            self._thread(arg)
        elif cmd == "/history":
            n = int(arg) if arg.isdigit() else 20
            self._history(n)
        elif cmd == "/clear":
            self.console.clear()
        elif cmd == "/ingest":
            self._ingest(arg)
        else:
            self.console.print(f"[red]unknown command:[/red] {cmd}")
        return None

    def _show_help(self) -> None:
        t = Table(show_header=False, box=None)
        for cmd, desc in _HELP:
            t.add_row(f"[cyan]{cmd}[/cyan]", desc)
        self.console.print(t)

    def _set_provider(self, name: str) -> None:
        if name not in {"openai", "chatgpt", "anthropic", "ollama"}:
            self.console.print(f"[red]unknown provider:[/red] {name!r}")
            return
        self.settings = self.settings.model_copy(update={"provider": name})
        self.model = None
        self._rebuild()

    def _set_model(self, name: str) -> None:
        if not name:
            self.console.print("[red]usage:[/red] /model <name>")
            return
        self.model = name
        self._rebuild()

    def _rebuild(self) -> None:
        try:
            self.llm = providers.get_chat_model(self.settings, model=self.model)
        except Exception as e:
            self.console.print(f"[red]provider error:[/red] {e}")
            return
        self.graph = self._build()
        self.console.print(
            f"[dim]switched to[/dim] {self.provider}/{self.model or '(default)'}"
        )

    def _thread(self, arg: str) -> None:
        if arg == "new" or arg == "":
            self.thread_id = str(uuid.uuid4())
            self.console.print(f"[dim]new thread:[/dim] {self.thread_id}")
        elif arg == "list":
            ids = memory.list_threads(self.saver)
            if not ids:
                self.console.print("[dim](no threads)[/dim]")
                return
            for tid in ids:
                marker = " *" if tid == self.thread_id else ""
                self.console.print(f"  {tid}{marker}")
        else:
            self.thread_id = arg
            self.console.print(f"[dim]switched to thread:[/dim] {arg}")

    def _history(self, n: int) -> None:
        cfg = {"configurable": {"thread_id": self.thread_id}}
        snap = self.graph.get_state(cfg)
        msgs = (snap.values or {}).get("messages") or []
        for m in msgs[-n:]:
            label = {"human": "you", "ai": "bot", "system": "sys"}.get(m.type, m.type)
            content = m.content if isinstance(m.content, str) else str(m.content)
            self.console.print(f"[bold]{label}:[/bold] {content}")

    def _ingest(self, arg: str) -> None:
        if not arg:
            self.console.print("[red]usage:[/red] /ingest <path>")
            return
        added = self.store.ingest([Path(arg)])
        self.store.persist()
        self.console.print(f"[dim]indexed {added} chunk(s)[/dim]")

    # ----- agent turn -----

    def _turn(self, user_text: str) -> None:
        cfg = {"configurable": {"thread_id": self.thread_id}}
        initial = {
            "messages": [HumanMessage(content=user_text)],
            "plan": None,
            "draft": None,
            "critique": None,
            "revision_count": 0,
            "max_revisions": self.max_revisions,
        }
        try:
            with Live("", console=self.console, refresh_per_second=20) as live:
                buf = ""
                for event, payload in self.graph.stream(
                    initial, cfg, stream_mode=["updates", "messages"]
                ):
                    if event == "messages":
                        chunk, meta = payload
                        node = (meta or {}).get("langgraph_node")
                        if node != "worker":
                            continue
                        text = getattr(chunk, "content", "")
                        if isinstance(text, str) and text:
                            buf += text
                            live.update(Markdown(buf))
                    elif event == "updates":
                        for node, update in payload.items():
                            if node in ("planner", "critic"):
                                msg = update.get("plan") or update.get("critique") or ""
                                if msg:
                                    self.console.print(
                                        f"[dim]({node})[/dim] {msg.splitlines()[0][:100]}"
                                    )
        except Exception as e:
            self.console.print(f"[red]turn error:[/red] {e}")
