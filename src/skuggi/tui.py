"""Rich + prompt_toolkit REPL: a console front-end over ``AgentCore``.

Non-slash input goes through the agent graph (``core.turn``) and the worker's
tokens stream into a ``rich.live.Live`` pane while the planner and critic report
one line each. All agent state and behavior live in ``AgentCore``; this module
only renders. The wrapped-shell daemon is the other front-end over the same core.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from langchain_core.messages import AIMessage
from langchain_core.tools import BaseTool
from langgraph.graph.state import CompiledStateGraph
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.table import Table

from skuggi import palette
from skuggi.config import Settings
from skuggi.core import AgentCore
from skuggi.engagement import EngagementConfig
from skuggi.ledger import Ledger
from skuggi.registry import ToolRegistry, doctor_hints, doctor_table
from skuggi.state import AgentState


class DraftView:
    """Accumulates streamed worker tokens and renders them into a Live pane."""

    def __init__(self, live: Live) -> None:
        self._live = live
        self.buffer = ""

    def reset(self) -> None:
        """Start a new pass, discarding anything buffered."""
        self.buffer = ""

    def push_text(self, text: str) -> None:
        """Append one incremental token and re-render."""
        self.buffer += text
        self._live.update(Markdown(self.buffer))

    def show(self, final: str) -> None:
        """Render the authoritative draft, as judged by the critic."""
        self.buffer = final
        self._live.update(Markdown(final))


class Tui:
    """The interactive REPL (``skuggi-repl``)."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        console: Console | None = None,
        session: PromptSession[str] | None = None,
    ) -> None:
        """Wire up a session. `console` and `session` are injectable for tests."""
        self.console = console or Console()
        self.core = AgentCore(settings)

        history_file = self.core.settings.history_path
        history_file.parent.mkdir(parents=True, exist_ok=True)
        self.session: PromptSession[str] = session or PromptSession(
            history=FileHistory(str(history_file))
        )

        # Surface any config-degrade warnings at construction (tests read these
        # straight after building the app, before run()/the banner).
        for warning in self.core.warnings:
            self.console.print(f"[yellow]{warning}[/yellow]")

        self._commands: dict[str, Callable[[str], bool | None]] = {
            "/help": self._cmd_help,
            "/provider": self._cmd_provider,
            "/model": self._cmd_model,
            "/mode": self._cmd_mode,
            "/thread": self._cmd_thread,
            "/history": self._cmd_history,
            "/trace": self._cmd_trace,
            "/engagement": self._cmd_engagement,
            "/doctor": self._cmd_doctor,
            "/findings": self._cmd_findings,
            "/report": self._cmd_report,
            "/autonomous": self._cmd_autonomous,
            "/clear": self._cmd_clear,
            "/ingest": self._cmd_ingest,
            "/quit": self._cmd_quit,
            "/exit": self._cmd_quit,
        }

    # ----- delegated read state ----------------------------------------------

    @property
    def engagement(self) -> EngagementConfig | None:
        """The loaded engagement scope (or None)."""
        return self.core.engagement

    @property
    def registry(self) -> ToolRegistry:
        """The loaded tool registry."""
        return self.core.registry

    @property
    def ledger(self) -> Ledger:
        """The session ledger."""
        return self.core.ledger

    @property
    def session_id(self) -> str:
        """The ledger session id."""
        return self.core.session_id

    @property
    def thread_id(self) -> str:
        """The active conversation thread id."""
        return self.core.thread_id

    @property
    def mode(self) -> str:
        """The active operating mode."""
        return self.core.mode

    @property
    def provider(self) -> str:
        """The active provider name."""
        return self.core.provider

    @property
    def tools_list(self) -> list[BaseTool]:
        """The bound tool list."""
        return self.core.tools_list

    @property
    def graph(self) -> CompiledStateGraph[AgentState]:
        """The compiled agent graph."""
        return self.core.graph

    def close(self) -> None:
        """Release the core's ledger and checkpointer connections."""
        self.core.close()

    # ----- lifecycle ---------------------------------------------------------

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
            self.close()
            self.console.print("[dim]bye.[/dim]")

    # ----- UI helpers --------------------------------------------------------

    def _prompt(self) -> str:
        model = self.core.model or "(default)"
        auto = "!" if self.core.autonomous else ""
        # The shield marks that skuggi is active; the `!` warns autonomous
        # execution is armed.
        return (
            f"{palette.SHIELD} [skuggi:{self.mode}/{self.provider}/{model}"
            f"{auto} thread={self.thread_id[:8]}] > "
        )

    def _banner(self) -> None:
        self.console.rule("[bold]skuggi[/bold]")
        core = self.core
        engagement = core.engagement.name if core.engagement else "[red](none)[/red]"
        autonomous = palette.paint("ON", palette.DANGER) if core.autonomous else "off"
        self.console.print(
            f"mode=[cyan]{self.mode}[/cyan]  "
            f"provider=[cyan]{self.provider}[/cyan]  "
            f"engagement=[cyan]{engagement}[/cyan]  "
            f"autonomous={autonomous}"
        )
        if self.provider == "chatgpt":
            self.console.print(
                "[yellow]note:[/yellow] the chatgpt provider cannot call tools, "
                "so run_command is unavailable in this session"
            )
        self.console.print("type /help for commands\n")

    def _status(self, node: str, text: str) -> None:
        if not text:
            return
        style = "red" if node == "error" else "dim"
        self.console.print(f"[{style}]({node})[/{style}] {text.splitlines()[0][:100]}")

    # ----- dispatch ----------------------------------------------------------

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
        try:
            self.core.set_provider(arg)
        except ValueError as e:
            self.console.print(f"[red]{e}[/red]")
            return
        except (RuntimeError, ImportError) as e:
            self.console.print(f"[red]provider error:[/red] {e}")
            return
        self.console.print(
            f"[dim]switched to[/dim] {self.provider}/{self.core.model or '(default)'}"
        )

    def _cmd_model(self, arg: str) -> None:
        try:
            self.core.set_model(arg)
        except ValueError:
            self.console.print("[red]usage:[/red] /model <name>")
            return
        except (RuntimeError, ImportError) as e:
            self.console.print(f"[red]provider error:[/red] {e}")
            return
        self.console.print(f"[dim]switched to[/dim] {self.provider}/{self.core.model}")

    def _cmd_mode(self, arg: str) -> None:
        try:
            self.core.set_mode(arg)
        except ValueError as e:
            self.console.print(f"[red]{e}[/red]")
            return
        self.console.print(f"[dim]mode:[/dim] {self.mode}")

    def _cmd_engagement(self, _arg: str) -> None:
        described = self.core.describe_engagement()
        if described is None:
            self.console.print("[yellow]no engagement loaded[/yellow]")
            return
        self.console.print(self._colour_scope(described))

    def _colour_scope(self, described: str) -> str:
        """Tint the method line of a scope summary with the method palette."""
        out: list[str] = []
        for line in described.splitlines():
            if line.strip().startswith("methods:"):
                label, _, rest = line.partition(":")
                names = [n.strip() for n in rest.split(",") if n.strip()]
                painted = ", ".join(
                    palette.paint(n, palette.method_style(n)) for n in names
                )
                out.append(f"{label}: {painted}")
            else:
                out.append(line)
        return "\n".join(out)

    def _cmd_doctor(self, arg: str) -> None:
        parts = arg.split()
        if parts and parts[0] == "install":
            self._install_tool(parts[1] if len(parts) > 1 else "")
            return
        statuses = self.core.doctor_statuses()
        self.console.print(doctor_table(statuses))
        hints = doctor_hints(statuses)
        if hints:
            self.console.print(hints)

    def _install_tool(self, binary: str) -> None:
        """Install one recognized tool. Issuing this command is the confirm."""
        self.console.print(f"[dim]installing {binary}...[/dim]")
        status = self.core.install_tool(binary)
        if status is None:
            self.console.print(f"[red]unknown tool:[/red] {binary!r}")
        elif status.found:
            self.console.print(
                f"[green]installed[/green] {binary} "
                f"({status.version or '?'}) via {status.source}"
            )
        else:
            self.console.print(f"[red]install failed or unavailable[/red] for {binary}")

    def _cmd_findings(self, _arg: str) -> None:
        rows = self.core.findings()
        if not rows:
            self.console.print("[dim](no findings yet)[/dim]")
            return
        for finding in rows:
            src = (
                f" (cmd:{finding.command_id})" if finding.command_id is not None else ""
            )
            sev = palette.paint(
                finding.severity.upper(), palette.severity_style(finding.severity)
            )
            self.console.print(f"{sev} [{finding.id}] {finding.title}{src}")

    def _cmd_report(self, _arg: str) -> None:
        path = self.core.write_report()
        self.console.print(f"[green]report written:[/green] {path}")

    def _cmd_autonomous(self, arg: str) -> None:
        want = {"on": True, "off": False}.get(arg.lower())
        try:
            state = self.core.set_autonomous(want)
        except ValueError as e:
            self.console.print(f"[yellow]{e}[/yellow]")
            return
        if state:
            self.console.print(
                palette.paint("autonomous execution is now ON", palette.DANGER)
                + " -- proposed commands will EXECUTE within scope"
            )
        else:
            self.console.print("autonomous execution is now off")

    def _cmd_thread(self, arg: str) -> None:
        if arg in ("new", ""):
            new_id = self.core.new_thread()
            self.console.print(f"[dim]new thread:[/dim] {new_id}")
        elif arg == "list":
            ids = self.core.list_threads()
            if not ids:
                self.console.print("[dim](no threads)[/dim]")
                return
            for thread_id in ids:
                marker = " *" if thread_id == self.thread_id else ""
                self.console.print(f"  {thread_id}{marker}")
        else:
            self.core.set_thread(arg)
            self.console.print(f"[dim]switched to thread:[/dim] {arg}")

    def _cmd_history(self, arg: str) -> None:
        count = int(arg) if arg.isdigit() else 20
        labels = {"human": "you", "ai": "bot", "system": "sys", "tool": "tool"}
        for message in self.core.state().get("messages", [])[-count:]:
            self.console.print(
                f"[bold]{labels.get(message.type, message.type)}:[/bold] {message.text}"
            )

    def _cmd_trace(self, _arg: str) -> None:
        """Show the worker's tool trail, which /history deliberately excludes."""
        shown = False
        for message in self.core.state().get("scratch", []):
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
            self.console.print("[dim](no tool activity on this thread)[/dim]")

    def _cmd_clear(self, _arg: str) -> None:
        self.console.clear()

    def _cmd_ingest(self, arg: str) -> None:
        if not arg:
            self.console.print("[red]usage:[/red] /ingest <path>")
            return
        added = self.core.ingest(Path(arg))
        self.console.print(f"[dim]indexed {added} chunk(s)[/dim]")

    # ----- agent turn --------------------------------------------------------

    def turn(self, user_text: str) -> None:
        """Run one agent turn, streaming the worker's answer."""
        with Live("", console=self.console, refresh_per_second=20) as live:
            view = DraftView(live)
            for ev in self.core.turn(user_text):
                if ev.kind == "reset":
                    view.reset()
                elif ev.kind == "status":
                    self._status(ev.node, ev.text)
                elif ev.kind == "token":
                    view.push_text(ev.text)
                elif ev.kind == "final":
                    view.show(ev.text)


HELP: list[tuple[str, str]] = [
    ("/help", "show this help"),
    ("/provider <openai|chatgpt|anthropic|ollama>", "switch LLM provider"),
    ("/model <name>", "switch model (current provider)"),
    ("/mode <pentest|redteam|blueteam>", "switch operating mode (prompts)"),
    ("/thread new|list|<id>", "new/list/switch session thread"),
    ("/history [n]", "show last n messages on the current thread"),
    ("/trace", "show the worker's tool calls on the current thread"),
    ("/engagement", "show the loaded engagement scope"),
    ("/doctor [install <tool>]", "probe host tools; install a missing one"),
    ("/findings", "list findings recorded this session"),
    ("/report", "write a Markdown engagement report"),
    ("/autonomous [on|off]", "toggle autonomous command execution"),
    ("/clear", "clear the screen"),
    ("/ingest <path>", "index a file or directory into FAISS"),
    ("/quit", "exit (alias /exit)"),
]
