"""Rich + prompt_toolkit REPL: a console front-end over ``AgentCore``.

Non-slash input goes through the agent graph (``core.turn``) and the worker's
tokens stream into a ``rich.live.Live`` pane while the planner and critic report
one line each. All agent state and behavior live in ``AgentCore``; this module
only renders. The wrapped-shell daemon is the other front-end over the same core.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from langgraph.graph.state import CompiledStateGraph
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.spinner import Spinner
from rich.table import Table

from skuggi.agent import prompts
from skuggi.agent.core import AgentCore, parse_toggle
from skuggi.agent.state import AgentState
from skuggi.common import palette
from skuggi.common.paths import ensure_parent
from skuggi.config.config import PROVIDERS, Settings
from skuggi.engagement.engagement import EngagementConfig
from skuggi.frontend import cmdflow, configflow, dispatch, menu, setup, verbs, wizard
from skuggi.persistence import reports, visualize
from skuggi.persistence.ledger import Ledger, finding_line
from skuggi.tooling.commands import CommandAlias, render
from skuggi.tooling.doctor import PROBING_MSG, render_doctor
from skuggi.tooling.registry import ToolRegistry


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
        ensure_parent(history_file)
        self.session: PromptSession[str] = session or PromptSession(
            history=FileHistory(str(history_file))
        )

        # Surface any config-degrade warnings at construction (tests read these
        # straight after building the app, before run()/the banner).
        for warning in self.core.warnings:
            self.console.print(f"[yellow]{warning}[/yellow]")
        # Actionable next steps in the REPL's own grammar.
        if self.core.llm is None:
            self.console.print(
                f"[dim]run {verbs.cmd('setup', 'repl')} to configure a model[/dim]"
            )
        if self.core.engagement is None:
            self.console.print(
                f"[dim]run {verbs.cmd('engagement setup', 'repl')} "
                "to scope an engagement[/dim]"
            )

        # Keyed by bare verb (the shared registry in `verbs`); `ask` and `exit`
        # are handled directly in `dispatch`. Kept in sync with `verbs.KNOWN` by
        # a drift test.
        self._commands: dict[str, Callable[[str], bool | None]] = {
            "help": self._cmd_help,
            "provider": self._cmd_provider,
            "model": self._cmd_model,
            "mode": self._cmd_mode,
            "thread": self._cmd_thread,
            "history": self._cmd_history,
            "trace": self._cmd_trace,
            "engagement": self._cmd_engagement,
            "config": self._cmd_config,
            "setup": self._cmd_setup,
            "login": self._cmd_login,
            "cmd": self._cmd_cmd,
            "doctor": self._cmd_doctor,
            "add": self._cmd_add,
            "notes": self._cmd_notes,
            "loot": self._cmd_loot,
            "findings": self._cmd_findings,
            "report": self._cmd_report,
            "visualize": self._cmd_visualize,
            "replay": self._cmd_replay,
            "review": self._cmd_review,
            "memory": self._cmd_memory,
            "autonomous": self._cmd_autonomous,
            "clear": self._cmd_clear,
            "ingest": self._cmd_ingest,
            "update": self._cmd_update,
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
                "[yellow]note:[/yellow] the chatgpt provider has no native "
                "structured output, so responses use the JSON-contract fallback"
            )
        self.console.print("type /help for commands\n")

    def _status(self, node: str, text: str) -> None:
        if not text:
            return
        style = "red" if node == "error" else "dim"
        self.console.print(f"[{style}]({node})[/{style}] {text.splitlines()[0][:100]}")

    # ----- dispatch ----------------------------------------------------------

    def dispatch(self, line: str) -> bool | None:
        """Run a `/verb` control. Returns False to end the session.

        Verb-first over the shared registry: `exit`/`quit` leave, `ask` routes to
        an agent turn (so `/ask x` and bare `x` behave the same), everything else
        is a control handler.
        """
        verb, rest = verbs.split_verb(line)
        if verbs.is_exit(verb):
            return False
        if verb == "ask":
            self.turn(rest)
            return None
        if verb in verbs.KNOWN and not verbs.is_engagement(verb):
            self.core.note_interaction(verb, rest)  # control verb -> audit log
        handler = self._commands.get(verb)
        if handler is None:
            self.console.print(f"[red]unknown command:[/red] /{verb}")
            return None
        return handler(rest)

    def _cmd_quit(self, _arg: str) -> bool:
        return False

    def _cmd_help(self, _arg: str) -> None:
        table = Table(show_header=False, box=None)
        for invocation, summary in verbs.help_rows():
            table.add_row(f"[cyan]/{invocation}[/cyan]", summary)
        self.console.print(table)

    def _cmd_provider(self, arg: str) -> None:
        """Switch the LLM provider on the live session."""
        match dispatch.run_provider(self.core, arg):
            case dispatch.ProviderUsage():
                self.console.print(
                    f"[yellow]usage:[/yellow] /provider <{'|'.join(PROVIDERS)}> "
                    f"-- or run {verbs.cmd('setup', 'repl')} to configure one"
                )
            case dispatch.ProviderUnknown(message):
                self.console.print(f"[red]{message}[/red]")
            case dispatch.ProviderNoCredential(provider):
                self.console.print(
                    f"[yellow]{provider} isn't configured[/yellow] -- run "
                    f"{verbs.cmd('setup', 'repl')} to add a key"
                )
            case dispatch.ProviderError(message):
                self.console.print(f"[red]provider error:[/red] {message}")
            case dispatch.ProviderSwitched(provider, model):
                self.console.print(
                    f"[dim]switched to[/dim] {provider}/{model or '(default)'}"
                )

    def _cmd_model(self, arg: str) -> None:
        """Switch the model on the current provider."""
        match dispatch.run_model(self.core, arg):
            case dispatch.ModelUsage():
                self.console.print("[yellow]usage:[/yellow] /model <name>")
            case dispatch.ModelNoCredential(provider):
                self.console.print(
                    f"[yellow]can't switch model:[/yellow] {provider} isn't "
                    f"configured -- run {verbs.cmd('setup', 'repl')} first"
                )
            case dispatch.ModelError(message):
                self.console.print(f"[red]provider error:[/red] {message}")
            case dispatch.ModelSwitched(provider, model):
                self.console.print(f"[dim]switched to[/dim] {provider}/{model}")

    def _cmd_mode(self, arg: str) -> None:
        try:
            self.core.set_mode(arg)
        except ValueError as e:
            self.console.print(f"[red]{e}[/red]")
            return
        self.console.print(f"[dim]mode:[/dim] {self.mode}")

    def _cmd_engagement(self, arg: str) -> None:
        parts = arg.split()
        if parts and parts[0] in wizard.WIZARD_ARGS:
            self._engagement_wizard()
            return
        eng = self.engagement
        if eng is None:
            self.console.print(
                f"[yellow]no engagement loaded[/yellow] -- run "
                f"{verbs.cmd('engagement setup', 'repl')} to create one"
            )
            return
        self.console.print(
            eng.describe(
                method_paint=lambda m: palette.paint(m, palette.method_style(m))
            )
        )

    def _ask(self, prompt: str) -> str | None:
        """Prompt the operator for one line; None on EOF / Ctrl-C (an abort)."""
        try:
            return self.session.prompt(prompt)
        except (EOFError, KeyboardInterrupt):
            return None

    def _choose(
        self, prompt: str, options: list[str], default: str | None
    ) -> str | None:
        """Pick one option via an arrow-key menu; None on abort."""
        return menu.select(prompt, options, default=default)

    def _engagement_wizard(self) -> None:
        """Collect a scope field-by-field via the prompt session and load it."""
        wizard.run_wizard(
            self._ask,
            self.core.create_engagement,
            lambda text: self.console.print(f"[dim]{text}[/dim]"),
            existing=self.core.engagement,
        )

    def _cmd_config(self, arg: str) -> None:
        text = self.core.config.line(arg)
        if text is not None:  # show / mechanical key-value
            self.console.print(text)
            return
        configflow.run_config_request(  # natural-language request -> LLM + confirm
            arg,
            choose=self._choose,
            notify=lambda text: self.console.print(f"[dim]{text}[/dim]"),
            propose=self.core.config.propose,
            apply=self.core.config.apply,
        )

    def _cmd_setup(self, _arg: str) -> None:
        """Guided provider + credential setup (the app owns the credentials)."""
        setup.run_setup(
            self.core,
            self._ask,
            self._choose,
            lambda text: self.console.print(f"[dim]{text}[/dim]"),
        )

    def _cmd_login(self, _arg: str) -> None:
        """Log in to a ChatGPT account via OAuth and switch to the provider."""
        try:
            account = self.core.login_chatgpt(
                lambda text: self.console.print(f"[dim]{text}[/dim]")
            )
        except (RuntimeError, ImportError) as e:
            self.console.print(f"[red]login failed:[/red] {e}")
            return
        suffix = f" (account {account})" if account else ""
        self.console.print(f"[dim]logged in to chatgpt{suffix}[/dim]")

    def _cmd_doctor(self, arg: str) -> None:
        target = dispatch.doctor_install_target(arg)
        if target is not None:
            self._install_tool(target)
            return
        with self.console.status(PROBING_MSG, spinner="dots"):
            statuses = self.core.doctor.tools()
            runtimes = self.core.doctor.runtimes()
            net_tools = self.core.doctor.net_tools()
        render_doctor(self.console, statuses, runtimes, net_tools, self.core.settings)

    def _install_tool(self, binary: str) -> None:
        """Install one recognized tool. Issuing this command is the confirm."""
        self.console.print(f"[dim]installing {binary}...[/dim]")
        match dispatch.run_install(self.core, binary):
            case dispatch.InstallUnknown(name):
                self.console.print(f"[red]unknown tool:[/red] {name!r}")
            case dispatch.Installed(name, version, source):
                self.console.print(
                    f"[green]installed[/green] {name} ({version or '?'}) via {source}"
                )
            case dispatch.InstallFailed(name):
                self.console.print(
                    f"[red]install failed or unavailable[/red] for {name}"
                )

    def _cmd_cmd(self, arg: str) -> None:
        """Search the cheatsheet, resolve an exact alias, or edit the registry."""
        sub, _, rest = arg.partition(" ")
        sub, rest = sub.strip(), rest.strip()
        if not sub or sub == "list":
            self._cheatsheet(self.core.commands.commands)
            return
        if sub in cmdflow.ADD_ARGS:
            self._cmd_alias_add()
            return
        if sub in cmdflow.EDIT_ARGS:
            self._cmd_alias_edit(rest)
            return
        if sub in cmdflow.REMOVE_ARGS:
            self._cmd_alias_remove(rest)
            return
        if self.core.commands.alias_for(sub) is not None:  # exact name -> resolve
            self._resolve_cmd(sub)
            return
        matches = self.core.cmds.search(arg.strip())  # otherwise substring search
        if not matches:
            self.console.print(
                f"[yellow]no cheatsheet entry matches[/yellow] {arg.strip()!r} "
                f"-- try {verbs.cmd('cmd list', 'repl')}"
            )
            return
        self._cheatsheet(matches)

    def _cheatsheet(self, aliases: tuple[CommandAlias, ...]) -> None:
        if not aliases:
            self.console.print("[dim]no command aliases configured[/dim]")
            return
        for a in aliases:
            self.console.print(f"[cyan]{a.name}[/cyan]  {render(a, self.registry)}")
            if a.description:
                self.console.print(f"    [dim]{a.description}[/dim]")

    def _resolve_cmd(self, name: str) -> None:
        plan = self.core.cmds.plan(name)
        if not plan.known:
            self.console.print(f"[yellow]{plan.note}[/yellow]")
            return
        self.console.print(f"[bold]$ {plan.raw}[/bold]")  # the rendered raw command
        if plan.verdict is not None and not plan.verdict.allowed:
            self.console.print(
                palette.paint(f"OUT OF SCOPE: {plan.note}", palette.DANGER)
            )
            return
        if plan.verdict is None:
            self.console.print(f"[yellow]{plan.note}[/yellow]")
        else:
            self.console.print(
                f"[green]{plan.note}[/green] -- recorded proposed "
                f"(cmd:{plan.command_id}); submit it yourself"
            )
        self.turn(prompts.EVALUATE_RUN.format(command=plan.raw))

    def _cmd_alias_add(self) -> None:
        cmdflow.run_cmd_editor(
            self._ask,
            self.core.cmds.add,
            lambda text: self.console.print(f"[dim]{text}[/dim]"),
        )

    def _cmd_alias_edit(self, name: str) -> None:
        existing = self.core.commands.alias_for(name)
        if existing is None:
            self.console.print(f"[yellow]unknown alias[/yellow] {name!r}")
            return
        cmdflow.run_cmd_editor(
            self._ask,
            lambda raw: self.core.cmds.update(name, raw),
            lambda text: self.console.print(f"[dim]{text}[/dim]"),
            existing=existing,
        )

    def _cmd_alias_remove(self, name: str) -> None:
        if not name:
            self.console.print(
                f"[yellow]usage:[/yellow] {verbs.cmd('cmd rm <name>', 'repl')}"
            )
            return
        if self.core.cmds.remove(name):
            self.console.print(f"[dim]removed alias '{name}'[/dim]")
        else:
            self.console.print(f"[yellow]unknown alias[/yellow] {name!r}")

    def _cmd_add(self, arg: str) -> None:
        """Record a note, loot item or finding (one grammar, per-case rendering)."""
        match dispatch.run_add(self.core, arg):
            case dispatch.AddUsage(form):
                self.console.print(
                    f"[yellow]usage:[/yellow] {verbs.cmd(f'add {form}', 'repl')}"
                )
            case dispatch.NoEngagement(kind):
                self.console.print(
                    f"[yellow]no engagement loaded[/yellow] -- run "
                    f"{verbs.cmd('engagement setup', 'repl')} to record {kind}s"
                )
            case dispatch.BadSeverity(value, allowed):
                self.console.print(
                    f"[red]unknown severity[/red] {value!r}; "
                    f"choose one of: {', '.join(allowed)}"
                )
            case dispatch.AddedNote(path):
                self.console.print(f"[green]noted[/green] [dim]{path}[/dim]")
            case dispatch.AddedLoot(path):
                self.console.print(f"[green]loot recorded[/green] [dim]{path}[/dim]")
            case dispatch.FindingRecorded(row):
                self.console.print(
                    "[green]recorded[/green] "
                    + finding_line(
                        row,
                        lambda text, sev: palette.paint(
                            text, palette.severity_style(sev)
                        ),
                    )
                )

    def _cmd_notes(self, _arg: str) -> None:
        text = self.core.journal.notes()
        if not text.strip():
            self.console.print("[dim](no notes yet)[/dim]")
            return
        self.console.print(Markdown(text))

    def _cmd_loot(self, _arg: str) -> None:
        text = self.core.journal.loot()
        if not text.strip():
            self.console.print("[dim](no loot yet)[/dim]")
            return
        self.console.print(Markdown(text))

    def _cmd_findings(self, _arg: str) -> None:
        rows = self.core.journal.findings()
        if not rows:
            self.console.print("[dim](no findings yet)[/dim]")
            return
        for finding in rows:
            self.console.print(
                finding_line(
                    finding,
                    lambda text, sev: palette.paint(text, palette.severity_style(sev)),
                )
            )

    def _cmd_report(self, arg: str) -> None:
        result = self.core.journal.write_report(pdf=arg.strip().lower() == "pdf")
        for line in reports.report_written_lines(result):
            self.console.print(f"[green]{line}[/green]")

    def _cmd_visualize(self, _arg: str) -> None:
        path = self.core.journal.write_visualization()
        for line in visualize.visualization_written_lines(path):
            self.console.print(f"[green]{line}[/green]")

    def _cmd_replay(self, arg: str) -> None:
        """Reconstruct & view a session transcript (``list`` enumerates them)."""
        if arg.strip() == "list":
            rows = self.core.archive.sessions()
            if not rows:
                self.console.print("[dim](no sessions)[/dim]")
                return
            for s in rows:
                marker = " *" if s.session_id == self.session_id else ""
                self.console.print(
                    f"[cyan]{s.session_id[:8]}[/cyan]  {s.started_at}  {s.mode}{marker}"
                )
            return
        self.console.print(Markdown(self.core.archive.transcript(arg.strip() or None)))

    def _cmd_review(self, arg: str) -> None:
        """Print the private LLM critique of a session (also audit-logged)."""
        with self.console.status("reviewing the session...", spinner="dots"):
            text = self.core.archive.review(arg.strip() or None)
        self.console.print(Markdown(text))

    def _cmd_memory(self, arg: str) -> None:
        """Show, add or forget remembered operator preferences (harness memory)."""
        match dispatch.run_memory(self.core, arg):
            case dispatch.MemoryUsage(form):
                self.console.print(f"[red]usage:[/red] /memory {form}")
            case dispatch.MemoryAdded(row):
                self.console.print(f"[green]remembered[/green] [{row.id}] {row.text}")
            case dispatch.MemoryAlreadyKnown():
                self.console.print("[dim]already remembered[/dim]")
            case dispatch.MemoryForgotten():
                self.console.print("[dim]forgotten[/dim]")
            case dispatch.MemoryMissing(ref):
                self.console.print(f"[yellow]no preference {ref}[/yellow]")
            case dispatch.MemoryCleared(count):
                self.console.print(f"[dim]cleared {count} preference(s)[/dim]")
            case dispatch.MemoryList(rows):
                if not rows:
                    self.console.print("[dim](nothing remembered yet)[/dim]")
                for row in rows:
                    self.console.print(
                        f"[cyan][{row.id}][/cyan] {row.text} [dim]({row.source})[/dim]"
                    )

    def _cmd_autonomous(self, arg: str) -> None:
        try:
            state = self.core.set_autonomous(parse_toggle(arg))
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
        """Show the command trail, which /history deliberately excludes."""
        commands = self.core.state().get("commands") or []
        if not commands:
            self.console.print("[dim](no command activity on this thread)[/dim]")
            return
        for cmd in commands:
            self.console.print(
                f"[cyan]{cmd.status}[/cyan] [cmd:{cmd.id}] {cmd.command}"
            )
            if cmd.summary:
                self.console.print(
                    f"[green]  {cmd.summary.splitlines()[0][:200]}[/green]"
                )

    def _cmd_update(self, _arg: str) -> None:
        for line in self.core.self_update():
            self.console.print(line.rstrip())

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
        """Run one agent turn, streaming the worker's answer.

        The pane opens on a spinner so a slow planner/first token never looks
        hung; the first streamed token or final draft replaces it.
        """
        with Live(
            Spinner("dots", "thinking..."), console=self.console, refresh_per_second=20
        ) as live:
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
