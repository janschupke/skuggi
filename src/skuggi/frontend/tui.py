"""Rich + prompt_toolkit REPL: a console front-end over ``AgentCore``.

Non-slash input goes through the agent graph (``core.turn``) and the worker's
tokens stream into a ``rich.live.Live`` pane while the planner and critic report
one line each. All agent state and behavior live in ``AgentCore``; this module
only renders. The wrapped-shell daemon is the other front-end over the same core.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from langgraph.graph.state import CompiledStateGraph
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.shortcuts import CompleteStyle
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.spinner import Spinner
from rich.table import Table

from skuggi.agent import readiness
from skuggi.agent.core import AgentCore
from skuggi.agent.state import AgentState
from skuggi.common import palette, text
from skuggi.config.config import Settings
from skuggi.engagement.engagement import EngagementConfig
from skuggi.frontend import (
    cmdflow,
    completion,
    control,
    dispatch,
    menu,
    outcomes,
    presenters,
    presenters_journal,
    render,
    verbs,
    wizard,
)
from skuggi.frontend.repl_flows import ReplFlows
from skuggi.install import reconcile
from skuggi.persistence.ledger import Ledger
from skuggi.tooling.commands import CommandAlias
from skuggi.tooling.commands import render as render_alias
from skuggi.tooling.doctor import (
    PROBING_MSG,
    TOOL_FILTERS,
    ToolFilter,
    doctor_table,
    filter_tool_statuses,
    render_doctor,
)
from skuggi.tooling.registry import ToolRegistry


class DraftView:
    """Accumulates streamed worker tokens and renders them into a Live pane."""

    def __init__(self, live: Live) -> None:
        self._live = live
        self.buffer = ""

    def reset(self) -> None:
        """Start a new pass, discarding anything buffered."""
        self.buffer = ""

    def push_text(self, chunk: str) -> None:
        """Append one incremental token and re-render."""
        self.buffer += chunk
        self._live.update(Markdown(text.markdown_hardbreaks(self.buffer)))

    def show(self, final: str) -> None:
        """Render the authoritative draft, as judged by the critic."""
        self.buffer = final
        self._live.update(Markdown(text.markdown_hardbreaks(final)))


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

        cancel_bindings, self._cancel_state = menu.cancel_bindings()
        self.session: PromptSession[str] = session or PromptSession(
            history=InMemoryHistory(),
            completer=NestedCompleter.from_nested_dict(
                completion.completion_tree(
                    self.core.commands.names(), reconcile.known_names()
                )
            ),
            complete_style=CompleteStyle.READLINE_LIKE,
            complete_while_typing=False,
            key_bindings=cancel_bindings,
        )
        # The interactive, prompt-driven flows (setup, wizard, config/scope/install/
        # cmd proposals, the alias editor) live in ReplFlows, which reads this app's
        # console/core/session live (tests reassign session after construction).
        self._flows = ReplFlows(self)

        # Surface any config-degrade warnings at construction (tests read these
        # straight after building the app, before run()/the banner).
        for warning in self.core.warnings:
            self.console.print(f"[yellow]{warning}[/yellow]")
        # Actionable next steps, computed once from the one readiness model and
        # phrased in the REPL's own grammar.
        for step in readiness.from_core(self.core).pending:
            self.console.print(
                f"[dim]{step.message} -- run {verbs.cmd(step.invocation, 'repl')}[/dim]"
            )

        # Keyed by bare verb (the shared registry in `verbs`); `ask` and `exit`
        # are handled directly in `dispatch`. Kept in sync with `verbs.KNOWN` by
        # a drift test. `show`/`set`/`add`/`remove` route on a noun internally.
        self._commands: dict[str, Callable[[str], bool | None]] = {
            "help": self._cmd_help,
            "show": self._cmd_show,
            "set": self._cmd_set,
            "add": self._cmd_add,
            "remove": self._cmd_remove,
            "cmd": self._cmd_cmd,
            "engagement": self._cmd_engagement,
            "login": self._flows.login,
            "doctor": self._cmd_doctor,
            "findings": self._cmd_findings,
            "report": self._styled(control.report),
            "visualize": self._styled(control.visualize),
            "replay": self._cmd_replay,
            "review": self._cmd_review,
            "clear": self._cmd_clear,
            "ingest": self._styled(control.ingest),
            "update": self._cmd_update,
            "reconcile": self._cmd_reconcile,
        }
        # Noun routers for the grouping verbs; each is drift-checked against
        # `verbs.noun_names(<verb>)` so a new noun cannot be half-wired.
        self._show_nouns: dict[str, Callable[[str], None]] = {
            **{n: self._styled(a) for n, a in control.SHOW_ACTIONS.items()},
            "engagement": self._show_engagement,
            "db": self._show_db,
            "tools": self._show_tools,
            "notes": self._show_notes,
            "loot": self._show_loot,
            "history": self._show_history,
            "trace": self._show_trace,
        }
        self._set_nouns: dict[str, Callable[[str], None]] = {
            **{n: self._styled(a) for n, a in control.SET_ACTIONS.items()},
            "provider": self._set_provider,
            "model": self._set_model,
            "config": self._flows.set_config,
            "scope": self._flows.set_scope,
        }
        self._add_nouns: dict[str, Callable[[str], None]] = {
            "note": self._styled(control.add_record_for("note")),
            "loot": self._styled(control.add_record_for("loot")),
            "finding": self._styled(control.add_record_for("finding")),
            "memory": self._styled(control.add_memory),
        }
        self._remove_nouns: dict[str, Callable[[str], None]] = {
            n: self._styled(a) for n, a in control.REMOVE_ACTIONS.items()
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
                except EOFError:  # Ctrl-D leaves the REPL
                    break
                except KeyboardInterrupt:  # Ctrl-C abandons the line, like a shell
                    if not self._cancel_state.get("had_text"):  # empty -> hint only
                        self.console.print("[dim]type exit to leave[/dim]")
                    continue
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
        # The shield marks that skuggi is active; the `!` warns autonomous
        # execution is armed. The engagement name is the only context worth the
        # space -- mode/provider/model live in the banner and `/show status`.
        auto = "!" if self.core.autonomous else ""
        engagement = self.core.engagement
        if engagement is not None:
            return f"{palette.SHIELD} [{engagement.name}]{auto} > "
        return f"{palette.SHIELD}{auto} > "

    def _banner(self) -> None:
        self.console.rule("[bold]skuggi[/bold]")
        self.console.print(
            palette.paint(
                readiness.glance(readiness.from_core(self.core)), palette.INFO
            )
        )
        self.console.print("type /help for commands\n")

    def _emit(self, lines: render.Styled) -> None:
        """Print presenter output, painting each line per its semantic style."""
        for line in lines:
            self.console.print(render.to_markup(line))

    def _styled(self, action: control.Action) -> Callable[[str], None]:
        """Adapt a shared control action to this surface's console emit."""

        def handler(rest: str) -> None:
            self._emit(action(self.core, rest, "repl"))

        return handler

    def _status(self, node: str, text: str) -> None:
        if not text:
            return
        style = "red" if node == "error" else "dim"
        summary = text.splitlines()[0][: presenters.STATUS_LINE_CAP]
        self.console.print(f"[{style}]({node})[/{style}] {summary}")

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
            self._emit(presenters.present_unknown(verb, "repl"))
            return None
        return handler(rest)

    def _cmd_help(self, arg: str) -> None:
        verb = arg.strip().split(" ", 1)[0]
        if verb:
            rows = verbs.help_for(verb)
            if rows is None:
                self.console.print(f"[red]no such command:[/red] {verb}")
                return
            table = Table(show_header=False, box=None, title=verbs.cmd(verb, "repl"))
            for invocation, summary in rows:
                table.add_row(f"[cyan]{verbs.cmd(invocation, 'repl')}[/cyan]", summary)
            self.console.print(table)
            return
        for title, section_rows in verbs.help_sections():
            self.console.print(f"[bold]{title}[/bold]")
            table = Table(show_header=False, box=None, pad_edge=False)
            for invocation, summary in section_rows:
                table.add_row(
                    f"  [cyan]{verbs.cmd(invocation, 'repl')}[/cyan]", summary
                )
            self.console.print(table)

    # ----- grouping-verb routers ---------------------------------------------

    def _route_noun(
        self, verb: str, arg: str, router: dict[str, Callable[[str], None]]
    ) -> None:
        """Dispatch ``<verb> <noun> <rest>`` to `router`, or show the noun usage."""
        noun, _, rest = arg.partition(" ")
        noun = noun.strip().lower()
        handler = router.get(noun)
        if handler is None:
            options = " | ".join(n.name for n in verbs.nouns_of(verb))
            self.console.print(
                f"[yellow]usage:[/yellow] {verbs.cmd(f'{verb} <{options}>', 'repl')}"
            )
            return
        handler(rest.strip())

    def _cmd_show(self, arg: str) -> None:
        """Inspect state: ``show <config|provider|model|…>``."""
        self._route_noun("show", arg, self._show_nouns)

    def _cmd_set(self, arg: str) -> None:
        """Change config / session state: ``set <provider|model|mode|…>``."""
        self._route_noun("set", arg, self._set_nouns)

    def _cmd_add(self, arg: str) -> None:
        """Record engagement data: ``add <note|loot|finding|memory>``."""
        self._route_noun("add", arg, self._add_nouns)

    def _cmd_remove(self, arg: str) -> None:
        """Delete records: ``remove <memory>``."""
        self._route_noun("remove", arg, self._remove_nouns)

    # ----- set <noun> --------------------------------------------------------

    def _set_provider(self, arg: str) -> None:
        """Switch provider; with no name, run the guided provider+model setup."""
        if not arg:
            self._flows.run_setup()
            return
        self._emit(control.set_provider_named(self.core, arg, "repl"))

    def _set_model(self, arg: str) -> None:
        """Switch model; with no name, pick one from the provider's curated list."""
        if not arg:
            self._flows.model_select()
            return
        self._emit(control.set_model_named(self.core, arg, "repl"))

    def _cmd_engagement(self, arg: str) -> None:
        first = arg.split(maxsplit=1)[0] if arg.split() else ""
        if first in wizard.WIZARD_ARGS:
            self._flows.engagement_wizard()
            return
        if first == "threat-model":
            rest = arg.split(maxsplit=1)[1] if len(arg.split()) > 1 else ""
            self.console.print(dispatch.run_threat_model(self.core, rest))
            return
        adopt = verbs.cmd("set engagement [<path>]", "repl")
        self.console.print(
            "[yellow]usage:[/yellow] "
            f"{verbs.cmd('engagement setup | threat-model', 'repl')} "
            f"-- adopt/scaffold a root with {adopt}, "
            f"scope summary is {verbs.cmd('show engagement', 'repl')}"
        )

    def _cmd_doctor(self, arg: str) -> None:
        research_target = dispatch.doctor_research_target(arg)
        if research_target is not None:
            if research_target:
                self._flows.research_install(research_target)
            else:
                self.console.print("usage: doctor research <tool>")
            return
        target = dispatch.doctor_install_target(arg)
        if target == "missing":
            self._flows.install_missing()
            return
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
        with self.console.status(f"installing {binary}…", spinner="dots"):
            outcome = dispatch.run_install(self.core, binary)
        self._emit(presenters.present_install(outcome))
        # The `doctor research <tool>` fallback is REPL-only (the daemon has no
        # research verb), so it is appended here rather than in the shared presenter.
        if isinstance(outcome, (outcomes.InstallUnknown, outcomes.InstallFailed)):
            self.console.print(f"[dim]try: doctor research {outcome.binary}[/dim]")

    def _cmd_cmd(self, arg: str) -> None:  # noqa: PLR0911 -- one return per cmd sub-command
        """Search the cheatsheet, resolve an exact alias, or edit the registry."""
        sub, _, rest = arg.partition(" ")
        sub, rest = sub.strip(), rest.strip()
        if not sub or sub == "list":
            self._cheatsheet(self.core.commands.commands, "")
            return
        if sub in cmdflow.ADD_ARGS:
            self._flows.alias_add()
            return
        if sub in cmdflow.EDIT_ARGS:
            self._flows.alias_edit(rest)
            return
        if sub in cmdflow.REMOVE_ARGS:
            self._flows.alias_remove(rest)
            return
        if sub in cmdflow.SUGGEST_ARGS:
            self._flows.cmd_suggest(rest)
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
        self._cheatsheet(matches, arg.strip())

    def _cheatsheet(self, aliases: tuple[CommandAlias, ...], query: str) -> None:
        """List `aliases`, highlighting `query` wherever it matched (name/desc)."""
        if not aliases:
            self.console.print("[dim]no command aliases configured[/dim]")
            return
        for a in aliases:
            name = text.highlight(a.name, query, base="cyan", match=palette.MATCH)
            self.console.print(f"{name}  {render_alias(a, self.registry)}")
            if a.description:
                desc = text.highlight(
                    a.description, query, base="dim", match=palette.MATCH
                )
                self.console.print(f"    {desc}")

    def _resolve_cmd(self, name: str) -> None:
        self._emit(control.resolve_cmd(self.core, name, "repl"))

    # ----- show <noun> -------------------------------------------------------

    def _show_engagement(self, _rest: str) -> None:
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

    def _show_db(self, _rest: str) -> None:
        self.console.print(dispatch.run_db_stats(self.core))

    def _show_tools(self, rest: str) -> None:
        which = rest.strip().lower() or "all"
        if which not in TOOL_FILTERS:
            self.console.print(
                "[yellow]usage:[/yellow] "
                f"{verbs.cmd('show tools [all|scoped|installed|missing]', 'repl')}"
            )
            return
        with self.console.status(PROBING_MSG, spinner="dots"):
            statuses = self.core.doctor.tools()
        filtered = filter_tool_statuses(
            statuses, cast("ToolFilter", which), self.core.engagement
        )
        if not filtered:
            self.console.print(f"[dim](no {which} tools)[/dim]")
            return
        self.console.print(doctor_table(filtered))

    def _show_notes(self, _rest: str) -> None:
        text = self.core.journal.notes()
        if not text.strip():
            self.console.print("[dim](no notes yet)[/dim]")
            return
        self.console.print(Markdown(text))

    def _show_loot(self, _rest: str) -> None:
        text = self.core.journal.loot()
        if not text.strip():
            self.console.print("[dim](no loot yet)[/dim]")
            return
        self.console.print(Markdown(text))

    def _show_history(self, arg: str) -> None:
        self._emit(
            presenters.present_history(self.core.state().get("messages", []), arg)
        )

    def _show_trace(self, _arg: str) -> None:
        """Show the command trail, which `show history` deliberately excludes."""
        self._emit(presenters.present_trace(self.core.state().get("commands") or []))

    def _cmd_findings(self, arg: str) -> None:
        """Review a finding (approve/reject/rescore); listing is `show findings`."""
        message = dispatch.run_findings(self.core, arg)
        if message is not None:
            self._emit([render.plain(message)])
            return
        self._emit(presenters.present_findings_usage("repl"))

    def _cmd_replay(self, arg: str) -> None:
        """Reconstruct & view a session transcript (``list`` enumerates them)."""
        outcome = dispatch.run_replay(self.core, arg, current_id=self.session_id)
        if isinstance(outcome, outcomes.ReplayTranscript):
            self.console.print(Markdown(outcome.text))  # structural body
            return
        self._emit(presenters_journal.present_replay_list(outcome))

    def _cmd_review(self, arg: str) -> None:
        """Print the private LLM critique of a session (also audit-logged)."""
        with self.console.status("reviewing the session...", spinner="dots"):
            text = self.core.archive.review(arg.strip() or None)
        self.console.print(Markdown(text))

    def _cmd_update(self, _arg: str) -> None:
        for line in self.core.self_update():
            self.console.print(line.rstrip())

    def _cmd_reconcile(self, arg: str) -> None:
        self._emit(control.reconcile(self.core, arg, "repl"))

    def _cmd_clear(self, _arg: str) -> None:
        self.console.clear()

    # ----- agent turn --------------------------------------------------------

    def turn(self, user_text: str) -> None:
        """Run one agent turn, streaming the worker's answer.

        The pane opens on a spinner so a slow planner/first token never looks
        hung; the first streamed token or final draft replaces it.
        """
        completed = False
        with Live(
            Spinner("dots", "thinking..."), console=self.console, refresh_per_second=20
        ) as live:
            view = DraftView(live)
            try:
                for ev in self.core.turn(user_text):
                    if ev.kind == "reset":
                        view.reset()
                    elif ev.kind == "status":
                        self._status(ev.node, ev.text)
                    elif ev.kind == "token":
                        view.push_text(ev.text)
                    elif ev.kind == "final":
                        view.show(ev.text)
                completed = True
            except KeyboardInterrupt:
                # Ctrl-C cancels the in-flight turn and returns to the prompt. The
                # interrupt already unwound ``core.turn`` (its ``finally`` closed the
                # timeline), so there is nothing to clean up here but the pane.
                view.reset()
                self.console.print("[dim]cancelled -- type exit to leave[/dim]")
        # Post-turn, outside the Live pane so the confirm menu renders normally:
        # the gated memory-capture flow (a no-op unless a directive was detected).
        if completed:
            self._flows.capture_memory(user_text)
