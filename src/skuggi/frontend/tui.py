"""Rich + prompt_toolkit REPL: a console front-end over ``AgentCore``.

Non-slash input goes through the agent graph (``core.turn``) and the worker's
tokens stream into a ``rich.live.Live`` pane while the planner and critic report
one line each. All agent state and behavior live in ``AgentCore``; this module
only renders. The wrapped-shell daemon is the other front-end over the same core.
"""

from __future__ import annotations

import zoneinfo
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, cast

from langgraph.graph.state import CompiledStateGraph
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.spinner import Spinner
from rich.table import Table

from skuggi.agent import protocol, readiness
from skuggi.agent.core import AgentCore, parse_toggle
from skuggi.agent.state import AgentState
from skuggi.common import palette, text
from skuggi.common.paths import ensure_parent
from skuggi.config.config import Settings
from skuggi.engagement.engagement import EngagementConfig
from skuggi.frontend import (
    cmdflow,
    configflow,
    dispatch,
    installflow,
    menu,
    render,
    scopeflow,
    setup,
    verbs,
    wizard,
)
from skuggi.frontend.prompter import Prompter
from skuggi.persistence import reports, visualize
from skuggi.persistence.ledger import Ledger, finding_line
from skuggi.tooling.commands import CommandAlias
from skuggi.tooling.commands import render as render_alias
from skuggi.tooling.doctor import (
    PROBING_MSG,
    ToolFilter,
    doctor_table,
    filter_tool_statuses,
    render_doctor,
)
from skuggi.tooling.registry import ToolRegistry

if TYPE_CHECKING:
    pass

# The filters ``show tools`` accepts, for argument validation.
_TOOL_FILTERS: frozenset[str] = frozenset({"all", "scoped", "installed", "missing"})


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
            "login": self._cmd_login,
            "doctor": self._cmd_doctor,
            "findings": self._cmd_findings,
            "report": self._cmd_report,
            "visualize": self._cmd_visualize,
            "replay": self._cmd_replay,
            "review": self._cmd_review,
            "clear": self._cmd_clear,
            "ingest": self._cmd_ingest,
            "update": self._cmd_update,
            "reconcile": self._cmd_reconcile,
        }
        # Noun routers for the grouping verbs; each is drift-checked against
        # `verbs.noun_names(<verb>)` so a new noun cannot be half-wired.
        self._show_nouns: dict[str, Callable[[str], None]] = {
            "config": self._show_config,
            "provider": self._show_provider,
            "model": self._show_model,
            "engagement": self._show_engagement,
            "db": self._show_db,
            "sessions": self._show_sessions,
            "tools": self._show_tools,
            "memory": self._show_memory,
            "notes": self._show_notes,
            "loot": self._show_loot,
            "findings": self._show_findings,
            "history": self._show_history,
            "trace": self._show_trace,
            "threads": self._show_threads,
            "status": self._show_status,
            "grants": self._show_grants,
        }
        self._set_nouns: dict[str, Callable[[str], None]] = {
            "provider": self._set_provider,
            "model": self._set_model,
            "mode": self._set_mode,
            "autonomous": self._set_autonomous,
            "config": self._set_config,
            "scope": self._set_scope,
            "thread": self._set_thread,
        }
        self._add_nouns: dict[str, Callable[[str], None]] = {
            "note": lambda rest: self._add_record("note", rest),
            "loot": lambda rest: self._add_record("loot", rest),
            "finding": lambda rest: self._add_record("finding", rest),
            "memory": self._add_memory,
        }
        self._remove_nouns: dict[str, Callable[[str], None]] = {
            "memory": self._remove_memory,
            "grants": self._remove_grants,
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
                except KeyboardInterrupt:  # Ctrl-C at an idle prompt stays put
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
            self._emit(dispatch.present_unknown(verb, "repl"))
            return None
        return handler(rest)

    def _cmd_quit(self, _arg: str) -> bool:
        return False

    def _cmd_help(self, arg: str) -> None:
        verb = arg.strip().split(" ", 1)[0]
        if verb:
            rows = verbs.help_for(verb)
            if rows is None:
                self.console.print(f"[red]no such command:[/red] {verb}")
                return
            table = Table(show_header=False, box=None, title=f"/{verb}")
            for invocation, summary in rows:
                table.add_row(f"[cyan]/{invocation}[/cyan]", summary)
            self.console.print(table)
            return
        for title, section_rows in verbs.help_sections():
            self.console.print(f"[bold]{title}[/bold]")
            table = Table(show_header=False, box=None, pad_edge=False)
            for invocation, summary in section_rows:
                table.add_row(f"  [cyan]/{invocation}[/cyan]", summary)
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
            self._run_setup()
            return
        self._emit(
            dispatch.present_provider(dispatch.run_provider(self.core, arg), "repl")
        )

    def _set_model(self, arg: str) -> None:
        """Switch model; with no name, pick one from the provider's curated list."""
        if not arg:
            setup.run_model_select(
                self.core,
                self.core.provider,
                self._ask,
                self._choose,
                lambda text: self.console.print(f"[dim]{text}[/dim]"),
            )
            return
        self._emit(dispatch.present_model(dispatch.run_model(self.core, arg), "repl"))

    def _set_mode(self, arg: str) -> None:
        try:
            self.core.set_mode(arg)
        except ValueError as e:
            self._emit(dispatch.present_error(str(e)))
            return
        self._emit(dispatch.present_mode(self.mode))

    def _cmd_engagement(self, arg: str) -> None:
        first = arg.split(maxsplit=1)[0] if arg.split() else ""
        if first in wizard.WIZARD_ARGS:
            self._engagement_wizard()
            return
        if first == "scaffold":
            self._engagement_scaffold()
            return
        if first == "threat-model":
            rest = arg.split(maxsplit=1)[1] if len(arg.split()) > 1 else ""
            self.console.print(dispatch.run_threat_model(self.core, rest))
            return
        self.console.print(
            "[yellow]usage:[/yellow] "
            f"{verbs.cmd('engagement setup | scaffold | threat-model', 'repl')} "
            f"-- scope summary is {verbs.cmd('show engagement', 'repl')}"
        )

    def _engagement_scaffold(self) -> None:
        """Copy the packaged scope template into the cwd for the operator to edit."""
        self._emit(dispatch.present_scaffold(dispatch.run_scaffold(Path.cwd())))

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

    def _ask_complete(
        self, prompt: str, candidates: Sequence[str], default: str | None
    ) -> str | None:
        """Prompt for one line with Tab completion; None on abort."""
        return menu.ask_complete(prompt, candidates, default=default, multi=True)

    def _multiselect(
        self, prompt: str, options: Sequence[str], preselected: Sequence[str]
    ) -> list[str] | None:
        """Pick several options via a checklist; None on abort."""
        return menu.multiselect(prompt, options, preselected=preselected)

    def _confirm(self, prompt: str, default: bool) -> bool | None:
        """Yes/no via an arrow menu; None on abort."""
        return menu.confirm(prompt, default=default)

    def _progress(self, step: int, total: int, label: str) -> None:
        """Render a horizontal step bar above the next question."""
        done = "▸" * step
        todo = "▹" * (total - step)
        self.console.print(f"[dim]\\[{step}/{total}] {label}[/dim] {done}{todo}")

    def _engagement_catalog(self) -> wizard.Catalog:
        """The option sources the engagement wizard offers (zones, tools, enums)."""
        tools = tuple(spec.binary for spec in self.core.registry.tools)
        return wizard.Catalog(
            timezones=tuple(sorted(zoneinfo.available_timezones())),
            tools=tools,
            methods=palette.methods(),
            methodologies=protocol.METHODOLOGIES,
            taxonomies=protocol.TAXONOMIES,
            stances=protocol.STANCES,
        )

    def _engagement_wizard(self) -> None:
        """Collect a scope field-by-field via rich widgets and load it."""
        prompter = Prompter(
            ask=self._ask,
            ask_complete=self._ask_complete,
            choose=self._choose,
            multiselect=self._multiselect,
            confirm=self._confirm,
            notify=lambda text: self.console.print(f"[dim]{text}[/dim]"),
            progress=self._progress,
        )
        wizard.run_wizard(
            prompter,
            self.core.create_engagement,
            self._engagement_catalog(),
            existing=self.core.engagement,
        )

    def _set_config(self, arg: str) -> None:
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
            grants=self.core.grants,
        )

    def _set_scope(self, arg: str) -> None:
        if not arg.strip():
            self._emit(dispatch.usage("set scope <request>", "repl"))
            return
        scopeflow.run_scope_request(
            arg,
            choose=self._choose,
            notify=lambda text: self.console.print(f"[dim]{text}[/dim]"),
            propose=self.core.scope.propose,
            preview=self.core.scope.preview,
            apply=self.core.scope.apply,
            grants=self.core.grants,
        )

    def _set_autonomous(self, arg: str) -> None:
        try:
            state = self.core.set_autonomous(parse_toggle(arg))
        except ValueError as e:
            self._emit(dispatch.present_error(str(e)))
            return
        self._emit(dispatch.present_autonomous(state))

    def _set_thread(self, arg: str) -> None:
        if arg in ("new", ""):
            self._emit(dispatch.present_thread("new", self.core.new_thread()))
        else:
            self.core.set_thread(arg)
            self._emit(dispatch.present_thread("switch", arg))

    def _run_setup(self) -> None:
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
        if target == "missing":
            self._install_missing()
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

    def _install_missing(self) -> None:
        """Install the missing scoped tools, gated by the shared confirm."""
        installflow.run_install_missing(
            choose=self._choose,
            notify=lambda text: self.console.print(f"[dim]{text}[/dim]"),
            propose=self.core.doctor.propose_installs,
            install=self.core.doctor.install,
            grants=self.core.grants,
        )

    def _cmd_cmd(self, arg: str) -> None:  # noqa: PLR0911 -- one return per cmd sub-command
        """Search the cheatsheet, resolve an exact alias, or edit the registry."""
        sub, _, rest = arg.partition(" ")
        sub, rest = sub.strip(), rest.strip()
        if not sub or sub == "list":
            self._cheatsheet(self.core.commands.commands, "")
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
        if sub in cmdflow.SUGGEST_ARGS:
            self._cmd_suggest(rest)
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
        self._emit(dispatch.present_cmd_plan(self.core.cmds.plan(name), "repl"))

    def _cmd_suggest(self, request: str) -> None:
        if not request.strip():
            self._emit(dispatch.usage("cmd suggest <request>", "repl"))
            return
        cmdflow.run_cmd_suggest(
            request,
            choose=self._choose,
            notify=lambda text: self.console.print(f"[dim]{text}[/dim]"),
            propose=self.core.cmds.propose,
            preview=self.core.cmds.preview_proposal,
            apply=self.core.cmds.apply_proposal,
            grants=self.core.grants,
        )

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

    # ----- add <noun> --------------------------------------------------------

    def _add_record(self, noun: str, rest: str) -> None:
        """Record a note, loot item or finding (finding keeps its severity colour)."""
        outcome = dispatch.run_add(self.core, f"{noun} {rest}".strip())
        if not isinstance(outcome, dispatch.FindingRecorded):
            self._emit(dispatch.present_add(outcome, "repl"))
            return
        self.console.print(
            "[green]recorded[/green] "
            + finding_line(
                outcome.row,
                lambda text, sev: palette.paint(text, palette.severity_style(sev)),
            )
        )

    def _add_memory(self, rest: str) -> None:
        """Remember an operator preference (``add memory <entry>``)."""
        if not rest:
            self._emit(dispatch.usage("add memory <entry>", "repl"))
            return
        self._emit(
            dispatch.present_memory(dispatch.run_memory(self.core, f"add {rest}"))
        )

    # ----- remove <noun> -----------------------------------------------------

    def _remove_memory(self, rest: str) -> None:
        """Forget one preference (``remove memory <id>``) or every one (``all``)."""
        if rest == "all":
            self._emit(dispatch.present_memory(dispatch.run_memory(self.core, "clear")))
            return
        if not rest.isdigit():
            self._emit(dispatch.usage("remove memory <id> | all", "repl"))
            return
        self._emit(
            dispatch.present_memory(dispatch.run_memory(self.core, f"forget {rest}"))
        )

    def _remove_grants(self, _rest: str) -> None:
        """Revoke every active session approval grant."""
        self._emit(dispatch.present_grants_revoked(self.core.grants.revoke_all()))

    # ----- show <noun> -------------------------------------------------------

    def _show_config(self, _rest: str) -> None:
        self.console.print(self.core.config.summary())

    def _show_provider(self, _rest: str) -> None:
        self._emit(
            dispatch.present_show_provider(readiness.from_core(self.core), "repl")
        )

    def _show_model(self, _rest: str) -> None:
        self._emit(dispatch.present_show_model(readiness.from_core(self.core)))

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

    def _show_grants(self, _rest: str) -> None:
        self._emit(dispatch.present_grants(self.core.grants.active()))

    def _show_status(self, _rest: str) -> None:
        self._emit(dispatch.present_status(dispatch.run_status(self.core), "repl"))

    def _show_sessions(self, _rest: str) -> None:
        self._emit(dispatch.present_sessions(dispatch.run_sessions(self.core)))

    def _show_tools(self, rest: str) -> None:
        which = rest.strip().lower() or "all"
        if which not in _TOOL_FILTERS:
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

    def _show_memory(self, _rest: str) -> None:
        self._emit(dispatch.present_memory(dispatch.run_memory(self.core, "")))

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

    def _show_findings(self, _rest: str) -> None:
        rows = self.core.journal.findings()
        if not rows:
            self.console.print("[dim](no findings yet)[/dim]")
            return
        current = self.core.ledger.current_threat_model_version()
        for finding in rows:
            self.console.print(
                finding_line(
                    finding,
                    lambda text, sev: palette.paint(text, palette.severity_style(sev)),
                    outdated=finding.cvss_tm_version is not None
                    and finding.cvss_tm_version != current,
                )
            )

    def _show_history(self, arg: str) -> None:
        count = int(arg) if arg.isdigit() else 20
        labels = {"human": "you", "ai": "bot", "system": "sys", "tool": "tool"}
        for message in self.core.state().get("messages", [])[-count:]:
            self.console.print(
                f"[bold]{labels.get(message.type, message.type)}:[/bold] {message.text}"
            )

    def _show_trace(self, _arg: str) -> None:
        """Show the command trail, which `show history` deliberately excludes."""
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

    def _show_threads(self, _rest: str) -> None:
        self._emit(
            dispatch.present_threads(
                self.core.ledger.thread_summaries(), self.thread_id
            )
        )

    def _cmd_findings(self, arg: str) -> None:
        """Review a finding (approve/reject/rescore); listing is `show findings`."""
        message = dispatch.run_findings(self.core, arg)
        if message is not None:
            self._emit([render.plain(message)])
            return
        self._emit(dispatch.present_findings_usage("repl"))

    def _cmd_report(self, arg: str) -> None:
        first, _, rest = arg.strip().partition(" ")
        if first.lower() == "note":
            if not rest.strip():
                self._emit(dispatch.usage("report note <text>", "repl"))
                return
            path = self.core.journal.add_report_note(rest)
            self.console.print(f"[green]changelog: {path}[/green]")
            return
        result = self.core.journal.write_report(pdf=first.lower() == "pdf")
        for line in reports.report_written_lines(result):
            self.console.print(f"[green]{line}[/green]")

    def _cmd_visualize(self, _arg: str) -> None:
        path = self.core.journal.write_visualization()
        for line in visualize.visualization_written_lines(path):
            self.console.print(f"[green]{line}[/green]")

    def _cmd_replay(self, arg: str) -> None:
        """Reconstruct & view a session transcript (``list`` enumerates them)."""
        match dispatch.run_replay(self.core, arg, current_id=self.session_id):
            case dispatch.ReplayEmpty():
                self.console.print("[dim](no sessions)[/dim]")
            case dispatch.ReplayList(rows, current_id):
                for s in rows:
                    marker = " *" if s.session_id == current_id else ""
                    self.console.print(
                        f"[cyan]{s.session_id[:8]}[/cyan]  "
                        f"{s.started_at}  {s.mode}{marker}"
                    )
            case dispatch.ReplayTranscript(text):
                self.console.print(Markdown(text))

    def _cmd_review(self, arg: str) -> None:
        """Print the private LLM critique of a session (also audit-logged)."""
        with self.console.status("reviewing the session...", spinner="dots"):
            text = self.core.archive.review(arg.strip() or None)
        self.console.print(Markdown(text))

    def _cmd_update(self, _arg: str) -> None:
        for line in self.core.self_update():
            self.console.print(line.rstrip())

    def _cmd_reconcile(self, arg: str) -> None:
        self._emit(
            dispatch.present_reconcile(dispatch.run_reconcile(self.core, arg), "repl")
        )

    def _cmd_clear(self, _arg: str) -> None:
        self.console.clear()

    def _cmd_ingest(self, arg: str) -> None:
        if not arg:
            self._emit(dispatch.usage("ingest <path>", "repl"))
            return
        self._emit([render.info(f"indexed {self.core.ingest(Path(arg))} chunk(s)")])

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
            except KeyboardInterrupt:
                # Ctrl-C cancels the in-flight turn and returns to the prompt. The
                # interrupt already unwound ``core.turn`` (its ``finally`` closed the
                # timeline), so there is nothing to clean up here but the pane.
                view.reset()
                self.console.print("[dim]cancelled -- type exit to leave[/dim]")
