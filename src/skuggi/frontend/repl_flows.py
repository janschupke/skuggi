"""The REPL's interactive, prompt-driven flows.

Lifted out of ``tui.py`` as the console analog of what ``attach.py`` is to the
daemon: every flow that collects input through a widget and drives a shared
``*flow`` module (setup, the engagement wizard, config/scope/install/cmd
proposals, the alias editor). ``tui`` keeps the dispatch loop, the noun routers
and the turn/draft rendering, and delegates these to a ``ReplFlows`` built over the
same console, core and prompt session.

The prompt primitives (:meth:`ask`, :meth:`choose`, ...) live here too, since they
are only ever used by these flows, and the one dim-text ``notify`` closure that was
written out at every call site is now the single :meth:`_notify`.
"""

from __future__ import annotations

import zoneinfo
from typing import TYPE_CHECKING

from skuggi.agent import protocol
from skuggi.common import palette
from skuggi.engagement.scope import OSINT_SOURCES
from skuggi.frontend import (
    cmdflow,
    configflow,
    engagementflow,
    installflow,
    memoryflow,
    menu,
    presenters,
    render,
    setup,
    verbs,
    wizard,
)
from skuggi.frontend.prompter import Prompter

if TYPE_CHECKING:
    from collections.abc import Sequence

    from prompt_toolkit import PromptSession
    from rich.console import Console

    from skuggi.agent.core import AgentCore
    from skuggi.frontend.tui import Tui


class ReplFlows:
    """The REPL's prompt primitives and interactive flows.

    Holds a back-ref to the ``Tui`` and reads ``console``/``core``/``session``
    live, rather than capturing them at construction: tests reassign ``app.session``
    (a scripted session) after building the app, and the flows must see that.
    """

    def __init__(self, tui: Tui) -> None:
        self._tui = tui

    @property
    def _console(self) -> Console:
        return self._tui.console

    @property
    def _core(self) -> AgentCore:
        return self._tui.core

    @property
    def _session(self) -> PromptSession[str]:
        return self._tui.session

    def _notify(self, text: str) -> None:
        """The dim incidental line every flow emits for progress/hints."""
        self._console.print(f"[dim]{text}[/dim]")

    def _emit(self, lines: render.Styled) -> None:
        for line in lines:
            self._console.print(render.to_markup(line))

    # ----- prompt primitives -------------------------------------------------

    def ask(self, prompt: str) -> str | None:
        """Prompt the operator for one line; None on EOF / Ctrl-C (an abort)."""
        try:
            return self._session.prompt(prompt)
        except (EOFError, KeyboardInterrupt):
            return None

    def choose(
        self, prompt: str, options: list[str], default: str | None
    ) -> str | None:
        """Pick one option via an arrow-key menu; None on abort."""
        return menu.select(prompt, options, default=default)

    def ask_complete(
        self, prompt: str, candidates: Sequence[str], default: str | None
    ) -> str | None:
        """Prompt for one line with Tab completion; None on abort."""
        return menu.ask_complete(prompt, candidates, default=default, multi=True)

    def multiselect(
        self, prompt: str, options: Sequence[str], preselected: Sequence[str]
    ) -> list[str] | None:
        """Pick several options via a checklist; None on abort."""
        return menu.multiselect(prompt, options, preselected=preselected)

    def confirm(self, prompt: str, default: bool) -> bool | None:
        """Yes/no via an arrow menu; None on abort."""
        return menu.confirm(prompt, default=default)

    def progress(self, step: int, total: int, label: str) -> None:
        """Render a horizontal step bar above the next question."""
        done = "▸" * step
        todo = "▹" * (total - step)
        self._console.print(f"[dim]\\[{step}/{total}] {label}[/dim] {done}{todo}")

    # ----- setup / provider / model ------------------------------------------

    def run_setup(self) -> None:
        """Guided provider + credential setup (the app owns the credentials)."""
        setup.run_setup(self._core.provider_kernel, self.ask, self.choose, self._notify)

    def model_select(self) -> None:
        """Pick a model from the active provider's curated list."""
        setup.run_model_select(
            self._core.provider_kernel,
            self._core.provider,
            self.ask,
            self.choose,
            self._notify,
        )

    def login(self, _arg: str = "") -> None:
        """Log in to a ChatGPT account via OAuth and switch to the provider."""
        try:
            account = self._core.provider_kernel.login_chatgpt(self._notify)
        except (RuntimeError, ImportError) as e:
            self._console.print(f"[red]login failed:[/red] {e}")
            return
        suffix = f" (account {account})" if account else ""
        self._console.print(f"[dim]logged in to chatgpt{suffix}[/dim]")

    # ----- engagement wizard -------------------------------------------------

    def engagement_catalog(self) -> wizard.Catalog:
        """The option sources the engagement wizard offers (zones, tools, enums)."""
        tools = tuple(spec.binary for spec in self._core.registry.tools)
        return wizard.Catalog(
            timezones=tuple(sorted(zoneinfo.available_timezones())),
            tools=tools,
            methods=palette.methods(),
            methodologies=protocol.METHODOLOGIES,
            taxonomies=protocol.TAXONOMIES,
            stances=protocol.STANCES,
            osint_sources=OSINT_SOURCES,
        )

    def _prompter(self) -> Prompter:
        """The operator-interaction bundle the wizard / engagement flows drive."""
        return Prompter(
            ask=self.ask,
            ask_complete=self.ask_complete,
            choose=self.choose,
            multiselect=self.multiselect,
            confirm=self.confirm,
            notify=self._notify,
            progress=self.progress,
        )

    def engagement_wizard(self) -> None:
        """Collect a scope field-by-field via rich widgets and load it."""
        wizard.run_wizard(
            self._prompter(),
            self._core.engagement_mgr.create_engagement,
            self.engagement_catalog(),
            existing=self._core.engagement,
        )

    def set_engagement_param(self, name: str, value: str) -> None:
        """Edit one engagement field interactively (``set engagement <param>``)."""
        engagementflow.run_param_edit(
            self._core,
            name,
            value,
            prompter=self._prompter(),
            catalog=self.engagement_catalog(),
            grants=self._core.grants,
        )

    # ----- config / scope ----------------------------------------------------

    def set_config(self, arg: str) -> None:
        """Show/set a config key, or drive a natural-language config request."""
        text = self._core.config.line(arg)
        if text is not None:  # show / mechanical key-value
            self._console.print(text)
            return
        configflow.run_config_request(  # natural-language request -> LLM + confirm
            arg,
            choose=self.choose,
            notify=self._notify,
            propose=self._core.config.propose,
            apply=self._core.config.apply,
            grants=self._core.grants,
        )

    def capture_memory(self, user_text: str) -> None:
        """Post-turn: propose remembering any standing directive, gated by confirm.

        The REPL analog of ``attach.attach_memory_capture`` -- the in-loop evaluator
        proposes, the operator approves, and only then is harness memory written.
        """
        candidates = self._core.memory.propose_capture(user_text)
        memoryflow.run_memory_capture(
            candidates,
            choose=self.choose,
            notify=self._notify,
            apply=self._core.memory.apply_capture,
            grants=self._core.grants,
            interactive=True,
        )

    # ----- install -----------------------------------------------------------

    def install_missing(self) -> None:
        """Install the missing scoped tools, gated by the shared confirm."""
        installflow.run_install_missing(
            choose=self.choose,
            notify=self._notify,
            propose=self._core.doctor.propose_installs,
            install=self._core.doctor.install,
            grants=self._core.grants,
            pending=lambda label: self._console.status(label, spinner="dots"),
        )

    def research_install(self, tool: str) -> None:
        """Research how to install `tool`, then confirm and install (gated)."""
        installflow.run_install_research(
            tool,
            choose=self.choose,
            notify=self._notify,
            research=self._core.installer.research,
            install=self._core.installer.install,
            grants=self._core.grants,
            pending=lambda label: self._console.status(label, spinner="dots"),
        )

    # ----- cmd registry ------------------------------------------------------

    def cmd_suggest(self, request: str) -> None:
        """Propose a cheatsheet alias for a natural-language request, then confirm."""
        if not request.strip():
            self._emit(presenters.usage("cmd suggest <request>", "repl"))
            return
        cmdflow.run_cmd_suggest(
            request,
            choose=self.choose,
            notify=self._notify,
            propose=self._core.cmds.propose,
            preview=self._core.cmds.preview_proposal,
            apply=self._core.cmds.apply_proposal,
            grants=self._core.grants,
        )

    def alias_add(self) -> None:
        """Create a cheatsheet alias field-by-field in the editor."""
        cmdflow.run_cmd_editor(self.ask, self._core.cmds.add, self._notify)

    def alias_edit(self, name: str) -> None:
        """Edit an existing cheatsheet alias in the editor."""
        existing = self._core.commands.alias_for(name)
        if existing is None:
            self._console.print(f"[yellow]unknown alias[/yellow] {name!r}")
            return
        cmdflow.run_cmd_editor(
            self.ask,
            lambda raw: self._core.cmds.update(name, raw),
            self._notify,
            existing=existing,
        )

    def alias_remove(self, name: str) -> None:
        """Remove a cheatsheet alias by name."""
        if not name:
            self._console.print(
                f"[yellow]usage:[/yellow] {verbs.cmd('cmd rm <name>', 'repl')}"
            )
            return
        if self._core.cmds.remove(name):
            self._console.print(f"[dim]removed alias '{name}'[/dim]")
        else:
            self._console.print(f"[yellow]unknown alias[/yellow] {name!r}")
