"""The command cheatsheet for the ``cmd`` verb (``core.cmds``).

A sub-component of :class:`~skuggi.agent.core.AgentCore`: it resolves and
scope-checks cheatsheet aliases and persists edits to the alias registry. It
reads the live ``commands`` registry, tool registry, engagement and ledger off
the core each call (``commands`` is reassigned by tests and by its own ``_save``;
the ledger is hot-swapped by ``adopt_engagement``), so nothing is cached.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import ValidationError

from skuggi.agent import prompts
from skuggi.agent.protocol import CmdProposal, structured_invoke
from skuggi.config.configs import ConfigError, write_commands
from skuggi.engagement.engagement import (
    GuardVerdict,
    check_command,
    parse_command,
)
from skuggi.tooling.commands import CommandAlias, CommandRegistry, raw_command, render

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore


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


class CommandBook:
    """Resolves, scope-checks and edits the cheatsheet command aliases."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core

    def search(self, query: str) -> tuple[CommandAlias, ...]:
        """Cheatsheet aliases matching `query` by substring (blank = all)."""
        return self._core.commands.search(query)

    def plan(self, name: str) -> RunPlan:
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
        core = self._core
        alias = core.commands.alias_for(name)
        if alias is None:
            avail = ", ".join(core.commands.names()) or "(none configured)"
            return RunPlan(
                alias=name,
                raw="",
                known=False,
                verdict=None,
                command_id=None,
                note=f"unknown alias {name!r}. available: {avail}",
            )
        raw = render(alias, core.registry)
        if core.engagement is None:
            return RunPlan(
                alias=name,
                raw=raw,
                known=True,
                verdict=None,
                command_id=None,
                note="no engagement loaded -- scope not checked; review before running",
            )
        resolved = core.engagement.resolve_target()
        check_argv = [*alias.argv, *([resolved] if resolved else [])]
        parsed = parse_command(raw_command(check_argv), core.registry)
        if resolved is None:
            # No single ${target} to substitute, so don't *demand* one -- but
            # still scope-check any literal host in the alias's own argv (and
            # keep the unresolved/target-file denials). Only the requirement is
            # relaxed, not the checks.
            parsed = replace(parsed, requires_target=False)
        verdict = check_command(
            parsed, core.engagement, now=datetime.now(core.engagement.tzinfo())
        )
        status = "proposed" if verdict.allowed else "blocked"
        command_id = core.ledger.record_command(
            session_id=core.session_id,
            thread_id=core.thread_id,
            command=raw,
            binary=parsed.binary,
            method=parsed.method,
            status=status,
            reason="" if verdict.allowed else verdict.reason,
            turn_event_id=core._current_turn_event_id,  # noqa: SLF001 -- links to the in-flight turn
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

    def _validate(self, raw: dict[str, object]) -> CommandAlias:
        try:
            return CommandAlias.model_validate(raw)
        except ValidationError as exc:
            msg = f"invalid command alias: {exc}"
            raise ConfigError(msg) from exc

    def _save(self, registry: CommandRegistry) -> None:
        write_commands(self._core.settings.commands_path, registry)
        self._core.commands = registry

    def add(self, raw: dict[str, object]) -> CommandAlias:
        """Validate and append a new cheatsheet alias, persisting the registry.

        Raises ``ConfigError`` if the alias does not validate or its name is
        already taken (the editor shows the reason and re-asks).
        """
        alias = self._validate(raw)
        if self._core.commands.alias_for(alias.name) is not None:
            msg = f"command alias {alias.name!r} already exists (use edit)"
            raise ConfigError(msg)
        self._save(CommandRegistry(commands=(*self._core.commands.commands, alias)))
        return alias

    def update(self, name: str, raw: dict[str, object]) -> CommandAlias:
        """Replace the alias named `name`, persisting the registry.

        Raises ``ConfigError`` if `name` is unknown or the new alias is invalid.
        """
        if self._core.commands.alias_for(name) is None:
            msg = f"unknown command alias {name!r}"
            raise ConfigError(msg)
        alias = self._validate(raw)
        self._save(
            CommandRegistry(
                commands=tuple(
                    alias if a.name == name else a for a in self._core.commands.commands
                )
            )
        )
        return alias

    def remove(self, name: str) -> bool:
        """Drop the alias named `name`; ``True`` if it existed. Persists the change."""
        if self._core.commands.alias_for(name) is None:
            return False
        self._save(
            CommandRegistry(
                commands=tuple(
                    a for a in self._core.commands.commands if a.name != name
                )
            )
        )
        return True

    # ----- natural-language suggestion (the `cmd suggest` verb) --------------

    def propose(self, request: str) -> CmdProposal:
        """Ask the LLM to propose one cheatsheet alias for `request`."""
        core = self._core
        existing = ", ".join(core.commands.names()) or "(none)"
        return structured_invoke(
            core._ensure_llm(),  # noqa: SLF001 -- sub-component drives the model kernel
            CmdProposal,
            [
                SystemMessage(
                    content=prompts.PROPOSE_CMD_INSTRUCTION.format(existing=existing)
                ),
                HumanMessage(content=request),
            ],
            native=core.settings.supports_structured_output(),
        )

    def preview_proposal(self, proposal: CmdProposal) -> str:
        """The rendered command for a proposal. Raises ConfigError if invalid."""
        alias = self._validate(_proposal_raw(proposal))
        return render(alias, self._core.registry)

    def apply_proposal(self, proposal: CmdProposal) -> str:
        """Add the proposed alias, or update it if its name already exists."""
        raw = _proposal_raw(proposal)
        if self._core.commands.alias_for(proposal.name) is not None:
            self.update(proposal.name, raw)
            return f"cmd updated: {proposal.name}"
        self.add(raw)
        return f"cmd added: {proposal.name}"


def _proposal_raw(proposal: CmdProposal) -> dict[str, object]:
    """The CommandAlias dict for a proposal, dropping blank optional fields."""
    raw: dict[str, object] = {"name": proposal.name, "argv": proposal.argv}
    if proposal.description:
        raw["description"] = proposal.description
    if proposal.tool:
        raw["tool"] = proposal.tool
    if proposal.label:
        raw["label"] = proposal.label
    return raw
