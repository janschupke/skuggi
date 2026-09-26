"""The command-alias registry: named shorthands for real CLI invocations.

An alias maps a short name (``nmap-host``) to a base argv (``nmap -sV -sC``); the
operator's extra arguments are appended, so ``run nmap-host 10.0.0.5`` resolves to
``nmap -sV -sC 10.0.0.5``. The **resolved raw command is always surfaced** to the
operator (the transparency invariant) and checked against the engagement scope
like any agent-proposed command -- ``run`` advises and records, it never executes
silently.

Loaded from ``configs/commands.json`` (shipped as ``.example``); user-extendable
by editing that JSON. The model mirrors ``registry.ToolRegistry`` deliberately.
"""

from __future__ import annotations

import shlex

from pydantic import BaseModel, ConfigDict


class CommandAlias(BaseModel):
    """One named command shorthand and the base argv it expands to."""

    model_config = ConfigDict(frozen=True)

    name: str
    argv: tuple[str, ...]
    description: str = ""

    def resolve(self, extra: list[str]) -> list[str]:
        """The full argv: the base plus the operator's extra arguments."""
        return [*self.argv, *extra]


class CommandRegistry(BaseModel):
    """The set of command aliases skuggi knows."""

    model_config = ConfigDict(frozen=True)

    commands: tuple[CommandAlias, ...] = ()

    def alias_for(self, name: str) -> CommandAlias | None:
        """The alias registered under `name`, or None."""
        for alias in self.commands:
            if alias.name == name:
                return alias
        return None

    def names(self) -> tuple[str, ...]:
        """Every registered alias name, in registry order."""
        return tuple(a.name for a in self.commands)


def raw_command(argv: list[str]) -> str:
    """The shell-quoted raw command string for `argv` (what the operator sees)."""
    return shlex.join(argv)
