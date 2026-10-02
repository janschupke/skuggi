"""Presentation-free dispatch for the drift-prone control verbs.

The two front-ends render differently -- Rich markup in the REPL, plain text over
the daemon socket -- but the *logic* behind a few verbs (parse the argument, call
the one ``AgentCore`` method, map the same exceptions to the same outcomes) must
not drift between them, which it has before (``daemon._CONTROL_HELP`` vs
``tui.HELP``). Each ``run_*`` here returns a typed outcome and the front-end
matches it and renders in its own style, the same split the ``run`` verb already
uses with ``core.cmds.plan`` -> ``RunPlan``. No ``AgentCore`` method changes;
this only wraps the existing calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from skuggi.common import palette
from skuggi.config.configs import ConfigError

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore
    from skuggi.persistence.ledger import FindingRow
    from skuggi.persistence.preferences import PreferenceRow


# ----- provider -------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ProviderUsage:
    """No argument given -- the front-end shows its own usage line."""


@dataclass(frozen=True, slots=True)
class ProviderSwitched:
    """The provider changed; names the live provider and model."""

    provider: str
    model: str | None


@dataclass(frozen=True, slots=True)
class ProviderUnknown:
    """The provider name was not recognised."""

    message: str


@dataclass(frozen=True, slots=True)
class ProviderNoCredential:
    """Switched, but the new provider has no credential."""

    provider: str


@dataclass(frozen=True, slots=True)
class ProviderError:
    """The provider switch failed to build a model."""

    message: str


ProviderOutcome = (
    ProviderUsage
    | ProviderSwitched
    | ProviderUnknown
    | ProviderNoCredential
    | ProviderError
)


def run_provider(core: AgentCore, arg: str) -> ProviderOutcome:
    """Switch provider, mapping the switch's failures to typed outcomes."""
    if not arg.strip():
        return ProviderUsage()
    try:
        core.set_provider(arg)
    except ValueError as exc:
        return ProviderUnknown(str(exc))
    except ConfigError:  # switched, but the new provider has no credential
        return ProviderNoCredential(arg)
    except (RuntimeError, ImportError) as exc:
        return ProviderError(str(exc))
    return ProviderSwitched(core.provider, core.model)


# ----- model ----------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ModelUsage:
    """Empty/invalid name -- the front-end shows its own usage line."""


@dataclass(frozen=True, slots=True)
class ModelSwitched:
    """The model changed; names the live provider and model."""

    provider: str
    model: str | None


@dataclass(frozen=True, slots=True)
class ModelNoCredential:
    """Switched, but the current provider has no credential."""

    provider: str


@dataclass(frozen=True, slots=True)
class ModelError:
    """The model switch failed to build a model."""

    message: str


ModelOutcome = ModelUsage | ModelSwitched | ModelNoCredential | ModelError


def run_model(core: AgentCore, arg: str) -> ModelOutcome:
    """Switch model on the current provider, mapping failures to outcomes."""
    try:
        core.set_model(arg)
    except ValueError:
        return ModelUsage()
    except ConfigError:  # the switch rebuilt the llm and found no key
        return ModelNoCredential(core.provider)
    except (RuntimeError, ImportError) as exc:
        return ModelError(str(exc))
    return ModelSwitched(core.provider, core.model)


# ----- memory ---------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class MemoryUsage:
    """The sub-command needs an argument; `form` is its usage tail."""

    form: str  # e.g. "add <preference>" / "forget <id>"


@dataclass(frozen=True, slots=True)
class MemoryAdded:
    """A preference was remembered."""

    row: PreferenceRow


@dataclass(frozen=True, slots=True)
class MemoryAlreadyKnown:
    """The preference text was already remembered."""


@dataclass(frozen=True, slots=True)
class MemoryForgotten:
    """A preference was removed."""


@dataclass(frozen=True, slots=True)
class MemoryMissing:
    """No preference matched the given id."""

    ref: str


@dataclass(frozen=True, slots=True)
class MemoryCleared:
    """Every preference was removed; `count` is how many."""

    count: int


@dataclass(frozen=True, slots=True)
class MemoryList:
    """The current preferences, for the front-end to render."""

    rows: list[PreferenceRow]


MemoryOutcome = (
    MemoryUsage
    | MemoryAdded
    | MemoryAlreadyKnown
    | MemoryForgotten
    | MemoryMissing
    | MemoryCleared
    | MemoryList
)


def run_memory(core: AgentCore, arg: str) -> MemoryOutcome:
    """Show / add / forget / clear remembered operator preferences."""
    sub, _, rest = arg.partition(" ")
    sub, rest = sub.strip().lower(), rest.strip()
    if sub == "add":
        if not rest:
            return MemoryUsage("add <preference>")
        row = core.memory.add(rest)
        return MemoryAdded(row) if row else MemoryAlreadyKnown()
    if sub == "forget":
        if not rest.isdigit():
            return MemoryUsage("forget <id>")
        removed = core.memory.forget(int(rest))
        return MemoryForgotten() if removed else MemoryMissing(rest)
    if sub == "clear":
        return MemoryCleared(core.memory.clear())
    return MemoryList(core.memory.entries())


# ----- add (note / loot / finding) ------------------------------------------
@dataclass(frozen=True, slots=True)
class AddUsage:
    """Missing or unknown sub-command; `form` is the usage tail after ``add``."""

    form: str


@dataclass(frozen=True, slots=True)
class NoEngagement:
    """Notes and loot are workspace files; none is loaded. `kind` is note/loot."""

    kind: str


@dataclass(frozen=True, slots=True)
class AddedNote:
    """A note was appended to the engagement journal at `path`."""

    path: Path


@dataclass(frozen=True, slots=True)
class AddedLoot:
    """A loot entry was appended to the engagement journal at `path`."""

    path: Path


@dataclass(frozen=True, slots=True)
class BadSeverity:
    """The finding severity was not one of `allowed`."""

    value: str
    allowed: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FindingRecorded:
    """A finding was written to the ledger; `row` is the stored record."""

    row: FindingRow


AddOutcome = (
    AddUsage | NoEngagement | AddedNote | AddedLoot | BadSeverity | FindingRecorded
)


def _run_add_finding(core: AgentCore, rest: str) -> AddOutcome:
    """Parse ``<severity> <title>`` and record the finding, or explain the problem."""
    severity, _, title = rest.partition(" ")
    severity, title = severity.strip().lower(), title.strip()
    if not severity or not title:
        return AddUsage("finding <severity> <title>")
    if severity not in palette.severities():
        return BadSeverity(severity, palette.severities())
    row = core.journal.record_finding(severity, title)
    if row is None:  # pragma: no cover -- severity already validated above
        return BadSeverity(severity, palette.severities())
    return FindingRecorded(row)


def run_add(core: AgentCore, arg: str) -> AddOutcome:
    """Record a note, loot item or finding, mapping each case to a typed outcome."""
    sub, _, rest = arg.partition(" ")
    sub, rest = sub.strip().lower(), rest.strip()
    if sub == "note":
        if not rest:
            return AddUsage("note <text>")
        path = core.journal.add_note(rest)
        return AddedNote(path) if path is not None else NoEngagement("note")
    if sub == "loot":
        if not rest:
            return AddUsage("loot <text>")
        path = core.journal.add_loot(rest)
        return AddedLoot(path) if path is not None else NoEngagement("loot")
    if sub == "finding":
        return _run_add_finding(core, rest)
    return AddUsage("note <text> | loot <text> | finding <severity> <title>")
