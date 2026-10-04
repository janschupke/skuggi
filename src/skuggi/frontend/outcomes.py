"""Typed outcomes for the drift-prone control verbs.

Each ``run_*`` in :mod:`skuggi.frontend.dispatch` returns one of these; the
front-ends match on them and :mod:`skuggi.frontend.presenters` renders them. They
live apart from both so the logic layer, the view layer and the shared vocabulary
of results can be imported without pulling the other two in.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from skuggi.install import configdiff, reconcile
    from skuggi.persistence.ledger import FindingRow, SessionRow
    from skuggi.persistence.preferences import PreferenceRow


@dataclass(frozen=True, slots=True)
class Scaffolded:
    """The scope template was copied to `path`."""

    path: Path


@dataclass(frozen=True, slots=True)
class ScaffoldExists:
    """A scope file is already present at `path`; nothing was overwritten."""

    path: Path


@dataclass(frozen=True, slots=True)
class ScaffoldError:
    """Copying the template failed (`message` is the OS error)."""

    message: str


ScaffoldOutcome = Scaffolded | ScaffoldExists | ScaffoldError


@dataclass(frozen=True, slots=True)
class EngagementAdopted:
    """An existing engagement at `root` was adopted (`name` is its scope name)."""

    name: str
    root: Path


@dataclass(frozen=True, slots=True)
class EngagementScaffolded:
    """`root` had no scope; the template was scaffolded to `scope_path` and adopted."""

    name: str
    root: Path
    scope_path: Path


@dataclass(frozen=True, slots=True)
class SetEngagementError:
    """Creating, scaffolding or loading the engagement failed (`message`)."""

    message: str


SetEngagementOutcome = EngagementAdopted | EngagementScaffolded | SetEngagementError


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


@dataclass(frozen=True, slots=True)
class MemoryUsage:
    """The sub-command needs an argument; `form` is its usage tail."""

    form: str  # e.g. "add <preference>" / "forget <id>"


@dataclass(frozen=True, slots=True)
class MemoryAdded:
    """A preference was remembered."""

    row: PreferenceRow


@dataclass(frozen=True, slots=True)
class MemoryAddedOverCap:
    """A preference was remembered, but the store is now over its capacity cap."""

    row: PreferenceRow
    count: int
    maximum: int


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
    | MemoryAddedOverCap
    | MemoryAlreadyKnown
    | MemoryForgotten
    | MemoryMissing
    | MemoryCleared
    | MemoryList
)


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


@dataclass(frozen=True, slots=True)
class InstallUnknown:
    """The install target is not a recognized tool (`binary` may be empty)."""

    binary: str


@dataclass(frozen=True, slots=True)
class Installed:
    """A tool was installed; names its version and the installer source."""

    binary: str
    version: str | None
    source: str


@dataclass(frozen=True, slots=True)
class InstallFailed:
    """The install ran but the tool is still not available."""

    binary: str


InstallOutcome = InstallUnknown | Installed | InstallFailed


@dataclass(frozen=True, slots=True)
class ReplayEmpty:
    """``replay list`` with no sessions recorded yet."""


@dataclass(frozen=True, slots=True)
class ReplayList:
    """The recorded sessions; `current_id` marks the live one for the renderer."""

    rows: list[SessionRow]
    current_id: str | None


@dataclass(frozen=True, slots=True)
class ReplayTranscript:
    """A reconstructed session transcript for the front-end to render."""

    text: str


ReplayOutcome = ReplayEmpty | ReplayList | ReplayTranscript


@dataclass(frozen=True, slots=True)
class ReconcileRow:
    """A config file's status plus its drift magnitude (0s unless drifted)."""

    status: reconcile.FileStatus
    added: int
    removed: int
    changed: int


@dataclass(frozen=True, slots=True)
class ReconcileList:
    """The status + drift magnitude of every reconcilable config file."""

    rows: tuple[ReconcileRow, ...]


@dataclass(frozen=True, slots=True)
class ReconcileDiff:
    """The semantic diff `name` installed -> packaged (empty when up to date)."""

    name: str
    diff: configdiff.StructuredDiff


@dataclass(frozen=True, slots=True)
class ReconcileOverwritten:
    """`name` was overwritten from its template; `backup` is the saved copy."""

    name: str
    backup: Path | None


@dataclass(frozen=True, slots=True)
class ReconcileAll:
    """Every drifted file was overwritten; `results` is ``(name, backup)`` per file."""

    results: tuple[tuple[str, Path | None], ...]


@dataclass(frozen=True, slots=True)
class ReconcileUnknown:
    """`name` is not a reconcilable config file."""

    name: str


@dataclass(frozen=True, slots=True)
class ReconcileUsage:
    """An unrecognised subcommand -- the front-end shows the usage line."""


ReconcileOutcome = (
    ReconcileList
    | ReconcileDiff
    | ReconcileOverwritten
    | ReconcileAll
    | ReconcileUnknown
    | ReconcileUsage
)


@dataclass(frozen=True, slots=True)
class SessionCount:
    """A session row with derived activity counts, for ``show sessions``."""

    session_id: str
    started_at: str
    mode: str
    turns: int
    commands: int
    findings: int
    current: bool
