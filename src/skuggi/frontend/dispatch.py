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

from skuggi.agent import readiness
from skuggi.common import palette
from skuggi.common.paths import packaged_template
from skuggi.config.configs import ConfigError
from skuggi.engagement.engagement import ThreatModel

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore
    from skuggi.agent.readiness import Readiness
    from skuggi.persistence.ledger import FindingRow, SessionRow
    from skuggi.persistence.preferences import PreferenceRow

# The packaged scope template and the name it scaffolds to in the cwd.
_SCOPE_TEMPLATE = "scope.example.json"
_SCOPE_OUT = "scope.json"


def run_status(core: AgentCore) -> Readiness:
    """A readiness snapshot for the ``show status`` view (rendered per front-end)."""
    return readiness.from_core(core)


def _count_journal_entries(text: str) -> int:
    """Count timestamped journal bullets (``- `<iso>` …`` lines) in a journal."""
    return sum(1 for line in text.splitlines() if line.strip().startswith("- "))


def run_db_stats(core: AgentCore) -> str:
    """Render the current session's ledger stats (the ``show db`` view).

    Reads turns / commands / findings / notes / loot back from the live ledger
    and journal and formats them with the shared session-summary renderer, so the
    REPL, the daemon and the shell's exit summary all read the same.
    """
    from datetime import UTC, datetime  # noqa: PLC0415 -- keep module load light

    from skuggi.persistence.session_summary import (  # noqa: PLC0415
        render_session_summary,
    )

    events = core.ledger.events_for(core.session_id)
    session = core.ledger.session(core.session_id)
    elapsed: float | None = None
    if session is not None:
        started = datetime.fromisoformat(session.started_at)
        elapsed = (datetime.now(UTC) - started).total_seconds()
    return render_session_summary(
        engagement_name=core.engagement.name if core.engagement else None,
        mode=core.mode,
        elapsed_s=elapsed,
        turns=sum(1 for ev in events if ev.kind == "prompt"),
        commands=core.ledger.commands_for(core.session_id),
        findings=core.ledger.findings_for(core.session_id),
        notes=_count_journal_entries(core.journal.notes()),
        loot=_count_journal_entries(core.journal.loot()),
    )


# ----- engagement scaffold --------------------------------------------------
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


def run_scaffold(dest_dir: Path) -> ScaffoldOutcome:
    """Copy the packaged scope template into `dest_dir`, never overwriting.

    The operator edits the resulting ``scope.json`` and points an engagement at
    it. A pre-existing file is left untouched (the template is a starting point,
    not a reset).
    """
    target = dest_dir / _SCOPE_OUT
    if target.exists():
        return ScaffoldExists(target)
    try:
        target.write_bytes(packaged_template(_SCOPE_TEMPLATE).read_bytes())
    except OSError as exc:
        return ScaffoldError(str(exc))
    return Scaffolded(target)


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
    """Parse ``<severity|CVSS:3.1/...> <title>`` and record the finding, or explain."""
    first, _, title = rest.partition(" ")
    first, title = first.strip(), title.strip()
    if not first or not title:
        return AddUsage("finding <severity|CVSS:3.1/...> <title>")
    # A CVSS vector scores deterministically (band derived); otherwise a severity word.
    if first.upper().startswith("CVSS:"):
        row = core.journal.record_finding(title=title, cvss_vector=first)
        if row is None:
            return AddUsage("finding <severity|CVSS:3.1/...> <title>")
        return FindingRecorded(row)
    severity = first.lower()
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


# ----- findings review (approve / reject) -----------------------------------
_FINDINGS_USAGE = "findings [approve <id> | reject <id> <reason> | rescore [all|<id>]]"


def _review_finding(core: AgentCore, id_str: str, status: str, reason: str) -> str:
    try:
        fid = int(id_str.lstrip("#").strip())
    except ValueError:
        return f"not a finding id: {id_str!r}"
    row = core.journal.set_status(fid, status, reason=reason)
    if row is None:
        return f"no such finding in this session: {id_str}"
    extra = f": {reason}" if reason else ""
    return f"{status} finding [{fid}]{extra}"


def run_findings(core: AgentCore, arg: str) -> str | None:
    """Handle a `findings` review sub-command. ``None`` means "list them instead".

    Shared by both front-ends so the approve/reject grammar and messages never
    drift; each front-end still owns how it *renders the listing*.
    """
    tokens = arg.split()
    if not tokens:
        return None
    action = tokens[0].lower()
    if action == "approve" and len(tokens) >= 2:  # noqa: PLR2004 -- action + id
        return _review_finding(core, tokens[1], "approved", "")
    if action == "reject" and len(tokens) >= 2:  # noqa: PLR2004 -- action + id
        reason = arg.split(maxsplit=2)[2] if len(tokens) >= 3 else ""  # noqa: PLR2004
        return _review_finding(core, tokens[1], "rejected", reason)
    if action == "rescore":
        return _rescore_findings(core, tokens[1] if len(tokens) >= 2 else "all")  # noqa: PLR2004
    if action in {"approve", "reject"}:
        return f"usage: {_FINDINGS_USAGE}"
    return None


_TM_LEVELS = frozenset({"low", "medium", "high"})
_TM_USAGE = "engagement threat-model <conf> <int> <avail> [| note]  (low|medium|high)"


def run_threat_model(core: AgentCore, arg: str) -> str:
    """Show or set the engagement's CVSS threat model, versioning any change.

    ``<conf> <int> <avail>`` are the CR/IR/AR levels; ``clear`` removes the model.
    An optional ``| note`` after the levels is the change-log entry. Setting it marks
    findings scored under the prior version outdated (rescore with ``findings
    rescore all``).
    """
    if core.engagement is None:
        return "no engagement loaded; cannot set a threat model"
    rest = arg.strip()
    if not rest:
        tm = core.engagement.threat_model
        version = core.ledger.current_threat_model_version()
        if tm is None:
            return f"threat model: none (v{version})"
        return (
            f"threat model (v{version}): CR={tm.confidentiality_requirement} "
            f"IR={tm.integrity_requirement} AR={tm.availability_requirement}"
        )
    body, _, note = rest.partition("|")
    note = note.strip()
    if body.strip().lower() in {"clear", "none"}:
        version = core.update_threat_model(None, note=note or "cleared")
        return f"threat model cleared (now v{version}); run `findings rescore all`"
    levels = [t.strip().lower() for t in body.replace(",", " ").split() if t.strip()]
    if len(levels) != 3 or any(level not in _TM_LEVELS for level in levels):  # noqa: PLR2004
        return f"usage: {_TM_USAGE}"
    threat_model = ThreatModel.model_validate(
        {
            "confidentiality_requirement": levels[0],
            "integrity_requirement": levels[1],
            "availability_requirement": levels[2],
        }
    )
    version = core.update_threat_model(threat_model, note=note)
    return f"threat model updated (now v{version}); run `findings rescore all`"


def _rescore_findings(core: AgentCore, target: str) -> str:
    """Rescore one finding (``<id>``) or every outdated one (``all``)."""
    if target == "all":
        n = core.journal.rescore(None)
        return f"rescored {n} finding(s) to the current threat model"
    try:
        fid = int(target.lstrip("#").strip())
    except ValueError:
        return f"not a finding id: {target!r}"
    ok = core.journal.rescore(fid)
    return (
        f"rescored finding [{fid}]"
        if ok
        else f"finding [{fid}] has no CVSS score to rescore"
    )


# ----- doctor install -------------------------------------------------------
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


def doctor_install_target(arg: str) -> str | None:
    """The binary for a ``doctor install [binary]`` form, else ``None``.

    Shared so the REPL and the daemon parse the sub-command identically -- they
    diverged (one read the first token, the other the whole tail). ``""`` means
    ``install`` with no binary (which ``run_install`` reports as unknown).
    """
    parts = arg.split()
    if not parts or parts[0] != "install":
        return None
    return parts[1] if len(parts) > 1 else ""


def run_install(core: AgentCore, binary: str) -> InstallOutcome:
    """Install one recognized tool. Issuing the command is itself the confirm."""
    status = core.doctor.install(binary)
    if status is None:
        return InstallUnknown(binary)
    if status.found:
        return Installed(binary, status.version, status.source)
    return InstallFailed(binary)


# ----- replay ---------------------------------------------------------------
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


def run_replay(core: AgentCore, arg: str, *, current_id: str | None) -> ReplayOutcome:
    """List sessions (``replay list``) or reconstruct one's transcript."""
    a = arg.strip()
    if a == "list":
        rows = core.archive.sessions()
        return ReplayList(rows, current_id) if rows else ReplayEmpty()
    return ReplayTranscript(core.archive.transcript(a or None))
