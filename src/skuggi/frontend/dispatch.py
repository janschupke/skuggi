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
from skuggi.frontend import render, verbs
from skuggi.frontend.render import Styled
from skuggi.install import reconcile

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore
    from skuggi.agent.readiness import Readiness
    from skuggi.persistence.ledger import FindingRow, SessionRow, ThreadSummary
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


# ===== presenters ===========================================================
# One place for every verb's WORDING. A presenter takes the already-computed
# result and returns a list of styled `render.Line`s; each front-end only styles
# them (Rich in the REPL, plain over the socket), so the two surfaces can no
# longer say different things for the same command. `surface` is threaded through
# only where a command hint is embedded (via `verbs.cmd`). Structural outputs
# (severity-painted finding lines, Markdown journals, Rich tables) are NOT lines;
# they keep dedicated per-surface paths over shared content.


def usage(invocation: str, surface: verbs.Surface) -> Styled:
    """A single ``usage: <command>`` line, phrased for `surface`."""
    return [render.warning(f"usage: {verbs.cmd(invocation, surface)}")]


def empty(kind: str) -> Styled:
    """A single ``(no <kind> yet)`` empty-state line (uniform across verbs)."""
    return [render.info(f"(no {kind} yet)")]


def present_provider(outcome: ProviderOutcome, surface: verbs.Surface) -> Styled:
    """Render the result of switching provider."""
    match outcome:
        case ProviderUsage():
            return usage("set provider <name>", surface)
        case ProviderUnknown(message):
            return [render.danger(message)]
        case ProviderNoCredential(provider):
            fix = verbs.cmd("set provider", surface)
            return [
                render.warning(f"{provider} isn't configured -- run {fix} to add a key")
            ]
        case ProviderError(message):
            return [render.danger(f"provider error: {message}")]
        case ProviderSwitched(provider, model):
            return [render.info(f"switched to {provider}/{model or '(default)'}")]


def present_model(outcome: ModelOutcome, surface: verbs.Surface) -> Styled:
    """Render the result of switching model."""
    match outcome:
        case ModelUsage():
            return usage("set model <name>", surface)
        case ModelNoCredential(provider):
            fix = verbs.cmd("set provider", surface)
            return [
                render.warning(
                    f"can't switch model: {provider} isn't configured "
                    f"-- run {fix} first"
                )
            ]
        case ModelError(message):
            return [render.danger(f"provider error: {message}")]
        case ModelSwitched(provider, model):
            return [render.info(f"switched to {provider}/{model}")]


def present_memory(outcome: MemoryOutcome) -> Styled:  # noqa: PLR0911 -- one return per outcome
    """Render a memory outcome (callers pre-validate, so no usage case)."""
    match outcome:
        case MemoryUsage():  # pragma: no cover -- callers validate before calling
            return []
        case MemoryAdded(row):
            return [render.success(f"remembered [{row.id}] {row.text}")]
        case MemoryAlreadyKnown():
            return [render.info("already remembered")]
        case MemoryForgotten():
            return [render.info("forgotten")]
        case MemoryMissing(ref):
            return [render.warning(f"no preference {ref}")]
        case MemoryCleared(count):
            return [render.info(f"cleared {count} preference(s)")]
        case MemoryList(rows):
            if not rows:
                return empty("memories")
            return [render.plain(f"[{r.id}] {r.text} ({r.source})") for r in rows]


def present_add(outcome: AddOutcome, surface: verbs.Surface) -> Styled:
    """Render note/loot/usage add outcomes.

    A recorded FINDING is NOT handled here (the front-end paints its severity via
    ``finding_line``); callers branch on ``FindingRecorded`` before calling.
    """
    match outcome:
        case AddUsage(form):
            return usage(f"add {form}", surface)
        case NoEngagement(kind):
            fix = verbs.cmd("engagement setup", surface)
            return [
                render.warning(f"no engagement loaded -- run {fix} to record {kind}s")
            ]
        case BadSeverity(value, allowed):
            choices = ", ".join(allowed)
            return [
                render.danger(f"unknown severity {value!r}; choose one of: {choices}")
            ]
        case AddedNote(path):
            return [render.success(f"noted {path}")]
        case AddedLoot(path):
            return [render.success(f"loot recorded {path}")]
        case FindingRecorded():  # pragma: no cover -- caller renders findings
            return []


def present_install(outcome: InstallOutcome) -> Styled:
    """Render a ``doctor install`` outcome."""
    match outcome:
        case InstallUnknown(binary):
            return [render.danger(f"unknown tool: {binary!r}")]
        case Installed(binary, version, source):
            return [
                render.success(f"installed {binary} ({version or '?'}) via {source}")
            ]
        case InstallFailed(binary):
            return [render.danger(f"install failed or unavailable for {binary}")]


def present_scaffold(outcome: ScaffoldOutcome) -> Styled:
    """Render an ``engagement scaffold`` outcome."""
    match outcome:
        case Scaffolded(path):
            return [render.success(f"scaffolded {path}")]
        case ScaffoldExists(path):
            return [render.warning(f"{path} already exists -- not overwritten")]
        case ScaffoldError(message):
            return [render.danger(f"scaffold failed: {message}")]


def present_mode(mode: str) -> Styled:
    """Render a mode switch."""
    return [render.info(f"mode: {mode}")]


def present_autonomous(state: bool) -> Styled:
    """Render an autonomous toggle, keeping the scope warning on BOTH surfaces."""
    if state:
        return [
            render.danger(
                "autonomous execution is now ON -- proposed commands will "
                "EXECUTE within scope"
            )
        ]
    return [render.plain("autonomous execution is now off")]


def present_thread(action: str, value: str) -> Styled:
    """Render a thread action (``new`` -> value is the id; else a switch)."""
    if action == "new":
        return [render.info(f"new thread: {value}")]
    return [render.info(f"switched to thread: {value}")]


def present_error(message: str) -> Styled:
    """A single error line (e.g. a ValueError from set mode/autonomous/thread)."""
    return [render.danger(message)]


def present_cmd_plan(plan: object, surface: verbs.Surface) -> Styled:  # noqa: ARG001
    """Render a resolved ``cmd`` plan (rendered command + scope verdict).

    `plan` is a ``commandbook.RunPlan``; typed loosely to avoid importing the
    agent layer here. Never fires an agent turn -- it only presents.
    """
    from skuggi.agent.commandbook import RunPlan  # noqa: PLC0415 -- avoid import cycle

    assert isinstance(plan, RunPlan)  # noqa: S101
    if not plan.known:
        return [render.warning(plan.note)]
    lines: Styled = [render.heading(f"$ {plan.raw}")]
    if plan.verdict is not None and not plan.verdict.allowed:
        lines.append(render.danger(f"OUT OF SCOPE: {plan.note}"))
    elif plan.verdict is None:
        lines.append(render.warning(plan.note))
    else:
        lines.append(
            render.success(
                f"{plan.note} -- recorded proposed (cmd:{plan.command_id}); "
                "submit it yourself"
            )
        )
    return lines


def present_status(readiness_now: Readiness, surface: verbs.Surface) -> Styled:
    """Render ``show status``: the shared glance plus pending steps (or 'ready')."""
    lines: Styled = [render.plain(readiness.glance(readiness_now))]
    notes = readiness.render_banner_notes(readiness_now, surface)
    if notes:
        lines += [render.info(note) for note in notes]
    else:
        lines.append(render.success("ready"))
    return lines


# ----- config reconcile -----------------------------------------------------
@dataclass(frozen=True, slots=True)
class ReconcileList:
    """The status of every reconcilable config file (``reconcile`` / ``list``)."""

    items: tuple[reconcile.FileStatus, ...]


@dataclass(frozen=True, slots=True)
class ReconcileDiff:
    """The diff `name` -> packaged template (`text` empty when up to date)."""

    name: str
    text: str


@dataclass(frozen=True, slots=True)
class ReconcileOverwritten:
    """`name` was overwritten from its template; `backup` is the saved copy."""

    name: str
    backup: Path | None


@dataclass(frozen=True, slots=True)
class ReconcileUnknown:
    """`name` is not a reconcilable config file."""

    name: str


@dataclass(frozen=True, slots=True)
class ReconcileUsage:
    """No/!unrecognised subcommand -- the front-end shows the usage line."""


ReconcileOutcome = (
    ReconcileList
    | ReconcileDiff
    | ReconcileOverwritten
    | ReconcileUnknown
    | ReconcileUsage
)


def run_reconcile(core: AgentCore, arg: str) -> ReconcileOutcome:
    """Parse ``reconcile [list | diff <file> | overwrite <file>]`` and act.

    ``overwrite`` is the only mutating path; it backs up the current file and
    reloads the in-memory config (both inside ``core.reconcile_overwrite``).
    """
    sub, _, rest = arg.partition(" ")
    sub, rest = sub.strip().lower(), rest.strip()
    if not sub or sub == "list":
        return ReconcileList(core.reconcile_status())
    if sub not in {"diff", "overwrite"} or not rest:
        return ReconcileUsage()
    if not reconcile.is_known(rest):
        return ReconcileUnknown(rest)
    if sub == "diff":
        return ReconcileDiff(rest, core.reconcile_diff(rest))
    return ReconcileOverwritten(rest, core.reconcile_overwrite(rest))


_RECONCILE_STYLE = {
    "up_to_date": render.success,
    "drifted": render.warning,
    "missing": render.info,
}


def _diff_line(line: str) -> render.Line:
    """Colour a unified-diff line: additions green, removals red, hunks dim."""
    if line.startswith("+") and not line.startswith("+++"):
        return render.success(line)
    if line.startswith("-") and not line.startswith("---"):
        return render.danger(line)
    if line.startswith(("@@", "+++", "---")):
        return render.info(line)
    return render.plain(line)


def present_reconcile(  # noqa: PLR0911 -- one return per outcome
    outcome: ReconcileOutcome, surface: verbs.Surface
) -> Styled:
    """Render a ``reconcile`` outcome identically on both surfaces."""
    match outcome:
        case ReconcileUsage():
            return [
                render.warning(
                    "usage: "
                    + verbs.cmd(
                        "reconcile [list | diff <file> | overwrite <file>]", surface
                    )
                )
            ]
        case ReconcileUnknown(name):
            choices = ", ".join(reconcile.known_names())
            return [
                render.danger(f"unknown config file {name!r}; choose one of: {choices}")
            ]
        case ReconcileList(items):
            lines: Styled = [render.heading("installed config vs packaged templates:")]
            lines += [
                _RECONCILE_STYLE[s.state](f"  {s.name:<16} {s.state}") for s in items
            ]
            if any(s.state == "drifted" for s in items):
                lines.append(
                    render.info(
                        "update a drifted file: "
                        + verbs.cmd("reconcile overwrite <file>", surface)
                        + " (a backup is saved)"
                    )
                )
            return lines
        case ReconcileDiff(name, text):
            if not text:
                return [
                    render.success(f"{name} is up to date with the packaged template")
                ]
            lines = [render.heading(f"{name}: installed -> packaged")]
            lines += [_diff_line(ln) for ln in text.splitlines()]
            lines.append(
                render.info(
                    "apply with "
                    + verbs.cmd(f"reconcile overwrite {name}", surface)
                    + " (a backup is saved)"
                )
            )
            return lines
        case ReconcileOverwritten(name, backup):
            done = render.success(f"{name} updated from the packaged template")
            if backup is not None:
                return [done, render.info(f"backup saved: {backup}")]
            return [done]


# ----- sessions -------------------------------------------------------------
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


def run_sessions(core: AgentCore) -> list[SessionCount]:
    """Every session in this engagement's ledger with turn/command/finding counts."""
    current = core.session_id
    out: list[SessionCount] = []
    for row in core.archive.sessions():
        events = core.ledger.events_for(row.session_id)
        out.append(
            SessionCount(
                session_id=row.session_id,
                started_at=row.started_at,
                mode=row.mode,
                turns=sum(1 for ev in events if ev.kind == "prompt"),
                commands=len(core.ledger.commands_for(row.session_id)),
                findings=len(core.ledger.findings_for(row.session_id)),
                current=row.session_id == current,
            )
        )
    return out


def present_sessions(rows: list[SessionCount]) -> Styled:
    """Render ``show sessions`` as one compact line per session."""
    if not rows:
        return empty("sessions")
    lines: Styled = []
    for s in rows:
        mark = " *" if s.current else ""
        lines.append(
            render.plain(
                f"{s.session_id[:8]}  {s.started_at}  {s.mode}  "
                f"{s.turns}t {s.commands}c {s.findings}f{mark}"
            )
        )
    return lines


def _snippet(text: str, width: int = 48) -> str:
    """A one-line, length-capped snippet of `text` for a list row."""
    flat = " ".join(text.split())
    return flat if len(flat) <= width else flat[: width - 1] + "…"


def present_threads(rows: list[ThreadSummary], current: str) -> Styled:
    """Render ``show threads`` so each thread is recognisable and resumable."""
    if not rows:
        return empty("threads")
    lines: Styled = []
    for t in rows:
        mark = " *" if t.thread_id == current else ""
        label = _snippet(t.first_prompt) if t.first_prompt else "(no prompts yet)"
        lines.append(
            render.plain(
                f"{t.thread_id[:8]}  {t.turns}t  {t.last_activity}  {label}{mark}"
            )
        )
    return lines


def present_show_provider(readiness_now: Readiness, surface: verbs.Surface) -> Styled:
    """Render ``show provider`` (active provider + whether it's configured)."""
    if readiness_now.provider_configured:
        state = "configured"
    else:
        state = f"not configured -- run {verbs.cmd('set provider', surface)}"
    return [render.plain(f"provider {readiness_now.provider} -- {state}")]


def present_show_model(readiness_now: Readiness) -> Styled:
    """Render ``show model`` (active model and its provider)."""
    return [
        render.plain(
            f"model {readiness_now.model} on provider {readiness_now.provider}"
        )
    ]


def present_findings_usage(surface: verbs.Surface) -> Styled:
    """Render the ``findings`` review usage + a pointer to the listing."""
    return [
        render.warning(
            f"usage: {verbs.cmd('findings <approve|reject|rescore>', surface)}"
        ),
        render.info(f"list findings with {verbs.cmd('show findings', surface)}"),
    ]


def present_unknown(verb: str, surface: verbs.Surface) -> Styled:
    """Render an unknown-command error, pointing at help (same on both surfaces)."""
    return [
        render.danger(f"unknown command: {verb!r} -- try {verbs.cmd('help', surface)}")
    ]
