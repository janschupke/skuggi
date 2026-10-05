"""Rendering for the journal / engagement-artifact verbs: outcome -> styled lines.

Split from :mod:`skuggi.frontend.presenters` (which sat near the file-size cap):
the report, visualize and ingest presenters, and -- as they are centralized -- the
findings/replay presenters that build on the shared ``finding_line``. Same contract
as the parent module: each ``present_*`` maps a typed outcome from
:mod:`skuggi.frontend.outcomes` to a ``render.Styled`` phrased for a
``verbs.Surface``, so the REPL and the daemon render these verbs identically.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skuggi.common import palette
from skuggi.frontend import presenters, render, verbs
from skuggi.frontend.outcomes import (
    AddedCredential,
    AddedFoothold,
    AddedLoot,
    AddedNote,
    AddOutcome,
    AddUsage,
    BadSeverity,
    FindingRecorded,
    Indexed,
    IngestOutcome,
    IngestUsage,
    NoEngagement,
    ReplayEmpty,
    ReplayList,
    ReportNoteAdded,
    ReportNoteUsage,
    ReportOutcome,
    ReportWritten,
    VisualizeWritten,
)
from skuggi.frontend.render import Styled

if TYPE_CHECKING:
    from collections.abc import Sequence

    from skuggi.persistence.ledger import (
        CoverageRow,
        CredentialRow,
        FindingRow,
        FootholdRow,
    )


def present_report(outcome: ReportOutcome, surface: verbs.Surface) -> Styled:
    """Render a ``report`` outcome identically on both surfaces."""
    match outcome:
        case ReportNoteUsage():
            return presenters.usage("report note <text>", surface)
        case ReportNoteAdded(path):
            return [render.success(f"changelog: {path}")]
        case ReportWritten(lines):
            return [render.success(line) for line in lines]


def present_visualize(outcome: VisualizeWritten) -> Styled:
    """Render a ``visualize`` outcome: the written-file lines."""
    return [render.success(line) for line in outcome.lines]


def present_ingest(outcome: IngestOutcome, surface: verbs.Surface) -> Styled:
    """Render an ``ingest`` outcome: usage, or the indexed-chunk count."""
    match outcome:
        case IngestUsage():
            return presenters.usage("ingest <path>", surface)
        case Indexed(count):
            return [render.info(f"indexed {count} chunk(s)")]


def _finding_parts(row: FindingRow, *, outdated: bool = False) -> tuple[str, str]:
    """``(severity token, the rest of the line)`` for a finding summary.

    Split so the severity can be painted its own colour in a ``render.spans`` line
    (on both surfaces) while the remainder stays unpainted; the plain concatenation
    is ``SEV [id] title — author/status (cmd:N)``.
    """
    link = f" (cmd:{row.command_id})" if row.command_id is not None else ""
    stale = " ⚠ outdated" if outdated else ""
    rest = f" [{row.id}] {row.title} — {row.author}/{row.status}{stale}{link}"
    return row.severity.upper(), rest


def _finding_span(row: FindingRow, *, outdated: bool = False) -> render.Line:
    """One finding as a spans line: severity painted its colour, the rest plain."""
    sev, rest = _finding_parts(row, outdated=outdated)
    return render.spans([(sev, palette.severity_style(row.severity)), (rest, None)])


def present_findings_list(
    rows: Sequence[FindingRow], current_version: int | None
) -> Styled:
    """Render ``show findings``: one severity-painted line per finding.

    A finding whose CVSS score predates `current_version` (the engagement's current
    threat-model version) is flagged ``⚠ outdated``. Painting rides ``render.spans``
    so the severity token is coloured on the REPL *and* the shell daemon, where it
    was previously plain.
    """
    if not rows:
        return presenters.empty("findings")
    return [
        _finding_span(
            f,
            outdated=f.cvss_tm_version is not None
            and f.cvss_tm_version != current_version,
        )
        for f in rows
    ]


def present_credentials(rows: Sequence[CredentialRow]) -> Styled:
    """Render ``show creds``: one line per credential, the secret masked (E8/E9).

    The stored ``secret_ref`` is a vault placeholder, so even this listing never
    shows a plaintext secret -- only whether one is held, and whether it validated.
    """
    if not rows:
        return presenters.empty("creds")
    lines: Styled = []
    for c in rows:
        who = f"{c.username}@{c.host}" if c.host else (c.username or "?")
        svc = f" [{c.service}]" if c.service else ""
        mark = "✓" if c.validated else "·"
        held = "secret held" if c.secret_ref else "no secret"
        lines.append(render.info(f"{mark} {who}{svc} — {held} ({c.source or '?'})"))
    return lines


def present_footholds(rows: Sequence[FootholdRow]) -> Styled:
    """Render ``show footholds``: one line per foothold; secrets stay masked (pivot).

    The template may embed a ``«CRED:id»`` vault placeholder, never a plaintext
    secret, so this listing is safe to show -- it reports the host, transport, what
    the foothold reaches, and the (placeholder-form) template.
    """
    if not rows:
        return presenters.empty("footholds")
    lines: Styled = []
    for f in rows:
        reach = ", ".join(p for p in (f.reachable_networks, f.reachable_hosts) if p)
        lines.append(
            render.info(f"{f.host} [{f.transport}] → {reach or '—'}  ::  {f.template}")
        )
    return lines


def present_coverage(rows: Sequence[CoverageRow], enabled: tuple[str, ...]) -> Styled:
    """Render ``show coverage``: exercised methodology ids vs the enabled taxonomy (E7).

    Each framework's exercised ids are listed; an enabled taxonomy that produced no
    exercised id yet is called out as a gap, so the operator sees what the run has
    and has not touched.
    """
    exercised: dict[str, list[str]] = {}
    for r in rows:
        exercised.setdefault(r.framework, []).append(r.ref_id)
    lines: Styled = []
    for fw in sorted(exercised):
        ids = ", ".join(sorted(exercised[fw]))
        lines.append(render.info(f"{fw}: {len(exercised[fw])} exercised — {ids}"))
    for tax in sorted(t for t in enabled if t not in exercised):
        lines.append(render.info(f"{tax}: none exercised yet"))
    if not lines:
        return presenters.empty("coverage")
    return lines


def present_replay_list(outcome: ReplayEmpty | ReplayList) -> Styled:
    """Render the ``replay list`` listing: the empty state, or one row per session.

    The reconstructed transcript (``ReplayTranscript``) is NOT handled here -- its
    body is structural (Markdown in the REPL, plain text over the socket), so each
    front-end renders that case itself. The session id is painted via
    ``render.spans`` so the listing is coloured on both surfaces (the daemon's was
    previously plain) and the two drifting row formats collapse to one.
    """
    if isinstance(outcome, ReplayEmpty):
        return [render.info("(no sessions)")]
    lines: Styled = []
    for s in outcome.rows:
        mark = " *" if s.session_id == outcome.current_id else ""
        lines.append(
            render.spans(
                [
                    (s.session_id[:8], "cyan"),
                    (f"  {s.started_at}  {s.mode}{mark}", None),
                ]
            )
        )
    return lines


def present_finding_recorded(row: FindingRow) -> Styled:
    """Render a just-recorded finding: ``recorded`` + the painted finding line."""
    sev, rest = _finding_parts(row)
    return [
        render.spans(
            [
                ("recorded ", palette.SUCCESS),
                (sev, palette.severity_style(row.severity)),
                (rest, None),
            ]
        )
    ]


def present_add(outcome: AddOutcome, surface: verbs.Surface) -> Styled:  # noqa: PLR0911 -- one case per add outcome
    """Render note/loot/usage add outcomes.

    A recorded FINDING is NOT handled here (its severity is painted by
    ``presenters_journal.present_finding_recorded``); the shared ``add`` action
    branches on ``FindingRecorded`` before calling this.
    """
    match outcome:
        case AddUsage(form):
            return presenters.usage(f"add {form}", surface)
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
        case AddedCredential(host, username):
            who = f"{username}@{host}" if host else username
            return [render.success(f"credential stored for {who} (secret vaulted)")]
        case AddedFoothold(host):
            return [render.success(f"foothold registered on {host}")]
        case FindingRecorded():  # pragma: no cover -- caller renders findings
            return []
