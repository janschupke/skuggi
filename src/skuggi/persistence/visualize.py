"""Build a self-contained, interactive HTML dashboard for an engagement.

Where :mod:`skuggi.persistence.reports` is the outward-facing client artifact
(scope, findings, a command table -- deliberately no prompts, no audit) and
:mod:`skuggi.persistence.transcript` is a per-session text replay, this module is
the *operator's* whole-engagement picture. It reads everything the harness
recorded for one engagement -- across **all** its sessions -- and renders one
offline HTML file: a chronological trace of commands with their captured output,
per-command durations and the gaps between actions, findings/notes/loot
interleaved on that timeline, the agent conversation transcript and the
harness-interaction audit as their own panels, the diagnostic-log entries written
within the engagement's timeframe, the scope, the recognized tools and their
usage counts.

It crosses the client-facing boundary that ``reports`` enforces on purpose: this
is an internal review tool, never handed to a client.

The split mirrors ``reports``: :func:`collect_engagement` is a pure, I/O-free
transform from ledger rows (+ journals + the log text) to a JSON-serializable
view model, and :func:`render_html` injects that model into the packaged template
(``templates/visualize.html``). The vanilla-JS page reads the embedded JSON and
draws the timeline and charts client-side, so there is no templating or charting
dependency -- the file opens from ``file://`` with no network access, which is
what an air-gapped engagement needs.

Two things that are easy to get wrong and are handled here:

* **Durations and gaps are not stored.** Command rows carry only ``started_at``
  and ``finished_at`` (ISO-8601, UTC); both are parsed and subtracted here.
* **The diagnostic log is local-time and global.** Its ``asctime`` has no UTC
  converter (see :mod:`skuggi.common.logs`), so its lines are *local* time while
  every ledger timestamp is UTC; :func:`_log_entries` converts before comparing,
  and bounds the lines to the engagement window (the log is not tagged by
  engagement, so a time window is the best available filter).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from skuggi.common import palette
from skuggi.common.clock import file_stamp, now_iso
from skuggi.common.paths import ensure_dir, packaged_template
from skuggi.common.text import redact_secrets

if TYPE_CHECKING:
    from skuggi.engagement.engagement import EngagementConfig
    from skuggi.persistence.ledger import (
        AuditRow,
        CommandRow,
        EventRow,
        FindingRow,
        Ledger,
        SessionRow,
    )
    from skuggi.tooling.registry import ToolRegistry

_TEMPLATE_NAME = "visualize.html"
_DATA_SENTINEL = "__SKUGGI_DATA__"  # replaced in the template with the JSON blob

# A log line splits into three leading space-separated fields (date, time+ms,
# level); everything after is the ``<logger>: <message>`` tail.
_LOG_HEAD_FIELDS = 3


def _parse(ts: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp to an aware datetime, or ``None``."""
    if not ts:
        return None
    try:
        parsed = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _seconds(start: datetime | None, end: datetime | None) -> float | None:
    """Elapsed seconds between two instants, or ``None`` if either is missing."""
    if start is None or end is None:
        return None
    return round((end - start).total_seconds(), 3)


def _command_view(
    row: CommandRow, prev_end: datetime | None, registry: ToolRegistry
) -> dict[str, Any]:
    """One command as a timeline/trace entry, with derived duration and gap."""
    started = _parse(row.started_at)
    finished = _parse(row.finished_at)
    method = row.method or registry.method_for(row.binary)
    return {
        "type": "command",
        "id": row.id,
        "session_id": row.session_id,
        "ts": row.started_at,
        "finished_at": row.finished_at,
        "duration_s": _seconds(started, finished),
        "gap_before_s": _seconds(prev_end, started),
        "binary": row.binary,
        "method": method,
        "status": row.status,
        "exit_code": row.exit_code,
        "command": row.command,
        "stdout": row.stdout,
        "stderr": row.stderr,
        "reason": row.reason,
    }


def _finding_view(row: FindingRow) -> dict[str, Any]:
    """One finding as a timeline entry."""
    return {
        "type": "finding",
        "id": row.id,
        "session_id": row.session_id,
        "ts": row.created_at,
        "title": row.title,
        "severity": row.severity,
        "description": row.description,
        "evidence": row.evidence,
        "command_id": row.command_id,
    }


def _journal_views(kind: str, text: str) -> list[dict[str, Any]]:
    """Parse a notes/loot journal into timestamped timeline entries.

    ``journal.append_entry`` writes ``- `<iso>`  <text>`` lines; a line that does
    not match that shape is kept whole with no timestamp (it still shows, just
    unplaced on the timeline).
    """
    entries: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        ts: str | None = None
        body = line
        if line.startswith("- `") and "`" in line[3:]:
            close = line.index("`", 3)
            ts = line[3:close]
            body = line[close + 1 :].strip()
        entries.append({"type": kind, "ts": ts, "text": body})
    return entries


def _usage(commands: list[CommandRow], registry: ToolRegistry) -> list[dict[str, Any]]:
    """Per-binary usage counts, aggregated from the command rows.

    Counts are not stored anywhere, so they are derived here: one row per binary
    with its total and a breakdown by status, ordered most-used first.
    """
    agg: dict[str, dict[str, Any]] = {}
    for row in commands:
        entry = agg.setdefault(
            row.binary,
            {
                "binary": row.binary,
                "method": row.method or registry.method_for(row.binary),
                "count": 0,
                "executed": 0,
                "blocked": 0,
                "proposed": 0,
                "passthrough": 0,
                "failed": 0,
            },
        )
        entry["count"] += 1
        if row.status in entry:
            entry[str(row.status)] += 1
        if row.status == "executed" and row.exit_code not in (0, None):
            entry["failed"] += 1
    return sorted(agg.values(), key=lambda e: (-e["count"], e["binary"]))


def _log_entries(
    log_text: str, start: datetime | None, end: datetime | None
) -> list[dict[str, Any]]:
    """Diagnostic-log lines falling within ``[start, end]`` (inclusive).

    The log's ``asctime`` is *local* time with no UTC converter, so each stamp is
    read as local and converted before it is compared with the (UTC) window.
    Lines with no parseable stamp are continuations (tracebacks) and append to
    the entry above them. With no window (an engagement with no activity) nothing
    is returned rather than dumping the whole global log.
    """
    if start is None or end is None or not log_text:
        return []
    local_tz = datetime.now().astimezone().tzinfo
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in log_text.splitlines():
        parsed = _parse_log_line(line, local_tz)
        if parsed is None:  # continuation of the entry above
            if current is not None:
                current["message"] += "\n" + line
            continue
        when, level, logger, message = parsed
        current = {
            "ts": when.astimezone(UTC).isoformat(),
            "level": level,
            "logger": logger,
            "message": message,
            "_when": when,
        }
        if start <= when <= end:
            entries.append(current)
    for entry in entries:
        del entry["_when"]
    return entries


def _parse_log_line(
    line: str, local_tz: tzinfo | None
) -> tuple[datetime, str, str, str] | None:
    """Read ``(when, level, logger, message)`` from a log line, or ``None``.

    A log line is ``<date> <time>,<ms> <LEVEL> <logger>: <message>``; the time is
    parsed as *local* (the log has no UTC converter) and made aware with
    ``local_tz``. A line that does not start with a timestamp is a continuation
    (a traceback) and returns ``None`` so the caller folds it into the entry
    above.
    """
    head = line.split(" ", _LOG_HEAD_FIELDS)
    if len(head) < _LOG_HEAD_FIELDS:
        return None
    date_part, time_part, level = head[0], head[1], head[2]
    clock = time_part.split(",", 1)[0]
    try:
        naive = datetime.strptime(f"{date_part} {clock}", "%Y-%m-%d %H:%M:%S")  # noqa: DTZ007
    except ValueError:
        return None
    logger, _, message = (head[3] if len(head) > _LOG_HEAD_FIELDS else "").partition(
        ": "
    )
    return naive.replace(tzinfo=local_tz), level, logger, message


def _redact_model(obj: object, secrets: frozenset[str]) -> object:
    """Recursively mask secrets/auth headers in every string of the view model.

    Applied as a final pass so no embedded command output, transcript or log
    line carries a credential into the on-disk dashboard, wherever it sits in
    the structure.
    """
    if isinstance(obj, str):
        return redact_secrets(obj, secrets)
    if isinstance(obj, dict):
        return {key: _redact_model(value, secrets) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_redact_model(value, secrets) for value in obj]
    return obj


def collect_engagement(  # noqa: PLR0913 -- one keyword arg per already-read source
    ledger: Ledger,
    *,
    engagement: EngagementConfig | None,
    registry: ToolRegistry,
    notes_text: str = "",
    loot_text: str = "",
    log_text: str = "",
    secrets: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Build the JSON-serializable view model for the whole engagement.

    Pure: every argument is already-read data, and the result contains only JSON
    primitives, so it serializes directly and is trivial to unit-test. Commands,
    findings, events and audit are unioned across *all* sessions in the ledger;
    durations and gaps are derived from the ISO timestamps; the diagnostic log is
    bounded to the engagement's timeframe. A final pass redacts `secrets` and any
    ``Authorization``/``Bearer`` material from every embedded string.
    """
    sessions: list[SessionRow] = ledger.sessions()
    all_commands: list[CommandRow] = []
    conversation: list[dict[str, Any]] = []
    audit: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    instants: list[datetime] = []

    for session in sessions:
        all_commands.extend(ledger.commands_for(session.session_id))
        for ev in ledger.events_for(session.session_id):
            _absorb_event(ev, conversation, instants)
        for audit_row in ledger.audit_for(session.session_id):
            audit.append(_audit_view(audit_row))
            _push(instants, audit_row.created_at)
        for finding in ledger.findings_for(session.session_id):
            timeline.append(_finding_view(finding))
            _push(instants, finding.created_at)
        _push(instants, session.started_at)

    all_commands.sort(key=lambda c: c.started_at)
    prev_end: datetime | None = None
    for cmd in all_commands:
        timeline.append(_command_view(cmd, prev_end, registry))
        _push(instants, cmd.started_at)
        _push(instants, cmd.finished_at)
        prev_end = _parse(cmd.finished_at) or _parse(cmd.started_at) or prev_end

    notes = _journal_views("note", notes_text)
    loot = _journal_views("loot", loot_text)
    timeline.extend(notes)
    timeline.extend(loot)
    for item in (*notes, *loot):
        _push(instants, item["ts"])
    timeline.sort(key=lambda e: (e.get("ts") is None, e.get("ts") or ""))

    window_start = min(instants) if instants else None
    window_end = max(instants) if instants else None

    model: dict[str, Any] = {
        "generated": now_iso(),
        "brand": f"{palette.SHIELD} skuggi",
        "engagement": engagement.model_dump(mode="json") if engagement else None,
        "scope_describe": engagement.describe() if engagement else "",
        "window": {
            "start": window_start.isoformat() if window_start else None,
            "end": window_end.isoformat() if window_end else None,
        },
        "sessions": [
            {
                "session_id": s.session_id,
                "mode": s.mode,
                "started_at": s.started_at,
                "engagement_name": s.engagement_name,
            }
            for s in sessions
        ],
        "timeline": timeline,
        "conversation": conversation,
        "audit": audit,
        "log_entries": _log_entries(log_text, window_start, window_end),
        "tools": {
            "registry": [
                {"name": t.name, "binary": t.binary, "method": t.method}
                for t in registry.tools
            ],
            "usage": _usage(all_commands, registry),
        },
        "notes_raw": notes_text,
        "loot_raw": loot_text,
        "palette": {
            "severity": {s: palette.severity_hex(s) for s in palette.severities()},
            "method": {m: palette.method_hex(m) for m in palette.methods()},
            "severity_order": list(palette.severities()),
            "method_order": list(palette.methods()),
        },
        "counts": {
            "sessions": len(sessions),
            "commands": len(all_commands),
            "findings": sum(1 for e in timeline if e["type"] == "finding"),
            "notes": len(notes),
            "loot": len(loot),
        },
    }
    return cast("dict[str, Any]", _redact_model(model, secrets))


def _absorb_event(
    ev: EventRow, conversation: list[dict[str, Any]], instants: list[datetime]
) -> None:
    """Add a prompt/response event to the conversation; ignore command/finding."""
    if ev.kind in ("prompt", "response"):
        conversation.append(
            {
                "session_id": ev.session_id,
                "kind": ev.kind,
                "ts": ev.created_at,
                "text": ev.text,
            }
        )
    _push(instants, ev.created_at)


def _audit_view(row: AuditRow) -> dict[str, Any]:
    """One harness-interaction audit record."""
    return {
        "session_id": row.session_id,
        "kind": row.kind,
        "verb": row.verb,
        "detail": row.detail,
        "ts": row.created_at,
    }


def _push(instants: list[datetime], ts: str | None) -> None:
    """Record a timestamp for the engagement-window computation, if parseable."""
    parsed = _parse(ts)
    if parsed is not None:
        instants.append(parsed)


def render_html(view_model: dict[str, Any]) -> str:
    r"""Inject the view model into the packaged template as embedded JSON.

    ``<``, ``>`` and ``&`` are escaped to their ``\uXXXX`` JSON forms so
    arbitrary command output containing ``</script>`` cannot break out of the
    embedding ``<script>`` tag. This is a *backstop*: the template's DOM builder
    never assigns engagement data via ``innerHTML`` (it uses ``textContent``),
    which is the primary defense; a future edit that reintroduced ``innerHTML``
    would still not execute script smuggled through this blob.
    """
    blob = (
        json.dumps(view_model, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    template = packaged_template(_TEMPLATE_NAME).read_text(encoding="utf-8")
    return template.replace(_DATA_SENTINEL, blob)


def _slug(text: str) -> str:
    """A filesystem-safe slug for the output filename (mirrors ``reports``)."""
    return (
        "".join(c if c.isalnum() or c in "-_" else "-" for c in text).strip("-")
        or "engagement"
    )


def write_visualization(  # noqa: PLR0913 -- keyword-only data sources, like collect
    ledger: Ledger,
    out_dir: Path,
    *,
    engagement: EngagementConfig | None,
    registry: ToolRegistry,
    notes_text: str = "",
    loot_text: str = "",
    log_text: str = "",
    engagement_name: str | None = None,
    secrets: frozenset[str] = frozenset(),
) -> Path:
    """Render the engagement dashboard and write a timestamped ``.html`` file.

    The file lands in ``out_dir`` (the engagement's ``reports`` dir) named for the
    engagement and the moment it was generated. Returns the written path.
    """
    view_model = collect_engagement(
        ledger,
        engagement=engagement,
        registry=registry,
        notes_text=notes_text,
        loot_text=loot_text,
        log_text=log_text,
        secrets=secrets,
    )
    name = engagement_name or (engagement.name if engagement else None)
    if not name:
        sessions = view_model["sessions"]
        name = sessions[0]["engagement_name"] if sessions else "engagement"
    html = render_html(view_model)
    out_dir = ensure_dir(out_dir)
    stamp = file_stamp()
    path = out_dir / f"{_slug(name)}-{stamp}.html"
    path.write_text(html, encoding="utf-8")
    return path


def visualization_written_lines(path: Path) -> list[str]:
    """Describe what :func:`write_visualization` produced, for either front-end."""
    return [f"visualization written: {path}"]


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``skuggi-visualize`` -- read-only, no agent/LLM.

    Resolves a *named* engagement under ``engagements_dir`` (the setting, honoured
    via ``SKUGGI_ENGAGEMENTS_DIR``, overridable with ``--engagements-dir``), reads
    its ledger, scope, journals and the diagnostic log, and writes the dashboard.
    """
    import argparse

    from skuggi.common.logs import default_log_path, setup_logging
    from skuggi.config.config import Settings
    from skuggi.config.configs import (
        ConfigError,
        load_layout,
        load_registry,
        load_scope,
    )
    from skuggi.engagement.journal import read_entries
    from skuggi.engagement.workspace import Workspace
    from skuggi.persistence.ledger import open_ledger
    from skuggi.tooling.registry import ToolRegistry

    setup_logging()
    parser = argparse.ArgumentParser(
        prog="skuggi-visualize",
        description="Build an interactive HTML dashboard for an engagement.",
    )
    parser.add_argument("engagement", help="the engagement name under engagements/")
    parser.add_argument(
        "--engagements-dir",
        type=Path,
        help="root of the engagement workspaces (default: the SKUGGI setting)",
    )
    parser.add_argument(
        "-o", "--out", type=Path, help="output directory (default: the reports dir)"
    )
    args = parser.parse_args(argv)

    settings = Settings()
    engagements_dir = args.engagements_dir or settings.engagements_dir
    try:
        layout = load_layout(settings.layout_path)
    except ConfigError:
        layout = None
    workspace = Workspace.for_engagement(
        engagements_dir, args.engagement, layout=layout
    )
    if not workspace.root.is_dir():
        print(f"no such engagement: {workspace.root}")
        return 2

    try:
        scope = (
            load_scope(workspace.scope_path) if workspace.scope_path.is_file() else None
        )
    except ConfigError:
        scope = None
    try:
        registry = load_registry(settings.registry_path)
    except ConfigError:
        registry = ToolRegistry()

    log_path = default_log_path()
    log_text = (
        log_path.read_text(encoding="utf-8", errors="replace")
        if log_path.is_file()
        else ""
    )
    out_dir = args.out or workspace.reports_dir
    secrets = frozenset(
        key.get_secret_value()
        for key in (settings.openai_api_key, settings.anthropic_api_key)
        if key is not None
    )
    with open_ledger(workspace.ledger_path) as ledger:
        path = write_visualization(
            ledger,
            out_dir,
            engagement=scope,
            registry=registry,
            notes_text=read_entries(workspace.notes_file),
            loot_text=read_entries(workspace.loot_file),
            log_text=log_text,
            engagement_name=args.engagement,
            secrets=secrets,
        )
    print(f"visualization written: {path}")
    return 0
