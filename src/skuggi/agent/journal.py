"""The engagement record and its outputs (``core.journal``).

A sub-component of :class:`~skuggi.agent.core.AgentCore` covering the operator's
engagement record: ledger findings, the notes/loot journals, the client-facing
Markdown/PDF report and the internal HTML dashboard. It reads the live ledger,
workspace, engagement and registry off the core each call (the ledger is
hot-swapped by ``load_engagement``), so nothing is cached. The notes/loot file
I/O lives in :mod:`skuggi.engagement.journal`, imported here as ``journal_io``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, get_args

from skuggi.agent.protocol import Severity
from skuggi.common import logs
from skuggi.engagement import journal as journal_io
from skuggi.persistence import reports, visualize

if TYPE_CHECKING:
    from pathlib import Path

    from skuggi.agent.core import AgentCore
    from skuggi.persistence.ledger import FindingRow


class Journal:
    """The engagement's findings, notes/loot journals, report and dashboard."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core

    def findings(self) -> list[FindingRow]:
        """Findings recorded this session."""
        return self._core.ledger.findings_for(self._core.session_id)

    def record_finding(self, severity: str, title: str) -> FindingRow | None:
        """Record an operator finding in the ledger, or ``None`` on a bad severity.

        The same writer the worker uses, so hand-entered and agent-found findings
        share one store -- the ``findings`` listing and the report's severity
        section. ``description`` defaults to the title (the one-line operator
        grammar); evidence is left for the agent or a later edit.
        """
        sev = severity.strip().lower()
        if sev not in get_args(Severity):
            return None
        core = self._core
        fid = core.ledger.record_finding(
            session_id=core.session_id,
            title=title.strip(),
            severity=sev,
            description=title.strip(),
        )
        return core.ledger.finding(fid)

    def add_note(self, text: str) -> Path | None:
        """Append a timestamped note to the journal (``None`` with no engagement)."""
        ws = self._core.workspace
        if ws is None:
            return None
        journal_io.append_entry(ws.notes_file, text)
        return ws.notes_file

    def notes(self) -> str:
        """The engagement's notes journal (``""`` when none / no engagement)."""
        ws = self._core.workspace
        if ws is None:
            return ""
        return journal_io.read_entries(ws.notes_file)

    def add_loot(self, text: str) -> Path | None:
        """Append a timestamped loot entry to the journal (``None`` if unscoped)."""
        ws = self._core.workspace
        if ws is None:
            return None
        journal_io.append_entry(ws.loot_file, text)
        return ws.loot_file

    def loot(self) -> str:
        """The engagement's loot journal (``""`` when none / no engagement)."""
        ws = self._core.workspace
        if ws is None:
            return ""
        return journal_io.read_entries(ws.loot_file)

    def write_report(self, *, pdf: bool = False) -> Path | tuple[Path, Path]:
        """Write the session's Markdown report and return its path.

        With ``pdf=True`` a styled PDF is written alongside the canonical
        Markdown and both paths are returned.
        """
        core = self._core
        return reports.write_report(
            core.session_id,
            core.ledger,
            core.reports_dir,
            engagement=core.engagement,
            pdf=pdf,
        )

    def write_visualization(self) -> Path:
        """Write the engagement's interactive HTML dashboard and return its path.

        An internal operator artifact (unlike ``write_report``): it spans every
        session in the ledger and pulls in the notes/loot journals, the agent
        transcript, the audit log and the diagnostic log bounded to the
        engagement's timeframe.
        """
        core = self._core
        log_path = logs.default_log_path()
        log_text = (
            log_path.read_text(encoding="utf-8", errors="replace")
            if log_path.is_file()
            else ""
        )
        return visualize.write_visualization(
            core.ledger,
            core.reports_dir,
            engagement=core.engagement,
            registry=core.registry,
            notes_text=self.notes(),
            loot_text=self.loot(),
            log_text=log_text,
            engagement_name=core.engagement.name if core.engagement else None,
        )
