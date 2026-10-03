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
from skuggi.frameworks import cvss
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

    def record_finding(
        self,
        severity: str | None = None,
        title: str = "",
        *,
        cvss_vector: str | None = None,
    ) -> FindingRow | None:
        """Record an operator finding in the ledger, or ``None`` on invalid input.

        The same writer the worker uses, so hand-entered and agent-found findings
        share one store. Pass a ``cvss_vector`` to score it deterministically (the
        band is derived); otherwise pass a ``severity``. ``description`` defaults to
        the title; evidence is left for the agent or a later edit.
        """
        core = self._core
        clean_title = title.strip()
        if cvss_vector:
            try:
                cvss.parse(cvss_vector)
            except cvss.CvssError:
                return None
            fid = core.ledger.record_finding(
                session_id=core.session_id,
                title=clean_title,
                description=clean_title,
                cvss_vector=cvss_vector,
                author="operator",
            )
            return core.ledger.finding(fid)
        sev = (severity or "").strip().lower()
        if sev not in get_args(Severity):
            return None
        fid = core.ledger.record_finding(
            session_id=core.session_id,
            title=clean_title,
            severity=sev,
            description=clean_title,
            author="operator",
        )
        return core.ledger.finding(fid)

    def set_status(
        self, finding_id: int, status: str, *, reason: str = ""
    ) -> FindingRow | None:
        """Approve/reject/reset a finding by id, returning the updated row or None.

        Returns ``None`` when the id is not a finding in this session, so a front
        end can report a bad id rather than silently succeeding.
        """
        core = self._core
        row = core.ledger.finding(finding_id)
        if row is None or row.session_id != core.session_id:
            return None
        core.ledger.set_finding_status(finding_id, status, reason=reason)
        return core.ledger.finding(finding_id)

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
