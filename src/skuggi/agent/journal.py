"""The engagement record and its outputs (``core.journal``).

A sub-component of :class:`~skuggi.agent.core.AgentCore` covering the operator's
engagement record: ledger findings, the notes/loot journals, the client-facing
Markdown/PDF report and the internal HTML dashboard. It reads the live ledger,
workspace, engagement and registry off the core each call (the ledger is
hot-swapped by ``adopt_engagement``), so nothing is cached. The notes/loot file
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
            env_metrics, tm_version = self._scoring_context()
            fid = core.ledger.record_finding(
                session_id=core.session_id,
                title=clean_title,
                description=clean_title,
                cvss_vector=cvss_vector,
                env_metrics=env_metrics,
                tm_version=tm_version,
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

    def _scoring_context(self) -> tuple[dict[str, str], int | None]:
        """The engagement's env metrics + current threat-model version for scoring."""
        core = self._core
        tm = core.engagement.threat_model if core.engagement else None
        env_metrics = tm.cvss_environmental_metrics() if tm else {}
        return env_metrics, core.ledger.current_threat_model_version() or None

    def rescore(self, finding_id: int | None = None) -> int:
        """Rescore one finding (or every outdated one) to the current threat model.

        Returns how many findings were rescored. With ``finding_id=None`` it rescopes
        exactly the findings whose stored score predates the current version.
        """
        core = self._core
        env_metrics, tm_version = self._scoring_context()
        current = core.ledger.current_threat_model_version()
        if finding_id is not None:
            return int(core.ledger.rescore_finding(finding_id, env_metrics, tm_version))
        count = 0
        for row in core.ledger.findings_for(core.session_id):
            if row.cvss_tm_version is not None and row.cvss_tm_version != current:
                count += int(
                    core.ledger.rescore_finding(row.id, env_metrics, tm_version)
                )
        return count

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
        ws = core.workspace
        return reports.write_report(
            core.session_id,
            core.ledger,
            core.reports_dir,
            engagement=core.engagement,
            media_root=ws.root if ws is not None else None,
            pdf=pdf,
        )

    def write_engagement_report(self, *, pdf: bool = False) -> Path | tuple[Path, Path]:
        """Write the cross-session engagement report; return its path(s) (E5).

        Aggregates every session's approved findings for the loaded engagement into
        one deduplicated client deliverable.
        """
        core = self._core
        ws = core.workspace
        name = core.engagement.name if core.engagement else core.session_id
        return reports.write_engagement_report(
            name,
            core.ledger,
            core.reports_dir,
            engagement=core.engagement,
            media_root=ws.root if ws is not None else None,
            pdf=pdf,
        )

    def add_report_note(self, text: str) -> Path:
        """Append a timestamped note to the report changelog; return its path."""
        return reports.append_changelog(self._core.reports_dir, text)

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
            current_target=core.effective_target(),
        )
