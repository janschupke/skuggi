"""The engagement record and its outputs (``core.journal``).

A sub-component of :class:`~skuggi.agent.core.AgentCore` covering the operator's
engagement record: ledger findings, the structured notes/loot records, the
client-facing Markdown/PDF report and the internal HTML dashboard. It reads the
live ledger, workspace, engagement and registry off the core each call (the ledger
is hot-swapped by ``adopt_engagement``), so nothing is cached. Notes and loot are
structured, redacted ledger records (recalled into the agent's context by nature,
never value); the dashboard still consumes them as journal text, rendered from the
rows by ``notes_to_text``/``loot_to_text``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, get_args

from skuggi.agent.protocol import Severity
from skuggi.common import logs
from skuggi.frameworks import cvss
from skuggi.persistence import reports, visualize
from skuggi.persistence.visualize_model import loot_to_text, notes_to_text
from skuggi.security.redaction import redact

if TYPE_CHECKING:
    from pathlib import Path

    from skuggi.agent.core import AgentCore
    from skuggi.persistence.ledger import (
        CredentialRow,
        FindingRow,
        FootholdRow,
        LootRow,
        NoteRow,
    )


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

    def add_note(
        self, *, subject: str, text: str, host: str = "", source: str = "operator"
    ) -> int | None:
        """Record a structured note; the body is redacted before storage.

        Returns the note id, or ``None`` with no engagement. Any secret in ``text``
        is vaulted to a ``«KIND:id»`` placeholder first, so plaintext never reaches
        the ledger or a recall brief.
        """
        core = self._core
        if core.workspace is None:
            return None
        body = redact(text, core.redaction_policy(), core.vault)
        return core.ledger.record_note(
            session_id=core.session_id,
            subject=subject,
            host=host,
            text=body,
            source=source,
        )

    def note_items(self) -> list[NoteRow]:
        """The engagement's notes (every session), for show/dashboard/recall."""
        core = self._core
        if core.engagement is not None:
            return core.ledger.notes_for_engagement(core.engagement.name)
        return core.ledger.notes_for(core.session_id)

    def notes(self) -> str:
        """The notes journal rendered as timestamped bullets (dashboard input)."""
        return notes_to_text(self.note_items())

    def add_loot(
        self, *, kind: str, host: str, label: str, source: str = "operator"
    ) -> int | None:
        """Record a structured loot item; the label is redacted before storage.

        Returns the loot id, or ``None`` with no engagement. A secret in ``label``
        is vaulted to a placeholder first -- loot never lands as plaintext on disk,
        in a brief or in the model's context.
        """
        core = self._core
        if core.workspace is None:
            return None
        clean_label = redact(label, core.redaction_policy(), core.vault)
        return core.ledger.record_loot(
            session_id=core.session_id,
            kind=kind,
            host=host,
            label=clean_label,
            source=source,
        )

    def loot_items(self) -> list[LootRow]:
        """The engagement's loot (every session), for show/dashboard/recall."""
        core = self._core
        if core.engagement is not None:
            return core.ledger.loot_for_engagement(core.engagement.name)
        return core.ledger.loot_for(core.session_id)

    def loot(self) -> str:
        """The loot journal rendered as timestamped bullets (dashboard input)."""
        return loot_to_text(self.loot_items())

    def add_credential(  # noqa: PLR0913 -- a credential is several named fields
        self,
        *,
        host: str = "",
        service: str = "",
        username: str = "",
        secret: str = "",
        source: str = "operator",
        validated: bool = False,
    ) -> int | None:
        """Store a captured credential: secret in the vault, row in the ledger (E8/E9).

        Returns the credential id, or ``None`` when there is no engagement vault to
        hold the secret. The secret is interned as a ``«CRED:id»`` placeholder so a
        command the worker runs rehydrates it at exec, and the plaintext never lands
        in the ledger, a brief or the model's context.
        """
        core = self._core
        if core.vault is None:
            return None
        secret_ref = core.vault.intern(secret, "CRED", source=source) if secret else ""
        return core.ledger.record_credential(
            session_id=core.session_id,
            host=host,
            service=service,
            username=username,
            secret_ref=secret_ref,
            source=source,
            validated=validated,
        )

    def credentials(self) -> list[CredentialRow]:
        """The captured credentials for this session (E8/E9)."""
        return self._core.ledger.credentials_for(self._core.session_id)

    def add_foothold(
        self,
        *,
        host: str,
        transport: str = "command",
        template: str = "",
        reachable: str = "",
    ) -> int | None:
        """Register a pivot foothold for this session; return its id (pivot/P3).

        ``reachable`` is a comma-separated mix of CIDRs and hostnames the foothold
        can reach, split here into the two ledger columns the router reads. Any
        secret belongs in ``template`` as a ``«CRED:id»`` vault placeholder (from a
        prior ``add cred``), rehydrated at exec by the executor -- never plaintext.
        Returns ``None`` when no engagement is loaded (nothing to pivot within).
        """
        core = self._core
        if core.engagement is None:
            return None
        networks, hosts = _split_reachable(reachable)
        return core.ledger.record_foothold(
            session_id=core.session_id,
            host=host,
            transport=transport,
            template=template,
            reachable_networks=networks,
            reachable_hosts=hosts,
        )

    def footholds(self) -> list[FootholdRow]:
        """The registered pivot footholds for this session (pivot/P3)."""
        return self._core.ledger.footholds_for(self._core.session_id)

    def clear_footholds(self) -> int:
        """Drop every registered foothold for this session; return how many."""
        return self._core.ledger.clear_footholds(self._core.session_id)

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


def _split_reachable(reachable: str) -> tuple[str, str]:
    """Split a comma-separated reach list into (networks_csv, hosts_csv) (pivot/P3).

    A token that parses as an IP network goes to the networks column; anything else
    is treated as a hostname. Order within each column is preserved.
    """
    import ipaddress  # noqa: PLC0415 -- local to this small helper

    networks: list[str] = []
    hosts: list[str] = []
    for token in (part.strip() for part in reachable.split(",")):
        if not token:
            continue
        try:
            ipaddress.ip_network(token, strict=False)
        except ValueError:
            hosts.append(token)
        else:
            networks.append(token)
    return ",".join(networks), ",".join(hosts)
