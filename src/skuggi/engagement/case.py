"""A forensics *case*: the engagement-free context forensics mode operates in.

An engagement authorizes action against a target; a case authorizes *nothing* --
it is a strictly read-only examination of local evidence, so it carries no scope,
no allowed hosts, no autonomous ceiling. A case *is* a directory (the forensics
analogue of an engagement root) holding ``case.json`` (this metadata), its own
SEPARATE ledger ``case.db`` (never commingled with an offensive engagement's
findings), an ``evidence/`` input dir and the ``forensics/``/``reports/`` outputs.

This module is the pure config half (model + probe + scaffold write), mirroring
``config.configs.load_scope``; the live lifecycle (opening the ledger, starting a
session, hot-adopting) lives in ``skuggi.agent.case_manager``.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from skuggi.common.clock import now_iso
from skuggi.config.configs import ConfigError
from skuggi.engagement.workspace import WorkspaceLayout


class CaseConfig(BaseModel):
    """A forensics case's metadata -- never an authorization boundary.

    ``name`` labels the ledger/session/report (like an engagement's name). The rest
    is provenance for the case report's header: who is examining, and free-text
    notes on where the evidence came from (a disk image, a handed-over folder).
    """

    model_config = ConfigDict(frozen=True)

    name: str
    description: str = ""
    examiner: str = ""
    evidence_sources: tuple[str, ...] = ()
    created_at: str = ""

    def describe(self) -> str:
        """A one-paragraph summary for ``show case`` / the report header."""
        parts = [f"case: {self.name}"]
        if self.examiner:
            parts.append(f"examiner: {self.examiner}")
        if self.description:
            parts.append(self.description)
        if self.evidence_sources:
            parts.append(f"evidence sources: {', '.join(self.evidence_sources)}")
        return " · ".join(parts)


def has_case(root: Path, layout: WorkspaceLayout | None = None) -> bool:
    """Whether `root` is a forensics case directory (holds a ``case.json``).

    The probe behind cwd discovery and the explicit-override check; a missing
    `root`, or a folder without ``case.json``, yields ``False``.
    """
    resolved = layout or WorkspaceLayout()
    return (root.expanduser() / resolved.case_file).is_file()


def load_case(path: Path) -> CaseConfig:
    """Load and validate one case's metadata (``case.json``) from JSON."""
    try:
        return CaseConfig.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        msg = f"invalid case config at {path}: {exc}"
        raise ConfigError(msg) from exc


def build_case(raw: dict[str, object]) -> CaseConfig:
    """Validate a case dict into a ``CaseConfig``, stamping ``created_at`` if unset.

    Raises ``ConfigError`` (so the wizard/front-end re-asks) on a validation error.
    """
    seeded = dict(raw)
    seeded.setdefault("created_at", now_iso())
    try:
        return CaseConfig.model_validate(seeded)
    except ValidationError as exc:
        msg = f"invalid case: {exc}"
        raise ConfigError(msg) from exc
