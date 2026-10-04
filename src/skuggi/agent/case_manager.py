"""The forensics case plane: a read-only case workspace + its SEPARATE ledger.

The forensics analogue of ``EngagementManager``, but far smaller because a case
authorizes nothing: there is no scope, no vault of engagement secrets, no
autonomous arming, no threat model. A ``CaseManager`` owns exactly two things for
one forensics session -- the case ``Workspace`` (evidence input + forensics/reports
output) and a ledger opened at the case's own ``case.db`` under a fresh
``mode="forensics"`` session. Kept a distinct file so forensic evidence, the
chain-of-custody procedure log and severity-only findings never commingle with an
offensive engagement's CVSS findings (the "multiple modes, no conflicts" rule).

Lazily created by ``AgentCore`` when a case is adopted; torn down with ``close``.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from skuggi.common.logs import get_logger
from skuggi.engagement.case import CaseConfig, load_case
from skuggi.engagement.workspace import Workspace
from skuggi.persistence import ledger as ledger_mod
from skuggi.security.policy import RedactionPolicy

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

log = get_logger(__name__)


class CaseManager:
    """Owns the case workspace and its separate ledger for one forensics session."""

    def __init__(self, core: AgentCore, root: Path, case: CaseConfig) -> None:
        self._core = core
        self.root = root.expanduser()
        self.case = case
        self.workspace = Workspace.at(self.root, layout=core.layout)
        self.workspace.ensure_case()
        self._ledger_ctx = ledger_mod.open_ledger(self.workspace.case_ledger_path)
        self.ledger = self._ledger_ctx.__enter__()
        # A case keeps its OWN session id, distinct from the engagement session on
        # AgentCore: forensic records live in the case ledger under this session.
        self.session_id = str(uuid.uuid4())
        self.ledger.start_session(
            self.session_id,
            engagement_name=f"case:{case.name}",
            mode="forensics",
        )

    @classmethod
    def open(cls, core: AgentCore, root: Path) -> CaseManager:
        """Open the case rooted at `root` (must hold a ``case.json``).

        Raises ``ConfigError`` (via ``load_case``) when the metadata is missing or
        invalid -- the caller surfaces that as a re-ask.
        """
        resolved = root.expanduser()
        case = load_case(Workspace.at(resolved, layout=core.layout).case_path)
        return cls(core, resolved, case)

    def redaction_policy(self) -> RedactionPolicy:
        """A default redaction policy: a case has no scope, so nothing is allow-listed.

        Evidence is local and untrusted, so every detector-flagged secret is
        scrubbed from anything that reaches the model or a report.
        """
        return RedactionPolicy()

    @property
    def forensics_dir(self) -> Path:
        """Where the forensics loop writes its case report + JSON artifacts."""
        return self.workspace.forensics_dir

    @property
    def reports_dir(self) -> Path:
        """Where the case report is written."""
        return self.workspace.reports_dir

    def describe(self) -> str:
        """The case summary for ``show case`` / the report header."""
        return self.case.describe()

    def close(self) -> None:
        """Close the case ledger (mirrors how it was opened)."""
        self._ledger_ctx.__exit__(None, None, None)
