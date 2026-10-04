"""The forensics graph's dependency bundle (its own value object).

Distinct from the OSINT/research deps: forensics carries the case plane it records
into -- the case ``Workspace`` (evidence input + confinement), the case ledger (the
chain-of-custody + findings), and the session id -- plus the model, the provider
name (to gate AI vision), the artifact output root, and the toggles for the
optional OCR/vision capabilities. No scope object: the forensics boundary is the
built-in read-only analyzer battery, not an operator-editable scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from langchain_core.language_models import BaseChatModel

from skuggi.engagement.workspace import Workspace
from skuggi.forensics.prompts import ForensicsPromptSet, forensics_prompt_set
from skuggi.persistence.ledger import Ledger
from skuggi.security.policy import RedactionPolicy


@dataclass(frozen=True, slots=True)
class ForensicsDeps:
    """Everything ``build_forensics_graph`` needs, bundled for a small signature."""

    llm: BaseChatModel | None = None
    native_structured: bool = True
    redaction_policy: RedactionPolicy | None = None
    workspace: Workspace | None = None
    ledger: Ledger | None = None
    session_id: str = ""
    case_name: str = ""
    provider: str = ""
    output_root: Path | None = None
    vision: bool = False
    max_files: int = 100
    prompts: ForensicsPromptSet = field(default_factory=forensics_prompt_set)
