"""The OSINT graph's dependency bundle (its own value object, not GraphDeps).

A distinct frozen struct from the turn graph's ``GraphDeps``: the two subsystems
share request *logic* (``agent.requests``), not a deps container. This carries only
what the OSINT nodes need -- the model + structured-output flag, the OSINT scope +
engagement (for the guard and finding scoring), the collector set + the injected
collection context, the workspace + ledger for structured output, and the loop
bounds. ``None`` where a plane is absent (agent-only mode has no engagement).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from langchain_core.language_models import BaseChatModel

from skuggi.engagement.engagement import EngagementConfig
from skuggi.engagement.scope import OsintScope
from skuggi.engagement.workspace import Workspace
from skuggi.osint.collectors.base import CollectContext, Collector
from skuggi.osint.prompts import OsintPromptSet, osint_prompt_set
from skuggi.persistence.ledger import Ledger
from skuggi.security.policy import RedactionPolicy


@dataclass(frozen=True, slots=True)
class OsintDeps:
    """Everything ``build_osint_graph`` needs, bundled so the signature stays small."""

    llm: BaseChatModel | None = None
    native_structured: bool = True
    redaction_policy: RedactionPolicy | None = None
    engagement: EngagementConfig | None = None
    osint: OsintScope | None = None
    collectors: tuple[Collector, ...] = ()
    collect_context: CollectContext | None = None
    workspace: Workspace | None = None
    ledger: Ledger | None = None
    session_id: str = ""
    max_tasks: int = 12
    max_replans: int = 2
    prompts: OsintPromptSet = field(default_factory=osint_prompt_set)
