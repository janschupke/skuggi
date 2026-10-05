"""The research graph's dependency bundle (its own value object).

A distinct frozen struct from the OSINT ``OsintDeps`` and the turn graph's
``GraphDeps``: the three subsystems share request *logic* (``agent.requests``),
not a deps container. This carries only what the research nodes need -- the model
+ structured-output flag, the collector set + the injected collection context, the
resolved output directory for artifacts, and the loop bounds. There is no
engagement/ledger/scope here: research is engagement-independent and report-only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from langchain_core.language_models import BaseChatModel

from skuggi.intel.collectors.base import CollectContext, Collector
from skuggi.research.prompts import ResearchPromptSet, research_prompt_set
from skuggi.research.schema import ResearchTask
from skuggi.security.policy import RedactionPolicy


@dataclass(frozen=True, slots=True)
class ResearchDeps:
    """Everything ``build_research_graph`` needs, bundled for a small signature."""

    llm: BaseChatModel | None = None
    native_structured: bool = True
    redaction_policy: RedactionPolicy | None = None
    collectors: tuple[Collector[ResearchTask], ...] = ()
    collect_context: CollectContext | None = None
    output_root: Path | None = None
    session_id: str = ""
    max_tasks: int = 10
    max_replans: int = 2
    # Max pure-I/O collectors run concurrently per superstep (D1); driver-backed
    # collectors always run serially regardless of this cap.
    concurrency: int = 4
    prompts: ResearchPromptSet = field(default_factory=research_prompt_set)
