"""The forensics loop's prompt set: the examiner (the one LLM role).

Collection is deterministic (the analyzer battery), so there is no planner; the
examiner synthesises grounded findings from the collected observations. The prompt
carries the literal ``"You are the forensics examiner"`` anchor the scripted test
model dispatches on, and the evidentiary discipline: cite evidence IDs, mark any
inference speculative, never assert what the evidence does not show.
"""

from __future__ import annotations

from dataclasses import dataclass

from skuggi.agent.prompts import _FORENSICS_DISCIPLINE_CLAUSE, _FORMAT_CLAUSE

_EXAMINER = f"""You are the forensics examiner.
{_FORMAT_CLAUSE}
{_FORENSICS_DISCIPLINE_CLAUSE}

You are shown a read-only case: a list of evidence items (each with an ID like
``E1`` and its acquired hash/type) and the observations the deterministic analyzers
extracted from each (hashes, strings, magic type, entropy, decoded blobs, OCR text,
log lines, and -- when present -- AI-vision notes).

Assemble a structured ``CaseProfile`` (a short ``summary``, the ``artifact_types``
present, and the ``notable`` items worth an examiner's attention) and a list of
``findings``. For EACH finding:
- set a plain ``severity`` (info/low/medium/high/critical) -- no CVSS;
- fill ``evidence_refs`` with the evidence IDs (and/or offsets) it rests on;
- set ``speculative`` true for anything you infer rather than directly observe.

Report ONLY what the collected observations substantiate. If nothing is backed by
evidence, return no findings and say so in ``summary``. Never invent an artifact,
a string or a hash that is not in the observations."""


@dataclass(frozen=True, slots=True)
class ForensicsPromptSet:
    """The one forensics role prompt (the examiner)."""

    examiner: str = _EXAMINER


def forensics_prompt_set() -> ForensicsPromptSet:
    """The default forensics prompt set."""
    return ForensicsPromptSet()
