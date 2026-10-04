"""Write an OSINT result as a confined, redacted JSON artifact.

The file-based half of OSINT's structured output: every :class:`OsintResult`
lands at ``osint/<subject>/<source>.json`` inside the engagement workspace. The
path is confined with ``Workspace.resolve_within`` (a ``..``/symlink escape raises
rather than writing outside the tree), and the serialized payload is run through
the session redactor before it touches disk -- a secret a collector happened to
surface becomes a vault placeholder in the artifact, exactly as scan output is
scrubbed before it reaches the model.

The ledger/report path is unchanged: security-relevant items are promoted to
``FindingDraft`` and recorded there separately. This module only owns the raw
corpus on disk.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from skuggi.common.paths import ensure_parent
from skuggi.engagement.workspace import Workspace, safe_engagement_name
from skuggi.osint.schema import OsintResult


def result_path(workspace: Workspace, result: OsintResult) -> Path:
    """The confined ``osint/<subject>/<source>.json`` path for a result.

    The subject is slugged into one safe path segment (``Acme Corp`` ->
    ``acme-corp``), and the whole relative path is resolved under ``osint_dir`` so
    nothing can escape the workspace. Raises ``ValueError`` on a subject that
    reduces to nothing usable or a path that would escape.
    """
    subject = safe_engagement_name(result.subject)
    return workspace.resolve_within(
        workspace.osint_dir, f"{subject}/{result.source}.json"
    )


def write_result(
    workspace: Workspace, result: OsintResult, *, clean: Callable[[str], str]
) -> Path:
    """Serialize, redact and write ``result``; return the artifact path.

    ``clean`` is the session redactor (``executor._redactor``). The placeholders it
    inserts are plain string tokens, so the JSON stays well-formed.
    """
    path = result_path(workspace, result)
    payload = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
    ensure_parent(path)
    path.write_text(clean(payload) + "\n", encoding="utf-8")
    return path
