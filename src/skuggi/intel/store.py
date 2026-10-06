"""Write an intelligence result as a confined, redacted JSON artifact.

The file-based half of both loops' structured output: every :class:`IntelResult`
is written to ``<dir>/<subject>/<source>.json`` under a caller-chosen output directory
(the OSINT loop passes ``workspace.osint_dir``; the research loop passes the
engagement's ``research_dir`` or a cwd fallback). The path is confined with
``common.paths.confine_under`` (a ``..``/symlink escape raises rather than writing
outside the tree), and the serialized payload is run through the session redactor
before it touches disk -- a secret a collector happened to surface becomes a vault
placeholder in the artifact.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from skuggi.common.paths import confine_under, ensure_parent
from skuggi.engagement.workspace import safe_engagement_name
from skuggi.intel.schema import IntelResult


def result_path(output_dir: Path, result: IntelResult) -> Path:
    """The confined ``<output_dir>/<subject>/<source>.json`` path for a result.

    The subject is slugged into one safe path segment (``WordPress 6.x`` ->
    ``wordpress-6.x``), and the whole relative path is resolved under ``output_dir``
    so nothing can escape it. Raises ``ValueError`` on a subject that reduces to
    nothing usable or a path that would escape.
    """
    subject = safe_engagement_name(result.subject)
    return confine_under(output_dir, f"{subject}/{result.source}.json")


def write_result(
    output_dir: Path, result: IntelResult, *, clean: Callable[[str], str]
) -> Path:
    """Serialize, redact and write ``result``; return the artifact path.

    ``clean`` is the session redactor (``executor._redactor``). The placeholders it
    inserts are plain string tokens, so the JSON stays well-formed.
    """
    path = result_path(output_dir, result)
    payload = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
    ensure_parent(path)
    path.write_text(clean(payload) + "\n", encoding="utf-8")
    return path
