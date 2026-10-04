"""Write an OSINT result as a confined, redacted JSON artifact.

A thin OSINT-specific binding over :func:`skuggi.intel.store.write_result`: it
targets the workspace's ``osint_dir`` so every :class:`OsintResult` lands at
``osint/<subject>/<source>.json`` inside the engagement. The confinement and
redaction discipline live in the shared writer; this only chooses the directory.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from skuggi.engagement.workspace import Workspace
from skuggi.intel import store as intel_store
from skuggi.osint.schema import OsintResult


def result_path(workspace: Workspace, result: OsintResult) -> Path:
    """The confined ``osint/<subject>/<source>.json`` path for a result."""
    return intel_store.result_path(workspace.osint_dir, result)


def write_result(
    workspace: Workspace, result: OsintResult, *, clean: Callable[[str], str]
) -> Path:
    """Serialize, redact and write ``result`` under the workspace's osint dir."""
    return intel_store.write_result(workspace.osint_dir, result, clean=clean)
