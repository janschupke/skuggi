"""L1: the forensics subsystem is read-only BY ARCHITECTURE, enforced here.

The forensics loop runs only pure-Python analyzers over evidence obtained by a
filesystem walk -- it spawns no process, so a malicious filename or an injected
instruction cannot become a command. ``forensics/scope.py`` carries the written
guard (allow-list + no-write flags + evidence confinement) for the day an
external-tool node is added, but today nothing calls it. This test keeps the
guarantee from silently eroding: if any forensics module ever grows a subprocess
/ exec primitive, it fails until that path is routed through
``check_forensic_command`` (and this invariant is updated to match).
"""

from __future__ import annotations

import re
from pathlib import Path

import skuggi.forensics as forensics_pkg

# Actual process-spawning usage -- not the word "subprocess" in a docstring. A new
# forensic external-tool path must go through check_forensic_command instead.
_FORBIDDEN = re.compile(
    r"\bimport subprocess\b|\bsubprocess\.|\bPopen\b|\bos\.system\b|\bos\.exec|"
    r"\bpty\.spawn\b|\bexecution\.run\b"
)


def _forensics_sources() -> list[Path]:
    root = Path(forensics_pkg.__file__).parent
    return sorted(root.rglob("*.py"))


def test_no_forensics_module_spawns_a_process() -> None:
    offenders = {
        path.name: _FORBIDDEN.findall(path.read_text(encoding="utf-8"))
        for path in _forensics_sources()
        if _FORBIDDEN.search(path.read_text(encoding="utf-8"))
    }
    assert offenders == {}, (
        "forensics must stay subprocess-free (read-only by architecture); "
        f"route any tool path through check_forensic_command. Offenders: {offenders}"
    )


def test_the_invariant_actually_scans_something() -> None:
    # Guard against a silently-empty glob making the invariant vacuous.
    assert len(_forensics_sources()) >= 5
