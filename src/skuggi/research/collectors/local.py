"""The injectable local-tool seam for research collectors.

The HTTP collectors inject their network I/O through ``CollectContext.fetch``; the
local-tool collectors (searchsploit, metasploit) need the analogous seam for a
bounded subprocess call and a metadata-file read, so the whole set stays offline-
testable with fakes. Both defaults are best-effort and never raise -- any failure
(missing binary, timeout, non-zero exit, unreadable file) yields ``None``, which a
collector turns into an empty result / coverage gap.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

# (argv) -> stdout text, or None on any failure (missing binary / timeout / error).
LocalRun = Callable[[list[str]], "str | None"]

# () -> the parsed metasploit module-metadata cache, or None when unavailable.
CacheLoader = Callable[[], "dict[str, object] | None"]

_TIMEOUT_S = 20.0
_MSF_CACHE = Path.home() / ".msf4" / "store" / "modules_metadata.json"


def have(binary: str) -> bool:
    """Whether ``binary`` resolves on the host PATH (``shutil.which``)."""
    return shutil.which(binary) is not None


def default_local_run(argv: list[str]) -> str | None:
    """Run ``argv`` with a hard timeout; return stdout, or None on any failure.

    Read-only local-database queries only (searchsploit/metasploit). The binary is
    resolved from PATH; a missing binary, a non-zero exit, or a timeout all yield
    ``None`` so the collector degrades to an empty result.
    """
    if not argv or not have(argv[0]):
        return None
    try:
        proc = subprocess.run(  # noqa: S603 -- argv list, no shell, bounded timeout
            argv,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def default_msf_cache(path: Path = _MSF_CACHE) -> dict[str, object] | None:
    """Load the metasploit module-metadata cache JSON, or None when unreadable.

    ``~/.msf4/store/modules_metadata.json`` is metasploit's own on-disk module
    index -- a reliable, fast, read-only source of module metadata that avoids
    spawning a slow ``msfconsole`` search. Any read/parse error yields ``None``.
    """
    try:
        body = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(body)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None
