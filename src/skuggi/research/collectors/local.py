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

# The ONLY binaries a research collector may spawn. Research is the one mode where
# model-chosen input (``task.subject``) reaches a subprocess argv, and it never
# passes through the engagement guard -- so the binary allow-list is the
# deterministic backstop here, deny-by-default like ``check_command`` elsewhere.
RESEARCH_BINARIES = frozenset({"searchsploit", "msfconsole"})

# Characters that must never appear in a model-supplied argv token. There is no
# shell (argv list), so these cannot inject a command, but a newline/NUL can still
# confuse a tool's own parser or its JSON output -- reject them outright.
_FORBIDDEN_IN_TOKEN = ("\x00", "\n", "\r")


def have(binary: str) -> bool:
    """Whether ``binary`` resolves on the host PATH (``shutil.which``)."""
    return shutil.which(binary) is not None


def safe_subject(subject: str) -> str | None:
    """A model-supplied research subject cleared for an argv, or None if unsafe.

    The subject is the one token a research collector interpolates into a tool's
    argv. A leading ``-`` would be read as a flag (argument injection -- e.g.
    searchsploit's ``-m``/``-x`` write/examine options), and a control character
    could corrupt the tool's parse; both are rejected so the collector degrades to
    a coverage gap rather than running something other than a plain query.
    """
    stripped = subject.strip()
    if not stripped or stripped.startswith("-"):
        return None
    if any(c in stripped for c in _FORBIDDEN_IN_TOKEN):
        return None
    return stripped


def default_local_run(argv: list[str]) -> str | None:
    """Run ``argv`` with a hard timeout; return stdout, or None on any failure.

    Read-only local-database queries only (searchsploit/metasploit). ``argv[0]``
    must be on the ``RESEARCH_BINARIES`` allow-list and no token may carry a
    control character; the binary is then resolved from PATH, and a missing
    binary, a non-zero exit, or a timeout all yield ``None`` so the collector
    degrades to an empty result.
    """
    if not argv or argv[0] not in RESEARCH_BINARIES:
        return None
    if any(c in tok for tok in argv for c in _FORBIDDEN_IN_TOKEN):
        return None
    if not have(argv[0]):
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
