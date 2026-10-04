"""The forensics boundary: read-only, deny-by-default, evidence-confined.

Forensics has no engagement and no operator-editable ``scope.json`` -- the
boundary is built in and non-negotiable, the analogue of
``research.scope.check_research_source``. Three invariants, all deny-by-default:

1. **Allow-list.** Only a fixed set of read-only external utilities may run
   (:data:`FORENSIC_TOOLS`). Everything else -- every offensive tool -- is denied.
2. **No writes.** Even an allow-listed tool is denied if its argv carries a
   write/extract/exec flag (``exiftool`` can overwrite tags, ``binwalk -e`` extracts
   to disk). We never trust a tool to stay read-only; we forbid the flags.
3. **Evidence confinement.** Every positional path that resolves to a real file
   must live inside the case ``evidence/`` dir (``Workspace.confine_evidence``), so
   a tool can never be pointed at ``/etc/shadow`` or a sibling outside the case.

The in-process analyzers (``forensics.analyzers``) run no binary at all, so they
bypass (1)/(2); their evidence path is still confined via the same primitive.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from skuggi.engagement.guard import GuardVerdict
from skuggi.engagement.workspace import Workspace
from skuggi.tooling.registry import ToolSpec

# The only external binaries the forensics loop may execute. Each parses/inspects a
# file and prints to stdout; with the write-flag deny-list below, each is confined
# to read-only use.
FORENSIC_TOOLS: frozenset[str] = frozenset({"file", "exiftool", "binwalk"})

# Flags that make an otherwise read-only tool WRITE, EXTRACT or EXECUTE. Denied for
# any forensic tool. ``exiftool`` also writes via a bare ``-TAG=value`` assignment,
# caught separately below.
_WRITE_FLAGS: frozenset[str] = frozenset(
    {
        "-o",
        "--output",
        "-w",
        "-W",
        "-D",
        "-M",
        "-e",
        "--extract",
        "--dd",
        "-overwrite_original",
        "-overwrite_original_in_place",
        "-delete_original",
        "--run",
        "--exec",
        "-exec",
    }
)


def check_forensic_tool(binary: str) -> GuardVerdict:
    """Whether `binary` is an allowed read-only forensic utility (deny-by-default)."""
    if binary in FORENSIC_TOOLS:
        return GuardVerdict(True, "read-only forensic tool")
    return GuardVerdict(False, f"{binary!r} is not an allowed forensic tool")


def _is_write_token(token: str) -> bool:
    """Whether an argv token would make a forensic tool write/extract/execute."""
    head = token.split("=", 1)[0]
    if head in _WRITE_FLAGS:
        return True
    # A tag assignment such as ``-Comment=...`` (exiftool) edits the file in place.
    return token.startswith("-") and "=" in token


def check_forensic_command(
    spec: ToolSpec | None,
    argv: Sequence[str],
    workspace: Workspace,
    *,
    cwd: Path,
) -> GuardVerdict:
    """The forensics command choke point: allow-list, no-writes, evidence-confined.

    An ordered deny-chain; the first failing invariant wins. `cwd` is the tool's
    working directory (the case root), used to resolve a positional path the way
    the tool will.
    """
    if not argv:
        return GuardVerdict(False, "empty command")
    binary = Path(argv[0]).name
    allowed = check_forensic_tool(binary)
    if not allowed.allowed:
        return allowed
    for token in argv[1:]:
        if _is_write_token(token):
            return GuardVerdict(False, f"write/extract flag not allowed: {token!r}")
    # Confine every positional token that denotes a filesystem path to evidence/.
    # "Path-ish" = absolute, or carrying a separator, or an existing file; a bare
    # flag value such as ``8`` (from ``-n 8``) is none of these and is skipped.
    if spec is None or spec.positional_file:
        for token in argv[1:]:
            if token.startswith("-"):
                continue
            pathish = token.startswith("/") or "/" in token or (cwd / token).exists()
            if not pathish:
                continue
            try:
                workspace.confine_evidence(token, cwd=cwd)
            except ValueError as exc:
                return GuardVerdict(False, str(exc))
    return GuardVerdict(True, "read-only, evidence-confined")
