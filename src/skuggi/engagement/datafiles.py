"""A metadata-only inventory of the engagement's tool-input and evidence files.

This is how the data-plane split is realised on skuggi's propose-a-command
model: the agent must be able to *point a tool at* a wordlist or an evidence
file, but must never see the file's contents. ``list_datafiles`` describes each
file by name, kind, size, line count and SHA-256 -- enough for the model to
choose one and reference it by its workspace-relative path -- and nothing of
what is inside. The real bytes reach the tool (which reads the path) or a parser
(evidence), never the prompt.

The descriptions are a pure function of the tree, so the listing is testable
without a running session.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

# Read in blocks for the hash/line count so a large wordlist does not load whole.
_READ_BLOCK = 1 << 20
# A file over this is listed with size only (line count skipped): a multi-GB
# wordlist should not be walked line by line just to describe it.
_MAX_SCAN_BYTES = 50 * 1024 * 1024


class DataFile(BaseModel):
    """What the model is told about one data file -- never its contents."""

    model_config = ConfigDict(frozen=True)

    path: str  # workspace-relative, the token the agent references
    kind: str  # the directory it came from (input / evidence / loot)
    size_bytes: int
    line_count: int | None  # None for binary or oversized files
    sha256: str


def _looks_binary(sample: bytes) -> bool:
    """Whether a leading sample suggests a binary file (a NUL byte is decisive)."""
    return b"\x00" in sample


def _digest_and_lines(path: Path) -> tuple[str, int | None]:
    """The SHA-256 and line count of `path`, reading in blocks.

    Line count is ``None`` for a file that looks binary or exceeds the scan cap;
    the hash is always computed (it is cheap and is the file's identity).
    """
    sha = hashlib.sha256()
    lines = 0
    binary = False
    size = path.stat().st_size
    too_big = size > _MAX_SCAN_BYTES
    with path.open("rb") as handle:
        first = True
        while block := handle.read(_READ_BLOCK):
            sha.update(block)
            if first and _looks_binary(block[:1024]):
                binary = True
            first = False
            if not binary and not too_big:
                lines += block.count(b"\n")
    if binary or too_big:
        return sha.hexdigest(), None
    return sha.hexdigest(), lines


def describe_file(path: Path, root: Path, *, kind: str) -> DataFile:
    """Describe one file relative to the workspace `root`."""
    digest, lines = _digest_and_lines(path)
    return DataFile(
        path=str(path.relative_to(root)),
        kind=kind,
        size_bytes=path.stat().st_size,
        line_count=lines,
        sha256=digest,
    )


def _describe_dir(directory: Path, root: Path, *, kind: str) -> list[DataFile]:
    if not directory.is_dir():
        return []
    files = [p for p in sorted(directory.rglob("*")) if p.is_file()]
    return [describe_file(p, root, kind=kind) for p in files]


def list_datafiles(
    dirs: Iterable[tuple[Path, str]], root: Path
) -> tuple[DataFile, ...]:
    """Describe every file under each ``(directory, kind)`` pair, relative to `root`."""
    out: list[DataFile] = []
    for directory, kind in dirs:
        out.extend(_describe_dir(directory, root, kind=kind))
    return tuple(out)


def render_datafiles(files: Iterable[DataFile]) -> str:
    """A compact one-line-per-file block for a request (metadata only)."""
    lines = []
    for f in files:
        count = "binary" if f.line_count is None else f"{f.line_count} lines"
        lines.append(
            f"{f.path} ({f.kind}, {f.size_bytes}B, {count}, sha256:{f.sha256[:12]})"
        )
    return "\n".join(lines)
