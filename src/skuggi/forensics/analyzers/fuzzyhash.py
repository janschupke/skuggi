"""Fuzzy (similarity) hashing of an evidence file -- TLSH, and ssdeep when present.

A cryptographic hash answers only identical-or-not; a *fuzzy* hash lets two
artifacts be compared for similarity -- near-duplicate malware, a tweaked config,
a re-packed binary, a lightly-edited document. TLSH is the primary backend
(``py-tlsh``, which ships pure wheels and is declared in the ``forensics`` extra)
and is computed by streaming the whole file through an incremental context, so a
multi-gigabyte artifact needs no full-file buffer (the ``read_capped`` 8 MiB cap
would be wrong here -- a similarity digest must cover the entire file). ssdeep is
used *in addition* when an operator happens to have it installed (it is not in the
extra: its C extension needs the system ``libfuzzy`` and has no cp314 wheel, so
forcing it would break a clean install). Both are lazily imported, so the core
import graph never pulls them, and an absent backend degrades to a single ``note``
observation -- the battery keeps running (audit F1).

TLSH needs a minimum amount of input with some byte variance (~50 bytes); below
that it raises, and this analyzer emits a note rather than a meaningless digest.
"""

from __future__ import annotations

from pathlib import Path

from skuggi.forensics.analyzers.base import Observation

_CHUNK = 1024 * 1024


def _tlsh_digest(path: Path) -> list[Observation] | None:
    """A TLSH observation for `path`, or None when the ``tlsh`` module is absent."""
    try:
        import tlsh  # noqa: PLC0415 -- lazy: the optional `forensics` extra
    except ImportError:
        return None
    ctx = tlsh.Tlsh()
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            ctx.update(chunk)
    try:
        ctx.final()
        digest = ctx.hexdigest()
    except ValueError:
        # Too little data, or too little byte variation, for a stable digest.
        return [
            Observation(
                kind="note",
                value="TLSH fuzzy hash: insufficient data or variation",
            )
        ]
    return [
        Observation(kind="fuzzyhash", value=digest, attributes={"algorithm": "tlsh"})
    ]


def _ssdeep_digest(path: Path) -> list[Observation] | None:
    """An ssdeep observation for `path`, or None when the ``ssdeep`` module is absent.

    Not part of the ``forensics`` extra (see the module docstring); used only when
    an operator has installed it out of band.
    """
    try:
        import ssdeep  # noqa: PLC0415 -- lazy, and only if the operator has it
    except ImportError:
        return None
    try:
        digest = ssdeep.hash_from_file(str(path))
    except OSError:
        return [Observation(kind="note", value="ssdeep fuzzy hash: unreadable file")]
    return [
        Observation(kind="fuzzyhash", value=digest, attributes={"algorithm": "ssdeep"})
    ]


def analyze(path: Path) -> list[Observation]:
    """Fuzzy-hash `path` with every available backend; note when none is installed."""
    out: list[Observation] = []
    for digest in (_tlsh_digest(path), _ssdeep_digest(path)):
        if digest is not None:
            out.extend(digest)
    if not out:
        return [
            Observation(
                kind="note",
                value="fuzzy hashing unavailable: install the `forensics` extra",
            )
        ]
    return out
