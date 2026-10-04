"""Hash digests of an evidence file (the integrity pin + IOC lookup values)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from skuggi.forensics.analyzers.base import Observation

# The digests worth recording: md5/sha1 for IOC/threat-intel lookups (still the
# common currency there), sha256/sha512 for integrity.
_ALGOS = ("md5", "sha1", "sha256", "sha512")
_CHUNK = 1024 * 1024


def analyze(path: Path) -> list[Observation]:
    """Compute md5/sha1/sha256/sha512 of `path`, streamed over the whole file."""
    digests = {name: hashlib.new(name) for name in _ALGOS}
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            size += len(chunk)
            for d in digests.values():
                d.update(chunk)
    return [
        Observation(
            kind="hash",
            value=digests[name].hexdigest(),
            attributes={"algorithm": name, "size": str(size)},
        )
        for name in _ALGOS
    ]
