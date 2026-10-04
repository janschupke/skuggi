"""Pure-Python, subprocess-free forensic analyzers.

Each analyzer reads an evidence file READ-ONLY and returns a list of
:class:`Observation`s -- a deterministic transform, no model, no network, no
binary executed. They are the forensics loop's in-process collectors; the loop
wraps each ``Observation`` into an ``intel.IntelItem`` and records a procedure row
for the operation. Reads are byte-capped (``MAX_READ_BYTES``) so a huge or hostile
artifact cannot exhaust memory, mirroring ``common.execution``'s capture cap.
"""

from skuggi.forensics.analyzers.base import (
    MAX_READ_BYTES,
    Observation,
    read_capped,
    sha256_of,
)

__all__ = ["MAX_READ_BYTES", "Observation", "read_capped", "sha256_of"]
