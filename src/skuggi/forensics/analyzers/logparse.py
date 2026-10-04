"""Parse common log formats into a normalised ``(timestamp, source, message)`` line.

Recognises syslog (RFC3164 ``Mon DD HH:MM:SS host proc: msg``), a leading ISO-8601
timestamp, and the Common/Combined Log Format (``host - - [dd/Mon/yyyy:...] "req"
status size``). A line that matches none is still emitted with an empty timestamp
so nothing is silently dropped -- the examiner sees the raw line. Bounded line
count so a huge log cannot blow up the result.
"""

from __future__ import annotations

import re
from pathlib import Path

from skuggi.forensics.analyzers.base import Observation

_MAX_LINES = 1000

_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<msg>.*)$"
)
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<msg>.*)$"
)
_CLF = re.compile(r"^(?P<host>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+(?P<msg>.*)$")


def _parse_line(line: str) -> tuple[str, str, str]:
    """Return ``(timestamp, source, message)`` for one log line (best effort)."""
    if m := _SYSLOG.match(line):
        return m["ts"], m["host"], m["msg"]
    if m := _CLF.match(line):
        return m["ts"], m["host"], m["msg"]
    if m := _ISO.match(line):
        return m["ts"], "", m["msg"]
    return "", "", line


def analyze(path: Path) -> list[Observation]:
    """Normalise each log line of `path` into a timeline observation."""
    out: list[Observation] = []
    truncated = False
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for i, raw in enumerate(fh):
            if i >= _MAX_LINES:
                truncated = True
                break
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            ts, source, msg = _parse_line(line)
            out.append(
                Observation(
                    kind="log",
                    value=msg,
                    attributes={"timestamp": ts, "source": source, "line": str(i + 1)},
                )
            )
    if truncated:
        out.append(
            Observation(
                kind="note",
                value="log parsing truncated",
                attributes={"max_lines": str(_MAX_LINES)},
            )
        )
    return out
