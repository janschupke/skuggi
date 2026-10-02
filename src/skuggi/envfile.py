"""Write secrets into skuggi's own env file.

Credentials belong to the app, not to the operator's shell. A key goes into
``<config home>/env`` -- the dotenv file pydantic-settings already reads
(`config.settings_customise_sources`) -- at mode 0600, never into ``config.json``
(which refuses secrets by design) and never via a shell ``export``. This is the
writer half; pydantic-settings is the reader.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from skuggi import home
from skuggi.paths import ensure_parent

# A dotenv assignment line: KEY= ... . Comments and blanks are preserved as-is.
_ASSIGNMENT = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_]*)=")


def write_secret(name: str, value: str, *, path: Path | None = None) -> Path:
    """Upsert ``name=value`` into the env file, preserving every other line.

    Writes atomically at mode 0600 (``mkstemp`` then ``replace``, the same way
    ``CodexTokenStore._save`` keeps auth.json owner-only): the temp file is born
    at 0600 and ``replace`` carries that onto the target, so this can only ever
    narrow the mode -- a secret must never be left world-readable. Returns the
    path written.
    """
    target = (path or home.env_path()).expanduser()
    ensure_parent(target)
    existing = (
        target.read_text(encoding="utf-8").splitlines() if target.is_file() else []
    )
    assignment = f"{name}={value}"
    lines: list[str] = []
    replaced = False
    for line in existing:
        match = _ASSIGNMENT.match(line)
        if match and match.group("key") == name:
            lines.append(assignment)
            replaced = True
        else:
            lines.append(line)
    if not replaced:
        lines.append(assignment)
    _atomic_write(target, "\n".join(lines) + "\n")
    return target


def _atomic_write(target: Path, text: str) -> None:
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".env-", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
