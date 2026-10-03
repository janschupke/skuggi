"""The per-engagement secret vault: placeholders in, real values stay here.

When the redactor replaces a discovered secret it needs a *stable, reversible*
token: stable so the model sees the same ``«CRED:ab12»`` every time that value
recurs (and can reason about it as one thing), reversible so the harness can put
the real value back into a command it runs for a tool -- never into the model's
context. The vault is that mapping.

It is a 0600 SQLite file under ``engagements/<name>/`` and is **never**
serialized into any request, brief, report or dashboard. Placeholder ids are an
HMAC of the value under a per-vault random salt, so the id leaks nothing about
the secret and two distinct values never collide to the same token; the salt
persists in the vault so ids are stable across reopen but differ between
engagements.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from skuggi.common.clock import now_iso
from skuggi.common.paths import ensure_parent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
    placeholder TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    kind        TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    first_seen  TEXT NOT NULL
);
"""

# ``«KIND:id»`` -- guillemets so a placeholder is visually distinct and matches
# no secret/PII detector (keeping redaction idempotent). id is lowercase base32.
_PLACEHOLDER = re.compile(r"«(?P<kind>[A-Z]+):(?P<id>[a-z2-7]+)»")
_ID_LEN = 6


class SecretVault:
    """A reversible store of secret values discovered during an engagement."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        # check_same_thread=False: graph nodes run on a worker-thread pool, as
        # with the ledger; every access is guarded by the lock below.
        self._conn = conn
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._salt = self._load_or_make_salt()

    def _load_or_make_salt(self) -> bytes:
        row = self._conn.execute("SELECT value FROM meta WHERE key = 'salt'").fetchone()
        if row is not None:
            return bytes.fromhex(row[0])
        salt = secrets.token_bytes(16)
        self._conn.execute(
            "INSERT INTO meta (key, value) VALUES ('salt', ?)", (salt.hex(),)
        )
        self._conn.commit()
        return salt

    def _placeholder_for(self, value: str, kind: str) -> str:
        digest = hmac.new(
            self._salt, f"{kind}\x00{value}".encode(), hashlib.sha256
        ).digest()
        token = base64.b32encode(digest).decode("ascii").lower().rstrip("=")
        return f"«{kind}:{token[:_ID_LEN]}»"

    def intern(self, value: str, kind: str, *, source: str = "") -> str:
        """Record `value` under `kind` and return its stable placeholder.

        Idempotent on the (kind, value) pair: the same input always yields the
        same placeholder and leaves the first ``source``/``first_seen`` intact.
        """
        placeholder = self._placeholder_for(value, kind)
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO secrets "
                "(placeholder, value, kind, source, first_seen) "
                "VALUES (?, ?, ?, ?, ?)",
                (placeholder, value, kind, source, now_iso()),
            )
            self._conn.commit()
        return placeholder

    def resolve(self, placeholder: str) -> str | None:
        """The real value behind a ``«KIND:id»`` placeholder, or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM secrets WHERE placeholder = ?", (placeholder,)
            ).fetchone()
        return None if row is None else str(row[0])

    def rehydrate(self, text: str) -> str:
        """Replace every known placeholder in `text` with its real value.

        Used on a command the harness is about to run so a tool receives the
        real credential. An unknown placeholder is left untouched (fail-safe:
        an unresolvable token never becomes a blank that silently changes a
        command's meaning).
        """

        def _sub(match: re.Match[str]) -> str:
            return self.resolve(match.group(0)) or match.group(0)

        return _PLACEHOLDER.sub(_sub, text)

    def close(self) -> None:
        """Close the underlying connection."""
        with self._lock:
            self._conn.close()


@contextmanager
def open_vault(path: Path) -> Iterator[SecretVault]:
    """Open a `SecretVault` over `path`, creating the file (0600) and its parent.

    The file is chmod-ed before anything is written, so the salt and secrets are
    never briefly world-readable on a fresh create.
    """
    expanded = ensure_parent(path)
    existed = expanded.exists()
    conn = sqlite3.connect(str(expanded), check_same_thread=False)
    if not existed:
        expanded.chmod(0o600)
    vault = SecretVault(conn)
    try:
        yield vault
    finally:
        vault.close()
