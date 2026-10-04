"""Operator-key decryption of an evidence file -- reversible, never a brute-force.

Forensics decrypts only when the operator supplies the key (recovered elsewhere in
the case); it never guesses or cracks a cipher. Supports Fernet tokens and raw
AES-GCM/CBC given a key (and nonce/iv). ``cryptography`` is an optional dependency
(the ``forensics`` extra), imported lazily so the core import graph never pulls it;
when it is absent, a decrypt request returns a note rather than raising.
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

from skuggi.forensics.analyzers.base import Observation, read_capped

_PREVIEW = 512


def _decode_key(key: str) -> bytes:
    """Decode a key given as hex or base64; fall back to raw UTF-8 bytes.

    Hex is tried FIRST: an all-hex key (the common ``openssl``/``xxd`` form) is also
    valid base64, so base64-first would silently mis-decode it into the wrong bytes.
    A real base64 key almost always carries a non-hex character (``+/=`` or g-z), so
    it falls through to the base64 branch.
    """
    stripped = key.strip()
    if len(stripped) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        return bytes.fromhex(stripped)
    try:
        return base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return stripped.encode("utf-8")


def _preview(raw: bytes) -> str:
    try:
        return raw[:_PREVIEW].decode("utf-8")
    except UnicodeDecodeError:
        return raw[:_PREVIEW].hex()


def analyze(
    path: Path,
    *,
    key: str,
    algorithm: str = "fernet",
    nonce: str | None = None,
) -> list[Observation]:
    """Decrypt `path` with the operator-supplied `key`; preview the plaintext.

    `algorithm` is ``fernet``, ``aes-gcm`` or ``aes-cbc``; ``aes-*`` need a
    hex/base64 `nonce` (the GCM nonce or CBC iv). A wrong key / corrupt ciphertext
    yields a ``note`` observation, not an exception.
    """
    try:
        from cryptography.fernet import Fernet, InvalidToken  # noqa: PLC0415
        from cryptography.hazmat.primitives.ciphers import (  # noqa: PLC0415
            Cipher,
            algorithms,
            modes,
        )
        from cryptography.hazmat.primitives.ciphers.aead import (  # noqa: PLC0415
            AESGCM,
        )
    except ImportError:
        return [
            Observation(
                kind="note",
                value="decryption unavailable: install the `forensics` extra",
            )
        ]
    data, _ = read_capped(path)
    try:
        if algorithm == "fernet":
            plain = Fernet(key.encode("utf-8")).decrypt(data)
        elif algorithm == "aes-gcm":
            if nonce is None:
                return [Observation(kind="note", value="aes-gcm needs a nonce")]
            plain = AESGCM(_decode_key(key)).decrypt(_decode_key(nonce), data, None)
        elif algorithm == "aes-cbc":
            if nonce is None:
                return [Observation(kind="note", value="aes-cbc needs an iv")]
            dec = Cipher(
                algorithms.AES(_decode_key(key)), modes.CBC(_decode_key(nonce))
            ).decryptor()
            plain = dec.update(data) + dec.finalize()
        else:
            return [Observation(kind="note", value=f"unknown algorithm {algorithm!r}")]
    except (InvalidToken, ValueError) as exc:
        return [
            Observation(kind="note", value=f"decryption failed ({algorithm}): {exc}")
        ]
    return [
        Observation(
            kind="decrypted",
            value=_preview(plain),
            attributes={"algorithm": algorithm, "size": str(len(plain))},
        )
    ]
