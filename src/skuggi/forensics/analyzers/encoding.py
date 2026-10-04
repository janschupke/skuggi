"""Detect and reverse common encodings/compression over an evidence file.

Deterministic decoding only -- base64/base32/hex/url/rot13 and gzip/zlib
detection. Never a cipher brute-force (that is not forensics); keyed decryption
lives in ``keyed_decrypt`` and needs an operator-supplied key. Each successful
decode is an ``Observation`` carrying a bounded preview of the cleartext, so the
report can show what an encoded blob actually held.
"""

from __future__ import annotations

import base64
import binascii
import codecs
from pathlib import Path
from urllib.parse import unquote

from skuggi.forensics.analyzers.base import Observation, read_capped

_PREVIEW = 512
# Shortest blob worth attempting a text-codec decode on (below this, random noise
# coincidentally satisfies the charset too often to be a useful signal).
_MIN_ENCODED_LEN = 8
# A decoded blob is "textual" when at least this fraction of it is printable.
_TEXT_RATIO = 0.9
_B64 = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_B32 = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
_HEX = frozenset(b"0123456789abcdefABCDEF")


def _preview(raw: bytes) -> tuple[str, bool]:
    """A short, printable preview of decoded bytes, and whether it looks textual."""
    slice_ = raw[:_PREVIEW]
    try:
        text = slice_.decode("utf-8")
    except UnicodeDecodeError:
        return slice_.hex(), False
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return text, bool(text) and printable / len(text) > _TEXT_RATIO


def _try_base64(blob: bytes) -> bytes | None:
    if (
        len(blob) < _MIN_ENCODED_LEN
        or len(blob) % 4 != 0
        or any(b not in _B64 for b in blob)
    ):
        return None
    try:
        return base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None


def _try_base32(blob: bytes) -> bytes | None:
    if (
        len(blob) < _MIN_ENCODED_LEN
        or len(blob) % 8 != 0
        or any(b not in _B32 for b in blob)
    ):
        return None
    try:
        return base64.b32decode(blob)
    except (binascii.Error, ValueError):
        return None


def _try_hex(blob: bytes) -> bytes | None:
    if (
        len(blob) < _MIN_ENCODED_LEN
        or len(blob) % 2 != 0
        or any(b not in _HEX for b in blob)
    ):
        return None
    try:
        return bytes.fromhex(blob.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None


def analyze(path: Path) -> list[Observation]:
    """Report every encoding that cleanly reverses the file's (stripped) content."""
    data, _ = read_capped(path)
    out: list[Observation] = []
    if data[:2] == b"\x1f\x8b":
        out.append(Observation(kind="encoding", value="gzip stream detected"))
    if data[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
        out.append(Observation(kind="encoding", value="zlib stream detected"))
    blob = b"".join(data.split())  # drop all whitespace for the text codecs
    for name, decoder in (
        ("base64", _try_base64),
        ("base32", _try_base32),
        ("hex", _try_hex),
    ):
        decoded = decoder(blob)
        if decoded is not None and decoded != blob:
            preview, textual = _preview(decoded)
            out.append(
                Observation(
                    kind="decoded",
                    value=preview,
                    attributes={"encoding": name, "textual": str(textual)},
                )
            )
    # url/rot13 only make sense on text; attempt them on a utf-8 view.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return out
    unquoted = unquote(text)
    if "%" in text and unquoted != text:
        out.append(
            Observation(
                kind="decoded",
                value=unquoted[:_PREVIEW],
                attributes={"encoding": "url"},
            )
        )
    rot = codecs.encode(text, "rot_13")
    if rot != text:
        out.append(
            Observation(
                kind="decoded",
                value=rot[:_PREVIEW],
                attributes={"encoding": "rot13", "note": "candidate; verify"},
            )
        )
    return out
