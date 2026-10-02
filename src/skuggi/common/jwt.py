"""Read claims from a JWT locally, without verifying its signature."""

from __future__ import annotations

import base64
import json


def decode_claims(token: str) -> dict[str, object]:
    """Decode a JWT payload without verifying the signature (local read only).

    Hand-rolled rather than taking a ``pyjwt`` dependency to read a couple of
    unverified claims from a token skuggi already holds. Returns ``{}`` on any
    malformation -- the caught exceptions are exactly what the three steps can
    raise: indexing the payload segment, base64-decoding it, and JSON-parsing it
    (both ``binascii.Error`` and ``json.JSONDecodeError`` are ``ValueError``
    subclasses).
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError):
        return {}
    return claims if isinstance(claims, dict) else {}
