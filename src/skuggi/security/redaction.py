"""Deterministic, rule-based detection and redaction of secrets and PII.

No model, no network, no I/O: a pure function of ``(text, policy)``. Each
detector is a high-precision pattern (anchored, length-bounded, or validated)
so a match is very likely a real secret -- the failure mode we most want to
avoid is a loose pattern that blanks unrelated output and misleads the operator.

``scan`` finds every candidate span; ``redact`` rewrites them. A detector marks
the exact *substring* to replace (a named ``v`` group when the match carries
context, e.g. ``Authorization: <token>``), so redaction never eats the
surrounding structure. Overlapping matches resolve to the longest, then to the
earliest-listed detector, so a token inside an auth header is masked once.

Reversibility is delegated to an ``Interner``: with one (the per-engagement
``SecretVault``) each value becomes a stable ``«KIND:id»`` placeholder the
harness can later rehydrate for a tool; without one, every value collapses to
the opaque ``REDACTED`` constant (the engagement dashboard's one-way mode).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import NamedTuple, Protocol

from skuggi.common.text import REDACTED
from skuggi.security.policy import RedactionPolicy
from skuggi.security.vault import PLACEHOLDER_RE

# The one-way mask sentinel is `common.text.REDACTED` (imported above): the same
# value the dashboard's one-way `redact_secrets` uses, so a secret reads the same
# whether it was masked on the model-facing path (here) or the HTML-embed path.

# Primary Account Number length band for a plausible card (ISO/IEC 7812).
_PAN_MIN, _PAN_MAX = 13, 19


class Interner(Protocol):
    """Turns a real secret value into a stable, reversible placeholder."""

    def intern(self, value: str, kind: str) -> str:
        """Record `value` under `kind` and return its placeholder token."""
        ...


def _luhn(value: str) -> bool:
    """Whether the digits of `value` satisfy the Luhn checksum (card numbers)."""
    digits = [int(ch) for ch in value if ch.isdigit()]
    if not _PAN_MIN <= len(digits) <= _PAN_MAX:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        doubled = digit * 2 if index % 2 == 1 else digit
        total += doubled - 9 if doubled > 9 else doubled  # noqa: PLR2004 -- Luhn fold
    return total % 10 == 0


@dataclass(frozen=True, slots=True)
class Detector:
    """One secret/PII pattern and how to treat its matches."""

    category: str  # the RedactionPolicy toggle this detector obeys
    kind: str  # the placeholder KIND (e.g. "EMAIL", "TOKEN")
    pattern: re.Pattern[str]
    # When set, only this named group is the sensitive substring to replace;
    # otherwise the whole match is replaced.
    group: str | None = None
    # A value that fails this check is not a real secret (e.g. Luhn for cards).
    validate: Callable[[str], bool] | None = None
    # Gate short matches on ``policy.min_secret_len``; off for patterns whose
    # own structure already guarantees the match is a secret.
    respect_min_len: bool = False


# Ordered most-specific first. Order is the final tie-break when two matches
# start at the same offset with equal length.
DETECTORS: tuple[Detector, ...] = (
    Detector(
        category="keys",
        kind="KEY",
        pattern=re.compile(
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
            r".*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    Detector(
        category="tokens",
        kind="JWT",
        pattern=re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
    ),
    Detector(
        category="tokens",
        kind="AWSKEY",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    Detector(
        category="tokens",
        kind="TOKEN",
        pattern=re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}"
            r"|github_pat_[A-Za-z0-9_]{20,}"
            r"|xox[baprs]-[A-Za-z0-9-]{10,}"
            r"|sk-[A-Za-z0-9]{20,}"
            r"|AIza[0-9A-Za-z_-]{30,}"
            r"|glpat-[A-Za-z0-9_-]{18,})\b"
        ),
    ),
    Detector(
        category="auth",
        kind="AUTH",
        pattern=re.compile(
            r"(?im)^(?:\s*(?:proxy-)?authorization|\s*x-api-key)\s*:\s*(?P<v>\S.*)$"
        ),
        group="v",
    ),
    Detector(
        category="auth",
        kind="TOKEN",
        pattern=re.compile(r"(?i)\b(?:bearer|token)\s+(?P<v>[A-Za-z0-9._~+/=-]{8,})"),
        group="v",
    ),
    Detector(
        category="passwords",
        kind="URLCRED",
        pattern=re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://(?P<v>[^/\s:@]+:[^/\s:@]+)@"),
        group="v",
    ),
    Detector(
        category="hashes",
        kind="HASH",
        pattern=re.compile(r"\$(?:1|2[aby]|5|6|y)\$[./A-Za-z0-9$]{10,}"),
    ),
    Detector(
        category="passwords",
        kind="PASSWORD",
        pattern=re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\b"
            r"\s*[:=]\s*(?P<v>[^\s\"',;]+)"
        ),
        group="v",
        respect_min_len=True,
    ),
    Detector(
        category="cards",
        kind="CARD",
        pattern=re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        validate=_luhn,
    ),
    Detector(
        category="emails",
        kind="EMAIL",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
)


class Match(NamedTuple):
    """One sensitive span: the substring to replace and what it is."""

    start: int
    end: int
    kind: str
    value: str


def _already_masked(value: str) -> bool:
    """Whether `value` is wholly mask output (a sentinel/placeholder, no secret).

    A broad detector (an auth-header line keeps content after the colon even
    after its token is masked) would otherwise re-match its own output; this
    lets ``scan`` skip a span whose only content is a mask, so redacting twice
    is a no-op and the egress tripwire does not flag clean text.
    """
    residual = PLACEHOLDER_RE.sub("", value).replace(REDACTED, "")
    return not residual.strip()


def scan(text: str, policy: RedactionPolicy) -> list[Match]:
    """Every non-overlapping sensitive span in `text`, left to right.

    Candidates are gathered from all enabled detectors, dropped when the value
    is allow-listed, fails the detector's validator, or is shorter than the
    policy minimum; overlaps are then resolved to the longest match (ties to the
    earliest-listed detector).
    """
    if not text:
        return []
    candidates: list[tuple[int, int, int, str, str]] = []
    for order, det in enumerate(DETECTORS):
        if not policy.enabled(det.category):
            continue
        for found in det.pattern.finditer(text):
            start, end = found.span(det.group) if det.group else found.span()
            if start < 0:  # an optional group that did not participate
                continue
            value = text[start:end]
            if policy.allows(value) or _already_masked(value):
                continue
            if det.validate and not det.validate(value):
                continue
            if det.respect_min_len and len(value) < policy.min_secret_len:
                continue
            candidates.append((start, -(end - start), order, det.kind, value))
    candidates.sort()
    chosen: list[Match] = []
    covered = 0
    for start, neg_len, _order, kind, value in candidates:
        end = start - neg_len
        if start < covered:
            continue  # overlaps an already-chosen, higher-priority span
        chosen.append(Match(start, end, kind, value))
        covered = end
    return chosen


def redact(text: str, policy: RedactionPolicy, interner: Interner | None = None) -> str:
    """Return `text` with every sensitive span masked.

    With an `interner` each value becomes a reversible ``«KIND:id»`` placeholder;
    without one every value collapses to :data:`REDACTED`. Already-redacted text
    is unchanged -- a placeholder matches no detector -- so applying ``redact``
    again (ingress then the egress tripwire) is idempotent.
    """
    spans = scan(text, policy)
    if not spans:
        return text
    out: list[str] = []
    cursor = 0
    for span in spans:
        out.append(text[cursor : span.start])
        out.append(interner.intern(span.value, span.kind) if interner else REDACTED)
        cursor = span.end
    out.append(text[cursor:])
    return "".join(out)
