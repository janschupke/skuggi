"""What the redactor scrubs, and the scope values it must leave alone.

A ``RedactionPolicy`` is pure configuration: a set of category toggles plus the
*allow set* -- exact strings that must never be redacted even when a detector
matches them. The allow set exists because the agent has to reason about its own
engagement: its in-scope hosts, networks and target are identifiers it needs to
see in plain text, yet a hostname or address can look exactly like PII a detector
would otherwise mask. ``core`` builds the allow set from the loaded
``EngagementConfig`` (never imported here, to keep this a dependency-free leaf).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

# Shorter candidate values are too generic to mask without blanking unrelated
# text; carried over from the original ``common.text`` discipline.
DEFAULT_MIN_SECRET_LEN = 8


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    """The categories to scrub and the exact values to leave untouched."""

    # Exact strings a detector must pass through unchanged -- the engagement's
    # in-scope hosts, networks and primary target, plus its own name.
    allow: frozenset[str] = field(default_factory=frozenset)
    # Per-category switches. All on by default: the safe posture is to scrub.
    keys: bool = True
    tokens: bool = True
    auth: bool = True
    passwords: bool = True
    emails: bool = True
    cards: bool = True
    hashes: bool = True
    min_secret_len: int = DEFAULT_MIN_SECRET_LEN

    @classmethod
    def from_scope(
        cls,
        *,
        allow: Iterable[str] = (),
        min_secret_len: int = DEFAULT_MIN_SECRET_LEN,
    ) -> RedactionPolicy:
        """A policy whose allow set is seeded from engagement scope values.

        Empty and whitespace-only entries are dropped so an unset ``primary_target``
        cannot smuggle a blank string into the allow set (where it would match
        and suppress nothing, but still be noise).
        """
        cleaned = frozenset(value for value in allow if value and value.strip())
        return cls(allow=cleaned, min_secret_len=min_secret_len)

    def allows(self, value: str) -> bool:
        """Whether `value` is an in-scope identifier that must not be redacted."""
        return value in self.allow

    def enabled(self, category: str) -> bool:
        """Whether `category` (a detector's category name) is switched on."""
        return bool(getattr(self, category, True))
