"""The per-session approval broker for gated writes.

A single in-process registry of "approve for the rest of this session" grants,
keyed by a coarse capability class (``config``, ``install``, ``scope-edit``,
``cmd-edit``, ``memory``). One :class:`~skuggi.agent.core.AgentCore` -- and therefore
one ``SessionGrants`` -- lives behind the warm daemon per session, so a grant is
naturally scoped to the session and gone when the shell relaunches.

The confirm step (``skuggi.frontend.confirm``) consults it before prompting and
records a grant when the operator picks the session option, so a repeated
same-class write stops re-prompting -- but an auto-apply always announces the
grant, so it is never silent.
"""

from __future__ import annotations


class SessionGrants:
    """The capabilities the operator has approved for the rest of this session."""

    def __init__(self) -> None:
        self._granted: set[str] = set()

    def granted(self, capability: str) -> bool:
        """Whether `capability` has a standing session grant."""
        return capability in self._granted

    def grant(self, capability: str) -> None:
        """Record a standing grant for `capability` for the rest of the session."""
        self._granted.add(capability)

    def active(self) -> tuple[str, ...]:
        """The granted capabilities, sorted -- for ``show grants``."""
        return tuple(sorted(self._granted))

    def revoke_all(self) -> int:
        """Drop every grant; returns how many were cleared -- for ``remove grants``."""
        count = len(self._granted)
        self._granted.clear()
        return count
