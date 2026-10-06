"""The authorization-boundary taxonomy: hard block vs escalation vs grantable.

Three distinct things decide whether an action happens, and they are *not*
interchangeable -- conflating them is how an operator ends up thinking a scope
denial is something they can click through. This module names them so every
front-end and the ledger describe a refusal the same way.

* ``HARD_BLOCK`` -- a code-level boundary. The engagement scope guard
  (``check_command``) and the network egress gate. No session grant, no operator
  menu, and no mode overrides it: an out-of-scope or egress-denied command simply
  does not run. The only way to change it is to change the authorized scope, which
  is itself the non-session-grantable ``scope-edit`` confirm.
* ``ESCALATION`` -- in scope, but above the engagement's autonomous ceiling (or
  non-autonomous mode). The harness will not auto-run it; it is recorded
  ``proposed`` and the operator runs it by hand in their own shell. Operator-
  overridable by definition -- that is the manual-escalation path, not a block.
* ``GRANTABLE`` -- a gated *write* (config / install / cmd / memory / scope). The
  ``confirm_write`` three-way menu applies it, optionally for the session --
  except ``scope-edit``, which is confirmed every time (it is the authorization
  boundary, and its natural-language context can carry injected tool/web output).

The invariant: HARD_BLOCK lives only in deterministic code and is never a
grant/menu; GRANTABLE lives only in the write-confirm layer and never gates a
command's execution. ESCALATION is the one bridge the operator can cross by hand.
"""

from __future__ import annotations

from enum import StrEnum


class BoundaryKind(StrEnum):
    """Which kind of authorization boundary refused (or gated) an action."""

    HARD_BLOCK = "hard block"
    ESCALATION = "escalation"
    GRANTABLE = "grantable"


# Gated-write capabilities that are confirmed every time (never session-grantable);
# mirrors frontend.confirm._NON_GRANTABLE, named here as part of the taxonomy.
NON_SESSION_GRANTABLE = frozenset({"scope-edit"})


def boundary_kind(*, allowed: bool, within_ceiling: bool) -> BoundaryKind | None:
    """Classify a guarded action. ``None`` means it runs (in scope, under ceiling).

    Shared by every autonomous path -- a shell command (the turn graph) and an
    OSINT reconnaissance source alike -- so a refusal is classified the same way
    everywhere:

    - not ``allowed`` -> ``HARD_BLOCK`` (scope guard / egress; non-overridable).
    - ``allowed`` but over the ceiling -> ``ESCALATION`` (operator acts by hand).
    - ``allowed`` and under the ceiling -> ``None`` (the harness runs it).
    """
    if not allowed:
        return BoundaryKind.HARD_BLOCK
    if not within_ceiling:
        return BoundaryKind.ESCALATION
    return None


def label(kind: BoundaryKind, reason: str) -> str:
    """A consistent operator/ledger-facing refusal string, e.g. ``hard block: ...``."""
    return f"{kind.value}: {reason}"
