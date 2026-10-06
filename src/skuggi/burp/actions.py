"""The gated runner for one agent-driven Burp action.

The Burp analogue of ``agent/executor.py::_run_or_propose``: it applies the same
authorization discipline every offensive action in the harness goes through --
``gate -> record -> (execute | propose | block)`` -- so a Burp write is held to
exactly the boundary a shell command is. A denied action is a HARD_BLOCK, an
in-scope action above the Burp scope's autonomous ceiling is an ESCALATION held as
``proposed`` for the operator, and a cleared action runs and is recorded
``executed``. Every outcome is written to the tamper-evident ``burp_actions``
ledger with its tier and authority, so the audit trail covers Burp like any tool.

The actual client call is injected (``execute``) so this stays a leaf over the
engagement guard + the ledger + the boundary taxonomy, with no edge up into the
client transport or the agent graph; the caller supplies the closure that drives
the :class:`~skuggi.burp.client.BurpClient` and returns a redacted summary (and a
task handle for an async scan/attack).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from skuggi.burp.models import BurpAction
from skuggi.engagement.burp_guard import action_tier, check_burp_action
from skuggi.security import boundaries

if TYPE_CHECKING:
    from skuggi.engagement.scope import EngagementConfig
    from skuggi.persistence.ledger import Ledger

# (clear) -> (result_summary, handle). Invoked only when the action is cleared to
# run; returns the redacted outcome summary and a Burp task handle ('' when none).
Executor = Callable[[], "tuple[str, str]"]


@dataclass(frozen=True, slots=True)
class BurpOutcome:
    """The result of gating (and maybe running) one Burp action."""

    status: str  # executed | proposed | blocked
    action_id: int
    summary: str
    handle: str = ""

    @property
    def ran(self) -> bool:
        """Whether the action actually executed (vs blocked/proposed)."""
        return self.status == "executed"


def run_burp_action(  # noqa: PLR0913 -- cohesive keyword-only gate signature
    *,
    engagement: EngagementConfig,
    ledger: Ledger,
    session_id: str,
    thread_id: str,
    action: BurpAction,
    target_host: str,
    params: str,
    autonomous: bool,
    execute: Executor,
) -> BurpOutcome:
    """Gate, record and (when cleared) run one Burp action. Mirrors _run_or_propose.

    ``params`` is a short human description for the ledger/operator; ``target_host``
    is the host a traffic action acts on (scope-checked). ``execute`` is called only
    when the action clears both the scope guard and the autonomous ceiling.
    """
    verdict = check_burp_action(action, target_host, engagement)
    if not verdict.allowed:
        aid = ledger.record_burp_action(
            session_id=session_id,
            thread_id=thread_id,
            action=action,
            status="blocked",
            target=target_host,
            params=params,
            reason=verdict.reason,
        )
        label = boundaries.label(boundaries.BoundaryKind.HARD_BLOCK, verdict.reason)
        return BurpOutcome("blocked", aid, label)

    burp = engagement.burp
    assert burp is not None  # noqa: S101 -- guard allows only when burp is enabled
    tier = action_tier(action)
    within_ceiling = autonomous and tier <= burp.autonomous_ceiling
    if (
        boundaries.boundary_kind(allowed=True, within_ceiling=within_ceiling)
        is boundaries.BoundaryKind.ESCALATION
    ):
        reason = (
            f"{action!r} is tier {tier.name}, above the Burp ceiling "
            f"{burp.autonomous_ceiling.name}"
            if autonomous
            else f"{action!r} held: autonomous execution is not armed"
        )
        aid = ledger.record_burp_action(
            session_id=session_id,
            thread_id=thread_id,
            action=action,
            status="proposed",
            target=target_host,
            params=params,
            risk_tier=tier.name,
            reason=reason,
        )
        label = boundaries.label(boundaries.BoundaryKind.ESCALATION, reason)
        return BurpOutcome("proposed", aid, label)

    summary, handle = execute()
    aid = ledger.record_burp_action(
        session_id=session_id,
        thread_id=thread_id,
        action=action,
        status="executed",
        target=target_host,
        params=params,
        risk_tier=tier.name,
        authority="autonomous",
        handle=handle,
        result_summary=summary,
    )
    return BurpOutcome("executed", aid, summary, handle)
