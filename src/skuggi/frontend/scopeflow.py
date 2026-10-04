"""Interactive, gated scope editing: propose, diff, confirm, apply.

Mirror of ``configflow`` for the engagement authorization scope. The core maps a
natural-language request to typed edits; this shows them as a per-field diff
(scope governs authorization, so the change is always visible before it is
written), confirms through the shared gated-write step (capability
``scope-edit``), and applies on a yes. An invalid edit (a bad CIDR, host or tier)
is reported, never written.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from pydantic import ValidationError

from skuggi.frontend.confirm import Choose, Notify, confirm_write

if TYPE_CHECKING:
    from skuggi.agent.grants import SessionGrants
    from skuggi.agent.protocol import ScopeEdit

Propose = Callable[[str], "list[ScopeEdit]"]
Preview = Callable[["list[ScopeEdit]"], list[tuple[str, str, str]]]
Apply = Callable[["list[ScopeEdit]"], str]


def run_scope_request(  # noqa: PLR0913 -- keyword-only collaborators + the request
    request: str,
    *,
    choose: Choose,
    notify: Notify,
    propose: Propose,
    preview: Preview,
    apply: Apply,
    grants: SessionGrants,
) -> None:
    """Propose scope edits, show the diff, confirm, and apply on a yes."""
    edits = propose(request)
    if not edits:
        notify("scope: no changes proposed")
        return
    try:
        rows = preview(edits)
    except (ValidationError, ValueError) as exc:
        notify(f"scope: invalid edit -- {exc}")
        return
    if not rows:
        notify("scope: the proposed edits change nothing")
        return
    notify("proposed scope changes:")
    for field, old, new in rows:
        notify(f"  {field}: {old} -> {new}")
    if not confirm_write(
        "scope-edit", grants=grants, choose=choose, notify=notify, agentic=True
    ):
        notify("scope unchanged")
        return
    notify(apply(edits))
