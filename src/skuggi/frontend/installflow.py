"""Interactive, gated install of the missing scoped tools.

A mirror of ``configflow``: the core proposes a deterministic candidate set
(scoped & missing & installable, see ``ToolDoctor.propose_installs``); this shows
each tool with the exact install command, confirms through the shared
gated-write step (capability ``install``, so one session grant covers the batch),
and installs the approved set, reporting each result. Installing is a real system
write, so it never runs without the operator's yes -- unlike ``doctor install
<tool>``, where naming the tool is itself the confirm.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from skuggi.frontend.confirm import Choose, Notify, confirm_write

if TYPE_CHECKING:
    from skuggi.agent.grants import SessionGrants
    from skuggi.tooling.registry import InstallPlan, ToolStatus

# () -> [(binary, plan), ...]; (binary) -> post-install status (None if unknown).
Propose = Callable[[], list[tuple[str, "InstallPlan"]]]
Install = Callable[[str], "ToolStatus | None"]


def run_install_missing(
    *,
    choose: Choose,
    notify: Notify,
    propose: Propose,
    install: Install,
    grants: SessionGrants,
) -> None:
    """Preview the missing scoped tools, confirm once, and install the approved set."""
    candidates = propose()
    if not candidates:
        notify("install: no missing scoped tools to install")
        return
    notify("missing scoped tools to install:")
    for binary, plan in candidates:
        notify(f"  {binary}: {' '.join(plan.argv)} (via {plan.installer})")
    if not confirm_write(
        "install", grants=grants, choose=choose, notify=notify, prompt="Install these?"
    ):
        notify("install cancelled")
        return
    for binary, _plan in candidates:
        status = install(binary)
        if status is not None and status.found:
            notify(f"installed {binary} ({status.version or '?'}) via {status.source}")
        else:
            notify(f"install failed or unavailable for {binary}")
