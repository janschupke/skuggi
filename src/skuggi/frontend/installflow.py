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
from contextlib import AbstractContextManager, nullcontext
from typing import TYPE_CHECKING

from skuggi.frontend.confirm import Choose, Notify, confirm_write

if TYPE_CHECKING:
    from skuggi.agent.grants import SessionGrants
    from skuggi.tooling.registry import (
        InstallOutcome,
        InstallPlan,
        ResearchResult,
        ToolStatus,
    )

# () -> [(binary, plan), ...]; (binary) -> post-install status (None if unknown).
Propose = Callable[[], list[tuple[str, "InstallPlan"]]]
Install = Callable[[str], "ToolStatus | None"]
# (tool) -> researched plans/advice; (plan, tool) -> the ad-hoc install outcome.
Research = Callable[[str], "ResearchResult"]
InstallPlanRunner = Callable[["InstallPlan", str], "InstallOutcome"]
# (label) -> a context manager held open across the blocking install subprocess,
# so the front-end can show live "installing ..." progress (a spinner on the REPL,
# a `pending` frame driving the client spinner over the attach socket). The default
# is inert, so a caller that does not care about progress can omit it.
Pending = Callable[[str], AbstractContextManager[object]]


def _no_pending(_label: str) -> AbstractContextManager[object]:
    """Default `Pending`: no progress affordance (used by tests and simple callers)."""
    return nullcontext()


def run_install_missing(  # noqa: PLR0913 -- keyword-only collaborators + the progress hook
    *,
    choose: Choose,
    notify: Notify,
    propose: Propose,
    install: Install,
    grants: SessionGrants,
    pending: Pending = _no_pending,
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
    total = len(candidates)
    for index, (binary, _plan) in enumerate(candidates, start=1):
        # Each install is a blocking subprocess (up to minutes). Hold a pending
        # affordance open across it so the operator sees progress, not a frozen
        # shell -- the whole point of threading `pending` through.
        with pending(f"installing {binary} ({index} of {total})"):
            status = install(binary)
        if status is not None and status.found:
            notify(f"installed {binary} ({status.version or '?'}) via {status.source}")
        else:
            notify(f"install failed or unavailable for {binary}")


def run_install_research(  # noqa: PLR0913 -- keyword-only collaborators + the progress hook
    tool: str,
    *,
    choose: Choose,
    notify: Notify,
    research: Research,
    install: InstallPlanRunner,
    grants: SessionGrants,
    pending: Pending = _no_pending,
) -> None:
    """Research how to install `tool`, preview the plan(s), confirm once, install.

    The escalation when a tool is not in the registry (or has no usable install
    key): the researcher resolves candidates from the host's package managers, this
    previews the exact command(s) and their rationale, gates the write through the
    shared confirm (capability ``install``, marked agentic -- the model proposed
    it), and installs the approved plans, stopping at the first that succeeds.
    """
    result = research(tool)
    if not result.plans:
        notify(
            f"install research: {result.advice}"
            if result.advice
            else f"install research: found no way to install {tool!r} on this host"
        )
        return
    notify(f"researched install plan(s) for {tool}:")
    for plan in result.plans:
        why = f"  -- {plan.rationale}" if plan.rationale else ""
        notify(f"  {' '.join(plan.argv)} (via {plan.installer}){why}")
    if not confirm_write(
        "install",
        grants=grants,
        choose=choose,
        notify=notify,
        prompt=f"Install {tool} using the researched plan?",
        agentic=True,
    ):
        notify("install cancelled")
        return
    total = len(result.plans)
    for index, plan in enumerate(result.plans, start=1):
        with pending(f"installing {tool} ({index} of {total}): {' '.join(plan.argv)}"):
            outcome = install(plan, tool)
        if outcome.installed:
            notify(f"installed {tool} via {outcome.source}")
            return  # alternates are fallbacks; the first success wins
        notify(f"install attempt failed: {' '.join(plan.argv)}")
    notify(f"install research: none of the researched plans installed {tool}")
