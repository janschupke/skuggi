"""System- and harness-awareness blocks for the agent's request context.

Two pre-rendered text blocks the core hands the graph (via ``GraphDeps``) so the
agent reasons with knowledge of the host it runs on -- OS, which installers
exist, which *scoped* tools are installed vs missing -- and of the harness it
runs inside -- the verb/noun catalogue plus the saved ``cmd`` aliases. Both are
plain metadata: no host file contents, no secrets.

Kept out of :mod:`skuggi.agent.protocol` (which must not import tooling or the
front-ends) and out of the front-ends (which only style). The renderers are pure
functions over already-gathered data, so a test pins the exact text. The one host
touch -- :func:`skuggi.tooling.probe.probe_presence` -- is deliberately
version-free (just ``shutil.which``), cheap enough to run on every graph rebuild.
"""

from __future__ import annotations

import platform
from typing import TYPE_CHECKING

from skuggi.frontend import verbs
from skuggi.tooling import probe

if TYPE_CHECKING:
    from pathlib import Path

    from skuggi.engagement.engagement import EngagementConfig
    from skuggi.tooling.registry import ToolRegistry, ToolStatus


def _os_line() -> str:
    """The host OS/arch, e.g. ``Darwin 25.4.0 (arm64)``."""
    base = " ".join(b for b in (platform.system(), platform.release()) if b)
    machine = platform.machine()
    base = base or "unknown"
    return f"{base} ({machine})" if machine else base


def _scoped_statuses(
    statuses: list[ToolStatus], engagement: EngagementConfig | None
) -> list[ToolStatus]:
    """The probed tools this engagement's scope reaches (by binary or method).

    Mirrors ``doctor.filter_tool_statuses(..., "scoped", ...)`` but inlined to
    keep this module off the doctor's front-end import chain. Empty with no
    engagement -- the agent then sees only OS/installer facts, not a tool list.
    """
    if engagement is None:
        return []
    return [
        s
        for s in statuses
        if s.spec.binary in engagement.allowed_tools
        or s.spec.method in engagement.allowed_methods
    ]


def network_posture_line(
    *, backend: str, container_network: str, egress_proxy: str | None
) -> str:
    """One line telling the agent how its commands reach the network.

    So the worker reasons with its own confinement in view -- e.g. that recon
    egress is public-only (an OSINT/research fetch cannot reach an internal host),
    and whether tool traffic is direct, proxied, or namespaced by a container.
    """
    if backend == "container":
        tool = f"container, --network {container_network}"
    elif egress_proxy:
        tool = "host subprocess via egress proxy"
    else:
        tool = "direct host network (no egress proxy)"
    return (
        f"tool execution: {tool}; "
        "recon egress: public-only (OSINT/research cannot reach "
        "private/loopback/metadata hosts)"
    )


def system_facts_block(
    registry: ToolRegistry,
    engagement: EngagementConfig | None,
    *,
    source: str,
    managed_dir: Path,
    network: str = "",
) -> str:
    """Render the host-awareness block: OS, installers, scoped tool presence.

    ``network`` is the optional :func:`network_posture_line`, appended so the agent
    also sees how its commands reach the network.
    """
    installers = sorted(probe.available_installers())
    lines = [
        f"os: {_os_line()}",
        f"installers available: {', '.join(installers) or '(none)'}",
    ]
    scoped = _scoped_statuses(
        probe.probe_presence(registry, source=source, managed_dir=managed_dir),
        engagement,
    )
    if scoped:
        installed = sorted(s.spec.binary for s in scoped if s.found)
        missing = sorted(s.spec.binary for s in scoped if not s.found)
        lines.append(f"scoped tools installed: {', '.join(installed) or '(none)'}")
        lines.append(f"scoped tools missing: {', '.join(missing) or '(none)'}")
    if network:
        lines.append(f"network: {network}")
    return "\n".join(lines)


def harness_catalogue_block(command_names: tuple[str, ...]) -> str:
    """Render the harness command catalogue: the verb/noun groups + cmd aliases.

    Grounds the agent so ``ask "how do I ... with the harness"`` is answerable.
    Built from the same drift-guarded ``verbs.help_sections`` the ``help`` verb
    renders, so it never drifts from the real command surface.
    """
    lines = [
        f"{title}: " + "; ".join(f"{inv} — {summary}" for inv, summary in rows)
        for title, rows in verbs.help_sections()
    ]
    lines.append(f"saved cmd aliases: {', '.join(command_names) or '(none saved)'}")
    return "\n".join(lines)
