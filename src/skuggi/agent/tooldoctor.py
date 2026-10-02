"""Host-tool probing for the ``doctor``/``install`` verbs (``core.doctor``).

A sub-component of :class:`~skuggi.agent.core.AgentCore`: it reads the live tool
registry and tool-source settings off the core on every call and holds no state
of its own, so a registry reload is reflected without rewiring.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skuggi.tooling import probe

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore
    from skuggi.tooling.registry import RuntimeStatus, ToolStatus


class ToolDoctor:
    """Probes the host for recognized tools, runtimes and net tools."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core

    def tools(self) -> list[ToolStatus]:
        """Probe the host for every recognized tool."""
        core = self._core
        return probe.probe(
            core.registry,
            source=core.settings.tool_source,
            managed_dir=core.settings.managed_tools_dir,
        )

    def runtimes(self) -> list[RuntimeStatus]:
        """Probe the host for the standard runtimes/toolchains."""
        return probe.probe_runtimes()

    def net_tools(self) -> list[RuntimeStatus]:
        """Probe the host for the standard Unix net tools."""
        return probe.probe_net_tools()

    def install(self, binary: str) -> ToolStatus | None:
        """Install one recognized tool; returns its status, or None if unknown."""
        core = self._core
        spec = core.registry.spec_for(binary)
        if spec is None:
            return None
        return probe.install_tool(
            spec,
            source=core.settings.tool_source,
            managed_dir=core.settings.managed_tools_dir,
        )
