"""Host-tool probing for the ``doctor``/``install`` verbs (``core.doctor``).

A sub-component of :class:`~skuggi.agent.core.AgentCore`: it reads the live tool
registry and tool-source settings off the core on every call and holds no state
of its own, so a registry reload is reflected without rewiring.
"""

from __future__ import annotations

import platform
from typing import TYPE_CHECKING

from skuggi.config.configs import ConfigError, load_registry
from skuggi.tooling import probe
from skuggi.tooling.registry import ToolRegistry

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore
    from skuggi.tooling.registry import InstallPlan, RuntimeStatus, ToolStatus


class ToolDoctor:
    """Probes the host for recognized tools, runtimes and net tools."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core

    def full_registry(self) -> ToolRegistry:
        """The complete recognized-tool registry (NOT the mode-filtered one).

        ``core.registry`` is scoped to the active mode by ``for_mode`` (blueteam
        drops the offensive tools and vice-versa), which is correct for the guard
        but WRONG for ``doctor``: the operator must see every tool the harness
        recognizes, whatever mode they are in, matching the ``skuggi-doctor`` CLI.
        So doctor reads the unfiltered registry from disk; a missing/broken
        registry degrades to empty rather than raising.
        """
        try:
            return load_registry(self._core.settings.registry_path)
        except ConfigError:
            return ToolRegistry()

    def tools(self) -> list[ToolStatus]:
        """Probe the host for every recognized tool (the full, unfiltered set)."""
        core = self._core
        return probe.probe(
            self.full_registry(),
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

    def propose_installs(self) -> list[tuple[str, InstallPlan]]:
        """Scoped-but-missing tools that are installable on this host.

        The deterministic candidate set for the gated install flow (no LLM): the
        engagement's scoped tools (by binary or method) that are absent AND have
        an install command for an available installer. Each pairs the binary with
        the exact, not-yet-run install plan so the flow can preview it. Empty with
        no engagement.
        """
        core = self._core
        engagement = core.engagement
        if engagement is None:
            return []
        source = core.settings.tool_source
        system = platform.system()
        statuses = probe.probe_presence(
            core.registry, source=source, managed_dir=core.settings.managed_tools_dir
        )
        out: list[tuple[str, InstallPlan]] = []
        for status in statuses:
            spec = status.spec
            scoped = (
                spec.binary in engagement.allowed_tools
                or spec.method in engagement.allowed_methods
            )
            if status.found or not scoped:
                continue
            plan = probe.select_install(spec, source=source, system=system)
            if plan is not None:
                out.append((spec.binary, plan))
        return out
