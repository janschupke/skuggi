"""Install research for an unregistered/unresolvable tool (``core.installer``).

A sub-component of :class:`~skuggi.agent.core.AgentCore`, mirroring
:class:`~skuggi.agent.config_controller.ConfigController`: it does read-only
research -- host facts plus a search of the host's own package managers -- hands
the results to the LLM as *untrusted data*, and returns VALIDATED, grounded
install plans. It never installs; the gated flow
(:func:`skuggi.frontend.installflow.run_install_research`) does, behind the
operator's approval.

The validation in :meth:`InstallResearcher.research` is the security boundary. The
model only *selects* from the search hits; it never emits a command. For every
candidate the harness re-checks that (1) the installer is allow-listed and present
on the host, (2) the exact package token appeared in the search results it was
shown (grounding -- so an invented or attacker-suggested name is rejected), and
(3) the token carries no shell metacharacters -- then rebuilds the argv itself. So
a prompt injection in a package description can never become an executed command:
the worst it can do is name a package that is not in the (deterministic) search
results, which is dropped.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, NamedTuple

from langchain_core.messages import HumanMessage, SystemMessage

from skuggi.agent import prompts
from skuggi.agent.invoke import structured_invoke
from skuggi.agent.protocol import InstallResearch
from skuggi.common.text import safe_cmd_fragment
from skuggi.tooling import probe, websearch
from skuggi.tooling.registry import (
    InstallOutcome,
    InstallPlan,
    PackageHit,
    ResearchResult,
)

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

# At most this many alternates proposed, so the operator reads a short list.
_MAX_CANDIDATES = 3


class _Builder(NamedTuple):
    argv: Callable[[str], tuple[str, ...]]
    requires: str  # the host installer that must be present
    target: str  # "host" | "managed" (pip installs into skuggi's managed venv)


# installer name -> how to build/route it. ``brew-cask`` installs a GUI app and maps
# onto the ``brew`` binary with ``--cask``; ``pip`` installs into skuggi's managed
# venv. This dict IS the allow-list: an installer the model names that is not a key
# here is dropped.
_BUILDERS: dict[str, _Builder] = {
    "brew": _Builder(lambda pkg: ("brew", "install", pkg), "brew", "host"),
    "brew-cask": _Builder(
        lambda pkg: ("brew", "install", "--cask", pkg), "brew", "host"
    ),
    "apt": _Builder(lambda pkg: ("apt-get", "install", "-y", pkg), "apt", "host"),
    "pip": _Builder(lambda pkg: ("pip", "install", pkg), "pip", "managed"),
}


def _render_context(installers: frozenset[str], hits: list[PackageHit]) -> str:
    """The human turn: host facts, then the search hits inside an untrusted fence."""
    lines = [
        f"host package managers available: {', '.join(sorted(installers)) or 'none'}",
        "",
        "<untrusted_search_results>",
    ]
    if hits:
        lines.extend(
            f"[{hit.installer}] {hit.name}"
            + (f" -- {hit.summary}" if hit.summary else "")
            for hit in hits
        )
    else:
        lines.append("(no package-manager matches found)")
    lines.append("</untrusted_search_results>")
    return "\n".join(lines)


class InstallResearcher:
    """Researches how to install a tool, and runs an approved plan."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core

    def research(self, tool: str) -> ResearchResult:
        """Resolve how to install `tool` on this host: grounded plans and/or advice.

        Read-only. Searches the host's package managers (and PyPI, for pip), asks
        the LLM to pick from the results, then validates every pick (allow-listed +
        present installer, the package grounded in the search hits, a
        metacharacter-free token) and rebuilds the argv. Returns at most
        ``_MAX_CANDIDATES`` plans.
        """
        tool = tool.strip()
        installers = probe.available_installers()
        hits = probe.search_packages(tool, installers=installers)
        if "pip" in installers:
            # PyPI has no search API, so this confirms pip packages by name; it is
            # best-effort (no hits when offline) and widens the grounded set only.
            hits = [*hits, *websearch.pypi_candidates(tool)]
        research = self._propose(tool, installers, hits)
        grounded = {(hit.installer, hit.name) for hit in hits}
        plans: list[InstallPlan] = []
        seen: set[tuple[str, str]] = set()
        for candidate in research.candidates:
            installer = candidate.installer.strip()
            package = candidate.package.strip()
            key = (installer, package)
            built = _BUILDERS.get(installer)
            if (
                built is None  # installer not allow-listed
                or key in seen
                or not package
                or built.requires not in installers  # required host installer absent
                or key not in grounded  # not present in the search hits (grounding)
            ):
                continue
            try:  # defensive: hits are already token-filtered, but never trust it
                safe_cmd_fragment(package, field="package")
            except ValueError:
                continue
            seen.add(key)
            plans.append(
                InstallPlan(
                    argv=built.argv(package),
                    target=built.target,
                    installer=installer,
                    rationale=candidate.rationale.strip() or None,
                    source=f"searched:{installer}",
                )
            )
            if len(plans) >= _MAX_CANDIDATES:
                break
        return ResearchResult(plans=tuple(plans), advice=research.advice.strip())

    def install(self, plan: InstallPlan, binary: str) -> InstallOutcome:
        """Run an approved, researched `plan` to install `binary` (the caller gates)."""
        return probe.install_with_plan(
            plan, binary, managed_dir=self._core.settings.managed_tools_dir
        )

    def _propose(
        self, tool: str, installers: frozenset[str], hits: list[PackageHit]
    ) -> InstallResearch:
        """Ask the LLM to select grounded candidates, and/or advise a manual step.

        Called even with no search hits: a tool that is in no package manager (e.g. a
        GitHub-distributed one) still deserves an honest "here is how to get it"
        rather than a bare failure. Any candidate the model returns is still grounded
        against `hits` by the caller, so with no hits only free-text ``advice`` can
        survive -- never an ungrounded install command.
        """
        core = self._core
        system = SystemMessage(
            content=prompts.PROPOSE_INSTALL_INSTRUCTION.format(
                tool=tool,
                limit=_MAX_CANDIDATES,
                installers=", ".join(sorted(_BUILDERS)),
            )
        )
        human = HumanMessage(content=_render_context(installers, hits))
        return structured_invoke(
            core.ensure_llm(),
            InstallResearch,
            [system, human],
            native=core.settings.supports_structured_output(),
        )
