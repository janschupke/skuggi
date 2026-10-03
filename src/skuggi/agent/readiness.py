"""The one readiness model: is skuggi ready, and what is still pending.

"No engagement loaded" and "no model configured" used to be re-phrased in the
shell banner, the REPL banner, the REPL's boot hints and the daemon -- each in
its own words, drifting apart. This computes those signals once, as a pure
:class:`Readiness` snapshot of an :class:`~skuggi.agent.core.AgentCore`, and
renders the next-step notes once (through :func:`skuggi.frontend.verbs.cmd`, so a
hint is phrased for whichever surface shows it). Every banner and the ``show
status`` verb consume this, so the states and their wording cannot drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from skuggi.frontend import verbs
from skuggi.providers import providers

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore


@dataclass(frozen=True, slots=True)
class PendingStep:
    """One thing the operator still needs to do, phrased once.

    ``invocation`` is the remedy verb WITHOUT a surface prefix (``set provider``,
    ``engagement setup``); the renderer runs it through ``verbs.cmd`` for the
    surface in hand. ``message`` is the one canonical description of the remedy.
    """

    invocation: str
    message: str


@dataclass(frozen=True, slots=True)
class Readiness:
    """A snapshot of whether the harness is ready to work, and what is pending."""

    provider: str
    model: str
    has_llm: bool
    provider_configured: bool
    engagement: str | None
    autonomous: bool
    mode: str
    warnings: tuple[str, ...]
    stale_configs: tuple[str, ...] = ()

    @property
    def pending(self) -> tuple[PendingStep, ...]:
        """The ordered next steps: configure a model, then scope an engagement."""
        steps: list[PendingStep] = []
        if not self.has_llm or not self.provider_configured:
            steps.append(PendingStep("set provider", "configure a model provider"))
        if self.engagement is None:
            steps.append(PendingStep("engagement setup", "scope an engagement"))
        return tuple(steps)


def from_core(core: AgentCore) -> Readiness:
    """Snapshot `core`'s readiness, reading every signal from the live core."""
    provider = core.provider
    return Readiness(
        provider=provider,
        model=core.model or core.settings.model_for(provider),
        has_llm=core.llm is not None,
        provider_configured=providers.is_configured(core.settings, provider),
        engagement=core.engagement.name if core.engagement else None,
        autonomous=core.autonomous,
        mode=core.mode,
        warnings=tuple(core.warnings),
        stale_configs=core.stale_configs(),
    )


def glance(readiness: Readiness) -> str:
    """The one-line status glance, identical across the banner and `show status`."""
    return (
        f"mode {readiness.mode} · provider {readiness.provider} "
        f"· model {readiness.model} · engagement {readiness.engagement or '(none)'} "
        f"· autonomous {'ON' if readiness.autonomous else 'off'}"
    )


def render_banner_notes(readiness: Readiness, surface: verbs.Surface) -> list[str]:
    """The banner's note lines: boot warnings verbatim, then each pending step.

    Each pending step is phrased once here and formatted for `surface`, so the
    shell, the chat loop and the REPL all point at the command that runs there.
    """
    notes = list(readiness.warnings)
    notes += [
        f"{step.message} -- run {verbs.cmd(step.invocation, surface)}"
        for step in readiness.pending
    ]
    if readiness.stale_configs:
        names = ", ".join(readiness.stale_configs)
        notes.append(
            f"{len(readiness.stale_configs)} config file(s) behind the packaged "
            f"templates ({names}) -- run {verbs.cmd('reconcile', surface)}"
        )
    return notes
