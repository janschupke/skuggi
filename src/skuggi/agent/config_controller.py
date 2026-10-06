"""App-settings editing for the ``config`` verb (``core.config``).

A sub-component of :class:`~skuggi.agent.core.AgentCore`. The pure kernels (which
keys are editable, rendering, value coercion) live in
:mod:`skuggi.config.editing`; this layer adds the live session glue -- persisting
to ``config.json`` and hot-applying ``provider``/``mode`` back through the core's
switch methods -- and the natural-language proposal path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from langchain_core.messages import HumanMessage, SystemMessage

from skuggi.agent import prompts
from skuggi.agent.invoke import structured_invoke
from skuggi.agent.protocol import ConfigProposal
from skuggi.config import editing
from skuggi.config.config import config_path, write_config

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore


class ConfigController:
    """Shows and edits app settings, and maps NL requests to config edits."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core

    def settable_keys(self) -> frozenset[str]:
        """Config keys the operator may edit -- every setting except secrets."""
        return editing.settable_keys()

    def summary(self) -> str:
        """Every setting, one per line, with credentials redacted."""
        return editing.render_summary(self._core.settings)

    def line(self, arg: str) -> str | None:
        """Handle the mechanical `config` forms; None means "escalate to the LLM".

        ``config`` / ``config show`` prints the settings; ``config <key> <value>``
        for a known setting applies it. A first word that is not a setting is a
        natural-language request, which the interactive front-end escalates.
        """
        key, _, rest = arg.strip().partition(" ")
        if not key or key == "show":
            return self.summary()
        if key not in self.settable_keys():
            return None
        value = rest.strip()
        if not value:
            return f"usage: config {key} <value>"
        return self.apply(key, value)

    def apply(self, key: str, value: str) -> str:
        """Validate, persist and (where possible) hot-apply one setting.

        Coerces `value` to the field's type, writes it to ``configs/config.json``
        (never a secret), and applies ``provider``/``mode`` to the live session
        through the core; other keys persist and take effect on restart.
        """
        core = self._core
        result = editing.coerce_value(key, value)
        if isinstance(result, str):
            return result
        json_value = result.json_value
        # Apply the live switch *before* persisting: a failed provider/mode change
        # must not leave the new value in config.json, where it would re-apply
        # (and perhaps fail to boot) on the next restart.
        try:
            if key == "provider":
                core.provider_kernel.set_provider(str(result.value))
                applied = True
            elif key == "mode":
                core.set_mode(str(result.value))
                applied = True
            else:
                core.settings = core.settings.model_copy(update={key: result.value})
                applied = False
        except (ValueError, RuntimeError, ImportError) as exc:
            return f"config: {key} not changed; the live switch failed: {exc}"
        write_config(config_path(), {key: json_value})
        tail = "applied live" if applied else "written; restart to apply"
        return f"config: {key} = {json_value} ({tail})"

    def propose(self, request: str) -> list[tuple[str, str]]:
        """Ask the LLM to map a natural-language request to config edits.

        Returns only proposals whose key is an editable setting; the front-end
        shows them and applies on confirmation. Never proposes a secret. The reply
        is a strict ``ConfigProposal``, so no free-text key=value parsing.
        """
        core = self._core
        keys = ", ".join(sorted(self.settable_keys()))
        proposal = structured_invoke(
            core.ensure_llm(),
            ConfigProposal,
            [
                SystemMessage(
                    content=prompts.PROPOSE_CONFIG_INSTRUCTION.format(keys=keys)
                ),
                HumanMessage(content=request),
            ],
            native=core.settings.supports_structured_output(),
        )
        settable = self.settable_keys()
        return [
            (edit.key.strip(), edit.value.strip())
            for edit in proposal.edits
            if edit.key.strip() in settable
        ]
