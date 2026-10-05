"""Natural-language edits to the engagement authorization scope.

A sub-component of :class:`~skuggi.agent.core.AgentCore`, mirroring
:class:`~skuggi.agent.config_controller.ConfigController`: it maps an operator
request to a strict :class:`~skuggi.agent.protocol.ScopeProposal` (typed edits to
the editable scope fields only), previews the result as a per-field diff, and --
on confirmation, through the shared gated-write step -- rewrites ``scope.json``
and hot-reloads it. Scope governs *authorization*, so every edit is re-validated
by :class:`EngagementConfig` (``model_copy(update=...)`` does NOT re-validate) and
always shown as a diff before it is written -- never widened silently.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from langchain_core.messages import HumanMessage, SystemMessage

from skuggi.agent import prompts
from skuggi.agent.invoke import structured_invoke
from skuggi.agent.protocol import (
    SCOPE_FIELDS,
    ScopeEdit,
    ScopeProposal,
)
from skuggi.engagement.engagement import EngagementConfig

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore

# The set-valued scope fields take add/remove of one element; the scalar takes set.
_SET_FIELDS = frozenset(
    {"allowed_hosts", "target_networks", "allowed_tools", "allowed_methods"}
)
_SCALAR_FIELDS = frozenset({"autonomous_ceiling"})


def _is_valid(edit: ScopeEdit) -> bool:
    """Whether an edit's action matches its field kind (add/remove vs. set)."""
    if edit.field in _SET_FIELDS:
        return edit.action in ("add", "remove")
    return edit.field in _SCALAR_FIELDS and edit.action == "set"


def apply_scope_edits(
    engagement: EngagementConfig, edits: tuple[ScopeEdit, ...]
) -> EngagementConfig:
    """Compute the edited engagement, re-validated. Raises on an invalid value.

    Works on the JSON dump so the result goes back through full
    ``EngagementConfig`` validation -- a bad CIDR, host or tier is rejected here,
    not written. Pure: it never touches disk or the core.
    """
    raw = engagement.model_dump(mode="json")
    for edit in edits:
        if edit.field in _SCALAR_FIELDS:
            raw[edit.field] = edit.value
            continue
        current = [str(v) for v in (raw.get(edit.field) or [])]
        if edit.action == "add":
            if edit.value not in current:
                current.append(edit.value)
        else:  # remove
            current = [v for v in current if v != edit.value]
        raw[edit.field] = current
    return EngagementConfig.model_validate(raw)


def _render(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) or "(none)"
    return str(value)


def scope_diff(
    before: EngagementConfig, after: EngagementConfig
) -> list[tuple[str, str, str]]:
    """``(field, old, new)`` for each scope field the edits changed."""
    b = before.model_dump(mode="json")
    a = after.model_dump(mode="json")
    return [
        (field, _render(b.get(field)), _render(a.get(field)))
        for field in SCOPE_FIELDS
        if b.get(field) != a.get(field)
    ]


class ScopeController:
    """Maps NL requests to scope edits, previews them, and applies on confirm."""

    def __init__(self, core: AgentCore) -> None:
        self._core = core

    def propose(self, request: str) -> list[ScopeEdit]:
        """Ask the LLM for scope edits; keep only the well-formed ones."""
        core = self._core
        fields = ", ".join(SCOPE_FIELDS)
        proposal = structured_invoke(
            core.ensure_llm(),
            ScopeProposal,
            [
                SystemMessage(
                    content=prompts.PROPOSE_SCOPE_INSTRUCTION.format(fields=fields)
                ),
                HumanMessage(content=request),
            ],
            native=core.settings.supports_structured_output(),
        )
        return [edit for edit in proposal.edits if _is_valid(edit)]

    def preview(self, edits: list[ScopeEdit]) -> list[tuple[str, str, str]]:
        """The per-field diff the edits would produce. Raises on an invalid value."""
        engagement = self._require_engagement()
        after = apply_scope_edits(engagement, tuple(edits))
        return scope_diff(engagement, after)

    def apply(self, edits: list[ScopeEdit]) -> str:
        """Validate, persist and hot-reload the edited scope. Raises on invalid."""
        engagement = self._require_engagement()
        after = apply_scope_edits(engagement, tuple(edits))
        self._core.apply_engagement_scope(after)
        return f"scope updated: {len(scope_diff(engagement, after))} field(s) changed"

    def _require_engagement(self) -> EngagementConfig:
        engagement = self._core.engagement
        if engagement is None:
            msg = "no engagement loaded; cannot edit scope"
            raise ValueError(msg)
        return engagement
