"""Interactive, single-field engagement editing (``set engagement <param>``).

Front-end-agnostic like ``scopeflow`` / ``listenerflow`` / the wizard: it collects
one engagement field through a :class:`~skuggi.frontend.prompter.Prompter` and
applies it, choosing the path by the param's kind:

- ``composite`` (osint / threat_model / rules_of_engagement): the wizard's guided
  multi-field widget;
- ``auth`` (hosts / networks / ports / tools / methods / windows / dates /
  ceiling): a diff + gated confirm before writing -- authorization never widens
  silently;
- ``scope``: the natural-language scope editor;
- ``listener``: the interface + port picker;
- ``direct``: the field's own widget (no value) or the parsed value, persisted in
  place.

Both the REPL (``ReplFlows``) and the daemon attach loop build the Prompter +
``wizard.Catalog`` and call :func:`run_param_edit`, so the two surfaces share this
logic exactly as they share ``run_scope_request``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import ValidationError

from skuggi.agent import scope_controller
from skuggi.config.configs import ConfigError
from skuggi.engagement.engagement import ThreatModel
from skuggi.frontend import engagement_params, listenerflow, scopeflow, wizard
from skuggi.frontend.confirm import confirm_write

if TYPE_CHECKING:
    from skuggi.agent.core import AgentCore
    from skuggi.agent.grants import SessionGrants
    from skuggi.frontend.prompter import Prompter


def run_param_edit(  # noqa: PLR0913 -- the edit target + keyword-only collaborators
    core: AgentCore,
    name: str,
    value: str,
    *,
    prompter: Prompter,
    catalog: wizard.Catalog,
    grants: SessionGrants,
) -> None:
    """Edit the engagement field `name` interactively (value optional) and apply it."""
    param = engagement_params.get(name)
    if param is None:  # pragma: no cover -- callers pass a known param
        prompter.notify(f"unknown engagement field: {name}")
        return
    if core.engagement is None:
        prompter.notify("no engagement loaded")
        return
    if param.kind == "scope":
        _run_scope(core, value, prompter=prompter, grants=grants)
        return
    if param.kind == "listener":
        _run_listener(core, prompter=prompter)
        return
    collected = _collect(core, name, value, prompter=prompter, catalog=catalog)
    if collected is None:
        return
    parsed = collected[0]
    if param.kind == "auth":
        _apply_auth(core, name, parsed, prompter=prompter, grants=grants)
    elif name == "threat_model":
        _apply_threat_model(core, parsed, prompter=prompter)
    else:
        _apply_direct(core, name, parsed, prompter=prompter)


def _collect(
    core: AgentCore,
    name: str,
    value: str,
    *,
    prompter: Prompter,
    catalog: wizard.Catalog,
) -> tuple[object] | None:
    """The value for `name`: parsed from `value` if given, else via the field widget.

    Returned as a 1-tuple so a collected ``None`` (e.g. threat-model disabled) is
    distinguishable from an abort (bare ``None``).
    """
    param = engagement_params.get(name)
    if value.strip() and param is not None and param.kind in ("direct", "auth"):
        try:
            return (engagement_params.parse_value(name, value),)
        except ValueError as exc:
            prompter.notify(f"invalid {name}: {exc}")
            return None
    raw = wizard.collect_scope(
        prompter, catalog, existing=core.engagement, only=frozenset({name})
    )
    if raw is None:
        prompter.notify("cancelled")
        return None
    return (raw.get(name),)


def _apply_direct(
    core: AgentCore, name: str, value: object, *, prompter: Prompter
) -> None:
    """Persist a non-authorization field in place (no gate)."""
    try:
        core.engagement_mgr.update_engagement_fields({name: value})
    except ConfigError as exc:
        prompter.notify(f"could not edit {name}: {exc}")
        return
    prompter.notify(f"{name} updated")


def _apply_threat_model(core: AgentCore, value: object, *, prompter: Prompter) -> None:
    """Set or clear the threat model, versioning the change in the ledger."""
    model = ThreatModel.model_validate(value) if value else None
    core.engagement_mgr.update_threat_model(model)
    prompter.notify("threat model " + ("updated" if model else "cleared"))


def _apply_auth(
    core: AgentCore,
    name: str,
    value: object,
    *,
    prompter: Prompter,
    grants: SessionGrants,
) -> None:
    """Apply an authorization-bearing edit behind a diff + gated confirm."""
    before = core.engagement
    assert before is not None  # noqa: S101 -- guarded by the caller
    try:
        after = scope_controller.build_field_edit(before, name, value)
    except ValidationError as exc:
        prompter.notify(f"invalid {name}: {exc}")
        return
    rows = scope_controller.changed_fields(before, after)
    if not rows:
        prompter.notify(f"{name}: no change")
        return
    prompter.notify("proposed scope changes:")
    for field, old, new in rows:
        prompter.notify(f"  {field}: {old} -> {new}")
    if not confirm_write(
        "scope-edit",
        grants=grants,
        choose=prompter.choose,
        notify=prompter.notify,
        agentic=False,
    ):
        prompter.notify("scope unchanged")
        return
    core.engagement_mgr.apply_engagement_scope(after)
    prompter.notify(f"{name} updated")


def _run_scope(
    core: AgentCore, request: str, *, prompter: Prompter, grants: SessionGrants
) -> None:
    """Run the natural-language scope editor (``set engagement scope <request>``)."""
    if not request.strip():
        prompter.notify("usage: set engagement scope <request>")
        return
    scopeflow.run_scope_request(
        request,
        choose=prompter.choose,
        notify=prompter.notify,
        propose=core.scope.propose,
        preview=core.scope.preview,
        apply=core.scope.apply,
        grants=grants,
    )


def _run_listener(core: AgentCore, *, prompter: Prompter) -> None:
    """Run the listener interface/port picker (``set engagement listener``)."""
    from skuggi.engagement.runtime_env import EngagementEnv  # noqa: PLC0415
    from skuggi.tooling import probe  # noqa: PLC0415

    def apply(lhost: str, lport: str | None) -> None:
        env = EngagementEnv.model_validate(
            {**core.env.model_dump(), "lhost": lhost, "lport": lport}
        )
        core.engagement_mgr.apply_env(env)
        shown = f"{lhost}:{lport}" if lport else lhost
        prompter.notify(f"listener set to {shown}")

    listenerflow.run_set_listener(
        interfaces=probe.local_interfaces(),
        choose=prompter.choose,
        ask=prompter.ask,
        notify=prompter.notify,
        apply=apply,
    )
