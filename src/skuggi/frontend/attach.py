"""Interactive attach-loop handlers for the wrapped-shell daemon.

The daemon's persistent attach session (:meth:`Daemon.run_attached`) drives the
multi-turn interactive flows -- the engagement wizard, the cmd editor, the
natural-language config/scope confirms, cmd suggest, and the gated install -- over
the socket by round-tripping prompt frames to the thin client. Each flow is a free
function here taking its dependencies explicitly (the warm ``core``, the daemon's
``lock``, and the connection's ``read_line``/``emit``), so the ``Daemon`` class
stays the request handler and this interactive sub-system lives on its own. The
``is_*`` classifiers decide which flow (if any) a line opens.
"""

from __future__ import annotations

import json
import zoneinfo
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

from skuggi.agent import protocol
from skuggi.common import palette
from skuggi.common.logs import get_logger
from skuggi.frontend import (
    cmdflow,
    configflow,
    dispatch,
    installflow,
    scopeflow,
    setup,
    verbs,
    wizard,
)
from skuggi.frontend.prompter import Prompter

if TYPE_CHECKING:
    import threading

    from skuggi.agent.core import AgentCore

log = get_logger(__name__)

# A line of operator input (None when the client disconnects), and a response
# frame sink -- the attach connection's two ends, threaded into every flow.
ReadLine = Callable[[], str | None]
Emit = Callable[[dict[str, object]], None]


def engagement_catalog(core: AgentCore) -> wizard.Catalog:
    """The option sources the wizard offers (zones, tools, enums)."""
    tools = tuple(spec.binary for spec in core.registry.tools)
    return wizard.Catalog(
        timezones=tuple(sorted(zoneinfo.available_timezones())),
        tools=tools,
        methods=palette.methods(),
        methodologies=protocol.METHODOLOGIES,
        taxonomies=protocol.TAXONOMIES,
        stances=protocol.STANCES,
    )


# ----- engagement wizard -----------------------------------------------------


def is_wizard(line: str) -> bool:
    """Whether `line` opens the interactive engagement wizard."""
    verb, rest = verbs.split_verb(line)
    parts = rest.split()
    return verb == "engagement" and bool(parts) and parts[0] in wizard.WIZARD_ARGS


def attach_wizard(
    core: AgentCore, lock: threading.Lock, read_line: ReadLine, emit: Emit
) -> None:
    """Run the engagement wizard over the attach connection.

    Menus (``{"choose"}``) and the checklist (``{"multiselect"}``) round-trip to
    the client, which renders prompt_toolkit widgets locally; autocomplete is
    REPL-only and degrades to a plain ``{"ask"}`` prompt here. The step bar and
    status lines ride ``{"chunk"}``. The turn closes with a non-exit ``end`` frame.
    """

    def ask(prompt: str) -> str | None:
        emit({"ask": prompt})
        return read_line()

    def ask_complete(
        prompt: str, _candidates: Sequence[str], _default: str | None
    ) -> str | None:
        emit({"ask": prompt})  # autocomplete is REPL-only; label carries [current]
        return read_line()

    def choose(prompt: str, options: list[str], default: str | None) -> str | None:
        emit({"choose": {"prompt": prompt, "options": options, "default": default}})
        return read_line()

    def multiselect(
        prompt: str, options: Sequence[str], preselected: Sequence[str]
    ) -> list[str] | None:
        emit(
            {
                "multiselect": {
                    "prompt": prompt,
                    "options": list(options),
                    "preselected": list(preselected),
                }
            }
        )
        line = read_line()
        if line is None:
            return None
        try:
            picks = json.loads(line)
        except json.JSONDecodeError:
            return None
        return [str(p) for p in picks] if isinstance(picks, list) else None

    def confirm(prompt: str, default: bool) -> bool | None:
        emit(
            {
                "choose": {
                    "prompt": prompt,
                    "options": ["yes", "no"],
                    "default": "yes" if default else "no",
                }
            }
        )
        line = read_line()
        return None if line is None else line == "yes"

    def notify(text: str) -> None:
        emit({"chunk": text + "\n"})

    def progress(step: int, total: int, label: str) -> None:
        emit({"chunk": f"[{step}/{total}] {label}\n"})

    prompter = Prompter(
        ask=ask,
        ask_complete=ask_complete,
        choose=choose,
        multiselect=multiselect,
        confirm=confirm,
        notify=notify,
        progress=progress,
    )
    core.note_interaction("engagement", "setup")
    with lock:
        try:
            wizard.run_wizard(
                prompter,
                core.create_engagement,
                engagement_catalog(core),
                existing=core.engagement,
            )
        except Exception as exc:  # defensive: never kill the daemon thread
            log.exception("engagement wizard failed")
            emit({"chunk": f"engagement setup failed: {exc}\n"})
    emit({"end": True, "exit": False})


# ----- cmd editor (cmd add / edit) -------------------------------------------


def is_cmd_editor(line: str) -> bool:
    """Whether `line` opens the interactive cheatsheet editor (cmd add/edit)."""
    verb, rest = verbs.split_verb(line)
    parts = rest.split()
    return (
        verb == "cmd"
        and bool(parts)
        and parts[0] in (cmdflow.ADD_ARGS | cmdflow.EDIT_ARGS)
    )


def attach_cmd_editor(
    core: AgentCore, lock: threading.Lock, line: str, read_line: ReadLine, emit: Emit
) -> None:
    """Run the cheatsheet editor over the attach connection (like the wizard)."""

    def ask(prompt: str) -> str | None:
        emit({"ask": prompt})
        return read_line()

    def notify(text: str) -> None:
        emit({"chunk": text + "\n"})

    _, rest = verbs.split_verb(line)
    parts = rest.split()
    sub, name = parts[0], (parts[1] if len(parts) > 1 else "")
    core.note_interaction("cmd", rest)
    with lock:
        if sub in cmdflow.EDIT_ARGS:
            existing = core.commands.alias_for(name)
            if existing is None:
                notify(f"unknown alias {name!r}")
            else:
                cmdflow.run_cmd_editor(
                    ask,
                    lambda raw: core.cmds.update(name, raw),
                    notify,
                    existing=existing,
                )
        else:
            cmdflow.run_cmd_editor(ask, core.cmds.add, notify)
    emit({"end": True, "exit": False})


# ----- set provider / model (no-value pickers) -------------------------------


def is_set_interactive(line: str) -> bool:
    """Whether `line` is ``set provider``/``set model`` with no value (a picker).

    Only the no-value forms prompt; ``set provider openai`` stays a one-shot.
    """
    verb, rest = verbs.split_verb(line)
    parts = rest.split()
    return verb == "set" and len(parts) == 1 and parts[0] in {"provider", "model"}


def attach_set(
    core: AgentCore, lock: threading.Lock, line: str, read_line: ReadLine, emit: Emit
) -> None:
    """Run ``set provider`` / ``set model`` interactively over the attach loop.

    ``set provider`` (no name) is the full guided provider+credential+model flow;
    ``set model`` (no name) picks a model for the current provider.
    """

    def ask(prompt: str) -> str | None:
        emit({"ask": prompt})
        return read_line()

    def choose(prompt: str, options: list[str], default: str | None) -> str | None:
        emit({"choose": {"prompt": prompt, "options": options, "default": default}})
        return read_line()

    def notify(text: str) -> None:
        emit({"chunk": text + "\n"})

    _, rest = verbs.split_verb(line)
    noun = rest.split()[0]
    core.note_interaction("set", rest)
    with lock:
        if noun == "provider":
            setup.run_setup(core, ask, choose, notify)
        else:
            setup.run_model_select(core, core.provider, ask, choose, notify)
    emit({"end": True, "exit": False})


# ----- natural-language config escalation ------------------------------------


def is_config_request(core: AgentCore, line: str) -> bool:
    """Whether `line` is a natural-language ``set config`` request (escalation)."""
    verb, rest = verbs.split_verb(line)
    if verb != "set":
        return False
    noun, _, tail = rest.partition(" ")
    if noun != "config":
        return False
    parts = tail.split(maxsplit=1)
    if not parts or parts[0] == "show":
        return False
    return parts[0] not in core.config.settable_keys()


def attach_config(
    core: AgentCore, lock: threading.Lock, arg: str, read_line: ReadLine, emit: Emit
) -> None:
    """Run the LLM config escalation over the attach connection."""

    def choose(prompt: str, options: list[str], default: str | None) -> str | None:
        emit({"choose": {"prompt": prompt, "options": options, "default": default}})
        return read_line()

    core.note_interaction("config", arg)
    with lock:
        configflow.run_config_request(
            arg,
            choose=choose,
            notify=lambda text: emit({"chunk": text + "\n"}),
            propose=core.config.propose,
            apply=core.config.apply,
            grants=core.grants,
        )
    emit({"end": True, "exit": False})


# ----- cmd suggest -----------------------------------------------------------


def is_cmd_suggest(line: str) -> bool:
    """Whether `line` is ``cmd suggest <request>`` (interactive)."""
    verb, rest = verbs.split_verb(line)
    parts = rest.split()
    return (
        verb == "cmd"
        and bool(parts)
        and parts[0] in cmdflow.SUGGEST_ARGS
        and len(parts) > 1
    )


def attach_cmd_suggest(
    core: AgentCore,
    lock: threading.Lock,
    request: str,
    read_line: ReadLine,
    emit: Emit,
) -> None:
    """Run the cmd-suggest confirm flow over the attach connection."""

    def choose(prompt: str, options: list[str], default: str | None) -> str | None:
        emit({"choose": {"prompt": prompt, "options": options, "default": default}})
        return read_line()

    core.note_interaction("cmd", f"suggest {request}")
    with lock:
        cmdflow.run_cmd_suggest(
            request,
            choose=choose,
            notify=lambda text: emit({"chunk": text + "\n"}),
            propose=core.cmds.propose,
            preview=core.cmds.preview_proposal,
            apply=core.cmds.apply_proposal,
            grants=core.grants,
        )
    emit({"end": True, "exit": False})


# ----- scope edit ------------------------------------------------------------


def is_scope_request(line: str) -> bool:
    """Whether `line` is a ``set scope <request>`` (always interactive)."""
    verb, rest = verbs.split_verb(line)
    if verb != "set":
        return False
    noun, _, tail = rest.partition(" ")
    return noun == "scope" and bool(tail.strip())


def attach_scope(
    core: AgentCore,
    lock: threading.Lock,
    request: str,
    read_line: ReadLine,
    emit: Emit,
) -> None:
    """Run the scope-edit confirm flow over the attach connection."""

    def choose(prompt: str, options: list[str], default: str | None) -> str | None:
        emit({"choose": {"prompt": prompt, "options": options, "default": default}})
        return read_line()

    core.note_interaction("set", f"scope {request}")
    with lock:
        scopeflow.run_scope_request(
            request,
            choose=choose,
            notify=lambda text: emit({"chunk": text + "\n"}),
            propose=core.scope.propose,
            preview=core.scope.preview,
            apply=core.scope.apply,
            grants=core.grants,
        )
    emit({"end": True, "exit": False})


# ----- doctor install missing ------------------------------------------------


def is_install_missing(line: str) -> bool:
    """Whether `line` is ``doctor install missing`` (the gated install flow)."""
    verb, rest = verbs.split_verb(line)
    return verb == "doctor" and dispatch.doctor_install_target(rest) == "missing"


def attach_install_missing(
    core: AgentCore, lock: threading.Lock, read_line: ReadLine, emit: Emit
) -> None:
    """Install the missing scoped tools over the attach connection."""

    def choose(prompt: str, options: list[str], default: str | None) -> str | None:
        emit({"choose": {"prompt": prompt, "options": options, "default": default}})
        return read_line()

    core.note_interaction("doctor", "install missing")
    with lock:
        installflow.run_install_missing(
            choose=choose,
            notify=lambda text: emit({"chunk": text + "\n"}),
            propose=core.doctor.propose_installs,
            install=core.doctor.install,
            grants=core.grants,
        )
    emit({"end": True, "exit": False})
