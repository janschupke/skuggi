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
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING

from skuggi.agent import protocol
from skuggi.common import palette
from skuggi.common.logs import get_logger
from skuggi.engagement.scope import OSINT_SOURCES
from skuggi.frontend import (
    cmdflow,
    configflow,
    dispatch,
    engagement_params,
    engagementflow,
    installflow,
    memoryflow,
    setup,
    verbs,
    wizard,
)
from skuggi.frontend.confirm import Choose, Notify
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
        osint_sources=OSINT_SOURCES,
    )


# ----- engagement wizard -----------------------------------------------------


def is_wizard(line: str) -> bool:
    """Whether `line` opens the engagement wizard (``set engagement setup``)."""
    verb, rest = verbs.split_verb(line)
    noun, _, tail = rest.partition(" ")
    parts = tail.split()
    return (
        verb == "set"
        and noun == "engagement"
        and bool(parts)
        and parts[0] in wizard.WIZARD_ARGS
    )


def _attach_prompter(emit: Emit, read_line: ReadLine) -> Prompter:
    """Build the Prompter that round-trips widget frames over the attach socket.

    Menus (``{"choose"}``) and the checklist (``{"multiselect"}``) render in the
    client; autocomplete is REPL-only and degrades to a plain ``{"ask"}`` prompt;
    the step bar and status lines ride ``{"chunk"}``. Shared by the wizard and the
    single-field engagement edits so the two collect input identically.
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

    return Prompter(
        ask=ask,
        ask_complete=ask_complete,
        choose=choose,
        multiselect=multiselect,
        confirm=confirm,
        notify=notify,
        progress=progress,
    )


def attach_wizard(
    core: AgentCore, lock: threading.Lock, read_line: ReadLine, emit: Emit
) -> None:
    """Run the engagement wizard over the attach connection.

    The turn closes with a non-exit ``end`` frame.
    """
    prompter = _attach_prompter(emit, read_line)
    core.note_interaction("set", "engagement setup")
    with lock:
        try:
            wizard.run_wizard(
                prompter,
                core.engagement_mgr.create_engagement,
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
    """Whether `line` is a no-value ``set`` noun that prompts (provider/model).

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
            setup.run_setup(core.provider_kernel, ask, choose, notify)
        else:
            setup.run_model_select(
                core.provider_kernel, core.provider, ask, choose, notify
            )
    emit({"end": True, "exit": False})


# ----- interactive engagement-field edits ------------------------------------


def is_engagement_interactive(line: str) -> bool:
    """Whether `line` is a ``set engagement <param>`` that needs an interactive turn.

    Composite / authorization / listener / scope params, and any direct param with
    no value, prompt; a one-shot direct or env edit (a value present) does not.
    """
    verb, rest = verbs.split_verb(line)
    noun, _, tail = rest.partition(" ")
    if verb != "set" or noun != "engagement":
        return False
    inv = engagement_params.classify(tail)
    return inv.action == "param" and engagement_params.needs_prompt(
        inv.target, has_value=bool(inv.value)
    )


def attach_engagement_param(
    core: AgentCore, lock: threading.Lock, line: str, read_line: ReadLine, emit: Emit
) -> None:
    """Run one interactive ``set engagement <param>`` edit over the attach loop."""
    _, rest = verbs.split_verb(line)
    tail = rest.partition(" ")[2]
    inv = engagement_params.classify(tail)
    prompter = _attach_prompter(emit, read_line)
    core.note_interaction("set", f"engagement {tail}")
    with lock:
        try:
            engagementflow.run_param_edit(
                core,
                inv.target,
                inv.value,
                prompter=prompter,
                catalog=engagement_catalog(core),
                grants=core.grants,
            )
        except Exception as exc:  # defensive: never kill the daemon thread
            log.exception("engagement field edit failed")
            emit({"chunk": f"edit failed: {exc}\n"})
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


def intercept(
    core: AgentCore,
    lock: threading.Lock,
    line: str,
    read_line: ReadLine,
    emit: Emit,
) -> bool:
    """Run `line` as an interactive attach flow if it is one; else return False.

    The round-trip flows (wizard, set-interactive, single engagement-field edits,
    cmd editor/suggest, config edits, install-missing, doctor-research) each own a
    multi-turn sub-dialogue over this connection; this is the one place that
    recognises and dispatches them so the daemon's attach loop stays a thin router.
    """
    if is_wizard(line):
        attach_wizard(core, lock, read_line, emit)
    elif is_engagement_interactive(line):
        attach_engagement_param(core, lock, line, read_line, emit)
    elif is_set_interactive(line):
        attach_set(core, lock, line, read_line, emit)
    elif is_cmd_editor(line):
        attach_cmd_editor(core, lock, line, read_line, emit)
    elif is_cmd_suggest(line):
        request = verbs.split_verb(line)[1].partition(" ")[2]
        attach_cmd_suggest(core, lock, request, read_line, emit)
    elif is_config_request(core, line):
        request = verbs.split_verb(line)[1].partition(" ")[2]
        attach_config(core, lock, request, read_line, emit)
    elif is_install_missing(line):
        attach_install_missing(core, lock, read_line, emit)
    elif (research_tool := doctor_research_tool(line)) is not None:
        attach_doctor_research(core, lock, research_tool, read_line, emit)
    else:
        return False
    return True


def chat_turn(
    line: str,
    emit: Emit,
    agent: Callable[[str], Iterator[dict[str, object]]],
) -> tuple[bool, str | None]:
    """One turn inside a chat context: ``(stay_active, capture_line)``.

    Every line is a prompt (no verb routing); ``exit``/``quit`` leaves the context
    (back to the loop, agent warm). `agent` streams the turn's frames (the daemon's
    ``_agent``). The returned `capture_line` is the synthetic ``chat <prompt>`` the
    caller feeds to :func:`capture_after_ask` (it holds the core/lock/read_line), or
    ``None`` when there is nothing to capture (the exit line).
    """
    if verbs.is_exit(verbs.split_verb(line)[0]):
        emit({"chunk": "left chat context\n"})
        return False, None
    for resp in agent(line):
        emit(resp)
    emit({"end": True, "exit": False})
    return True, f"chat {line}"


def capture_after_ask(
    core: AgentCore,
    lock: threading.Lock,
    line: str,
    read_line: ReadLine,
    emit: Emit,
) -> None:
    """If `line` was a ``chat``, gate remembering any directive it carried, post-turn.

    The chat loop's post-turn hook: only a ``chat`` turn is an engagement turn worth
    capturing from, and only the chat loop can do the confirm round-trip (a one-shot
    announces instead). A no-op for any other line, or when nothing was proposed.
    Emits no ``end`` frame -- the turn's own frames already closed the reply.
    """
    verb, rest = verbs.split_verb(line)
    if verb != "chat" or not rest.strip():
        return

    def choose(prompt: str, options: list[str], default: str | None) -> str | None:
        emit({"choose": {"prompt": prompt, "options": options, "default": default}})
        return read_line()

    with lock:
        candidates = core.memory.propose_capture(rest)
        memoryflow.run_memory_capture(
            candidates,
            choose=choose,
            notify=lambda text: emit({"chunk": text + "\n"}),
            apply=core.memory.apply_capture,
            grants=core.grants,
            interactive=True,
        )


# ----- doctor install missing ------------------------------------------------


def is_install_missing(line: str) -> bool:
    """Whether `line` is ``doctor install missing`` (the gated install flow)."""
    verb, rest = verbs.split_verb(line)
    return verb == "doctor" and dispatch.doctor_install_target(rest) == "missing"


def doctor_research_tool(line: str) -> str | None:
    """The tool for a ``doctor research <tool>`` line, else ``None`` (not that verb)."""
    verb, rest = verbs.split_verb(line)
    if verb != "doctor":
        return None
    target = dispatch.doctor_research_target(rest)
    return target or None  # "" (no tool named) is not a runnable research request


def _install_frames(read_line: ReadLine, emit: Emit) -> tuple[Choose, Notify]:
    """The ``choose``/``notify`` closures shared by the install flows over the socket.

    ``choose`` round-trips a menu to the client; ``notify`` emits one output line.
    """

    def choose(prompt: str, options: list[str], default: str | None) -> str | None:
        emit({"choose": {"prompt": prompt, "options": options, "default": default}})
        return read_line()

    return choose, lambda text: emit({"chunk": text + "\n"})


def _pending_frames(emit: Emit) -> installflow.Pending:
    @contextmanager
    def pending(label: str) -> Iterator[None]:
        # Tell the client to spin with `label` while this install blocks; the result
        # `chunk` frame that follows stops that spinner on the client side.
        emit({"pending": label})
        yield

    return pending


def attach_install_missing(
    core: AgentCore, lock: threading.Lock, read_line: ReadLine, emit: Emit
) -> None:
    """Install the missing scoped tools over the attach connection."""
    choose, notify = _install_frames(read_line, emit)
    core.note_interaction("doctor", "install missing")
    with lock:
        installflow.run_install_missing(
            choose=choose,
            notify=notify,
            propose=core.doctor.propose_installs,
            install=core.doctor.install,
            grants=core.grants,
            pending=_pending_frames(emit),
        )
    emit({"end": True, "exit": False})


def attach_doctor_research(
    core: AgentCore,
    lock: threading.Lock,
    tool: str,
    read_line: ReadLine,
    emit: Emit,
) -> None:
    """Research how to install `tool`, then confirm and install, over the socket."""
    choose, notify = _install_frames(read_line, emit)
    core.note_interaction("doctor", f"research {tool}")
    with lock:
        installflow.run_install_research(
            tool,
            choose=choose,
            notify=notify,
            research=core.installer.research,
            install=core.installer.install,
            grants=core.grants,
            pending=_pending_frames(emit),
        )
    emit({"end": True, "exit": False})
