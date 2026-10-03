"""``skuggi`` -- the native shell wrapper (the default entry point).

The operator wanted their *real* CLI: their prompt, colours, completion,
history and signals, with skuggi layered on. So ``skuggi`` runs the operator's
own ``$SHELL`` as a child that inherits the real terminal -- ``ls``, ``cat``,
``nmap`` and ``Ctrl+C`` are all handled natively by that shell, never by
skuggi. Only ``/skuggi …`` reaches the agent, via a shell hook.

How the hook works: skuggi points the child shell at a temporary init file that
sources the operator's own rc, prepends a 🐐 to the prompt, and defines a shell
*function* literally named ``/skuggi`` (both bash and zsh resolve a function by
that name before treating the word as a path). The function forwards its
arguments to ``skuggi-client`` -- a thin client that talks to the warm
in-process agent daemon. ``/skuggi exit`` (and a client exit code of 42) leaves
the shell. bash and zsh are supported; other shells degrade to a plain child
with a printed note.

Enforcement scope, stated honestly: the engagement boundary applies to commands
the *agent* proposes (the worker's ``command``, guarded by the executor).
Commands the operator free-types
are the operator's own; skuggi does not veto them (true pre-exec interception of
a live interactive shell is not feasible here). It does, however, *log* them: a
zsh ``preexec`` hook (and a bash ``PROMPT_COMMAND`` equivalent) forwards each
free-typed command to the daemon, which records it on the engagement timeline as
``passthrough`` (or filters navigation noise to the audit ``cli`` channel). The
forwarder is guarded (it skips its own ``/skuggi`` / ``skuggi-client`` calls),
backgrounded (it never blocks the prompt) and fail-open (a dead daemon is
silently ignored) -- logging must never disrupt the operator's real shell.

The hook spells ``skuggi-client`` as an **absolute path**, resolved once before
the child starts. It cannot rely on ``$PATH``: the init file sources the
operator's own rc first, by design, and an rc that rebuilds ``PATH`` (``path=(...)``
in zsh is idiomatic) would leave ``/skuggi`` reporting "command not found" with no
hint as to why. Resolving once also pins the hook to the *same* install the
daemon is running from, which matters when a checkout and a ``uv tool`` install
both exist.
"""

from __future__ import annotations

import os
import shlex
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from skuggi.common import palette
from skuggi.common.logs import get_logger, setup_logging
from skuggi.frontend.banner import render_startup_banner

if TYPE_CHECKING:
    from collections.abc import Mapping

    from skuggi.agent.core import AgentCore
    from skuggi.engagement.engagement import EngagementConfig

# Exported into every child shell the wrapper launches; its presence marks "we
# are already inside a skuggi shell" so a bare `skuggi` run here never boots a
# second daemon (see ``nested_launch_note``).
ACTIVE_ENV = "SKUGGI_ACTIVE"

SHIELD = palette.SHIELD

# The console script the shell hook calls. Its name is also matched inside the
# hook to keep the passthrough recorder from logging its own invocations.
CLIENT_NAME = "skuggi-client"

_ZSH_HOOK = """\
[ -f "{home}/.zshrc" ] && source "{home}/.zshrc"
PROMPT="{shield} ${{PROMPT}}"
_skuggi_client={client}
function /skuggi {{
  if [[ "$1" == "exit" || "$1" == "quit" ]]; then exit 0; fi
  "$_skuggi_client" "$@"
  [[ $? -eq 42 ]] && exit 0
}}
# A bare `skuggi` (no slash) means the same thing inside the wrapped shell:
# reach the warm daemon. Without this it would resolve through $PATH to the
# console script and boot a nested harness. Delegates to /skuggi so the
# exit/42 handling is shared. `command skuggi` still reaches the real launcher.
function skuggi {{ /skuggi "$@"; }}
# Disable filename globbing for /skuggi (and bare skuggi) args so an unquoted
# natural-language query (`skuggi ask who are you?`) is not mangled by zsh's
# nomatch error.
alias '/skuggi'='noglob /skuggi'
alias skuggi='noglob skuggi'
function _skuggi_record {{
  case "$1" in
    /skuggi*|skuggi*|"$_skuggi_client"*) ;;
    *) "$_skuggi_client" --record "$1" 2>/dev/null &! ;;
  esac
}}
autoload -Uz add-zsh-hook
add-zsh-hook preexec _skuggi_record
autoload -Uz compinit
(( $+functions[compdef] )) || compinit -C
function _skuggi_complete {{
  local out
  out="$("$_skuggi_client" --complete "${{(@)words[2,CURRENT-1]}}" 2>/dev/null)"
  compadd -- ${{(f)out}}
}}
compdef _skuggi_complete /skuggi skuggi
"""

_BASH_HOOK = """\
[ -f "{home}/.bashrc" ] && source "{home}/.bashrc"
PS1="{shield} ${{PS1}}"
_skuggi_client={client}
function /skuggi {{
  if [ "$1" = "exit" ] || [ "$1" = "quit" ]; then exit 0; fi
  "$_skuggi_client" "$@"
  [ $? -eq 42 ] && exit 0
}}
# A bare `skuggi` (no slash) means the same thing inside the wrapped shell:
# reach the warm daemon, not boot a nested harness via the $PATH console
# script. Delegates to /skuggi so exit/42 handling is shared. `command skuggi`
# still reaches the real launcher.
function skuggi {{ /skuggi "$@"; }}
_skuggi_last=""
function _skuggi_record {{
  local _n cmd
  read -r _n cmd <<< "$(HISTTIMEFORMAT= history 1)"
  case "$cmd" in
    ""|/skuggi*|skuggi*|"$_skuggi_client"*|"$_skuggi_last") ;;
    *) "$_skuggi_client" --record "$cmd" 2>/dev/null & ;;
  esac
  _skuggi_last="$cmd"
}}
PROMPT_COMMAND="_skuggi_record${{PROMPT_COMMAND:+; $PROMPT_COMMAND}}"
_skuggi_complete() {{
  local cur prev out
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  prev=( "${{COMP_WORDS[@]:1:COMP_CWORD-1}}" )
  out="$("$_skuggi_client" --complete "${{prev[@]}}" 2>/dev/null)"
  COMPREPLY=( $(compgen -W "$out" -- "$cur") )
}}
complete -F _skuggi_complete /skuggi skuggi
"""


def client_path() -> str:
    """Absolute path to the ``skuggi-client`` console script, for the shell hook.

    Preference order, and why:

    1. A sibling of the running ``skuggi`` script. Console scripts of one install
       share a ``bin`` directory, so this pins the hook to the same install as the
       daemon -- the right answer when a checkout's ``.venv`` and a ``uv tool``
       install both exist on the machine.
    2. ``$PATH``, for the case where argv[0] tells us nothing useful (``python -m``,
       an exec'd wrapper).
    3. The bare name, so a broken resolution degrades to the old behaviour rather
       than to a traceback at startup.
    """
    argv0 = sys.argv[0]
    if argv0:
        sibling = Path(argv0).resolve().parent / CLIENT_NAME
        if sibling.is_file():
            return str(sibling)
    return shutil.which(CLIENT_NAME) or CLIENT_NAME


def build_shell_invocation(
    shell_path: str, tmpdir: Path, *, home: Path, client: str | None = None
) -> tuple[list[str], dict[str, str]]:
    """Argv + env overrides that launch `shell_path` with the skuggi hook.

    The temp init file sources the operator's own rc first (preserving prompt,
    aliases and colours), prepends the shield, and defines the ``/skuggi`` shell
    function. Shells other than bash/zsh get a degraded, hook-free invocation
    (a printed note tells the operator ``/skuggi`` is disabled).

    `client` is the ``skuggi-client`` path baked into the hook (default:
    ``client_path()``). It is shell-quoted, so a home directory with a space in it
    does not split the command -- the hook would otherwise fail in exactly the
    place that is hardest to debug from inside a wrapped shell.
    """
    name = Path(shell_path).name
    env = {ACTIVE_ENV: "1"}
    quoted = shlex.quote(client if client is not None else client_path())
    if name == "zsh":
        (tmpdir / ".zshrc").write_text(
            _ZSH_HOOK.format(home=home, shield=SHIELD, client=quoted), encoding="utf-8"
        )
        env["ZDOTDIR"] = str(tmpdir)
        return [shell_path, "-i"], env
    if name == "bash":
        rcfile = tmpdir / "rcfile"
        rcfile.write_text(
            _BASH_HOOK.format(home=home, shield=SHIELD, client=quoted), encoding="utf-8"
        )
        return [shell_path, "--rcfile", str(rcfile), "-i"], env
    return [shell_path], env


def supports_hook(shell_path: str) -> bool:
    """Whether `shell_path` gets the ``/skuggi`` hook (bash/zsh) or degrades."""
    return Path(shell_path).name in ("bash", "zsh")


def nested_launch_note(env: Mapping[str, str]) -> str | None:
    """A note when ``skuggi`` is launched inside an already-active shell, else None.

    bash/zsh shadow the bare ``skuggi`` word with a function that reaches the warm
    daemon, so this only fires when that hook is bypassed -- ``command skuggi``, a
    script, or a degraded shell with no hook. In every such case booting a second
    ``AgentCore`` + daemon + nested child shell is never what the operator wants;
    the launcher prints this and exits instead.
    """
    if not env.get(ACTIVE_ENV):
        return None
    return (
        "skuggi: already inside a skuggi shell -- use `skuggi <verb>` or "
        "`/skuggi <verb>` to reach the running agent; a bare `skuggi` would "
        "start a nested session."
    )


def shell_env_target(engagement: EngagementConfig | None) -> dict[str, str]:
    """``{"target": <host>}`` to export into the wrapped shell, or ``{}``.

    The cheatsheet renders ``${target}`` literally so the operator's shell
    expands it; exporting the engagement's resolved primary target here makes a
    pasted ``cmd`` output just work. Returns ``{}`` when there is no engagement
    or no unambiguous target, leaving ``target`` for the operator to set.
    """
    if engagement is None:
        return {}
    target = engagement.resolve_target()
    return {"target": target} if target else {}


def _session_summary(core: AgentCore) -> str:  # pragma: no cover -- live ledger I/O
    """Read the current session back from the ledger and render the exit summary.

    Called in ``main()``'s ``finally`` before ``core.close()`` (which shuts the
    ledger). Shares the ``show db`` renderer (``dispatch.run_db_stats``); any read
    failure degrades to a bare sign-off, since leaving the shell must never hinge
    on the ledger being readable.
    """
    from skuggi.frontend.dispatch import run_db_stats

    try:
        return run_db_stats(core)
    except Exception:  # noqa: BLE001 -- exit must not fail on a summary read
        return (
            f"{SHIELD} {palette.paint('session closed · ledger saved', palette.INFO)}"
        )


def main() -> None:  # pragma: no cover -- launches a child shell + daemon
    """Console entry point: warm agent daemon + the operator's real shell."""
    nested = nested_launch_note(os.environ)
    if nested is not None:
        # Never boot a second daemon from inside an active skuggi shell.
        print(nested, file=sys.stderr)
        return

    import signal
    import subprocess
    import tempfile

    from rich.console import Console

    from skuggi.agent import readiness
    from skuggi.agent.core import AgentCore
    from skuggi.config.config import Settings
    from skuggi.frontend import daemon_server
    from skuggi.install.boot import guard_boot

    setup_logging()
    get_logger(__name__).info("skuggi shell starting")
    # highlight=False: the banners carry their own deliberate palette styling;
    # Rich's auto-highlighter would otherwise repaint every "/skuggi" and digit.
    console = Console(highlight=False)
    # The warm agent (graph + llm + ledger + registry) takes a beat to build;
    # a spinner means the shell never looks hung before the banner appears.
    with console.status("starting skuggi…", spinner="dots"):
        core = guard_boot(lambda: AgentCore(Settings()))

    shell_path = os.environ.get("SHELL", shutil.which("bash") or "/bin/sh")
    # A stray Ctrl+C must never tear the harness down; the child shell owns the
    # foreground and handles interrupts natively for the commands it runs.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        sock_path = str(tmp / "skuggi.sock")
        handle = daemon_server.serve(core, sock_path)
        argv, env_overrides = build_shell_invocation(shell_path, tmp, home=Path.home())
        env = {
            **os.environ,
            **env_overrides,
            "SKUGGI_SOCK": sock_path,
            **shell_env_target(core.engagement),
        }
        console.print(
            render_startup_banner(
                readiness=readiness.from_core(core),
                unsupported_shell=(
                    None if supports_hook(shell_path) else Path(shell_path).name
                ),
            )
        )
        try:
            subprocess.run(argv, env=env, check=False)  # noqa: S603 -- the operator's own shell
        finally:
            handle.stop()
            # Read the session back before close() shuts the ledger.
            summary = _session_summary(core)
            core.close()
            console.print(summary)


if __name__ == "__main__":  # pragma: no cover
    main()
