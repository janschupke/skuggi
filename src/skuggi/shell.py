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
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from skuggi import palette

SHIELD = palette.SHIELD

_ZSH_HOOK = """\
[ -f "{home}/.zshrc" ] && source "{home}/.zshrc"
PROMPT="{shield} ${{PROMPT}}"
function /skuggi {{
  if [[ "$1" == "exit" || "$1" == "quit" ]]; then exit 0; fi
  skuggi-client "$@"
  [[ $? -eq 42 ]] && exit 0
}}
function _skuggi_record {{
  case "$1" in
    /skuggi*|skuggi-client*) ;;
    *) skuggi-client --record "$1" 2>/dev/null &! ;;
  esac
}}
autoload -Uz add-zsh-hook
add-zsh-hook preexec _skuggi_record
"""

_BASH_HOOK = """\
[ -f "{home}/.bashrc" ] && source "{home}/.bashrc"
PS1="{shield} ${{PS1}}"
function /skuggi {{
  if [ "$1" = "exit" ] || [ "$1" = "quit" ]; then exit 0; fi
  skuggi-client "$@"
  [ $? -eq 42 ] && exit 0
}}
_skuggi_last=""
function _skuggi_record {{
  local _n cmd
  read -r _n cmd <<< "$(HISTTIMEFORMAT= history 1)"
  case "$cmd" in
    ""|/skuggi*|skuggi-client*|"$_skuggi_last") ;;
    *) skuggi-client --record "$cmd" 2>/dev/null & ;;
  esac
  _skuggi_last="$cmd"
}}
PROMPT_COMMAND="_skuggi_record${{PROMPT_COMMAND:+; $PROMPT_COMMAND}}"
"""


def build_shell_invocation(
    shell_path: str, tmpdir: Path, *, home: Path
) -> tuple[list[str], dict[str, str]]:
    """Argv + env overrides that launch `shell_path` with the skuggi hook.

    The temp init file sources the operator's own rc first (preserving prompt,
    aliases and colours), prepends the shield, and defines the ``/skuggi`` shell
    function. Shells other than bash/zsh get a degraded, hook-free invocation
    (a printed note tells the operator ``/skuggi`` is disabled).
    """
    name = Path(shell_path).name
    env = {"SKUGGI_ACTIVE": "1"}
    if name == "zsh":
        (tmpdir / ".zshrc").write_text(
            _ZSH_HOOK.format(home=home, shield=SHIELD), encoding="utf-8"
        )
        env["ZDOTDIR"] = str(tmpdir)
        return [shell_path, "-i"], env
    if name == "bash":
        rcfile = tmpdir / "rcfile"
        rcfile.write_text(_BASH_HOOK.format(home=home, shield=SHIELD), encoding="utf-8")
        return [shell_path, "--rcfile", str(rcfile), "-i"], env
    return [shell_path], env


def supports_hook(shell_path: str) -> bool:
    """Whether `shell_path` gets the ``/skuggi`` hook (bash/zsh) or degrades."""
    return Path(shell_path).name in ("bash", "zsh")


def main() -> None:  # pragma: no cover -- launches a child shell + daemon
    """Console entry point: warm agent daemon + the operator's real shell."""
    import signal
    import subprocess
    import tempfile

    from skuggi import daemon as daemon_mod
    from skuggi.config import Settings
    from skuggi.core import AgentCore

    core = AgentCore(Settings())
    for warning in core.warnings:
        print(f"skuggi: {warning}")

    shell_path = os.environ.get("SHELL", shutil.which("bash") or "/bin/sh")
    # A stray Ctrl+C must never tear the harness down; the child shell owns the
    # foreground and handles interrupts natively for the commands it runs.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        sock_path = str(tmp / "skuggi.sock")
        handle = daemon_mod.serve(core, sock_path)
        argv, env_overrides = build_shell_invocation(shell_path, tmp, home=Path.home())
        env = {**os.environ, **env_overrides, "SKUGGI_SOCK": sock_path}
        print(
            f"{SHIELD} skuggi shell -- '/skuggi' opens a chat loop, "
            "'/skuggi ask <prompt>' asks once, '/skuggi help' lists verbs, "
            "'/skuggi exit' leaves"
        )
        if not supports_hook(shell_path):
            print(
                f"skuggi: {Path(shell_path).name} is unsupported; /skuggi is "
                "disabled (bash or zsh gets the hook)"
            )
        try:
            subprocess.run(argv, env=env, check=False)  # noqa: S603 -- the operator's own shell
        finally:
            handle.stop()
            core.close()
            print("bye.")


if __name__ == "__main__":  # pragma: no cover
    main()
