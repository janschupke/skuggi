"""Shell wrapper: a PTY-backed transparent proxy around the host shell.

Feasibility (req #8). The operator wants their real CLI experience -- their
prompt, their colours, their tools -- with skuggi layered on top. Two shapes
were considered:

* Hooking the user's *real* interactive zsh via ``preexec``/``precmd``. Rejected
  for the prototype: it is zsh-specific, it means sourcing into the user's rc,
  and ``preexec`` fires before a command but cannot cleanly *veto* it, so the
  engagement boundary could not actually block anything.
* A skuggi-owned proxy that runs the user's ``$SHELL`` inside a pseudo-terminal.
  Chosen. Because the child believes it owns a real terminal, it emits its
  normal coloured, prompted output verbatim; skuggi forwards keystrokes and
  output untouched, watching only for ``/skuggi ...`` lines to intercept.

The emoji prompt (req #8) is injected host-agnostically by pointing the child
shell at a temporary init file that first sources the user's own rc, then
prepends the shield to the prompt -- ``ZDOTDIR`` for zsh, ``--rcfile`` for bash.
An unknown shell degrades: skuggi prints its own active marker instead.

Honest scope note: boundary *enforcement* applies to commands the agent
proposes through ``run_command`` (they pass ``check_command``). Commands the
operator free-types into the wrapped shell are *logged* to the ledger for the
record but not vetoed -- true pre-exec interception in a live shell is the
rejected zsh-hook approach.
"""

from __future__ import annotations

import os
import shlex
import shutil
from pathlib import Path

from skuggi.tui import Tui

SHIELD = "🛡️"
_PREFIX = "/skuggi"


def is_skuggi_command(line: str) -> bool:
    """Whether `line` is addressed to skuggi rather than the host shell."""
    stripped = line.strip()
    return stripped == _PREFIX or stripped.startswith(_PREFIX + " ")


def skuggi_body(line: str) -> str:
    """The text after the ``/skuggi`` prefix."""
    return line.strip()[len(_PREFIX) :].strip()


def build_shell_invocation(
    shell_path: str, tmpdir: Path, *, home: Path
) -> tuple[list[str], dict[str, str]]:
    """Argv + env overrides that launch `shell_path` with a shield-prefixed prompt.

    The temp init file sources the operator's own rc first, so their prompt,
    aliases and colours are preserved, then prepends the shield. Returns a
    degraded (no-prompt-injection) invocation for shells other than bash/zsh.
    """
    name = Path(shell_path).name
    env = {"SKUGGI_ACTIVE": "1"}
    if name == "zsh":
        (tmpdir / ".zshrc").write_text(
            f'[ -f "{home}/.zshrc" ] && source "{home}/.zshrc"\n'
            f'PROMPT="{SHIELD} ${{PROMPT}}"\n',
            encoding="utf-8",
        )
        env["ZDOTDIR"] = str(tmpdir)
        return [shell_path], env
    if name == "bash":
        rcfile = tmpdir / "rcfile"
        rcfile.write_text(
            f'[ -f "{home}/.bashrc" ] && source "{home}/.bashrc"\n'
            f'PS1="{SHIELD} ${{PS1}}"\n',
            encoding="utf-8",
        )
        return [shell_path, "--rcfile", str(rcfile), "-i"], env
    return [shell_path], env


class ShellHarness:
    """Routes wrapped-shell input: skuggi commands to the agent, the rest through.

    ``handle_line`` is the whole decision, kept out of the PTY event loop so it
    is testable without a terminal.
    """

    def __init__(self, tui: Tui) -> None:
        self.tui = tui

    def handle_line(self, line: str) -> str | None:
        """Dispatch one input line.

        Returns None when skuggi handled the line (nothing goes to the shell),
        or the original line to forward to the host shell (after logging it).
        """
        stripped = line.strip()
        if not stripped:
            return line
        if is_skuggi_command(stripped):
            body = skuggi_body(stripped)
            if body.startswith("/"):
                self.tui.dispatch(body)
            elif body:
                self.tui.turn(body)
            return None
        self._log_passthrough(stripped)
        return line

    def _log_passthrough(self, command: str) -> None:
        """Record an operator-typed command in the ledger (observational)."""
        try:
            argv = shlex.split(command)
        except ValueError:
            argv = []
        binary = Path(argv[0]).name if argv else ""
        self.tui.ledger.record_command(
            session_id=self.tui.session_id,
            thread_id=self.tui.thread_id,
            command=command,
            binary=binary,
            method=self.tui.registry.method_for(binary),
            status="passthrough",
        )


def run_wrapped_shell(tui: Tui) -> None:  # pragma: no cover -- interactive PTY loop
    """Run the host shell inside a PTY, intercepting ``/skuggi`` lines.

    This is the interactive loop; it needs a real terminal and is exercised by
    hand, not in the offline suite (the routing it delegates to -- ShellHarness
    and build_shell_invocation -- is unit tested).
    """
    import pty
    import select
    import termios
    import tty

    shell_path = os.environ.get("SHELL", shutil.which("bash") or "/bin/sh")
    harness = ShellHarness(tui)
    tui.console.print(
        f"{SHIELD} skuggi shell -- type '/skuggi <input>' to reach the agent"
    )

    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as raw_tmp:
        argv, env_overrides = build_shell_invocation(
            shell_path, Path(raw_tmp), home=Path.home()
        )
        pid, master = pty.fork()
        if pid == 0:  # child
            os.environ.update(env_overrides)
            os.execvp(argv[0], argv)  # noqa: S606 -- launching the user's own shell

        old = termios.tcgetattr(0)
        line_buffer = ""
        try:
            tty.setraw(0)
            while True:
                readable, _, _ = select.select([0, master], [], [])
                if 0 in readable:
                    data = os.read(0, 1024)
                    if not data:
                        break
                    for byte in data:
                        if byte in (10, 13):  # newline: decide on the buffered line
                            if harness.handle_line(line_buffer) is None:
                                line_buffer = ""
                                continue
                            line_buffer = ""
                        else:
                            line_buffer += chr(byte)
                    os.write(master, data)
                if master in readable:
                    try:
                        out = os.read(master, 4096)
                    except OSError:
                        break
                    if not out:
                        break
                    os.write(1, out)
        finally:
            termios.tcsetattr(0, termios.TCSADRAIN, old)
            os.close(master)


def main() -> None:  # pragma: no cover -- console entry point
    """Console entry point for the wrapped shell."""
    from skuggi.config import Settings

    tui = Tui(Settings())
    try:
        run_wrapped_shell(tui)
    finally:
        tui.close()


if __name__ == "__main__":  # pragma: no cover
    main()
