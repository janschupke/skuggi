"""L3: the shell wrapper's rc/hook injection.

The launcher (``shell.main``) spawns a child shell + daemon and needs a real
terminal, so it is exercised by hand; the rc/hook builder it delegates to is
unit tested here. Routing lives in the daemon (see ``test_daemon.py``).
"""

from __future__ import annotations

from pathlib import Path

from skuggi.shell import SHIELD, build_shell_invocation, supports_hook


def test_zsh_invocation_injects_via_zdotdir(tmp_path: Path) -> None:
    argv, env = build_shell_invocation("/bin/zsh", tmp_path, home=Path("/home/u"))
    assert argv == ["/bin/zsh", "-i"]
    assert env["ZDOTDIR"] == str(tmp_path)
    zshrc = (tmp_path / ".zshrc").read_text(encoding="utf-8")
    assert SHIELD in zshrc
    assert "/home/u/.zshrc" in zshrc


def test_zsh_hook_routes_skuggi_to_the_client(tmp_path: Path) -> None:
    build_shell_invocation("/bin/zsh", tmp_path, home=Path("/home/u"))
    zshrc = (tmp_path / ".zshrc").read_text(encoding="utf-8")
    assert "function /skuggi" in zshrc
    assert "skuggi-client" in zshrc
    assert "exit 0" in zshrc  # a client exit code of 42 leaves the shell


def test_zsh_hook_forwards_free_typed_commands_via_preexec(tmp_path: Path) -> None:
    build_shell_invocation("/bin/zsh", tmp_path, home=Path("/home/u"))
    zshrc = (tmp_path / ".zshrc").read_text(encoding="utf-8")
    assert "add-zsh-hook preexec _skuggi_record" in zshrc
    assert "skuggi-client --record" in zshrc
    assert "/skuggi*|skuggi-client*" in zshrc  # re-entrancy guard
    assert "2>/dev/null &!" in zshrc  # fail-open + backgrounded


def test_bash_hook_forwards_free_typed_commands_via_prompt_command(
    tmp_path: Path,
) -> None:
    build_shell_invocation("/bin/bash", tmp_path, home=Path("/home/u"))
    rcfile = tmp_path / "rcfile"
    body = rcfile.read_text(encoding="utf-8")
    assert "_skuggi_record" in body
    assert "PROMPT_COMMAND=" in body
    assert "skuggi-client --record" in body
    assert "/skuggi*|skuggi-client*" in body  # re-entrancy guard
    assert "2>/dev/null &" in body  # fail-open + backgrounded


def test_bash_invocation_uses_an_rcfile(tmp_path: Path) -> None:
    argv, _ = build_shell_invocation("/bin/bash", tmp_path, home=Path("/home/u"))
    assert "--rcfile" in argv
    assert "-i" in argv
    rcfile = Path(argv[argv.index("--rcfile") + 1])
    body = rcfile.read_text(encoding="utf-8")
    assert SHIELD in body
    assert "function /skuggi" in body
    assert "skuggi-client" in body


def test_unknown_shell_degrades(tmp_path: Path) -> None:
    argv, env = build_shell_invocation("/usr/bin/fish", tmp_path, home=Path("/home/u"))
    assert argv == ["/usr/bin/fish"]
    assert env == {"SKUGGI_ACTIVE": "1"}


def test_supports_hook() -> None:
    assert supports_hook("/bin/zsh")
    assert supports_hook("/usr/local/bin/bash")
    assert not supports_hook("/usr/bin/fish")
