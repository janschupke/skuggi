"""L3: the shell wrapper's rc/hook injection.

The launcher (``shell.main``) spawns a child shell + daemon and needs a real
terminal, so it is exercised by hand; the rc/hook builder it delegates to is
unit tested here. Routing lives in the daemon (see ``test_daemon.py``).
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from skuggi.frontend import shell
from skuggi.frontend.shell import (
    CLIENT_NAME,
    SHIELD,
    build_shell_invocation,
    client_path,
    supports_hook,
)

# A stand-in for the resolved absolute client path, so the hook assertions do not
# depend on where this test happens to be installed.
CLIENT = "/opt/skuggi/bin/skuggi-client"


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
    build_shell_invocation("/bin/zsh", tmp_path, home=Path("/home/u"), client=CLIENT)
    zshrc = (tmp_path / ".zshrc").read_text(encoding="utf-8")
    assert "add-zsh-hook preexec _skuggi_record" in zshrc
    assert '"$_skuggi_client" --record' in zshrc
    assert "/skuggi*|skuggi-client*" in zshrc  # re-entrancy guard
    assert '"$_skuggi_client"*' in zshrc  # ... incl. the absolute form
    assert "2>/dev/null &!" in zshrc  # fail-open + backgrounded


def test_bash_hook_forwards_free_typed_commands_via_prompt_command(
    tmp_path: Path,
) -> None:
    build_shell_invocation("/bin/bash", tmp_path, home=Path("/home/u"), client=CLIENT)
    rcfile = tmp_path / "rcfile"
    body = rcfile.read_text(encoding="utf-8")
    assert "_skuggi_record" in body
    assert "PROMPT_COMMAND=" in body
    assert '"$_skuggi_client" --record' in body
    assert "/skuggi*|skuggi-client*" in body  # re-entrancy guard
    assert '"$_skuggi_client"*' in body  # ... incl. the absolute form
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


# --- the client path baked into the hook ------------------------------------
#
# The hook must not resolve `skuggi-client` through $PATH: the init file sources
# the operator's own rc first, and an rc that rebuilds PATH (idiomatic in zsh)
# would leave /skuggi reporting "command not found" from inside a wrapped shell --
# the least debuggable place it could fail.


@pytest.mark.parametrize(
    ("shell_path", "rc_name"), [("/bin/zsh", ".zshrc"), ("/bin/bash", "rcfile")]
)
def test_hook_spells_the_client_as_an_absolute_path(
    tmp_path: Path, shell_path: str, rc_name: str
) -> None:
    build_shell_invocation(shell_path, tmp_path, home=Path("/home/u"), client=CLIENT)
    body = (tmp_path / rc_name).read_text(encoding="utf-8")
    assert f"_skuggi_client={CLIENT}" in body
    # The bare name never appears as the thing being executed.
    assert f"\n  {CLIENT_NAME} " not in body


def test_a_client_path_with_spaces_is_quoted(tmp_path: Path) -> None:
    """A home directory with a space in it must not split the command."""
    spaced = "/Users/jan schupke/bin/skuggi-client"
    build_shell_invocation("/bin/zsh", tmp_path, home=Path("/home/u"), client=spaced)
    body = (tmp_path / ".zshrc").read_text(encoding="utf-8")
    assert f"_skuggi_client='{spaced}'" in body


def test_client_path_prefers_a_sibling_of_argv0(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Console scripts of one install share a bin dir; that pins hook to daemon."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "skuggi").touch()
    sibling = bindir / CLIENT_NAME
    sibling.touch()
    monkeypatch.setattr(sys, "argv", [str(bindir / "skuggi")])
    assert client_path() == str(sibling)


def test_client_path_falls_back_to_path_then_to_the_bare_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """argv[0] tells us nothing useful under `python -m` or an exec'd wrapper."""
    lonely = tmp_path / "bin"
    lonely.mkdir()
    (lonely / "skuggi").touch()
    monkeypatch.setattr(sys, "argv", [str(lonely / "skuggi")])

    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/skuggi-client")
    assert client_path() == "/usr/bin/skuggi-client"

    # Degrade to the bare name rather than crash at startup.
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert client_path() == CLIENT_NAME


def test_build_shell_invocation_resolves_the_client_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shell, "client_path", lambda: "/resolved/skuggi-client")
    build_shell_invocation("/bin/zsh", tmp_path, home=Path("/home/u"))
    body = (tmp_path / ".zshrc").read_text(encoding="utf-8")
    assert "_skuggi_client=/resolved/skuggi-client" in body
