"""L3: per-engagement runtime vars -- persistence, migration, and the verbs.

Exercises the env layer end-to-end against a real ``AgentCore``: it persists to
``env.json`` (separate from ``scope.json``), survives an engagement re-adopt,
seeds a legacy ``primary_target``, refreshes the shell-sourced file, and backs
``show env`` / ``set target`` / ``set wordlist``.
"""

from __future__ import annotations

from pathlib import Path

from skuggi.engagement.runtime_env import EngagementEnv
from skuggi.frontend import control
from skuggi.tooling.commands import CommandAlias, CommandRegistry
from tests.support import engaged_core

_SCOPE: dict[str, object] = {
    "name": "env-eng",
    "timezone": "UTC",
    "target_networks": ["10.0.0.0/8"],
    "allowed_hosts": ["box.example.com", "alpha.example.com"],
    "allowed_tools": ["nmap", "ffuf", "nc"],
    "allowed_methods": ["recon", "scan"],
}


def _text(styled: object) -> str:
    from skuggi.frontend import render  # noqa: PLC0415

    assert isinstance(styled, list)
    return "\n".join(render.to_ansi(line) for line in styled)


def test_env_persists_to_its_own_file_and_reloads_on_adopt(tmp_path: Path) -> None:
    core = engaged_core(tmp_path, _SCOPE)
    try:
        core.apply_env(EngagementEnv(target="10.1.2.3", lport="4444"))
        env_file = core.workspace.env_path  # type: ignore[union-attr]
        assert env_file.name == "env.json"
        assert env_file.is_file()
        assert "primary_target" not in (
            tmp_path / "engagement" / "scope.json"
        ).read_text(encoding="utf-8")
        # Re-adopting the same root reloads the env from disk.
        core.adopt_engagement(env_file.parent)
        assert core.env.target == "10.1.2.3"
        assert core.env.lport == "4444"
    finally:
        core.close()


def test_effective_target_prefers_manual_over_the_scope_default(tmp_path: Path) -> None:
    core = engaged_core(tmp_path, _SCOPE)
    try:
        # Default: the first (lexicographic) scoped host.
        assert core.effective_target() == "alpha.example.com"
        core.apply_env(EngagementEnv(target="10.9.9.9"))
        assert core.effective_target() == "10.9.9.9"
    finally:
        core.close()


def test_legacy_primary_target_seeds_the_env(tmp_path: Path) -> None:
    core = engaged_core(tmp_path, {**_SCOPE, "primary_target": "10.4.4.4"})
    try:
        # The field moved out of scope; its value is carried into the env once.
        assert core.env.target == "10.4.4.4"
        assert core.effective_target() == "10.4.4.4"
    finally:
        core.close()


def test_apply_env_refreshes_the_shell_sourced_file(tmp_path: Path) -> None:
    core = engaged_core(tmp_path, _SCOPE)
    try:
        session_file = tmp_path / "skuggi.env"
        core.runtime_env_path = session_file
        core.apply_env(EngagementEnv(lhost="10.8.0.2", lport="4444"))
        text = session_file.read_text(encoding="utf-8")
        assert "export lhost=10.8.0.2" in text
        assert "export lport=4444" in text
        # The target falls back to the scope default in the exported file.
        assert "export target=alpha.example.com" in text
    finally:
        core.close()


def test_plan_cmd_with_listener_placeholders_scope_checks(tmp_path: Path) -> None:
    core = engaged_core(tmp_path, _SCOPE)
    try:
        core.apply_env(EngagementEnv(target="10.0.0.5", lport="4444"))
        core.commands = CommandRegistry(
            commands=(
                CommandAlias(
                    name="nc-listen",
                    argv=("nc", "-lvnp", "${lport}"),
                    output=False,
                ),
            )
        )
        plan = core.cmds.plan("nc-listen")  # must not raise on the ${lport} token
        assert plan.known
        assert "${lport}" in plan.raw
    finally:
        core.close()


def test_show_env_reports_target_source(tmp_path: Path) -> None:
    core = engaged_core(tmp_path, _SCOPE)
    try:
        out = _text(control.show_env(core, "", "repl"))
        assert "target" in out
        assert "alpha.example.com" in out  # the scope default
        assert "scope default" in out
        core.apply_env(EngagementEnv(target="10.0.0.5"))
        assert "manual" in _text(control.show_env(core, "", "repl"))
    finally:
        core.close()


def test_set_target_and_wordlist_one_shot(tmp_path: Path) -> None:
    core = engaged_core(tmp_path, _SCOPE)
    try:
        control.set_engagement_param(core, "target", "10.0.0.5", "repl")
        assert core.env.target == "10.0.0.5"
        control.set_engagement_param(core, "wordlist", "/wl/rock.txt", "repl")
        assert core.env.wordlist == "/wl/rock.txt"
        # A bare invocation shows usage, changing nothing.
        out = _text(control.set_engagement_param(core, "target", "", "repl"))
        assert "usage" in out
        assert core.env.target == "10.0.0.5"
    finally:
        core.close()


def test_set_target_rejects_a_whitespace_host(tmp_path: Path) -> None:
    core = engaged_core(tmp_path, _SCOPE)
    try:
        out = _text(
            control.set_engagement_param(core, "target", "10.0.0.5 evil", "repl")
        )
        assert "whitespace" in out.lower()
        assert core.env.target is None  # nothing persisted
    finally:
        core.close()


def test_set_wordlist_bare_shows_usage(tmp_path: Path) -> None:
    core = engaged_core(tmp_path, _SCOPE)
    try:
        assert "usage" in _text(
            control.set_engagement_param(core, "wordlist", "", "repl")
        )
        assert core.env.wordlist is None
    finally:
        core.close()


def test_set_target_and_wordlist_require_an_engagement(tmp_path: Path) -> None:
    core = engaged_core(tmp_path, _SCOPE)
    try:
        core.engagement = None
        assert "no engagement" in _text(
            control.set_engagement_param(core, "target", "10.0.0.5", "repl")
        )
        assert "no engagement" in _text(
            control.set_engagement_param(core, "wordlist", "/wl.txt", "repl")
        )
    finally:
        core.close()
