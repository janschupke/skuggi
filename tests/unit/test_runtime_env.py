"""L1: the per-engagement runtime vars model + the shell-sourced env writer."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from skuggi.engagement.runtime_env import (
    VAR_ORDER,
    EngagementEnv,
    write_runtime_env,
)
from skuggi.tooling.commands import RUNTIME_VARS


def test_var_order_stays_in_sync_with_the_model_and_renderer() -> None:
    # VAR_ORDER, the model's fields and the renderer's sanctioned set must agree,
    # or a var would export but not resolve in a rendered command (or vice versa).
    assert set(VAR_ORDER) == set(EngagementEnv.model_fields)
    assert set(VAR_ORDER) == RUNTIME_VARS


def test_exports_fills_target_from_the_scope_default() -> None:
    env = EngagementEnv()
    assert env.exports(default_target="scanme.example.com") == {
        "target": "scanme.example.com"
    }


def test_exports_manual_target_overrides_the_default_and_drops_blanks() -> None:
    env = EngagementEnv(target="10.0.0.5", lport="4444")
    assert env.exports(default_target="scanme.example.com") == {
        "target": "10.0.0.5",
        "lport": "4444",
    }


def test_exports_is_empty_when_nothing_is_set_and_no_default() -> None:
    assert EngagementEnv().exports() == {}


def test_effective_target_prefers_manual_then_default() -> None:
    assert EngagementEnv(target="10.0.0.5").effective_target("d") == "10.0.0.5"
    assert EngagementEnv().effective_target("d") == "d"
    assert EngagementEnv().effective_target(None) is None


def test_host_fields_reject_whitespace() -> None:
    with pytest.raises(ValidationError):
        EngagementEnv(target="10.0.0.5 evil")
    with pytest.raises(ValidationError):
        EngagementEnv(lhost="tun0\n")
    # lport/wordlist are free strings (ranges / paths with spaces are fine).
    assert EngagementEnv(lport="4444-4500").lport == "4444-4500"
    assert EngagementEnv(wordlist="/a b/rock.txt").wordlist == "/a b/rock.txt"


def test_write_runtime_env_exports_present_and_unsets_absent(tmp_path: Path) -> None:
    path = tmp_path / "skuggi.env"
    env = EngagementEnv(lport="4444", wordlist="/a b/rock.txt")
    write_runtime_env(path, env, default_target="10.0.0.5")
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines == [
        "export target=10.0.0.5",
        "unset lhost",
        "export lport=4444",
        "export wordlist='/a b/rock.txt'",  # shlex-quoted: the space is neutralised
    ]


def test_write_runtime_env_neutralises_shell_metacharacters(tmp_path: Path) -> None:
    path = tmp_path / "skuggi.env"
    # A hostile port value must not be able to inject a command when sourced.
    write_runtime_env(path, EngagementEnv(lport="$(touch pwned)"))
    text = path.read_text(encoding="utf-8")
    assert "export lport='$(touch pwned)'" in text  # single-quoted, inert
