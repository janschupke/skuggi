"""L1: the runtime-var presenters (`show env` / env-change lines)."""

from __future__ import annotations

from skuggi.engagement.runtime_env import EngagementEnv
from skuggi.frontend.presenters import present_env, present_env_update


def _text(styled: object) -> str:
    assert isinstance(styled, list)
    return "\n".join(line.text for line in styled)


def test_present_env_labels_the_target_source() -> None:
    manual = _text(present_env(EngagementEnv(target="10.0.0.5"), "host.example"))
    assert "10.0.0.5" in manual
    assert "[manual]" in manual
    default = _text(present_env(EngagementEnv(), "host.example"))
    assert "host.example" in default
    assert "[scope default]" in default
    # Empty scope, no manual target -> unset.
    none = _text(present_env(EngagementEnv(), None))
    assert "(unset)" in none
    assert "[unset]" in none


def test_present_env_update_set_and_cleared() -> None:
    assert "set to 4444" in _text(present_env_update("lport", "4444"))
    assert "cleared" in _text(present_env_update("target", None))
