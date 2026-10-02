"""L1: the verb registry's per-surface command-hint formatter."""

from __future__ import annotations

from skuggi.frontend import verbs


def test_cmd_formats_per_surface() -> None:
    assert verbs.cmd("setup", "shell") == "/skuggi setup"
    assert verbs.cmd("setup", "repl") == "/setup"
    assert verbs.cmd("setup", "chat") == "setup"


def test_cmd_keeps_multiword_invocations() -> None:
    assert verbs.cmd("engagement setup", "shell") == "/skuggi engagement setup"
    assert verbs.cmd("engagement setup", "repl") == "/engagement setup"
    assert verbs.cmd("engagement setup", "chat") == "engagement setup"


def test_cmd_defaults_to_shell() -> None:
    assert verbs.cmd("setup") == "/skuggi setup"
