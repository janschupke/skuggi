"""The operating-mode literal.

skuggi runs one of four modes -- ``pentest``, ``redteam``, ``blueteam`` (offensive
and defensive, engagement-scoped) and ``forensics`` (a strictly read-only,
engagement-free analysis discipline over local evidence, bound to a *case* rather
than an engagement). The *type* lives here, in a leaf, so both ``config`` (the
``Settings.mode`` field) and ``agent`` (the prompts keyed by mode) can depend on it
without ``config`` having to import ``agent`` -- which would invert the dependency
graph. What a mode *does* (the prompt set it selects) stays in
``skuggi.agent.prompts``.
"""

from __future__ import annotations

from typing import Literal, get_args

Mode = Literal["pentest", "redteam", "blueteam", "forensics"]

MODES: tuple[Mode, ...] = get_args(Mode)

__all__ = ["MODES", "Mode"]
