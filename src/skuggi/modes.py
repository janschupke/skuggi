"""Operating modes -- a compatibility shim over ``skuggi.prompts``.

skuggi runs one of three modes -- ``pentest``, ``redteam``, ``blueteam`` -- and
the only thing a mode changes is the three prompts the graph's planner, worker
and critic run under. Those prompts (and every other prompt skuggi sends) now
live in ``skuggi.prompts``; this module re-exports the mode surface so the many
existing ``from skuggi.modes import Mode / MODES / prompt_set`` imports keep
working without change.
"""

from __future__ import annotations

from skuggi.prompts import MODES, Mode, PromptSet, prompt_set

__all__ = ["MODES", "Mode", "PromptSet", "prompt_set"]
