"""The engagement boundary: the scope model and the guard that enforces it.

Re-export facade. The scope model (:class:`TimeWindow` / :class:`ThreatModel` /
:class:`EngagementConfig`) lives in :mod:`skuggi.engagement.scope`, and the parse +
guard engine (:func:`parse_command` / :func:`check_command`) in
:mod:`skuggi.engagement.guard`. Both were split out of this module for size; this
stays the stable public import surface the rest of the harness imports from.
"""

from __future__ import annotations

from skuggi.engagement.guard import (
    GuardVerdict,
    ParsedCommand,
    check_command,
    parse_command,
)
from skuggi.engagement.scope import EngagementConfig, ThreatModel, TimeWindow

__all__ = [
    "EngagementConfig",
    "GuardVerdict",
    "ParsedCommand",
    "ThreatModel",
    "TimeWindow",
    "check_command",
    "parse_command",
]
