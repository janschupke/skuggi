"""Shared fixtures and helpers for the wrapped-shell daemon tests.

The daemon's routing is exercised across two modules -- ``test_daemon`` (verb
dispatch) and ``test_daemon_attach`` (the persistent attach session) -- so the
``daemon`` fixture and the little response-collecting helpers live here.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from skuggi.agent.core import AgentCore
from skuggi.frontend.daemon import Daemon
from tests.conftest import offline_settings, wire_offline_core

# The daemon paints presenter output with ANSI (matching the REPL); the tests
# assert on logical content, so strip the SGR codes before matching.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def daemon_core(tmp_path: Path) -> AgentCore:
    """An offline, wired AgentCore for a daemon under test."""
    core = AgentCore(offline_settings(tmp_path))
    wire_offline_core(core)
    return core


@pytest.fixture
def daemon(tmp_path: Path, pentest_configs: Callable[..., Path]) -> Iterator[Daemon]:
    pentest_configs()
    core = daemon_core(tmp_path)
    yield Daemon(core)
    core.close()


def chunks(daemon: Daemon, msg: dict[str, object]) -> str:
    """The daemon's streamed chunks for one request, joined and ANSI-stripped."""
    joined = "".join(str(r.get("chunk", "")) for r in daemon.handle_request(msg))
    return _ANSI.sub("", joined)


def responses(daemon: Daemon, msg: dict[str, object]) -> list[dict[str, object]]:
    """Every response frame the daemon yields for one request."""
    return list(daemon.handle_request(msg))


def candidates(daemon: Daemon, words: list[str]) -> list[str]:
    """The completion candidates the daemon returns for `words`."""
    [frame] = daemon.handle_request({"op": "complete", "words": words})
    cands = frame["candidates"]
    assert isinstance(cands, list)
    return cands
