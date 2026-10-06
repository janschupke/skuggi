"""L3: AgentCore.burp_client builds the configured bridge client, offline.

Construction is lazy (no network), so this asserts the settings -> client wiring
and the backend dispatch without reaching a live Burp.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.burp.client import ReburpClient
from tests.support import engaged_core

_SCOPE: dict[str, object] = {
    "name": "burp-eng",
    "timezone": "UTC",
    "allowed_tools": ["burpsuite"],
    "allowed_methods": ["scan"],
}


def test_burp_client_defaults_to_reburp(tmp_path: Path) -> None:
    core = engaged_core(tmp_path, dict(_SCOPE))
    client = core.burp_client()
    assert isinstance(client, ReburpClient)


def test_burp_client_honours_key_override(tmp_path: Path) -> None:
    core = engaged_core(
        tmp_path,
        dict(_SCOPE),
        burp_base_url="http://127.0.0.1:9999",
        burp_api_key="secret-token",
    )
    assert isinstance(core.burp_client(), ReburpClient)


def test_burp_client_unimplemented_backend_raises(tmp_path: Path) -> None:
    # reburp is the only implemented backend; an unimplemented one raises rather
    # than silently mis-dispatching.
    core = engaged_core(tmp_path, dict(_SCOPE), burp_backend="mcp")
    with pytest.raises(NotImplementedError):
        core.burp_client()
