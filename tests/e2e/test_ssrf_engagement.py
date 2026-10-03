"""L5 SSRF: a vuln class the web+db fixture cannot express, on its own stack.

Proves the real pipeline (guard, registry, executor, ledger) drives an SSRF: the
worker proposes a curl of the edge's ``/fetch?url=`` and the app crosses the
boundary to its own unpublished internal ``:9000/secret`` and hands the secret
back. The fixture is a separate compose project on an auto-allocated network, so
it coexists with everything else and touches no ``labs/``.
"""

from __future__ import annotations

import httpx
import pytest

from tests.e2e.conftest import Lab, Runner, require_tool

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]

_SECRET = "SSRF-SECRET-a1b2c3d4-internal-only"  # tests/e2e/fixtures/ssrf/server.py


def test_edge_is_healthy_and_carries_no_secret(ssrf: Lab) -> None:
    """The published edge serves health but never the secret directly."""
    resp = httpx.get(f"{ssrf.base_url}/", timeout=5.0)
    assert resp.is_success
    assert resp.text == "ok"
    assert _SECRET not in resp.text


def test_ssrf_reaches_the_unpublished_internal_secret(
    ssrf_engage: Runner, ssrf: Lab
) -> None:
    require_tool("curl")
    # The internal :9000 is not published, so this is reachable only because the
    # edge fetches it for us -- the SSRF crossing the boundary.
    rows = ssrf_engage.run(
        f"curl -s {ssrf.base_url}/fetch?url=http://127.0.0.1:9000/secret"
    )
    executed = [r for r in rows if r.status == "executed"]
    assert len(executed) == 1
    assert executed[0].exit_code == 0
    assert _SECRET in executed[0].stdout
