"""L1: the system/harness awareness blocks fed into the agent's request context.

These are pure renderers over already-gathered data, so the whole surface pins as
text. Presence is probed through the ``managed`` source against a temp venv bin so
the result never depends on what the developer happens to have on ``$PATH``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from skuggi.agent import awareness
from skuggi.engagement.engagement import EngagementConfig
from skuggi.tooling import probe
from skuggi.tooling.registry import ToolRegistry, ToolSpec

REGISTRY = ToolRegistry(
    tools=(
        ToolSpec(name="nmap", binary="nmap", method="scan"),
        ToolSpec(name="nikto", binary="nikto", method="scan"),
        ToolSpec(name="sqlmap", binary="sqlmap", method="exploit"),
        ToolSpec(name="unscoped", binary="unscoped", method="crack"),
    )
)


def _engagement(**overrides: object) -> EngagementConfig:
    base: dict[str, object] = {
        "name": "e",
        "timezone": "UTC",
        "authorized_start": datetime(2026, 1, 1, tzinfo=UTC),
        "authorized_end": datetime(2026, 12, 31, 23, 59, tzinfo=UTC),
        "target_networks": ("10.0.0.0/8",),
        "allowed_hosts": frozenset({"scanme.example.com"}),
        "allowed_tools": frozenset({"nmap", "nikto"}),
        "allowed_methods": frozenset({"exploit"}),  # also pulls sqlmap in by method
    }
    base.update(overrides)
    return EngagementConfig.model_validate(base)


@pytest.fixture
def managed_dir(tmp_path: Path) -> Path:
    """A managed tool dir with ``nmap`` present and ``nikto``/``sqlmap`` absent."""
    bindir = probe.managed_bin(tmp_path)
    bindir.mkdir(parents=True)
    (bindir / "nmap").write_text("#!/bin/sh\n")
    return tmp_path


def _facts(managed_dir: Path, engagement: EngagementConfig | None) -> str:
    return awareness.system_facts_block(
        REGISTRY, engagement, source="managed", managed_dir=managed_dir
    )


def test_system_facts_always_report_os_and_installers(
    managed_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(probe, "available_installers", lambda: frozenset({"pip"}))
    block = _facts(managed_dir, None)
    assert block.startswith("os: ")
    assert "installers available: pip" in block


def test_no_installers_renders_none(
    managed_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(probe, "available_installers", frozenset)
    assert "installers available: (none)" in _facts(managed_dir, None)


def test_without_engagement_no_tool_lines(managed_dir: Path) -> None:
    block = _facts(managed_dir, None)
    assert "scoped tools" not in block


def test_scoped_tools_split_installed_vs_missing(managed_dir: Path) -> None:
    # nmap is present; nikto (scoped by name) and sqlmap (scoped by method) absent.
    block = _facts(managed_dir, _engagement())
    assert "scoped tools installed: nmap" in block
    assert "scoped tools missing: nikto, sqlmap" in block
    # `unscoped` is neither in allowed_tools nor allowed_methods -> excluded entirely.
    assert "unscoped" not in block


def test_catalogue_lists_verbs_and_aliases() -> None:
    block = awareness.harness_catalogue_block(("nmap-fast", "nikto-basic"))
    assert "chat" in block  # the agent verb is always present
    assert "saved cmd aliases: nmap-fast, nikto-basic" in block


def test_catalogue_with_no_aliases() -> None:
    assert "saved cmd aliases: (none saved)" in awareness.harness_catalogue_block(())


# --- network posture awareness ----------------------------------------------


def test_network_posture_host_direct() -> None:
    line = awareness.network_posture_line(
        backend="host", container_network="none", egress_proxy=None
    )
    assert "direct host network" in line
    assert "public-only" in line  # recon egress note always present


def test_network_posture_host_proxied() -> None:
    line = awareness.network_posture_line(
        backend="host", container_network="none", egress_proxy="http://127.0.0.1:8080"
    )
    assert "egress proxy" in line


def test_network_posture_container_names_the_network() -> None:
    line = awareness.network_posture_line(
        backend="container", container_network="scoped-egress", egress_proxy=None
    )
    assert "container" in line
    assert "scoped-egress" in line


def test_system_facts_block_appends_the_network_line() -> None:
    block = awareness.system_facts_block(
        ToolRegistry(tools=()),
        None,
        source="host",
        managed_dir=Path("/tmp/x"),  # noqa: S108
        network="tool execution: container, --network none; recon egress: public-only",
    )
    assert "network: tool execution: container" in block
