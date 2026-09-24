"""L1: the tool registry, host probe and install selection.

A fake runner stands in for real command execution, so version capture and the
install path are exercised without spawning anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from skuggi.execution import CommandResult
from skuggi.registry import (
    ToolRegistry,
    ToolSpec,
    doctor_report,
    install_tool,
    managed_bin,
    probe,
    select_install,
)


class FakeRunner:
    """Records the argvs it is asked to run and returns canned output."""

    def __init__(self, stdout: str = "") -> None:
        self.stdout = stdout
        self.calls: list[list[str]] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        cwd: Path,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        self.calls.append(list(argv))
        now = datetime.now(UTC)
        return CommandResult(
            command=" ".join(argv),
            exit_code=0,
            stdout=self.stdout,
            stderr="",
            started_at=now,
            finished_at=now,
        )


NMAP = ToolSpec(
    name="nmap",
    binary="nmap",
    method="scan",
    version_args=("--version",),
    version_regex=r"Nmap version ([0-9.]+)",
    install={"brew": "brew install nmap", "apt": "apt-get install -y nmap"},
)
SQLMAP = ToolSpec(
    name="sqlmap",
    binary="sqlmap",
    method="enumerate",
    install={"pip": "pip install sqlmap"},
)
LOCAL_ONLY = ToolSpec(name="local", binary="localthing", method="recon")


# --- probe ------------------------------------------------------------------


def test_missing_tool_reports_missing() -> None:
    runner = FakeRunner()
    [status] = probe(
        ToolRegistry(tools=(LOCAL_ONLY,)),
        source="host",
        managed_dir=Path("/nonexistent"),
        runner=runner,
    )
    assert not status.found
    assert status.source == "missing"
    assert runner.calls == []


def test_managed_tool_is_found_and_versioned(tmp_path: Path) -> None:
    bindir = managed_bin(tmp_path)
    bindir.mkdir(parents=True)
    (bindir / "nmap").write_text("#!/bin/sh\n", encoding="utf-8")
    runner = FakeRunner(stdout="Nmap version 7.95 ( https://nmap.org )")

    [status] = probe(
        ToolRegistry(tools=(NMAP,)),
        source="managed",
        managed_dir=tmp_path,
        runner=runner,
    )

    assert status.found
    assert status.source == "managed"
    assert status.version == "7.95"


# --- select_install ---------------------------------------------------------


def test_combine_prefers_host_package_manager_on_macos() -> None:
    plan = select_install(NMAP, source="combine", system="Darwin")
    assert plan is not None
    assert plan.installer == "brew"


def test_combine_uses_apt_on_linux() -> None:
    plan = select_install(NMAP, source="combine", system="Linux")
    assert plan is not None
    assert plan.installer == "apt"


def test_managed_source_uses_pip() -> None:
    plan = select_install(SQLMAP, source="managed", system="Linux")
    assert plan is not None
    assert plan.target == "managed"


def test_host_source_cannot_install_a_pip_only_tool() -> None:
    assert select_install(SQLMAP, source="host", system="Linux") is None


def test_no_install_hint_is_unavailable() -> None:
    assert select_install(LOCAL_ONLY, source="combine", system="Linux") is None


# --- install_tool -----------------------------------------------------------


def test_install_runs_the_selected_host_command(tmp_path: Path) -> None:
    runner = FakeRunner()
    install_tool(
        NMAP, source="host", managed_dir=tmp_path, system="Darwin", runner=runner
    )
    assert ["brew", "install", "nmap"] in runner.calls


def test_managed_install_targets_the_venv_pip(tmp_path: Path) -> None:
    runner = FakeRunner()
    install_tool(
        SQLMAP, source="managed", managed_dir=tmp_path, system="Linux", runner=runner
    )
    pip = str(managed_bin(tmp_path) / "pip")
    assert any(call and call[0] == pip and "sqlmap" in call for call in runner.calls)


def test_unavailable_install_does_not_run_anything(tmp_path: Path) -> None:
    runner = FakeRunner()
    status = install_tool(
        LOCAL_ONLY,
        source="combine",
        managed_dir=tmp_path,
        system="Linux",
        runner=runner,
    )
    assert status.source == "unavailable"
    assert runner.calls == []


# --- doctor_report ----------------------------------------------------------


def test_doctor_report_lists_missing_with_hints() -> None:
    """Use a binary guaranteed absent from PATH so the row is always missing."""
    ghost = ToolSpec(
        name="ghost",
        binary="ghost-scanner-xyz",
        method="scan",
        install={"brew": "brew install ghost"},
    )
    runner = FakeRunner()
    statuses = probe(
        ToolRegistry(tools=(ghost,)),
        source="host",
        managed_dir=Path("/nonexistent"),
        runner=runner,
    )
    report = doctor_report(statuses)
    assert "# skuggi tool doctor" in report
    assert "Missing tools" in report
    assert "brew install ghost" in report


@pytest.mark.parametrize("missing_binary", ["localthing"])
def test_method_lookup_unknown_returns_none(missing_binary: str) -> None:
    assert ToolRegistry(tools=(NMAP,)).method_for(missing_binary) is None
