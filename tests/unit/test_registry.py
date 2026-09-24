"""L1: the tool registry, host probe and install selection.

A fake runner stands in for real command execution, so version capture and the
install path are exercised without spawning anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from rich.console import Console

from skuggi.execution import CommandResult
from skuggi.registry import (
    ToolRegistry,
    ToolSpec,
    ToolStatus,
    available_installers,
    doctor_hints,
    doctor_table,
    install_tool,
    managed_bin,
    net_tool_table,
    probe,
    probe_net_tools,
    probe_runtimes,
    runtime_table,
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


# --- doctor rendering -------------------------------------------------------


def _missing_ghost() -> list[ToolStatus]:
    """A status list with one guaranteed-missing tool."""
    ghost = ToolSpec(
        name="ghost",
        binary="ghost-scanner-xyz",
        method="scan",
        install={"brew": "brew install ghost", "apt": "apt-get install -y ghost"},
    )
    return probe(
        ToolRegistry(tools=(ghost,)),
        source="host",
        managed_dir=Path("/nonexistent"),
        runner=FakeRunner(),
    )


def test_doctor_table_shows_tool_status() -> None:
    console = Console(force_terminal=True, width=100)
    with console.capture() as cap:
        console.print(doctor_table(_missing_ghost()))
    rendered = cap.get()
    assert "ghost-scanner-xyz" in rendered
    assert "missing" in rendered


def test_available_installers_is_host_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only package managers actually on PATH are reported available."""
    monkeypatch.setattr(
        "skuggi.registry.shutil.which",
        lambda name: "/usr/bin/x" if name == "brew" else None,
    )
    assert available_installers() == frozenset({"brew"})


def test_doctor_hints_filters_to_available_installers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An apt-only hint is not shown on a host without apt (the bug reported)."""
    # brew present, apt and pip absent
    monkeypatch.setattr(
        "skuggi.registry.shutil.which",
        lambda name: "/usr/bin/brew" if name == "brew" else None,
    )
    hints = doctor_hints(_missing_ghost())
    assert "brew install ghost" in hints
    assert "apt-get install" not in hints


def test_doctor_hints_reports_no_installer_when_none_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("skuggi.registry.shutil.which", lambda _name: None)
    hints = doctor_hints(_missing_ghost())
    assert "no installer available on this host" in hints


def test_doctor_hints_empty_when_nothing_missing() -> None:
    spec = ToolSpec(name="x", binary="x", method="scan")
    status = ToolStatus(spec, found=True, path=Path("/x"), version="1", source="host")
    assert doctor_hints([status]) == ""


@pytest.mark.parametrize("missing_binary", ["localthing"])
def test_method_lookup_unknown_returns_none(missing_binary: str) -> None:
    assert ToolRegistry(tools=(NMAP,)).method_for(missing_binary) is None


# --- runtime / toolchain probe ----------------------------------------------


def test_probe_runtimes_reports_found_and_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only python3 is on PATH; its version parses, the rest are missing."""
    monkeypatch.setattr(
        "skuggi.registry.shutil.which",
        lambda name: "/usr/bin/python3" if name == "python3" else None,
    )
    statuses = probe_runtimes(runner=FakeRunner(stdout="Python 3.14.0"))
    by_name = {s.spec.name: s for s in statuses}
    assert by_name["python3"].found
    assert by_name["python3"].version == "3.14.0"
    assert not by_name["ruby"].found
    assert by_name["ruby"].version is None


def test_runtime_table_renders_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("skuggi.registry.shutil.which", lambda _name: None)
    console = Console(force_terminal=True, width=100)
    with console.capture() as cap:
        console.print(runtime_table(probe_runtimes(runner=FakeRunner())))
    rendered = cap.get()
    assert "python3" in rendered
    assert "missing" in rendered


def test_runtimes_include_powershell_dotnet_and_perl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The runtime set covers the added interpreters/SDKs."""
    monkeypatch.setattr("skuggi.registry.shutil.which", lambda _name: None)
    names = {s.spec.name for s in probe_runtimes(runner=FakeRunner())}
    assert {"powershell", ".net", "perl"} <= names


def test_doctor_hints_lists_missing_runtimes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing runtime gets a host-filtered install hint in its own block."""
    monkeypatch.setattr(
        "skuggi.registry.shutil.which",
        lambda name: "/usr/bin/brew" if name == "brew" else None,
    )
    runtimes = probe_runtimes(runner=FakeRunner())
    hints = doctor_hints([], runtimes)
    assert "Missing runtimes" in hints
    assert "brew install perl" in hints
    assert "apt install perl" not in hints  # apt absent on this fake host


def test_probe_net_tools_reports_found_and_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only ssh is on PATH; its version parses, the rest are missing."""
    monkeypatch.setattr(
        "skuggi.registry.shutil.which",
        lambda name: "/usr/bin/ssh" if name == "ssh" else None,
    )
    statuses = probe_net_tools(runner=FakeRunner(stdout="OpenSSH_9.9p1, LibreSSL"))
    by_name = {s.spec.name: s for s in statuses}
    assert by_name["ssh"].found
    assert by_name["ssh"].version == "9.9p1"
    assert {"dig", "nslookup", "ifconfig", "ip", "wget"} <= set(by_name)
    assert not by_name["dig"].found


def test_net_tool_table_renders_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("skuggi.registry.shutil.which", lambda _name: None)
    console = Console(force_terminal=True, width=100)
    with console.capture() as cap:
        console.print(net_tool_table(probe_net_tools(runner=FakeRunner())))
    rendered = cap.get()
    assert "dig" in rendered
    assert "missing" in rendered


def test_doctor_hints_lists_missing_net_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing net tool gets its own host-filtered install-hint block."""
    monkeypatch.setattr(
        "skuggi.registry.shutil.which",
        lambda name: "/usr/bin/apt" if name in ("apt", "apt-get") else None,
    )
    net_tools = probe_net_tools(runner=FakeRunner())
    hints = doctor_hints([], None, net_tools)
    assert "Missing net tools" in hints
    assert "apt install iproute2" in hints
    assert "brew install" not in hints  # brew absent on this fake host


def test_doctor_table_sorts_by_method_and_shows_path() -> None:
    def status(binary: str, method: str, path: str) -> ToolStatus:
        return ToolStatus(
            ToolSpec(name=binary, binary=binary, method=method),
            found=True,
            path=Path(path),
            version=None,
            source="host",
        )

    statuses = [
        status("hydra", "bruteforce", "/b/hydra"),
        status("nmap", "scan", "/b/nmap"),
        status("curl", "recon", "/b/curl"),
    ]
    console = Console(force_terminal=True, width=120)
    with console.capture() as cap:
        console.print(doctor_table(statuses))
    rendered = cap.get()
    # palette method order: recon < scan < bruteforce
    assert rendered.index("curl") < rendered.index("nmap") < rendered.index("hydra")
    assert "/b/nmap" in rendered  # the binary-path column is present
