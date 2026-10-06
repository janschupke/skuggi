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

from skuggi.common import palette
from skuggi.common.execution import CommandResult
from skuggi.common.modes import Mode
from skuggi.tooling.doctor import (
    doctor_hints,
    doctor_table,
    net_tool_table,
    runtime_table,
    tool_tables,
)
from skuggi.tooling.probe import (
    available_installers,
    install_tool,
    install_with_plan,
    managed_bin,
    probe,
    probe_net_tools,
    probe_runtimes,
    search_packages,
    select_install,
)
from skuggi.tooling.registry import (
    InstallPlan,
    ToolRegistry,
    ToolSpec,
    ToolStatus,
    tool_category,
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
        "skuggi.tooling.probe.shutil.which",
        lambda name: "/usr/bin/x" if name == "brew" else None,
    )
    assert available_installers() == frozenset({"brew"})


def test_doctor_hints_filters_to_available_installers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An apt-only hint is not shown on a host without apt (the bug reported)."""
    # brew present, apt and pip absent
    monkeypatch.setattr(
        "skuggi.tooling.probe.shutil.which",
        lambda name: "/usr/bin/brew" if name == "brew" else None,
    )
    hints = doctor_hints(_missing_ghost())
    assert "brew install ghost" in hints
    assert "apt-get install" not in hints


def test_doctor_hints_reports_no_installer_when_none_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("skuggi.tooling.probe.shutil.which", lambda _name: None)
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
        "skuggi.tooling.probe.shutil.which",
        lambda name: "/usr/bin/python3" if name == "python3" else None,
    )
    statuses = probe_runtimes(runner=FakeRunner(stdout="Python 3.14.0"))
    by_name = {s.spec.name: s for s in statuses}
    assert by_name["python3"].found
    assert by_name["python3"].version == "3.14.0"
    assert not by_name["ruby"].found
    assert by_name["ruby"].version is None


def test_runtime_table_renders_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("skuggi.tooling.probe.shutil.which", lambda _name: None)
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
    monkeypatch.setattr("skuggi.tooling.probe.shutil.which", lambda _name: None)
    names = {s.spec.name for s in probe_runtimes(runner=FakeRunner())}
    assert {"powershell", ".net", "perl"} <= names


def test_doctor_hints_lists_missing_runtimes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing runtime gets a host-filtered install hint in its own block."""
    monkeypatch.setattr(
        "skuggi.tooling.probe.shutil.which",
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
        "skuggi.tooling.probe.shutil.which",
        lambda name: "/usr/bin/ssh" if name == "ssh" else None,
    )
    statuses = probe_net_tools(runner=FakeRunner(stdout="OpenSSH_9.9p1, LibreSSL"))
    by_name = {s.spec.name: s for s in statuses}
    assert by_name["ssh"].found
    assert by_name["ssh"].version == "9.9p1"
    assert {"dig", "nslookup", "ifconfig", "ip", "wget"} <= set(by_name)
    assert not by_name["dig"].found


def test_net_tool_table_renders_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("skuggi.tooling.probe.shutil.which", lambda _name: None)
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
        "skuggi.tooling.probe.shutil.which",
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


# --- casks and package search (install research, Phase 3a) -------------------

BURP = ToolSpec(
    name="burpsuite",
    binary="burpsuite",
    method="scan",
    install={"brew": "brew install --cask burp-suite"},
)


class _ExitRunner:
    """A runner with a configurable exit code and per-argv canned stdout."""

    def __init__(
        self, *, exit_code: int = 0, outputs: dict[str, str] | None = None
    ) -> None:
        self.exit_code = exit_code
        self._outputs = outputs or {}
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
        key = " ".join(argv)
        stdout = next((v for k, v in self._outputs.items() if k in key), "")
        return CommandResult(
            command=key,
            exit_code=self.exit_code,
            stdout=stdout,
            stderr="",
            started_at=now,
            finished_at=now,
        )


def test_cask_plan_is_recognised() -> None:
    plan = select_install(BURP, source="host", system="Darwin")
    assert plan is not None
    assert plan.installer == "brew"
    assert plan.is_cask


def test_a_cask_install_that_exits_clean_is_a_success_despite_no_path_binary(
    tmp_path: Path,
) -> None:
    """A clean exit is the only success signal a cask gives.

    burpsuite/bloodhound install an .app bundle, never a PATH binary, so this must
    not read as 'install failed'.
    """
    runner = _ExitRunner(exit_code=0)
    status = install_tool(
        BURP, source="host", managed_dir=tmp_path, system="Darwin", runner=runner
    )
    assert ["brew", "install", "--cask", "burp-suite"] in runner.calls
    assert status.found
    assert status.source == "cask"


def test_a_cask_install_that_fails_is_not_claimed_as_installed(tmp_path: Path) -> None:
    runner = _ExitRunner(exit_code=1)
    status = install_tool(
        BURP, source="host", managed_dir=tmp_path, system="Darwin", runner=runner
    )
    assert not status.found


def test_search_packages_parses_brew_and_apt_and_tags_each_hit() -> None:
    runner = _ExitRunner(
        outputs={
            "brew search --formula": "burp\nburpsuite-helper\n",
            "brew search --cask": "==> Casks\nburp-suite\nburp-suite-professional\n",
            "apt-cache search": "burpsuite - web proxy\nlibburp - unrelated\n",
        }
    )
    hits = search_packages("burp", installers=frozenset({"brew", "apt"}), runner=runner)
    pairs = {(h.installer, h.name) for h in hits}
    assert ("brew", "burp") in pairs
    assert ("brew-cask", "burp-suite") in pairs
    assert ("apt", "burpsuite") in pairs
    # Section headers never become hits.
    assert all(h.name != "==> Casks" for h in hits)
    # apt summaries are carried through.
    assert any(h.name == "burpsuite" and "web proxy" in h.summary for h in hits)


def test_search_packages_only_queries_present_installers() -> None:
    runner = _ExitRunner(outputs={"brew search --formula": "nmap\n"})
    search_packages("nmap", installers=frozenset({"brew"}), runner=runner)
    assert not any("apt-cache" in " ".join(c) for c in runner.calls)


def test_search_packages_rejects_a_query_that_could_be_a_flag_or_injection() -> None:
    runner = _ExitRunner(outputs={"brew": "x\n"})
    for bad in ("-x", "; rm -rf /", "a b", "$(whoami)", ""):
        assert search_packages(bad, installers=frozenset({"brew"}), runner=runner) == []
    assert runner.calls == []  # nothing was ever searched


def test_search_packages_is_best_effort_on_a_failing_search() -> None:
    runner = _ExitRunner(exit_code=2, outputs={"brew": "nmap\n"})
    assert search_packages("nmap", installers=frozenset({"brew"}), runner=runner) == []


# --- install_with_plan: running a researched (ad-hoc) plan -------------------


def test_install_with_plan_reports_cask_success(tmp_path: Path) -> None:
    plan = InstallPlan(
        argv=("brew", "install", "--cask", "burp-suite"),
        target="host",
        installer="brew-cask",
    )
    outcome = install_with_plan(
        plan, "burpsuite", managed_dir=tmp_path, runner=_ExitRunner(exit_code=0)
    )
    assert outcome.installed
    assert outcome.source == "cask"


def test_install_with_plan_reports_failure_on_a_nonzero_exit(tmp_path: Path) -> None:
    plan = InstallPlan(
        argv=("brew", "install", "nmap"), target="host", installer="brew"
    )
    outcome = install_with_plan(
        plan, "nmap", managed_dir=tmp_path, runner=_ExitRunner(exit_code=1)
    )
    assert not outcome.installed
    assert outcome.source == "failed"


def test_install_with_plan_resolves_a_host_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("skuggi.tooling.probe.shutil.which", lambda _b: "/usr/bin/nmap")
    plan = InstallPlan(
        argv=("brew", "install", "nmap"), target="host", installer="brew"
    )
    outcome = install_with_plan(
        plan, "nmap", managed_dir=tmp_path, runner=_ExitRunner(exit_code=0)
    )
    assert outcome.installed
    assert outcome.source == "host"
    assert outcome.path == Path("/usr/bin/nmap")


# --- doctor tool categories + sectioning ------------------------------------


def test_tool_category_derives_from_method_and_modes() -> None:
    off = ToolSpec(name="nmap", binary="nmap", method="scan")
    fmethod = ToolSpec(name="volatility", binary="vol", method="forensics")
    blue = ToolSpec(name="yara", binary="yara", method="enumerate", modes=("blueteam",))
    # A tool offered in blueteam AND an offensive mode is still offensive.
    mixed = ToolSpec(name="x", binary="x", method="scan", modes=("blueteam", "pentest"))
    assert tool_category(off) == "offensive"
    assert tool_category(fmethod) == "forensics"
    assert tool_category(blue) == "forensics"
    assert tool_category(mixed) == "offensive"


def test_tool_tables_split_into_offensive_and_forensics_sections() -> None:
    def status(binary: str, method: str, modes: tuple[Mode, ...] = ()) -> ToolStatus:
        return ToolStatus(
            ToolSpec(name=binary, binary=binary, method=method, modes=modes),
            found=True,
            path=Path(f"/b/{binary}"),
            version=None,
            source="host",
        )

    statuses = [
        status("nmap", "scan"),
        status("yara", "enumerate", ("blueteam",)),
        status("vol", "forensics"),
    ]
    titles = [str(t.title) for t in tool_tables(statuses)]
    assert any("offensive" in t for t in titles)
    assert any("forensics" in t for t in titles)
    # `--category` narrows to one section.
    only = tool_tables(statuses, category="forensics")
    assert len(only) == 1
    assert "forensics" in str(only[0].title)


def test_transport_method_rows_are_coloured_not_default() -> None:
    # `transport` tools (ssh/proxychains/socat/chisel) used to fall through to the
    # default white because the method was missing from the palette; it's added now.
    assert "transport" in palette.methods()
    assert palette.method_style("transport") != palette._METHOD_DEFAULT
