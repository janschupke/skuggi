"""Recognized-tool registry, host probe, and confirm-gated install.

The registry (loaded from ``configs/tools.json``) is skuggi's model of the
tools it knows: for each one, the binary name, the engagement *method* it
belongs to (recon / scan / ...), how to read its version, which argv positions
carry targets (this feeds ``engagement.parse_command`` so target extraction is
declarative, not guesswork), and per-installer install commands.

Host-agnosticism lives here. ``probe`` resolves each tool against the host
``PATH`` and/or a skuggi-managed directory per the configured ``tool_source``,
capturing versions by actually running the binary. ``select_install`` picks an
installer for the current OS without running anything (so it is unit-testable),
and ``install_tool`` runs the chosen command -- only ever on the operator's
explicit confirmation, which is the caller's responsibility.
"""

from __future__ import annotations

import platform
import re
import shlex
import shutil
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict, Field
from rich.console import Console
from rich.table import Table

from skuggi import execution, palette
from skuggi.execution import CommandResult

# Injectable so a test drives probe/install without spawning anything.
Runner = Callable[..., CommandResult]

# A single tool's version command must never stall the doctor: capped low, and
# every probe runs concurrently (see `probe`), so the whole survey is bounded by
# the slowest one, not their sum.
_VERSION_PROBE_TIMEOUT = 5.0
_PROBE_WORKERS = 8
_INSTALL_TIMEOUT = 600.0


class ToolSpec(BaseModel):
    """One recognized tool and everything skuggi needs to reason about it."""

    model_config = ConfigDict(frozen=True)

    name: str
    binary: str
    method: str
    version_args: tuple[str, ...] = ()
    version_regex: str | None = None
    # Argv flags whose following value is a target (e.g. curl's implicit
    # positional URL is covered by requires_target + the positional scan).
    target_flags: tuple[str, ...] = ()
    requires_target: bool = True
    install: dict[str, str] = Field(default_factory=dict)


class ToolRegistry(BaseModel):
    """The set of tools skuggi recognizes."""

    model_config = ConfigDict(frozen=True)

    tools: tuple[ToolSpec, ...] = ()

    def spec_for(self, binary: str) -> ToolSpec | None:
        """The spec whose binary matches `binary` (basename), or None."""
        for spec in self.tools:
            if spec.binary == binary:
                return spec
        return None

    def method_for(self, binary: str) -> str | None:
        """The engagement method `binary` belongs to, or None if unrecognized."""
        spec = self.spec_for(binary)
        return spec.method if spec else None


class ToolStatus(NamedTuple):
    """The result of probing one tool on this host."""

    spec: ToolSpec
    found: bool
    path: Path | None
    version: str | None
    source: str  # "host" | "managed" | "missing"


@dataclass(frozen=True, slots=True)
class InstallPlan:
    """A selected, not-yet-run install command."""

    argv: tuple[str, ...]
    target: str  # "host" | "managed"
    installer: str  # "brew" | "apt" | "pip"


def managed_bin(managed_dir: Path) -> Path:
    """The bin/ directory of skuggi's managed tool venv."""
    return managed_dir.expanduser() / "venv" / "bin"


def _resolve(
    spec: ToolSpec, *, source: str, managed_dir: Path
) -> tuple[Path | None, str]:
    """Find `spec.binary`, preferring the host in `combine`, then managed."""
    host = shutil.which(spec.binary) if source in ("host", "combine") else None
    if host is not None:
        return Path(host), "host"
    if source in ("managed", "combine"):
        candidate = managed_bin(managed_dir) / spec.binary
        if candidate.is_file():
            return candidate, "managed"
    return None, "missing"


def _version_from(
    path: Path,
    version_args: tuple[str, ...],
    version_regex: str | None,
    runner: Runner,
) -> str | None:
    """Run `path version_args` and extract a version string, or None."""
    if not version_args:
        return None
    result = runner(
        [str(path), *version_args],
        timeout=_VERSION_PROBE_TIMEOUT,
        cwd=Path.cwd(),
    )
    text = f"{result.stdout}\n{result.stderr}".strip()
    if not text:
        return None
    if version_regex:
        match = re.search(version_regex, text)
        return match.group(match.lastindex or 0) if match else None
    return text.splitlines()[0][:80]


def _read_version(path: Path, spec: ToolSpec, runner: Runner) -> str | None:
    """Run the tool's version command and extract a version string."""
    return _version_from(path, spec.version_args, spec.version_regex, runner)


def _map_concurrently[T, R](fn: Callable[[T], R], items: tuple[T, ...]) -> list[R]:
    """Apply `fn` to each item in a thread pool, preserving order.

    Probing is I/O-bound (spawning version commands), so threads keep the whole
    survey bounded by the slowest probe. An empty input avoids spinning up a pool.
    """
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(_PROBE_WORKERS, len(items))) as pool:
        return list(pool.map(fn, items))


def probe(
    registry: ToolRegistry,
    *,
    source: str,
    managed_dir: Path,
    runner: Runner = execution.run,
) -> list[ToolStatus]:
    """Resolve every tool in the registry against this host, concurrently.

    Each tool's version command is a subprocess with its own timeout; running
    them in a thread pool means the survey takes as long as the slowest single
    probe, not the sum -- so one slow tool never hangs the doctor.
    """

    def one(spec: ToolSpec) -> ToolStatus:
        path, where = _resolve(spec, source=source, managed_dir=managed_dir)
        version = _read_version(path, spec, runner) if path is not None else None
        return ToolStatus(
            spec=spec,
            found=path is not None,
            path=path,
            version=version,
            source=where,
        )

    return _map_concurrently(one, registry.tools)


def select_install(spec: ToolSpec, *, source: str, system: str) -> InstallPlan | None:
    """Pick an install command for `spec` on `system`, or None if unavailable.

    Pure: it chooses but never runs, so the whole OS/source matrix is unit
    tested. `system` is ``platform.system()`` ("Darwin" / "Linux" / ...).
    Preference: in ``combine`` a host package manager wins over pip (system
    scanners are rarely pip-installable); ``managed`` uses pip into the venv.
    """
    host_installer = "brew" if system == "Darwin" else "apt"
    want_host = source in ("host", "combine") and host_installer in spec.install
    want_pip = source in ("managed", "combine") and "pip" in spec.install

    if want_host:
        return InstallPlan(
            argv=tuple(shlex.split(spec.install[host_installer])),
            target="host",
            installer=host_installer,
        )
    if want_pip:
        return None if source == "host" else _pip_plan(spec)
    return None


def _pip_plan(spec: ToolSpec) -> InstallPlan:
    """A pip install targeting the managed venv (path filled by install_tool)."""
    return InstallPlan(
        argv=tuple(shlex.split(spec.install["pip"])),
        target="managed",
        installer="pip",
    )


def install_tool(
    spec: ToolSpec,
    *,
    source: str,
    managed_dir: Path,
    system: str | None = None,
    runner: Runner = execution.run,
) -> ToolStatus:
    """Install `spec` via the selected command, then re-probe it.

    The caller must have obtained the operator's confirmation first; this
    function does not prompt. A managed (pip) install bootstraps the venv on
    first use. Returns the post-install status so the caller can report it.
    """
    plan = select_install(spec, source=source, system=system or platform.system())
    if plan is None:
        return ToolStatus(
            spec=spec, found=False, path=None, version=None, source="unavailable"
        )

    if plan.target == "managed":
        _ensure_managed_venv(managed_dir, runner)
        pip = managed_bin(managed_dir) / "pip"
        # Replace a leading "pip"/"pip3" token with the venv's pip.
        rest = (
            plan.argv[1:] if plan.argv and plan.argv[0].startswith("pip") else plan.argv
        )
        argv: tuple[str, ...] = (str(pip), *rest)
    else:
        argv = plan.argv

    runner(list(argv), timeout=_INSTALL_TIMEOUT, cwd=Path.cwd())
    path, where = _resolve(spec, source=source, managed_dir=managed_dir)
    version = _read_version(path, spec, runner) if path is not None else None
    return ToolStatus(
        spec=spec, found=path is not None, path=path, version=version, source=where
    )


def _ensure_managed_venv(managed_dir: Path, runner: Runner) -> None:
    """Create the managed venv if it does not already exist."""
    venv = managed_dir.expanduser() / "venv"
    if (venv / "bin" / "python").is_file() or (venv / "bin" / "pip").is_file():
        return
    venv.parent.mkdir(parents=True, exist_ok=True)
    runner(
        ["python3", "-m", "venv", str(venv)],
        timeout=_INSTALL_TIMEOUT,
        cwd=Path.cwd(),
    )


def _method_rank(method: str) -> int:
    """Sort key placing methods in the palette's defined order, unknowns last."""
    order = palette.methods()
    return order.index(method) if method in order else len(order)


def doctor_table(statuses: list[ToolStatus]) -> Table:
    """A colour-coded Rich table of the host tool probe (palette-driven).

    Rows are grouped by method (in the palette's order) and carry the resolved
    binary path.
    """
    table = Table(title="skuggi tool doctor")
    for column in ("tool", "method", "status", "version", "source", "path"):
        table.add_column(column)
    ordered = sorted(
        statuses, key=lambda st: (_method_rank(st.spec.method), st.spec.binary)
    )
    for st in ordered:
        table.add_row(
            st.spec.binary,
            palette.paint(st.spec.method, palette.method_style(st.spec.method)),
            palette.paint(
                "found" if st.found else "missing",
                palette.status_style(found=st.found),
            ),
            st.version or "-",
            palette.paint(st.source, palette.source_style(st.source)),
            str(st.path) if st.path else "-",
        )
    return table


def available_installers() -> frozenset[str]:
    """The package managers actually present on this host.

    Install hints are host-agnostic in the registry; this is what makes the
    doctor's advice host-*verified* -- an ``apt`` hint is only shown where
    ``apt`` exists, a ``brew`` hint only where ``brew`` does. ``pip`` counts
    when a Python is present (the managed venv bootstraps its own pip).
    """
    found: set[str] = set()
    if shutil.which("brew"):
        found.add("brew")
    if shutil.which("apt-get") or shutil.which("apt"):
        found.add("apt")
    if shutil.which("pip") or shutil.which("pip3") or shutil.which("python3"):
        found.add("pip")
    return frozenset(found)


def _hint_block(
    header: str,
    missing: list[tuple[str, dict[str, str]]],
    available: frozenset[str],
) -> list[str]:
    """Lines for one group of missing things, each with a host-filtered hint.

    A thing whose only hints target absent package managers is reported as
    having no installer available here, rather than printing a command that
    cannot run.
    """
    lines = [header]
    for label, install in missing:
        usable = {k: v for k, v in install.items() if k in available}
        if usable:
            hints = "; ".join(f"{k}: {v}" for k, v in usable.items())
        elif install:
            hints = "no installer available on this host"
        else:
            hints = "no install hint"
        lines.append(f"  - {label}: {hints}")
    return lines


def doctor_hints(
    statuses: list[ToolStatus],
    runtimes: list[RuntimeStatus] | None = None,
    net_tools: list[RuntimeStatus] | None = None,
) -> str:
    """Install hints for the missing tools/runtimes/net tools, filtered to host.

    Returns '' when nothing is missing. Each kind is reported in its own block
    so the operator can tell a scoped tool from a host capability; all are
    filtered to the package managers that actually exist on this host.
    """
    groups = (
        ("tools", [(s.spec.binary, s.spec.install) for s in statuses if not s.found]),
        (
            "runtimes",
            [(s.spec.name, s.spec.install) for s in (runtimes or []) if not s.found],
        ),
        (
            "net tools",
            [(s.spec.name, s.spec.install) for s in (net_tools or []) if not s.found],
        ),
    )
    if not any(pairs for _, pairs in groups):
        return ""
    available = available_installers()
    header = ", ".join(sorted(available)) or "none"
    lines: list[str] = []
    for label, pairs in groups:
        if pairs:
            lines += _hint_block(
                f"Missing {label} (installers on this host: {header}):",
                pairs,
                available,
            )
    return "\n".join(lines)


def doctor_ansi(
    statuses: list[ToolStatus],
    runtimes: list[RuntimeStatus] | None = None,
    net_tools: list[RuntimeStatus] | None = None,
) -> str:
    """Render the tool table + capability tables + hints to an ANSI string.

    For the shell daemon: it renders on a non-terminal (the socket) while the
    client writes the result to the operator's real terminal, so colour must be
    forced on here.
    """
    console = Console(force_terminal=True, width=100)
    with console.capture() as capture:
        console.print(doctor_table(statuses))
        if runtimes:
            console.print(runtime_table(runtimes))
        if net_tools:
            console.print(net_tool_table(net_tools))
    hints = doctor_hints(statuses, runtimes, net_tools)
    return capture.get() + (hints + "\n" if hints else "")


@dataclass(frozen=True, slots=True)
class RuntimeSpec:
    """A standard host toolchain skuggi checks for (not a scoped tool)."""

    name: str
    binary: str
    version_args: tuple[str, ...] = ()
    version_regex: str | None = None
    # Host-verified install hints, keyed like ToolSpec.install (brew/apt/pip);
    # shown in the doctor for a missing runtime, filtered to present installers.
    install: dict[str, str] = field(default_factory=dict)


class RuntimeStatus(NamedTuple):
    """The result of probing one runtime on this host."""

    spec: RuntimeSpec
    found: bool
    path: Path | None
    version: str | None


# The interpreters and build tools an operator relies on to run scripts and
# build exploits. Distinct from the engagement tool registry: these are host
# capabilities, not authorized-and-scoped commands.
_RUNTIMES: tuple[RuntimeSpec, ...] = (
    RuntimeSpec(
        "ruby",
        "ruby",
        ("--version",),
        r"ruby ([0-9][0-9.]*)",
        {"brew": "brew install ruby", "apt": "apt install ruby"},
    ),
    RuntimeSpec(
        "rustc",
        "rustc",
        ("--version",),
        r"rustc ([0-9][0-9.]*)",
        {"brew": "brew install rust", "apt": "apt install rustc"},
    ),
    RuntimeSpec(
        "cargo",
        "cargo",
        ("--version",),
        r"cargo ([0-9][0-9.]*)",
        {"brew": "brew install rust", "apt": "apt install cargo"},
    ),
    RuntimeSpec(
        "python3",
        "python3",
        ("--version",),
        r"Python ([0-9][0-9.]*)",
        {"brew": "brew install python", "apt": "apt install python3"},
    ),
    RuntimeSpec(
        "node",
        "node",
        ("--version",),
        r"v?([0-9][0-9.]*)",
        {"brew": "brew install node", "apt": "apt install nodejs"},
    ),
    RuntimeSpec(
        "php",
        "php",
        ("--version",),
        r"PHP ([0-9][0-9.]*)",
        {"brew": "brew install php", "apt": "apt install php"},
    ),
    RuntimeSpec(
        "perl",
        "perl",
        ("--version",),
        r"\(v([0-9][0-9.]*)\)",
        {"brew": "brew install perl", "apt": "apt install perl"},
    ),
    RuntimeSpec(
        "cc",
        "cc",
        ("--version",),
        None,
        {"brew": "xcode-select --install", "apt": "apt install build-essential"},
    ),
    RuntimeSpec(
        "c++",
        "c++",
        ("--version",),
        None,
        {"brew": "xcode-select --install", "apt": "apt install build-essential"},
    ),
    RuntimeSpec(
        "make",
        "make",
        ("--version",),
        r"[Mm]ake ([0-9][0-9.]*)",
        {"brew": "xcode-select --install", "apt": "apt install build-essential"},
    ),
    RuntimeSpec(
        "powershell",
        "pwsh",
        ("--version",),
        r"PowerShell ([0-9][0-9.]*)",
        {"brew": "brew install --cask powershell", "apt": "apt install powershell"},
    ),
    RuntimeSpec(
        ".net",
        "dotnet",
        ("--version",),
        r"([0-9][0-9.]*)",
        {"brew": "brew install --cask dotnet-sdk", "apt": "apt install dotnet-sdk-8.0"},
    ),
)


# Standard Unix network utilities an operator reaches for constantly. Like the
# runtimes, these are host capabilities (not scoped engagement tools); they get
# their own table so a missing `ip` or `dig` is obvious at a glance.
_NET_TOOLS: tuple[RuntimeSpec, ...] = (
    RuntimeSpec(
        "dig",
        "dig",
        ("-v",),
        r"DiG ([0-9][0-9.]*)",
        {"brew": "brew install bind", "apt": "apt install dnsutils"},
    ),
    RuntimeSpec(
        "nslookup",
        "nslookup",
        (),
        None,
        {"brew": "brew install bind", "apt": "apt install dnsutils"},
    ),
    RuntimeSpec(
        "ifconfig",
        "ifconfig",
        (),
        None,
        {"apt": "apt install net-tools"},
    ),
    RuntimeSpec(
        "ip",
        "ip",
        (),
        None,
        {"brew": "brew install iproute2mac", "apt": "apt install iproute2"},
    ),
    RuntimeSpec(
        "wget",
        "wget",
        ("--version",),
        r"Wget ([0-9][0-9.]*)",
        {"brew": "brew install wget", "apt": "apt install wget"},
    ),
    RuntimeSpec(
        "ssh",
        "ssh",
        ("-V",),
        r"OpenSSH_([0-9][^,\s]*)",
        {"brew": "brew install openssh", "apt": "apt install openssh-client"},
    ),
)


def _probe_capabilities(
    specs: tuple[RuntimeSpec, ...], runner: Runner
) -> list[RuntimeStatus]:
    """Resolve and version every spec against this host, concurrently."""

    def one(spec: RuntimeSpec) -> RuntimeStatus:
        resolved = shutil.which(spec.binary)
        path = Path(resolved) if resolved is not None else None
        version = (
            _version_from(path, spec.version_args, spec.version_regex, runner)
            if path is not None
            else None
        )
        return RuntimeStatus(
            spec=spec, found=path is not None, path=path, version=version
        )

    return _map_concurrently(one, specs)


def probe_runtimes(runner: Runner = execution.run) -> list[RuntimeStatus]:
    """Resolve and version every standard runtime/toolchain, concurrently."""
    return _probe_capabilities(_RUNTIMES, runner)


def probe_net_tools(runner: Runner = execution.run) -> list[RuntimeStatus]:
    """Resolve and version every standard Unix net tool, concurrently."""
    return _probe_capabilities(_NET_TOOLS, runner)


def _capability_table(
    title: str, first_column: str, statuses: list[RuntimeStatus]
) -> Table:
    """A colour-coded Rich table of a host-capability probe (runtime or net)."""
    table = Table(title=title)
    for column in (first_column, "status", "version", "path"):
        table.add_column(column)
    for st in statuses:
        table.add_row(
            st.spec.name,
            palette.paint(
                "found" if st.found else "missing",
                palette.status_style(found=st.found),
            ),
            st.version or "-",
            str(st.path) if st.path else "-",
        )
    return table


def runtime_table(statuses: list[RuntimeStatus]) -> Table:
    """A colour-coded Rich table of the host runtime/toolchain probe."""
    return _capability_table("host runtimes / toolchains", "runtime", statuses)


def net_tool_table(statuses: list[RuntimeStatus]) -> Table:
    """A colour-coded Rich table of the standard Unix net-tool probe."""
    return _capability_table("standard net tools", "net tool", statuses)
