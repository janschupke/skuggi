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
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from skuggi import execution
from skuggi.execution import CommandResult

# Injectable so a test drives probe/install without spawning anything.
Runner = Callable[..., CommandResult]

_VERSION_PROBE_TIMEOUT = 10.0
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


def _read_version(path: Path, spec: ToolSpec, runner: Runner) -> str | None:
    """Run the tool's version command and extract a version string."""
    if not spec.version_args:
        return None
    result = runner(
        [str(path), *spec.version_args],
        timeout=_VERSION_PROBE_TIMEOUT,
        cwd=Path.cwd(),
    )
    text = f"{result.stdout}\n{result.stderr}".strip()
    if not text:
        return None
    if spec.version_regex:
        match = re.search(spec.version_regex, text)
        return match.group(match.lastindex or 0) if match else None
    return text.splitlines()[0][:80]


def probe(
    registry: ToolRegistry,
    *,
    source: str,
    managed_dir: Path,
    runner: Runner = execution.run,
) -> list[ToolStatus]:
    """Resolve every tool in the registry against this host."""
    statuses: list[ToolStatus] = []
    for spec in registry.tools:
        path, where = _resolve(spec, source=source, managed_dir=managed_dir)
        version = _read_version(path, spec, runner) if path is not None else None
        statuses.append(
            ToolStatus(
                spec=spec,
                found=path is not None,
                path=path,
                version=version,
                source=where,
            )
        )
    return statuses


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


def doctor_report(statuses: list[ToolStatus]) -> str:
    """Render a Markdown status table plus install hints for missing tools."""
    lines = [
        "# skuggi tool doctor",
        "",
        "| tool | method | status | version | source |",
        "|---|---|---|---|---|",
    ]
    for st in statuses:
        mark = "found" if st.found else "**missing**"
        lines.append(
            f"| {st.spec.binary} | {st.spec.method} | {mark} | "
            f"{st.version or '-'} | {st.source} |"
        )
    missing = [st for st in statuses if not st.found]
    if missing:
        lines += ["", "## Missing tools", ""]
        for st in missing:
            hints = ", ".join(f"`{k}`: `{v}`" for k, v in st.spec.install.items())
            lines.append(f"- **{st.spec.binary}** — {hints or 'no install hint'}")
    return "\n".join(lines)
