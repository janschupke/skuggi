"""Host probing and confirm-gated install for the tool registry.

Host-agnosticism lives here. ``probe`` resolves each registry tool against the
host ``PATH`` and/or a skuggi-managed directory per the configured
``tool_source``, capturing versions by actually running the binary;
``probe_runtimes`` / ``probe_net_tools`` do the same for the standard host
capabilities. ``select_install`` picks an installer for the current OS without
running anything (so it is unit-testable), and ``install_tool`` runs the chosen
command -- only ever on the operator's explicit confirmation, which is the
caller's responsibility. Rendering the results is ``skuggi.doctor``'s job.
"""

from __future__ import annotations

import platform
import re
import shlex
import shutil
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from skuggi.common import execution
from skuggi.common.execution import CommandResult
from skuggi.common.paths import ensure_parent
from skuggi.tooling.registry import (
    InstallOutcome,
    InstallPlan,
    PackageHit,
    RuntimeSpec,
    RuntimeStatus,
    ToolRegistry,
    ToolSpec,
    ToolStatus,
)

# Injectable so a test drives probe/install without spawning anything.
Runner = Callable[..., CommandResult]

# A single tool's version command must never stall the doctor: capped low, and
# every probe runs concurrently (see `probe`), so the whole survey is bounded by
# the slowest one, not their sum.
_VERSION_PROBE_TIMEOUT = 5.0
_PROBE_WORKERS = 8
_INSTALL_TIMEOUT = 600.0
_SEARCH_TIMEOUT = 20.0
_MAX_HITS_PER_INSTALLER = 25

# A query safe to pass as a search term: name-like, no leading dash (so it can
# never be read as a flag) and only characters a package name uses.
_SEARCHABLE_QUERY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")
# A package token we are willing to return. Kept within what `safe_cmd_fragment`
# accepts, so every hit can be rebuilt into an install argv without rejection.
_SAFE_PKG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./=-]*$")


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


def _read_version(
    spec: ToolSpec | RuntimeSpec, path: Path | None, runner: Runner
) -> str | None:
    """Version string for a resolved spec, or None if unresolved/unreadable.

    Shared by the tool probe and the capability probes -- both spec types carry
    ``version_args``/``version_regex``.
    """
    if path is None:
        return None
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
        return ToolStatus(
            spec=spec,
            found=path is not None,
            path=path,
            version=_read_version(spec, path, runner),
            source=where,
        )

    return _map_concurrently(one, registry.tools)


def probe_presence(
    registry: ToolRegistry, *, source: str, managed_dir: Path
) -> list[ToolStatus]:
    """Resolve each tool's presence WITHOUT running its version command.

    The agent's awareness context needs only found/missing per tool, not
    versions, and ``_resolve`` is a pure ``shutil.which``/``is_file`` check with
    no subprocess -- so this is cheap enough to run on every graph rebuild, unlike
    :func:`probe` (which spawns a version command per tool). ``version`` is always
    ``None`` here; call :func:`probe` when a version is wanted.
    """

    def one(spec: ToolSpec) -> ToolStatus:
        path, where = _resolve(spec, source=source, managed_dir=managed_dir)
        return ToolStatus(
            spec=spec, found=path is not None, path=path, version=None, source=where
        )

    return [one(spec) for spec in registry.tools]


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

    argv = _install_argv(plan, managed_dir, runner)
    result = runner(list(argv), timeout=_INSTALL_TIMEOUT, cwd=Path.cwd())
    path, where = _resolve(spec, source=source, managed_dir=managed_dir)
    if path is None and plan.is_cask and result.exit_code == 0:
        # A Homebrew cask installs a GUI .app, not a PATH binary, so `_resolve`
        # will never find it -- reporting that as "install failed" is the bug that
        # made burpsuite/bloodhound look broken after a clean install. A clean exit
        # is the only success signal a cask gives, so trust it.
        return ToolStatus(spec=spec, found=True, path=None, version=None, source="cask")
    return ToolStatus(
        spec=spec,
        found=path is not None,
        path=path,
        version=_read_version(spec, path, runner),
        source=where,
    )


def _install_argv(
    plan: InstallPlan, managed_dir: Path, runner: Runner
) -> tuple[str, ...]:
    """The argv to actually run for `plan`, bootstrapping the managed venv if needed.

    A ``managed`` (pip) plan installs into skuggi's own venv: the venv is created on
    first use and the leading ``pip``/``pip3`` token is rewritten to that venv's pip.
    A host plan runs verbatim. Shared by :func:`install_tool` and
    :func:`install_with_plan` so the pip-into-venv handling lives in one place.
    """
    if plan.target != "managed":
        return plan.argv
    _ensure_managed_venv(managed_dir, runner)
    pip = managed_bin(managed_dir) / "pip"
    rest = plan.argv[1:] if plan.argv and plan.argv[0].startswith("pip") else plan.argv
    return (str(pip), *rest)


def install_with_plan(
    plan: InstallPlan,
    binary: str,
    *,
    managed_dir: Path,
    runner: Runner = execution.run,
) -> InstallOutcome:
    """Run a researched `plan` to install `binary`, then report the outcome.

    Unlike :func:`install_tool`, there is no registry ``ToolSpec``: the plan was
    produced by install research (searching the host's package managers), so the
    tool is re-probed with a plain ``shutil.which(binary)``. The caller must have
    gated this behind the operator's approval. A non-zero exit is a failure; a cask
    that exits clean counts as installed even though its GUI app is not on PATH.
    """
    argv = _install_argv(plan, managed_dir, runner)
    result = runner(list(argv), timeout=_INSTALL_TIMEOUT, cwd=Path.cwd())
    if result.exit_code != 0:
        return InstallOutcome(
            binary=binary, installed=False, path=None, source="failed"
        )
    resolved = shutil.which(binary)
    path = Path(resolved) if resolved is not None else None
    if plan.is_cask:
        return InstallOutcome(binary=binary, installed=True, path=path, source="cask")
    source = "managed" if plan.target == "managed" else "host"
    return InstallOutcome(
        binary=binary, installed=path is not None, path=path, source=source
    )


def _ensure_managed_venv(managed_dir: Path, runner: Runner) -> None:
    """Create the managed venv if it does not already exist."""
    venv = managed_dir.expanduser() / "venv"
    if (venv / "bin" / "python").is_file() or (venv / "bin" / "pip").is_file():
        return
    ensure_parent(venv)
    runner(
        ["python3", "-m", "venv", str(venv)],
        timeout=_INSTALL_TIMEOUT,
        cwd=Path.cwd(),
    )


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


def _brew_search(query: str, *, cask: bool, runner: Runner) -> list[PackageHit]:
    """Search Homebrew formulae (or casks) for `query`; [] on any error."""
    kind = "--cask" if cask else "--formula"
    result = runner(
        ["brew", "search", kind, query], timeout=_SEARCH_TIMEOUT, cwd=Path.cwd()
    )
    if result.exit_code != 0:
        return []
    installer = "brew-cask" if cask else "brew"
    hits: list[PackageHit] = []
    for line in result.stdout.splitlines():
        name = line.strip()
        # Skip brew's section headers ("==> Formulae") and its "If you meant ..."
        # tap suggestions; keep only bare, install-safe tokens.
        if not name or name.startswith("==>") or not _SAFE_PKG.match(name):
            continue
        hits.append(PackageHit(installer=installer, name=name))
        if len(hits) >= _MAX_HITS_PER_INSTALLER:
            break
    return hits


def _apt_search(query: str, *, runner: Runner) -> list[PackageHit]:
    """Search apt's package index for `query` (``name - description``); [] on error."""
    result = runner(
        ["apt-cache", "search", query], timeout=_SEARCH_TIMEOUT, cwd=Path.cwd()
    )
    if result.exit_code != 0:
        return []
    hits: list[PackageHit] = []
    for line in result.stdout.splitlines():
        name, _, summary = line.partition(" - ")
        name = name.strip()
        if not name or not _SAFE_PKG.match(name):
            continue
        hits.append(
            PackageHit(installer="apt", name=name, summary=summary.strip()[:120])
        )
        if len(hits) >= _MAX_HITS_PER_INSTALLER:
            break
    return hits


def search_packages(
    query: str,
    *,
    installers: frozenset[str],
    runner: Runner = execution.run,
) -> list[PackageHit]:
    """Search every available host package manager for `query`, read-only.

    The deterministic grounding for install research: it SEARCHES, never installs,
    so a caller can resolve a tool whose exact package name it does not know. Only
    the installers the host actually has are queried (`available_installers`), and
    each search is best-effort -- one that errors or times out contributes no hits
    rather than failing the call. `query` is validated to a name-like token first,
    so it can never be read as a flag or carry shell metacharacters. Searches run
    concurrently, like the host probes.
    """
    query = query.strip()
    if not _SEARCHABLE_QUERY.match(query):
        return []
    probes: list[Callable[[], list[PackageHit]]] = []
    if "brew" in installers:
        probes.append(lambda: _brew_search(query, cask=False, runner=runner))
        probes.append(lambda: _brew_search(query, cask=True, runner=runner))
    if "apt" in installers:
        probes.append(lambda: _apt_search(query, runner=runner))
    hits: list[PackageHit] = []
    for batch in _map_concurrently(lambda probe_fn: probe_fn(), tuple(probes)):
        hits.extend(batch)
    return hits


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
    """Resolve and version every capability spec against this host, concurrently."""

    def one(spec: RuntimeSpec) -> RuntimeStatus:
        resolved = shutil.which(spec.binary)
        path = Path(resolved) if resolved is not None else None
        return RuntimeStatus(
            spec=spec,
            found=path is not None,
            path=path,
            version=_read_version(spec, path, runner),
        )

    return _map_concurrently(one, specs)


def probe_runtimes(runner: Runner = execution.run) -> list[RuntimeStatus]:
    """Resolve and version every standard runtime/toolchain, concurrently."""
    return _probe_capabilities(_RUNTIMES, runner)


def probe_net_tools(runner: Runner = execution.run) -> list[RuntimeStatus]:
    """Resolve and version every standard Unix net tool, concurrently."""
    return _probe_capabilities(_NET_TOOLS, runner)
