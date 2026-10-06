"""The doctor report's view layer: colour-coded tables, hints and composition.

Split out of :mod:`skuggi.tooling.doctor` so the Rich rendering lives in the
front-end layer with the other ``presenters_*`` modules, leaving ``tooling`` to
return plain probe data. Three surfaces share this one view: the ``skuggi-doctor``
CLI (``skuggi.tooling.doctor.main``), the REPL ``/doctor``, and the shell daemon
(``doctor_ansi``/``table_ansi``, which force colour on for the socket). The probe
logic, the flag parsing and the :class:`~skuggi.tooling.doctor.DoctorView` knobs
stay in ``tooling.doctor``; this module only presents their results.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from rich.console import Console
from rich.table import Table

from skuggi.common import home, palette
from skuggi.config.config import PROVIDERS, Settings, config_path
from skuggi.engagement.workspace import has_engagement
from skuggi.frontend import shell
from skuggi.providers import providers
from skuggi.tooling import probe
from skuggi.tooling.doctor import DoctorView, stale_wrappers
from skuggi.tooling.registry import (
    RuntimeStatus,
    ToolCategory,
    ToolStatus,
    tool_category,
)


def _method_rank(method: str) -> int:
    """Sort key placing methods in the palette's defined order, unknowns last."""
    order = palette.methods()
    return order.index(method) if method in order else len(order)


def doctor_table(
    statuses: list[ToolStatus],
    *,
    title: str = "skuggi tool doctor",
    verbose: bool = True,
) -> Table:
    """A colour-coded Rich table of a tool probe (palette-driven), method-sorted.

    Compact (``verbose=False``) shows tool / method / status; ``verbose`` adds the
    version, where it resolved, and the path. Rows sort by method in the palette's
    order (unknown methods last), then binary.
    """
    table = Table(title=title)
    columns: tuple[str, ...] = ("tool", "method", "status")
    if verbose:
        columns += ("version", "source", "path")
    for column in columns:
        table.add_column(column)
    ordered = sorted(
        statuses, key=lambda st: (_method_rank(st.spec.method), st.spec.binary)
    )
    for st in ordered:
        row = [
            st.spec.binary,
            palette.paint(st.spec.method, palette.method_style(st.spec.method)),
            palette.paint(
                "found" if st.found else "missing",
                palette.status_style(found=st.found),
            ),
        ]
        if verbose:
            row += [
                st.version or "-",
                palette.paint(st.source, palette.source_style(st.source)),
                str(st.path) if st.path else "-",
            ]
        table.add_row(*row)
    return table


_TOOL_SECTIONS: tuple[tuple[ToolCategory, str], ...] = (
    ("offensive", "offensive tools"),
    ("forensics", "forensics / defensive tools"),
)


def tool_tables(
    statuses: list[ToolStatus],
    *,
    verbose: bool = True,
    category: str | None = None,
) -> list[Table]:
    """The tool probe split into its display sections (offensive / forensics).

    Every recognized tool is listed -- the sectioning is by ``tool_category``
    (derived from method + modes), so nothing is hidden the way the old
    mode-filtered table hid blueteam tools. An empty section is omitted;
    `category` (``offensive``/``forensics``) narrows to one section.
    """
    tables: list[Table] = []
    for cat, title in _TOOL_SECTIONS:
        if category is not None and category != cat:
            continue
        rows = [st for st in statuses if tool_category(st.spec) == cat]
        if rows:
            tables.append(doctor_table(rows, title=title, verbose=verbose))
    return tables


def _capability_table(
    title: str, first_column: str, statuses: list[RuntimeStatus], *, verbose: bool
) -> Table:
    """A colour-coded Rich table of a host-capability probe (runtime or net)."""
    table = Table(title=title)
    columns: tuple[str, ...] = (first_column, "status")
    if verbose:
        columns += ("version", "path")
    for column in columns:
        table.add_column(column)
    for st in statuses:
        row = [
            st.spec.name,
            palette.paint(
                "found" if st.found else "missing",
                palette.status_style(found=st.found),
            ),
        ]
        if verbose:
            row += [st.version or "-", str(st.path) if st.path else "-"]
        table.add_row(*row)
    return table


def runtime_table(statuses: list[RuntimeStatus], *, verbose: bool = True) -> Table:
    """A colour-coded Rich table of the host runtime/toolchain probe."""
    return _capability_table(
        "host runtimes / toolchains", "runtime", statuses, verbose=verbose
    )


def net_tool_table(statuses: list[RuntimeStatus], *, verbose: bool = True) -> Table:
    """A colour-coded Rich table of the standard Unix net-tool (standard CLI) probe."""
    return _capability_table(
        "standard CLI / net tools", "net tool", statuses, verbose=verbose
    )


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
    available = probe.available_installers()
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


def install_table(settings: Settings) -> Table:
    """A table of where this install reads and writes, and what is missing.

    ``skuggi`` is a command on ``$PATH`` run from anywhere, so "which config am I
    actually using?" stops being obvious the moment it is not the cwd. This is the
    answer to that question, and the first thing to look at when the harness
    behaves as though it were unconfigured.
    """
    table = Table(title="skuggi install")
    for column in ("item", "status", "path"):
        table.add_column(column)

    def row(item: str, path: Path, *, required: bool) -> None:
        if path.exists():
            state, style = "present", palette.SUCCESS
        elif required:
            state, style = "MISSING", palette.DANGER
        else:
            state, style = "absent", palette.WARNING
        table.add_row(item, palette.paint(state, style), str(path))

    table.add_row("config home", "", str(home.config_home()))
    table.add_row("data home", "", str(home.data_home()))
    # The diagnostic log; absent on a fresh install until something first writes.
    row("log file", settings.log_path, required=False)
    # The registry is the one file whose absence breaks the harness outright
    # (`load_registry` raises), so it is the only "MISSING" rather than "absent".
    row("config.json", config_path(), required=False)
    row("tools.json (registry)", settings.registry_path, required=True)
    row("layout.json", settings.layout_path, required=False)
    row("commands.json", settings.commands_path, required=False)

    env_file = home.env_path()
    if env_file.is_file():
        mode = env_file.stat().st_mode & 0o777
        # Group/world readability on a file whose purpose is API keys. Worth
        # saying out loud: nothing else in the harness will ever complain.
        status = (
            palette.paint(f"present ({mode:04o})", palette.SUCCESS)
            if not mode & 0o077
            else palette.paint(f"mode {mode:04o} -- run chmod 600", palette.DANGER)
        )
        table.add_row("env (secrets)", status, str(env_file))
    else:
        table.add_row(
            "env (secrets)", palette.paint("absent", palette.WARNING), str(env_file)
        )

    client = shutil.which(shell.CLIENT_NAME)
    table.add_row(
        f"{shell.CLIENT_NAME} on PATH",
        palette.paint("found", palette.SUCCESS)
        if client
        else palette.paint("NOT ON PATH", palette.DANGER),
        client or "run `uv tool update-shell`, or add uv's bin dir to PATH",
    )
    skuggi_path = shutil.which("skuggi") or client
    if skuggi_path:
        stale = stale_wrappers(Path(skuggi_path).resolve().parent)
        if stale:
            table.add_row(
                "console scripts",
                palette.paint(
                    f"{len(stale)} STALE -- run `make install-cli`", palette.DANGER
                ),
                ", ".join(name for name, _ in stale),
            )
        else:
            table.add_row(
                "console scripts",
                palette.paint("all current", palette.SUCCESS),
                str(Path(skuggi_path).resolve().parent),
            )
    root = (settings.engagement_root or Path.cwd()).expanduser()
    source = "override" if settings.engagement_root is not None else "cwd probe"
    detected = (
        "scope.json found"
        if has_engagement(root)
        else "no scope.json (agent-only, no scope or ledger)"
    )
    table.add_row("engagement root", f"({source})", f"{root.resolve()} -- {detected}")
    return table


def providers_table(settings: Settings) -> Table:
    """Per-provider credential status, marking the active one.

    The single answer to "is my model actually configured?" -- a story that used
    to be split across env vars, the env secrets file and auth.json. ``not
    configured`` on the active provider is the cue to run ``/setup``.
    """
    table = Table(title="skuggi providers")
    for column in ("provider", "status", "credential"):
        table.add_column(column)

    active = settings.provider

    def add(name: str, ok: bool, detail: str) -> None:
        label = f"{name} (active)" if name == active else name
        status = (
            palette.paint("ready", palette.SUCCESS)
            if ok
            else palette.paint("not configured -- set provider", palette.WARNING)
        )
        table.add_row(label, status, detail)

    details = {
        "openai": "API key in skuggi's config, env, or auth.json",
        "anthropic": "API key in skuggi's config or env",
        "chatgpt": f"OAuth tokens in {settings.auth_json()} (run login)",
        "claude-cli": "your local `claude` login (no key stored)",
        "ollama": f"local, no key ({settings.ollama_base_url})",
    }
    for name in PROVIDERS:
        add(name, providers.is_configured(settings, name), details.get(name, ""))
    return table


def _only_missing(statuses: list[RuntimeStatus]) -> list[RuntimeStatus]:
    return [s for s in statuses if not s.found]


def render_doctor(  # noqa: PLR0913 -- the display knobs are the point
    console: Console,
    statuses: list[ToolStatus],
    runtimes: list[RuntimeStatus] | None = None,
    net_tools: list[RuntimeStatus] | None = None,
    settings: Settings | None = None,
    *,
    view: DoctorView | None = None,
) -> None:
    """Print the install table, the tool sections, the capability tables, the hints.

    The one place that composes a full doctor report; every surface calls it so
    the ordering and the hint formatting never drift. Hints are printed verbatim
    (no markup, no wrapping) so their exact text survives a narrow console.

    The tool inventory is sectioned (offensive / forensics) via ``tool_tables``,
    then the standard-CLI and runtime capability tables. `view` carries the
    ``-v``/``--missing``/``--category`` display knobs; its category also gates
    which sections appear. The install/providers tables are shown only on an
    unfiltered full report (a caller with `settings` and no narrowing view), since
    a missing registry explains an empty tool table.
    """
    view = view or DoctorView(verbose=True)
    tools = [s for s in statuses if s.found is False] if view.missing_only else statuses
    cat = view.category
    full_report = cat is None and not view.missing_only
    if full_report and settings is not None:
        console.print(install_table(settings))
        console.print(providers_table(settings))
    if cat in (None, "offensive", "forensics"):
        for table in tool_tables(tools, verbose=view.verbose, category=cat):
            console.print(table)
    if runtimes and cat in (None, "runtimes"):
        rts = _only_missing(runtimes) if view.missing_only else runtimes
        if rts:
            console.print(runtime_table(rts, verbose=view.verbose))
    if net_tools and cat in (None, "cli"):
        nts = _only_missing(net_tools) if view.missing_only else net_tools
        if nts:
            console.print(net_tool_table(nts, verbose=view.verbose))
    hints = doctor_hints(statuses, runtimes, net_tools)
    if hints and not view.missing_only and cat is None:
        console.print(hints, markup=False, soft_wrap=True)


def doctor_ansi(
    statuses: list[ToolStatus],
    runtimes: list[RuntimeStatus] | None = None,
    net_tools: list[RuntimeStatus] | None = None,
    settings: Settings | None = None,
    *,
    view: DoctorView | None = None,
) -> str:
    """Render a full doctor report to an ANSI string (for the shell daemon).

    The daemon renders on a non-terminal (the socket) while the client writes
    the result to the operator's real terminal, so colour is forced on here.
    """
    console = Console(force_terminal=True, width=100)
    with console.capture() as capture:
        render_doctor(console, statuses, runtimes, net_tools, settings, view=view)
    return capture.get()


def table_ansi(table: Table) -> str:
    """Render one Rich table to a forced-colour ANSI string (for the daemon socket)."""
    console = Console(force_terminal=True, width=100)
    with console.capture() as capture:
        console.print(table)
    return capture.get()
