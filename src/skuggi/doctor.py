"""The doctor report: rendering the host probe, and the ``skuggi-doctor`` CLI.

One place builds the colour-coded tables (tools grouped by method, runtimes, net
tools) and the host-filtered install hints, and one helper -- ``render_doctor``
-- prints them in order. Three surfaces share it: the ``skuggi-doctor`` CLI
(``main``), the REPL ``/doctor``, and the shell daemon (``doctor_ansi``, which
renders to a forced-colour string for the socket). Probing itself lives in
``skuggi.probe``; this module only presents its results.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from skuggi import palette, probe
from skuggi.config import Settings
from skuggi.configs import ConfigError, load_registry
from skuggi.registry import RuntimeStatus, ToolStatus

# Emitted before a probe runs so the operator sees progress, not a silent wait.
PROBING_MSG = "probing host tools and runtimes..."


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


def render_doctor(
    console: Console,
    statuses: list[ToolStatus],
    runtimes: list[RuntimeStatus] | None = None,
    net_tools: list[RuntimeStatus] | None = None,
) -> None:
    """Print the tool table, the capability tables, then the install hints.

    The one place that composes a full doctor report; every surface calls it so
    the ordering and the hint formatting never drift. Hints are printed verbatim
    (no markup, no wrapping) so their exact text survives a narrow console.
    """
    console.print(doctor_table(statuses))
    if runtimes:
        console.print(runtime_table(runtimes))
    if net_tools:
        console.print(net_tool_table(net_tools))
    hints = doctor_hints(statuses, runtimes, net_tools)
    if hints:
        console.print(hints, markup=False, soft_wrap=True)


def doctor_ansi(
    statuses: list[ToolStatus],
    runtimes: list[RuntimeStatus] | None = None,
    net_tools: list[RuntimeStatus] | None = None,
) -> str:
    """Render a full doctor report to an ANSI string (for the shell daemon).

    The daemon renders on a non-terminal (the socket) while the client writes
    the result to the operator's real terminal, so colour is forced on here.
    """
    console = Console(force_terminal=True, width=100)
    with console.capture() as capture:
        render_doctor(console, statuses, runtimes, net_tools)
    return capture.get()


def probe_statuses(settings: Settings) -> list[ToolStatus]:
    """Probe the host per `settings` for every recognized tool."""
    reg = load_registry(settings.registry_path)
    return probe.probe(
        reg,
        source=settings.tool_source,
        managed_dir=settings.managed_tools_dir,
    )


def main() -> int:
    """Print the host tool report; return non-zero if the registry is missing."""
    console = Console()
    try:
        with console.status(PROBING_MSG, spinner="dots"):
            statuses = probe_statuses(Settings())
            runtimes = probe.probe_runtimes()
            net_tools = probe.probe_net_tools()
    except ConfigError as exc:
        console.print(f"[red]doctor:[/red] {exc}")
        return 1
    render_doctor(console, statuses, runtimes, net_tools)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
