"""The doctor report: rendering the host probe, and the ``skuggi-doctor`` CLI.

One place builds the colour-coded tables (tools grouped by method, runtimes, net
tools) and the host-filtered install hints, and one helper -- ``render_doctor``
-- prints them in order. Three surfaces share it: the ``skuggi-doctor`` CLI
(``main``), the REPL ``/doctor``, and the shell daemon (``doctor_ansi``, which
renders to a forced-colour string for the socket). Probing itself lives in
``skuggi.probe``; this module only presents its results.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from rich.console import Console
from rich.table import Table

from skuggi import home, palette, probe, providers, shell
from skuggi.codex_chat import CodexTokenStore
from skuggi.config import Settings, config_path
from skuggi.configs import ConfigError, load_registry
from skuggi.logs import get_logger, setup_logging
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
    table.add_row(
        "engagement",
        "",
        settings.engagement or "(none -- agent-only, no scope or ledger)",
    )
    table.add_row("engagements dir", "", str(settings.engagements_dir.resolve()))
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
            else palette.paint("not configured -- /setup", palette.WARNING)
        )
        table.add_row(label, status, detail)

    add(
        "openai",
        providers.resolve_openai_key(settings) is not None,
        "API key in skuggi's config, env, or auth.json",
    )
    add(
        "anthropic",
        settings.anthropic_api_key is not None,
        "API key in skuggi's config or env",
    )
    add(
        "chatgpt",
        CodexTokenStore(settings.auth_json()).is_logged_in(),
        f"OAuth tokens in {settings.auth_json()} (run /login)",
    )
    add("ollama", True, f"local, no key ({settings.ollama_base_url})")
    return table


def render_doctor(
    console: Console,
    statuses: list[ToolStatus],
    runtimes: list[RuntimeStatus] | None = None,
    net_tools: list[RuntimeStatus] | None = None,
    settings: Settings | None = None,
) -> None:
    """Print the install table, the tool table, the capability tables, then the hints.

    The one place that composes a full doctor report; every surface calls it so
    the ordering and the hint formatting never drift. Hints are printed verbatim
    (no markup, no wrapping) so their exact text survives a narrow console.

    The install table comes first and only when `settings` is supplied: a caller
    that already has the settings gets "where am I reading from" before the tool
    inventory, since a missing registry explains an empty tool table.
    """
    if settings is not None:
        console.print(install_table(settings))
        console.print(providers_table(settings))
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
    settings: Settings | None = None,
) -> str:
    """Render a full doctor report to an ANSI string (for the shell daemon).

    The daemon renders on a non-terminal (the socket) while the client writes
    the result to the operator's real terminal, so colour is forced on here.
    """
    console = Console(force_terminal=True, width=100)
    with console.capture() as capture:
        render_doctor(console, statuses, runtimes, net_tools, settings)
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
    """Print the install and host tool report; non-zero if the registry is missing.

    The install table is printed even when the probe fails: a missing registry is
    the most likely reason to be running ``skuggi-doctor`` at all on a fresh
    install, and the table is what says where the file was expected and that
    ``skuggi-init`` would seed it.
    """
    setup_logging()
    get_logger(__name__).info("skuggi-doctor starting")
    console = Console()
    settings = Settings()
    try:
        with console.status(PROBING_MSG, spinner="dots"):
            statuses = probe_statuses(settings)
            runtimes = probe.probe_runtimes()
            net_tools = probe.probe_net_tools()
    except ConfigError as exc:
        console.print(install_table(settings))
        console.print(f"[red]doctor:[/red] {exc}")
        console.print("run `skuggi-init` to seed the harness config from templates")
        return 1
    render_doctor(console, statuses, runtimes, net_tools, settings)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
