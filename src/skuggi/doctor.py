"""``skuggi-doctor`` -- probe the host for the registry's tools and report.

A standalone entry point (mirroring ``skuggi-ingest``) so the host survey can
run without entering the harness. ``probe_statuses`` is the testable core;
``main`` renders the colour-coded table plus install hints filtered to the
package managers actually present on this host.
"""

from __future__ import annotations

from rich.console import Console

from skuggi.config import Settings
from skuggi.configs import ConfigError, load_registry
from skuggi.registry import (
    ToolStatus,
    doctor_hints,
    doctor_table,
    probe,
    probe_runtimes,
    runtime_table,
)


def probe_statuses(settings: Settings) -> list[ToolStatus]:
    """Probe the host per `settings` for every recognized tool."""
    reg = load_registry(settings.registry_path)
    return probe(
        reg,
        source=settings.tool_source,
        managed_dir=settings.managed_tools_dir,
    )


def main() -> int:
    """Print the host tool report; return non-zero if the registry is missing."""
    console = Console()
    try:
        statuses = probe_statuses(Settings())
    except ConfigError as exc:
        console.print(f"[red]doctor:[/red] {exc}")
        return 1
    console.print(doctor_table(statuses))
    hints = doctor_hints(statuses)
    if hints:
        console.print(hints)
    console.print(runtime_table(probe_runtimes()))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
