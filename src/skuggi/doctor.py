"""``skuggi-doctor`` -- probe the host for the registry's tools and report.

A standalone entry point (mirroring ``skuggi-ingest``) so the host survey can
run without entering the REPL. ``render`` is the testable core; ``main`` wires
it to real settings and prints the Markdown.
"""

from __future__ import annotations

from rich.console import Console
from rich.markdown import Markdown

from skuggi.config import Settings
from skuggi.configs import ConfigError, load_registry
from skuggi.registry import doctor_report, probe


def render(settings: Settings) -> str:
    """Probe the host per `settings` and return the Markdown doctor report."""
    reg = load_registry(settings.registry_path)
    statuses = probe(
        reg,
        source=settings.tool_source,
        managed_dir=settings.managed_tools_dir,
    )
    return doctor_report(statuses)


def main() -> int:
    """Print the host tool report; return non-zero if the registry is missing."""
    console = Console()
    try:
        report = render(Settings())
    except ConfigError as exc:
        console.print(f"[red]doctor:[/red] {exc}")
        return 1
    console.print(Markdown(report))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
