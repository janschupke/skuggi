"""The doctor probe facade and the ``skuggi-doctor`` CLI.

Owns the plain probe data and the display knobs: which tools/runtimes the host
has, the ``show tools`` filters, the ``doctor`` flag parsing, and the stale-wrapper
diagnostic. The colour-coded tables and the report composition are the view layer
in :mod:`skuggi.frontend.presenters_doctor`; probing itself lives in
:mod:`skuggi.tooling.probe`. The ``skuggi-doctor`` CLI entry point stays here
(``main``, pinned by ``pyproject``/``test_cli``); it imports the view layer to
print its report.
"""

from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, get_args

from rich.console import Console

from skuggi.common.logs import get_logger, setup_logging
from skuggi.config.config import Settings
from skuggi.config.configs import ConfigError, load_registry
from skuggi.tooling import probe
from skuggi.tooling.registry import ToolStatus

if TYPE_CHECKING:
    from skuggi.engagement.engagement import EngagementConfig

# The filters ``show tools`` accepts. ``TOOL_FILTERS`` is derived from the type so
# the accepted set and the type cannot drift, and both front-ends validate against
# this one frozenset rather than each re-typing the literals.
ToolFilter = Literal["all", "scoped", "installed", "missing"]
TOOL_FILTERS: frozenset[str] = frozenset(get_args(ToolFilter))

# The ``--category`` values accepted by ``doctor``/``show tools``. ``offensive`` and
# ``forensics`` select a tool section; ``cli`` and ``runtimes`` select the host
# capability sections.
DoctorCategory = Literal["offensive", "forensics", "cli", "runtimes"]
DOCTOR_CATEGORIES: frozenset[str] = frozenset(get_args(DoctorCategory))

# Emitted before a probe runs so the operator sees progress, not a silent wait.
PROBING_MSG = "probing host tools and runtimes..."


_WRAPPER_IMPORT = re.compile(r"^from (skuggi[\w.]*) import", re.MULTILINE)


def stale_wrappers(bin_dir: Path) -> list[tuple[str, str]]:
    """Installed ``skuggi*`` console scripts whose imported module no longer resolves.

    A uv-generated wrapper hard-codes ``from skuggi.<module> import main`` at its
    top; after an internal refactor moves ``<module>`` an old wrapper still names
    the vanished path and crashes before any skuggi code runs. This reads each
    wrapper in ``bin_dir`` and returns ``(wrapper_name, dead_module)`` for every
    one whose module ``find_spec`` cannot resolve -- the cue to reinstall. Purely
    diagnostic and best-effort: an unreadable file or a resolver error is skipped,
    never raised, so ``doctor`` itself cannot be broken by the check.
    """
    stale: list[tuple[str, str]] = []
    for script in sorted(bin_dir.glob("skuggi*")):
        if not script.is_file():
            continue
        try:
            text = script.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = _WRAPPER_IMPORT.search(text)
        if match is None:
            continue
        module = match.group(1)
        try:
            resolved = importlib.util.find_spec(module) is not None
        except (ImportError, AttributeError, ValueError):
            resolved = False
        if not resolved:
            stale.append((script.name, module))
    return stale


def filter_tool_statuses(
    statuses: list[ToolStatus],
    which: ToolFilter,
    engagement: EngagementConfig | None,
) -> list[ToolStatus]:
    """The subset of `statuses` named by `which`, for the ``show tools`` views.

    ``installed``/``missing`` split on the host probe; ``scoped`` keeps only the
    tools this engagement's scope reaches (by binary or by method), empty when no
    engagement is loaded; ``all`` is every recognized tool.
    """
    if which == "installed":
        return [s for s in statuses if s.found]
    if which == "missing":
        return [s for s in statuses if not s.found]
    if which == "scoped":
        if engagement is None:
            return []
        return [
            s
            for s in statuses
            if s.spec.binary in engagement.allowed_tools
            or s.spec.method in engagement.allowed_methods
        ]
    return list(statuses)


@dataclass(frozen=True, slots=True)
class DoctorView:
    """The display options parsed from a ``doctor``/``show tools`` argument.

    `rest` is whatever is left after the flags are removed (e.g. a ``show tools``
    positional filter), so a caller can still route its own sub-grammar.
    """

    verbose: bool = False
    missing_only: bool = False
    category: str | None = None
    rest: str = ""


def parse_doctor_flags(arg: str) -> DoctorView:
    """Pull ``-v``/``--verbose``, ``--missing`` and ``--category <c>`` out of `arg`.

    Flags may appear anywhere; everything else is preserved (in order) as `rest`.
    An unknown ``--category`` value is left in `rest` so the caller can reject it.
    """
    verbose = missing_only = False
    category: str | None = None
    leftover: list[str] = []
    tokens = arg.split()
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-v", "--verbose"):
            verbose = True
        elif tok == "--missing":
            missing_only = True
        elif (
            tok == "--category"
            and i + 1 < len(tokens)
            and tokens[i + 1] in DOCTOR_CATEGORIES
        ):
            category = tokens[i + 1]
            i += 1
        else:
            leftover.append(tok)
        i += 1
    return DoctorView(verbose, missing_only, category, " ".join(leftover))


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
    # Local import: the CLI entry lives here (contract), but the rendering lives
    # in the front-end layer, which imports data types from this module -- a
    # module-level import back would cycle.
    from skuggi.frontend import presenters_doctor  # noqa: PLC0415

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
        console.print(presenters_doctor.install_table(settings))
        console.print(f"[red]doctor:[/red] {exc}")
        console.print("run `skuggi-init` to seed the harness config from templates")
        return 1
    presenters_doctor.render_doctor(console, statuses, runtimes, net_tools, settings)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
