"""Build a self-contained, interactive HTML dashboard for an engagement.

Where :mod:`skuggi.persistence.reports` is the outward-facing client artifact
(scope, findings, a command table -- deliberately no prompts, no audit) and
:mod:`skuggi.persistence.transcript` is a per-session text replay, this module is
the *operator's* whole-engagement picture. It reads everything the harness
recorded for one engagement -- across **all** its sessions -- and renders one
offline HTML file.

It crosses the client-facing boundary that ``reports`` enforces on purpose: this
is an internal review tool, never handed to a client.

This module is the writer/CLI half: :func:`render_html` injects the view model
into the packaged template (``templates/visualize.html``) and
:func:`write_visualization`/:func:`main` drive the filesystem. The pure, I/O-free
view-model builder is :mod:`skuggi.persistence.visualize_model` (re-exported here
as ``collect_engagement``, its long-standing public home). The vanilla-JS page
reads the embedded JSON client-side, so the file opens from ``file://`` with no
network access -- what an air-gapped engagement needs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from skuggi.common.clock import file_stamp
from skuggi.common.paths import ensure_dir, packaged_template
from skuggi.common.text import slug
from skuggi.persistence.visualize_model import (
    collect_engagement,
    loot_to_text,
    notes_to_text,
)

if TYPE_CHECKING:
    from skuggi.engagement.engagement import EngagementConfig
    from skuggi.persistence.ledger import Ledger
    from skuggi.tooling.registry import ToolRegistry

__all__ = [
    "collect_engagement",
    "main",
    "render_html",
    "visualization_written_lines",
    "write_visualization",
]

_TEMPLATE_NAME = "visualize.html"
_DATA_SENTINEL = "__SKUGGI_DATA__"  # replaced in the template with the JSON blob


def render_html(view_model: dict[str, Any]) -> str:
    r"""Inject the view model into the packaged template as embedded JSON.

    ``<``, ``>`` and ``&`` are escaped to their ``\uXXXX`` JSON forms so
    arbitrary command output containing ``</script>`` cannot break out of the
    embedding ``<script>`` tag. This is a *backstop*: the template's DOM builder
    never assigns engagement data via ``innerHTML`` (it uses ``textContent``),
    which is the primary defense; a future edit that reintroduced ``innerHTML``
    would still not execute script smuggled through this blob.
    """
    blob = (
        json.dumps(view_model, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    template = packaged_template(_TEMPLATE_NAME).read_text(encoding="utf-8")
    return template.replace(_DATA_SENTINEL, blob)


def write_visualization(  # noqa: PLR0913 -- keyword-only data sources, like collect
    ledger: Ledger,
    out_dir: Path,
    *,
    engagement: EngagementConfig | None,
    registry: ToolRegistry,
    notes_text: str = "",
    loot_text: str = "",
    log_text: str = "",
    engagement_name: str | None = None,
    current_target: str | None = None,
    secrets: frozenset[str] = frozenset(),
) -> Path:
    """Render the engagement dashboard and write a timestamped ``.html`` file.

    The file lands in ``out_dir`` (the engagement's ``reports`` dir) named for the
    engagement and the moment it was generated. Returns the written path.
    """
    view_model = collect_engagement(
        ledger,
        engagement=engagement,
        registry=registry,
        notes_text=notes_text,
        loot_text=loot_text,
        log_text=log_text,
        current_target=current_target,
        secrets=secrets,
    )
    name = engagement_name or (engagement.name if engagement else None)
    if not name:
        sessions = view_model["sessions"]
        name = sessions[0]["engagement_name"] if sessions else "engagement"
    html = render_html(view_model)
    out_dir = ensure_dir(out_dir)
    stamp = file_stamp()
    path = out_dir / f"{slug(name)}-{stamp}.html"
    path.write_text(html, encoding="utf-8")
    return path


def visualization_written_lines(path: Path) -> list[str]:
    """Describe what :func:`write_visualization` produced, for either front-end."""
    return [f"visualization written: {path}"]


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``skuggi-visualize`` -- read-only, no agent/LLM.

    Takes the engagement *root* directory (the directory that holds its
    ``scope.json``; defaults to the current directory), reads its ledger, scope,
    journals and the diagnostic log, and writes the dashboard.
    """
    import argparse

    from skuggi.common.logs import default_log_path, setup_logging
    from skuggi.config.config import Settings
    from skuggi.config.configs import (
        ConfigError,
        load_env,
        load_layout,
        load_registry,
        load_scope,
    )
    from skuggi.engagement.runtime_env import EngagementEnv
    from skuggi.engagement.workspace import Workspace
    from skuggi.persistence.ledger import open_ledger
    from skuggi.tooling.registry import ToolRegistry

    setup_logging()
    parser = argparse.ArgumentParser(
        prog="skuggi-visualize",
        description="Build an interactive HTML dashboard for an engagement.",
    )
    parser.add_argument(
        "root",
        type=Path,
        nargs="?",
        default=Path.cwd(),
        help="the engagement root directory (holds scope.json; default: cwd)",
    )
    parser.add_argument(
        "-o", "--out", type=Path, help="output directory (default: the reports dir)"
    )
    args = parser.parse_args(argv)

    settings = Settings()
    try:
        layout = load_layout(settings.layout_path)
    except ConfigError:
        layout = None
    workspace = Workspace.at(args.root, layout=layout)
    if not workspace.root.is_dir():
        print(f"no such engagement directory: {workspace.root}")
        return 2

    try:
        scope = (
            load_scope(workspace.scope_path) if workspace.scope_path.is_file() else None
        )
    except ConfigError:
        scope = None
    try:
        env = load_env(workspace.env_path)
    except ConfigError:
        env = EngagementEnv()
    current_target = env.effective_target(scope.resolve_target() if scope else None)
    try:
        registry = load_registry(settings.registry_path)
    except ConfigError:
        registry = ToolRegistry()

    log_path = default_log_path()
    log_text = (
        log_path.read_text(encoding="utf-8", errors="replace")
        if log_path.is_file()
        else ""
    )
    out_dir = args.out or workspace.reports_dir
    secrets = frozenset(
        key.get_secret_value()
        for key in (settings.openai_api_key, settings.anthropic_api_key)
        if key is not None
    )
    eng_name = scope.name if scope is not None else workspace.root.name
    with open_ledger(workspace.ledger_path) as ledger:
        path = write_visualization(
            ledger,
            out_dir,
            engagement=scope,
            registry=registry,
            notes_text=notes_to_text(ledger.notes_for_engagement(eng_name)),
            loot_text=loot_to_text(ledger.loot_for_engagement(eng_name)),
            log_text=log_text,
            engagement_name=eng_name,
            current_target=current_target,
            secrets=secrets,
        )
    print(f"visualization written: {path}")
    return 0
