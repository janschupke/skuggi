"""Stable, guarded console entry points for every ``skuggi*`` command.

The uv-generated wrappers in the operator's bin import *this* module, never a
command's real home module directly. So when an internal refactor moves a
command's implementation (as the 2026-10 domain-package regrouping did), a
wrapper left over from an older install still loads -- and the moved import
surfaces here as one actionable line ("reinstall"), not a bare
``ModuleNotFoundError`` traceback thrown before any skuggi code runs.

``_TARGETS`` is the single source of truth tying each console script to its
implementation module; ``tests/unit/test_cli.py`` pins it to ``pyproject``'s
``[project.scripts]`` so the two cannot drift silently again.
"""

from __future__ import annotations

import importlib
import os
import sys
from collections.abc import Callable
from typing import cast

# console-script suffix -> module whose ``main()`` implements it. In lockstep
# with [project.scripts] (enforced by tests/unit/test_cli.py).
_TARGETS: dict[str, str] = {
    "shell": "skuggi.frontend.shell",
    "repl": "skuggi.__main__",
    "init": "skuggi.install.init",
    "ingest": "skuggi.install.ingest",
    "doctor": "skuggi.tooling.doctor",
    "client": "skuggi.frontend.client",
    "login": "skuggi.providers.codex_login",
    "pdf": "skuggi.persistence.pdf",
    "visualize": "skuggi.persistence.visualize",
    "eval": "skuggi.eval.cli",
}

_STALE_HINT = (
    "Your skuggi install is out of date -- reinstall it:\n"
    "  cd <your skuggi checkout> && make install-cli\n"
    "  (or: uv tool install --editable '<checkout>[pdf]' --force)\n"
    "Set SKUGGI_DEBUG=1 to see the underlying import error."
)


def _run(name: str) -> None:
    """Import ``name``'s target and call its ``main``; guide, don't crash, if stale."""
    try:
        module = importlib.import_module(_TARGETS[name])
    except ImportError as exc:
        if os.environ.get("SKUGGI_DEBUG"):
            raise
        print(
            f"skuggi: '{name}' could not load ({exc}).\n{_STALE_HINT}",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    main = cast("Callable[[], object]", module.main)
    main()


def shell() -> None:
    """Launch the wrapped-shell ``skuggi`` command."""
    _run("shell")


def repl() -> None:
    """Launch the pure agent REPL (``skuggi-repl``)."""
    _run("repl")


def init() -> None:
    """Seed/update the config and data homes (``skuggi-init``)."""
    _run("init")


def ingest() -> None:
    """Ingest documents into the vector store (``skuggi-ingest``)."""
    _run("ingest")


def doctor() -> None:
    """Print the install/tool/provider diagnostics (``skuggi-doctor``)."""
    _run("doctor")


def client() -> None:
    """Talk to the warm daemon over the socket (``skuggi-client``)."""
    _run("client")


def login() -> None:
    """Run the ChatGPT OAuth login (``skuggi-login``)."""
    _run("login")


def pdf() -> None:
    """Render a Markdown report to PDF (``skuggi-pdf``)."""
    _run("pdf")


def visualize() -> None:
    """Write the engagement HTML dashboard (``skuggi-visualize``)."""
    _run("visualize")


def eval_() -> None:  # ``eval`` shadows a builtin; the script maps here.
    """Run the local evaluation suite (``skuggi-eval``)."""
    _run("eval")
