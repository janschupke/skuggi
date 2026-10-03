"""Where skuggi keeps its own files when it is not run from its checkout.

skuggi is installed as a command (``uv tool install --editable``) and launched
from wherever the operator happens to be, so "the harness's config" and "the
directory I am standing in" are two different things. This module resolves the
first; the second stays with ``Settings.engagement_root`` (the engagement
directory, cwd by default).

The split is deliberate:

* **Config home** (``~/.config/skuggi``) -- the app config, the recognized-tool
  registry, the workspace-layout override, the ``run``-alias file, and the
  optional ``env`` file of secrets. Harness-level: one operator, one set.
* **Data home** (``~/.local/share/skuggi``) -- the checkpoint store, the harness
  memory, the FAISS index, the REPL history, the managed tool venv. Regenerable
  state; nothing here is worth backing up.
* **The engagement workspace stays relative to the working directory.** An
  engagement's scope, ledger, recon output and reports belong to the client
  directory you ran skuggi in, not to a global dotdir -- see
  ``skuggi.workspace``.

Both honour the XDG variables, and both take a dedicated ``SKUGGI_*`` override
in front of them so a second harness home does not require relocating all of
XDG.

Every lookup reads the environment **at call time**. That is load-bearing twice
over: the test suite redirects both homes per test (a suite about credential
files must never read the developer's real ones), and ``codex_chat``'s
module-level ``.expanduser()`` is the standing example of what import-time
resolution costs -- the conftest has to monkeypatch the constant itself to undo
it. Nothing here is cached.
"""

from __future__ import annotations

import os
from pathlib import Path

# Direct overrides, checked before the XDG variables.
CONFIG_HOME_ENV = "SKUGGI_CONFIG_HOME"
DATA_HOME_ENV = "SKUGGI_DATA_HOME"

_XDG_CONFIG_ENV = "XDG_CONFIG_HOME"
_XDG_DATA_ENV = "XDG_DATA_HOME"

# The leaf directory name under an XDG base.
_APP = "skuggi"

# The secrets file inside the config home. Named `env` rather than `.env`: it is
# not hidden inside a directory that exists only to hold skuggi's config, and the
# repo's own `.env` stays a separate, deliberately unloaded thing.
ENV_FILENAME = "env"


def _home(direct: str, xdg: str, fallback: str) -> Path:
    """Resolve one home: a direct override, else an XDG base, else `fallback`.

    An empty or whitespace-only value counts as unset -- an exported-but-empty
    ``XDG_CONFIG_HOME`` is common enough that treating it as "use ``/skuggi``"
    would be a nasty surprise. The XDG spec also requires an absolute path, so a
    relative one is ignored rather than quietly resolved against the cwd, which
    is exactly the cwd-sensitivity this module exists to remove.
    """
    override = (os.environ.get(direct) or "").strip()
    if override:
        return Path(override).expanduser()
    base = (os.environ.get(xdg) or "").strip()
    if base:
        candidate = Path(base).expanduser()
        if candidate.is_absolute():
            return candidate / _APP
    return Path(fallback).expanduser() / _APP


def config_home() -> Path:
    """The harness config directory (``SKUGGI_CONFIG_HOME``, XDG, ``~/.config``)."""
    return _home(CONFIG_HOME_ENV, _XDG_CONFIG_ENV, "~/.config")


def data_home() -> Path:
    """The harness data directory (``SKUGGI_DATA_HOME``, XDG, ``~/.local/share``)."""
    return _home(DATA_HOME_ENV, _XDG_DATA_ENV, "~/.local/share")


def env_path() -> Path:
    """The optional secrets file read by ``Settings`` (``<config home>/env``)."""
    return config_home() / ENV_FILENAME
