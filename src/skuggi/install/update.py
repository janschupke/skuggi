"""Updating a skuggi install in place: ``git pull`` then a dependency refresh.

The checkout-root resolution lives here too, as the one authority both the
update path (which must refuse to run ``git`` outside a real checkout) and the
first-run migration in :mod:`skuggi.install.init` share. It is verified rather
than assumed because ``parents[3]`` only means "the repo root" for an editable
install; a wheel copy lands inside the tool environment's ``site-packages``.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

from skuggi import __version__
from skuggi.common.execution import CommandResult, run
from skuggi.common.logs import get_logger

log = get_logger(__name__)

# One command for both front-ends' /update; injected in tests to capture argv.
UpdateRunner = Callable[[list[str]], CommandResult]

# Update commands can build wheels; give them far longer than a scan's cap.
_UPDATE_TIMEOUT_S = 600.0


def checkout_root(*, require_git: bool = False) -> Path | None:
    """The git checkout skuggi runs from, or None for a non-editable install.

    ``skuggi`` is installed with ``uv tool install --editable``, whose ``.pth``
    points at the checkout's ``src``, so ``parents[3]`` is the repo root (this
    module lives at ``src/skuggi/install/update.py``). A non-editable install has
    no checkout, and there ``parents[3]`` lands inside the tool environment's
    ``site-packages`` -- which is why the result is verified rather than assumed.

    ``require_git`` additionally demands a ``.git`` directory: the update path
    runs ``git pull`` and must never do so in a stranger's directory, while the
    migration path needs only a seedable source tree.
    """
    here = Path(__file__).resolve()
    root = here.parents[3]
    if here.parents[2].name != "src":
        return None
    if not (root / "pyproject.toml").is_file():
        return None
    if require_git and not (root / ".git").exists():
        return None
    return root


def is_uv_tool_env() -> bool:
    """Whether the running interpreter is a ``uv tool`` environment.

    ``uv`` drops a ``uv-receipt.toml`` beside ``pyvenv.cfg`` in a tool env and
    nowhere else, which makes this a one-file check rather than path arithmetic
    against ``uv tool dir``. It decides which command refreshes dependencies:
    ``uv sync`` syncs the *checkout's* ``.venv``, which is the wrong environment
    when skuggi is running from a tool install.
    """
    return (Path(sys.prefix) / "uv-receipt.toml").is_file()


def installed_version(root: Path) -> str:
    """Read ``__version__`` from the on-disk source (post-pull), or ``?``."""
    try:
        text = (root / "src" / "skuggi" / "__init__.py").read_text(encoding="utf-8")
    except OSError as exc:
        log.debug("could not read installed version from %s: %s", root, exc)
        return "?"
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else "?"


def perform_update(runner: UpdateRunner | None = None) -> Iterator[str]:
    """Update the install in place: ``git pull --ff-only`` then a dependency sync.

    Yields progress text. ``runner`` is injected (default ``execution.run``,
    bound to the repo root) so the subprocess path stays captured and testable.
    A non-zero step aborts; code changes take effect on restart.

    Two install shapes, two second steps. From the checkout's own ``.venv``,
    ``uv sync`` is right. From a ``uv tool`` environment it is not -- it would
    sync the checkout's ``.venv`` while skuggi keeps running the tool env's
    dependencies -- so the tool install is refreshed instead. Without a checkout
    at all there is nothing to pull, and we say so rather than running git
    somewhere arbitrary.
    """
    root = checkout_root(require_git=True)
    if root is None:
        yield (
            f"skuggi {__version__} -- not running from a git checkout, "
            "so there is nothing to pull.\n"
            "Reinstall with: uv tool install --editable <path/to/skuggi> --force\n"
        )
        return
    run_cmd = runner or (lambda argv: run(argv, timeout=_UPDATE_TIMEOUT_S, cwd=root))
    sync = (
        ["uv", "tool", "install", "--editable", f"{root}[pdf]", "--force"]
        if is_uv_tool_env()
        else ["uv", "sync", "--all-groups", "--all-extras"]
    )
    yield f"skuggi {__version__} -- updating in {root}\n"
    for argv in (["git", "pull", "--ff-only"], sync):
        yield f"$ {' '.join(argv)}\n"
        result = run_cmd(list(argv))
        output = (result.stdout + result.stderr).strip()
        if output:
            yield output + "\n"
        if result.exit_code != 0:
            yield f"update aborted: '{' '.join(argv)}' exited {result.exit_code}\n"
            return
    after = installed_version(root)
    yield f"updated to skuggi {after}; restart skuggi to run the new code\n"
