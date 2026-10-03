"""``skuggi-init`` -- populate the config and data homes on first run.

Installing skuggi puts a command on ``$PATH``; it does not give that command
anything to read. The harness needs a ``config.json`` and a recognized-tool
registry, and the templates for both live in the repo as ``.example`` files that
an operator running ``skuggi`` from ``~`` has no way to reach. This module closes
that gap, and it is the reason the install instructions are two commands rather
than five ``cp`` lines.

Two jobs, in this order:

1. **Migrate.** When this install resolves to a checkout, any live config and
   data already there is moved into the homes. That state --
   ``configs/tools.json``, ``data/sessions.db``, the ledger, the harness memory,
   past reports -- is gitignored, so it exists nowhere else; leaving it behind
   would silently orphan an operator's session history the moment the paths
   changed. Note this does not depend on the working directory: an editable
   install resolves ``__file__`` into the checkout from anywhere, so the
   migration happens on the first run wherever it is launched.
2. **Seed.** Any harness config file still missing is copied from the template
   shipped inside the package.

Nothing is ever overwritten and nothing is ever deleted: every step is guarded
on the destination not existing, which makes the whole thing idempotent and makes
a re-run after a partial failure safe. A migration *moves* rather than copies, so
there is exactly one live copy of a database and no question about which one the
harness is using -- but only into a destination that does not yet exist, so a
second checkout can never clobber the first one's data.
"""

from __future__ import annotations

import shutil
from importlib.resources import files
from pathlib import Path

from skuggi.common import home
from skuggi.common.logs import get_logger, setup_logging
from skuggi.common.paths import ensure_dir
from skuggi.install.update import checkout_root

# Harness config seeded into the config home, as (template, installed name).
# `scope.example.json` is deliberately NOT in this list: a scope is per-engagement
# case data, not harness config, so it is shipped as a template to copy rather
# than installed as a live file (see `SCOPE_TEMPLATE`).
SEEDED = (
    ("config.example.json", "config.json"),
    ("tools.example.json", "tools.json"),
    ("layout.example.json", "layout.json"),
    ("commands.example.json", "commands.json"),
)

# Copied into the config home under its own name, for `engagement setup` and for
# anyone building a scope by hand.
SCOPE_TEMPLATE = "scope.example.json"

_TEMPLATE_DIR = "templates"

# Sentinel for `initialise(migrate_from=...)`: detect the checkout. Distinct from
# None, which means "seed only, migrate nothing". Migration MOVES an operator's
# live databases, so it must never be something a caller triggers by accident by
# leaving an argument off -- a test or a smoke run that reached for the default
# would relocate the developer's real session history out of their checkout.
_AUTO = Path("<auto>")


def _template(name: str) -> bytes:
    """Read a packaged template. Ships inside the wheel, so no repo path is used."""
    return (files("skuggi") / _TEMPLATE_DIR / name).read_bytes()


def _migrate(src_dir: Path, dest_dir: Path, *, skip_examples: bool) -> list[str]:
    """Move every entry of `src_dir` into `dest_dir`, skipping ones already there."""
    if not src_dir.is_dir():
        return []
    moved: list[str] = []
    for entry in sorted(src_dir.iterdir()):
        if skip_examples and entry.name.endswith(".example.json"):
            continue
        dest = dest_dir / entry.name
        if dest.exists():
            continue
        shutil.move(str(entry), str(dest))
        moved.append(f"  moved {entry.name} -> {dest}")
    return moved


def initialise(
    *,
    config_dir: Path | None = None,
    data_dir: Path | None = None,
    migrate_from: Path | None = _AUTO,
) -> list[str]:
    """Create both homes, migrate any checkout-local state, then seed what is missing.

    Returns the report lines (``main`` prints them). Idempotent: a second run
    reports only that everything is already in place.

    `migrate_from` is the checkout whose ``configs/`` and ``data/`` are moved into
    the homes: the detected one by default, or None to skip migration entirely.
    Pass None from anything that is not a real install -- migration *moves* live
    databases, so a caller that wanted only the seeding half and took the default
    would walk an operator's session history out of their repo.
    """
    config_dir = ensure_dir(config_dir or home.config_home())
    data_dir = ensure_dir(data_dir or home.data_home())
    # The diagnostic log lives under the data home; create its directory now so
    # the very first run (including this one) has somewhere to write.
    ensure_dir(data_dir / "logs")
    lines = [f"config home: {config_dir}", f"data home:   {data_dir}"]

    root = checkout_root() if migrate_from is _AUTO else migrate_from
    if root is not None:
        migrated = _migrate(root / "configs", config_dir, skip_examples=True)
        migrated += _migrate(root / "data", data_dir, skip_examples=False)
        if migrated:
            lines.append(f"migrated existing state out of {root}:")
            lines.extend(migrated)

    seeded: list[str] = []
    for template, installed in SEEDED:
        dest = config_dir / installed
        if dest.exists():
            continue
        dest.write_bytes(_template(template))
        seeded.append(f"  seeded {installed}")
    scope_dest = config_dir / SCOPE_TEMPLATE
    if not scope_dest.exists():
        scope_dest.write_bytes(_template(SCOPE_TEMPLATE))
        seeded.append(f"  seeded {SCOPE_TEMPLATE} (template for a new engagement)")
    if seeded:
        lines.append("seeded harness config from the packaged templates:")
        lines.extend(seeded)
    else:
        lines.append("harness config already present; nothing seeded.")

    # Seeding never overwrites, so a config file that already exists can fall
    # behind a newer packaged template (e.g. a tool gaining an output
    # convention). Note any such drift here -- reconciling is the operator's
    # explicit choice, made from the REPL where the diff can be read first.
    from skuggi.install import reconcile  # noqa: PLC0415 -- avoid an import cycle

    behind = reconcile.drifted(config_dir)
    if behind:
        lines.append("")
        lines.append(
            f"{len(behind)} config file(s) differ from the packaged templates: "
            + ", ".join(behind)
        )
        lines.append(
            "  review with `reconcile diff <file>`, update with "
            "`reconcile <file>` or `reconcile all` (a timestamped backup is saved)."
        )

    lines.append("")
    lines.append("Next: run `skuggi` and `/setup` to configure a model provider")
    lines.append("(skuggi stores credentials in its own config, not your shell).")
    lines.append("Then `skuggi-doctor` checks the install.")
    return lines


def main() -> int:
    """Console entry point: initialise both homes and report what happened."""
    setup_logging()
    get_logger(__name__).info("skuggi-init starting")
    for line in initialise():
        print(line)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
