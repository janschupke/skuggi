"""The ``labctl`` command line: list / up / down / restore / wipe / verify / scope.

Rendering and the destructive-confirm prompt live here; every state change is
delegated to :mod:`labctl.compose` (docker) or the filesystem. ``main`` takes an
injectable ``ask`` and ``labs_dir`` so the whole dispatch is unit-testable
offline, with docker mocked.
"""

from __future__ import annotations

import argparse
import shutil
from collections.abc import Callable
from pathlib import Path

from labctl import LABS_DIR, compose, loot
from labctl.manifest import LabManifest, discover_labs, resolve_lab
from skuggi.engagement.engagement import EngagementConfig

Ask = Callable[[str], str]

_TIER_ORDER = {"trivial": 0, "easy": 1, "medium": 2, "hard": 3}


def build_parser() -> argparse.ArgumentParser:
    """The argument parser for every subcommand."""
    parser = argparse.ArgumentParser(
        prog="labctl", description="skuggi practice-range controller"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="every lab, its tier, ports and up/down state")

    for name, helptext in (
        ("up", "build + start a lab (loopback-only)"),
        ("down", "stop a lab, keeping planted data"),
        ("restore", "revert the target to pristine planted state, keep your work"),
        ("verify", "assert the manifest's planted loot is present"),
    ):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("lab", help="lab id, e.g. 01-trivial-goat-cms")

    wipe = sub.add_parser("wipe", help="nuke the target AND ./engagements/<lab>")
    wipe.add_argument("lab", help="lab id, e.g. 01-trivial-goat-cms")
    wipe.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    scope = sub.add_parser("scope", help="print or install a lab's engagement scope")
    scope.add_argument("lab", help="lab id, e.g. 01-trivial-goat-cms")
    scope.add_argument(
        "--install",
        action="store_true",
        help="copy scope.json into ./engagements/<lab>/scope.json",
    )
    return parser


def _cmd_list(labs_dir: Path) -> int:
    labs = discover_labs(labs_dir)
    labs.sort(key=lambda m: (_TIER_ORDER.get(m.tier, 9), m.id))
    print(f"{'LAB':<26} {'TIER':<8} {'PORTS':<22} STATE")
    for m in labs:
        ports = ",".join(str(p.published) for p in m.ports) or "-"
        state = "up" if compose.is_up(m.compose_file) else "down"
        print(f"{m.id:<26} {m.tier:<8} {ports:<22} {state}")
    return 0


def _cmd_up(manifest: LabManifest) -> int:
    print(f"bringing up {manifest.id} ...")
    code = compose.up(manifest.compose_file)
    print("up" if code == 0 else f"up failed (exit {code})")
    return code


def _cmd_down(manifest: LabManifest) -> int:
    return compose.down(manifest.compose_file)


def _cmd_restore(manifest: LabManifest) -> int:
    r = manifest.restore
    if r.strategy == "reseed" and r.service and r.exec:
        print(f"re-seeding {manifest.id} in place ...")
        return compose.exec_in(manifest.compose_file, r.service, r.exec)
    print(f"recreating {manifest.id} from a fresh volume ...")
    compose.down(manifest.compose_file, volumes=True)
    return compose.up(manifest.compose_file)


def _cmd_verify(manifest: LabManifest) -> int:
    results = loot.verify(manifest)
    if not results:
        print(f"{manifest.id}: no loot declared")
        return 0
    ok = True
    for res in results:
        mark = "OK  " if res.present else "MISS"
        print(f"[{mark}] {res.loot.id:<20} {res.detail}")
        ok = ok and res.present
    print("all loot present" if ok else "some loot missing")
    return 0 if ok else 1


def _cmd_wipe(manifest: LabManifest, *, yes: bool, ask: Ask) -> int:
    eng = loot.engagements_dir() / manifest.id
    if not yes:
        prompt = (
            f"Wipe {manifest.id}: drop its volumes"
            + (f" and delete {eng}" if eng.exists() else "")
            + "? [y/N] "
        )
        if ask(prompt).strip().lower() not in {"y", "yes"}:
            print("aborted")
            return 1
    compose.down(manifest.compose_file, volumes=True)
    if eng.exists():
        shutil.rmtree(eng)
        print(f"removed {eng}")
    print(f"wiped {manifest.id}")
    return 0


def _cmd_scope(manifest: LabManifest, *, install: bool) -> int:
    text = manifest.scope_file.read_text(encoding="utf-8")
    EngagementConfig.model_validate_json(text)  # fail loudly on a broken scope
    if not install:
        print(text)
        return 0
    dest = loot.engagements_dir() / manifest.id / "scope.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    print(f"installed scope -> {dest}")
    return 0


def main(
    argv: list[str] | None = None,
    *,
    ask: Ask = input,
    labs_dir: Path = LABS_DIR,
) -> int:
    """Parse ``argv`` and dispatch one subcommand; return a process exit code."""
    args = build_parser().parse_args(argv)
    if args.cmd == "list":
        return _cmd_list(labs_dir)

    try:
        manifest = resolve_lab(labs_dir, args.lab)
    except KeyError as exc:
        print(str(exc))
        return 2

    handlers: dict[str, Callable[[], int]] = {
        "up": lambda: _cmd_up(manifest),
        "down": lambda: _cmd_down(manifest),
        "restore": lambda: _cmd_restore(manifest),
        "verify": lambda: _cmd_verify(manifest),
        "wipe": lambda: _cmd_wipe(manifest, yes=args.yes, ask=ask),
        "scope": lambda: _cmd_scope(manifest, install=args.install),
    }
    return handlers[args.cmd]()
