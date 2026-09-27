"""Verify that a lab's planted loot is present in the running target.

Each ``Loot`` entry names a stable fingerprint and where to find it. This is the
proof that a ``restore`` re-seeded correctly, and the seam a future scoring
harness would reuse to auto-grade an engagement. Network reads use stdlib
``urllib`` so the controller pulls in no HTTP dependency of its own.
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from labctl import compose
from labctl.manifest import LabManifest, Loot


@dataclass(frozen=True)
class LootResult:
    """The outcome of checking one loot entry."""

    loot: Loot
    present: bool
    detail: str


def _http_contains(url: str, needle: str) -> tuple[bool, str]:
    """GET ``url`` and report whether ``needle`` appears in the body."""
    try:
        with urllib.request.urlopen(url, timeout=5.0) as resp:  # noqa: S310
            body = resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, f"request failed: {exc}"
    return (needle in body), f"GET {url}"


def _tcp_banner(host: str, port: int, needle: str) -> tuple[bool, str]:
    """Connect, read a banner, and report whether ``needle`` appears in it."""
    try:
        with socket.create_connection((host, port), timeout=5.0) as sock:
            sock.settimeout(5.0)
            banner = sock.recv(4096).decode("utf-8", "replace")
    except OSError as exc:
        return False, f"connect failed: {exc}"
    return (needle in banner), f"banner {host}:{port}"


def check_one(manifest: LabManifest, loot: Loot) -> LootResult:
    """Check a single loot entry against the running lab."""
    if loot.kind == "http_contains" and loot.where:
        present, detail = _http_contains(loot.where, loot.fingerprint)
    elif loot.kind == "file_in_container" and loot.service and loot.path:
        body = compose.exec_output(
            manifest.compose_file, loot.service, ["cat", loot.path]
        )
        present, detail = (
            loot.fingerprint in body,
            f"{loot.service}:{loot.path}",
        )
    elif loot.kind == "container_exec" and loot.service and loot.cmd:
        body = compose.exec_output(manifest.compose_file, loot.service, loot.cmd)
        present, detail = (
            loot.fingerprint in body,
            f"{loot.service}: {' '.join(loot.cmd)}",
        )
    elif loot.kind == "tcp_banner" and loot.host and loot.port:
        present, detail = _tcp_banner(loot.host, loot.port, loot.fingerprint)
    else:
        present, detail = False, "malformed loot entry"
    return LootResult(loot=loot, present=present, detail=detail)


def verify(manifest: LabManifest) -> list[LootResult]:
    """Check every loot entry declared by the lab."""
    return [check_one(manifest, item) for item in manifest.loot]


def engagements_dir(cwd: Path | None = None) -> Path:
    """The cwd-relative engagements workspace root skuggi uses (``./engagements``)."""
    return (cwd or Path.cwd()) / "engagements"
