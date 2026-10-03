#!/usr/bin/env python
"""Maintainer tool: refresh the vendored framework taxonomies from upstream.

This is the *only* thing that touches the network for framework data. It is run by
a maintainer (``make frameworks``), never at user runtime, and its output -- the
distilled, version-pinned JSON under ``src/skuggi/frameworks/data/`` -- is committed
to the repo. That is what keeps the app offline and drift-free: lookups read the
vendored snapshot, and a deliberate, reviewed sync is the only way it changes.

Pins live in ``PINS`` below. To update a framework, bump its pin and re-run; the
diff lands in the committed JSON. ``--check`` re-distils from upstream and compares
to what is on disk (ignoring the fetch timestamp), exiting non-zero on any drift --
a maintainer signal, not part of the offline test suite.

Usage:
    python scripts/sync_frameworks.py [wstg|attack|ptes|all]   # default: all
    python scripts/sync_frameworks.py all --check              # drift check only
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_DATA_DIR = (
    Path(__file__).resolve().parent.parent / "src" / "skuggi" / "frameworks" / "data"
)
_RAW = "https://raw.githubusercontent.com"

# The upstream pins. Bump these (and re-run) to adopt a newer framework release.
PINS: dict[str, dict[str, str]] = {
    "wstg": {
        "repo": "OWASP/wstg",
        "path": "checklists/checklist.md",
        # Commit sha of the checklist file; resolve a new one with:
        #   gh api 'repos/OWASP/wstg/commits?path=checklists/checklist.md&per_page=1'
        "ref": "ea174034f91439a17a1595e57d51e5b461820273",
        "version": "WSTG checklist @ ea174034",
    },
    "attack": {
        "repo": "mitre-attack/attack-stix-data",
        "version": "16.1",
    },
}

_PTES_SOURCE = "http://www.pentest-standard.org/index.php/Main_Page"
# PTES has no machine-readable release; its wiki (dormant since ~2017) is the
# source. The seven top-level phases are stable, so they are curated here and the
# sync simply re-stamps them -- that is the honest provenance for this one.
_PTES_ENTRIES: list[dict[str, str]] = [
    {"id": "PTES-01", "title": "Pre-engagement Interactions", "slug": "Pre-engagement"},
    {
        "id": "PTES-02",
        "title": "Intelligence Gathering",
        "slug": "Intelligence_Gathering",
    },
    {"id": "PTES-03", "title": "Threat Modeling", "slug": "Threat_Modeling"},
    {
        "id": "PTES-04",
        "title": "Vulnerability Analysis",
        "slug": "Vulnerability_Analysis",
    },
    {"id": "PTES-05", "title": "Exploitation", "slug": "Exploitation"},
    {"id": "PTES-06", "title": "Post Exploitation", "slug": "Post_Exploitation"},
    {"id": "PTES-07", "title": "Reporting", "slug": "Reporting"},
]


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "skuggi-sync"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data: bytes = resp.read()
    return data


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def distil_wstg() -> dict[str, Any]:
    """Parse the WSTG checklist markdown table into {id,title,category,url} entries."""
    pin = PINS["wstg"]
    text = _fetch(f"{_RAW}/{pin['repo']}/{pin['ref']}/{pin['path']}").decode("utf-8")
    # Per-test deep URLs are not in the checklist; link to the stable guide and let
    # the precise WSTG id be the locator.
    guide = "https://owasp.org/www-project-web-security-testing-guide/stable/"
    entries: list[dict[str, str]] = []
    category = ""
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:  # noqa: PLR2004 -- id + name are the first two columns
            continue
        ident, name = cells[0], cells[1]
        if ident.startswith("**WSTG-") and ident.endswith("**"):
            category = name.strip("*").strip()
        elif ident.startswith("WSTG-") and "-" in ident[5:]:
            entries.append(
                {"id": ident, "title": name, "category": category, "url": guide}
            )
    return {
        "framework": "wstg",
        "provenance": {
            "source_url": f"https://github.com/{pin['repo']}/blob/{pin['ref']}/{pin['path']}",
            "ref": pin["ref"],
            "version": pin["version"],
            "fetched_at": _now(),
        },
        "entries": sorted(entries, key=lambda e: e["id"]),
    }


def distil_attack() -> dict[str, Any]:
    """Distil MITRE ATT&CK Enterprise techniques from the pinned STIX bundle."""
    pin = PINS["attack"]
    version = pin["version"]
    stix = f"enterprise-attack/enterprise-attack-{version}.json"
    url = f"{_RAW}/{pin['repo']}/master/{stix}"
    bundle = json.loads(_fetch(url))
    collection = next(
        (o for o in bundle["objects"] if o.get("type") == "x-mitre-collection"), {}
    )
    entries: list[dict[str, Any]] = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next(
            (
                r
                for r in obj.get("external_references", [])
                if r.get("source_name") == "mitre-attack" and r.get("external_id")
            ),
            None,
        )
        if ref is None:
            continue
        tactics = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        entries.append(
            {
                "id": ref["external_id"],
                "title": obj["name"],
                "category": "subtechnique"
                if obj.get("x_mitre_is_subtechnique")
                else "technique",
                "tactics": tactics,
                "url": ref.get(
                    "url", f"https://attack.mitre.org/techniques/{ref['external_id']}"
                ),
            }
        )
    return {
        "framework": "attack",
        "provenance": {
            "source_url": f"https://github.com/{pin['repo']}/blob/master/enterprise-attack/enterprise-attack-{version}.json",
            "ref": version,
            "version": f"ATT&CK Enterprise v{version}",
            "collection_modified": collection.get("modified", ""),
            "fetched_at": _now(),
        },
        "entries": sorted(entries, key=lambda e: e["id"]),
    }


def distil_ptes() -> dict[str, Any]:
    """Re-stamp the curated PTES phase outline (no machine-readable upstream)."""
    base = "http://www.pentest-standard.org/index.php/"
    entries = [
        {
            "id": e["id"],
            "title": e["title"],
            "category": "phase",
            "url": base + e["slug"],
        }
        for e in _PTES_ENTRIES
    ]
    return {
        "framework": "ptes",
        "provenance": {
            "source_url": _PTES_SOURCE,
            "ref": "curated",
            "version": "PTES technical guidelines (curated)",
            "note": (
                "PTES has no machine-readable release; the 7 phases are curated here."
            ),
            "fetched_at": _now(),
        },
        "entries": entries,
    }


_DISTILLERS = {"wstg": distil_wstg, "attack": distil_attack, "ptes": distil_ptes}


def _comparable(doc: dict[str, Any]) -> dict[str, Any]:
    """A view that ignores the volatile fetch timestamp, for drift comparison."""
    prov = {k: v for k, v in doc["provenance"].items() if k != "fetched_at"}
    return {
        "framework": doc["framework"],
        "provenance": prov,
        "entries": doc["entries"],
    }


def _write(name: str, doc: dict[str, Any]) -> None:
    path = _DATA_DIR / f"{name}.json"
    path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    rel = path.relative_to(_DATA_DIR.parent.parent.parent.parent)
    print(f"wrote {rel} ({len(doc['entries'])} entries)")


def main() -> int:
    """Sync (or --check) the requested frameworks."""
    ap = argparse.ArgumentParser(description="Refresh vendored framework data.")
    ap.add_argument(
        "frameworks", nargs="?", default="all", choices=["all", *_DISTILLERS]
    )
    ap.add_argument(
        "--check", action="store_true", help="compare to disk; exit 1 on drift"
    )
    args = ap.parse_args()
    names = list(_DISTILLERS) if args.frameworks == "all" else [args.frameworks]
    drift = False
    for name in names:
        fresh = _DISTILLERS[name]()
        if args.check:
            disk = json.loads((_DATA_DIR / f"{name}.json").read_text(encoding="utf-8"))
            if _comparable(fresh) != _comparable(disk):
                print(f"DRIFT: {name} differs from upstream at its pin")
                drift = True
            else:
                print(f"ok: {name} matches ({len(fresh['entries'])} entries)")
        else:
            _write(name, fresh)
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
