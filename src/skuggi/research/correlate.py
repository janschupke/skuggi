"""Deterministic CVE-centred join across the research collectors (audit E16).

The research loop runs independent collectors -- NVD CVEs, Exploit-DB, searchsploit,
Metasploit modules -- that each emit their own :class:`IntelResult`. This module
correlates them by CVE id into one per-CVE view (severity + the exploits and
Metasploit modules that target it), so the report can say "this CVE is exploitable,
here is the module" instead of listing four unjoined source dumps. Pure and
offline: it reads the already-collected corpus and performs no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from skuggi.intel.schema import IntelResult

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class CveCorrelation:
    """One CVE and the exploits / Metasploit modules that reference it."""

    cve_id: str
    severity: str = ""
    description: str = ""
    url: str = ""
    exploits: tuple[str, ...] = ()  # Exploit-DB ids referencing this CVE
    modules: tuple[str, ...] = ()  # Metasploit module fullnames referencing it


@dataclass
class _Acc:
    severity: str = ""
    description: str = ""
    url: str = ""
    exploits: set[str] = field(default_factory=set)
    modules: set[str] = field(default_factory=set)


def _cves_in(text: str) -> list[str]:
    """Every CVE id in a free-text / comma-joined attribute, upper-cased."""
    return [m.upper() for m in _CVE_RE.findall(text or "")]


def cve_correlations(results: Sequence[IntelResult]) -> list[CveCorrelation]:
    """Join the corpus by CVE id into a sorted per-CVE correlation list.

    A CVE enters the view either as a first-class ``cve`` item (carrying its
    severity/description/url) or by being referenced from an exploit/module. An
    exploit (``kind == "exploit"``) or module (``kind == "module"``) attaches to
    every CVE id in its ``cves`` attribute. The result is sorted by CVE id so the
    report is stable.
    """
    acc: dict[str, _Acc] = {}
    for result in results:
        for item in result.items:
            if item.kind == "cve":
                cid = item.value.strip().upper()
                if not _CVE_RE.fullmatch(cid):
                    continue
                entry = acc.setdefault(cid, _Acc())
                entry.severity = item.attributes.get("severity", "") or entry.severity
                entry.description = (
                    item.attributes.get("description", "") or entry.description
                )
                entry.url = item.attributes.get("url", "") or entry.url
            elif item.kind in ("exploit", "module"):
                for cid in _cves_in(item.attributes.get("cves", "")):
                    entry = acc.setdefault(cid, _Acc())
                    if item.kind == "exploit":
                        entry.exploits.add(item.value)
                    else:
                        entry.modules.add(item.value)
    return [
        CveCorrelation(
            cve_id=cid,
            severity=a.severity,
            description=a.description,
            url=a.url,
            exploits=tuple(sorted(a.exploits)),
            modules=tuple(sorted(a.modules)),
        )
        for cid, a in sorted(acc.items())
    ]
