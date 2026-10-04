"""First-party package lookups over HTTP for install research (read-only).

The deterministic package-manager search (:func:`skuggi.tooling.probe.search_packages`)
covers Homebrew and apt, but not pip: PyPI has no usable search API, only a
per-package JSON endpoint. This module confirms whether a pip package *exists* by
name -- trying the requested name and the obvious ``-``/``_`` spelling variants --
so a pip-only tool (e.g. ``enum4linux-ng``) can be grounded and proposed like any
other hit.

Everything here is best-effort and read-only: any network error, non-200, or
unparseable body yields no hits, so install research degrades to the
package-manager results and never blocks on the network. The returned names are
still re-validated by the researcher before they can reach an install argv; this
module only widens the grounded set, it does not bypass any check. It is kept off
the import hot path (httpx is imported lazily) and the fetch is injectable so tests
never touch the network.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from skuggi.tooling.registry import PackageHit

# One PyPI project's metadata. Public, read-only, no auth.
_PYPI_URL = "https://pypi.org/pypi/{name}/json"
_TIMEOUT_S = 8.0
# A pip project name we are willing to look up / return. Name-like, no leading
# dash; a superset is normalised by PyPI, and the researcher re-validates anyway.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# (url) -> parsed JSON object, or None on any failure. Injected in tests.
Fetch = Callable[[str], "dict[str, object] | None"]


def _default_fetch(url: str) -> dict[str, object] | None:
    """GET `url` and return its JSON object, or None on any error (best-effort)."""
    import httpx  # noqa: PLC0415 -- lazy; keep httpx off the import hot path

    try:
        resp = httpx.get(url, timeout=_TIMEOUT_S, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:  # noqa: PLR2004 -- a 404 just means "no such package"
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _variants(query: str) -> list[str]:
    """The name plus its ``-``/``_`` spellings, de-duplicated, order preserved."""
    query = query.strip()
    seen: set[str] = set()
    out: list[str] = []
    for candidate in (query, query.replace("_", "-"), query.replace("-", "_")):
        if candidate and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
    return out


def pypi_candidates(query: str, *, fetch: Fetch = _default_fetch) -> list[PackageHit]:
    """Pip packages matching `query` that actually exist on PyPI (best-effort).

    Confirms the requested name and its ``-``/``_`` variants against PyPI's JSON
    endpoint and returns a :class:`PackageHit` per existing project. Returns ``[]``
    for an unsafe query or when the network is unreachable -- never raises.
    """
    if not _SAFE_NAME.match(query.strip()):
        return []
    hits: list[PackageHit] = []
    seen: set[str] = set()
    for name in _variants(query):
        data = fetch(_PYPI_URL.format(name=name))
        if not data:
            continue
        info = data.get("info")
        info = info if isinstance(info, dict) else {}
        real = str(info.get("name") or name)
        if not _SAFE_NAME.match(real) or real in seen:
            continue
        seen.add(real)
        summary = str(info.get("summary") or "").strip()[:120]
        hits.append(PackageHit(installer="pip", name=real, summary=summary))
    return hits
