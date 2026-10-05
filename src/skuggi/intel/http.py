"""The injectable HTTP / collection-context seam shared by every collector.

The dependencies a collector needs -- an HTTP fetch, a browser driver factory,
secrets, the session redactor, per-source config -- are bundled in a
:class:`CollectContext` and injected, so the whole collector set is offline-
testable with fakes; the suite never touches the network. Result-agnostic on
purpose (it knows nothing of ``IntelResult``), so it sits below both the OSINT
and research schemas.

Discipline: the default HTTP fetch imports httpx lazily, is best-effort, and
never raises (any error/non-200 -> ``None``); a collector turns ``None`` into an
empty result with a note, never an exception, so a dead source degrades to a
coverage gap the verifier can see.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from skuggi.common.logs import get_logger
from skuggi.intel.schema import IntelResult

log = get_logger(__name__)

_TIMEOUT_S = 10.0
# A plain, honest identifier so a source does not silently 403 an empty UA (many
# public endpoints reject the default httpx agent), plus a small retry with linear
# backoff for transient failures (timeouts, 429, 5xx).
_USER_AGENT = "skuggi-intel/1.0 (+research; contact via operator)"
_RETRIES = 2
_BACKOFF_S = 0.5
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_BLOCKED_STATUS = frozenset({401, 403, 407, 429})


@dataclass(frozen=True, slots=True)
class HttpRequest:
    """One outbound HTTP request a collector wants made (injectable)."""

    url: str
    params: Mapping[str, str] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)
    method: str = "GET"
    data: Mapping[str, str] | None = None


# (request) -> the response body text, or None on any failure (best-effort).
Fetch = Callable[[HttpRequest], "str | None"]

# (actor_id, run_input) -> the actor run's dataset rows, or None on any failure.
# The injectable Apify seam: the default lazily imports apify-client; a test passes
# a fake that returns canned rows. None means "actor unavailable / failed".
ApifyRun = Callable[[str, "Mapping[str, object]"], "list[dict[str, object]] | None"]


@runtime_checkable
class Driver(Protocol):
    """A minimal rendered-page fetcher (a Playwright page, or a test fake)."""

    def fetch_html(self, url: str) -> str:
        """Return the fully-rendered HTML of ``url``."""
        ...

    def close(self) -> None:
        """Release the underlying browser/session."""
        ...


@dataclass(frozen=True, slots=True)
class CollectContext:
    """Everything a collector needs, injected so collection is testable offline."""

    fetch: Fetch
    clean: Callable[[str], str]  # the session redactor (executor._redactor)
    secrets: Mapping[str, str] = field(default_factory=dict)
    driver_factory: Callable[[], Driver] | None = None
    apify_run: ApifyRun | None = None
    source_config: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    # The results of this task's completed dependencies (audit E15), set per task by
    # the collect step so a dependent collector (e.g. CVE lookup from a resolved
    # version) reads its upstream output directly instead of the planner having to
    # re-state it. Empty for a task with no dependencies.
    upstream: tuple[IntelResult, ...] = ()

    def config_for(self, source: str) -> Mapping[str, str]:
        """The non-secret config block for one source (empty when unset)."""
        return self.source_config.get(source, {})


def default_fetch(request: HttpRequest) -> str | None:
    """GET/POST ``request`` and return the body text, or None on any error.

    Lazy httpx import (kept off the module hot path) and best-effort: a network
    error, a non-200, or a timeout all yield ``None`` so a collector degrades to an
    empty result. Sends an honest User-Agent (an empty one is widely rejected) and
    retries a transient failure (timeout / 429 / 5xx) with linear backoff. A
    blocked response (401/403/429) is logged distinctly from "no data", so a
    Cloudflare/auth wall is diagnosable rather than silently indistinguishable from
    an empty result. The one place real network I/O happens; tests inject a fake.
    """
    import httpx  # noqa: PLC0415 -- lazy; keep httpx off the import hot path

    headers = {"User-Agent": _USER_AGENT, **dict(request.headers)}
    last_error: Exception | None = None
    for attempt in range(_RETRIES + 1):
        try:
            resp = httpx.request(
                request.method,
                request.url,
                params=dict(request.params),
                headers=headers,
                data=dict(request.data) if request.data is not None else None,
                timeout=_TIMEOUT_S,
                follow_redirects=True,
            )
        except httpx.HTTPError as exc:
            last_error = exc
        else:
            if resp.status_code == 200:  # noqa: PLR2004 -- HTTP OK
                return resp.text
            if resp.status_code in _RETRY_STATUS and attempt < _RETRIES:
                time.sleep(_BACKOFF_S * (attempt + 1))
                continue
            level = log.warning if resp.status_code in _BLOCKED_STATUS else log.info
            level(
                "intel fetch %s returned HTTP %d (%s)",
                request.url,
                resp.status_code,
                "blocked/rate-limited"
                if resp.status_code in _BLOCKED_STATUS
                else "no data",
            )
            return None
        if attempt < _RETRIES:
            time.sleep(_BACKOFF_S * (attempt + 1))
    if last_error is not None:
        log.info("intel fetch %s failed after retries: %s", request.url, last_error)
    return None
