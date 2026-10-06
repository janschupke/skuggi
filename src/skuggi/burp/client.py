"""The ``BurpClient`` protocol and its reburp (REST) backend adapter.

The connector talks to a bridge extension running *inside* Burp (Burp has no
native Python API: the Montoya API is Java/Kotlin and the legacy Extender API is
Jython/py2). The default backend is **reburp** (``forefy/reburp``), which exposes
the Montoya API as a plain JSON REST service on loopback, so it fits skuggi's
existing httpx discipline and needs no extra dependency. The official PortSwigger
MCP server and ``burp-mcp`` can be added as further adapters behind the same
``BurpClient`` protocol later.

Everything above the adapter is backend-agnostic: it speaks :mod:`skuggi.burp.models`
value objects, never a wire payload. The transport is injected (``Transport``), so
the whole adapter is tested offline against canned responses and never touches the
network in the suite -- exactly like :mod:`skuggi.intel.http`.

Wire contract: the REST paths and JSON field names below follow reburp's documented
surface; each is centralised here and marked ``RECONCILE`` so they can be checked
against a live instance's ``/openapi.json`` without touching call sites. The
parsers read tolerantly (missing keys -> defaults), so a minor shape drift degrades
to a thinner result rather than an exception.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, cast, runtime_checkable

from skuggi.burp.models import (
    BurpAction,
    BurpConfidence,
    BurpFeatures,
    BurpSeverity,
    HttpExchange,
    IntruderResult,
    ProxyEntry,
    RepeaterResult,
    ScanIssue,
    ScopeRules,
    TaskStatus,
)
from skuggi.common.logs import get_logger

log = get_logger(__name__)

_TIMEOUT_S = 15.0
_FORBIDDEN = 403
_OK = 200

# RECONCILE against reburp's /openapi.json. One place to correct if the bridge's
# routes move; call sites use the symbol, never a literal path.
_PATHS: dict[str, str] = {
    "features": "/api/status",
    "proxy_history": "/api/proxy/history",
    "scan_issues": "/api/scanner/issues",
    "task_status": "/api/scanner/status",
    "repeater": "/api/repeater/send",
    "active_scan": "/api/scanner/scan",
    "intruder": "/api/intruder/attack",
    "intruder_results": "/api/intruder/results",
    "set_scope": "/api/scope",
    "match_replace": "/api/proxy/match-replace",
}


class BurpError(Exception):
    """A Burp bridge call failed (transport, protocol, or an error status)."""


class BurpUnreachableError(BurpError):
    """The Burp bridge could not be reached at all."""


class BurpFeatureUnavailableError(BurpError):
    """The bridge answered 403 -- a Professional-only feature on Community."""


@dataclass(frozen=True, slots=True)
class BurpResponse:
    """One backend response: an HTTP-ish status and the already-parsed JSON body."""

    status_code: int
    body: object = None


# (method, path, json_body) -> BurpResponse. The one real-I/O seam; a test injects
# a fake that returns canned BurpResponses so the adapter is exercised offline.
Transport = Callable[[str, str, "Mapping[str, object] | None"], BurpResponse]


@runtime_checkable
class BurpClient(Protocol):
    """A backend-agnostic handle on a running Burp instance.

    Read ops carry no attack traffic; write ops send real traffic to a target and
    must be gated + recorded by the caller (see :mod:`skuggi.engagement.burp_guard`
    and the ledger ``burp_actions`` row). An adapter raises :class:`BurpError`
    (or a subclass) on failure and never returns a partial lie.
    """

    def feature_probe(self) -> BurpFeatures:
        """Detect reachability + edition features (Scanner/Intruder). Never raises."""
        ...

    def proxy_history(
        self, *, host_filter: str = "", limit: int = 200
    ) -> tuple[ProxyEntry, ...]:
        """Read observed proxy exchanges, optionally filtered to one host."""
        ...

    def scan_issues(self, *, host_filter: str = "") -> tuple[ScanIssue, ...]:
        """Read the scanner's current issues, optionally filtered to one host."""
        ...

    def task_status(self, handle: str) -> TaskStatus:
        """Poll an in-flight scan/attack by its handle."""
        ...

    def send_request(self, exchange: HttpExchange) -> RepeaterResult:
        """Send one request through Burp and return the exchange (Repeater-style)."""
        ...

    def start_scan(self, url: str) -> str:
        """Launch an active scan against ``url``; return its pollable handle."""
        ...

    def start_intruder(
        self, exchange: HttpExchange, payloads: tuple[str, ...], marker: str
    ) -> str:
        """Launch an Intruder attack (``marker`` marks the insertion point)."""
        ...

    def attack_results(self, handle: str) -> tuple[IntruderResult, ...]:
        """Read an Intruder attack's result rows by its handle."""
        ...

    def set_scope(self, rules: ScopeRules) -> None:
        """Push include/exclude scope rules into Burp."""
        ...

    def add_match_replace(self, match: str, replace: str) -> None:
        """Install a proxy match/replace rule."""
        ...


def _as_str(value: object) -> str:
    """A string from a tolerant JSON value (None -> '')."""
    return "" if value is None else str(value)


def _as_int(value: object) -> int:
    """An int from a tolerant JSON value (non-numeric -> 0)."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return 0
    return 0


def _as_bool(value: object) -> bool:
    """A bool from a tolerant JSON value."""
    return bool(value)


def _rows(body: object, key: str) -> list[Mapping[str, object]]:
    """The list of record dicts in ``body`` -- a bare list, or ``body[key]``."""
    if isinstance(body, list):
        return [r for r in body if isinstance(r, Mapping)]
    if isinstance(body, Mapping):
        inner = body.get(key)
        if isinstance(inner, list):
            return [r for r in inner if isinstance(r, Mapping)]
    return []


def _exchange(row: Mapping[str, object]) -> HttpExchange:
    """Parse one HTTP exchange from a reburp record (RECONCILE field names)."""
    return HttpExchange(
        host=_as_str(row.get("host")),
        port=_as_int(row.get("port")),
        secure=_as_bool(row.get("secure") or row.get("https")),
        method=_as_str(row.get("method")),
        path=_as_str(row.get("path") or row.get("url")),
        request=_as_str(row.get("request")),
        response=_as_str(row.get("response")),
        status_code=_as_int(row.get("status")) or None,
    )


def _issue(row: Mapping[str, object]) -> ScanIssue:
    """Parse one scanner issue from a reburp record (RECONCILE field names)."""
    cwe_raw = row.get("cwe")
    cwe = tuple(_as_str(c) for c in cwe_raw) if isinstance(cwe_raw, list) else ()
    ev_rows = _rows(row.get("evidence"), "evidence")
    return ScanIssue(
        issue_type=_as_str(row.get("type") or row.get("issue_type") or row.get("name")),
        name=_as_str(row.get("name")),
        severity=_severity(_as_str(row.get("severity"))),
        confidence=_confidence(_as_str(row.get("confidence"))),
        host=_as_str(row.get("host")),
        port=_as_int(row.get("port")),
        protocol=_as_str(row.get("protocol")),
        path=_as_str(row.get("path")),
        parameter=_as_str(row.get("parameter")),
        detail=_as_str(row.get("detail") or row.get("issueDetail")),
        background=_as_str(row.get("background") or row.get("issueBackground")),
        remediation=_as_str(row.get("remediation") or row.get("remediationDetail")),
        cwe=cwe,
        evidence=tuple(_exchange(e) for e in ev_rows),
    )


def _severity(raw: str) -> BurpSeverity:
    """Normalise a Burp severity string to the model's vocabulary."""
    low = raw.strip().lower()
    if low in ("high", "medium", "low"):
        return cast("BurpSeverity", low)
    return "info"


def _confidence(raw: str) -> BurpConfidence:
    """Normalise a Burp confidence string to the model's vocabulary."""
    low = raw.strip().lower()
    if low in ("certain", "firm", "tentative"):
        return cast("BurpConfidence", low)
    return "tentative"


class ReburpClient:
    """A :class:`BurpClient` over the reburp REST bridge, via an injected transport.

    Construct with :func:`make_reburp_client` for the real httpx transport, or pass a
    fake ``transport`` in tests. ``backend`` is carried only for reporting.
    """

    def __init__(self, transport: Transport, *, backend: str = "reburp") -> None:
        self._transport = transport
        self._backend = backend

    def _call(
        self,
        path: str,
        *,
        method: str = "GET",
        body: Mapping[str, object] | None = None,
    ) -> object:
        """One backend call; map an error status to the right ``BurpError``."""
        try:
            resp = self._transport(method, path, body)
        except BurpError:
            raise
        except Exception as exc:
            msg = f"burp transport failed for {path}"
            raise BurpUnreachableError(msg) from exc
        if resp.status_code == _FORBIDDEN:
            msg = f"burp feature unavailable (403) at {path}"
            raise BurpFeatureUnavailableError(msg)
        if resp.status_code != _OK:
            msg = f"burp bridge returned HTTP {resp.status_code} for {path}"
            raise BurpError(msg)
        return resp.body

    def feature_probe(self) -> BurpFeatures:
        """Probe reachability + edition; a failure becomes an unreachable result."""
        try:
            body = self._call(_PATHS["features"])
        except BurpError as exc:
            return BurpFeatures.unreachable(str(exc))
        info = body if isinstance(body, Mapping) else {}
        edition_raw = _as_str(info.get("edition")).lower()
        edition = (
            "professional"
            if "pro" in edition_raw
            else ("community" if "comm" in edition_raw else "unknown")
        )
        scanner = _as_bool(info.get("scanner", edition == "professional"))
        intruder = _as_bool(info.get("intruder", edition == "professional"))
        return BurpFeatures(
            reachable=True,
            edition=edition,  # type: ignore[arg-type]
            version=_as_str(info.get("version")),
            scanner=scanner,
            intruder=intruder,
            backend=self._backend,
        )

    def proxy_history(
        self, *, host_filter: str = "", limit: int = 200
    ) -> tuple[ProxyEntry, ...]:
        """Read proxy history (RECONCILE query params + record shape)."""
        body = self._call(f"{_PATHS['proxy_history']}?host={host_filter}&limit={limit}")
        return tuple(
            ProxyEntry(
                index=_as_int(row.get("index")) or i,
                exchange=_exchange(row),
                notes=_as_str(row.get("notes")),
                highlight=_as_str(row.get("highlight")),
            )
            for i, row in enumerate(_rows(body, "history"))
        )

    def scan_issues(self, *, host_filter: str = "") -> tuple[ScanIssue, ...]:
        """Read scanner issues (RECONCILE query param + record shape)."""
        body = self._call(f"{_PATHS['scan_issues']}?host={host_filter}")
        return tuple(_issue(row) for row in _rows(body, "issues"))

    def task_status(self, handle: str) -> TaskStatus:
        """Poll a scan/attack by handle (RECONCILE record shape)."""
        body = self._call(f"{_PATHS['task_status']}?id={handle}")
        info = body if isinstance(body, Mapping) else {}
        state = _as_str(info.get("state") or info.get("status")).lower() or "running"
        if state not in ("queued", "running", "paused", "done", "failed"):
            state = "running"
        return TaskStatus(
            handle=handle,
            action="active_scan",
            state=state,  # type: ignore[arg-type]
            percent=_as_int(info.get("percent")) or None,
            issues_found=_as_int(info.get("issues")),
            note=_as_str(info.get("note")),
        )

    def send_request(self, exchange: HttpExchange) -> RepeaterResult:
        """Send one request through Burp (RECONCILE request/response body)."""
        body = self._call(
            _PATHS["repeater"], method="POST", body=_exchange_payload(exchange)
        )
        info = body if isinstance(body, Mapping) else {}
        return RepeaterResult(
            exchange=_exchange({**_exchange_payload(exchange), **dict(info)}),
            round_trip_ms=_as_int(info.get("time_ms")) or None,
            note=_as_str(info.get("note")),
        )

    def start_scan(self, url: str) -> str:
        """Launch an active scan; return the handle (RECONCILE response field)."""
        body = self._call(_PATHS["active_scan"], method="POST", body={"url": url})
        return _handle(body)

    def start_intruder(
        self, exchange: HttpExchange, payloads: tuple[str, ...], marker: str
    ) -> str:
        """Launch an Intruder attack; return the handle (RECONCILE body shape)."""
        payload = {
            **_exchange_payload(exchange),
            "payloads": list(payloads),
            "marker": marker,
        }
        body = self._call(_PATHS["intruder"], method="POST", body=payload)
        return _handle(body)

    def attack_results(self, handle: str) -> tuple[IntruderResult, ...]:
        """Read Intruder results by handle (RECONCILE record shape)."""
        body = self._call(f"{_PATHS['intruder_results']}?id={handle}")
        return tuple(
            IntruderResult(
                payload=_as_str(row.get("payload")),
                position=_as_str(row.get("position")),
                exchange=_exchange(row),
                length=_as_int(row.get("length")) or None,
                flagged=_as_bool(row.get("flagged")),
            )
            for row in _rows(body, "results")
        )

    def set_scope(self, rules: ScopeRules) -> None:
        """Push scope rules into Burp."""
        self._call(
            _PATHS["set_scope"],
            method="POST",
            body={"include": list(rules.include), "exclude": list(rules.exclude)},
        )

    def add_match_replace(self, match: str, replace: str) -> None:
        """Install a proxy match/replace rule."""
        self._call(
            _PATHS["match_replace"],
            method="POST",
            body={"match": match, "replace": replace},
        )


def _exchange_payload(exchange: HttpExchange) -> dict[str, object]:
    """The POST body for sending an exchange (RECONCILE field names)."""
    return {
        "host": exchange.host,
        "port": exchange.port,
        "secure": exchange.secure,
        "method": exchange.method,
        "path": exchange.path,
        "request": exchange.request,
    }


def _handle(body: object) -> str:
    """Extract a task handle from a start-scan/attack response (RECONCILE field)."""
    if isinstance(body, Mapping):
        handle = body.get("id") or body.get("handle") or body.get("task_id")
        if handle is not None:
            return str(handle)
    msg = "burp bridge did not return a task handle"
    raise BurpError(msg)


def make_reburp_client(
    base_url: str, *, api_key: str = "", timeout: float = _TIMEOUT_S
) -> ReburpClient:
    """A :class:`ReburpClient` with the real httpx transport against ``base_url``.

    httpx is imported lazily (off the module hot path). The transport posts/gets
    JSON on loopback; an API key, when the bridge requires one, is sent as a bearer
    header. Any transport error raises :class:`BurpUnreachableError` at the call site.
    """

    def _transport(
        method: str, path: str, body: Mapping[str, object] | None
    ) -> BurpResponse:
        import httpx  # noqa: PLC0415 -- lazy; keep httpx off the import hot path

        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        resp = httpx.request(
            method,
            f"{base_url.rstrip('/')}{path}",
            json=dict(body) if body is not None else None,
            headers=headers,
            timeout=timeout,
        )
        try:
            parsed: object = resp.json()
        except ValueError:
            parsed = None
        return BurpResponse(status_code=resp.status_code, body=parsed)

    return ReburpClient(_transport, backend="reburp")


def make_burp_client(backend: str, base_url: str, *, api_key: str = "") -> BurpClient:
    """The configured :class:`BurpClient` for ``backend`` (primitives, not Settings).

    Kept a leaf (no config import) so the core reads the settings and calls this.
    Only the reburp REST adapter ships today; the MCP adapters are a planned
    pluggable backend and raise until implemented, never silently mis-dispatch.
    """
    if backend == "reburp":
        return make_reburp_client(base_url, api_key=api_key)
    msg = f"burp backend {backend!r} is not implemented yet (reburp only)"
    raise NotImplementedError(msg)


def feature_for(client: BurpClient, action: BurpAction) -> bool:
    """Whether ``client``'s Burp supports ``action`` (one probe, cached by caller)."""
    return client.feature_probe().supports(action)
