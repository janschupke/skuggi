"""Burp-concept value objects, decoupled from any one bridge backend.

These model the Montoya concepts a connector reads or writes -- proxy history,
HTTP exchanges, scanner issues, repeater/intruder results -- independently of the
wire shape of whatever bridge extension serves them (reburp REST, the PortSwigger
MCP server, burp-mcp). A backend adapter (:mod:`skuggi.burp.client`) parses its own
transport payloads into these types, so everything above the adapter -- the
findings mapping, the guard, the loop -- is backend-agnostic and offline-testable.

Nothing here reaches the network or imports a transport; they are plain frozen
pydantic models.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Burp's native severity and confidence vocabularies (as the Montoya API and every
# bridge report them). Severity maps onto skuggi's finding vocabulary in
# skuggi.burp.findings; confidence decides whether an issue is recorded straight or
# held for operator review.
BurpSeverity = Literal["high", "medium", "low", "info"]
BurpConfidence = Literal["certain", "firm", "tentative"]

# A Burp action the connector can drive. Reads carry no attack traffic; writes send
# real traffic to a target and are gated + recorded per action (see the guard and
# the ledger burp_actions row). Kept here so the guard, the ledger and the client
# share one spelling.
BurpAction = Literal[
    "proxy_history",  # read: observed requests
    "scan_issues",  # read: scanner findings
    "scan_status",  # read: poll an in-flight scan/attack
    "repeater",  # write: send/modify one request
    "active_scan",  # write: launch an audit against a URL
    "intruder",  # write: launch a fuzzing attack
    "set_scope",  # write: push scope into Burp
    "match_replace",  # write: install a proxy match/replace rule
]

# The read actions, so the guard can cheaply class a read as recon without a table.
READ_ACTIONS: frozenset[BurpAction] = frozenset(
    {"proxy_history", "scan_issues", "scan_status"}
)


class HttpExchange(BaseModel):
    """One raw request (and optional response) as Burp holds it.

    ``request``/``response`` are the on-the-wire text; they are proof material and,
    like any finding evidence, are stored raw in the ledger and never fed to the
    model. ``host``/``port``/``secure`` locate the service.
    """

    model_config = ConfigDict(frozen=True)

    host: str = ""
    port: int = 0
    secure: bool = False
    method: str = ""
    path: str = ""
    request: str = ""
    response: str = ""
    status_code: int | None = None

    @property
    def url(self) -> str:
        """The reconstructed absolute URL (best effort; empty host -> path only)."""
        if not self.host:
            return self.path
        scheme = "https" if self.secure else "http"
        default = 443 if self.secure else 80
        hostport = (
            self.host if self.port in (0, default) else f"{self.host}:{self.port}"
        )
        return f"{scheme}://{hostport}{self.path}"


class ProxyEntry(BaseModel):
    """One proxy-history record (an observed exchange, plus Burp's annotations)."""

    model_config = ConfigDict(frozen=True)

    index: int = 0
    exchange: HttpExchange
    notes: str = ""
    highlight: str = ""


class ScanIssue(BaseModel):
    """One scanner issue -- the unit that maps to a skuggi finding.

    ``issue_type`` is Burp's stable type id/name; together with the locus it forms
    the dedup key so a re-scan does not re-emit the same finding. ``evidence`` holds
    the request/response pairs Burp attached as proof.
    """

    model_config = ConfigDict(frozen=True)

    issue_type: str
    name: str
    severity: BurpSeverity
    confidence: BurpConfidence
    host: str = ""
    port: int = 0
    protocol: str = ""
    path: str = ""
    parameter: str = ""
    detail: str = ""
    background: str = ""
    remediation: str = ""
    cwe: tuple[str, ...] = ()
    evidence: tuple[HttpExchange, ...] = ()

    @property
    def url(self) -> str:
        """The issue's absolute URL locus (best effort)."""
        if not self.host:
            return self.path
        scheme = self.protocol or "https"
        return f"{scheme}://{self.host}{self.path}"


class RepeaterResult(BaseModel):
    """The outcome of sending one request through Burp (a Repeater-style send)."""

    model_config = ConfigDict(frozen=True)

    exchange: HttpExchange
    round_trip_ms: int | None = None
    note: str = ""


class IntruderResult(BaseModel):
    """One row of an Intruder/fuzzing attack's results table."""

    model_config = ConfigDict(frozen=True)

    payload: str = ""
    position: str = ""
    exchange: HttpExchange
    length: int | None = None
    flagged: bool = False


# A started scan or attack whose work outlives the turn: the connector keeps the
# ``handle`` (Burp's task id) in the ledger and polls it on a later turn.
TaskState = Literal["queued", "running", "paused", "done", "failed"]


class TaskStatus(BaseModel):
    """The live status of an in-flight scan/intruder task, keyed by its handle."""

    model_config = ConfigDict(frozen=True)

    handle: str
    action: BurpAction
    state: TaskState
    percent: int | None = None
    issues_found: int = 0
    note: str = ""

    @property
    def finished(self) -> bool:
        """Whether the task has reached a terminal state (done or failed)."""
        return self.state in ("done", "failed")


class BurpFeatures(BaseModel):
    """What the connected Burp can do -- edition feature-detection.

    Burp Community has no Scanner and no usable Intruder, so an adapter probes the
    bridge once and records which capabilities are live. A connector degrades an
    unavailable capability to a recorded coverage gap (like an absent OSINT
    source), never an exception.
    """

    model_config = ConfigDict(frozen=True)

    reachable: bool = False
    edition: Literal["professional", "community", "unknown"] = "unknown"
    version: str = ""
    scanner: bool = False
    intruder: bool = False
    backend: str = ""
    detail: str = ""

    @classmethod
    def unreachable(cls, detail: str) -> BurpFeatures:
        """A probe result for a bridge that could not be reached."""
        return cls(reachable=False, detail=detail)

    def supports(self, action: BurpAction) -> bool:
        """Whether this Burp can perform ``action`` given its edition features."""
        if not self.reachable:
            return False
        if action in {"active_scan", "scan_issues"}:
            return self.scanner
        if action == "intruder":
            return self.intruder
        return True


class ScopeRules(BaseModel):
    """A scope push: the include/exclude host/URL rules to install in Burp."""

    model_config = ConfigDict(frozen=True)

    include: tuple[str, ...] = Field(default_factory=tuple)
    exclude: tuple[str, ...] = Field(default_factory=tuple)
