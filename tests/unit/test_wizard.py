"""L1: the engagement Q&A wizard -- answer shaping, step bar, preserve-on-retry."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from skuggi.config.configs import InvalidScopeError
from skuggi.engagement.engagement import EngagementConfig
from skuggi.frontend.prompter import Prompter
from skuggi.frontend.wizard import KNOWN_KEYS, Catalog, collect_scope, run_wizard

_CATALOG = Catalog(
    timezones=("UTC", "Europe/Helsinki"),
    tools=("nmap", "curl", "nikto"),
    methods=("recon", "scan", "enumerate", "bruteforce", "crack", "exploit"),
    methodologies=("phases", "ptes", "attack"),
    taxonomies=("wstg", "attack"),
    stances=("passive", "cautious", "balanced", "aggressive"),
    osint_sources=("crtsh", "dns", "github", "websearch"),
)

_VALID = EngagementConfig(
    name="x",
    timezone="UTC",
    authorized_start=datetime(2026, 1, 1, tzinfo=UTC),
    authorized_end=datetime(2026, 12, 31, tzinfo=UTC),
)


@dataclass
class _Script:
    """Scripted answers per widget kind, plus recorders for assertions."""

    asks: list[str | None] = field(default_factory=list)
    completes: list[str | None] = field(default_factory=list)
    chooses: list[str | None] = field(default_factory=list)
    multis: list[list[str] | None] = field(default_factory=list)
    confirms: list[bool | None] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    steps: list[tuple[int, int, str]] = field(default_factory=list)
    asked: list[str] = field(default_factory=list)  # every prompt label, in order

    def prompter(self) -> Prompter:
        asks = iter(self.asks)
        completes = iter(self.completes)
        chooses = iter(self.chooses)
        multis = iter(self.multis)
        confirms = iter(self.confirms)

        def ask(prompt: str) -> str | None:
            self.asked.append(prompt)
            return next(asks)

        def ask_complete(prompt: str, _c: Sequence[str], _d: str | None) -> str | None:
            self.asked.append(prompt)
            return next(completes)

        def choose(prompt: str, _o: list[str], _d: str | None) -> str | None:
            self.asked.append(prompt)
            return next(chooses)

        def multiselect(
            prompt: str, _o: Sequence[str], _pre: Sequence[str]
        ) -> list[str] | None:
            self.asked.append(prompt)
            return next(multis)

        def confirm(prompt: str, _d: bool) -> bool | None:
            self.asked.append(prompt)
            return next(confirms)

        return Prompter(
            ask=ask,
            ask_complete=ask_complete,
            choose=choose,
            multiselect=multiselect,
            confirm=confirm,
            notify=self.notes.append,
            progress=lambda s, t, label: self.steps.append((s, t, label)),
        )


def _full_script(**over: object) -> _Script:
    """A complete, valid pass. Keyword overrides replace a widget queue."""
    base = _Script(
        # name, start, end, daily, networks, hosts
        asks=[
            "acme",
            "2026-01-01T00:00:00+00:00",
            "2026-12-31T23:59:59+00:00",
            "",
            "192.0.2.0/24",
            "",
        ],
        completes=["UTC", "nmap, curl"],  # timezone, allowed_tools
        # methodology, stance, autonomous_ceiling, then the threat-model C/I/A dropdowns
        chooses=["ptes", "cautious", "active", "high", "medium", "low"],
        multis=[["recon", "scan"], ["wstg"]],  # allowed_methods, taxonomies
        # autonomous, enable-threat-model, enable-OSINT (declined by default)
        confirms=[True, True, False],
    )
    for key, value in over.items():
        setattr(base, key, value)
    return base


def test_collect_scope_shapes_answers_into_valid_scope() -> None:
    script = _full_script()
    raw = collect_scope(script.prompter(), _CATALOG)
    assert raw is not None
    assert raw["name"] == "acme"
    assert raw["timezone"] == "UTC"
    assert raw["target_networks"] == ["192.0.2.0/24"]
    assert raw["allowed_tools"] == ["nmap", "curl"]
    assert raw["allowed_methods"] == ["recon", "scan"]
    assert raw["methodology"] == "ptes"
    assert raw["taxonomies"] == ["wstg"]
    assert raw["stance"] == "cautious"
    assert raw["autonomous"] is True
    assert raw["threat_model"] == {
        "confidentiality_requirement": "high",
        "integrity_requirement": "medium",
        "availability_requirement": "low",
    }
    EngagementConfig.model_validate(raw)  # the shaped dict validates


def test_threat_model_declined_is_none() -> None:
    script = _full_script(confirms=[True, False, False])  # autonomous, tm, osint
    raw = collect_scope(script.prompter(), _CATALOG)
    assert raw is not None
    assert raw.get("threat_model") is None


def test_star_allows_all_tools() -> None:
    script = _full_script(completes=["UTC", "*"])
    raw = collect_scope(script.prompter(), _CATALOG)
    assert raw is not None
    assert raw["allowed_tools"] == ["*"]


def test_blank_time_bounds_leave_no_window() -> None:
    script = _full_script(
        asks=["acme", "", "", "", "", ""]  # blank start/end + the rest
    )
    raw = collect_scope(script.prompter(), _CATALOG)
    assert raw is not None
    assert "authorized_start" not in raw
    assert "authorized_end" not in raw
    config = EngagementConfig.model_validate(raw)
    assert config.authorized_start is None
    assert config.authorized_end is None


def test_step_bar_ticks_once_per_section() -> None:
    script = _full_script()
    collect_scope(script.prompter(), _CATALOG)
    assert script.steps == [
        (1, 7, "Identity"),
        (2, 7, "Authorization"),
        (3, 7, "Schedule"),
        (4, 7, "Targets"),
        (5, 7, "Capabilities"),
        (6, 7, "Approach"),
        (7, 7, "OSINT"),
    ]


def test_collect_scope_aborts_when_a_widget_returns_none() -> None:
    script = _full_script(asks=["acme", None])  # abort on authorized_start
    assert collect_scope(script.prompter(), _CATALOG) is None


def test_collect_scope_edit_keeps_existing_on_blank() -> None:
    script = _Script(
        asks=["", "", "", "", "", ""],
        completes=["", ""],
        chooses=["phases", "cautious", "active"],  # methodology, stance, ceiling
        multis=[[], []],
        confirms=[False, False, False],  # autonomous, threat-model, osint (declined)
    )
    raw = collect_scope(script.prompter(), _CATALOG, existing=_VALID)
    assert raw is not None
    assert raw["name"] == "x"  # blank kept the existing value


def test_run_wizard_applies_and_reports_loaded() -> None:
    script = _full_script()
    eng = run_wizard(script.prompter(), lambda _raw: _VALID, _CATALOG)
    assert eng is _VALID
    assert any("loaded" in n for n in script.notes)


def test_run_wizard_preserves_answers_and_reasks_only_failed_field() -> None:
    calls: list[dict[str, object]] = []

    def apply(raw: dict[str, object]) -> EngagementConfig:
        calls.append(dict(raw))
        if len(calls) == 1:
            detail = "authorized_end: bad"
            raise InvalidScopeError(detail, frozenset({"authorized_end"}))
        return _VALID

    # First pass is complete; the retry supplies ONLY a new authorized_end.
    script = _full_script()
    script.asks.append("2027-01-01T00:00:00+00:00")  # the re-asked field
    eng = run_wizard(script.prompter(), apply, _CATALOG)

    assert eng is _VALID
    assert len(calls) == 2  # applied twice: reject, then accept
    # The name from the first pass survived into the retry's payload...
    assert calls[1]["name"] == "acme"
    # ...and only authorized_end was re-asked on the second pass.
    reask_labels = [p for p in script.asked if p.startswith("authorized end")]
    assert len(reask_labels) == 2  # once per pass; the retry asked just this one
    assert calls[1]["authorized_end"] == "2027-01-01T00:00:00+00:00"
    # The retry's step bar showed only the Authorization section.
    assert script.steps[-1] == (2, 7, "Authorization")


def test_run_wizard_cancelled_on_abort() -> None:
    script = _full_script(asks=["acme", None])
    eng = run_wizard(script.prompter(), lambda _raw: _VALID, _CATALOG)
    assert eng is None
    assert any("cancelled" in n for n in script.notes)


def test_known_keys_cover_every_managed_engagement_field() -> None:
    # Every EngagementConfig field the operator should set is in exactly one
    # wizard field -- a field dropping out of the wizard fails here.
    managed = set(EngagementConfig.model_fields) - {"primary_target"}
    assert managed == set(KNOWN_KEYS)


def test_osint_enabled_collects_a_nested_scope() -> None:
    # Append the OSINT sub-prompts after the base pass: sources (multi),
    # four subject asks, passive-only (confirm), ceiling (choose).
    script = _full_script(
        confirms=[True, True, True, True],  # autonomous, tm, osint-enable, passive
    )
    script.multis.append(["crtsh", "github"])  # OSINT sources
    script.asks += ["Acme Corp", "acme.com", "", "acme"]  # orgs/domains/people/github
    script.chooses.append("recon")  # OSINT ceiling
    raw = collect_scope(script.prompter(), _CATALOG)
    assert raw is not None
    assert raw["osint"] == {
        "enabled_sources": ["crtsh", "github"],
        "organizations": ["Acme Corp"],
        "domains": ["acme.com"],
        "people": [],
        "github_orgs": ["acme"],
        "passive_only": True,
        "autonomous_ceiling": "recon",
    }
    EngagementConfig.model_validate(raw)  # the nested dict validates


def test_osint_declined_is_none() -> None:
    raw = collect_scope(_full_script().prompter(), _CATALOG)
    assert raw is not None
    assert raw.get("osint") is None
