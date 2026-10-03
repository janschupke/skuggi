"""L3: config / engagement / scoping setup driven end-to-end.

The unit layer tests each driver with a stubbed ``apply``/``FakeBackend``; this
drives the real front-end drivers against a real ``AgentCore`` -- both
in-process (the REPL's path) and over the daemon attach protocol (the
wrapped-shell socket path) -- so the seam between answer-shaping and real
persistence is covered. Offline (no provider, no subprocess), so it runs in the
gate; the autouse ``isolate_credentials`` points both homes + cwd at tmp, so the
``env``/``config.json``/``engagements/`` these flows write stay sandboxed.
"""

from __future__ import annotations

import zoneinfo
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from skuggi.agent import protocol
from skuggi.agent.core import AgentCore
from skuggi.common import home, palette
from skuggi.config.config import Settings
from skuggi.config.configs import load_scope
from skuggi.engagement.engagement import check_command, parse_command
from skuggi.engagement.workspace import Workspace
from skuggi.frontend import setup, wizard
from skuggi.frontend.daemon import Daemon
from skuggi.frontend.prompter import Prompter
from skuggi.install.boot import guard_boot
from skuggi.install.init import initialise
from tests.conftest import offline_settings, wire_offline_core
from tests.support import DEFAULT_REGISTRY


def _answers(*items: str | None) -> Callable[[str], str | None]:
    it = iter(items)
    return lambda _prompt: next(it, None)


def _catalog(core: AgentCore) -> wizard.Catalog:
    return wizard.Catalog(
        timezones=tuple(sorted(zoneinfo.available_timezones())),
        tools=tuple(spec.binary for spec in core.registry.tools),
        methods=palette.methods(),
        methodologies=protocol.METHODOLOGIES,
        taxonomies=protocol.TAXONOMIES,
        stances=protocol.STANCES,
    )


# A full, valid set of wizard answers producing engagement ``name`` -- one scripted
# queue per widget kind, matching the field order in wizard._SECTIONS.
def _wizard_prompter(name: str, notes: list[str] | None = None) -> Prompter:
    sink = notes if notes is not None else []
    # ask: name, start, end, daily, networks, hosts, threat_model
    asks = iter(
        [
            name,
            "2000-01-01T00:00:00+00:00",
            "2999-12-31T23:59:59+00:00",
            "",
            "10.0.0.0/8",
            "",
            "",
        ]
    )
    completes = iter(["UTC", "nmap, curl"])  # timezone, allowed_tools
    chooses = iter(["phases", "cautious"])  # methodology, stance
    multis: list[list[str]] = [["recon", "scan"], []]  # methods, taxonomies
    multi_it = iter(multis)
    confirms = iter([False])  # autonomous
    return Prompter(
        ask=lambda _p: next(asks),
        ask_complete=lambda _p, _c, _d: next(completes),
        choose=lambda _p, _o, _d: next(chooses),
        multiselect=lambda _p, _o, _pre: next(multi_it),
        confirm=lambda _p, _d: next(confirms),
        notify=sink.append,
        progress=lambda *_a: None,
    )


def _run_wizard(core: AgentCore, name: str, notes: list[str] | None = None) -> object:
    return wizard.run_wizard(
        _wizard_prompter(name, notes), core.create_engagement, _catalog(core)
    )


def _provider_then_keep_model(provider: str) -> setup.Choose:
    """A menu stub: the provider label for the provider menu, default for model."""
    label = setup._PROVIDER_LABELS[provider]

    def choose(prompt: str, _options: list[str], default: str | None) -> str | None:
        return default if prompt.startswith("model") else label

    return choose


def _core(tmp_path: Path, *, engagement: str | None = None) -> AgentCore:
    settings = offline_settings(tmp_path, engagement=engagement).model_copy(
        update={"registry_path": DEFAULT_REGISTRY}
    )
    core = AgentCore(settings)
    wire_offline_core(core)
    return core


def _assert_workspace_tree(ws: Workspace) -> None:
    assert ws.scope_path.is_file()
    for rel in ws.layout.dirs():
        assert (ws.root / rel).is_dir(), f"missing workspace dir: {rel}"


# --- in-process: engagement wizard -----------------------------------------


def test_wizard_creates_workspace_tree_and_scope_roundtrips(tmp_path: Path) -> None:
    core = _core(tmp_path)
    notes: list[str] = []

    result = _run_wizard(core, "wiz-eng", notes)

    assert result is not None
    assert core.engagement is not None
    assert core.engagement.name == "wiz-eng"
    assert core.workspace is not None
    _assert_workspace_tree(core.workspace)
    # The written scope.json round-trips back through the real loader.
    loaded = load_scope(core.workspace.scope_path)
    assert loaded == core.engagement
    assert "10.0.0.0/8" in str(loaded.target_networks)
    assert loaded.allowed_methods == frozenset({"recon", "scan"})


# --- in-process: provider / credential setup -------------------------------


def test_run_setup_ollama_persists_and_reresolves(tmp_path: Path) -> None:
    core = _core(tmp_path)
    ok = setup.run_setup(
        core,
        _answers(""),  # ollama url: blank -> default
        _provider_then_keep_model("ollama"),
        lambda _t: None,
    )
    assert ok
    # A fresh Settings re-reads config.json through the normal source precedence.
    assert Settings().provider == "ollama"


def test_run_setup_api_key_writes_env_and_reresolves(tmp_path: Path) -> None:
    core = _core(tmp_path)
    ok = setup.run_setup(
        core,
        _answers("sk-ant-test-abc123"),
        _provider_then_keep_model("anthropic"),
        lambda _t: None,
    )
    assert ok
    fresh = Settings()
    assert fresh.provider == "anthropic"
    assert fresh.anthropic_api_key is not None
    assert fresh.anthropic_api_key.get_secret_value() == "sk-ant-test-abc123"
    assert home.env_path().is_file()
    assert (home.env_path().stat().st_mode & 0o777) == 0o600  # secret file is 0600


# --- in-process: engagement lifecycle --------------------------------------


def test_load_engagement_hot_reload_swaps_ledger_and_session(tmp_path: Path) -> None:
    core = _core(tmp_path)
    _run_wizard(core, "eng-a")
    core.journal.record_finding(severity="high", title="finding only in A")
    ws_a = core.workspace
    assert ws_a is not None
    a_ledger = ws_a.ledger_path
    a_session = core.session_id

    _run_wizard(core, "eng-b")
    ws_b = core.workspace
    assert ws_b is not None
    assert core.session_id != a_session
    assert ws_b.ledger_path != a_ledger
    assert core.journal.findings() == []  # B's ledger is a different, clean file

    core.load_engagement("eng-a")
    ws_reload = core.workspace
    assert ws_reload is not None
    assert ws_reload.ledger_path == a_ledger  # reattached to A's ledger file
    # A hot-reload opens a fresh session, so the finding lives under A's ORIGINAL
    # session -- its survival proves the ledger file, not just the path, swapped.
    assert [f.title for f in core.ledger.findings_for(a_session)] == [
        "finding only in A"
    ]


def test_scope_guard_is_live_through_the_loaded_core(tmp_path: Path) -> None:
    """A proposed out-of-scope command is blocked by the guard the wizard loaded."""
    core = _core(tmp_path)
    _run_wizard(core, "guard-eng")
    engagement = core.engagement
    assert engagement is not None
    now = datetime.now(engagement.tzinfo())
    allowed = check_command(
        parse_command("curl -s http://10.0.0.5/", core.registry),
        engagement,
        now=now,
    )
    denied = check_command(
        parse_command("curl -s http://8.8.8.8/", core.registry),
        engagement,
        now=now,
    )
    assert allowed.allowed
    assert not denied.allowed
    assert "8.8.8.8" in denied.reason


# --- in-process: init -> boot ----------------------------------------------


def test_initialise_then_boot_is_clean(tmp_path: Path) -> None:
    # Seeds the (tmp, isolated) config/data homes, then boots a core from them.
    seeded = initialise(migrate_from=None)
    assert seeded  # reports what it created
    core = guard_boot(lambda: AgentCore(offline_settings(tmp_path)))
    assert isinstance(core, AgentCore)
    core.close()


# --- socket: the daemon attach protocol ------------------------------------


def _drive_attached(daemon: Daemon, lines: list[str]) -> list[dict[str, object]]:
    """Run a persistent attach session feeding ``lines`` then EOF; collect frames."""
    feed = iter([*lines, None])
    frames: list[dict[str, object]] = []
    daemon.run_attached(lambda: next(feed, None), frames.append)
    return frames


def test_attach_wizard_creates_engagement_over_socket(tmp_path: Path) -> None:
    core = _core(tmp_path)
    daemon = Daemon(core)
    try:
        # One answer per read, in field order: menus/checklists arrive as the
        # chosen string / a JSON list / yes-no, exactly as the client sends them.
        answers = [
            "sock-eng",  # name (ask)
            "UTC",  # timezone (ask -- autocomplete degrades over the socket)
            "2000-01-01T00:00:00+00:00",  # authorized_start
            "2999-12-31T23:59:59+00:00",  # authorized_end
            "",  # daily windows
            "10.0.0.0/8",  # target networks
            "",  # allowed hosts
            "nmap, curl",  # allowed tools
            '["recon", "scan"]',  # allowed methods (multiselect -> JSON list)
            "phases",  # methodology (choose)
            "[]",  # taxonomies (multiselect)
            "cautious",  # stance (choose)
            "no",  # autonomous (confirm -> yes/no choose)
            "",  # threat model
        ]
        frames = _drive_attached(daemon, ["engagement setup", *answers])
        # The wizard asked questions as frames of each kind...
        assert any("ask" in f for f in frames)
        assert any("multiselect" in f for f in frames)
        assert any("choose" in f for f in frames)  # methodology/stance/confirm
        assert any("chunk" in f for f in frames)  # the step bar + "loaded" line
        # ...and really created and hot-loaded the engagement through the core.
        assert core.engagement is not None
        assert core.engagement.name == "sock-eng"
        assert core.engagement.allowed_methods == frozenset({"recon", "scan"})
        ws = core.workspace
        assert ws is not None
        _assert_workspace_tree(ws)
    finally:
        core.close()


def test_attach_setup_configures_provider_over_socket(tmp_path: Path) -> None:
    core = _core(tmp_path)
    daemon = Daemon(core)
    try:
        # "setup" -> a {"choose"} provider menu (its label), the ollama url
        # (blank), then a {"choose"} model menu (keep the default).
        label = setup._PROVIDER_LABELS["ollama"]
        frames = _drive_attached(daemon, ["setup", label, "", "qwen3"])
        assert any("choose" in f for f in frames)
        assert Settings().provider == "ollama"
    finally:
        core.close()
