"""L1: the engagement boundary guard and command parsing.

The allow/deny matrix is the pentest analogue of the file_read prefix-escape
regression: the guard must be conservative, and target extraction must not miss
the host a command acts on.
"""

from __future__ import annotations

from datetime import UTC, datetime, time
from pathlib import Path

import pytest

from skuggi.agent.protocol import methodology_phases
from skuggi.engagement.engagement import (
    EngagementConfig,
    ThreatModel,
    TimeWindow,
    check_command,
    parse_command,
)
from skuggi.engagement.workspace import Workspace
from skuggi.tooling.registry import ToolRegistry, ToolSpec

REGISTRY = ToolRegistry(
    tools=(
        ToolSpec(name="nmap", binary="nmap", method="scan", target_file_flags=("-iL",)),
        ToolSpec(name="curl", binary="curl", method="recon"),
        ToolSpec(name="nikto", binary="nikto", method="scan", target_flags=("-h",)),
        ToolSpec(
            name="sqlmap", binary="sqlmap", method="enumerate", target_flags=("-u",)
        ),
        ToolSpec(
            name="hydra",
            binary="hydra",
            method="scan",
            target_flags=("-t",),
            input_file_flags=("-P", "-L"),
        ),
    )
)


def _engagement(**overrides: object) -> EngagementConfig:
    base: dict[str, object] = {
        "name": "e",
        "timezone": "UTC",
        "authorized_start": datetime(2026, 1, 1, tzinfo=UTC),
        "authorized_end": datetime(2026, 12, 31, 23, 59, tzinfo=UTC),
        "target_networks": ("10.0.0.0/8", "192.168.0.0/16"),
        "allowed_hosts": frozenset({"scanme.example.com"}),
        "allowed_tools": frozenset({"nmap", "curl", "sqlmap", "hydra"}),
        "allowed_methods": frozenset({"scan", "recon"}),
    }
    base.update(overrides)
    return EngagementConfig.model_validate(base)


NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


# --- parsing / target extraction --------------------------------------------


def test_parses_binary_and_method() -> None:
    cmd = parse_command("nmap -sV 10.0.0.5", REGISTRY)
    assert cmd.binary == "nmap"
    assert cmd.method == "scan"


def test_strips_a_path_from_the_binary() -> None:
    assert parse_command("/usr/bin/nmap 10.0.0.5", REGISTRY).binary == "nmap"


def test_extracts_an_ip_target() -> None:
    assert parse_command("nmap -p 80 10.0.0.5", REGISTRY).targets == ("10.0.0.5",)


def test_a_port_number_is_not_a_target() -> None:
    """`80` following `-p` must not be mistaken for a target host."""
    assert "80" not in parse_command("nmap -p 80 10.0.0.5", REGISTRY).targets


def test_extracts_a_cidr_target() -> None:
    assert parse_command("nmap 10.0.0.0/24", REGISTRY).targets == ("10.0.0.0/24",)


def test_extracts_the_host_from_a_url() -> None:
    cmd = parse_command("curl https://scanme.example.com/path", REGISTRY)
    assert cmd.targets == ("scanme.example.com",)


def test_a_target_flag_forces_a_bare_word() -> None:
    """`-t localhost` is a target even though `localhost` has no dot."""
    assert parse_command("hydra -t localhost", REGISTRY).targets == ("localhost",)


def test_a_url_after_a_target_flag_is_classified_to_its_host() -> None:
    """`sqlmap -u http://10.0.0.5/x` is the host `10.0.0.5`, not the whole URL."""
    cmd = parse_command("sqlmap -u http://10.0.0.5/dumps?id=1", REGISTRY)
    assert cmd.targets == ("10.0.0.5",)


def test_a_url_with_a_port_after_a_target_flag_strips_the_port() -> None:
    cmd = parse_command("sqlmap -u http://10.0.0.5:8080/x", REGISTRY)
    assert cmd.targets == ("10.0.0.5",)


def test_unparseable_command_yields_empty_binary() -> None:
    assert parse_command('nmap "', REGISTRY).binary == ""


# --- the allow/deny matrix --------------------------------------------------


def test_in_scope_command_is_allowed() -> None:
    verdict = check_command(
        parse_command("nmap 10.0.0.5", REGISTRY), _engagement(), now=NOW
    )
    assert verdict.allowed


def test_unknown_tool_is_denied() -> None:
    verdict = check_command(
        parse_command("foobar 10.0.0.5", REGISTRY), _engagement(), now=NOW
    )
    assert not verdict.allowed
    assert "registry" in verdict.reason


def test_unauthorized_tool_is_denied() -> None:
    """Nikto is in the registry but not this engagement's allowed_tools."""
    verdict = check_command(
        parse_command("nikto -h 10.0.0.5", REGISTRY), _engagement(), now=NOW
    )
    assert not verdict.allowed
    assert "not authorized" in verdict.reason


def test_unauthorized_method_is_denied() -> None:
    """Sqlmap is allowed, but its method 'enumerate' is not."""
    verdict = check_command(
        parse_command("sqlmap -u https://scanme.example.com", REGISTRY),
        _engagement(),
        now=NOW,
    )
    assert not verdict.allowed
    assert "method" in verdict.reason


def test_in_scope_url_after_a_target_flag_is_allowed() -> None:
    """The unhack: a flag-forced in-scope URL passes the guard cleanly."""
    verdict = check_command(
        parse_command("sqlmap -u http://10.0.0.5/x", REGISTRY),
        _engagement(allowed_methods=frozenset({"scan", "recon", "enumerate"})),
        now=NOW,
    )
    assert verdict.allowed


def test_out_of_scope_url_after_a_target_flag_is_denied() -> None:
    """The extracted host is still scope-checked -- security is preserved."""
    verdict = check_command(
        parse_command("sqlmap -u http://8.8.8.8/x", REGISTRY),
        _engagement(allowed_methods=frozenset({"scan", "recon", "enumerate"})),
        now=NOW,
    )
    assert not verdict.allowed
    assert "8.8.8.8" in verdict.reason


def test_before_the_window_is_denied() -> None:
    verdict = check_command(
        parse_command("nmap 10.0.0.5", REGISTRY),
        _engagement(),
        now=datetime(2025, 1, 1, tzinfo=UTC),
    )
    assert not verdict.allowed
    assert "date/time" in verdict.reason


def test_outside_the_daily_window_is_denied() -> None:
    eng = _engagement(daily_windows=(TimeWindow(start=time(9), end=time(17)),))
    verdict = check_command(
        parse_command("nmap 10.0.0.5", REGISTRY),
        eng,
        now=datetime(2026, 6, 1, 20, 0, tzinfo=UTC),
    )
    assert not verdict.allowed
    assert "daily" in verdict.reason


def test_inside_the_daily_window_is_allowed() -> None:
    eng = _engagement(daily_windows=(TimeWindow(start=time(9), end=time(17)),))
    verdict = check_command(parse_command("nmap 10.0.0.5", REGISTRY), eng, now=NOW)
    assert verdict.allowed


def test_out_of_scope_ip_is_denied() -> None:
    verdict = check_command(
        parse_command("nmap 8.8.8.8", REGISTRY), _engagement(), now=NOW
    )
    assert not verdict.allowed
    assert "8.8.8.8" in verdict.reason


def test_a_target_requiring_tool_with_no_target_is_denied() -> None:
    verdict = check_command(parse_command("nmap -sV", REGISTRY), _engagement(), now=NOW)
    assert not verdict.allowed
    assert "no in-scope target" in verdict.reason


def test_allowed_hostname_is_in_scope() -> None:
    verdict = check_command(
        parse_command("curl https://scanme.example.com", REGISTRY),
        _engagement(),
        now=NOW,
    )
    assert verdict.allowed


def test_unlisted_hostname_is_denied() -> None:
    verdict = check_command(
        parse_command("curl https://evil.example.com", REGISTRY), _engagement(), now=NOW
    )
    assert not verdict.allowed
    assert "evil.example.com" in verdict.reason


def test_empty_command_is_denied() -> None:
    verdict = check_command(parse_command("", REGISTRY), _engagement(), now=NOW)
    assert not verdict.allowed


# --- config validation ------------------------------------------------------


def test_naive_datetime_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        _engagement(authorized_start=datetime(2026, 1, 1))  # noqa: DTZ001


def test_unknown_timezone_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown timezone"):
        _engagement(timezone="Mars/Olympus")


@pytest.mark.parametrize(
    ("moment", "inside"),
    [("23:00", True), ("01:00", True), ("12:00", False)],
)
def test_midnight_spanning_window(moment: str, inside: bool) -> None:
    window = TimeWindow(start=time(22), end=time(2))
    assert window.contains(time.fromisoformat(moment)) is inside


# --- stance (advisory posture) ----------------------------------------------


def test_stance_defaults_to_cautious() -> None:
    assert _engagement().stance == "cautious"


def test_stance_loads_from_scope_and_shows_in_describe() -> None:
    eng = _engagement(stance="aggressive")
    assert eng.stance == "aggressive"
    assert "stance: aggressive" in eng.describe()


# --- primary target resolution (cheatsheet ${target} default) ---------------


def test_resolve_target_prefers_the_explicit_field() -> None:
    eng = _engagement(primary_target="10.1.2.3")
    assert eng.resolve_target() == "10.1.2.3"


def test_resolve_target_falls_back_to_a_sole_host() -> None:
    # The default helper has exactly one allowed host and no explicit target.
    assert _engagement().resolve_target() == "scanme.example.com"


def test_resolve_target_uses_a_sole_network_when_no_host() -> None:
    eng = _engagement(allowed_hosts=frozenset(), target_networks=("192.0.2.0/24",))
    assert eng.resolve_target() == "192.0.2.0/24"


def test_resolve_target_is_none_when_ambiguous() -> None:
    eng = _engagement(
        allowed_hosts=frozenset({"a.example.com", "b.example.com"}),
        target_networks=("10.0.0.0/8", "192.168.0.0/16"),
    )
    assert eng.resolve_target() is None


# --- S1: multi-host target expressions must not ride along unchecked --------
#
# The guard's contract is that anything it cannot prove in scope is denied. A
# target *expression* (an nmap range/list or a `-iL` file) used to classify as
# nothing and be silently dropped, so a command rode in-scope on one good host
# while touching others. These assert the expansion-or-deny behaviour.

_TIGHT = {"target_networks": ("10.0.0.5/32",), "allowed_hosts": frozenset()}


def test_range_rides_along_on_a_single_in_scope_host_is_blocked() -> None:
    """`nmap 10.0.0.5 10.0.0.1-254` scanned the /24 while passing on .5."""
    verdict = check_command(
        parse_command("nmap 10.0.0.5 10.0.0.1-254", REGISTRY),
        _engagement(**_TIGHT),
        now=NOW,
    )
    assert not verdict.allowed
    assert "10.0.0.1" in verdict.reason  # an expanded host, scope-checked


def test_comma_list_with_an_out_of_scope_member_is_blocked() -> None:
    verdict = check_command(
        parse_command("nmap 10.0.0.1,10.0.0.2,8.8.8.8", REGISTRY),
        _engagement(),
        now=NOW,
    )
    assert not verdict.allowed
    assert "8.8.8.8" in verdict.reason


def test_unenumerable_octet_shorthand_list_is_denied_fail_closed() -> None:
    verdict = check_command(
        parse_command("nmap 10.0.0.1,2,3", REGISTRY), _engagement(**_TIGHT), now=NOW
    )
    assert not verdict.allowed
    assert "resolve" in verdict.reason


def test_target_list_file_is_denied() -> None:
    verdict = check_command(
        parse_command("nmap -iL hosts.txt 10.0.0.5", REGISTRY),
        _engagement(**_TIGHT),
        now=NOW,
    )
    assert not verdict.allowed
    assert "target-list file" in verdict.reason


def test_a_range_fully_inside_scope_is_allowed() -> None:
    """No false positive: an enumerable, wholly in-scope range still passes."""
    verdict = check_command(
        parse_command("nmap 10.0.0.1-10", REGISTRY), _engagement(), now=NOW
    )
    assert verdict.allowed


def test_a_port_range_is_not_treated_as_a_target() -> None:
    """`-p 1-1000` has no dot: it is a port range, not host material."""
    cmd = parse_command("nmap -p 1-1000 10.0.0.5", REGISTRY)
    assert cmd.targets == ("10.0.0.5",)
    assert not cmd.unresolved


def test_threat_model_maps_requirements_to_cvss_metrics() -> None:
    tm = ThreatModel(
        confidentiality_requirement="high",
        integrity_requirement="medium",
        availability_requirement="low",
    )
    # Neutral "medium" (CVSS "M") is omitted; only shifting levels appear.
    assert tm.cvss_environmental_metrics() == {"CR": "H", "AR": "L"}
    assert ThreatModel().cvss_environmental_metrics() == {}  # all-medium default


def test_scope_defaults_and_framework_fields() -> None:
    base = {
        "name": "e",
        "timezone": "UTC",
        "authorized_start": "2026-01-01T00:00:00+00:00",
        "authorized_end": "2026-12-31T00:00:00+00:00",
    }
    # Defaults: built-in phases, no taxonomies, no threat model.
    default = EngagementConfig.model_validate(base)
    assert default.methodology == "phases"
    assert default.taxonomies == frozenset()
    assert default.threat_model is None
    # And the full framework-aware form validates.
    full = EngagementConfig.model_validate(
        {
            **base,
            "methodology": "attack",
            "taxonomies": ["wstg", "attack"],
            "threat_model": {"confidentiality_requirement": "high"},
        }
    )
    assert full.methodology == "attack"
    assert full.taxonomies == frozenset({"wstg", "attack"})
    assert full.threat_model is not None
    assert full.threat_model.cvss_environmental_metrics() == {"CR": "H"}


def test_methodology_phases_per_driver() -> None:
    assert methodology_phases("phases")[0] == "recon"
    # PTES phases come from the vendored taxonomy (single source).
    assert methodology_phases("ptes")[0] == "Pre-engagement Interactions"
    assert "initial-access" in methodology_phases("attack")


# --- data-file flag confinement (wordlists reach tools, not the model) ------


def test_parse_extracts_input_files_separate_and_glued() -> None:
    cmd = parse_command("hydra -P inputs/pw.txt -L=inputs/users.txt 10.0.0.5", REGISTRY)
    assert cmd.input_files == ("inputs/pw.txt", "inputs/users.txt")


def _ws(tmp_path: Path) -> Workspace:
    ws = Workspace.for_engagement(tmp_path / "engagements", "e")
    ws.ensure()
    return ws


def test_confined_wordlist_is_allowed(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.inputs_dir / "pw.txt").write_text("hunter2\n", encoding="utf-8")
    verdict = check_command(
        parse_command("hydra -P inputs/pw.txt 10.0.0.5", REGISTRY),
        _engagement(),
        now=NOW,
        workspace=ws,
        cwd=ws.root,
    )
    assert verdict.allowed, verdict.reason


def test_wordlist_outside_the_workspace_is_denied(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    verdict = check_command(
        parse_command("hydra -P /etc/shadow 10.0.0.5", REGISTRY),
        _engagement(),
        now=NOW,
        workspace=ws,
        cwd=ws.root,
    )
    assert not verdict.allowed
    assert "escapes the workspace" in verdict.reason


def test_wordlist_traversal_is_denied(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    verdict = check_command(
        parse_command("hydra -P ../../../etc/passwd 10.0.0.5", REGISTRY),
        _engagement(),
        now=NOW,
        workspace=ws,
        cwd=ws.root,
    )
    assert not verdict.allowed


def test_wordlist_targeting_a_control_file_is_denied(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    verdict = check_command(
        parse_command("hydra -P .vault.db 10.0.0.5", REGISTRY),
        _engagement(),
        now=NOW,
        workspace=ws,
        cwd=ws.root,
    )
    assert not verdict.allowed
    assert "control file" in verdict.reason


def test_input_file_without_a_workspace_is_scope_only() -> None:
    # The pure-scope path (e.g. the compliance scorer) passes no workspace, so
    # data-file confinement is not evaluated and scope alone decides.
    verdict = check_command(
        parse_command("hydra -P inputs/pw.txt 10.0.0.5", REGISTRY),
        _engagement(),
        now=NOW,
    )
    assert verdict.allowed, verdict.reason


def test_a_configured_wordlist_root_is_allowed(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    roots = (tmp_path / "share" / "wordlists",)
    roots[0].mkdir(parents=True)
    (roots[0] / "rockyou.txt").write_text("hunter2\n", encoding="utf-8")
    verdict = check_command(
        parse_command("hydra -P share/wordlists/rockyou.txt 10.0.0.5", REGISTRY),
        _engagement(),
        now=NOW,
        workspace=ws,
        cwd=tmp_path,
        wordlist_roots=roots,
    )
    assert verdict.allowed, verdict.reason
