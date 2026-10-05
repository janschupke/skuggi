"""L1: the verb registry's per-surface command-hint formatter."""

from __future__ import annotations

from skuggi.common.modes import Mode
from skuggi.frontend import verbs


def test_cmd_formats_per_surface() -> None:
    assert verbs.cmd("setup", "shell") == "/skuggi setup"
    assert verbs.cmd("setup", "repl") == "/setup"
    assert verbs.cmd("setup", "chat") == "setup"


def test_cmd_keeps_multiword_invocations() -> None:
    assert verbs.cmd("engagement setup", "shell") == "/skuggi engagement setup"
    assert verbs.cmd("engagement setup", "repl") == "/engagement setup"
    assert verbs.cmd("engagement setup", "chat") == "engagement setup"


def test_cmd_defaults_to_shell() -> None:
    assert verbs.cmd("setup") == "/skuggi setup"


# --- registry shape ---------------------------------------------------------


def test_grouping_verbs_carry_nouns() -> None:
    assert verbs.noun_names("show") >= {"config", "status", "tools", "db", "grants"}
    assert verbs.noun_names("set") == {
        "engagement",
        "case",
        "provider",
        "model",
        "mode",
        "autonomous",
        "config",
        "scope",
        "target",
        "listener",
        "wordlist",
        "thread",
    }
    assert verbs.noun_names("add") == {"note", "loot", "cred", "finding", "memory"}
    assert verbs.noun_names("remove") == {"memory", "grants"}


def test_plain_verb_has_no_nouns() -> None:
    assert verbs.nouns_of("report") == ()
    assert verbs.noun_names("report") == frozenset()


def test_only_agent_path_verbs_are_engagement() -> None:
    # Engagement-directed verbs are exempt from the control audit log.
    assert {"ask", "cmd", "add", "osint", "forensics"} == verbs.ENGAGEMENT


# --- help listing -----------------------------------------------------------


def test_help_sections_are_grouped_and_cover_every_verb() -> None:
    sections = verbs.help_sections()
    titles = [title for title, _ in sections]
    assert any("Commands" in t for t in titles)
    listed = {inv.split()[0] for _, rows in sections for inv, _ in rows}
    assert listed == verbs.KNOWN  # every verb appears exactly once, grouped


def test_help_for_grouping_verb_lists_its_nouns() -> None:
    rows = verbs.help_for("show")
    assert rows is not None
    invocations = {inv.split()[1] for inv, _ in rows}
    assert invocations == verbs.noun_names("show")


def test_help_for_plain_verb_is_a_single_row() -> None:
    rows = verbs.help_for("report")
    assert rows is not None
    assert len(rows) == 1
    assert rows[0][0].startswith("report")


def test_help_for_unknown_verb_is_none() -> None:
    assert verbs.help_for("nope") is None


# --- mode gating ------------------------------------------------------------


def test_offensive_verbs_are_unavailable_in_forensics() -> None:
    for verb in ("cmd", "osint"):
        assert verbs.is_available(verb, "pentest")
        assert verbs.is_available(verb, "redteam")
        assert not verbs.is_available(verb, "forensics")


def test_unrestricted_verbs_are_available_in_every_mode() -> None:
    modes: tuple[Mode, ...] = ("pentest", "redteam", "blueteam", "forensics")
    for verb in ("ask", "show", "set", "help", "report"):
        for mode in modes:
            assert verbs.is_available(verb, mode)


def test_help_sections_hide_mode_locked_verbs() -> None:
    forensic = {
        inv.split()[0]
        for _, rows in verbs.help_sections("forensics")
        for inv, _ in rows
    }
    assert "cmd" not in forensic
    assert "osint" not in forensic
    # the unfiltered listing still carries everything (the drift invariant)
    allv = {inv.split()[0] for _, rows in verbs.help_sections() for inv, _ in rows}
    assert "cmd" in allv
    assert "osint" in allv
