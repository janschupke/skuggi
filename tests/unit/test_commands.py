"""L1: the command-alias registry model."""

from __future__ import annotations

from pathlib import Path

from skuggi.commands import CommandAlias, CommandRegistry, raw_command


def test_resolve_appends_extra_args() -> None:
    alias = CommandAlias(name="nmap-host", argv=("nmap", "-sV", "-sC"))
    assert alias.resolve(["10.0.0.5"]) == ["nmap", "-sV", "-sC", "10.0.0.5"]


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
    example = Path(__file__).parents[2] / "configs" / "commands.example.json"
    reg = CommandRegistry.model_validate_json(example.read_text(encoding="utf-8"))
    assert "nmap-network" in reg.names()
    host = reg.alias_for("nmap-host")
    assert host is not None
    assert host.argv == ("nmap", "-sV", "-sC")
