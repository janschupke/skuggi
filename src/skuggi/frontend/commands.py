"""The command-alias registry: named shorthands for real CLI invocations.

An alias maps a short name (``nmap-host``) to a base argv (``nmap -sV -sC``) and
the tool it drives. The ``cmd`` verb searches this cheatsheet by substring and,
on an exact name, *renders* the full invocation: the base argv plus a ``${target}``
placeholder and -- for tools with an output convention -- an output flag pointing
at a timestamped artefact inside the engagement's folder for that tool, e.g.
``nmap -sV -sC ${target} -oA recon/nmap/$(date +%Y-%m-%d_%H%M%S)_${target}_host``.
The **rendered raw command is always surfaced** to the operator (the transparency
invariant) and checked against the engagement scope like any agent-proposed
command -- ``cmd`` advises and records, it never executes silently.

``$(date ...)`` and ``${target}`` are kept *literal* so the operator's shell
expands them at run time (skuggi exports ``target`` into the wrapped shell); only
the folder and the ``<label>`` are resolved here. The output path must therefore
be appended **unquoted** -- ``shlex.join`` would quote the ``$`` and kill the
expansion (see ``render``).

Loaded from ``configs/commands.json`` (shipped as ``.example``); user-extendable
by editing that JSON *or* via the guided ``cmd add``/``cmd edit`` editor
(``skuggi.cmdflow``). The model mirrors ``registry.ToolRegistry`` deliberately.
"""

from __future__ import annotations

import shlex

from pydantic import BaseModel, ConfigDict, field_validator

from skuggi.common.text import safe_cmd_fragment
from skuggi.tooling.registry import ToolRegistry

# Literal shell expressions preserved in the rendered command (the operator's
# shell expands them at run time, not skuggi).
_STAMP = "$(date +%Y-%m-%d_%H%M%S)"
_TARGET = "${target}"


class CommandAlias(BaseModel):
    """One named command shorthand and the base argv it expands to."""

    model_config = ConfigDict(frozen=True)

    name: str
    argv: tuple[str, ...]
    description: str = ""
    # The binary this alias drives (for the tool's output convention). Defaults
    # to ``argv[0]`` when blank.
    tool: str = ""
    # The ``<label>`` component of the output filename. Defaults to the alias
    # name with its leading ``<tool>-`` segment stripped (``nmap-host`` -> ``host``).
    label: str = ""
    # Per-alias overrides of the tool's output convention (hybrid model). A None
    # falls back to the tool spec; ``output=False`` suppresses output injection
    # entirely (e.g. a header-only ``curl`` that just prints).
    output: bool = True
    output_flag: str | None = None
    output_dir: str | None = None
    output_extra: tuple[str, ...] = ()

    @field_validator("label")
    @classmethod
    def _safe_label(cls, value: str) -> str:
        # Rendered UNQUOTED into the command; a bare filename label only.
        return safe_cmd_fragment(value, field="label", strict=True) or ""

    @field_validator("output_flag", "output_dir")
    @classmethod
    def _safe_output_field(cls, value: str | None) -> str | None:
        return safe_cmd_fragment(value, field="output field")

    @field_validator("output_extra")
    @classmethod
    def _safe_output_extra(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            safe_cmd_fragment(item, field="output_extra")
        return value

    def resolve(self, extra: list[str]) -> list[str]:
        """The full argv: the base plus the operator's extra arguments."""
        return [*self.argv, *extra]

    def tool_name(self) -> str:
        """The binary this alias drives (explicit ``tool`` or ``argv[0]``)."""
        if self.tool:
            return self.tool
        return self.argv[0] if self.argv else ""

    def label_text(self) -> str:
        """The output-filename ``<label>`` (explicit, else name sans tool prefix)."""
        if self.label:
            return self.label
        _, sep, rest = self.name.partition("-")
        return rest if sep else self.name


class CommandRegistry(BaseModel):
    """The set of command aliases skuggi knows."""

    model_config = ConfigDict(frozen=True)

    commands: tuple[CommandAlias, ...] = ()

    def alias_for(self, name: str) -> CommandAlias | None:
        """The alias registered under `name` (exact match), or None."""
        for alias in self.commands:
            if alias.name == name:
                return alias
        return None

    def names(self) -> tuple[str, ...]:
        """Every registered alias name, in registry order."""
        return tuple(a.name for a in self.commands)

    def search(self, query: str) -> tuple[CommandAlias, ...]:
        """Aliases whose name / tool / description contains `query` (case-insensitive).

        A blank query matches everything (the full cheatsheet). Registry order is
        preserved so the listing is stable.
        """
        q = query.strip().lower()
        if not q:
            return self.commands
        return tuple(
            a
            for a in self.commands
            if q in a.name.lower()
            or q in a.tool_name().lower()
            or q in a.description.lower()
        )


def raw_command(argv: list[str]) -> str:
    """The shell-quoted raw command string for `argv` (what the operator sees)."""
    return shlex.join(argv)


def _output_path(output_dir: str, label: str, kind: str, ext: str | None) -> str:
    """The literal, unquoted output path ``<dir>/<stamp>_${target}_<label>``.

    ``kind`` ``file`` appends ``ext`` (e.g. ``.json``); ``prefix`` (nmap ``-oA``)
    and ``dir`` leave the stem bare.
    """
    stem = f"{output_dir}/{_STAMP}_{_TARGET}_{label}"
    if kind == "file" and ext:
        return stem + ext
    return stem


def render(alias: CommandAlias, registry: ToolRegistry) -> str:
    """The full surfaced command for `alias`: base argv + target + output flag.

    Quoting-safe: the fixed argv (and any output *extra* flags) are
    ``shlex.join``-ed, but ``${target}`` and the output path are appended raw so
    the ``$(date ...)``/``${target}`` expressions survive for the operator's shell.
    """
    spec = registry.spec_for(alias.tool_name())
    parts = [raw_command(list(alias.argv))]

    requires_target = spec.requires_target if spec is not None else True
    if requires_target:
        parts.append(_TARGET)

    if alias.output:
        flag = (
            alias.output_flag
            if alias.output_flag is not None
            else (spec.output_flag if spec is not None else None)
        )
        odir = (
            alias.output_dir
            if alias.output_dir is not None
            else (spec.output_dir if spec is not None else None)
        )
        if flag and odir:
            extra = alias.output_extra or (
                spec.output_extra if spec is not None else ()
            )
            kind = spec.output_kind if spec is not None else "prefix"
            ext = spec.output_ext if spec is not None else None
            if extra:
                parts.append(raw_command(list(extra)))
            parts.append(flag)
            parts.append(_output_path(odir, alias.label_text(), kind, ext))

    return " ".join(parts)
