"""The recognized-tool registry and the host-probe data model.

The registry (loaded from ``configs/tools.json``) is skuggi's model of the tools
it knows: for each one, the binary name, the engagement *method* it belongs to
(recon / scan / ...), how to read its version, which argv positions carry targets
(this feeds ``engagement.parse_command`` so target extraction is declarative, not
guesswork), and per-installer install commands.

This module is pure data: the model types and the registry container, with no
host I/O. Resolving these specs against the host lives in ``skuggi.probe``, and
rendering them lives in ``skuggi.doctor`` -- so the model can be imported (by
``configs``, ``engagement``, ``graph``) without dragging in subprocess or
Rich machinery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Annotated, Literal, NamedTuple

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    field_validator,
)

from skuggi.common.modes import Mode
from skuggi.common.text import safe_cmd_fragment

# How a tool's output flag wants its path shaped: a basename *prefix* (nmap
# ``-oA scan`` writes ``scan.nmap``/``.gnmap``/``.xml``), a single *file*
# (``-o out.json``), or an output *directory* (``--output-dir dir``).
OutputKind = Literal["prefix", "file", "dir"]


class RiskTier(IntEnum):
    """How risky an allowed command is, ordered low -> high.

    Owned here because a tool's base risk is a registry fact (``ToolSpec.risk``);
    the scoring that raises it per invocation lives in ``engagement.risk``, and
    the autonomous ceiling that gates it lives on ``EngagementConfig``. Ordered so
    ``tier > ceiling`` is a plain comparison.
    """

    recon = 0  # passive information gathering
    active = 1  # touches the target but non-invasively (port/dir scans)
    intrusive = 2  # brute-force / credential cracking
    destructive = 3  # exploitation, privilege escalation, data extraction


_TIER_NAMES = ", ".join(t.name for t in RiskTier)


def _coerce_tier(value: object) -> RiskTier:
    """Read a RiskTier from itself, its name (``"active"``) or its rank (``1``).

    scope.json and tools.json are hand-editable, so the readable name is the
    canonical form; an int rank is accepted as a convenience.
    """
    if isinstance(value, RiskTier):
        return value
    if isinstance(value, str):
        try:
            return RiskTier[value]
        except KeyError:
            msg = f"unknown risk tier {value!r} (expected one of {_TIER_NAMES})"
            raise ValueError(msg) from None
    if isinstance(value, int):
        return RiskTier(value)  # raises ValueError if out of range
    msg = f"cannot read a risk tier from {value!r}"
    raise ValueError(msg)


# A RiskTier field that validates from / serializes to its readable name, so
# tools.json / scope.json carry ``"destructive"`` rather than ``3``.
RiskTierField = Annotated[
    RiskTier,
    BeforeValidator(_coerce_tier),
    PlainSerializer(lambda t: t.name, return_type=str),
]


class ToolSpec(BaseModel):
    """One recognized tool and everything skuggi needs to reason about it."""

    model_config = ConfigDict(frozen=True)

    name: str
    binary: str
    method: str
    version_args: tuple[str, ...] = ()
    version_regex: str | None = None
    # Argv flags whose following value is a target (e.g. curl's implicit
    # positional URL is covered by requires_target + the positional scan).
    target_flags: tuple[str, ...] = ()
    # Argv flags whose value is a *file* of targets (nmap ``-iL``, masscan
    # ``-iL``, hydra ``-M``). The file's contents cannot be scope-checked
    # statically, so the guard denies any command carrying one -- the operator
    # must enumerate hosts explicitly. See ``engagement.check_command``.
    target_file_flags: tuple[str, ...] = ()
    # Argv flags whose value is a *data* file the tool reads -- a wordlist, user
    # or credential list (hydra ``-L``/``-P``, ffuf/gobuster ``-w``, ...). The
    # guard requires each such path to be confined to the engagement workspace
    # (inputs/evidence/loot), so a wordlist reaches the tool by path while its
    # contents never enter the model's context. See ``engagement.check_command``.
    input_file_flags: tuple[str, ...] = ()
    # A read-only forensic tool that takes the artifact under examination as a bare
    # *positional* argument (``strings sample.bin``, ``file sample.bin``). The guard
    # confines every positional path that resolves to an existing file to the case
    # evidence dir -- so the tool can only ever READ evidence, never ``/etc/shadow``
    # or a sibling outside the case. See ``engagement.check_command``.
    positional_file: bool = False
    requires_target: bool = True
    install: dict[str, str] = Field(default_factory=dict)
    # Optional explicit risk tier. Unset -> derived from ``method`` by
    # ``engagement.risk``; set -> overrides it (e.g. mark msfvenom/sqlmap
    # ``destructive`` regardless of their method bucket).
    risk: RiskTierField | None = None
    # Which operating modes expose this tool. Empty = the offensive default
    # (available in every mode except blueteam); a tool tagged with explicit
    # modes (e.g. the defensive set with ``["blueteam"]``) is offered only in
    # those. ``blueteam`` sees ONLY tools that name it, so a defensive session
    # never fronts the offensive registry (audit E12).
    modes: tuple[Mode, ...] = ()
    # Output convention (optional). When ``output_flag`` is set, the cheatsheet
    # renderer injects ``<output_flag> <workspace-dir>/<stamp>_${target}_<label>``
    # so every invocation of this tool lands a timestamped artefact in the right
    # engagement folder. ``output_dir`` is a workspace-relative folder that the
    # ``WorkspaceLayout`` must create; ``output_extra`` are flags that always
    # accompany output (e.g. ffuf's ``-of json``); ``output_kind``/``output_ext``
    # shape the path. Interactive/GUI tools leave ``output_flag`` unset.
    output_flag: str | None = None
    output_dir: str | None = None
    output_extra: tuple[str, ...] = ()
    output_kind: OutputKind = "prefix"
    output_ext: str | None = None

    @field_validator("output_flag", "output_dir")
    @classmethod
    def _safe_output_field(cls, value: str | None) -> str | None:
        # Rendered UNQUOTED into the cheatsheet command (see commands.render).
        return safe_cmd_fragment(value, field="output field")

    @field_validator("output_extra")
    @classmethod
    def _safe_output_extra(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            safe_cmd_fragment(item, field="output_extra")
        return value


class ToolRegistry(BaseModel):
    """The set of tools skuggi recognizes."""

    model_config = ConfigDict(frozen=True)

    tools: tuple[ToolSpec, ...] = ()

    def spec_for(self, binary: str) -> ToolSpec | None:
        """The spec whose binary matches `binary` (basename), or None."""
        for spec in self.tools:
            if spec.binary == binary:
                return spec
        return None

    def method_for(self, binary: str) -> str | None:
        """The engagement method `binary` belongs to, or None if unrecognized."""
        spec = self.spec_for(binary)
        return spec.method if spec else None

    def for_mode(self, mode: Mode) -> ToolRegistry:
        """The subset of tools this ``mode`` exposes (audit E12).

        ``blueteam`` is defensive: it sees only tools that explicitly name it, so an
        offensive binary (``nmap``/``sqlmap``) is not even in its guard's registry.
        Every other mode keeps the historical behavior -- a tool with no declared
        modes is universal, and a mode-tagged tool appears only where it is named --
        so pentest/redteam/forensics are unchanged.
        """
        if mode == "blueteam":
            kept = tuple(t for t in self.tools if mode in t.modes)
        else:
            kept = tuple(t for t in self.tools if not t.modes or mode in t.modes)
        return ToolRegistry(tools=kept)


class ToolStatus(NamedTuple):
    """The result of probing one tool on this host."""

    spec: ToolSpec
    found: bool
    path: Path | None
    version: str | None
    source: str  # "host" | "managed" | "missing" | "unavailable"


@dataclass(frozen=True, slots=True)
class InstallPlan:
    """A selected, not-yet-run install command.

    `rationale`/`source` are set only for a *researched* plan (an unregistered tool
    resolved by searching the host's package managers): they carry why this command
    was chosen and where the name came from, so the operator sees it before the
    approve gate. They stay ``None`` for a plan taken straight from the registry.
    """

    argv: tuple[str, ...]
    target: str  # "host" | "managed"
    installer: str  # "brew" | "apt" | "pip"
    rationale: str | None = None
    source: str | None = None

    @property
    def is_cask(self) -> bool:
        """Whether this installs a Homebrew *cask* (a GUI app, not a PATH binary).

        A cask (``brew install --cask burp-suite``) drops an ``.app`` bundle, so the
        installed tool never appears on ``PATH`` -- the post-install binary probe
        cannot see it, and a clean exit is the only success signal. Callers use this
        to avoid reporting a succeeded cask install as a failure. Detected from the
        argv so it holds for a registry plan (``installer="brew"``) and a researched
        one (``installer="brew-cask"``) alike.
        """
        return "--cask" in self.argv


class ResearchResult(NamedTuple):
    """What install research produced for a tool: grounded plans and/or advice.

    ``plans`` are validated, ready-to-preview install commands (empty if nothing in
    the host's package managers matched); ``advice`` is a one-line fallback for when
    there is no installable candidate (e.g. a manual download step).
    """

    plans: tuple[InstallPlan, ...] = ()
    advice: str = ""


class InstallOutcome(NamedTuple):
    """The result of running a researched (ad-hoc) install plan for a binary.

    Unlike :class:`ToolStatus`, there is no registry ``ToolSpec`` behind it: the
    tool was resolved by searching, not from the registry, so this carries just the
    requested binary and whether it is now installed.
    """

    binary: str
    installed: bool
    path: Path | None
    source: str  # "host" | "cask" | "managed" | "failed"


class PackageHit(NamedTuple):
    """One candidate package found by searching a host package manager.

    The deterministic grounding for install research: an installer the host has,
    the exact package token it returned, and its one-line description. A researched
    install command is only ever built from a token that appears here, so the model
    can never invent a package name a real search never produced.
    """

    installer: str  # "brew" | "brew-cask" | "apt"
    name: str
    summary: str = ""


@dataclass(frozen=True, slots=True)
class RuntimeSpec:
    """A standard host capability skuggi checks for (a runtime or a net tool).

    Not a scoped engagement tool: it has no method/target, only how to find and
    version it plus install hints. Reused for both the runtime/toolchain probe
    and the standard Unix net-tool probe.
    """

    name: str
    binary: str
    version_args: tuple[str, ...] = ()
    version_regex: str | None = None
    # Host-verified install hints, keyed like ToolSpec.install (brew/apt/pip);
    # shown in the doctor for a missing capability, filtered to present installers.
    install: dict[str, str] = field(default_factory=dict)


class RuntimeStatus(NamedTuple):
    """The result of probing one host capability (runtime or net tool)."""

    spec: RuntimeSpec
    found: bool
    path: Path | None
    version: str | None
