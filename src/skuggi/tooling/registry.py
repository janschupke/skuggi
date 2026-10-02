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
from pathlib import Path
from typing import Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

# How a tool's output flag wants its path shaped: a basename *prefix* (nmap
# ``-oA scan`` writes ``scan.nmap``/``.gnmap``/``.xml``), a single *file*
# (``-o out.json``), or an output *directory* (``--output-dir dir``).
OutputKind = Literal["prefix", "file", "dir"]


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
    requires_target: bool = True
    install: dict[str, str] = Field(default_factory=dict)
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


class ToolStatus(NamedTuple):
    """The result of probing one tool on this host."""

    spec: ToolSpec
    found: bool
    path: Path | None
    version: str | None
    source: str  # "host" | "managed" | "missing" | "unavailable"


@dataclass(frozen=True, slots=True)
class InstallPlan:
    """A selected, not-yet-run install command."""

    argv: tuple[str, ...]
    target: str  # "host" | "managed"
    installer: str  # "brew" | "apt" | "pip"


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
