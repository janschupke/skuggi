"""Small text-composition helpers for prompt and report assembly.

The graph builds prompts from labelled sections and reports build Markdown from
the same shape; these two helpers are the shared kernel so neither hand-rolls
the empty-body guard or the blank-line join.
"""

from __future__ import annotations


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
