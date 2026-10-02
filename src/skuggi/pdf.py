"""Render Markdown reports to styled PDF (and standalone HTML).

The pipeline is ``Markdown -> HTML -> PDF``: markdown-it-py parses the report
(GFM tables, footnotes, fenced code highlighted by Pygments), a Jinja2 shell
wraps it with the packaged print stylesheet, and WeasyPrint paints the PDF. CSS
is the whole theming surface, so a report's look is customized by editing
``templates/report.css`` -- no code change -- and the intermediate HTML is a
valid document in its own right (``--html``).

WeasyPrint carries a native dependency (Pango); it is imported lazily so the
core agent installs and runs without the ``pdf`` dependency group.
"""

from __future__ import annotations

import argparse
import re
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path

from jinja2 import Environment, select_autoescape
from markdown_it import MarkdownIt
from markupsafe import Markup
from mdit_py_plugins.footnote import footnote_plugin
from pygments import highlight as _pygments_highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name
from pygments.util import ClassNotFound

from skuggi import palette
from skuggi.logs import get_logger, setup_logging
from skuggi.paths import ensure_parent

log = get_logger(__name__)

_TEMPLATE_NAME = "report.html.j2"
_STYLESHEET_NAME = "report.css"
# A light Pygments theme; the code background/border come from report.css, this
# only colours the tokens, and reads well on white paper.
_PYGMENTS_STYLE = "default"

_SEVERITY_WORDS = frozenset(s.lower() for s in palette.severities())


def _asset_text(name: str) -> str:
    """Read a packaged template/stylesheet asset (works from an installed wheel)."""
    return (resources.files("skuggi") / "templates" / name).read_text(encoding="utf-8")


def _pygments_css() -> str:
    """The Pygments token stylesheet, scoped to ``.highlight`` code blocks."""
    return str(HtmlFormatter(style=_PYGMENTS_STYLE).get_style_defs(".highlight"))


def _highlight(code: str, lang: str, _attrs: str) -> str:
    """markdown-it highlight hook: Pygments HTML for a known language, else plain.

    Returning ``""`` lets markdown-it fall back to its own escaped ``<pre><code>``
    (used for fences with no language, e.g. the scope and evidence blocks).
    """
    if not lang:
        return ""
    try:
        lexer = get_lexer_by_name(lang)
    except ClassNotFound:
        log.debug("no pygments lexer for %r; emitting code unhighlighted", lang)
        return ""
    inner = _pygments_highlight(code, lexer, HtmlFormatter(nowrap=True))
    # Leading "<pre" tells markdown-it to use this verbatim instead of re-wrapping.
    return f'<pre class="highlight"><code>{inner}</code></pre>'


def _make_parser() -> MarkdownIt:
    """A CommonMark parser with GFM tables, strikethrough, footnotes and highlight."""
    return (
        MarkdownIt("commonmark", {"highlight": _highlight})
        .enable("table")
        .enable("strikethrough")
        .use(footnote_plugin)
    )


def _tint_severity_headings(html: str) -> str:
    """Tag findings headings (``<h3>CRITICAL ...``) with a ``sev-<level>`` class.

    The report groups findings under a severity heading; tinting it by level is
    pure CSS (the ``--sev-*`` tokens), so this only adds the hook class.
    """

    def repl(match: re.Match[str]) -> str:
        word = match["word"].lower()
        if word not in _SEVERITY_WORDS:
            return match[0]
        return f'<h3 class="sev-{word}">{match["body"]}</h3>'

    return re.sub(r"<h3>(?P<body>(?P<word>[A-Za-z]+)[^<]*)</h3>", repl, html)


def markdown_to_html(md_text: str, *, title: str) -> str:
    """Render Markdown to a standalone, print-styled HTML document."""
    # autoescape keeps the (user-derived) title safe; the CSS assets and the
    # rendered body are our own trusted HTML. The parser runs with html=False
    # (the commonmark default), so raw HTML in the Markdown source is escaped,
    # not passed through -- so wrapping the body in Markup cannot inject markup.
    body = _tint_severity_headings(_make_parser().render(md_text))
    env = Environment(autoescape=select_autoescape(default=True))
    template = env.from_string(_asset_text(_TEMPLATE_NAME))
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return template.render(
        title=title,
        brand=f"{palette.SHIELD} skuggi",
        generated_label=f"Generated {generated}",
        base_css=Markup(_asset_text(_STYLESHEET_NAME)),  # noqa: S704
        pygments_css=Markup(_pygments_css()),  # noqa: S704
        severity_tokens={s: palette.severity_hex(s) for s in palette.severities()},
        method_tokens={m: palette.method_hex(m) for m in palette.methods()},
        body=Markup(body),  # noqa: S704
    )


def render_pdf(html: str, out: Path) -> Path:
    """Paint a standalone HTML document to ``out`` with WeasyPrint."""
    try:
        from weasyprint import HTML
    except ImportError as exc:
        msg = (
            "PDF rendering needs the 'pdf' dependency group: run "
            "`uv sync --group pdf` (or `make install`). WeasyPrint also needs a "
            "system Pango library (`brew install pango` on macOS)."
        )
        raise RuntimeError(msg) from exc
    out = ensure_parent(out)
    HTML(string=html).write_pdf(str(out))
    return out


def markdown_to_pdf(md_text: str, out: Path, *, title: str) -> Path:
    """Render Markdown straight to a styled PDF at ``out``."""
    return render_pdf(markdown_to_html(md_text, title=title), out)


def default_title(md_text: str, fallback: str) -> str:
    """The report title: the first level-1 heading, or ``fallback``."""
    for line in md_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return fallback


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skuggi-pdf",
        description="Render a Markdown file to a styled PDF (and optionally HTML).",
    )
    parser.add_argument("input", type=Path, help="the Markdown file to render")
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        help="output PDF path (default: the input with a .pdf suffix)",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="also write the intermediate standalone HTML next to the PDF",
    )
    parser.add_argument(
        "--title",
        help="document title (default: the first H1, else the file name)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``skuggi-pdf``."""
    setup_logging()
    log.info("skuggi-pdf starting")
    args = _build_arg_parser().parse_args(argv)
    input_path: Path = args.input
    md_text = input_path.read_text(encoding="utf-8")
    title = args.title or default_title(md_text, input_path.stem)
    html = markdown_to_html(md_text, title=title)

    if args.html:
        html_out = (args.out or input_path).with_suffix(".html")
        html_out.write_text(html, encoding="utf-8")
        print(f"HTML written: {html_out}")

    pdf_out: Path = args.out or input_path.with_suffix(".pdf")
    render_pdf(html, pdf_out)
    print(f"PDF written: {pdf_out}")
    return 0
