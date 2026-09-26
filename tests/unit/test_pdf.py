"""L1: the Markdown -> HTML pipeline, the CLI, and the report PDF wiring.

The HTML stage and CLI are deterministic and need no native libraries; the real
WeasyPrint render is exercised separately in tests/integration/test_pdf_render.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from skuggi import pdf
from skuggi.ledger import Ledger, open_ledger
from skuggi.reports import write_report

_SAMPLE = """# Acme External Assessment

Intro with ~~struck~~ text and a footnote.[^1]

## Findings

### CRITICAL (1)

**[1] RCE**

Remote code execution.

### Overview

Some prose.

| # | when | command |
|---|---|---|
| 1 | now | `nmap` |

```python
def hi() -> int:
    return 1
```

[^1]: the footnote body.
"""


def test_markdown_to_html_renders_gfm_pygments_and_palette_tokens() -> None:
    html = pdf.markdown_to_html(_SAMPLE, title="Acme External Assessment")
    # Title + brand (the shield comes from palette, the single source of truth).
    assert "<title>Acme External Assessment</title>" in html
    assert "🐐 skuggi" in html
    # GFM table, strikethrough, footnote.
    assert "<table>" in html
    assert "<s>" in html
    assert "footnote" in html
    # Pygments highlighting for a fenced python block.
    assert '<pre class="highlight">' in html
    assert 'class="k"' in html
    # Palette tokens injected as CSS variables (drift-proof against palette.py).
    assert "--sev-critical: #" in html
    assert "--method-recon: #" in html
    # A severity findings heading is tinted; a normal heading is left alone.
    assert '<h3 class="sev-critical">CRITICAL (1)</h3>' in html
    assert "<h3>Overview</h3>" in html


def test_highlight_falls_back_for_unknown_and_plain_fences() -> None:
    unknown = pdf.markdown_to_html("```notalang\nx = 1\n```\n", title="t")
    assert '<pre class="highlight">' not in unknown
    plain = pdf.markdown_to_html("```\nplain scope\n```\n", title="t")
    assert '<pre class="highlight">' not in plain
    assert "plain scope" in plain


def test_tint_leaves_non_severity_headings_untouched() -> None:
    html = pdf.markdown_to_html("### Not A Severity\n", title="t")
    assert "<h3>Not A Severity</h3>" in html
    assert "sev-" not in html.split("<body>")[1]


def test_default_title_prefers_first_h1_else_fallback() -> None:
    assert pdf.default_title("intro\n# Real Title\n", "fb") == "Real Title"
    assert pdf.default_title("no heading at all", "fb") == "fb"


def test_render_pdf_without_weasyprint_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # Simulate the `pdf` group not being installed: the lazy import fails.
    monkeypatch.setitem(sys.modules, "weasyprint", None)
    with pytest.raises(RuntimeError, match=r"pdf.*dependency group"):
        pdf.render_pdf("<html></html>", Path("/does/not/matter.pdf"))


def _fake_render(html: str, out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"%PDF-fake")
    return out


def test_cli_writes_pdf_only_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(pdf, "render_pdf", _fake_render)
    src = tmp_path / "report.md"
    src.write_text(_SAMPLE, encoding="utf-8")

    assert pdf.main([str(src)]) == 0

    out = src.with_suffix(".pdf")
    assert out.read_bytes().startswith(b"%PDF")
    assert not src.with_suffix(".html").exists()
    assert "PDF written" in capsys.readouterr().out


def test_cli_honours_out_html_and_title(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(pdf, "render_pdf", _fake_render)
    src = tmp_path / "in.md"
    src.write_text("no heading here\n", encoding="utf-8")
    out = tmp_path / "custom.pdf"

    assert pdf.main([str(src), "-o", str(out), "--html", "--title", "Given"]) == 0

    assert out.read_bytes().startswith(b"%PDF")
    html_out = out.with_suffix(".html")
    assert "<title>Given</title>" in html_out.read_text(encoding="utf-8")
    printed = capsys.readouterr().out
    assert "HTML written" in printed
    assert "PDF written" in printed


def _seed(led: Ledger) -> None:
    led.start_session("s1", engagement_name="acme ext", mode="pentest")
    led.record_finding(
        session_id="s1",
        title="SSH exposed",
        severity="high",
        description="Port 22 open",
    )


def test_write_report_pdf_flag_returns_both_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_markdown_to_pdf(md_text: str, out: Path, *, title: str) -> Path:
        captured["title"] = title
        captured["has_finding"] = "SSH exposed" in md_text
        out.write_bytes(b"%PDF-fake")
        return out

    monkeypatch.setattr(pdf, "markdown_to_pdf", fake_markdown_to_pdf)
    reports = tmp_path / "reports"
    with open_ledger(tmp_path / "l.db") as led:
        _seed(led)
        result = write_report("s1", led, reports, engagement=None, pdf=True)

    assert isinstance(result, tuple)
    md_path, pdf_path = result
    assert md_path.suffix == ".md"
    assert pdf_path.suffix == ".pdf"
    assert md_path.with_suffix("") == pdf_path.with_suffix("")  # shared stamp/slug
    assert captured == {"title": "acme ext", "has_finding": True}
