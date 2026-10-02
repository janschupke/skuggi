"""L2: the real WeasyPrint render.

Skipped when WeasyPrint's native stack (Pango) is unavailable, so the suite
still passes on a machine without it; CI installs Pango so this always runs there.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.persistence import pdf


def _weasyprint_available() -> bool:
    try:
        import weasyprint  # noqa: F401, PLC0415
    except (ImportError, OSError):  # OSError: the native Pango libs are missing
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _weasyprint_available(),
    reason="WeasyPrint / Pango not installed",
)

_MD = """# Engagement report: acme

- Generated: now

## Findings

### CRITICAL (1)

**[1] RCE** — remote code execution.

## Command log

| # | status | command |
|---|---|---|
| 1 | executed | `nmap 10.0.0.5` |

```python
def scan() -> None:
    pass
```

A footnote reference.[^1]

[^1]: footnote body
"""


def test_markdown_to_pdf_writes_a_real_pdf(tmp_path: Path) -> None:
    out = pdf.markdown_to_pdf(_MD, tmp_path / "nested" / "report.pdf", title="acme")
    assert out.exists()
    data = out.read_bytes()
    assert data.startswith(b"%PDF-")
    assert len(data) > 1000  # a painted A4 page, not an empty stub
