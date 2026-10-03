"""L1: safe text extraction from binary documents, and its guardrails.

The security claims these pin: supported documents yield their text; a macro
container (by suffix or a vbaProject.bin member) is refused; a zip bomb and an
oversized file are refused; an encrypted PDF is refused; and nothing is ever
executed (the parsers are pure-Python, asserted structurally by the fact that no
subprocess is spawned -- the no_subprocess autouse fixture would catch one).
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from skuggi.persistence import documents
from skuggi.persistence.documents import DocumentError, extract_text, is_supported


def _write_minimal_pdf(path: Path, text: str) -> None:
    """A hand-built one-page PDF with extractable text (no writer dependency)."""
    stream = f"BT /F1 24 Tf 20 100 Td ({text}) Tj ET".encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"
        ),
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n0 %d\n" % (len(objs) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF" % (
        len(objs) + 1,
        xref_pos,
    )
    path.write_bytes(bytes(out))


def test_pdf_text_is_extracted(tmp_path: Path) -> None:
    pytest.importorskip("pypdf")
    pdf = tmp_path / "report.pdf"
    _write_minimal_pdf(pdf, "Secret123Found")
    assert "Secret123Found" in extract_text(pdf)


def test_docx_text_and_tables_are_extracted(tmp_path: Path) -> None:
    docx = pytest.importorskip("docx")

    path = tmp_path / "notes.docx"
    doc = docx.Document()
    doc.add_paragraph("intro paragraph")
    table = doc.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text = "user"
    table.rows[0].cells[1].text = "admin"
    doc.save(str(path))

    text = extract_text(path)
    assert "intro paragraph" in text
    assert "user" in text
    assert "admin" in text


def test_xlsx_cells_are_extracted(tmp_path: Path) -> None:
    openpyxl = pytest.importorskip("openpyxl")

    path = tmp_path / "book.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = "host"
    ws["B1"] = "10.0.0.5"
    wb.save(str(path))

    text = extract_text(path)
    assert "host" in text
    assert "10.0.0.5" in text


def test_macro_suffix_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "evil.xlsm"
    path.write_bytes(b"PK\x03\x04anything")
    with pytest.raises(DocumentError, match="macro-enabled"):
        extract_text(path)


def test_vba_project_member_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "evil.xlsx"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("xl/workbook.xml", "<xml/>")
        zf.writestr("xl/vbaProject.bin", b"\x00fakevba")
    with pytest.raises(DocumentError, match="macro-bearing"):
        extract_text(path)


def test_zip_bomb_ratio_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "bomb.xlsx"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big", b"\x00" * (2 * 1024 * 1024))  # compresses to ~nothing
    with pytest.raises(DocumentError, match="compression ratio"):
        extract_text(path)


def test_oversized_document_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(documents, "MAX_DOCUMENT_BYTES", 8)
    path = tmp_path / "big.pdf"
    path.write_bytes(b"%PDF-1.4 and then some more bytes")
    with pytest.raises(DocumentError, match="too large"):
        extract_text(path)


def test_encrypted_pdf_is_refused(tmp_path: Path) -> None:
    pypdf = pytest.importorskip("pypdf")

    path = tmp_path / "locked.pdf"
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.encrypt("a-real-password")
    with path.open("wb") as handle:
        writer.write(handle)
    with pytest.raises(DocumentError, match="encrypted"):
        extract_text(path)


def test_corrupt_document_raises_not_crashes(tmp_path: Path) -> None:
    path = tmp_path / "broken.docx"
    path.write_bytes(b"not a real zip at all")
    with pytest.raises(DocumentError):
        extract_text(path)


def test_unsupported_type_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "image.png"
    path.write_bytes(b"\x89PNG")
    assert not is_supported(path)
    with pytest.raises(DocumentError, match="unsupported"):
        extract_text(path)
