"""L1: the metadata-only data-file inventory the agent references by path.

The point of these is the data-plane guarantee: a description carries a name,
size, line count and hash -- never a byte of content -- so a listing rendered
into a prompt cannot leak what a wordlist or an evidence file contains.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from skuggi.engagement.datafiles import (
    describe_file,
    list_datafiles,
    render_datafiles,
)


def test_describe_file_reports_metadata_not_contents(tmp_path: Path) -> None:
    f = tmp_path / "inputs" / "rockyou.txt"
    f.parent.mkdir()
    body = "alice\nbob\ncarol\n"
    f.write_text(body, encoding="utf-8")

    desc = describe_file(f, tmp_path, kind="input")

    assert desc.path == "inputs/rockyou.txt"
    assert desc.kind == "input"
    assert desc.size_bytes == len(body.encode())
    assert desc.line_count == 3
    assert desc.sha256 == hashlib.sha256(body.encode()).hexdigest()


def test_binary_file_has_no_line_count(tmp_path: Path) -> None:
    f = tmp_path / "evidence" / "dump.bin"
    f.parent.mkdir()
    f.write_bytes(b"PK\x03\x04\x00\x00binary\x00data")

    desc = describe_file(f, tmp_path, kind="evidence")

    assert desc.line_count is None
    assert desc.size_bytes > 0


def test_list_datafiles_walks_each_dir_with_its_kind(tmp_path: Path) -> None:
    (tmp_path / "inputs").mkdir()
    (tmp_path / "evidence").mkdir()
    (tmp_path / "inputs" / "u.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "evidence" / "e.txt").write_text("b\n", encoding="utf-8")

    files = list_datafiles(
        [(tmp_path / "inputs", "input"), (tmp_path / "evidence", "evidence")],
        tmp_path,
    )

    kinds = {f.path: f.kind for f in files}
    assert kinds == {"inputs/u.txt": "input", "evidence/e.txt": "evidence"}


def test_list_datafiles_skips_a_missing_dir(tmp_path: Path) -> None:
    assert list_datafiles([(tmp_path / "nope", "input")], tmp_path) == ()


def test_render_is_one_line_per_file_and_hides_contents(tmp_path: Path) -> None:
    f = tmp_path / "inputs" / "w.txt"
    f.parent.mkdir()
    f.write_text("secretpassword\n", encoding="utf-8")
    rendered = render_datafiles(
        list_datafiles([(tmp_path / "inputs", "input")], tmp_path)
    )
    assert "inputs/w.txt" in rendered
    assert "1 lines" in rendered
    assert "secretpassword" not in rendered


def test_render_marks_binary(tmp_path: Path) -> None:
    f = tmp_path / "evidence" / "b.bin"
    f.parent.mkdir()
    f.write_bytes(b"\x00\x01\x02")
    rendered = render_datafiles(
        list_datafiles([(tmp_path / "evidence", "evidence")], tmp_path)
    )
    assert "binary" in rendered
