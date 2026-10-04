"""L1: the OSINT artifact store -- confinement + redaction + path shape."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skuggi.engagement.workspace import Workspace
from skuggi.osint.schema import OsintItem, OsintResult
from skuggi.osint.store import result_path, write_result


def _result(**kw: object) -> OsintResult:
    base: dict[str, object] = {
        "task_id": "t1",
        "source": "crtsh",
        "subject": "acme.com",
        "items": (OsintItem(kind="subdomain", value="mail.acme.com"),),
        "note": "two certs",
    }
    base.update(kw)
    return OsintResult(**base)  # type: ignore[arg-type]


def test_result_path_is_subject_keyed_under_osint(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "eng")
    assert result_path(ws, _result()) == ws.osint_dir / "acme.com" / "crtsh.json"


def test_result_path_slugs_a_spaced_subject(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "eng")
    path = result_path(ws, _result(subject="Acme Corp", source="github"))
    assert path == ws.osint_dir / "acme-corp" / "github.json"


def test_write_result_persists_valid_json(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "eng")
    path = write_result(ws, _result(), clean=lambda s: s)
    assert path.is_file()
    data = json.loads(path.read_text())
    assert data["subject"] == "acme.com"
    assert data["items"][0]["value"] == "mail.acme.com"


def test_write_result_redacts_before_writing(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "eng")
    secret = "AKIAIOSFODNN7EXAMPLE"
    result = _result(items=(OsintItem(kind="leak", value=f"key {secret}"),))

    def clean(text: str) -> str:
        return text.replace(secret, "<<REDACTED>>")

    path = write_result(ws, result, clean=clean)
    body = path.read_text()
    assert secret not in body
    assert "<<REDACTED>>" in body


def test_result_path_rejects_an_empty_subject(tmp_path: Path) -> None:
    ws = Workspace.at(tmp_path / "eng")
    with pytest.raises(ValueError, match="invalid engagement name"):
        result_path(ws, _result(subject="..."))
