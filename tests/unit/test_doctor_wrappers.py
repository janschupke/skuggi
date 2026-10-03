"""L1: the doctor stale-wrapper scanner.

Pure, offline detection of installed ``skuggi*`` console scripts whose imported
module no longer resolves -- the operator-facing half of the fix for a wrapper
left behind by a module move.
"""

from __future__ import annotations

from pathlib import Path

from skuggi.tooling.doctor import stale_wrappers

_WRAPPER = "#!/usr/bin/env python\nimport sys\nfrom {module} import main\n"


def _write(bin_dir: Path, name: str, module: str) -> None:
    (bin_dir / name).write_text(_WRAPPER.format(module=module), encoding="utf-8")


def test_flags_only_wrappers_whose_module_vanished(tmp_path: Path) -> None:
    _write(tmp_path, "skuggi", "skuggi.frontend.shell")  # current -> resolves
    _write(tmp_path, "skuggi-doctor", "skuggi.tooling.doctor")  # current
    _write(tmp_path, "skuggi-old", "skuggi.shell")  # moved -> stale
    _write(tmp_path, "skuggi-gone", "skuggi.init")  # moved -> stale
    (tmp_path / "skuggi-note").write_text("no import here\n", encoding="utf-8")  # skip
    (tmp_path / "skuggi-sub").mkdir()  # a dir named skuggi* -> skip
    # a non-skuggi* file is never scanned:
    (tmp_path / "unrelated").write_text("from skuggi.shell import main\n")

    stale = stale_wrappers(tmp_path)

    assert stale == [("skuggi-gone", "skuggi.init"), ("skuggi-old", "skuggi.shell")]


def test_empty_when_no_wrappers(tmp_path: Path) -> None:
    assert stale_wrappers(tmp_path) == []
