"""L1: config reconcile -- detect drift vs the packaged templates, diff, overwrite.

The seed step (`skuggi-init`) never overwrites, so an existing config silently
falls behind a newer packaged template. These prove the three properties that
make catching that up safe: drift is detected by *content* (a reformat is not
drift), the diff shows what an overwrite would add, and an overwrite always
leaves the previous contents recoverable in a backup.
"""

from __future__ import annotations

import json
from pathlib import Path

from skuggi.common.paths import packaged_template
from skuggi.frontend import dispatch, presenters
from skuggi.install import configdiff, reconcile
from skuggi.install.init import SEEDED

_TOOLS = "tools.json"
_TOOLS_TEMPLATE = "tools.example.json"


def _packaged_tools() -> bytes:
    return packaged_template(_TOOLS_TEMPLATE).read_bytes()


def _write(config_dir: Path, name: str, raw: bytes) -> Path:
    config_dir.mkdir(parents=True, exist_ok=True)
    dest = config_dir / name
    dest.write_bytes(raw)
    return dest


def test_status_classifies_up_to_date_drifted_and_missing(tmp_path: Path) -> None:
    _write(tmp_path, _TOOLS, _packaged_tools())  # verbatim copy -> up to date
    _write(tmp_path, "config.json", b'{"provider": "surprise"}')  # -> drifted
    # commands.json / layout.json left absent -> missing
    states = {s.name: s.state for s in reconcile.status(tmp_path)}
    assert states[_TOOLS] == "up_to_date"
    assert states["config.json"] == "drifted"
    assert states["commands.json"] == "missing"
    assert states["layout.json"] == "missing"


def test_reformat_is_not_drift(tmp_path: Path) -> None:
    # Same data, reserialised with different key order and indentation.
    data = json.loads(_packaged_tools())
    reflowed = json.dumps(data, sort_keys=False, indent=4).encode() + b"\n"
    _write(tmp_path, _TOOLS, reflowed)
    assert reconcile.drifted(tmp_path) == ()
    assert reconcile.structured_diff(tmp_path, _TOOLS).empty


def test_drift_detected_when_a_field_is_missing(tmp_path: Path) -> None:
    data = json.loads(_packaged_tools())
    data["tools"][0].pop("output_flag")  # an old install lacking the convention
    _write(tmp_path, _TOOLS, json.dumps(data).encode())
    assert _TOOLS in reconcile.drifted(tmp_path)
    diff = reconcile.structured_diff(tmp_path, _TOOLS)
    # The missing field reads as a per-entry change: absent (—) -> the template's.
    change = next(c for c in diff.changed if c.path == "nmap.output_flag")
    assert change.old == "\N{EM DASH}"
    assert "-oA" in change.new


def test_overwrite_backs_up_then_replaces(tmp_path: Path) -> None:
    old = b'{"tools": []}\n'
    dest = _write(tmp_path, _TOOLS, old)
    backup = reconcile.overwrite(tmp_path, _TOOLS)
    assert backup is not None
    assert backup.parent == tmp_path / reconcile.BACKUP_DIRNAME
    assert backup.read_bytes() == old  # the previous contents survive
    assert dest.read_bytes() == _packaged_tools()  # now matches the template
    assert reconcile.drifted(tmp_path) == ()


def test_overwrite_missing_file_seeds_without_a_backup(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    backup = reconcile.overwrite(tmp_path, _TOOLS)
    assert backup is None
    assert (tmp_path / _TOOLS).read_bytes() == _packaged_tools()


def test_known_names_match_the_seed_map() -> None:
    assert reconcile.is_known(_TOOLS)
    assert not reconcile.is_known("scope.json")  # per-engagement, not harness config
    assert set(reconcile.known_names()) == {installed for _, installed in SEEDED}


# ----- the shared run/present path (both front-ends go through this) --------
class _StubCore:
    def __init__(self, config_dir: Path) -> None:
        self._dir = config_dir

    def reconcile_status(self) -> tuple[reconcile.FileStatus, ...]:
        return reconcile.status(self._dir)

    def reconcile_structured_diff(self, name: str) -> configdiff.StructuredDiff:
        return reconcile.structured_diff(self._dir, name)

    def reconcile_overwrite(self, name: str) -> Path | None:
        return reconcile.overwrite(self._dir, name)

    def reconcile_overwrite_all(self) -> tuple[tuple[str, Path | None], ...]:
        return tuple(
            (name, reconcile.overwrite(self._dir, name))
            for name in reconcile.drifted(self._dir)
        )


def _run(config_dir: Path, arg: str) -> list[str]:
    core = _StubCore(config_dir)
    outcome = dispatch.run_reconcile(core, arg)  # type: ignore[arg-type]
    return [line.text for line in presenters.present_reconcile(outcome, "repl")]


def test_present_list_flags_a_drifted_file_with_magnitude(tmp_path: Path) -> None:
    _write(tmp_path, _TOOLS, b'{"tools": []}')
    texts = _run(tmp_path, "")  # no argument lists every file
    # The drifted row carries its state and a (+added -removed ~changed) magnitude.
    assert any(_TOOLS in t and "drifted" in t and "(+" in t and "~" in t for t in texts)
    assert any("reconcile all" in t for t in texts)


def test_present_diff_shows_semantic_sections(tmp_path: Path) -> None:
    # An install with one tool dropped and one field changed vs the template.
    data = json.loads(_packaged_tools())
    data["tools"] = [t for t in data["tools"] if t["name"] != "nikto"]  # drop one
    data["tools"][0]["output_flag"] = "-OA"  # change nmap's convention
    _write(tmp_path, _TOOLS, json.dumps(data).encode())
    texts = _run(tmp_path, f"diff {_TOOLS}")
    assert any("Added:" in t for t in texts)  # nikto is re-added by an overwrite
    assert any("nikto" in t for t in texts)
    assert any("Changed:" in t for t in texts)
    assert any("nmap.output_flag" in t and "=>" in t for t in texts)


def test_present_bare_filename_overwrites_and_reports_the_backup(
    tmp_path: Path,
) -> None:
    _write(tmp_path, _TOOLS, b'{"tools": []}')
    texts = _run(tmp_path, _TOOLS)  # a bare known file name overwrites it
    assert any("updated from the packaged template" in t for t in texts)
    assert any("backup saved" in t for t in texts)


def test_present_all_overwrites_every_drifted_file(tmp_path: Path) -> None:
    _write(tmp_path, _TOOLS, b'{"tools": []}')
    texts = _run(tmp_path, "all")
    assert any("updated from the packaged templates" in t for t in texts)
    assert any(_TOOLS in t for t in texts)


def test_present_unknown_and_usage(tmp_path: Path) -> None:
    assert any("unknown config file" in t for t in _run(tmp_path, "diff nope.json"))
    # A bare unknown token is an unknown file; `diff` with no file is the usage.
    assert any("unknown config file" in t for t in _run(tmp_path, "wat"))
    assert any("usage:" in t for t in _run(tmp_path, "diff"))


def test_present_diff_up_to_date_says_so(tmp_path: Path) -> None:
    _write(tmp_path, _TOOLS, _packaged_tools())
    assert any("up to date" in t for t in _run(tmp_path, f"diff {_TOOLS}"))
