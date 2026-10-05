"""L1: the research local-tool seam (subprocess + cache loader), offline.

``default_local_run``/``default_msf_cache`` are the only two places a research
collector touches a subprocess or the real filesystem; these pin their best-effort,
never-raise contract with ``subprocess.run`` monkeypatched and real tmp files.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from skuggi.research.collectors import local


def test_have_false_for_absent_binary() -> None:
    assert local.have("definitely-not-a-real-binary-xyz") is False


def test_have_true_when_which_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "skuggi.research.collectors.local.shutil.which", lambda _n: "/usr/bin/x"
    )
    assert local.have("x") is True


def test_local_run_none_for_empty_or_absent_argv() -> None:
    assert local.default_local_run([]) is None
    assert local.default_local_run(["no-such-binary-xyz"]) is None


def test_local_run_returns_stdout_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local, "have", lambda _n: True)

    def fake_run(*_a: Any, **_k: Any) -> Any:
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout="OUT", stderr=""
        )

    monkeypatch.setattr("skuggi.research.collectors.local.subprocess.run", fake_run)
    assert local.default_local_run(["searchsploit", "--json", "x"]) == "OUT"


def test_local_run_none_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local, "have", lambda _n: True)
    monkeypatch.setattr(
        "skuggi.research.collectors.local.subprocess.run",
        lambda *_a, **_k: subprocess.CompletedProcess([], 1, "x", ""),
    )
    assert local.default_local_run(["searchsploit"]) is None


def test_local_run_none_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local, "have", lambda _n: True)

    def boom(*_a: Any, **_k: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr("skuggi.research.collectors.local.subprocess.run", boom)
    assert local.default_local_run(["searchsploit"]) is None


def test_local_run_none_on_os_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local, "have", lambda _n: True)

    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError

    monkeypatch.setattr("skuggi.research.collectors.local.subprocess.run", boom)
    assert local.default_local_run(["searchsploit"]) is None


def test_msf_cache_reads_dict(tmp_path: Path) -> None:
    f = tmp_path / "modules_metadata.json"
    f.write_text('{"mod": {"name": "x"}}', encoding="utf-8")
    assert local.default_msf_cache(f) == {"mod": {"name": "x"}}


def test_msf_cache_none_for_missing_file(tmp_path: Path) -> None:
    assert local.default_msf_cache(tmp_path / "absent.json") is None


def test_msf_cache_none_for_bad_json(tmp_path: Path) -> None:
    f = tmp_path / "bad.json"
    f.write_text("{not json", encoding="utf-8")
    assert local.default_msf_cache(f) is None


def test_msf_cache_none_for_non_dict(tmp_path: Path) -> None:
    f = tmp_path / "list.json"
    f.write_text("[1, 2, 3]", encoding="utf-8")
    assert local.default_msf_cache(f) is None


# --- research input guard: binary allow-list + subject sanitiser ------------


def test_local_run_rejects_a_non_allowlisted_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deny-by-default: only RESEARCH_BINARIES may be spawned, never reaching run."""
    monkeypatch.setattr(local, "have", lambda _n: True)

    def _never(*_a: Any, **_k: Any) -> Any:  # pragma: no cover -- must not run
        pytest.fail("subprocess.run must not be reached")

    monkeypatch.setattr("skuggi.research.collectors.local.subprocess.run", _never)
    assert local.default_local_run(["rm", "-rf", "/"]) is None


def test_local_run_rejects_a_control_char_in_a_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(local, "have", lambda _n: True)
    assert local.default_local_run(["searchsploit", "a\nb"]) is None


@pytest.mark.parametrize("bad", ["", "   ", "-m", "--examine", "a\x00b", "x\ny"])
def test_safe_subject_rejects_unsafe_input(bad: str) -> None:
    assert local.safe_subject(bad) is None


def test_safe_subject_accepts_and_strips_a_plain_query() -> None:
    assert local.safe_subject("  apache 2.4  ") == "apache 2.4"
