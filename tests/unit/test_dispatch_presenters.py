"""L1: the shared presenters -- one source of wording for both front-ends."""

from __future__ import annotations

from skuggi.agent.readiness import Readiness
from skuggi.frontend import dispatch
from skuggi.frontend.render import Styled
from skuggi.persistence.ledger import ThreadSummary


def _texts(lines: Styled) -> list[str]:
    return [line.text for line in lines]


def test_present_provider_switched() -> None:
    lines = dispatch.present_provider(
        dispatch.ProviderSwitched("ollama", "qwen3"), "repl"
    )
    assert _texts(lines) == ["switched to ollama/qwen3"]


def test_present_autonomous_keeps_the_scope_warning() -> None:
    [line] = dispatch.present_autonomous(state=True)
    assert "EXECUTE within scope" in line.text
    assert line.style == "danger"


def _readiness(**over: object) -> Readiness:
    base: dict[str, object] = {
        "provider": "ollama",
        "model": "qwen3",
        "has_llm": True,
        "provider_configured": True,
        "engagement": "acme",
        "autonomous": False,
        "mode": "pentest",
        "warnings": (),
    }
    base.update(over)
    return Readiness(**base)  # type: ignore[arg-type]


def test_present_status_ready_vs_pending() -> None:
    ready = dispatch.present_status(_readiness(), "repl")
    assert any("mode pentest" in line.text for line in ready)
    assert _texts(ready)[-1] == "ready"

    pending = dispatch.present_status(_readiness(engagement=None), "repl")
    assert any("scope an engagement" in line.text for line in pending)
    assert "ready" not in _texts(pending)


def test_present_sessions_empty_and_rows() -> None:
    assert _texts(dispatch.present_sessions([])) == ["(no sessions yet)"]
    row = dispatch.SessionCount(
        session_id="abcdef1234",
        started_at="2026-10-03T10:00:00",
        mode="pentest",
        turns=2,
        commands=1,
        findings=0,
        current=True,
    )
    lines = dispatch.present_sessions([row])
    assert any("turns" in ln.text for ln in lines)  # a legend heading precedes rows
    row_line = lines[-1]
    assert row_line.text.startswith("abcdef12")
    assert "2t 1c 0f" in row_line.text
    assert row_line.text.endswith("*")


def test_present_threads_snippet_and_marker() -> None:
    rows = [
        ThreadSummary(
            thread_id="abc12345-xyz",
            turns=3,
            first_prompt="enumerate the whole host " * 5,  # long -> truncated
            last_activity="2026-10-03T10:00:00",
        )
    ]
    lines = dispatch.present_threads(rows, current="abc12345-xyz")
    row_line = lines[-1]
    assert row_line.text.startswith("abc12345")
    assert "…" in row_line.text  # snippet capped
    assert row_line.text.endswith("*")  # current marker
    assert _texts(dispatch.present_threads([], current="x")) == ["(no threads yet)"]


def test_present_unknown_points_at_help() -> None:
    [line] = dispatch.present_unknown("bogus", "shell")
    assert "unknown command" in line.text
    assert "/skuggi help" in line.text
