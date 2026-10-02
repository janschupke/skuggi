"""L1: the guided provider/credential setup flow (front-end-agnostic)."""

from __future__ import annotations

from collections.abc import Iterator

from skuggi import setup


class FakeBackend:
    """Records what the flow asked the core to persist."""

    def __init__(self, provider: str = "openai") -> None:
        self.provider = provider
        self.api_key: tuple[str, str] | None = None
        self.ollama_url: str | None = "unset"
        self.logged_in = False

    def set_api_key(self, provider: str, key: str) -> None:
        self.api_key = (provider, key)

    def use_ollama(self, base_url: str | None) -> None:
        self.ollama_url = base_url

    def login_chatgpt(self, notify: setup.Notify) -> str | None:
        self.logged_in = True
        return "acct-7"


def _ask_from(answers: list[str | None]) -> setup.Ask:
    stream: Iterator[str | None] = iter(answers)

    def ask(_prompt: str) -> str | None:
        return next(stream)

    return ask


def _notes() -> tuple[setup.Notify, list[str]]:
    out: list[str] = []
    return out.append, out


def test_openai_key_rejected_then_accepted() -> None:
    backend = FakeBackend()
    notify, notes = _notes()
    ok = setup.run_setup(backend, _ask_from(["openai", "nope", "sk-good"]), notify)
    assert ok is True
    assert backend.api_key == ("openai", "sk-good")
    assert any("not a openai key" in n for n in notes)
    assert any("skuggi's config" in n for n in notes)


def test_anthropic_key_shape_enforced() -> None:
    backend = FakeBackend()
    notify, _ = _notes()
    ok = setup.run_setup(backend, _ask_from(["anthropic", "sk-ant-xyz"]), notify)
    assert ok is True
    assert backend.api_key == ("anthropic", "sk-ant-xyz")


def test_blank_choice_keeps_current_provider() -> None:
    backend = FakeBackend(provider="anthropic")
    notify, _ = _notes()
    setup.run_setup(backend, _ask_from(["", "sk-ant-k"]), notify)
    assert backend.api_key == ("anthropic", "sk-ant-k")


def test_ollama_blank_url_uses_default() -> None:
    backend = FakeBackend()
    notify, _ = _notes()
    ok = setup.run_setup(backend, _ask_from(["ollama", ""]), notify)
    assert ok is True
    assert backend.ollama_url is None  # blank -> backend applies its default


def test_chatgpt_runs_the_login() -> None:
    backend = FakeBackend()
    notify, notes = _notes()
    ok = setup.run_setup(backend, _ask_from(["chatgpt"]), notify)
    assert ok is True
    assert backend.logged_in
    assert any("acct-7" in n for n in notes)


def test_abort_returns_false() -> None:
    backend = FakeBackend()
    notify, _ = _notes()
    assert setup.run_setup(backend, _ask_from([None]), notify) is False
    assert backend.api_key is None


def test_unknown_provider_is_rejected() -> None:
    backend = FakeBackend()
    notify, notes = _notes()
    assert setup.run_setup(backend, _ask_from(["gemini"]), notify) is False
    assert any("unknown provider" in n for n in notes)


def test_a_backend_failure_is_reported_not_raised() -> None:
    class Boom(FakeBackend):
        def set_api_key(self, provider: str, key: str) -> None:
            msg = "disk full"
            raise RuntimeError(msg)

    notify, notes = _notes()
    ok = setup.run_setup(Boom(), _ask_from(["openai", "sk-x"]), notify)
    assert ok is False
    assert any("setup failed: disk full" in n for n in notes)
