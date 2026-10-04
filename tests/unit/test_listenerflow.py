"""L1: the front-end-agnostic `set listener` flow (pick lhost + lport)."""

from __future__ import annotations

from skuggi.frontend.listenerflow import run_set_listener

_IFACES = [("eth0", "192.168.1.10"), ("tun0", "10.8.0.2")]


class _Driver:
    """Scripts the choose/ask prompts and records what the flow applies."""

    def __init__(self, choices: list[str | None], answers: list[str | None]) -> None:
        self._choices = choices
        self._answers = answers
        self.notes: list[str] = []
        self.applied: tuple[str, str | None] | None = None
        self.default: str | None = None

    def choose(
        self, _prompt: str, _options: list[str], default: str | None
    ) -> str | None:
        self.default = default
        return self._choices.pop(0)

    def ask(self, _prompt: str) -> str | None:
        return self._answers.pop(0)

    def notify(self, text: str) -> None:
        self.notes.append(text)

    def apply(self, lhost: str, lport: str | None) -> None:
        self.applied = (lhost, lport)

    def run(self) -> None:
        run_set_listener(
            interfaces=_IFACES,
            choose=self.choose,
            ask=self.ask,
            notify=self.notify,
            apply=self.apply,
        )


def test_picks_an_interface_and_a_port() -> None:
    d = _Driver(choices=["eth0  192.168.1.10"], answers=["4444"])
    d.run()
    assert d.applied == ("192.168.1.10", "4444")
    assert d.default == "tun0  10.8.0.2"  # the VPN interface is the default pick


def test_manual_entry_and_a_blank_port() -> None:
    d = _Driver(choices=["enter manually…"], answers=["evil.example.com", ""])
    d.run()
    assert d.applied == ("evil.example.com", None)  # blank port -> unset


def test_abort_at_the_interface_picker_applies_nothing() -> None:
    d = _Driver(choices=[None], answers=[])
    d.run()
    assert d.applied is None
    assert "cancelled" in d.notes[-1]


def test_abort_at_the_port_prompt_applies_nothing() -> None:
    d = _Driver(choices=["eth0  192.168.1.10"], answers=[None])
    d.run()
    assert d.applied is None
    assert "cancelled" in d.notes[-1]


def test_no_interfaces_falls_back_to_manual_host() -> None:
    applied: dict[str, object] = {}

    def apply(lhost: str, lport: str | None) -> None:
        applied["value"] = (lhost, lport)

    answers = iter(["10.0.0.9", "9001"])
    run_set_listener(
        interfaces=[],
        choose=lambda *_a: None,  # never reached
        ask=lambda _prompt: next(answers),
        notify=lambda _t: None,
        apply=apply,
    )
    assert applied["value"] == ("10.0.0.9", "9001")
