"""L1: the in-app ChatGPT OAuth login (no real browser or network)."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from skuggi.providers import codex_login
from skuggi.providers.codex_chat import CodexAuthError


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _id_token(claims: dict[str, object]) -> str:
    """A minimal unsigned JWT carrying `claims` in the payload segment."""
    header = _b64url(b'{"alg":"none"}')
    payload = _b64url(json.dumps(claims).encode("utf-8"))
    return f"{header}.{payload}.sig"


class _Resp:
    def __init__(self, status: int, body: dict[str, Any]) -> None:
        self.status_code = status
        self._body = body

    def json(self) -> dict[str, Any]:
        return self._body


# --- pure helpers -----------------------------------------------------------


def test_pkce_challenge_is_s256_of_verifier() -> None:
    verifier, challenge = codex_login.pkce_pair()
    expected = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    assert challenge == expected


def test_authorize_url_carries_the_codex_parameters() -> None:
    url = codex_login.build_authorize_url(
        authorize_url="https://auth.example/oauth/authorize",
        client_id="app_x",
        redirect_uri="http://127.0.0.1:1455/auth/callback",
        challenge="chal",
        state="st",
    )
    query = parse_qs(urlparse(url).query)
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["id_token_add_organizations"] == ["true"]
    assert query["redirect_uri"] == ["http://127.0.0.1:1455/auth/callback"]


def test_account_id_from_top_level_and_nested_claims() -> None:
    top = _id_token({"chatgpt_account_id": "acct-top"})
    assert codex_login.account_id_from_id_token(top) == "acct-top"
    nested = _id_token(
        {"https://api.openai.com/auth": {"chatgpt_account_id": "acct-n"}}
    )
    assert codex_login.account_id_from_id_token(nested) == "acct-n"
    assert codex_login.account_id_from_id_token(_id_token({})) is None


# --- loopback round-trip ----------------------------------------------------


def test_callback_server_captures_the_redirect() -> None:
    # urllib, not httpx: the no_network fixture blocks httpx, and this test needs
    # a real client to hit the real loopback server.
    server = codex_login._CallbackServer()
    result: list[codex_login._Callback] = []

    def run() -> None:
        result.append(server.wait(timeout_s=5.0))

    worker = threading.Thread(target=run)
    worker.start()
    query = urlencode({"code": "the-code", "state": "the-state"})
    with urllib.request.urlopen(
        f"http://127.0.0.1:{server.port}/auth/callback?{query}", timeout=5.0
    ) as response:
        response.read()
    worker.join(timeout=5.0)
    assert result
    assert result[0].code == "the-code"
    assert result[0].state == "the-state"


# --- full flow, offline -----------------------------------------------------


def test_login_persists_tokens_and_returns_the_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, str] = {}

    def fake_open(url: str) -> bool:
        query = parse_qs(urlparse(url).query)
        seen["state"] = query["state"][0]
        return True

    class StubServer:
        port = 1455

        def wait(self, timeout_s: float) -> codex_login._Callback:
            # The real browser echoes the state back; mimic that.
            return codex_login._Callback(
                code="auth-code", state=seen["state"], error=None
            )

    monkeypatch.setattr(codex_login, "_CallbackServer", StubServer)

    def fake_post(url: str, *, json: dict[str, Any], timeout: float) -> Any:
        assert json["grant_type"] == "authorization_code"
        assert json["code"] == "auth-code"
        assert json["code_verifier"]  # PKCE verifier is sent
        return _Resp(
            200,
            {
                "access_token": "at",
                "refresh_token": "rt",
                "id_token": _id_token({"chatgpt_account_id": "acct-9"}),
            },
        )

    auth_path = tmp_path / "auth.json"
    account = codex_login.login(
        auth_path=auth_path, open_browser=fake_open, post=fake_post
    )

    assert account == "acct-9"
    data = json.loads(auth_path.read_text(encoding="utf-8"))
    assert data["auth_mode"] == "chatgpt"
    assert data["tokens"] == {
        "access_token": "at",
        "id_token": data["tokens"]["id_token"],
        "refresh_token": "rt",
        "account_id": "acct-9",
    }


def test_login_rejects_a_state_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class StubServer:
        port = 1455

        def wait(self, timeout_s: float) -> codex_login._Callback:
            return codex_login._Callback(code="c", state="attacker", error=None)

    monkeypatch.setattr(codex_login, "_CallbackServer", StubServer)

    def fake_post(url: str, *, json: dict[str, Any], timeout: float) -> Any:
        pytest.fail("must not exchange on a state mismatch")

    with pytest.raises(CodexAuthError, match="state mismatch"):
        codex_login.login(
            auth_path=tmp_path / "auth.json",
            open_browser=lambda _u: True,
            post=fake_post,
        )
