"""In-app ChatGPT login: the OAuth flow skuggi owns, so no external `codex`.

`codex login` is a separate CLI skuggi does not install. This module performs
the same PKCE loopback OAuth against OpenAI's auth server itself and writes
``~/.codex/auth.json`` in the shape the ``chatgpt`` provider already reads
(`CodexTokenStore`), so logging in never depends on another tool.

Flow (matches the public ``codex-rs`` login):
1. generate a PKCE verifier/challenge (S256) and a random ``state``;
2. start a localhost HTTP server on the codex callback port (1455, then 1457);
3. open the browser at ``/oauth/authorize``;
4. capture ``/auth/callback?code=…&state=…`` on the loopback, checking ``state``;
5. exchange the code (+ verifier) at ``/oauth/token`` for the token set;
6. read ``chatgpt_account_id`` from the id_token and persist the tokens.

The network call and browser opener are injectable so the exchange and URL
building are unit-tested without a real browser or OpenAI.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sys
import threading
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from skuggi.codex_chat import (
    CODEX_CLIENT_ID,
    CODEX_ORIGINATOR,
    CodexAuthError,
    CodexTokenStore,
)
from skuggi.config import CODEX_AUTHORIZE_URL, CODEX_REFRESH_URL, Settings
from skuggi.logs import get_logger, setup_logging

log = get_logger(__name__)

# codex listens on 1455 and falls back to 1457; the redirect must match exactly.
_CALLBACK_PORTS = (1455, 1457)
_CALLBACK_PATH = "/auth/callback"
_SCOPE = "openid profile email offline_access"
_POST_TIMEOUT_S = 30.0
_WAIT_TIMEOUT_S = 300.0

Notify = Callable[[str], None]
Opener = Callable[[str], object]
Poster = Callable[..., httpx.Response]

_SUCCESS_HTML = (
    b"<!doctype html><title>skuggi</title>"
    b"<body style='font:16px system-ui;padding:3rem'>"
    b"<h2>Signed in to skuggi.</h2><p>You can close this tab and return to the "
    b"terminal.</p></body>"
)


def _b64url(raw: bytes) -> str:
    """Base64url without padding (the PKCE/JWT encoding)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pkce_pair() -> tuple[str, str]:
    """A PKCE ``(verifier, challenge)`` pair using the S256 method."""
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def build_authorize_url(  # noqa: PLR0913 -- keyword-only OAuth parameters
    *,
    authorize_url: str,
    client_id: str,
    redirect_uri: str,
    challenge: str,
    state: str,
    scope: str = _SCOPE,
) -> str:
    """The ``/oauth/authorize`` URL, with the codex-specific extra parameters.

    ``id_token_add_organizations`` is what makes the id_token carry the account
    claims (``chatgpt_account_id``); without it there is no account to persist.
    """
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "originator": CODEX_ORIGINATOR,
    }
    return f"{authorize_url}?{urlencode(params)}"


def jwt_claims(token: str) -> dict[str, object]:
    """Decode a JWT payload without verifying the signature (local read only)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, json.JSONDecodeError) as exc:
        log.warning("could not decode JWT claims: %s", exc)
        return {}
    return claims if isinstance(claims, dict) else {}


def account_id_from_id_token(id_token: str) -> str | None:
    """Pull ``chatgpt_account_id`` from the id_token, top-level or nested.

    OpenAI nests the account claims under the ``https://api.openai.com/auth``
    namespace; older/other tokens carry it at the top level. Check both.
    """
    claims = jwt_claims(id_token)
    direct = claims.get("chatgpt_account_id")
    if isinstance(direct, str):
        return direct
    nested = claims.get("https://api.openai.com/auth")
    if isinstance(nested, dict):
        value = nested.get("chatgpt_account_id")
        if isinstance(value, str):
            return value
    return None


@dataclass(frozen=True, slots=True)
class _Callback:
    code: str | None
    state: str | None
    error: str | None


class _CallbackServer:
    """A one-shot loopback server that captures the OAuth redirect.

    Binds the codex callback port (1455, then 1457) on construction so the
    caller can build the matching ``redirect_uri`` before opening the browser.
    ``wait`` serves until ``/auth/callback`` arrives (ignoring stray requests
    like a favicon fetch) or the timeout elapses.
    """

    def __init__(self) -> None:
        self._result: _Callback | None = None
        self._done = threading.Event()
        self._server = self._bind()
        self.port: int = self._server.server_address[1]

    def _bind(self) -> HTTPServer:
        handler = self._handler()
        last_error: OSError | None = None
        for port in _CALLBACK_PORTS:
            try:
                return HTTPServer(("127.0.0.1", port), handler)
            except OSError as exc:
                last_error = exc
        msg = f"no free callback port among {_CALLBACK_PORTS}: {last_error}"
        raise CodexAuthError(msg)

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:  # silence stderr
                pass

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path != _CALLBACK_PATH:
                    self.send_error(404)
                    return
                query = parse_qs(parsed.query)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(_SUCCESS_HTML)
                server.capture(query)

        return Handler

    def capture(self, query: dict[str, list[str]]) -> None:
        """Record the callback query (called by the loopback handler)."""

        def first(key: str) -> str | None:
            values = query.get(key)
            return values[0] if values else None

        self._result = _Callback(
            code=first("code"), state=first("state"), error=first("error")
        )
        self._done.set()

    def wait(self, timeout_s: float) -> _Callback:
        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.start()
        try:
            if not self._done.wait(timeout_s):
                msg = "login timed out waiting for the browser callback"
                raise CodexAuthError(msg)
        finally:
            self._server.shutdown()
            self._server.server_close()
        if self._result is None:  # unreachable: the event is set with the result
            msg = "login callback produced no result"
            raise CodexAuthError(msg)
        return self._result


def login(  # noqa: PLR0913 -- keyword-only, each an injection point for tests
    *,
    auth_path: Path,
    authorize_url: str = CODEX_AUTHORIZE_URL,
    token_url: str = CODEX_REFRESH_URL,
    client_id: str = CODEX_CLIENT_ID,
    notify: Notify = lambda _msg: None,
    open_browser: Opener = webbrowser.open,
    post: Poster | None = None,
    wait_timeout_s: float = _WAIT_TIMEOUT_S,
) -> str | None:
    """Run the ChatGPT OAuth flow and persist the tokens to ``auth_path``.

    Returns the account id (or ``None`` if the token carried none). Raises
    ``CodexAuthError`` on any failure. ``post`` defaults to ``httpx.post`` and is
    injectable for tests.
    """
    http_post: Poster = post if post is not None else httpx.post
    verifier, challenge = pkce_pair()
    state = _b64url(secrets.token_bytes(16))
    server = _CallbackServer()
    redirect_uri = f"http://127.0.0.1:{server.port}{_CALLBACK_PATH}"
    url = build_authorize_url(
        authorize_url=authorize_url,
        client_id=client_id,
        redirect_uri=redirect_uri,
        challenge=challenge,
        state=state,
    )

    notify("opening your browser to sign in...")
    try:
        opened = open_browser(url)
    except webbrowser.Error as exc:
        log.warning("could not open a browser: %s", exc)
        opened = False
    if not opened:
        notify(f"could not open a browser; visit this URL to sign in:\n{url}")
    notify("waiting for the browser callback...")

    callback = server.wait(wait_timeout_s)
    if callback.error:
        msg = f"login denied: {callback.error}"
        raise CodexAuthError(msg)
    if not callback.code:
        msg = "login returned no authorization code"
        raise CodexAuthError(msg)
    if callback.state != state:
        msg = "login state mismatch (possible CSRF); aborted"
        raise CodexAuthError(msg)

    notify("exchanging the authorization code...")
    tokens = _exchange_code(
        http_post,
        token_url=token_url,
        client_id=client_id,
        code=callback.code,
        redirect_uri=redirect_uri,
        verifier=verifier,
    )
    CodexTokenStore(auth_path).persist_login(tokens)
    account = tokens.get("account_id")
    notify(f"signed in{f' as account {account}' if account else ''}.")
    return account or None


def _exchange_code(  # noqa: PLR0913 -- keyword-only OAuth token-exchange fields
    post: Poster,
    *,
    token_url: str,
    client_id: str,
    code: str,
    redirect_uri: str,
    verifier: str,
) -> dict[str, str]:
    """Exchange the authorization code for the token set (access/refresh/id)."""
    response = post(
        token_url,
        json={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
        timeout=_POST_TIMEOUT_S,
    )
    if response.status_code != httpx.codes.OK:
        msg = f"token exchange failed ({response.status_code})"
        raise CodexAuthError(msg)
    body = response.json()
    access = body.get("access_token")
    id_token = body.get("id_token")
    if not isinstance(access, str) or not isinstance(id_token, str):
        msg = "token exchange returned no usable tokens"
        raise CodexAuthError(msg)
    tokens: dict[str, str] = {"access_token": access, "id_token": id_token}
    refresh = body.get("refresh_token")
    if isinstance(refresh, str):
        tokens["refresh_token"] = refresh
    account = account_id_from_id_token(id_token)
    if account is not None:
        tokens["account_id"] = account
    return tokens


def main() -> None:  # pragma: no cover -- opens a real browser + OAuth
    """Console entry (``skuggi-login``): log in to ChatGPT before starting skuggi."""
    setup_logging()
    log.info("skuggi-login starting")
    try:
        login(
            auth_path=Settings().auth_json(),
            notify=lambda message: print(f"skuggi: {message}"),
        )
    except CodexAuthError as exc:
        log.exception("login failed")
        print(f"skuggi: login failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
