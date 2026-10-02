"""ChatGPT-account (codex OAuth) chat model, as a thin ChatOpenAI subclass.

The codex endpoint speaks the Responses API, so langchain-openai and the openai
SDK can do nearly all of the work: SSE framing, streaming, usage metadata, tool
binding and async all come for free. What remains genuinely bespoke is the
credential layer, and it is isolated into two small pieces:

- ``CodexTokenStore`` owns ``auth.json`` -- reading tokens, pre-empting expiry,
  and performing the OAuth2 refresh-token grant.
- ``CodexAuth`` is an ``httpx.Auth`` that stamps the bearer and the per-request
  ``x-codex-*`` headers, and refreshes then replays on a 401.

Only the request *body* needs shaping, which ``_get_request_payload`` does.

Endpoint and header details follow the codex CLI:
  https://github.com/openai/codex/blob/main/codex-rs/core/src/client.rs
  https://github.com/openai/codex/blob/main/codex-rs/login/src/auth/manager.rs
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
import time
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

import httpx
from langchain_core.language_models import LanguageModelInput
from langchain_openai import ChatOpenAI

from skuggi.config import CODEX_REFRESH_URL, CODEX_RESPONSES_BASE
from skuggi.prompts import CODEX_DEFAULT_INSTRUCTIONS

CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_OPENAI_BETA = "responses=experimental"
CODEX_ORIGINATOR = "codex_cli_rs"

_AUTH_PATH_DEFAULT = Path("~/.codex/auth.json").expanduser()
_REFRESH_SKEW_SECONDS = 60


def jwt_expiry(token: str) -> int | None:
    """Read the `exp` claim from a JWT without verifying its signature.

    Kept hand-rolled rather than taking a pyjwt dependency to read one
    unverified claim. The exception list is exactly what the three steps below
    can raise: indexing the payload segment, base64 decoding it, and parsing it.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, binascii.Error):
        return None
    exp = claims.get("exp") if isinstance(claims, dict) else None
    return (
        int(exp)
        if isinstance(exp, (int, float)) and not isinstance(exp, bool)
        else None
    )


class CodexAuthError(RuntimeError):
    """Raised when auth.json is missing, malformed, or cannot be refreshed."""


class CodexTokenStore:
    """Reads and refreshes the ChatGPT-account tokens in auth.json."""

    def __init__(
        self,
        auth_path: Path | None = None,
        *,
        refresh_url: str = CODEX_REFRESH_URL,
        client_id: str = CODEX_CLIENT_ID,
    ) -> None:
        self.auth_path = (auth_path or _AUTH_PATH_DEFAULT).expanduser()
        self.refresh_url = refresh_url
        self.client_id = client_id

    def _load(self) -> dict[str, Any]:
        if not self.auth_path.is_file():
            msg = (
                f"{self.auth_path} not found. "
                "Run `/login` (or `skuggi-login`) to sign in."
            )
            raise CodexAuthError(msg)
        data: object = json.loads(self.auth_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            msg = f"{self.auth_path} does not contain a JSON object."
            raise CodexAuthError(msg)
        return data

    def _save(self, data: dict[str, Any]) -> None:
        """Atomically rewrite auth.json, keeping it private to the owner.

        Writing a temp file with `write_text` creates it at the process umask
        (typically 0644) and `replace` carries that mode onto the target, which
        would widen the user's OAuth tokens to world-readable. `mkstemp` creates
        at 0600 instead, so this can only ever narrow the mode -- which also
        repairs a file an earlier version already widened. The fsync is so a
        crash between write and rename cannot leave a truncated credential file.
        """
        directory = self.auth_path.parent
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".auth-", suffix=".tmp")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            tmp.replace(self.auth_path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def _tokens(self) -> tuple[dict[str, Any], dict[str, Any]]:
        auth = self._load()
        tokens = auth.get("tokens")
        if not isinstance(tokens, dict) or not tokens.get("access_token"):
            msg = (
                f"{self.auth_path} has no ChatGPT tokens. "
                "Run `/login` (or `skuggi-login`) to sign in."
            )
            raise CodexAuthError(msg)
        return auth, tokens

    def account_id(self) -> str | None:
        """The chatgpt-account-id header value, if auth.json carries one."""
        _, tokens = self._tokens()
        value = tokens.get("account_id")
        return value if isinstance(value, str) else None

    def is_logged_in(self) -> bool:
        """Whether auth.json holds usable ChatGPT tokens (no network, no refresh)."""
        try:
            self._tokens()
        except CodexAuthError:
            return False
        return True

    def access_token(self) -> str:
        """Return a usable access token, refreshing ahead of expiry."""
        _, tokens = self._tokens()
        access = str(tokens["access_token"])
        probe = tokens.get("id_token") or access
        expiry = jwt_expiry(str(probe))
        if expiry is not None and expiry - time.time() < _REFRESH_SKEW_SECONDS:
            return self.refresh()
        return access

    def refresh(self) -> str:
        """Exchange the refresh token for a new access token and persist it."""
        auth, tokens = self._tokens()
        refresh_token = tokens.get("refresh_token")
        if not refresh_token:
            msg = (
                "auth.json has no refresh_token; "
                "run `/login` (or `skuggi-login`) again."
            )
            raise CodexAuthError(msg)
        response = httpx.post(
            self.refresh_url,
            json={
                "client_id": self.client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            timeout=30.0,
        )
        if response.status_code != httpx.codes.OK:
            msg = (
                f"OAuth refresh failed ({response.status_code}). "
                "Run `/login` (or `skuggi-login`) again."
            )
            raise CodexAuthError(msg)
        body = response.json()
        for key in ("access_token", "refresh_token", "id_token"):
            if body.get(key):
                tokens[key] = body[key]
        auth["tokens"] = tokens
        auth["last_refresh"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._save(auth)
        access = tokens.get("access_token")
        if not isinstance(access, str):
            msg = "OAuth refresh returned no access_token."
            raise CodexAuthError(msg)
        return access

    def persist_login(self, tokens: dict[str, str]) -> None:
        """Write a fresh ChatGPT login to auth.json (0600).

        ``tokens`` carries ``access_token``/``refresh_token``/``id_token`` and
        ``account_id``. The shape matches what ``_tokens`` reads back and what
        ``codex login`` itself writes, so the ``chatgpt`` provider and the
        refresh path work against it unchanged. ``auth_mode`` is recorded for
        parity with codex (skuggi never reads it).
        """
        self._save(
            {
                "OPENAI_API_KEY": None,
                "tokens": tokens,
                "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "auth_mode": "chatgpt",
            }
        )


class CodexAuth(httpx.Auth):
    """Stamps codex credentials per request, refreshing and replaying on a 401.

    `sync_auth_flow` is overridden rather than setting `requires_response_body`,
    because the base implementation reads every response body -- including the
    successful SSE one, which would buffer the whole stream and destroy
    incremental output. Overriding means the body is only read when the flow
    yields a second request, i.e. only on the 401 path.
    """

    def __init__(self, store: CodexTokenStore) -> None:
        self._store = store

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        """Sign the request, then refresh and replay it once on a 401."""
        request.headers["Authorization"] = f"Bearer {self._store.access_token()}"
        request.headers["x-codex-turn-state"] = str(uuid.uuid4())
        request.headers["x-codex-window-id"] = str(uuid.uuid4())
        response = yield request
        if response.status_code == httpx.codes.UNAUTHORIZED:
            request.headers["Authorization"] = f"Bearer {self._store.refresh()}"
            request.headers["x-codex-turn-state"] = str(uuid.uuid4())
            yield request


class CodexChatModel(ChatOpenAI):
    """ChatOpenAI pointed at the codex Responses endpoint."""

    codex_instructions: str = CODEX_DEFAULT_INSTRUCTIONS

    @property
    def _llm_type(self) -> str:
        return "codex-chatgpt"

    def _get_request_payload(
        self,
        input_: LanguageModelInput,
        *,
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Reshape the Responses payload into what the codex endpoint expects.

        Two differences from stock OpenAI: codex carries the system prompt in
        `instructions` rather than as a system entry inside `input`, and it wants
        `store`, `tools`, `tool_choice` and `parallel_tool_calls` stated
        explicitly. model_kwargs is not used for this because an empty `tools`
        list is silently dropped there and `store` triggers a UserWarning that a
        -W error test suite turns into a failure.
        """
        payload = super()._get_request_payload(input_, stop=stop, **kwargs)
        entries = payload.get("input")
        instructions = [self.codex_instructions]
        if isinstance(entries, list):
            kept: list[Any] = []
            for entry in entries:
                if isinstance(entry, dict) and entry.get("role") == "system":
                    instructions.append(_entry_text(entry))
                else:
                    kept.append(entry)
            payload["input"] = kept
        payload["instructions"] = "\n\n".join(part for part in instructions if part)
        payload.setdefault("tools", [])
        payload.setdefault("tool_choice", "auto")
        payload["parallel_tool_calls"] = False
        payload["store"] = False
        return payload


def _entry_text(entry: dict[str, Any]) -> str:
    """Flatten one Responses `input` entry to plain text."""
    content = entry.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            str(part.get("text", "")) for part in content if isinstance(part, dict)
        )
    return ""


def build_codex_chat_model(
    model: str,
    *,
    auth_path: Path | None = None,
    responses_base: str = CODEX_RESPONSES_BASE,
    refresh_url: str = CODEX_REFRESH_URL,
    http_client: httpx.Client | None = None,
) -> CodexChatModel:
    """Assemble a CodexChatModel against the ChatGPT-account endpoint."""
    store = CodexTokenStore(auth_path, refresh_url=refresh_url)
    client = http_client or httpx.Client(
        auth=CodexAuth(store), timeout=httpx.Timeout(60.0, read=600.0)
    )
    headers = {
        # The SDK sends `Accept: application/json` even when streaming; the codex
        # endpoint is an SSE stream, so this must be overridden explicitly.
        "Accept": "text/event-stream",
        "OpenAI-Beta": CODEX_OPENAI_BETA,
        "originator": CODEX_ORIGINATOR,
        "User-Agent": "skuggi (codex-compat)",
        "x-codex-installation-id": str(uuid.uuid4()),
        "x-codex-turn-metadata": "{}",
        "x-codex-parent-thread-id": "",
    }
    account_id = store.account_id()
    if account_id:
        headers["chatgpt-account-id"] = account_id
    return CodexChatModel(
        model=model,
        # The SDK requires a non-empty key; CodexAuth overwrites the header.
        api_key="codex-oauth",
        base_url=responses_base,
        use_responses_api=True,
        streaming=True,
        default_headers=headers,
        http_client=client,
    )
