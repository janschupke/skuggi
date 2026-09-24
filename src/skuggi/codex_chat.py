"""Custom LangChain chat model for the codex ChatGPT-account OAuth path.

Posts a Codex-flavored Responses API body to ``chatgpt.com/backend-api/responses``
with the ``x-codex-*`` headers the endpoint requires. Reads tokens from
``~/.codex/auth.json``; on 401, refreshes via the OAuth2 refresh-token grant
against ``auth.openai.com/oauth/token`` (codex's hardcoded ``client_id``) and
writes new tokens back to auth.json.

Limitations (see README): does NOT bind LangChain tools. The Codex Responses
API uses a codex-specific tool schema; this scaffold runs the worker as a
plain text generator when this model is selected.

Endpoint and header details verified against:
  https://github.com/openai/codex/blob/main/codex-rs/core/src/client.rs
  https://github.com/openai/codex/blob/main/codex-rs/login/src/auth/manager.rs
"""

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

import httpx
from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult
from pydantic import Field

CODEX_RESPONSES_URL = "https://chatgpt.com/backend-api/responses"
CODEX_REFRESH_URL = "https://auth.openai.com/oauth/token"
CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_OPENAI_BETA = "responses=experimental"
CODEX_ORIGINATOR = "codex_cli_rs"

_AUTH_PATH_DEFAULT = Path("~/.codex/auth.json").expanduser()


def _jwt_exp(token: str) -> int | None:
    """Decode the ``exp`` claim from a JWT without verifying the signature."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        exp = data.get("exp")
        return int(exp) if isinstance(exp, (int, float)) else None
    except Exception:
        return None


class CodexChatModel(BaseChatModel):
    """Chat model that speaks the codex ChatGPT-account Responses API."""

    model: str = "gpt-5"
    auth_path: Path = Field(default_factory=lambda: _AUTH_PATH_DEFAULT)
    responses_url: str = Field(
        default_factory=lambda: os.environ.get(
            "SKUGGI_CODEX_RESPONSES_URL", CODEX_RESPONSES_URL
        )
    )
    refresh_url: str = Field(
        default_factory=lambda: os.environ.get(
            "SKUGGI_CODEX_REFRESH_URL", CODEX_REFRESH_URL
        )
    )
    installation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def _llm_type(self) -> str:
        return "codex-chatgpt"

    # ----- auth.json I/O -----

    def _load_auth(self) -> dict[str, Any]:
        if not self.auth_path.is_file():
            raise RuntimeError(
                f"{self.auth_path} not found. Run `codex login` (ChatGPT mode) first."
            )
        return json.loads(self.auth_path.read_text())

    def _save_auth(self, data: dict[str, Any]) -> None:
        tmp = self.auth_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(self.auth_path)

    def _access_token(self) -> tuple[str, str | None]:
        """Return (access_token, account_id), refreshing if expired."""
        auth = self._load_auth()
        tokens = auth.get("tokens") or {}
        access = tokens.get("access_token")
        refresh = tokens.get("refresh_token")
        if not access or not refresh:
            raise RuntimeError(
                "~/.codex/auth.json has no ChatGPT tokens. "
                "Run `codex login` (browser flow) and retry."
            )
        exp = _jwt_exp(tokens.get("id_token") or access)
        if exp is not None and exp - time.time() < 60:
            access = self._refresh(refresh, auth)
        return access, tokens.get("account_id")

    def _refresh(self, refresh_token: str, auth: dict[str, Any]) -> str:
        resp = httpx.post(
            self.refresh_url,
            json={
                "client_id": CODEX_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            timeout=30.0,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"OAuth refresh failed ({resp.status_code}). Run `codex login` again."
            )
        body = resp.json()
        tokens = auth.setdefault("tokens", {})
        for k in ("access_token", "refresh_token", "id_token"):
            if body.get(k):
                tokens[k] = body[k]
        auth["last_refresh"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._save_auth(auth)
        return tokens["access_token"]

    # ----- HTTP -----

    def _headers(self, access: str, account_id: str | None) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {access}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "OpenAI-Beta": CODEX_OPENAI_BETA,
            "originator": CODEX_ORIGINATOR,
            "User-Agent": "skuggi/0.1 (codex-compat)",
            "x-codex-installation-id": self.installation_id,
            "x-codex-turn-state": str(uuid.uuid4()),
            "x-codex-turn-metadata": "{}",
            "x-codex-parent-thread-id": "",
            "x-codex-window-id": str(uuid.uuid4()),
        }
        if account_id:
            h["chatgpt-account-id"] = account_id
        return h

    def _messages_to_input(self, messages: list[BaseMessage]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in messages:
            role = {"human": "user", "ai": "assistant", "system": "system"}.get(
                m.type, m.type
            )
            content = m.content if isinstance(m.content, str) else str(m.content)
            out.append(
                {
                    "type": "message",
                    "role": role,
                    "content": [{"type": "input_text", "text": content}],
                }
            )
        return out

    def _body(self, messages: list[BaseMessage]) -> dict[str, Any]:
        return {
            "model": self.model,
            "instructions": "You are a helpful assistant.",
            "input": self._messages_to_input(messages),
            "tools": [],
            "tool_choice": "auto",
            "parallel_tool_calls": False,
            "store": False,
            "stream": True,
        }

    # ----- iteration -----

    def _iter_sse(self, messages: list[BaseMessage]) -> Iterator[str]:
        access, account_id = self._access_token()
        body = self._body(messages)
        headers = self._headers(access, account_id)

        for attempt in range(2):
            with httpx.Client(timeout=httpx.Timeout(60.0, read=600.0)) as client:
                with client.stream(
                    "POST", self.responses_url, json=body, headers=headers
                ) as resp:
                    if resp.status_code == 401 and attempt == 0:
                        auth = self._load_auth()
                        refresh = (auth.get("tokens") or {}).get("refresh_token")
                        if not refresh:
                            raise RuntimeError("401 and no refresh_token available.")
                        access = self._refresh(refresh, auth)
                        headers = self._headers(access, account_id)
                        continue
                    if resp.status_code != 200:
                        snippet = resp.read().decode("utf-8", errors="replace")[:400]
                        raise RuntimeError(
                            f"codex responses {resp.status_code}: {snippet}"
                        )
                    for line in resp.iter_lines():
                        if not line or not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            return
                        try:
                            event = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        for chunk in _extract_text(event):
                            yield chunk
                    return

    # ----- BaseChatModel hooks -----

    def _stream(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> Iterator[ChatGenerationChunk]:
        for piece in self._iter_sse(messages):
            chunk = ChatGenerationChunk(message=AIMessageChunk(content=piece))
            if run_manager:
                run_manager.on_llm_new_token(piece, chunk=chunk)
            yield chunk

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        text = "".join(self._iter_sse(messages))
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])


def _extract_text(event: dict[str, Any]) -> list[str]:
    """Pull text fragments from a Responses-API event.

    The Codex Responses stream emits several event types; the text we want
    appears under ``response.output_text.delta`` events or inside
    ``response.completed.output[].content[].text`` for non-streaming completion
    events. We collect any string we recognise as output text.
    """
    out: list[str] = []
    t = event.get("type")
    if t == "response.output_text.delta":
        delta = event.get("delta")
        if isinstance(delta, str):
            out.append(delta)
    elif t == "response.completed":
        for item in (event.get("response") or {}).get("output") or []:
            for c in item.get("content") or []:
                if c.get("type") in ("output_text", "text") and isinstance(
                    c.get("text"), str
                ):
                    out.append(c["text"])
    return out
