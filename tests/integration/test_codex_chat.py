"""L2: the codex request contract, against a mocked transport.

Real ChatOpenAI, real openai SDK, real SSE framing -- only the socket is fake.
That is what makes these assertions meaningful: they pin the bytes the codex
endpoint will actually receive.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from langchain_core.messages import HumanMessage

from skuggi.agent.protocol import CriticResponse, structured_invoke
from skuggi.providers.codex_chat import (
    CodexAuthError,
    CodexTokenStore,
    build_codex_chat_model,
    jwt_expiry,
)

pytestmark = pytest.mark.mock_http

RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses"
REFRESH_URL = "https://auth.openai.com/oauth/token"


def _sse(*chunks: str) -> str:
    events = [
        {"type": "response.created", "response": {"id": "r1", "output": []}},
        *[
            {"type": "response.output_text.delta", "delta": chunk, "output_index": 0}
            for chunk in chunks
        ],
        {
            "type": "response.completed",
            "response": {
                "id": "r1",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "".join(chunks)}],
                    }
                ],
            },
        },
    ]
    return "".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n"


def _auth_json(tmp_path: Path, access: str = "tok-initial") -> Path:
    path = tmp_path / "codex" / "auth.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": None,
                "tokens": {
                    "access_token": access,
                    "refresh_token": "refresh-me",
                    "account_id": "acct-1",
                },
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


@respx.mock
def test_request_lands_on_the_codex_url_with_codex_headers(tmp_path: Path) -> None:
    route = respx.post(RESPONSES_URL).mock(
        return_value=httpx.Response(
            200, text=_sse("Hi"), headers={"content-type": "text/event-stream"}
        )
    )
    model = build_codex_chat_model("gpt-5", auth_path=_auth_json(tmp_path))

    model.invoke("hello")

    assert route.called
    request = route.calls.last.request
    assert str(request.url) == RESPONSES_URL, "route is under /codex, no /v1 inserted"
    assert request.headers["authorization"] == "Bearer tok-initial"
    assert request.headers["accept"] == "text/event-stream"
    assert request.headers["originator"] == "codex_cli_rs"
    assert request.headers["chatgpt-account-id"] == "acct-1"
    assert request.headers["x-codex-turn-state"]
    assert request.headers["x-codex-window-id"]


@respx.mock
def test_body_matches_the_codex_shape(tmp_path: Path) -> None:
    route = respx.post(RESPONSES_URL).mock(
        return_value=httpx.Response(
            200, text=_sse("ok"), headers={"content-type": "text/event-stream"}
        )
    )
    model = build_codex_chat_model("gpt-5", auth_path=_auth_json(tmp_path))

    model.invoke(
        [("system", "Be terse."), ("human", "hi")],
    )

    body = json.loads(route.calls.last.request.content)
    assert body["model"] == "gpt-5"
    assert body["store"] is False
    assert body["parallel_tool_calls"] is False
    assert body["tools"] == []
    assert "Be terse." in body["instructions"], "system prompt belongs in instructions"
    roles = [e.get("role") for e in body["input"] if isinstance(e, dict)]
    assert "system" not in roles, "codex takes no system entry inside input"
    assert "user" in roles


@respx.mock
def test_reply_is_not_duplicated(tmp_path: Path) -> None:
    """The old client summed output_text.delta AND response.completed.

    The Responses stream emits both, so every chatgpt reply came back twice.
    """
    respx.post(RESPONSES_URL).mock(
        return_value=httpx.Response(
            200,
            text=_sse("Hel", "lo"),
            headers={"content-type": "text/event-stream"},
        )
    )
    model = build_codex_chat_model("gpt-5", auth_path=_auth_json(tmp_path))

    assert model.invoke("hi").text == "Hello"


@respx.mock
def test_401_refreshes_and_replays(tmp_path: Path) -> None:
    path = _auth_json(tmp_path, access="stale")
    refresh = respx.post(REFRESH_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "fresh"})
    )
    route = respx.post(RESPONSES_URL).mock(
        side_effect=[
            httpx.Response(401, json={"error": "expired"}),
            httpx.Response(
                200, text=_sse("done"), headers={"content-type": "text/event-stream"}
            ),
        ]
    )
    model = build_codex_chat_model("gpt-5", auth_path=path)

    assert model.invoke("hi").text == "done"
    assert route.call_count == 2
    assert refresh.called
    assert route.calls[0].request.headers["authorization"] == "Bearer stale"
    assert route.calls[1].request.headers["authorization"] == "Bearer fresh"
    assert json.loads(path.read_text())["tokens"]["access_token"] == "fresh"


@respx.mock
def test_refresh_keeps_auth_json_private(tmp_path: Path) -> None:
    path = _auth_json(tmp_path, access="stale")
    respx.post(REFRESH_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "fresh"})
    )

    CodexTokenStore(path, refresh_url=REFRESH_URL).refresh()

    assert path.stat().st_mode & 0o777 == 0o600


@respx.mock
def test_refresh_failure_is_actionable(tmp_path: Path) -> None:
    respx.post(REFRESH_URL).mock(return_value=httpx.Response(400, json={}))
    store = CodexTokenStore(_auth_json(tmp_path), refresh_url=REFRESH_URL)

    with pytest.raises(CodexAuthError, match="login"):
        store.refresh()


def test_missing_auth_json_is_actionable(tmp_path: Path) -> None:
    store = CodexTokenStore(tmp_path / "nope.json")
    with pytest.raises(CodexAuthError, match="login"):
        store.access_token()


def test_auth_json_without_tokens_is_actionable(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    path.write_text(json.dumps({"auth_mode": "ApiKey"}), encoding="utf-8")
    with pytest.raises(CodexAuthError, match="no ChatGPT tokens"):
        CodexTokenStore(path).access_token()


@pytest.mark.parametrize("token", ["", "a", "a.b", "....", "a.!!!.c"])
def test_jwt_expiry_tolerates_malformed_tokens(token: str) -> None:
    assert jwt_expiry(token) is None


def _sse_with_reasoning(text: str) -> str:
    """An SSE stream whose output carries a reasoning item before the text item.

    A reasoning model (gpt-6-luna) returns `.content` as a list of blocks, not a
    string -- the condition that crashed the non-native structured-output path.
    """
    events = [
        {"type": "response.created", "response": {"id": "r1", "output": []}},
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {"type": "reasoning", "id": "rs_abc", "summary": []},
        },
        {
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {"type": "reasoning", "id": "rs_abc", "summary": []},
        },
        {"type": "response.output_text.delta", "delta": text, "output_index": 1},
        {
            "type": "response.completed",
            "response": {
                "id": "r1",
                "output": [
                    {"type": "reasoning", "id": "rs_abc", "summary": []},
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": text}],
                    },
                ],
            },
        },
    ]
    return "".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n"


@respx.mock
def test_structured_invoke_parses_a_reasoning_models_block_content(
    tmp_path: Path,
) -> None:
    # End-to-end against the real CodexChatModel wiring: a reasoning model returns
    # list-shaped content, and structured_invoke(native=False) must still parse the
    # JSON text block out of it -- this is the real planner crash the user hit.
    respx.post(RESPONSES_URL).mock(
        return_value=httpx.Response(
            200,
            text=_sse_with_reasoning('{"approved": true, "reason": "ok"}'),
            headers={"content-type": "text/event-stream"},
        )
    )
    model = build_codex_chat_model("gpt-6-luna", auth_path=_auth_json(tmp_path))

    out = structured_invoke(
        model, CriticResponse, [HumanMessage(content="ok?")], native=False
    )

    assert out == CriticResponse(approved=True, reason="ok")
