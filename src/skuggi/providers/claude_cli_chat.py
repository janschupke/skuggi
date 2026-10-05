"""Claude CLI chat model: drive the operator's local ``claude`` binary headless.

Anthropic prohibits third-party use of Claude subscription OAuth tokens (and
blocks them), so skuggi cannot do a codex-style subscription login for Claude.
The legitimate way to use a Claude Pro/Max subscription from another tool is to
shell out to the operator's own installed Claude Code CLI, which carries its own
credentials. This model does exactly that: it flattens the conversation into a
single headless ``claude -p`` call and returns the final text.

It is a *tool-less* provider (``Settings.supports_structured_output`` returns
False for ``claude-cli``), so ``protocol.structured_invoke`` drives it through
the JSON-contract text path rather than ``with_structured_output``. Streaming is
not overridden: ``BaseChatModel.stream`` falls back to ``_generate``, so a turn
renders as one chunk -- correct, just not token-by-token.

Headless invocation (see https://docs.claude.com/en/docs/claude-code/headless):
    claude -p "<prompt>" --output-format json [--model <m>] [--append-system-prompt <s>]
"""

from __future__ import annotations

import json
import shutil
import subprocess

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.messages.ai import UsageMetadata
from langchain_core.outputs import ChatGeneration, ChatResult

from skuggi.common.logs import get_logger
from skuggi.config.config import LLM_RESPONSE_TIMEOUT_S

log = get_logger(__name__)

_BINARY = "claude"
_TIMEOUT_S = LLM_RESPONSE_TIMEOUT_S


class ClaudeCliError(RuntimeError):
    """The ``claude`` binary is missing, not logged in, or failed a call."""


def claude_binary() -> str | None:
    """The path to the ``claude`` executable on PATH, or ``None`` if absent."""
    return shutil.which(_BINARY)


def is_available() -> bool:
    """Whether the ``claude`` CLI is installed (no login or network check)."""
    return claude_binary() is not None


def _text(content: object) -> str:
    """Flatten a message's content (str or a list of parts) to plain text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            str(part.get("text", "")) if isinstance(part, dict) else str(part)
            for part in content
        ]
        return "".join(parts)
    return str(content)


def _split_messages(messages: list[BaseMessage]) -> tuple[str, str]:
    """Split messages into (system prompt, flattened conversation transcript)."""
    system: list[str] = []
    convo: list[str] = []
    for message in messages:
        text = _text(message.content)
        if not text:
            continue
        if message.type == "system":
            system.append(text)
        elif message.type == "human":
            convo.append(f"User: {text}")
        elif message.type == "ai":
            convo.append(f"Assistant: {text}")
        else:
            convo.append(text)
    return "\n\n".join(system), "\n\n".join(convo)


class ClaudeCliChatModel(BaseChatModel):
    """A chat model that runs the local ``claude`` CLI headlessly."""

    model: str = "haiku"
    binary: str = _BINARY
    timeout_s: float = _TIMEOUT_S

    @property
    def _llm_type(self) -> str:
        return "claude-cli"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,  # noqa: ARG002 -- CLI has no stop support
        run_manager: CallbackManagerForLLMRun | None = None,  # noqa: ARG002
        **kwargs: object,  # noqa: ARG002 -- generic BaseChatModel hook
    ) -> ChatResult:
        system, prompt = _split_messages(messages)
        # The transcript is passed on STDIN, not as an argv positional: a long
        # pentest conversation would otherwise exceed ARG_MAX and raise OSError
        # (E2BIG). `claude -p` with no positional reads the prompt from stdin.
        # Tools are disabled (`--allowedTools ""`): the prompt carries untrusted
        # scan/web output, and this is a text-only planner -- it must never be able
        # to drive the operator's own Claude Code tools outside skuggi's guard.
        argv = [
            self.binary,
            "-p",
            "--output-format",
            "json",
            "--model",
            self.model,
            "--allowedTools",
            "",
        ]
        if system:
            argv += ["--append-system-prompt", system]
        try:
            proc = subprocess.run(  # noqa: S603 -- fixed argv, no shell
                argv,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                check=False,
            )
        except FileNotFoundError as exc:
            msg = (
                f"the {self.binary!r} CLI is not installed. Install Claude Code and "
                "run `claude /login`, or `/setup` a different provider."
            )
            raise ClaudeCliError(msg) from exc
        except subprocess.TimeoutExpired as exc:
            msg = f"the {self.binary!r} CLI timed out after {self.timeout_s:g}s"
            raise ClaudeCliError(msg) from exc
        except OSError as exc:  # E2BIG and other spawn failures are not a crash
            msg = f"the {self.binary!r} CLI could not be run: {exc}"
            raise ClaudeCliError(msg) from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            msg = f"the {self.binary!r} CLI failed (exit {proc.returncode}): {detail}"
            raise ClaudeCliError(msg)
        text, usage = _parse_result(proc.stdout)
        message = AIMessage(content=text, usage_metadata=usage)
        return ChatResult(generations=[ChatGeneration(message=message)])


def _parse_result(stdout: str) -> tuple[str, UsageMetadata | None]:
    """Extract the ``result`` text and token usage from a json-format reply.

    The ``--output-format json`` reply carries a ``usage`` block; surfacing it as
    ``usage_metadata`` means cost accounting (``eval.cost``) sees real tokens
    rather than silently reading zero for every claude-cli turn.
    """
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        msg = "the claude CLI returned output that was not JSON"
        raise ClaudeCliError(msg) from exc
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, str):
        msg = "the claude CLI reply had no 'result' text"
        raise ClaudeCliError(msg)
    return result, _usage_of(payload)


def _usage_of(payload: dict[str, object]) -> UsageMetadata | None:
    """Map the CLI reply's ``usage`` block to a LangChain ``UsageMetadata``."""
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return None
    inp = int(usage.get("input_tokens", 0) or 0)
    out = int(usage.get("output_tokens", 0) or 0)
    return UsageMetadata(input_tokens=inp, output_tokens=out, total_tokens=inp + out)


def build_claude_cli_chat_model(model: str) -> ClaudeCliChatModel:
    """Assemble a ClaudeCliChatModel for `model`, checking the binary is present."""
    binary = claude_binary()
    if binary is None:
        msg = (
            "the 'claude' CLI is not installed. Install Claude Code and run "
            "`claude /login`, or run `/setup` to pick a different provider."
        )
        raise ClaudeCliError(msg)
    return ClaudeCliChatModel(model=model, binary=binary)
