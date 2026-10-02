"""The agnostic LLM-judge interface and skuggi's own G-Eval-style factuality judge.

The quality tier needs one subjective call -- "does this answer contain the
expected fact?" -- that a pure oracle cannot make. That is the only thing the old
``autoevals.Factuality`` provided. :class:`LLMJudge` replaces it with skuggi's own
provider-agnostic judge: it grades through the same ``get_chat_model`` factory
and :func:`skuggi.protocol.structured_invoke` seam the agent itself uses,
so any configured provider/model can be the judge and nothing third-party is
contacted. :class:`Judge` is the swap seam -- a future framework adapter
(deepeval, inspect, ...) can implement it without the engine changing.
"""

from __future__ import annotations

from typing import Protocol

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from skuggi.config import Settings
from skuggi.configs import ConfigError
from skuggi.eval.scorers import Score
from skuggi.protocol import structured_invoke
from skuggi.providers import get_chat_model

_DEFAULT_CRITERION = (
    "factual accuracy: whether the answer states the key fact(s) in the "
    "reference, allowing different wording, extra correct detail, and omissions "
    "that do not contradict the reference"
)

_SYSTEM = (
    "You are a strict evaluator scoring a security agent's answer against a "
    "reference answer. Judge only {criterion}. Do not reward fluent prose, "
    "confident tone, or unrelated true statements. Score from 0.0 (contradicts "
    "or misses the key fact) to 1.0 (states the key fact correctly). Set "
    "`passed` true only when the key fact is present and not contradicted."
)

_HUMAN = (
    "Question:\n{prompt}\n\n"
    "Reference answer (ground truth):\n{expected}\n\n"
    "Agent answer to grade:\n{actual}\n\n"
    "Grade the agent answer."
)


class FactualityJudgement(BaseModel):
    """One judge verdict: a graded score, a pass flag, and the reasoning."""

    score: float = Field(ge=0.0, le=1.0)
    passed: bool
    reasoning: str = ""


class Judge(Protocol):
    """The scoring seam the quality tier depends on, independent of any framework."""

    def score(self, *, prompt: str, expected: str, actual: str) -> Score:
        """Grade ``actual`` against ``expected``; return a Score in ``[0, 1]``."""
        ...


class LLMJudge:
    """A G-Eval-style factuality judge built on skuggi's own provider-agnostic model.

    The judge model is built once from ``settings`` (optionally overridden by
    ``model``). A ``chatgpt`` judge is rejected: that endpoint has no native
    structured output, and a judge must return a schema-validated verdict rather
    than fall back to a best-effort JSON contract.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        model: str | None = None,
        criterion: str = _DEFAULT_CRITERION,
    ) -> None:
        if not settings.supports_structured_output():
            msg = (
                f"provider {settings.provider!r} cannot be an eval judge: it has "
                "no native structured output. Use openai, anthropic or ollama."
            )
            raise ConfigError(msg)
        self._llm = get_chat_model(settings, model=model)
        self._model_name = model or settings.model_for(settings.provider)
        self._criterion = criterion

    @property
    def model_name(self) -> str:
        """The resolved judge model name, for scorecard metadata."""
        return self._model_name

    def score(self, *, prompt: str, expected: str, actual: str) -> Score:
        """Grade ``actual`` against ``expected`` and return a factuality Score.

        An empty answer is a 0 without a model call; anything else is graded by
        the live judge (:meth:`_grade`, which needs a provider and so is opt-in).
        """
        if not actual.strip():
            return Score(
                name="factuality",
                score=0.0,
                metadata={"judge_model": self._model_name, "reasoning": "empty answer"},
            )
        return self._grade(prompt, expected, actual)  # pragma: no cover

    def _grade(
        self, prompt: str, expected: str, actual: str
    ) -> Score:  # pragma: no cover
        """Call the live judge model and adapt its verdict into a Score."""
        messages = [
            SystemMessage(content=_SYSTEM.format(criterion=self._criterion)),
            HumanMessage(
                content=_HUMAN.format(prompt=prompt, expected=expected, actual=actual)
            ),
        ]
        verdict = structured_invoke(
            self._llm, FactualityJudgement, messages, native=True
        )
        return Score(
            name="factuality",
            score=verdict.score,
            metadata={
                "judge_model": self._model_name,
                "passed": verdict.passed,
                "reasoning": verdict.reasoning,
            },
        )
