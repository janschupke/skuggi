"""The configurable model matrix and the budget price table, for the quality tier.

The quality tier is run against a *matrix* of (provider, model) pairs so the suite
can compare models and treat their divergence as a regression. The matrix and the
judge model are committed in ``evals/models.json`` and overridable from the CLI.

``evals/prices.json`` -- previously a dead documentation snapshot -- is loaded here
into each eval ``Settings.model_prices`` so the budget dimension prices whatever
models the matrix configures, not just the three baked into ``Settings``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from skuggi.config import Provider, Settings

DEFAULT_EVALS_DIR = Path("evals")
_VALID_PROVIDERS: frozenset[str] = frozenset(
    ("openai", "chatgpt", "anthropic", "ollama")
)
_RATE_PAIR = 2  # a price is an [input, output] pair


class ModelsError(RuntimeError):
    """The models or prices config is missing or malformed."""


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """One matrix entry: a provider, a model name, and a stable scorecard label."""

    provider: Provider
    model: str
    label: str


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        msg = f"cannot read {path}: {exc}"
        raise ModelsError(msg) from exc
    except json.JSONDecodeError as exc:
        msg = f"malformed JSON in {path}: {exc}"
        raise ModelsError(msg) from exc


def _spec(entry: object) -> ModelSpec:
    if not isinstance(entry, dict) or "provider" not in entry or "model" not in entry:
        msg = f"model entry must have 'provider' and 'model': {entry!r}"
        raise ModelsError(msg)
    provider = entry["provider"]
    model = entry["model"]
    if provider not in _VALID_PROVIDERS:
        known = sorted(_VALID_PROVIDERS)
        msg = f"unknown provider {provider!r} (expected one of {known})"
        raise ModelsError(msg)
    if not isinstance(model, str) or not model:
        msg = f"model must be a non-empty string: {model!r}"
        raise ModelsError(msg)
    label = entry.get("label") or f"{provider}:{model}"
    return ModelSpec(provider=provider, model=model, label=str(label))


def load_prices(root: Path = DEFAULT_EVALS_DIR) -> dict[str, tuple[float, float]]:
    """Load ``prices.json`` as ``{model: (input_usd, output_usd)}`` per 1M tokens."""
    data = _read_json(root / "prices.json")
    if not isinstance(data, dict) or not isinstance(data.get("prices"), dict):
        msg = "prices.json must be an object with a 'prices' map"
        raise ModelsError(msg)
    out: dict[str, tuple[float, float]] = {}
    for model, rate in data["prices"].items():
        if not isinstance(rate, (list, tuple)) or len(rate) != _RATE_PAIR:
            msg = f"price for {model!r} must be a [input, output] pair"
            raise ModelsError(msg)
        out[str(model)] = (float(rate[0]), float(rate[1]))
    return out


def load_matrix(
    root: Path = DEFAULT_EVALS_DIR,
    *,
    suite: str = "full",
    overrides: Sequence[ModelSpec] | None = None,
) -> tuple[list[ModelSpec], ModelSpec]:
    """Return ``(matrix, judge)`` for ``suite`` from ``models.json``.

    A ``fast`` suite may define its own ``matrix``/``judge`` under a top-level
    ``fast`` key; anything it omits falls back to the top-level config. CLI
    ``overrides`` (paired ``--provider``/``--model``) replace the matrix entirely.
    """
    data = _read_json(root / "models.json")
    if not isinstance(data, dict):
        msg = "models.json must be an object"
        raise ModelsError(msg)

    section: dict[str, object] = dict(data)
    if suite != "full":
        sub = data.get(suite)
        if isinstance(sub, dict):
            section = {**data, **sub}

    raw_matrix = section.get("matrix")
    if not isinstance(raw_matrix, list) or not raw_matrix:
        msg = f"models.json needs a non-empty 'matrix' list (suite {suite!r})"
        raise ModelsError(msg)
    matrix = list(overrides) if overrides else [_spec(e) for e in raw_matrix]

    raw_judge = section.get("judge")
    if not isinstance(raw_judge, dict):
        msg = "models.json needs a 'judge' entry"
        raise ModelsError(msg)
    judge = _spec(raw_judge)
    return matrix, judge


def eval_settings(
    spec: ModelSpec,
    prices: dict[str, tuple[float, float]],
    **overrides: object,
) -> Settings:
    """Build eval ``Settings`` pinned to ``spec`` with ``prices`` merged in.

    The matrix model becomes the active model for its provider, and the committed
    price table overrides the three baked-in defaults so budget is correct for it.
    """
    merged_prices = {**prices}
    return Settings(
        provider=spec.provider,
        model_prices=merged_prices,
        **{f"model_{spec.provider}": spec.model},  # type: ignore[arg-type]
        **overrides,  # type: ignore[arg-type]
    )
