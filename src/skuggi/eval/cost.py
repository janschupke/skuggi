"""Token-cost accounting for the budget dimension.

Turns a turn's usage metadata -- captured out-of-band with LangChain's
``get_usage_metadata_callback`` so ``protocol.structured_invoke`` is never
touched -- into a USD figure via the price table on :class:`~skuggi.config.Settings`.
A model absent from the table is priced at zero (a local Ollama model genuinely
costs nothing) and reported as unknown, so an unpriced model never manufactures
a false budget failure.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from skuggi.config.config import Settings

_PER_MILLION = 1_000_000.0


@dataclass(frozen=True, slots=True)
class CostBreakdown:
    """The cost of one scope of model calls, plus any unpriced model names."""

    usd: float
    input_tokens: int
    output_tokens: int
    unknown_models: tuple[str, ...] = field(default_factory=tuple)


def price_for(settings: Settings, model: str) -> tuple[float, float]:
    """The ``(input, output)`` USD-per-million rate for ``model`` (zero if unknown)."""
    return settings.model_prices.get(model, (0.0, 0.0))


def cost_of_usage(
    settings: Settings, usage: Mapping[str, Mapping[str, int]]
) -> CostBreakdown:
    """Cost a ``{model: {input_tokens, output_tokens, ...}}`` usage map in USD.

    The shape is exactly what ``get_usage_metadata_callback().usage_metadata``
    produces: one entry per model touched during the scope.
    """
    total = 0.0
    in_toks = 0
    out_toks = 0
    unknown: list[str] = []
    for model, counts in usage.items():
        inp = int(counts.get("input_tokens", 0))
        out = int(counts.get("output_tokens", 0))
        in_toks += inp
        out_toks += out
        if model not in settings.model_prices:
            unknown.append(model)
        in_rate, out_rate = price_for(settings, model)
        total += (inp / _PER_MILLION) * in_rate + (out / _PER_MILLION) * out_rate
    return CostBreakdown(
        usd=total,
        input_tokens=in_toks,
        output_tokens=out_toks,
        unknown_models=tuple(unknown),
    )
