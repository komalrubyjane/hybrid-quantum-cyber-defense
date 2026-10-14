"""Context-free baselines.

- B0 :class:`UniformModel`: every active technique equally likely (chance floor).
- B1 :func:`frequency_model`: smoothed target frequency from the training documents,
  ignoring context. Implemented as the order-0 case of the Markov model so the
  normalisation and smoothing logic exists in exactly one place.
"""

from __future__ import annotations

from hqc.prediction.base import Context, OutputSpace
from hqc.prediction.markov import InterpolatedMarkovModel, MarkovCounts, MarkovParams

UNIFORM_NAME = "B0"
FREQUENCY_NAME = "B1"


class UniformModel:
    """B0: ``P(t) = 1/|outputs|`` for every active technique; ranking ties broken by
    vocabulary-index order (all ties, so the rank equals the output position)."""

    def __init__(self, space: OutputSpace) -> None:
        self._space = space
        self._p = 1.0 / space.size

    @property
    def name(self) -> str:
        return UNIFORM_NAME

    @property
    def space(self) -> OutputSpace:
        return self._space

    def distribution(self, context: Context) -> list[float]:
        return [self._p] * self._space.size

    def prob(self, context: Context, target: str) -> float:
        self._space.position(target)
        return self._p


def frequency_model(
    counts: MarkovCounts, beta: float, space: OutputSpace
) -> InterpolatedMarkovModel:
    """B1: ``P(t) = (U(t) + beta*s/|outputs|) / (N + beta*s)`` (see :mod:`markov`)."""
    # alpha is unused at order 0 (no context levels); any positive value is equivalent.
    params = MarkovParams(max_order=0, weights=(), alpha=1.0, beta=beta)
    return InterpolatedMarkovModel(counts, params, space, FREQUENCY_NAME)
