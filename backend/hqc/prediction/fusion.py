"""Markov + LSTM probability fusion.

    P_hybrid(t) = alpha * P_LSTM(t) + (1 - alpha) * P_Markov(t),   0 <= alpha <= 1

The result is renormalised with the shared ``normalize`` routine. ``alpha = 0`` returns
the Markov distribution and ``alpha = 1`` the LSTM distribution exactly (no rounding),
so the two endpoints of the alpha ablation are the component models themselves.
``alpha`` must be chosen on inner validation data only.
"""

from __future__ import annotations

from hqc.prediction.base import Context, NextTechniqueModel, OutputSpace, normalize

HYBRID_NAME = "HYBRID"


class HybridModel:
    def __init__(
        self,
        markov: NextTechniqueModel,
        lstm: NextTechniqueModel,
        alpha: float,
        name: str = HYBRID_NAME,
        context_window: int | None = None,
    ) -> None:
        """``context_window``: trailing tokens both components use (enables caching)."""
        if not 0.0 <= alpha <= 1.0:
            raise ValueError("alpha must be in [0, 1]")
        if markov.space.tokens != lstm.space.tokens:
            raise ValueError("Components must share the same output space")
        self.markov = markov
        self.lstm = lstm
        self.alpha = alpha
        self._name = name
        self._window = context_window
        self._cache: dict[tuple[str, ...], list[float]] = {}

    @property
    def name(self) -> str:
        return self._name

    @property
    def space(self) -> OutputSpace:
        return self.markov.space

    def distribution(self, context: Context) -> list[float]:
        if self.alpha == 0.0:
            return self.markov.distribution(context)
        if self.alpha == 1.0:
            return self.lstm.distribution(context)
        key = tuple(context[-self._window :]) if self._window else None
        if key is not None and key in self._cache:
            return list(self._cache[key])
        p_lstm = self.lstm.distribution(context)
        p_markov = self.markov.distribution(context)
        a = self.alpha
        mixed = normalize(
            [a * pl + (1.0 - a) * pm for pl, pm in zip(p_lstm, p_markov, strict=True)]
        )
        if key is not None:
            self._cache[key] = mixed
        return list(mixed)

    def prob(self, context: Context, target: str) -> float:
        return self.distribution(context)[self.space.position(target)]
