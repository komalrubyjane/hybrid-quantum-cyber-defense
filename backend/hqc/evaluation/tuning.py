"""Inner leave-one-group-out hyperparameter selection.

:func:`tune` receives ONLY the outer-training groups' data. It never receives the
outer test group, so the held-out group cannot influence any choice. Selection
criterion: mean over inner held-out groups of the per-group mean log loss (lower is
better); ties are resolved by grid order (first wins).
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from hqc.prediction.base import OutputSpace
from hqc.prediction.markov import (
    MAX_SUPPORTED_ORDER,
    InterpolatedMarkovModel,
    MarkovCounts,
    MarkovParams,
)

PairKey = tuple[tuple[str, ...], str]
"""(last <= MAX_SUPPORTED_ORDER prefix tokens, target): all a Markov model can see."""


@dataclass
class GroupData:
    """Per-group training counts and evaluation instances (counted per pair)."""

    counts: MarkovCounts
    eval_pairs: Counter[PairKey] = field(default_factory=Counter)

    @property
    def n_eval(self) -> int:
        return sum(self.eval_pairs.values())


def pair_key(prefix: Sequence[str], target: str) -> PairKey:
    return tuple(prefix[-MAX_SUPPORTED_ORDER:]), target


@dataclass(frozen=True)
class TuningResult:
    selected: MarkovParams
    candidate_scores: tuple[float, ...]
    inner_groups: tuple[str, ...]


def mean_log_loss(model: InterpolatedMarkovModel, pairs: Counter[PairKey]) -> float:
    total = sum(pairs.values())
    if total == 0:
        raise ValueError("No evaluation pairs")
    loss = math.fsum(n * -math.log(model.prob(ctx, target)) for (ctx, target), n in pairs.items())
    return loss / total


def tune(
    grid: Sequence[MarkovParams],
    train_data: Mapping[str, GroupData],
    space: OutputSpace,
    name: str,
) -> TuningResult:
    """Select hyperparameters by inner LOGO over ``train_data`` (training groups only)."""
    if not grid:
        raise ValueError("Empty hyperparameter grid")
    inner_groups = tuple(sorted(g for g, d in train_data.items() if d.n_eval > 0))
    if len(inner_groups) < 2:
        return TuningResult(grid[0], tuple(math.nan for _ in grid), inner_groups)
    per_candidate: list[list[float]] = [[] for _ in grid]
    for held_out in inner_groups:
        counts = MarkovCounts.merge([d.counts for g, d in train_data.items() if g != held_out])
        pairs = train_data[held_out].eval_pairs
        for i, params in enumerate(grid):
            model = InterpolatedMarkovModel(counts, params, space, name)
            per_candidate[i].append(mean_log_loss(model, pairs))
    scores = tuple(math.fsum(v) / len(v) for v in per_candidate)
    best = min(range(len(grid)), key=lambda i: (scores[i], i))
    return TuningResult(grid[best], scores, inner_groups)
