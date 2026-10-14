"""Deterministic beam search for multi-step attack-path prediction.

At step ``s`` every partial path is extended with every output technique using
``model.distribution(observed_prefix + generated_path)``: ONLY the observed prefix and
previously generated techniques are ever used as context; nothing from a true future is
injected. Paths are scored by cumulative log probability. Ties are broken by the
sequence of output positions (vocabulary-index order), so results are deterministic.
Repeated techniques are allowed (real Attack Flow paths repeat techniques).
"""

from __future__ import annotations

import heapq
import math
from collections.abc import Sequence
from dataclasses import dataclass

from hqc.prediction.base import NextTechniqueModel


@dataclass(frozen=True)
class BeamPath:
    technique_ids: tuple[str, ...]
    log_probability: float
    rank: int

    @property
    def probability(self) -> float:
        return math.exp(self.log_probability)

    @property
    def length(self) -> int:
        return len(self.technique_ids)


def beam_search(
    model: NextTechniqueModel,
    observed_prefix: Sequence[str],
    horizon: int,
    beam_width: int,
    top_k: int | None = None,
) -> list[BeamPath]:
    """Return up to ``top_k`` (default ``beam_width``) paths of exactly ``horizon`` steps."""
    if horizon < 1 or beam_width < 1:
        raise ValueError("horizon and beam_width must be >= 1")
    if not observed_prefix:
        raise ValueError("Beam search needs at least one observed technique")
    prefix = tuple(observed_prefix)  # never mutated
    tokens = model.space.tokens
    # Each beam: (path as output positions, cumulative log probability).
    beams: list[tuple[tuple[int, ...], float]] = [((), 0.0)]
    for _ in range(horizon):
        candidates: list[tuple[float, tuple[int, ...]]] = []
        for path, logp in beams:
            context = prefix + tuple(tokens[i] for i in path)
            distribution = model.distribution(context)
            for position, p in enumerate(distribution):
                if p > 0.0:
                    candidates.append((logp + math.log(p), (*path, position)))
        best = heapq.nsmallest(beam_width, candidates, key=lambda c: (-c[0], c[1]))
        beams = [(path, logp) for logp, path in best]
    keep = beams[: top_k if top_k is not None else beam_width]
    return [
        BeamPath(tuple(tokens[i] for i in path), logp, rank)
        for rank, (path, logp) in enumerate(keep, start=1)
    ]


def path_log_probability(
    model: NextTechniqueModel, observed_prefix: Sequence[str], path: Sequence[str]
) -> float:
    """log P(path | prefix) by the chain rule (scores a given path; generates nothing)."""
    context = list(observed_prefix)
    total = 0.0
    for technique in path:
        total += math.log(model.prob(context, technique))
        context.append(technique)
    return total
