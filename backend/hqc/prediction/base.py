"""Shared prediction primitives: output space, normalisation, model protocol.

Every next-technique model predicts a distribution over the same OUTPUT SPACE: the
active ATT&CK techniques of the committed vocabulary, in vocabulary-index order.
``<PAD>`` and ``<UNK>`` are never outputs. Ties in ranking are broken by this order.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Protocol

from hqc.prediction.vocabulary import SPECIAL_TOKENS, UNK_TOKEN, TechniqueVocabulary

PROBABILITY_TOLERANCE = 1e-12
"""Allowed deviation of ``math.fsum(distribution)`` from 1 (floating-point rounding)."""

Context = Sequence[str]
"""An observed prefix of vocabulary tokens (technique IDs or ``<UNK>``), oldest first."""


class OutputSpace:
    """The ordered set of predictable techniques (vocabulary minus special tokens)."""

    def __init__(self, vocabulary: TechniqueVocabulary) -> None:
        self.vocabulary_version = vocabulary.vocabulary_version
        self.tokens: tuple[str, ...] = tuple(vocabulary.index_to_token[len(SPECIAL_TOKENS) :])
        self.index: dict[str, int] = {t: i for i, t in enumerate(self.tokens)}

    @property
    def size(self) -> int:
        return len(self.tokens)

    def position(self, technique_id: str) -> int:
        """Output position of a technique; raises KeyError for non-predictable tokens."""
        if technique_id == UNK_TOKEN or technique_id in SPECIAL_TOKENS:
            raise KeyError(f"{technique_id} is not a predictable output")
        return self.index[technique_id]

    def __contains__(self, token: object) -> bool:
        return isinstance(token, str) and token in self.index


def normalize(weights: Sequence[float]) -> list[float]:
    """Scale non-negative finite weights to a probability distribution (``math.fsum``).

    The single normalisation routine used by every model.
    """
    if not weights:
        raise ValueError("Cannot normalise an empty weight vector")
    if any(not math.isfinite(w) or w < 0.0 for w in weights):
        raise ValueError("Weights must be finite and non-negative")
    total = math.fsum(weights)
    if total <= 0.0:
        raise ValueError("Weights sum to zero")
    return [w / total for w in weights]


def check_distribution(distribution: Sequence[float], space: OutputSpace) -> None:
    """Raise ValueError unless ``distribution`` is a valid distribution over ``space``."""
    if len(distribution) != space.size:
        raise ValueError(f"Distribution has {len(distribution)} entries, expected {space.size}")
    if any(not math.isfinite(p) or p < 0.0 for p in distribution):
        raise ValueError("Distribution contains negative or non-finite values")
    if abs(math.fsum(distribution) - 1.0) > PROBABILITY_TOLERANCE:
        raise ValueError("Distribution does not sum to 1")


class NextTechniqueModel(Protocol):
    """A fitted next-technique predictor over an :class:`OutputSpace`."""

    @property
    def name(self) -> str: ...

    @property
    def space(self) -> OutputSpace: ...

    def distribution(self, context: Context) -> list[float]:
        """P(next | context) for every output, aligned with ``space.tokens``."""
        ...

    def prob(self, context: Context, target: str) -> float:
        """P(target | context) for one predictable technique."""
        ...
