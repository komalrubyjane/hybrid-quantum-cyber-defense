"""Smoothed Markov models over ATT&CK technique sequences (B1, M1, M2).

Notation: ``s`` = mean training weight per instance (so smoothing strengths are in
"pseudo-instances" and comparable across weighting schemes), ``u = 1/|outputs|``.

    P0(t)        = (U(t) + beta*s*u) / (N + beta*s)                   frequency, smoothed to uniform
    Pk(t | c_k)  = (C(c_k, t) + alpha*s*P(k-1)(t)) / (C(c_k) + alpha*s)  if c_k was seen
    Pk(t | c_k)  = P(k-1)(t)                                          if c_k unseen or prefix < k
    P(t | prefix)= sum_k w_k Pk(t | c_k),  k = 1..K,  sum_k w_k = 1    (K = 0 -> P0)

``c_k`` is the last ``k`` tokens of the prefix (``<UNK>`` is an ordinary context token).
Each level is a convex combination of a distribution and the level below, so every
technique keeps non-zero probability and the result is normalised. The fallback order
is therefore: longest seen context -> shorter context -> frequency -> uniform.

Counts are sufficient statistics: tuning only changes ``alpha``, ``beta``, ``K``, ``w``.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

from pydantic import Field, model_validator

from hqc.common.errors import ModelCheckpointNotFoundError
from hqc.common.schemas.base import HQCModel, NonEmptyStr, UTCDatetime, utc_now
from hqc.prediction.base import Context, OutputSpace, normalize
from hqc.prediction.dataset import WeightedInstance
from hqc.prediction.vocabulary import UNK_TOKEN

MAX_SUPPORTED_ORDER = 3
WEIGHT_SUM_TOLERANCE = 1e-9
ContextKey = tuple[str, ...]


class MarkovParams(HQCModel):
    """Hyperparameters. ``max_order = 0`` is the frequency baseline (B1)."""

    max_order: int = Field(ge=0, le=MAX_SUPPORTED_ORDER)
    weights: tuple[float, ...] = Field(description="Interpolation weights w_1..w_K.")
    alpha: float = Field(gt=0.0, allow_inf_nan=False, description="Context smoothing.")
    beta: float = Field(gt=0.0, allow_inf_nan=False, description="Unigram->uniform smoothing.")

    @model_validator(mode="after")
    def _weights_valid(self) -> MarkovParams:
        if len(self.weights) != self.max_order:
            raise ValueError("weights must have exactly max_order entries")
        if any(w < 0.0 for w in self.weights):
            raise ValueError("weights must be non-negative")
        if self.max_order and abs(math.fsum(self.weights) - 1.0) > WEIGHT_SUM_TOLERANCE:
            raise ValueError("weights must sum to 1")
        return self


@dataclass
class MarkovCounts:
    """Weighted sufficient statistics up to ``MAX_SUPPORTED_ORDER``."""

    unigram: dict[str, float] = field(default_factory=dict)
    ngram: dict[ContextKey, dict[str, float]] = field(default_factory=dict)
    context_total: dict[ContextKey, float] = field(default_factory=dict)
    total_weight: float = 0.0
    instances: int = 0

    @classmethod
    def from_instances(cls, instances: Iterable[WeightedInstance]) -> Self:
        unigram: dict[str, float] = defaultdict(float)
        ngram: dict[ContextKey, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        context_total: dict[ContextKey, float] = defaultdict(float)
        total = 0.0
        count = 0
        for instance in instances:
            if instance.target == UNK_TOKEN:
                raise ValueError("<UNK> can never be a training target")
            if instance.weight <= 0.0:
                raise ValueError("Instance weights must be positive")
            unigram[instance.target] += instance.weight
            total += instance.weight
            count += 1
            for k in range(1, min(MAX_SUPPORTED_ORDER, len(instance.prefix)) + 1):
                key = instance.prefix[-k:]
                ngram[key][instance.target] += instance.weight
                context_total[key] += instance.weight
        return cls(
            unigram=dict(unigram),
            ngram={k: dict(v) for k, v in ngram.items()},
            context_total=dict(context_total),
            total_weight=total,
            instances=count,
        )

    @classmethod
    def merge(cls, parts: Sequence[MarkovCounts]) -> Self:
        """Sum of several count tables (e.g. per-group tables of the training groups)."""
        unigram: dict[str, float] = defaultdict(float)
        ngram: dict[ContextKey, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        context_total: dict[ContextKey, float] = defaultdict(float)
        for part in parts:
            for t, w in part.unigram.items():
                unigram[t] += w
            for key, targets in part.ngram.items():
                bucket = ngram[key]
                for t, w in targets.items():
                    bucket[t] += w
            for key, w in part.context_total.items():
                context_total[key] += w
        return cls(
            unigram=dict(unigram),
            ngram={k: dict(v) for k, v in ngram.items()},
            context_total=dict(context_total),
            total_weight=math.fsum(p.total_weight for p in parts),
            instances=sum(p.instances for p in parts),
        )

    @property
    def mean_instance_weight(self) -> float:
        return self.total_weight / self.instances if self.instances else 1.0


class InterpolatedMarkovModel:
    """Fitted smoothed (interpolated, recursively backed-off) Markov model."""

    def __init__(
        self, counts: MarkovCounts, params: MarkovParams, space: OutputSpace, name: str
    ) -> None:
        outside = [t for t in counts.unigram if t not in space.index]
        if outside:
            raise ValueError(f"Training targets outside the output space: {sorted(outside)}")
        self._counts = counts
        self.params = params
        self._space = space
        self._name = name
        self._scale = counts.mean_instance_weight
        self._uniform = 1.0 / space.size
        self._unigram_denominator = counts.total_weight + params.beta * self._scale
        self._p0_vector: list[float] | None = None  # built lazily (tuning uses prob() only)
        self._cache: dict[ContextKey, list[float]] = {}

    @property
    def name(self) -> str:
        return self._name

    @property
    def space(self) -> OutputSpace:
        return self._space

    @property
    def counts(self) -> MarkovCounts:
        return self._counts

    def _p0(self) -> list[float]:
        if self._p0_vector is None:
            smoothing = self.params.beta * self._scale * self._uniform
            self._p0_vector = normalize(
                [self._counts.unigram.get(t, 0.0) + smoothing for t in self._space.tokens]
            )
        return self._p0_vector

    # --- scalar path (used for tuning) ---------------------------------------------

    def _p0_scalar(self, target: str) -> float:
        smoothed = self._counts.unigram.get(target, 0.0) + (
            self.params.beta * self._scale * self._uniform
        )
        return smoothed / self._unigram_denominator

    def prob(self, context: Context, target: str) -> float:
        self._space.position(target)  # validates target
        level = self._p0_scalar(target)
        if self.params.max_order == 0:
            return level
        alpha_s = self.params.alpha * self._scale
        mixture = 0.0
        for k in range(1, self.params.max_order + 1):
            if len(context) >= k:
                key = tuple(context[-k:])
                total = self._counts.context_total.get(key, 0.0)
                if total > 0.0:
                    count = self._counts.ngram[key].get(target, 0.0)
                    level = (count + alpha_s * level) / (total + alpha_s)
            mixture += self.params.weights[k - 1] * level
        return mixture

    # --- vector path (used for ranking) ----------------------------------------------

    def distribution(self, context: Context) -> list[float]:
        key = tuple(context[-self.params.max_order :]) if self.params.max_order else ()
        cached = self._cache.get(key)
        if cached is not None:
            return list(cached)
        level = self._p0()
        if self.params.max_order == 0:
            result = list(level)
        else:
            alpha_s = self.params.alpha * self._scale
            mixture = [0.0] * self._space.size
            for k in range(1, self.params.max_order + 1):
                if len(key) >= k:
                    ctx = key[-k:]
                    total = self._counts.context_total.get(ctx, 0.0)
                    if total > 0.0:
                        denominator = total + alpha_s
                        nxt = [alpha_s * p / denominator for p in level]
                        for target, count in self._counts.ngram[ctx].items():
                            nxt[self._space.index[target]] += count / denominator
                        level = nxt
                weight = self.params.weights[k - 1]
                if weight:
                    mixture = [m + weight * p for m, p in zip(mixture, level, strict=True)]
            result = normalize(mixture)  # removes accumulated rounding only
        self._cache[key] = result
        return list(result)


# --- persistence ----------------------------------------------------------------------


class MarkovModelMetadata(HQCModel):
    """Model card stored next to a saved model."""

    model_type: NonEmptyStr
    model_name: NonEmptyStr
    training_dataset: NonEmptyStr
    dataset_version: NonEmptyStr
    attack_version: NonEmptyStr
    vocabulary_version: NonEmptyStr
    weighting: NonEmptyStr
    features: NonEmptyStr = "last K ATT&CK technique tokens of the observed prefix"
    hyperparameters: MarkovParams
    training_groups: list[str]
    trained_at: UTCDatetime = Field(default_factory=utc_now)
    seed: int
    evaluation_run_id: str | None = None
    evaluation_summary: dict[str, float] = Field(default_factory=dict)
    notes: str | None = None


class MarkovModelArtifact(HQCModel):
    metadata: MarkovModelMetadata
    unigram: dict[str, float]
    ngram: list[tuple[list[str], dict[str, float]]]
    context_total: list[tuple[list[str], float]]
    total_weight: float
    instances: int

    @classmethod
    def from_model(
        cls, model: InterpolatedMarkovModel, metadata: MarkovModelMetadata
    ) -> MarkovModelArtifact:
        counts = model.counts
        return cls(
            metadata=metadata,
            unigram=dict(sorted(counts.unigram.items())),
            ngram=[(list(k), dict(sorted(v.items()))) for k, v in sorted(counts.ngram.items())],
            context_total=[(list(k), v) for k, v in sorted(counts.context_total.items())],
            total_weight=counts.total_weight,
            instances=counts.instances,
        )

    def to_model(self, space: OutputSpace) -> InterpolatedMarkovModel:
        if space.vocabulary_version != self.metadata.vocabulary_version:
            raise ValueError("Model was trained with a different vocabulary")
        counts = MarkovCounts(
            unigram=self.unigram,
            ngram={tuple(k): v for k, v in self.ngram},
            context_total={tuple(k): v for k, v in self.context_total},
            total_weight=self.total_weight,
            instances=self.instances,
        )
        return InterpolatedMarkovModel(
            counts, self.metadata.hyperparameters, space, self.metadata.model_name
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=1) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> MarkovModelArtifact:
        if not path.is_file():
            raise ModelCheckpointNotFoundError(f"No saved Markov model at {path}")
        return cls.model_validate_json(path.read_text(encoding="utf-8"))
