"""Next-technique metrics, macro/micro aggregation and bootstrap intervals.

Definitions (one evaluation instance = one unique (document, prefix, target)):

- Ranking: outputs sorted by probability (descending), ties broken by vocabulary-index
  order. ``rank`` is the 1-based position of the true technique.
- top-k: 1 if rank <= k. MRR: mean of 1/rank.
- Tie-aware variants (diagnostic): the expected top-k hit / reciprocal rank if tied
  outputs were ordered uniformly at random. They matter for B0, where all 697 outputs
  tie and the deterministic rank only reflects technique-ID order.
- log loss: -ln P(true technique) (natural log). Smoothing guarantees P > 0.
- next-tactic accuracy: 1 if the top-1 predicted technique shares AT LEAST ONE ATT&CK
  tactic with the true technique (techniques can belong to several tactics; the
  "any-overlap" rule never invents a single tactic assignment). Techniques without
  tactics count as a miss.

Aggregation: per-group means over instances; MACRO = mean over groups (primary, each
group equal); MICRO = mean over all instances. Bootstrap intervals resample groups.
"""

from __future__ import annotations

import math
import random
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from hqc.prediction.base import OutputSpace

TOP_K_VALUES: tuple[int, ...] = (1, 3, 5)
STORED_TOP_N = 5
METRIC_NAMES: tuple[str, ...] = (
    "top1",
    "top3",
    "top5",
    "mrr",
    "log_loss",
    "tactic_top1",
    "top1_tie_aware",
    "top3_tie_aware",
    "top5_tie_aware",
    "mrr_tie_aware",
)
LOWER_IS_BETTER: frozenset[str] = frozenset({"log_loss"})


@dataclass(frozen=True)
class InstanceScore:
    p_target: float
    rank: int
    n_greater: int
    n_tied: int
    top: tuple[tuple[str, float], ...]
    tactic_hit: bool

    def metrics(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for k in TOP_K_VALUES:
            out[f"top{k}"] = 1.0 if self.rank <= k else 0.0
            out[f"top{k}_tie_aware"] = tie_aware_hit(self.n_greater, self.n_tied, k)
        out["mrr"] = 1.0 / self.rank
        out["mrr_tie_aware"] = tie_aware_reciprocal_rank(self.n_greater, self.n_tied)
        out["log_loss"] = log_loss(self.p_target)
        out["tactic_top1"] = 1.0 if self.tactic_hit else 0.0
        return out


def log_loss(p: float) -> float:
    if not 0.0 < p <= 1.0:
        raise ValueError(f"Probability of the true technique must be in (0, 1], got {p}")
    return -math.log(p)


def tie_aware_hit(n_greater: int, n_tied: int, k: int) -> float:
    """P(rank <= k) when the target is uniformly placed among its ``n_tied`` ties."""
    if n_greater < 0 or n_tied < 0 or k < 1:
        raise ValueError("Invalid tie statistics")
    return min(1.0, max(0.0, (k - n_greater) / (n_tied + 1)))


def tie_aware_reciprocal_rank(n_greater: int, n_tied: int) -> float:
    """Expected 1/rank over ranks n_greater+1 .. n_greater+n_tied+1."""
    ranks = range(n_greater + 1, n_greater + n_tied + 2)
    return math.fsum(1.0 / r for r in ranks) / len(ranks)


def tactics_overlap(predicted: str, true: str, tactics: Mapping[str, Sequence[str]]) -> bool:
    return bool(set(tactics.get(predicted, ())) & set(tactics.get(true, ())))


def score_distribution(
    distribution: Sequence[float],
    space: OutputSpace,
    target: str,
    tactics: Mapping[str, Sequence[str]],
) -> InstanceScore:
    """Score one predicted distribution against the true next technique."""
    target_pos = space.position(target)
    p_target = distribution[target_pos]
    order = sorted(range(space.size), key=lambda i: (-distribution[i], i))
    rank = order.index(target_pos) + 1
    n_greater = sum(1 for p in distribution if p > p_target)
    n_tied = sum(1 for p in distribution if p == p_target) - 1
    top = tuple((space.tokens[i], distribution[i]) for i in order[:STORED_TOP_N])
    return InstanceScore(
        p_target=p_target,
        rank=rank,
        n_greater=n_greater,
        n_tied=n_tied,
        top=top,
        tactic_hit=tactics_overlap(top[0][0], target, tactics),
    )


# --- aggregation ------------------------------------------------------------------------


def mean_metrics(scores: Sequence[InstanceScore]) -> dict[str, float]:
    if not scores:
        raise ValueError("No scores to aggregate")
    per_metric: dict[str, list[float]] = {m: [] for m in METRIC_NAMES}
    for score in scores:
        for name, value in score.metrics().items():
            per_metric[name].append(value)
    return {m: math.fsum(v) / len(v) for m, v in per_metric.items()}


@dataclass(frozen=True)
class Summary:
    mean: float
    std: float
    ci_low: float
    ci_high: float
    n: int


def bootstrap_ci(
    values: Sequence[float], n_resamples: int, seed: int, confidence: float = 0.95
) -> tuple[float, float]:
    """Percentile bootstrap CI of the mean (resampling the given units with replacement).

    Deterministic for a given seed. Uses nearest-rank percentiles.
    """
    if not values:
        raise ValueError("No values to bootstrap")
    if n_resamples < 1 or not 0.0 < confidence < 1.0:
        raise ValueError("Invalid bootstrap configuration")
    rng = random.Random(seed)
    n = len(values)
    means = sorted(math.fsum(rng.choices(values, k=n)) / n for _ in range(n_resamples))
    tail = (1.0 - confidence) / 2.0
    low_index = max(0, math.ceil(tail * n_resamples) - 1)
    high_index = min(n_resamples - 1, math.ceil((1.0 - tail) * n_resamples) - 1)
    return means[low_index], means[high_index]


def summarize(values: Sequence[float], n_resamples: int, seed: int) -> Summary:
    """Mean, sample std (0 for one value) and bootstrap CI over groups."""
    low, high = bootstrap_ci(values, n_resamples, seed)
    std = statistics.stdev(values) if len(values) > 1 else 0.0
    return Summary(math.fsum(values) / len(values), std, low, high, len(values))


@dataclass(frozen=True)
class PairedDifference:
    """Mean of (a - b) over paired groups with a bootstrap CI."""

    mean: float
    ci_low: float
    ci_high: float
    n: int

    @property
    def ci_excludes_zero(self) -> bool:
        return self.ci_low > 0.0 or self.ci_high < 0.0


def paired_difference(
    a: Mapping[str, float], b: Mapping[str, float], n_resamples: int, seed: int
) -> PairedDifference:
    """Paired bootstrap over the groups present in both mappings."""
    groups = sorted(set(a) & set(b))
    diffs = [a[g] - b[g] for g in groups]
    low, high = bootstrap_ci(diffs, n_resamples, seed)
    return PairedDifference(math.fsum(diffs) / len(diffs), low, high, len(diffs))
