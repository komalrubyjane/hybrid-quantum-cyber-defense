"""Multi-step (beam-search) evaluation against Attack Flow ground truth.

Ground truth: for an observed prefix ``t1..ti`` of a source path, the true H-step
continuation is ``t(i+1)..t(i+H)`` of the SAME path. Because Attack Flow branches, one
(document, prefix) can have several valid continuations; all are kept as a set of
alternatives (this is not an ordering assumption: each alternative is an explicit path).
Instances whose continuation contains ``<UNK>`` are skipped and counted (``<UNK>`` can
never be predicted). Prefixes with fewer than H remaining steps are not H-step instances.

Metrics per instance (beam width B, horizon H):
- ``path_hit@k``: 1 if any of the top-k beam paths equals ANY true continuation exactly.
- ``step{j}_acc``: 1 if step j of the top-1 beam path equals step j of ANY true
  continuation (set-based, branching-aware).
- ``true_path_nll``: mean over true continuations of -log P(continuation | prefix) / H,
  computed by the chain rule on the given continuation (scoring, not generation).

Not evaluated (with reasons, see ``NOT_EVALUATED``): calibrated probability of reaching
Impact/Exfiltration within H steps (beam search yields only a lower bound on that
marginal probability; Monte Carlo rollouts are deferred).
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field

from hqc.prediction.base import NextTechniqueModel
from hqc.prediction.beam_search import BeamPath, beam_search, path_log_probability
from hqc.prediction.dataset import NormalizedSequence
from hqc.prediction.vocabulary import UNK_TOKEN

NOT_EVALUATED: dict[str, str] = {
    "reach_impact_or_exfiltration_probability": (
        "NOT EVALUATED: beam search returns the most likely paths, whose summed probability is "
        "only a lower bound on the marginal probability of reaching a tactic; a calibrated "
        "estimate needs Monte Carlo rollouts or exact enumeration, deferred to a later milestone."
    ),
    "monte_carlo_rollouts": "NOT IMPLEMENTED in Milestone 4 (deferred; see docs/LSTM.md).",
}


@dataclass(frozen=True)
class MultiStepInstance:
    document_id: str
    source_group: str
    prefix: tuple[str, ...]
    futures: tuple[tuple[str, ...], ...]


@dataclass
class MultiStepBuild:
    horizon: int
    by_group: dict[str, list[MultiStepInstance]] = field(default_factory=dict)
    raw_continuations: int = 0
    skipped_unk_continuations: int = 0

    @property
    def instances(self) -> int:
        return sum(len(v) for v in self.by_group.values())


def build_multistep_instances(
    sequences: Sequence[NormalizedSequence], horizon: int
) -> MultiStepBuild:
    if horizon < 1:
        raise ValueError("horizon must be >= 1")
    futures: dict[tuple[str, str, tuple[str, ...]], set[tuple[str, ...]]] = defaultdict(set)
    order: list[tuple[str, str, tuple[str, ...]]] = []
    build = MultiStepBuild(horizon=horizon)
    for seq in sequences:
        tokens = seq.tokens
        for i in range(1, len(tokens) - horizon + 1):
            future = tokens[i : i + horizon]
            build.raw_continuations += 1
            if UNK_TOKEN in future:
                build.skipped_unk_continuations += 1
                continue
            key = (seq.source_group, seq.document_id, tokens[:i])
            if key not in futures:
                order.append(key)
            futures[key].add(future)
    for group, doc, prefix in order:
        build.by_group.setdefault(group, []).append(
            MultiStepInstance(doc, group, prefix, tuple(sorted(futures[(group, doc, prefix)])))
        )
    return build


@dataclass(frozen=True)
class MultiStepScore:
    instance: MultiStepInstance
    metrics: dict[str, float]
    top_paths: tuple[BeamPath, ...]


def multistep_metric_names(horizon: int, hit_ks: Sequence[int]) -> list[str]:
    return (
        [f"path_hit@{k}" for k in hit_ks]
        + [f"step{j}_acc" for j in range(1, horizon + 1)]
        + ["true_path_nll"]
    )


def beam_cache_key(prefix: tuple[str, ...], context_window: int | None) -> tuple[str, ...]:
    """Trailing tokens that fully determine a model's beam (explicit; avoids ``[-0:]``)."""
    if context_window is None:
        return prefix
    if context_window == 0:
        return ()
    return prefix[-context_window:]


def score_multistep(
    model: NextTechniqueModel,
    instances: Sequence[MultiStepInstance],
    horizon: int,
    beam_width: int,
    hit_ks: Sequence[int],
    context_window: int | None,
) -> list[MultiStepScore]:
    """Beam-search every instance. ``context_window`` = how many trailing prefix tokens the
    model uses (None = all); beams are cached per that key (exact, since the generated
    path depends only on those tokens)."""
    if max(hit_ks) > beam_width:
        raise ValueError("hit_ks cannot exceed the beam width")
    cache: dict[tuple[str, ...], list[BeamPath]] = {}
    scores: list[MultiStepScore] = []
    for inst in instances:
        key = beam_cache_key(inst.prefix, context_window)
        paths = cache.get(key)
        if paths is None:
            paths = beam_search(model, inst.prefix, horizon, beam_width)
            cache[key] = paths
        truths = set(inst.futures)
        metrics: dict[str, float] = {}
        for k in hit_ks:
            metrics[f"path_hit@{k}"] = (
                1.0 if any(p.technique_ids in truths for p in paths[:k]) else 0.0
            )
        top = paths[0].technique_ids
        for j in range(horizon):
            metrics[f"step{j + 1}_acc"] = 1.0 if any(f[j] == top[j] for f in truths) else 0.0
        nll = [-path_log_probability(model, inst.prefix, f) / horizon for f in inst.futures]
        metrics["true_path_nll"] = math.fsum(nll) / len(nll)
        scores.append(MultiStepScore(inst, metrics, tuple(paths[:3])))
    return scores
