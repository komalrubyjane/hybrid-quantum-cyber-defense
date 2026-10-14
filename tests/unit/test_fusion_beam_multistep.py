"""Fusion, beam search and multi-step evaluation (toy models with known probabilities)."""

from __future__ import annotations

import math
from collections.abc import Sequence

import pytest

from hqc.evaluation.multistep import (
    NOT_EVALUATED,
    MultiStepInstance,
    beam_cache_key,
    build_multistep_instances,
    multistep_metric_names,
    score_multistep,
)
from hqc.prediction.base import OutputSpace, check_distribution
from hqc.prediction.beam_search import beam_search, path_log_probability
from hqc.prediction.dataset import NormalizedSequence
from hqc.prediction.fusion import HybridModel
from hqc.prediction.vocabulary import UNK_TOKEN
from prediction_fixtures import mini_kb, mini_vocabulary

SPACE = OutputSpace(mini_vocabulary(mini_kb()))  # [T1003, T1059, T1059.001, T1059.004]
A, B, C, D = SPACE.tokens


class TableModel:
    """Next distribution depends only on the last token; records every context it sees."""

    def __init__(
        self, table: dict[str, list[float]], default: list[float], name: str = "toy"
    ) -> None:
        self.table, self.default, self._name = table, default, name
        self.contexts: list[tuple[str, ...]] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def space(self) -> OutputSpace:
        return SPACE

    def distribution(self, context: Sequence[str]) -> list[float]:
        self.contexts.append(tuple(context))
        return list(self.table.get(context[-1], self.default))

    def prob(self, context: Sequence[str], target: str) -> float:
        return self.distribution(context)[SPACE.position(target)]


CHAIN = TableModel(
    {B: [0.6, 0.1, 0.2, 0.1], A: [0.1, 0.1, 0.1, 0.7], D: [0.25, 0.25, 0.25, 0.25]},
    [0.25] * 4,
)


# --- fusion ----------------------------------------------------------------------------------


def test_fusion_endpoints_and_mixture() -> None:
    m = TableModel({}, [0.7, 0.1, 0.1, 0.1])
    l = TableModel({}, [0.1, 0.1, 0.1, 0.7])  # noqa: E741
    assert HybridModel(m, l, 0.0).distribution((B,)) == m.distribution((B,))
    assert HybridModel(m, l, 1.0).distribution((B,)) == l.distribution((B,))
    mid = HybridModel(m, l, 0.25, context_window=1)
    dist = mid.distribution((B,))
    assert dist == pytest.approx([0.55, 0.1, 0.1, 0.25])
    check_distribution(dist, SPACE)
    assert mid.distribution((B,)) == dist  # cached + deterministic
    assert mid.prob((B,), A) == pytest.approx(0.55)
    assert mid.name == "HYBRID" and mid.space is SPACE
    for bad in (-0.1, 1.1):
        with pytest.raises(ValueError):
            HybridModel(m, l, bad)


def test_fusion_requires_same_output_space() -> None:
    class Other(TableModel):
        @property
        def space(self) -> OutputSpace:
            from prediction_fixtures import TechniqueVocabulary

            return OutputSpace(TechniqueVocabulary.from_technique_ids(["T1059"], "0.1"))

    with pytest.raises(ValueError):
        HybridModel(TableModel({}, [0.25] * 4), Other({}, [1.0]), 0.5)


# --- beam search -----------------------------------------------------------------------------


def test_beam_ordering_probabilities_and_lengths() -> None:
    paths = beam_search(CHAIN, (B,), horizon=2, beam_width=3)
    assert [p.rank for p in paths] == [1, 2, 3]
    assert all(p.length == 2 for p in paths)
    assert paths[0].technique_ids == (A, D)  # 0.6 * 0.7 = 0.42
    assert paths[0].log_probability == pytest.approx(math.log(0.42))
    assert paths[0].probability == pytest.approx(0.42)
    logps = [p.log_probability for p in paths]
    assert logps == sorted(logps, reverse=True)
    assert len(beam_search(CHAIN, (B,), horizon=1, beam_width=2)) == 2
    assert len(beam_search(CHAIN, (B,), horizon=3, beam_width=4, top_k=2)) == 2


def test_beam_ties_are_deterministic_by_vocabulary_order() -> None:
    uniform = TableModel({}, [0.25] * 4)
    paths = beam_search(uniform, (B,), horizon=2, beam_width=5)
    assert [p.technique_ids for p in paths] == [(A, A), (A, B), (A, C), (A, D), (B, A)]
    assert paths == beam_search(uniform, (B,), horizon=2, beam_width=5)


def test_beam_uses_only_prefix_and_generated_tokens() -> None:
    model = TableModel(CHAIN.table, CHAIN.default)
    prefix = (C, B)
    paths = beam_search(model, prefix, horizon=3, beam_width=2)
    assert prefix == (C, B)  # observed prefix not modified
    for ctx in model.contexts:
        assert ctx[: len(prefix)] == prefix and len(ctx) - len(prefix) < 3
    generated = {t for p in paths for t in p.technique_ids}
    assert all(set(ctx[len(prefix) :]) <= set(SPACE.tokens) for ctx in model.contexts)
    assert generated


def test_beam_argument_validation() -> None:
    for kwargs in ({"horizon": 0, "beam_width": 1}, {"horizon": 1, "beam_width": 0}):
        with pytest.raises(ValueError):
            beam_search(CHAIN, (B,), **kwargs)
    with pytest.raises(ValueError):
        beam_search(CHAIN, (), horizon=1, beam_width=1)


def test_path_log_probability_chain_rule() -> None:
    assert path_log_probability(CHAIN, (B,), (A, D)) == pytest.approx(math.log(0.6 * 0.7))


# --- multi-step ------------------------------------------------------------------------------


def test_build_multistep_instances() -> None:
    seqs = [
        NormalizedSequence("s1", "doc", "g", (B, A, D, C)),
        NormalizedSequence("s2", "doc", "g", (B, A, C)),  # same prefix (B,), other future
        NormalizedSequence("s3", "doc2", "h", (B, UNK_TOKEN, A)),
    ]
    build = build_multistep_instances(seqs, horizon=2)
    g = build.by_group["g"]
    assert [i.prefix for i in g] == [(B,), (B, A)]
    assert g[0].futures == ((A, C), (A, D))  # both branches kept as alternatives
    assert g[1].futures == ((D, C),)
    assert build.skipped_unk_continuations == 1 and "h" not in build.by_group
    assert build.raw_continuations == 2 + 1 + 1 and build.instances == 2
    with pytest.raises(ValueError):
        build_multistep_instances(seqs, horizon=0)


def test_score_multistep_hand_checked() -> None:
    inst = MultiStepInstance("doc", "g", (B,), ((A, D), (C, B)))
    [score] = score_multistep(
        CHAIN, [inst], horizon=2, beam_width=3, hit_ks=[1, 3], context_window=1
    )
    m = score.metrics
    assert m["path_hit@1"] == 1.0  # top path (A, D) is a true continuation
    assert m["step1_acc"] == 1.0 and m["step2_acc"] == 1.0
    expected_nll = (-math.log(0.6 * 0.7) - math.log(0.2 * 0.25)) / 2 / 2
    assert m["true_path_nll"] == pytest.approx(expected_nll)
    assert set(m) == set(multistep_metric_names(2, [1, 3]))
    miss = MultiStepInstance("doc", "g", (B,), ((C, C),))
    [s2] = score_multistep(CHAIN, [miss], horizon=2, beam_width=3, hit_ks=[1, 3], context_window=1)
    assert s2.metrics["path_hit@1"] == 0.0 and s2.metrics["step1_acc"] == 0.0
    with pytest.raises(ValueError):
        score_multistep(CHAIN, [inst], horizon=2, beam_width=2, hit_ks=[5], context_window=1)


def test_generated_paths_ignore_true_future() -> None:
    """Beams are identical whatever the true continuation is (no ground-truth leakage)."""
    a = MultiStepInstance("d", "g", (C, B), ((A, D),))
    b = MultiStepInstance("d", "g", (C, B), ((D, D),))
    sa = score_multistep(CHAIN, [a], 2, 3, [1], context_window=None)[0]
    sb = score_multistep(CHAIN, [b], 2, 3, [1], context_window=None)[0]
    assert [p.technique_ids for p in sa.top_paths] == [p.technique_ids for p in sb.top_paths]
    assert sa.metrics["path_hit@1"] == 1.0 and sb.metrics["path_hit@1"] == 0.0


def test_beam_cache_key_variants() -> None:
    prefix = (A, B, C)
    assert beam_cache_key(prefix, None) == prefix
    assert beam_cache_key(prefix, 0) == ()
    assert beam_cache_key(prefix, 2) == (B, C)


def test_not_evaluated_reasons_present() -> None:
    assert "NOT EVALUATED" in NOT_EVALUATED["reach_impact_or_exfiltration_probability"]
    assert "monte_carlo_rollouts" in NOT_EVALUATED
