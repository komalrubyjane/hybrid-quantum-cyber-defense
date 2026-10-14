"""Baselines and smoothed Markov models, checked against hand-calculated values.

Output space (mini KB): [T1003, T1059, T1059.001, T1059.004]  (u = 1/4).
Training instances (weight 1 each, s = 1):
    (T1059) -> T1003  x2,  (T1059) -> T1059.004,  (T1003) -> T1059
Unigram U: T1003 2, T1059 1, T1059.004 1; N = 4.
P0 with beta = 1:  (U + 0.25) / 5  -> [0.45, 0.25, 0.05, 0.25]
P1 with alpha = 1 for context (T1059), total 3:  (C + P0) / 4
    -> [0.6125, 0.0625, 0.0125, 0.3125]
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest
from pydantic import ValidationError

from hqc.common.errors import ModelCheckpointNotFoundError
from hqc.prediction.base import OutputSpace, check_distribution, normalize
from hqc.prediction.baselines import UniformModel, frequency_model
from hqc.prediction.dataset import WeightedInstance
from hqc.prediction.markov import (
    InterpolatedMarkovModel,
    MarkovCounts,
    MarkovModelArtifact,
    MarkovModelMetadata,
    MarkovParams,
)
from hqc.prediction.vocabulary import UNK_TOKEN, TechniqueVocabulary
from prediction_fixtures import mini_kb, mini_vocabulary

P0 = [0.45, 0.25, 0.05, 0.25]
P1_T1059 = [0.6125, 0.0625, 0.0125, 0.3125]


@pytest.fixture(scope="module")
def vocab() -> TechniqueVocabulary:
    return mini_vocabulary(mini_kb())


@pytest.fixture(scope="module")
def space(vocab: TechniqueVocabulary) -> OutputSpace:
    return OutputSpace(vocab)


@pytest.fixture
def counts() -> MarkovCounts:
    return MarkovCounts.from_instances(
        [
            WeightedInstance(("T1059",), "T1003", 1.0),
            WeightedInstance(("T1059",), "T1003", 1.0),
            WeightedInstance(("T1059",), "T1059.004", 1.0),
            WeightedInstance(("T1003",), "T1059", 1.0),
        ]
    )


def m1(counts: MarkovCounts, space: OutputSpace, alpha: float = 1.0) -> InterpolatedMarkovModel:
    return InterpolatedMarkovModel(
        counts, MarkovParams(max_order=1, weights=(1.0,), alpha=alpha, beta=1.0), space, "M1"
    )


# --- shared primitives ----------------------------------------------------------------------


def test_output_space_excludes_special_tokens(space: OutputSpace) -> None:
    assert space.tokens == ("T1003", "T1059", "T1059.001", "T1059.004")
    assert space.size == 4 and "T1059" in space and UNK_TOKEN not in space
    with pytest.raises(KeyError):
        space.position(UNK_TOKEN)
    with pytest.raises(KeyError):
        space.position("<PAD>")


def test_normalize_and_check(space: OutputSpace) -> None:
    assert normalize([1.0, 3.0]) == [0.25, 0.75]
    for bad in ([], [0.0, 0.0], [-1.0, 2.0], [math.inf]):
        with pytest.raises(ValueError):
            normalize(bad)
    check_distribution([0.25] * 4, space)
    for bad_dist in ([0.5, 0.5], [0.5, 0.5, 0.5, -0.5], [0.3] * 4):
        with pytest.raises(ValueError):
            check_distribution(bad_dist, space)


# --- B0 / B1 ------------------------------------------------------------------------------


def test_uniform_baseline(space: OutputSpace) -> None:
    model = UniformModel(space)
    dist = model.distribution(("T1059",))
    assert dist == [0.25] * 4 and model.name == "B0" and model.space is space
    assert model.prob((), "T1059.004") == 0.25
    check_distribution(dist, space)
    with pytest.raises(KeyError):
        model.prob((), UNK_TOKEN)


def test_frequency_baseline_hand_calculated(counts: MarkovCounts, space: OutputSpace) -> None:
    model = frequency_model(counts, beta=1.0, space=space)
    assert model.name == "B1"
    assert model.distribution(("anything",)) == pytest.approx(P0)
    assert model.distribution(()) == model.distribution(("T1003", "T1059"))  # context ignored
    assert model.prob(("T1059",), "T1003") == pytest.approx(0.45)
    check_distribution(model.distribution(()), space)


def test_frequency_smoothing_limits(counts: MarkovCounts, space: OutputSpace) -> None:
    near_uniform = frequency_model(counts, beta=1e9, space=space).distribution(())
    assert near_uniform == pytest.approx([0.25] * 4, abs=1e-6)
    sharp = frequency_model(counts, beta=1e-9, space=space).distribution(())
    assert sharp == pytest.approx([0.5, 0.25, 0.0, 0.25], abs=1e-6)
    assert min(sharp) > 0.0  # still never exactly zero


# --- M1 / M2 ------------------------------------------------------------------------------


def test_first_order_hand_calculated(counts: MarkovCounts, space: OutputSpace) -> None:
    model = m1(counts, space)
    assert model.distribution(("T1059",)) == pytest.approx(P1_T1059)
    for target, expected in zip(space.tokens, P1_T1059, strict=True):
        assert model.prob(("T1003", "T1059"), target) == pytest.approx(expected)
    assert math.fsum(model.distribution(("T1059",))) == pytest.approx(1.0, abs=1e-12)


def test_unseen_transition_nonzero_and_unseen_context_falls_back(
    counts: MarkovCounts, space: OutputSpace
) -> None:
    model = m1(counts, space)
    unseen = model.prob(("T1059",), "T1059.001")
    assert unseen == pytest.approx(0.0125)
    assert unseen > 0.0
    # Context never seen (T1059.001) -> frequency level P0; <UNK> context likewise.
    assert model.distribution(("T1059.001",)) == pytest.approx(P0)
    assert model.distribution((UNK_TOKEN,)) == pytest.approx(P0)
    assert model.distribution(()) == pytest.approx(P0)  # empty prefix


def test_smoothing_strength_moves_toward_lower_order(
    counts: MarkovCounts, space: OutputSpace
) -> None:
    weak = m1(counts, space, alpha=0.01).distribution(("T1059",))
    strong = m1(counts, space, alpha=1e6).distribution(("T1059",))
    assert strong == pytest.approx(P0, abs=1e-5)
    assert weak[0] > P1_T1059[0] > strong[0]


def test_variable_order_interpolation(counts: MarkovCounts, space: OutputSpace) -> None:
    trigram_counts = MarkovCounts.from_instances(
        [WeightedInstance(("T1003", "T1059"), "T1059.004", 1.0)]
    )
    merged = MarkovCounts.merge([counts, trigram_counts])
    params = MarkovParams(max_order=2, weights=(0.5, 0.5), alpha=1.0, beta=1.0)
    model = InterpolatedMarkovModel(merged, params, space, "M2")
    dist = model.distribution(("T1003", "T1059"))
    check_distribution(dist, space)
    # Unseen order-2 context falls back to order 1: mixture equals the order-1 level.
    unseen = model.distribution(("T1059.004", "T1059"))
    only_m1 = m1(merged, space).distribution(("T1059",))
    assert unseen == pytest.approx(only_m1)
    # Seen order-2 context raises the observed continuation above the order-1 estimate.
    assert dist[space.index["T1059.004"]] > only_m1[space.index["T1059.004"]]
    for target in space.tokens:
        assert model.prob(("T1003", "T1059"), target) == pytest.approx(dist[space.index[target]])


def test_deterministic_inference(counts: MarkovCounts, space: OutputSpace) -> None:
    a = m1(counts, space).distribution(("T1059",))
    b = m1(
        MarkovCounts.from_instances(
            [
                WeightedInstance(("T1003",), "T1059", 1.0),
                WeightedInstance(("T1059",), "T1059.004", 1.0),
                WeightedInstance(("T1059",), "T1003", 1.0),
                WeightedInstance(("T1059",), "T1003", 1.0),
            ]
        ),
        space,
    ).distribution(("T1059",))
    assert a == pytest.approx(b, abs=1e-15)
    model = m1(counts, space)
    assert model.distribution(("T1059",)) == model.distribution(("T1059",))  # cache-safe copy


def test_weights_scale_invariance(space: OutputSpace) -> None:
    """Smoothing is in pseudo-instances: scaling all weights leaves P unchanged."""
    base = [WeightedInstance(("T1059",), "T1003", 1.0), WeightedInstance(("T1003",), "T1059", 1.0)]
    scaled = [WeightedInstance(i.prefix, i.target, 0.01) for i in base]
    p = MarkovParams(max_order=1, weights=(1.0,), alpha=2.0, beta=1.0)
    a = InterpolatedMarkovModel(MarkovCounts.from_instances(base), p, space, "M1")
    b = InterpolatedMarkovModel(MarkovCounts.from_instances(scaled), p, space, "M1")
    assert a.distribution(("T1059",)) == pytest.approx(b.distribution(("T1059",)))


def test_invalid_inputs(counts: MarkovCounts, space: OutputSpace) -> None:
    with pytest.raises(ValueError):
        MarkovCounts.from_instances([WeightedInstance(("T1059",), UNK_TOKEN, 1.0)])
    with pytest.raises(ValueError):
        MarkovCounts.from_instances([WeightedInstance(("T1059",), "T1003", 0.0)])
    for bad in (
        {"max_order": 2, "weights": (1.0,), "alpha": 1.0, "beta": 1.0},
        {"max_order": 2, "weights": (0.7, 0.7), "alpha": 1.0, "beta": 1.0},
        {"max_order": 1, "weights": (-1.0,), "alpha": 1.0, "beta": 1.0},
        {"max_order": 1, "weights": (1.0,), "alpha": 0.0, "beta": 1.0},
        {"max_order": 4, "weights": (0.25,) * 4, "alpha": 1.0, "beta": 1.0},
    ):
        with pytest.raises(ValidationError):
            MarkovParams.model_validate(bad)
    outside = MarkovCounts.from_instances([WeightedInstance(("T1059",), "T9999", 1.0)])
    with pytest.raises(ValueError):
        m1(outside, space)
    with pytest.raises(KeyError):
        m1(counts, space).prob(("T1059",), UNK_TOKEN)


def test_empty_counts_give_uniform(space: OutputSpace) -> None:
    model = m1(MarkovCounts.from_instances([]), space)
    assert model.distribution(("T1059",)) == pytest.approx([0.25] * 4)


def test_merge_equals_joint_counting(counts: MarkovCounts) -> None:
    extra = MarkovCounts.from_instances([WeightedInstance(("T1059", "T1003"), "T1059", 2.0)])
    merged = MarkovCounts.merge([counts, extra])
    assert merged.unigram["T1059"] == 3.0
    assert merged.ngram[("T1003",)]["T1059"] == 3.0
    assert merged.ngram[("T1059", "T1003")]["T1059"] == 2.0
    assert merged.instances == 5 and merged.total_weight == 6.0
    assert merged.mean_instance_weight == pytest.approx(1.2)


# --- persistence ---------------------------------------------------------------------------


def _metadata(vocab: TechniqueVocabulary) -> MarkovModelMetadata:
    return MarkovModelMetadata(
        model_type="interpolated-markov",
        model_name="M1",
        training_dataset="test",
        dataset_version="1",
        attack_version=vocab.attack_version,
        vocabulary_version=vocab.vocabulary_version,
        weighting="document",
        hyperparameters=MarkovParams(max_order=1, weights=(1.0,), alpha=1.0, beta=1.0),
        training_groups=["g1"],
        seed=42,
    )


def test_artifact_round_trip(
    tmp_path: Path, counts: MarkovCounts, space: OutputSpace, vocab: TechniqueVocabulary
) -> None:
    model = m1(counts, space)
    path = tmp_path / "m" / "M1.json"
    MarkovModelArtifact.from_model(model, _metadata(vocab)).save(path)
    restored = MarkovModelArtifact.load(path).to_model(space)
    for ctx in [("T1059",), ("T1003",), (), ("T1059.001", "T1059")]:
        assert restored.distribution(ctx) == model.distribution(ctx)


def test_artifact_errors(
    tmp_path: Path, counts: MarkovCounts, space: OutputSpace, vocab: TechniqueVocabulary
) -> None:
    with pytest.raises(ModelCheckpointNotFoundError):
        MarkovModelArtifact.load(tmp_path / "missing.json")
    artifact = MarkovModelArtifact.from_model(m1(counts, space), _metadata(vocab))
    other = OutputSpace(TechniqueVocabulary.from_technique_ids(["T1059"], vocab.attack_version))
    with pytest.raises(ValueError, match="vocabulary"):
        artifact.to_model(other)
