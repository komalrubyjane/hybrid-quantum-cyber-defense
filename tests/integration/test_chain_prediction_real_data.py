"""Structural checks of Milestone 3 on the REAL Attack Flow corpus (skips if absent).

No accuracy numbers are asserted; only structure, normalisation and leakage properties.
"""

from __future__ import annotations

import math

import pytest

from hqc.config import Settings
from hqc.evaluation.chain_prediction import ExperimentConfig, ModelSpec, run_experiment
from hqc.evaluation.splits import leave_one_group_out
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.paths import processed_attack_flow_path, processed_kb_path, vocabulary_path
from hqc.prediction.base import OutputSpace, check_distribution
from hqc.prediction.dataset import PredictionDataset, build_dataset, load_corpus
from hqc.prediction.markov import MarkovParams
from hqc.prediction.vocabulary import UNK_TOKEN, TechniqueVocabulary

pytestmark = [pytest.mark.integration, pytest.mark.requires_data]


@pytest.fixture(scope="module")
def real() -> tuple[PredictionDataset, OutputSpace, AttackKnowledgeBase]:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    corpus_path = processed_attack_flow_path(settings)
    if (
        not corpus_path.is_file()
        or not processed_kb_path(settings, settings.attack_version).is_file()
    ):
        pytest.skip("processed Attack Flow corpus / KB not available")
    kb = AttackKnowledgeBase.load(settings)
    vocab = TechniqueVocabulary.load(vocabulary_path(settings, settings.attack_version))
    return build_dataset(load_corpus(corpus_path), kb, vocab), OutputSpace(vocab), kb


def test_dataset_structure(
    real: tuple[PredictionDataset, OutputSpace, AttackKnowledgeBase],
) -> None:
    dataset, space, _ = real
    s = dataset.stats
    assert s.source_groups == len(dataset.groups) >= 2
    assert s.unique_instances == len(dataset.instances) > 0
    assert s.raw_instances >= s.unique_instances
    assert s.vocabulary_version == space.vocabulary_version
    assert all(i.target in space for i in dataset.instances)  # never <UNK>/<PAD>
    assert all(t in space or t == UNK_TOKEN for i in dataset.instances for t in i.prefix)
    assert all(r.replacement in space for r in s.remapped_ids)


def test_group_split_has_no_overlap(
    real: tuple[PredictionDataset, OutputSpace, AttackKnowledgeBase],
) -> None:
    dataset, _, _ = real
    folds = leave_one_group_out(dataset.group_of_document)
    assert len(folds) == dataset.stats.source_groups
    for fold in folds:
        record = fold.to_record()  # validator rejects any overlap
        assert not set(record.train_sources) & set(record.test_sources)


def test_small_experiment_produces_valid_predictions(
    real: tuple[PredictionDataset, OutputSpace, AttackKnowledgeBase],
) -> None:
    dataset, space, kb = real
    params = MarkovParams(max_order=2, weights=(0.5, 0.5), alpha=5.0, beta=1.0)
    config = ExperimentConfig(
        seed=0,
        bootstrap_resamples=100,
        confidence=0.95,
        selection_metric="log_loss",
        primary_weighting="document",  # type: ignore[arg-type]
        ablation_weightings=[],
        models=[ModelSpec(name="B0"), ModelSpec(name="M2", grid=[params])],
    )
    tactics = {t.technique_id: list(t.tactic_ids) for t in kb.get_techniques()}
    result = run_experiment(dataset, space, tactics, config)
    assert len(result.predictions) == 2 * dataset.stats.unique_instances
    for record in result.predictions[:: max(1, len(result.predictions) // 200)]:
        assert record.instance.target in space
        assert all(t in space for t, _ in record.score.top)
        assert 0.0 < record.score.p_target <= 1.0 and record.score.rank >= 1
    m2 = result.weighting_results[0].models[1]
    assert all(math.isfinite(v) for v in m2.micro.values())
    # Distributions normalise for real contexts.
    from hqc.evaluation.chain_prediction import build_group_data, fit_model

    data = build_group_data(dataset, config.primary_weighting)
    model, _ = fit_model(config.models[1], data, space)
    for instance in dataset.instances[:: max(1, len(dataset.instances) // 100)]:
        check_distribution(model.distribution(instance.prefix), space)
