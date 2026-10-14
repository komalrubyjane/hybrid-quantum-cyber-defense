"""Attack Flow -> dataset -> Markov -> LSTM -> fusion -> beam search -> metrics -> tracking,
on the REAL corpus with one fold and tiny settings. Structural assertions only (no accuracy)."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from hqc.common.repro import environment_info
from hqc.common.schemas.base import utc_now
from hqc.config import Settings
from hqc.evaluation.sequence_experiment import SequenceConfig, run_sequence_experiment
from hqc.evaluation.sequence_tracking import SequenceProvenance, write_sequence_run
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.paths import processed_attack_flow_path, processed_kb_path, vocabulary_path
from hqc.prediction.base import OutputSpace
from hqc.prediction.dataset import build_dataset, load_corpus
from hqc.prediction.vocabulary import TechniqueVocabulary
from prediction_fixtures import small_markov_config

pytestmark = [pytest.mark.integration, pytest.mark.requires_data]


def test_one_fold_end_to_end(tmp_path: Path) -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    corpus = processed_attack_flow_path(settings)
    if not corpus.is_file() or not processed_kb_path(settings, settings.attack_version).is_file():
        pytest.skip("processed Attack Flow corpus / KB not available")
    kb = AttackKnowledgeBase.load(settings)
    vocab = TechniqueVocabulary.load(vocabulary_path(settings, settings.attack_version))
    dataset = build_dataset(load_corpus(corpus), kb, vocab)
    space = OutputSpace(vocab)
    tactics = {t.technique_id: list(t.tactic_ids) for t in kb.get_techniques()}
    shared = {
        "batch_size": 256,
        "max_epochs": 2,
        "patience": 1,
        "min_delta": 0.0,
        "num_threads": 2,
        "seed": 1,
    }
    config = SequenceConfig.model_validate(
        {
            "seed": 1,
            "bootstrap_resamples": 100,
            "confidence": 0.95,
            "weighting": "document",
            "markov_config": "unused",
            "inner_validation": {"fraction": 0.2, "min_groups": 2},
            "lstm_candidates": [
                {
                    **shared,
                    "embedding_dim": 8,
                    "hidden_dim": 16,
                    "num_layers": 1,
                    "dropout": 0.0,
                    "learning_rate": 0.01,
                    "weight_decay": 0.0,
                    "context_length": 3,
                }
            ],
            "fusion_alphas": [0.0, 0.5, 1.0],
            "beam_search": {
                "beam_width": 3,
                "horizons": [2],
                "hit_ks": [1, 3],
                "models": ["LSTM", "HYBRID"],
            },
            "comparisons": [["LSTM", "B1"]],
        }
    )
    markov = small_markov_config(ablation_weightings=[])
    result = run_sequence_experiment(dataset, vocab, space, tactics, config, markov, fold_limit=1)
    [record] = result.fold_records
    assert record.test_group not in record.train_groups and record.validation_groups
    assert {m.model for m in result.single_step} >= {"LSTM", "HYBRID", "MARKOV"}
    for p in result.predictions:
        assert p.instance.target in space and all(t in space for t, _ in p.score.top)
        assert 0.0 < p.score.p_target <= 1.0
    for m in result.multistep:
        assert all(math.isfinite(v.mean) for v in m.macro.values())
    prov = SequenceProvenance(
        run_id="itest",
        created_at=utc_now(),
        git_commit=None,
        git_dirty=None,
        environment=environment_info(),
        runtime_s=0.0,
        config_path="x",
        corpus_sha256=None,
        checkpoint_dir=None,
    )
    run_dir = write_sequence_run(tmp_path, config, markov, result, dataset.stats, prov)
    assert (
        json.loads((run_dir / "metrics.json").read_text())["folds"][0]["test_group"]
        == record.test_group
    )
