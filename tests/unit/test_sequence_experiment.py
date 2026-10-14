"""Nested Milestone 4 experiment on the mini corpus: isolation, determinism, tracking."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from hqc.common.errors import ConfigurationError
from hqc.common.repro import environment_info
from hqc.common.schemas import EvaluationFold, EvaluationResult
from hqc.common.schemas.base import utc_now
from hqc.config import PROJECT_ROOT
from hqc.evaluation import sequence_experiment as se
from hqc.evaluation.sequence_experiment import (
    SequenceConfig,
    SequenceExperimentResult,
    load_sequence_config,
    run_sequence_experiment,
)
from hqc.evaluation.sequence_tracking import (
    RUN_FILES,
    SequenceProvenance,
    make_sequence_run_id,
    sequence_record,
    store_sequence_record,
    write_sequence_run,
)
from hqc.evaluation.splits import inner_validation_groups
from hqc.storage import SQLiteStore
from prediction_fixtures import mini_dataset, small_markov_config

LSTM_SHARED = {
    "batch_size": 4,
    "max_epochs": 3,
    "patience": 1,
    "min_delta": 0.0,
    "num_threads": 1,
    "seed": 3,
}


def seq_config(**overrides: Any) -> SequenceConfig:
    data: dict[str, Any] = {
        "seed": 3,
        "bootstrap_resamples": 200,
        "confidence": 0.95,
        "weighting": "document",
        "markov_config": "unused-in-tests",
        "inner_validation": {"fraction": 0.5, "min_groups": 1},
        "lstm_candidates": [
            {
                **LSTM_SHARED,
                "embedding_dim": 4,
                "hidden_dim": 4,
                "num_layers": 1,
                "dropout": 0.0,
                "learning_rate": 0.05,
                "weight_decay": 0.0,
                "context_length": 2,
            },
            {
                **LSTM_SHARED,
                "embedding_dim": 4,
                "hidden_dim": 8,
                "num_layers": 2,
                "dropout": 0.2,
                "learning_rate": 0.01,
                "weight_decay": 1e-4,
                "context_length": 3,
            },
        ],
        "fusion_alphas": [0.0, 0.5, 1.0],
        "beam_search": {
            "beam_width": 3,
            "horizons": [2],
            "hit_ks": [1, 3],
            "models": ["B1", "MARKOV", "LSTM", "HYBRID"],
        },
        "comparisons": [["LSTM", "B1"], ["HYBRID", "LSTM"], ["MARKOV", "B1"]],
    }
    data.update(overrides)
    return SequenceConfig.model_validate(data)


@pytest.fixture
def setup(tmp_path: Path) -> Any:
    dataset, space, kb = mini_dataset(tmp_path)
    tactics = {t.technique_id: list(t.tactic_ids) for t in kb.get_techniques()}
    from prediction_fixtures import mini_vocabulary

    return dataset, mini_vocabulary(kb), space, tactics


def run(setup: Any, **kwargs: Any) -> SequenceExperimentResult:
    dataset, vocab, space, tactics = setup
    return run_sequence_experiment(
        dataset,
        vocab,
        space,
        tactics,
        seq_config(),
        small_markov_config(ablation_weightings=[]),
        **kwargs,
    )


def test_structure_and_selection(setup: Any) -> None:
    result = run(setup)
    assert [r.test_group for r in result.fold_records] == ["Alpha", "Beta", "Gamma"]
    assert result.skipped_folds == ["fold-02"]
    names = [m.model for m in result.single_step]
    assert names == ["B0", "B1", "M1", "M2", "MARKOV", "LSTM", "HYBRID"]
    for r in result.fold_records:
        assert r.selected_candidate in (0, 1) and r.selected_alpha in (0.0, 0.5, 1.0)
        assert r.test_group not in r.train_groups + r.validation_groups + r.inner_train_groups
        assert not set(r.validation_groups) & set(r.inner_train_groups)
        assert set(r.validation_groups) <= set(r.train_groups)
        assert r.final_markov in ("M1", "M2") and r.final_epochs >= 1
        assert set(r.alpha_validation_loss) == {"0.00", "0.50", "1.00"}
    assert set(result.alpha_sweep) == {"0.00", "0.50", "1.00"}
    hm = {(m.model, m.horizon) for m in result.multistep}
    assert ("HYBRID", 2) in hm and ("LSTM", 2) in hm
    assert result.baseline_reproduction == {"B0": None, "B1": None, "M1": None, "M2": None}


def test_alpha_endpoints_equal_components(setup: Any) -> None:
    result = run(setup)
    single = {m.model: m for m in result.single_step}
    # Test-set sweep at alpha=1 is the LSTM and at alpha=0 the selected Markov model.
    assert result.alpha_sweep["1.00"]["log_loss"].mean == pytest.approx(
        single["LSTM"].macro["log_loss"].mean
    )
    assert result.alpha_sweep["0.00"]["log_loss"].mean == pytest.approx(
        single["MARKOV"].macro["log_loss"].mean
    )


def test_outer_test_group_never_used_for_fitting(
    setup: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spies on every training / tuning / validation entry point."""
    dataset = setup[0]
    seen: dict[str, list[set[str]]] = {"weighted": [], "validation": [], "tune": [], "train": []}
    real_weighted = dataset.weighted
    real_val = se.build_validation_sets
    real_tune = se.tune
    real_train = se.train_lstm

    current: dict[str, str | None] = {"test_group": None}
    real_run_fold = se.run_fold

    def run_fold(fold: Any, *args: Any, **kwargs: Any) -> Any:
        current["test_group"] = fold.test_group
        try:
            return real_run_fold(fold, *args, **kwargs)
        finally:
            current["test_group"] = None

    def weighted(instances: Any, weighting: Any) -> Any:
        groups = {i.source_group for i in instances}
        if current["test_group"] is not None:  # only training-data calls made inside a fold
            assert current["test_group"] not in groups
            seen["weighted"].append(groups)
        return real_weighted(instances, weighting)

    def validation_sets(by_group: Any, length: int) -> Any:
        seen["validation"].append(set(by_group))
        return real_val(by_group, length)

    def tune(grid: Any, train_data: Any, space: Any, name: str) -> Any:
        seen["tune"].append(set(train_data))
        return real_tune(grid, train_data, space, name)

    def train(
        config: Any,
        train: Any,
        vocab: Any,
        space: Any,
        validation: Any = None,
        fixed_epochs: Any = None,
    ) -> Any:
        seen["train"].append({v.group for v in validation} if validation is not None else set())
        return real_train(
            config, train, vocab, space, validation=validation, fixed_epochs=fixed_epochs
        )

    monkeypatch.setattr(dataset, "weighted", weighted)
    monkeypatch.setattr(se, "run_fold", run_fold)
    monkeypatch.setattr(se, "build_validation_sets", validation_sets)
    monkeypatch.setattr(se, "tune", tune)
    monkeypatch.setattr(se, "train_lstm", train)
    result = run(setup)
    folds_in_order = result.fold_records
    # Group the spy records per fold by replaying: every call inside a fold must exclude it.
    per_fold_calls = {k: len(v) // len(folds_in_order) for k, v in seen.items() if k != "weighted"}
    for key, calls in seen.items():
        if key == "weighted":
            continue
        chunk = per_fold_calls[key]
        for i, record in enumerate(folds_in_order):
            for groups in calls[i * chunk : (i + 1) * chunk]:
                assert record.test_group not in groups, (key, record.fold_id)
    # Early stopping (candidate training) only ever sees validation groups.
    for i, record in enumerate(folds_in_order):
        chunk = per_fold_calls["train"]
        candidate_calls = seen["train"][i * chunk : (i + 1) * chunk - 1]
        assert all(g <= set(record.validation_groups) for g in candidate_calls)
        assert (
            seen["train"][(i + 1) * chunk - 1] == set()
        )  # final model: fixed epochs, no validation
    # Training tensors were built inside every fold (and never contained its test group).
    assert len(seen["weighted"]) >= 2 * len(folds_in_order)


def test_deterministic(setup: Any) -> None:
    a, b = run(setup), run(setup)
    assert [m.model_dump() for m in a.single_step] == [m.model_dump() for m in b.single_step]
    assert [r.model_dump(exclude={"seconds"}) for r in a.fold_records] == [
        r.model_dump(exclude={"seconds"}) for r in b.fold_records
    ]


def test_tracking_and_sqlite(tmp_path: Path, setup: Any) -> None:
    result = run(setup)
    dataset = setup[0]
    prov = SequenceProvenance(
        run_id=make_sequence_run_id(),
        created_at=utc_now(),
        git_commit="c" * 40,
        git_dirty=True,
        environment=environment_info(),
        runtime_s=1.0,
        config_path="configs/sequence_prediction.yaml",
        corpus_sha256=None,
        checkpoint_dir=None,
    )
    config = seq_config()
    markov = small_markov_config(ablation_weightings=[])
    run_dir = write_sequence_run(tmp_path, config, markov, result, dataset.stats, prov)
    assert sorted(p.name for p in run_dir.iterdir()) == sorted(RUN_FILES)
    summary = (run_dir / "summary.md").read_text()
    for marker in (
        "TEST SOURCES",
        "VALIDATION SOURCES",
        "TRAIN SOURCES (inner training)",
        "REPORT ONLY",
        "NOT EVALUATED",
    ):
        assert marker in summary
    assert summary.count("\n- VALIDATION SOURCES:") == 3
    metrics = json.loads((run_dir / "metrics.json").read_text())
    assert metrics["multistep_status"]["beam_search_path_metrics"] == "EVALUATED"
    assert (
        "NOT EVALUATED" in metrics["multistep_status"]["reach_impact_or_exfiltration_probability"]
    )
    history = json.loads((run_dir / "training_history.json").read_text())
    assert set(history) == {r.fold_id for r in result.fold_records}
    assert "final" in history["fold-00"] and "candidate-0" in history["fold-00"]
    preds = json.loads((run_dir / "predictions.json").read_text())
    assert {r["model"] for r in preds["single_step"]} == {"MARKOV", "LSTM", "HYBRID"}
    record = sequence_record(config, result, dataset.stats, prov, run_dir)
    with SQLiteStore(":memory:") as store:
        restored = store_sequence_record(store, record)
        assert isinstance(restored, EvaluationResult) and restored == record
        assert all(f.validation_sources for f in restored.folds)


def test_fold_record_rejects_validation_test_overlap() -> None:
    with pytest.raises(ValidationError, match="validation and test"):
        EvaluationFold(
            fold_id="f",
            train_sources=["group:a"],
            validation_sources=["group:t"],
            test_sources=["group:t"],
        )


def test_inner_validation_groups() -> None:
    groups = [f"g{i}" for i in range(10)]
    inner, val = inner_validation_groups(groups, 0.2, 2, 42, "fold-00")
    assert len(val) == 2 and len(inner) == 8 and not set(inner) & set(val)
    assert (inner, val) == inner_validation_groups(list(reversed(groups)), 0.2, 2, 42, "fold-00")
    assert inner_validation_groups(groups, 0.2, 2, 42, "fold-01") != (inner, val)
    assert inner_validation_groups(["a", "b"], 0.9, 5, 1, "f")[0]  # keeps one training group
    with pytest.raises(ValueError):
        inner_validation_groups(["a"], 0.2, 1, 1, "f")
    with pytest.raises(ValueError):
        inner_validation_groups(["a", "b"], 1.5, 1, 1, "f")


def test_real_config_loads() -> None:
    config, markov = load_sequence_config(
        PROJECT_ROOT / "configs" / "sequence_prediction.yaml", PROJECT_ROOT
    )
    assert len(config.lstm_candidates) == 8
    assert all(c.max_epochs == 25 and c.seed == config.seed for c in config.lstm_candidates)
    assert config.fusion_alphas[0] == 0.0 and config.fusion_alphas[-1] == 1.0
    assert markov.ablation_weightings == [] and {m.name for m in markov.models} >= {
        "B1",
        "M1",
        "M2",
    }


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        ("fusion_alphas: [0.0,", "fusion_alphas: [0.1,"),
        ("hit_ks: [1, 5, 10]", "hit_ks: [1, 50]"),
        ("  - [LSTM, B1]", "  - [LSTM, ZZ]"),
        ("models: [B1, MARKOV, LSTM, HYBRID]", "models: [B0]"),
    ],
)
def test_invalid_sequence_configs(tmp_path: Path, needle: str, replacement: str) -> None:
    text = (PROJECT_ROOT / "configs" / "sequence_prediction.yaml").read_text()
    assert needle in text
    bad = tmp_path / "bad.yaml"
    bad.write_text(text.replace(needle, replacement))
    with pytest.raises(ConfigurationError):
        load_sequence_config(bad, PROJECT_ROOT)


def test_config_file_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        load_sequence_config(tmp_path / "missing.yaml", PROJECT_ROOT)


def test_reproduction_check_against_stored_run(tmp_path: Path, setup: Any) -> None:
    """Recomputed baselines are compared with a stored Milestone 3 metrics file."""
    from hqc.evaluation.chain_prediction import run_experiment
    from hqc.evaluation.tracking import metrics_payload

    dataset, _, space, tactics = setup
    markov = small_markov_config(ablation_weightings=[])
    stored = run_experiment(dataset, space, tactics, markov)
    path = tmp_path / "metrics.json"
    path.write_text(json.dumps(metrics_payload(markov, stored, dataset.stats)))
    result = run(setup, reference_metrics=path)
    assert result.baseline_reproduction == {"B0": 0.0, "B1": 0.0, "M1": 0.0, "M2": 0.0}
    payload = json.loads(path.read_text())
    payload["results"]["document"]["models"]["B1"]["per_group"]["Alpha"]["top1"] += 0.5
    del payload["results"]["document"]["models"]["M2"]["per_group"]["Beta"]
    path.write_text(json.dumps(payload))
    changed = run(setup, reference_metrics=path).baseline_reproduction
    assert changed["B1"] == pytest.approx(0.5) and changed["M2"] == float("inf")
