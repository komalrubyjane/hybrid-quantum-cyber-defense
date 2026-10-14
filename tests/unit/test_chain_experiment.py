"""Nested LOGO experiment, tuner isolation, config loading and run tracking."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest

from hqc.common.errors import ConfigurationError, StorageError
from hqc.common.repro import environment_info
from hqc.common.schemas import EvaluationResult
from hqc.common.schemas.base import utc_now
from hqc.config import PROJECT_ROOT
from hqc.evaluation import chain_prediction as cp
from hqc.evaluation.chain_prediction import (
    ExperimentResult,
    ModelSpec,
    load_experiment_config,
    run_experiment,
)
from hqc.evaluation.metrics import METRIC_NAMES
from hqc.evaluation.tracking import (
    RUN_FILES,
    RunProvenance,
    boundary_selections,
    evaluation_record,
    flat_metrics,
    make_run_id,
    store_record,
    write_run,
)
from hqc.evaluation.tuning import GroupData, tune
from hqc.prediction.base import OutputSpace
from hqc.prediction.dataset import PredictionDataset, Weighting
from hqc.prediction.markov import MarkovCounts, MarkovParams
from hqc.storage import SQLiteStore
from prediction_fixtures import mini_dataset, small_markov_config

REAL_CONFIG = PROJECT_ROOT / "configs" / "chain_prediction.yaml"


small_config = small_markov_config


@pytest.fixture
def setup(tmp_path: Path) -> tuple[PredictionDataset, OutputSpace, dict[str, list[str]]]:
    dataset, space, kb = mini_dataset(tmp_path)
    tactics = {t.technique_id: list(t.tactic_ids) for t in kb.get_techniques()}
    return dataset, space, tactics


@pytest.fixture
def result(setup: Any) -> ExperimentResult:
    dataset, space, tactics = setup
    return run_experiment(dataset, space, tactics, small_config())


# --- experiment ------------------------------------------------------------------------------


def test_experiment_structure(result: ExperimentResult) -> None:
    assert [f.test_group for f in result.folds] == ["Alpha", "Beta", "Delta", "Gamma"]
    assert result.skipped_folds == ["fold-02"]  # Delta has no instances
    assert [w.weighting for w in result.weighting_results] == [
        Weighting.DOCUMENT,
        Weighting.RAW,
        Weighting.UNIQUE,
    ]
    primary = result.weighting_results[0]
    assert [m.model for m in primary.models] == ["B0", "B1", "M1", "M2"]
    for model in primary.models:
        assert set(model.macro) == set(METRIC_NAMES)
        assert set(model.per_group) == {"Alpha", "Beta", "Gamma"}
        assert model.per_group_instances == {"Alpha": 4, "Beta": 1, "Gamma": 3}
        assert len(model.folds) == 4
        for metric in METRIC_NAMES:
            s = model.macro[metric]
            assert s.n_groups == 3 and s.ci_low <= s.mean + 1e-12 <= s.ci_high + 2e-12


def test_macro_vs_micro(result: ExperimentResult) -> None:
    for model in result.weighting_results[0].models:
        groups = model.per_group
        sizes = model.per_group_instances
        macro = sum(g["top1"] for g in groups.values()) / len(groups)
        micro = sum(groups[g]["top1"] * sizes[g] for g in groups) / sum(sizes.values())
        assert model.macro["top1"].mean == pytest.approx(macro)
        assert model.micro["top1"] == pytest.approx(micro)


def test_uniform_baseline_log_loss_and_predictions(result: ExperimentResult) -> None:
    b0 = next(m for m in result.weighting_results[0].models if m.model == "B0")
    assert b0.macro["log_loss"].mean == pytest.approx(math.log(4))
    assert b0.macro["top1_tie_aware"].mean == pytest.approx(0.25)
    # predictions exist only for the primary weighting: 8 instances x 4 models
    assert len(result.predictions) == 8 * 4
    assert {p.model for p in result.predictions} == {"B0", "B1", "M1", "M2"}
    assert all(p.score.top[0][0].startswith("T") for p in result.predictions)


def test_comparisons_recorded(result: ExperimentResult) -> None:
    comps = result.weighting_results[0].comparisons
    assert {(c.model_a, c.model_b) for c in comps} == {("M2", "B1"), ("B1", "B0")}
    assert len(comps) == 2 * len(METRIC_NAMES)


def test_experiment_is_deterministic(setup: Any) -> None:
    dataset, space, tactics = setup
    a = run_experiment(dataset, space, tactics, small_config())
    b = run_experiment(dataset, space, tactics, small_config())
    assert [w.model_dump() for w in a.weighting_results] == [
        w.model_dump() for w in b.weighting_results
    ]


def test_tuner_never_sees_outer_test_group(setup: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: every tune() call receives exactly the outer-training groups."""
    dataset, space, tactics = setup
    calls: list[set[str]] = []
    real_tune = cp.tune

    def spy(grid: Any, train_data: dict[str, GroupData], sp: Any, name: str) -> Any:
        calls.append(set(train_data))
        return real_tune(grid, train_data, sp, name)

    monkeypatch.setattr(cp, "tune", spy)
    config = small_config()
    result = run_experiment(dataset, space, tactics, config)
    evaluated = [f for f in result.folds if f.fold_id not in result.skipped_folds]
    tuned_models = sum(1 for m in config.models if m.grid)
    assert len(calls) == len(evaluated) * tuned_models * len(config.weightings)
    all_groups = set(dataset.groups)
    # Calls happen per weighting, per fold, per tuned model, in that order.
    expected = [all_groups - {f.test_group} for f in evaluated for _ in range(tuned_models)] * len(
        config.weightings
    )
    assert calls == expected
    for seen, fold in zip(
        calls, [f for f in evaluated for _ in range(tuned_models)] * 3, strict=True
    ):
        assert fold.test_group not in seen


def test_tune_selects_by_inner_log_loss() -> None:
    def gd(pairs: list[tuple[tuple[str, ...], str]]) -> GroupData:
        from collections import Counter

        from hqc.prediction.dataset import WeightedInstance

        counts = MarkovCounts.from_instances([WeightedInstance(p, t, 1.0) for p, t in pairs])
        return GroupData(counts=counts, eval_pairs=Counter(pairs))

    from prediction_fixtures import mini_kb, mini_vocabulary

    space = OutputSpace(mini_vocabulary(mini_kb()))
    same = [(("T1059",), "T1003")] * 3
    data = {"g1": gd(same), "g2": gd(same), "g3": gd(same)}
    grid = [MarkovParams(max_order=1, weights=(1.0,), alpha=a, beta=1.0) for a in (100.0, 0.1)]
    result = tune(grid, data, space, "M1")
    assert result.selected.alpha == 0.1  # consistent transitions favour weak smoothing
    assert result.inner_groups == ("g1", "g2", "g3")
    assert result.candidate_scores[1] < result.candidate_scores[0]
    single = tune(grid, {"g1": gd(same)}, space, "M1")
    assert single.selected == grid[0] and all(math.isnan(s) for s in single.candidate_scores)
    with pytest.raises(ValueError):
        tune([], data, space, "M1")


# --- configuration -----------------------------------------------------------------------------


def test_real_config_loads() -> None:
    config = load_experiment_config(REAL_CONFIG)
    sizes = {m.name: len(m.grid) for m in config.models}
    assert sizes == {"B0": 0, "B1": 7, "M1": 70, "M2": 495}
    assert config.primary_weighting is Weighting.DOCUMENT
    swapped = load_experiment_config(REAL_CONFIG, primary=Weighting.RAW)
    assert swapped.primary_weighting is Weighting.RAW
    assert set(swapped.ablation_weightings) == {Weighting.DOCUMENT, Weighting.UNIQUE}


@pytest.mark.parametrize(
    "override",
    [
        {"selection_metric": "top1"},
        {"ablation_weightings": ["document"]},
        {"comparisons": [("M9", "B1")]},
        {"models": [ModelSpec(name="B0"), ModelSpec(name="B0")]},
        {"models": [ModelSpec(name="M1")]},
    ],
)
def test_invalid_configs(override: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        small_config(**override)


def test_config_file_errors(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("seed: [unclosed")
    with pytest.raises(ConfigurationError):
        load_experiment_config(bad)
    with pytest.raises(ConfigurationError):
        load_experiment_config(tmp_path / "missing.yaml")


# --- tracking ----------------------------------------------------------------------------------


def _provenance(run_id: str) -> RunProvenance:
    return RunProvenance(
        run_id=run_id,
        created_at=utc_now(),
        seed=1,
        git_commit="c" * 40,
        git_dirty=True,
        environment=environment_info(),
        runtime_s=1.5,
        config_path="configs/chain_prediction.yaml",
        corpus_sha256="d" * 64,
    )


def test_run_folder_and_sqlite_round_trip(
    tmp_path: Path, setup: Any, result: ExperimentResult
) -> None:
    dataset, _, _ = setup
    config = small_config()
    prov = _provenance(make_run_id("document"))
    run_dir = write_run(tmp_path, config, result, dataset.stats, prov)
    assert sorted(p.name for p in run_dir.iterdir()) == sorted(RUN_FILES)

    cfg = json.loads((run_dir / "config.json").read_text())
    for key in (
        "run_id",
        "models",
        "weighting_primary",
        "hyperparameter_grid",
        "random_seed",
        "dataset_id",
        "dataset_version",
        "attack_version",
        "vocabulary_version",
        "id_cleanup",
        "environment",
        "git_commit",
        "working_tree_dirty",
    ):
        assert key in cfg
    assert cfg["working_tree_dirty"] is True and cfg["multi_step"] == "NOT EVALUATED"

    metrics = json.loads((run_dir / "metrics.json").read_text())
    assert set(metrics["results"]) == {"document", "raw", "unique"}
    m2 = metrics["results"]["document"]["models"]["M2"]
    assert {"macro", "micro", "per_group", "folds"} <= set(m2)
    assert metrics["dataset_statistics"]["unique_instances"] == 8

    preds = json.loads((run_dir / "predictions.json").read_text())
    assert len(preds["instances"]) == 8 and len(preds["predictions"]) == 32
    row = preds["predictions"][0]
    assert {"instance_id", "model", "fold", "top5", "p_true", "true_rank"} <= set(row)
    inst = preds["instances"][0]
    assert {"document", "group", "prefix", "true_next", "fold"} <= set(inst)

    summary = (run_dir / "summary.md").read_text()
    assert summary.count("\n- TRAIN SOURCES:") == 4  # one per fold
    assert summary.count("\n- TEST SOURCES:") == 4
    assert "multi-step: NOT EVALUATED" in summary
    assert "working tree dirty: **True**" in summary

    record = evaluation_record(config, result, dataset.stats, prov, run_dir)
    with SQLiteStore(":memory:") as store:
        restored = store_record(store, record)
        assert isinstance(restored, EvaluationResult) and restored == record
        assert restored.git_dirty is True and len(restored.folds) == 4
        assert restored.metrics["document.M2.macro.top1"] == pytest.approx(
            result.weighting_results[0].models[3].macro["top1"].mean
        )
        with pytest.raises(StorageError):
            store_record(store, record)
    with pytest.raises(FileExistsError):
        write_run(tmp_path, config, result, dataset.stats, prov)


def test_flat_metrics_and_boundaries(result: ExperimentResult) -> None:
    flat = flat_metrics(result)
    assert len(flat) == 3 * 4 * len(METRIC_NAMES) * 4
    counts = boundary_selections(small_config(), result.weighting_results[0])
    assert set(counts) == {"B1", "M1", "M2"}
    assert all(v >= 0 for c in counts.values() for v in c.values())


def test_make_run_id_format() -> None:
    from datetime import UTC, datetime

    run_id = make_run_id("raw", datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC))
    assert run_id == "20260102T030405Z-markov-baselines-raw"
