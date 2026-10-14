"""Milestone 6 pipeline on SYNTHETIC CIC-IDS2017-format data (the real dataset is not needed).

Covers sampling, train-only band derivation, train-only features, model arms, grouped CV,
fusion, the classical-verdict guard, adjudicator persistence, config validation and an
end-to-end run with tracking.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pytest
from sklearn.svm import SVC

from cic_fixtures import write_day_files
from hqc.common.errors import ConfigurationError, ModelCheckpointNotFoundError
from hqc.common.repro import environment_info
from hqc.common.schemas.base import Verdict, utc_now
from hqc.common.schemas.detection import QuantumOpinion
from hqc.detection.dataset import load_cic_dataset
from hqc.detection.models import Detector, ModelConfig, train_detector
from hqc.detection.preprocessing import (
    DaySplit,
    Preprocessor,
    build_feature_policy,
    day_split,
    split_masks,
)
from hqc.fusion.stacking import (
    PlattCalibrator,
    StackingFusion,
    attach_quantum_opinion,
    disagreement,
    logit,
)
from hqc.quantum.adjudicator import Adjudicator
from hqc.quantum.band import derive_band, out_of_fold_probabilities
from hqc.quantum.cv import grouped_cv_select, leave_one_day_out
from hqc.quantum.experiment import (
    PRIMARY_BAND,
    SECONDARY_BAND,
    QuantumExperimentConfig,
    aggregate_e2,
    load_quantum_config,
    mean_ci,
    run_e3_band,
)
from hqc.quantum.features import AngleFeatures
from hqc.quantum.models import (
    ALL_KINDS,
    Hyper,
    HyperGrid,
    TrainedModel,
    embed,
    gram,
    hyper_candidates,
)
from hqc.quantum.pipeline import run_quantum_experiment
from hqc.quantum.sampling import _allocate, day_stratified_balanced_sample, stratified_sample
from hqc.quantum.tracking import (
    RUN_FILES,
    QuantumProvenance,
    make_quantum_run_id,
    quantum_record,
    store_quantum_record,
    write_quantum_run,
)
from hqc.storage import SQLiteStore

DAYS_TRAIN = ["Monday", "Tuesday", "Wednesday"]
DAYS_TEST = ["Thursday", "Friday"]


@dataclass
class Data:
    split: DaySplit
    train: pd.DataFrame
    test: pd.DataFrame
    detector: Detector
    p_test: np.ndarray
    model_config: ModelConfig


@pytest.fixture(scope="module")
def data(tmp_path_factory: pytest.TempPathFactory) -> Data:
    dataset = load_cic_dataset(write_day_files(tmp_path_factory.mktemp("cic"), rows_per_label=30))
    frame = dataset.frame
    split = day_split(frame, DAYS_TRAIN, DAYS_TEST)
    tr, te = split_masks(frame, split)
    train, test = frame.loc[tr].reset_index(drop=True), frame.loc[te].reset_index(drop=True)
    model_config = ModelConfig(name="random_forest", seed=0, rf_n_estimators=10, n_jobs=1)
    policy = build_feature_policy(train)
    detector = train_detector(
        model_config, Preprocessor(policy).fit(train), train, "synthetic-v1", DAYS_TRAIN
    )
    return Data(split, train, test, detector, detector.predict_proba(test), model_config)


def make_config(**overrides: Any) -> QuantumExperimentConfig:
    payload: dict[str, Any] = {
        "seed": 0,
        "dataset_dir": "unused",
        "classical_run_id": "synthetic",
        "threshold": 0.5,
        "train_days": DAYS_TRAIN,
        "test_days": DAYS_TEST,
        "uncertainty": {"primary_band_coverage": 0.10, "secondary_band_coverage": 0.05},
        "mutual_info_k": 4,
        "grid": {"c": [1.0, 10.0], "alpha": [0.5], "rbf_gamma": [1.0]},
        "forest": {"n_estimators": 5},
        "e2": {"n_train": [16], "dims": [2], "seeds": [0], "test_sample_size": 20},
        "e3": {"n_train": 16, "n_dims": 2},
        "e4": {
            "n_train": 6,
            "n_test": 6,
            "n_dims": 2,
            "settings": [{"name": "shots-128", "shots": 128}],
        },
    }
    payload.update(overrides)
    return QuantumExperimentConfig.model_validate(payload)


# --- sampling ------------------------------------------------------------------------------


def test_allocation_is_even_and_capacity_capped() -> None:
    assert _allocate(10, [100, 100, 100]) == [4, 3, 3]
    assert _allocate(10, [1, 100, 100]) == [1, 5, 4]
    with pytest.raises(ValueError, match="only 3"):
        _allocate(4, [1, 2])


def test_day_stratified_balanced_sample(data: Data) -> None:
    idx = day_stratified_balanced_sample(data.train, 16, seed=3)
    rows = data.train.iloc[idx]
    assert len(rows) == 16 and rows["is_malicious"].sum() == 8
    assert rows.loc[rows["is_malicious"] == 0, "day"].value_counts().to_dict() == {
        "Monday": 3,
        "Tuesday": 3,
        "Wednesday": 2,
    }
    assert rows.loc[rows["is_malicious"] == 1, "day"].value_counts().to_dict() == {
        "Tuesday": 4,
        "Wednesday": 4,
    }
    assert np.array_equal(idx, day_stratified_balanced_sample(data.train, 16, seed=3))
    assert not np.array_equal(idx, day_stratified_balanced_sample(data.train, 16, seed=4))
    with pytest.raises(ValueError):
        day_stratified_balanced_sample(data.train, 1000, seed=0)
    fewer = day_stratified_balanced_sample(data.train, 1000, seed=0, allow_fewer=True)
    assert data.train.iloc[fewer]["is_malicious"].sum() == len(fewer) // 2 == 60


def test_stratified_sample_is_proportional(data: Data) -> None:
    idx = stratified_sample(data.test, 20, seed=0)
    assert len(idx) == 20 and len(set(idx)) == 20
    counts = data.test.iloc[idx]["label"].value_counts()
    assert counts["BENIGN"] > counts.drop("BENIGN").max()
    with pytest.raises(ValueError):
        stratified_sample(data.test, len(data.test) + 1, seed=0)


# --- band (training out-of-fold only) --------------------------------------------------------


def test_derive_band_quantile_and_validation() -> None:
    p = np.linspace(0.0, 1.0, 101)  # margins 0, 0.01, 0.01, ...
    band = derive_band(p, 0.10, 0.5, "primary")
    assert band.half_width == pytest.approx(0.05)
    assert (band.lower, band.upper) == pytest.approx((0.45, 0.55))
    assert band.train_oof_coverage == pytest.approx(11 / 101)
    assert band.contains(np.array([0.45, 0.5, 0.551])).tolist() == [True, True, False]
    assert derive_band(p, 0.05, 0.5, "s").half_width < band.half_width
    for bad in (np.array([]), np.array([np.nan]), np.zeros((2, 2))):
        with pytest.raises(ValueError):
            derive_band(bad, 0.1, 0.5, "x")
    with pytest.raises(ValueError, match="coverage"):
        derive_band(p, 1.0, 0.5, "x")


def test_out_of_fold_probabilities_cover_every_training_row(data: Data) -> None:
    oof = out_of_fold_probabilities(data.train, data.model_config, "synthetic-v1", DAYS_TRAIN)
    assert oof.p.shape == (len(data.train),) and np.all((oof.p >= 0) & (oof.p <= 1))
    assert [f.held_out_day for f in oof.folds] == DAYS_TRAIN
    for f in oof.folds:
        assert f.held_out_day not in f.training_days
    monday = next(f for f in oof.folds if f.held_out_day == "Monday")
    assert monday.held_out_roc_auc is None  # benign-only day
    with pytest.raises(ValueError, match="not scored"):
        out_of_fold_probabilities(data.train, data.model_config, "v", ["Monday", "Tuesday"])


# --- features and models ---------------------------------------------------------------------


def test_angle_features_fit_on_training_rows_only(data: Data) -> None:
    policy = data.detector.preprocessor.policy
    sample = data.train.iloc[day_stratified_balanced_sample(data.train, 20, seed=0)]
    feats = AngleFeatures(policy, 3, 6, seed=0).fit(sample)
    angles = feats.transform(data.test)
    assert angles.shape == (len(data.test), 3)
    assert angles.min() >= 0.0 and angles.max() <= np.pi
    poisoned = data.test.copy()
    poisoned["flow_duration"] = 1e12
    poisoned["is_malicious"] = 1 - poisoned["is_malicious"]
    feats.transform(poisoned)  # transforming test data never refits anything
    again = AngleFeatures(policy, 3, 6, seed=0).fit(sample)
    np.testing.assert_array_equal(feats.selected, again.selected)
    np.testing.assert_allclose(feats.pca.components_, again.pca.components_)  # type: ignore[union-attr]
    info = feats.describe()
    assert info["fit_rows"] == 20 and len(info["selected_features"]) == 6  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        AngleFeatures(policy, 4, 3, seed=0)
    with pytest.raises(ValueError, match="both classes"):
        AngleFeatures(policy, 2, 4, seed=0).fit(data.train[data.train["is_malicious"] == 0])
    with pytest.raises(RuntimeError):
        AngleFeatures(policy, 2, 4, seed=0).transform(data.test)


def test_hyper_candidates_order() -> None:
    grid = HyperGrid(c=[1.0, 10.0], alpha=[0.1, 0.5], rbf_gamma=[1.0])
    assert hyper_candidates("zz_qsvm", grid)[:2] == [
        Hyper(c=1.0, alpha=0.1),
        Hyper(c=10.0, alpha=0.1),
    ]
    assert len(hyper_candidates("rbf_svm", grid)) == 2
    assert hyper_candidates("random_forest", grid) == [Hyper()]


@pytest.mark.parametrize("kind", ["zz_qsvm", "z_qsvm", "rbf_svm", "linear_svm"])
def test_support_vector_inference_equals_full_svc(kind: str) -> None:
    rng = np.random.default_rng(0)
    x = rng.uniform(0, np.pi, (30, 3))
    y = (x[:, 0] + rng.normal(0, 0.3, 30) > np.pi / 2).astype(int)
    hyper = Hyper(c=1.0, alpha=0.5, gamma=0.5)
    model = TrainedModel(kind, hyper, reps=2, seed=0).fit(x, y)  # type: ignore[arg-type]
    x_new = rng.uniform(0, np.pi, (9, 3))
    e, e_new = embed(kind, hyper, x, 2), embed(kind, hyper, x_new, 2)  # type: ignore[arg-type]
    full = SVC(kernel="precomputed", C=1.0).fit(gram(kind, hyper, e, e), y)  # type: ignore[arg-type]
    expected = full.decision_function(gram(kind, hyper, e_new, e))  # type: ignore[arg-type]
    np.testing.assert_allclose(model.decision(x_new), expected, atol=1e-10)
    assert model.n_support is not None and model.n_support <= 30
    score = model.score(x_new)
    assert np.all((score > 0) & (score < 1))
    assert np.array_equal(score >= 0.5, expected >= 0)


def test_non_kernel_arms_and_errors() -> None:
    rng = np.random.default_rng(1)
    x = rng.uniform(0, np.pi, (40, 2))
    y = (x[:, 0] > np.pi / 2).astype(int)
    for kind in ("logreg", "random_forest"):
        model = TrainedModel(kind, Hyper(c=1.0), reps=2, seed=0).fit(x, y)  # type: ignore[arg-type]
        s = model.score(x)
        assert np.all((s >= 0) & (s <= 1)) and model.n_support is None
        assert ((s >= 0.5) == y).mean() > 0.8
    with pytest.raises(ValueError, match="both classes"):
        TrainedModel("rbf_svm", Hyper(c=1.0, gamma=1.0), 2, 0).fit(x, np.zeros(40, dtype=int))
    with pytest.raises(ValueError, match="alpha"):
        embed("zz_qsvm", Hyper(c=1.0), x, 2)
    with pytest.raises(ValueError, match="gamma"):
        gram("rbf_svm", Hyper(c=1.0), x, x)
    with pytest.raises(ValueError, match="not a kernel"):
        gram("logreg", Hyper(c=1.0), x, x)
    for kind in ("rbf_svm", "logreg"):
        with pytest.raises(RuntimeError):
            TrainedModel(kind, Hyper(c=1.0, gamma=1.0), 2, 0).decision(x)  # type: ignore[arg-type]


def test_leave_one_day_out_and_cv_selection(data: Data) -> None:
    sample = data.train.iloc[day_stratified_balanced_sample(data.train, 16, seed=0)]
    folds = leave_one_day_out(sample["day"].to_numpy())
    assert [f.held_out_day for f in folds] == DAYS_TRAIN
    for f in folds:
        assert set(sample.iloc[f.val_idx]["day"]) == {f.held_out_day}
        assert f.held_out_day not in set(sample.iloc[f.train_idx]["day"])
        assert len(np.intersect1d(f.train_idx, f.val_idx)) == 0
    grid = HyperGrid(c=[1.0, 10.0], alpha=[0.25, 0.5], rbf_gamma=[1.0])
    policy = data.detector.preprocessor.policy
    first = grouped_cv_select(sample, list(ALL_KINDS), grid, policy, 2, 4, 2, 0)
    second = grouped_cv_select(sample, list(ALL_KINDS), grid, policy, 2, 4, 2, 0)
    for kind in ALL_KINDS:
        assert first[kind].selected == second[kind].selected
        assert first[kind].cv_balanced_accuracy == max(s for _, s in first[kind].candidate_scores)
        assert np.isfinite(first[kind].oof_decision).all()
        assert first[kind].skipped_folds == []
    with pytest.raises(ValueError, match="two training days"):
        leave_one_day_out(np.array(["Monday"] * 3))


def test_single_class_training_folds_are_skipped(data: Data) -> None:
    # Monday (benign only) + Tuesday: holding out Tuesday leaves a benign-only training fold.
    two_days = data.train[data.train["day"].isin(["Monday", "Tuesday"])]
    sample = two_days.iloc[day_stratified_balanced_sample(two_days, 12, seed=0)]
    grid = HyperGrid(c=[1.0], alpha=[0.5], rbf_gamma=[1.0])
    policy = data.detector.preprocessor.policy
    out = grouped_cv_select(sample, ["rbf_svm"], grid, policy, 2, 4, 2, 0)["rbf_svm"]
    assert out.skipped_folds == ["Tuesday"]
    assert np.isnan(out.oof_decision[sample["day"].to_numpy() == "Tuesday"]).all()
    only_monday_val = sample[sample["day"] == "Tuesday"]
    with pytest.raises(ValueError, match="two training days"):
        grouped_cv_select(only_monday_val, ["rbf_svm"], grid, policy, 2, 4, 2, 0)


# --- fusion and the classical-verdict guard ---------------------------------------------------


def test_fusion_calibration_and_disagreement() -> None:
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, 200)
    decision = (2 * y - 1) * 1.5 + rng.normal(0, 1, 200)
    p_cls = np.clip(0.5 + (2 * y - 1) * 0.1 + rng.normal(0, 0.1, 200), 0, 1)
    p_q = PlattCalibrator().fit(decision, y).predict(decision)
    assert np.all((p_q > 0) & (p_q < 1)) and ((p_q >= 0.5) == y).mean() > 0.8
    fusion = StackingFusion().fit(p_cls, decision, y)
    assert fusion.coefficients["adjudicator_decision"] > 0
    assert fusion.predict(p_cls, decision).shape == (200,)
    assert np.all(np.isfinite(logit(np.array([0.0, 1.0]))))
    np.testing.assert_allclose(disagreement(np.array([0.2, 0.9]), np.array([0.7, 0.9])), [0.5, 0.0])
    with pytest.raises(ValueError, match="both classes"):
        StackingFusion().fit(p_cls, decision, np.zeros(200, dtype=int))
    with pytest.raises(ValueError, match="finite"):
        PlattCalibrator().fit(np.full(200, np.nan), y)


def test_attach_quantum_opinion_never_changes_the_classical_verdict(data: Data) -> None:
    result = data.detector.to_results(data.test.head(1), data.p_test[:1])[0]
    flipped = Verdict.BENIGN if result.verdict == Verdict.MALICIOUS else Verdict.MALICIOUS
    opinion = QuantumOpinion(
        gate_triggered=True,
        verdict=flipped,
        p_malicious=1.0 - result.p_malicious,
        confidence=0.9,
        backend="test",
    )
    updated = attach_quantum_opinion(result, opinion)
    assert (updated.verdict, updated.p_malicious) == (result.verdict, result.p_malicious)
    assert updated.quantum == opinion and updated.needs_additional_evidence
    assert result.quantum is None  # the original is not mutated
    idle = attach_quantum_opinion(result, QuantumOpinion(gate_triggered=False))
    assert idle.quantum_agrees is None


# --- configuration ---------------------------------------------------------------------------


def test_config_validation(tmp_path: Path) -> None:
    project = load_quantum_config(
        Path(__file__).parents[2] / "configs" / "quantum_adjudicator.yaml"
    )
    assert project.uncertainty.primary_band_coverage == 0.10
    assert project.uncertainty.secondary_band_coverage == 0.05
    assert project.e2.n_train == [100, 250, 500, 1000, 2000] and project.e2.dims == [4, 6, 8]
    assert len(project.e2.seeds) == 5 and len(project.e4.settings) == 8
    assert project.primary_detector == "random_forest" and project.threshold == 0.5
    bad: list[dict[str, Any]] = [
        {"uncertainty": {"primary_band_coverage": 0.05, "secondary_band_coverage": 0.10}},
        {
            "mutual_info_k": 2,
            "e2": {"n_train": [16], "dims": [4], "seeds": [0], "test_sample_size": 20},
        },
        {"e3": {"n_train": 16, "n_dims": 2, "kinds": ["logreg"]}},
        {"e3": {"n_train": 16, "n_dims": 2, "kinds": ["rbf_svm"]}},
        {"test_days": ["Wednesday"]},
    ]
    for override in bad:
        with pytest.raises(ValueError):
            make_config(**override)
    broken = tmp_path / "q.yaml"
    broken.write_text("seed: -1\n")
    with pytest.raises(ConfigurationError):
        load_quantum_config(broken)


def test_mean_ci_and_aggregation_helpers() -> None:
    assert mean_ci([]) == {"n": 0, "mean": None, "std": None, "ci95": None}
    single = mean_ci([0.5])
    assert single["mean"] == 0.5 and single["ci95"] is None
    many = mean_ci([1.0, 2.0, 3.0])
    assert many["mean"] == 2.0 and many["ci95"] == pytest.approx(2.4842, abs=1e-3)


# --- E3 leakage regression and end-to-end ------------------------------------------------------


def test_e3_fits_nothing_on_test_data(data: Data) -> None:
    config = make_config()
    oof = out_of_fold_probabilities(data.train, data.model_config, "synthetic-v1", DAYS_TRAIN)
    band = derive_band(oof.p, 0.10, 0.5, PRIMARY_BAND)
    policy = data.detector.preprocessor.policy
    args = (oof.p, data.p_test, band, policy, config, data.detector, "synthetic-v1")
    clean = run_e3_band(data.train, data.test, *args)
    poisoned_test = data.test.copy()
    poisoned_test["is_malicious"] = 1 - poisoned_test["is_malicious"]
    poisoned_test["flow_duration"] = -5.0
    poisoned = run_e3_band(data.train, poisoned_test, *args)
    for a, b in zip(clean.result.arms, poisoned.result.arms, strict=True):
        assert a.hyper == b.hyper and a.fusion_coefficients == b.fusion_coefficients
        assert a.model_version == b.model_version
    assert clean.result.features == poisoned.result.features


def test_end_to_end_run_tracking_and_persistence(tmp_path: Path, data: Data) -> None:
    config = make_config()
    run_id = make_quantum_run_id(utc_now())
    result = run_quantum_experiment(
        data.split,
        data.train,
        data.test,
        data.detector,
        data.p_test,
        data.model_config,
        config,
        "synthetic-v1",
        model_dir=tmp_path / "models",
        run_id=run_id,
    )
    assert set(result.bands) == {PRIMARY_BAND, SECONDARY_BAND}
    assert result.bands[SECONDARY_BAND].half_width <= result.bands[PRIMARY_BAND].half_width
    assert all(b.derived_from.startswith("training out-of-fold") for b in result.bands.values())
    assert result.reload_check["identical"] is True
    assert len(result.e2.cells) == 1 and {a.kind for a in result.e2.cells[0].arms} == set(ALL_KINDS)
    rows = aggregate_e2(result.e2.cells)
    assert {r["arm"] for r in rows} >= {"zz_qsvm", "paired:zz_qsvm-rbf_svm"}
    assert len(result.e4.settings) == 1 and result.e4.settings[0].circuits == 15 + 36
    primary = result.e3[PRIMARY_BAND]
    assert {a.kind for a in primary.result.arms} == {"rbf_svm", "zz_qsvm", "z_qsvm"}
    for arm in primary.result.arms:
        f = arm.flips
        assert f.flips == f.flips_to_correct + f.flips_to_wrong

    prov = QuantumProvenance(
        run_id=run_id,
        created_at=utc_now(),
        git_commit=None,
        git_dirty=None,
        environment=environment_info(),
        runtime_s=1.0,
        config_path="configs/quantum_adjudicator.yaml",
        manifest_entry=None,
        dataset_version="synthetic-v1",
        file_sha256={},
        classical={"run_id": "synthetic"},
        model_dir=None,
    )
    run_dir = write_quantum_run(
        tmp_path / "reports", config, result, prov, data.test, data.p_test, data.detector
    )
    assert sorted(p.name for p in run_dir.iterdir()) == sorted(RUN_FILES)
    assert "No quantum advantage is claimed" in (run_dir / "summary.md").read_text()
    import json

    predictions = json.loads((run_dir / "predictions.json").read_text())
    examples = predictions["detection_result_examples"]
    assert any(e["quantum"]["gate_triggered"] for e in examples)
    assert all(e["dataset_label"] for e in examples)
    record = quantum_record(config, result, prov, run_dir)
    assert record.task.value == "quantum_comparison"
    assert not set(record.train_sources) & set(record.test_sources)
    with SQLiteStore(":memory:") as store:
        assert store_quantum_record(store, record) == record

    loaded = Adjudicator.load(tmp_path / "models" / PRIMARY_BAND / "zz_qsvm")
    assert loaded.metadata.kind == "zz_qsvm" and loaded.metadata.evaluation_run_id == run_id
    opinion = loaded.opinion(0.7, 1.0)
    assert opinion.verdict == Verdict.MALICIOUS and opinion.feature_map is not None
    with pytest.raises(ValueError, match="quantum-kernel"):
        Adjudicator.load(tmp_path / "models" / PRIMARY_BAND / "rbf_svm").opinion(0.5, None)
    artifact = tmp_path / "models" / PRIMARY_BAND / "zz_qsvm" / "adjudicator.joblib"
    artifact.write_bytes(artifact.read_bytes() + b"tamper")
    with pytest.raises(ModelCheckpointNotFoundError, match="integrity"):
        Adjudicator.load(artifact.parent)
    with pytest.raises(ModelCheckpointNotFoundError, match="Incomplete"):
        Adjudicator.load(tmp_path / "missing")
    with pytest.raises(ValueError, match="share a day"):
        run_quantum_experiment(
            data.split, data.train, data.train, data.detector, data.p_test, data.model_config,
            config, "v",
        )  # fmt: skip


def test_solver_iteration_cap_is_applied_and_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """libsvm's default is unlimited iterations (it cycled on a real rank-deficient Gram)."""
    from hqc.quantum import models

    rng = np.random.default_rng(2)
    x = rng.uniform(0, np.pi, (60, 2))
    y = (x[:, 0] + rng.normal(0, 0.8, 60) > np.pi / 2).astype(int)
    ok = TrainedModel("linear_svm", Hyper(c=1.0), 2, 0).fit(x, y)
    assert ok.svc is not None and ok.svc.max_iter == models.SVC_MAX_ITER > 0
    assert ok.converged
    monkeypatch.setattr(models, "SVC_MAX_ITER", 1)
    capped = TrainedModel("linear_svm", Hyper(c=100.0), 2, 0).fit(x, y)
    assert not capped.converged and np.isfinite(capped.decision(x)).all()
    monkeypatch.setattr(models, "LOGREG_MAX_ITER", 1)
    assert not TrainedModel("logreg", Hyper(c=1.0), 2, 0).fit(x, y).converged


def test_chunked_kernel_inference_is_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    from hqc.quantum import models

    rng = np.random.default_rng(3)
    x = rng.uniform(0, np.pi, (40, 3))
    y = (x[:, 1] > np.pi / 2).astype(int)
    x_new = rng.uniform(0, np.pi, (23, 3))
    for kind in ("zz_qsvm", "rbf_svm"):
        model = TrainedModel(kind, Hyper(c=1.0, alpha=0.5, gamma=0.5), 2, 0).fit(x, y)  # type: ignore[arg-type]
        whole = model.decision(x_new)
        monkeypatch.setattr(models, "INFERENCE_CHUNK", 4)
        np.testing.assert_allclose(model.decision(x_new), whole, atol=1e-12)
        monkeypatch.undo()


def test_cv_balanced_accuracy_matches_sklearn() -> None:
    from sklearn.metrics import balanced_accuracy_score

    from hqc.quantum.cv import balanced_accuracy

    rng = np.random.default_rng(0)
    y, pred = rng.integers(0, 2, 50), rng.integers(0, 2, 50)
    assert balanced_accuracy(y, pred) == pytest.approx(balanced_accuracy_score(y, pred))
    assert balanced_accuracy(np.zeros(4, dtype=int), np.array([0, 0, 1, 1])) == 0.5
