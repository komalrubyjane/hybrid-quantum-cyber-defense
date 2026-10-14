"""Milestone 6 experiments: quantum-kernel second opinion on CIC-IDS2017 (no advantage claimed).

Research question: at matched data and feature budgets, does an entangling quantum kernel
change detection quality compared with an RBF-SVM (and other classical arms) and with no
second opinion? A null result is a valid result.

- E2 matched budget: every arm trained on the same day-stratified balanced N training rows
  and the same angle features; hyperparameters by leave-one-training-day-out CV; evaluated on
  one fixed stratified sample of the held-out test days.
- E3 second opinion: adjudicators trained on training rows inside the uncertainty band
  (band and fusion derived from training out-of-fold scores only), applied to test rows that
  the Milestone 5 primary detector places in the band.
- E4 noise: Aer depolarizing / readout / shot noise on a small ZZ-kernel problem.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml
from pydantic import Field, ValidationError, model_validator
from scipy import stats

from hqc.common.errors import ConfigurationError
from hqc.common.schemas.base import HQCModel
from hqc.detection.evaluation import binary_metrics, evaluate_block
from hqc.detection.models import Detector
from hqc.detection.schemas import BinaryMetrics, EvaluationBlock, FeaturePolicy
from hqc.fusion.stacking import PlattCalibrator, StackingFusion, disagreement
from hqc.quantum.adjudicator import (
    EXACT_BACKEND,
    Adjudicator,
    AdjudicatorMetadata,
    adjudicator_version,
    describe_feature_map,
)
from hqc.quantum.band import UncertaintyBand
from hqc.quantum.cv import CVOutcome, grouped_cv_select
from hqc.quantum.feature_maps import statevectors
from hqc.quantum.features import AngleFeatures
from hqc.quantum.kernels import (
    KernelDiagnostics,
    fidelity_kernel,
    geometric_difference,
    kernel_diagnostics,
)
from hqc.quantum.models import (
    ALL_KINDS,
    KERNEL_KINDS,
    QUANTUM_KINDS,
    ForestSettings,
    HyperGrid,
    ModelKind,
    TrainedModel,
    embed,
    feature_map_for,
    gram,
    to_score,
)
from hqc.quantum.noise import NoiseSetting, NoisyKernelEstimator
from hqc.quantum.sampling import day_stratified_balanced_sample, stratified_sample

Progress = Callable[[str], None]
PRIMARY_BAND = "primary"
SECONDARY_BAND = "secondary"
SUMMARY_METRICS = ("balanced_accuracy", "roc_auc", "pr_auc", "f1", "recall",
                   "benign_false_positive_rate")  # fmt: skip
LATENCY_SINGLE_EVENTS = 100
DEFAULT_E3_KINDS: tuple[ModelKind, ...] = ("rbf_svm", "zz_qsvm", "z_qsvm")


# --- configuration -------------------------------------------------------------------------


class UncertaintyConfig(HQCModel):
    primary_band_coverage: float = Field(gt=0.0, lt=1.0)
    secondary_band_coverage: float = Field(gt=0.0, lt=1.0)


class E2Config(HQCModel):
    n_train: list[int] = Field(min_length=1)
    dims: list[int] = Field(min_length=1)
    seeds: list[int] = Field(min_length=1)
    test_sample_size: int = Field(ge=10)
    kinds: list[ModelKind] = Field(default_factory=lambda: list(ALL_KINDS))


class E3Config(HQCModel):
    n_train: int = Field(ge=4)
    n_dims: int = Field(ge=2)
    kinds: list[ModelKind] = Field(default_factory=lambda: list(DEFAULT_E3_KINDS))


class E4Config(HQCModel):
    n_train: int = Field(ge=4, le=300)
    n_test: int = Field(ge=4, le=300)
    n_dims: int = Field(ge=2)
    settings: list[NoiseSetting] = Field(min_length=1)


class QuantumExperimentConfig(HQCModel):
    seed: int = Field(ge=0)
    dataset_dir: str
    classical_run_id: str
    classical_feature_set: str = "full"
    primary_detector: str = "random_forest"
    threshold: float = Field(gt=0.0, lt=1.0)
    train_days: list[str] = Field(min_length=2)
    test_days: list[str] = Field(min_length=1)
    uncertainty: UncertaintyConfig
    feature_map_reps: int = Field(default=2, ge=1)
    mutual_info_k: int = Field(ge=2)
    grid: HyperGrid
    forest: ForestSettings = Field(default_factory=ForestSettings)
    e2: E2Config
    e3: E3Config
    e4: E4Config

    @model_validator(mode="after")
    def _consistent(self) -> QuantumExperimentConfig:
        u = self.uncertainty
        if u.secondary_band_coverage >= u.primary_band_coverage:
            raise ValueError("secondary band must be narrower than the primary band")
        dims = [*self.e2.dims, self.e3.n_dims, self.e4.n_dims]
        if max(dims) > self.mutual_info_k:
            raise ValueError("feature dimension exceeds mutual_info_k")
        if any(k not in KERNEL_KINDS for k in self.e3.kinds):
            raise ValueError("E3 adjudicators must be kernel models")
        if "zz_qsvm" not in self.e3.kinds:
            raise ValueError("E3 must include the zz_qsvm adjudicator")
        if set(self.train_days) & set(self.test_days):
            raise ValueError("train and test days overlap")
        return self


def load_quantum_config(path: Path) -> QuantumExperimentConfig:
    try:
        return QuantumExperimentConfig.model_validate(
            yaml.safe_load(path.read_text(encoding="utf-8"))
        )
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ConfigurationError(f"Invalid quantum experiment config {path}: {exc}") from exc


# --- shared helpers ------------------------------------------------------------------------


def balanced_accuracy(m: BinaryMetrics) -> float | None:
    if m.benign_false_positive_rate is None or m.malicious_detection_rate is None:
        return None
    return (m.malicious_detection_rate + 1.0 - m.benign_false_positive_rate) / 2.0


def metric_value(m: BinaryMetrics, name: str) -> float | None:
    if name == "balanced_accuracy":
        return balanced_accuracy(m)
    value = getattr(m, name)
    return None if value is None else float(value)


def mean_ci(values: list[float]) -> dict[str, float | int | None]:
    arr = np.asarray(values, dtype=np.float64)
    n = len(arr)
    if n == 0:
        return {"n": 0, "mean": None, "std": None, "ci95": None}
    std = float(arr.std(ddof=1)) if n > 1 else 0.0
    half = float(stats.t.ppf(0.975, n - 1) * std / math.sqrt(n)) if n > 1 else None
    return {"n": n, "mean": float(arr.mean()), "std": std, "ci95": half}


def _labels(frame: pd.DataFrame) -> np.ndarray:
    y: np.ndarray = frame["is_malicious"].to_numpy(dtype=np.int64)
    return y


def _day_class_counts(frame: pd.DataFrame) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for day, mal in zip(frame["day"].astype(str), frame["is_malicious"].astype(bool), strict=True):
        counts = out.setdefault(day, {})
        key = "malicious" if mal else "benign"
        counts[key] = counts.get(key, 0) + 1
    return out


# --- E2: matched-budget comparison ---------------------------------------------------------


class ArmResult(HQCModel):
    kind: str
    hyper: dict[str, float | None]
    cv_balanced_accuracy: float
    test: BinaryMetrics
    test_balanced_accuracy: float | None
    fit_seconds: float
    predict_seconds: float
    n_support: int | None
    final_fit_converged: bool
    cv_nonconverged_fits: int
    train_kernel: KernelDiagnostics | None = None


class E2Cell(HQCModel):
    n_train: int
    n_dims: int
    seed: int
    sample_day_class_counts: dict[str, dict[str, int]]
    features: dict[str, Any]
    skipped_cv_folds: list[str]
    arms: list[ArmResult]
    geometric_difference: dict[str, float]
    seconds: float


@dataclass
class E2Result:
    cells: list[E2Cell]
    test_sample_index: np.ndarray
    test_sample_label_counts: dict[str, int]
    seconds: float


def _train_gram_diagnostics(
    kind: ModelKind, outcome: CVOutcome, angles: np.ndarray, y: np.ndarray, reps: int
) -> tuple[np.ndarray, KernelDiagnostics]:
    e = embed(kind, outcome.selected, angles, reps)
    k = gram(kind, outcome.selected, e, e)
    return k, kernel_diagnostics(k, y)


def run_e2_cell(
    train: pd.DataFrame,
    test_sample: pd.DataFrame,
    policy: FeaturePolicy,
    config: QuantumExperimentConfig,
    n_train: int,
    n_dims: int,
    seed: int,
) -> E2Cell:
    started = time.perf_counter()
    reps = config.feature_map_reps
    sample = train.iloc[day_stratified_balanced_sample(train, n_train, seed)]
    y = _labels(sample)
    kinds = list(config.e2.kinds)
    cv = grouped_cv_select(
        sample, kinds, config.grid, policy, n_dims, config.mutual_info_k, reps, seed, config.forest
    )
    features = AngleFeatures(policy, n_dims, config.mutual_info_k, seed).fit(sample)
    a_train, a_test = features.transform(sample), features.transform(test_sample)
    y_test = _labels(test_sample)
    arms: list[ArmResult] = []
    grams: dict[str, np.ndarray] = {}
    for kind in kinds:
        t0 = time.perf_counter()
        model = TrainedModel(kind, cv[kind].selected, reps, seed, config.forest).fit(a_train, y)
        t1 = time.perf_counter()
        score = model.score(a_test)
        t2 = time.perf_counter()
        diag = None
        if kind in KERNEL_KINDS and kind != "linear_svm":
            grams[kind], diag = _train_gram_diagnostics(kind, cv[kind], a_train, y, reps)
        metrics = binary_metrics(y_test, score, 0.5)
        arms.append(
            ArmResult(
                kind=kind,
                hyper=cv[kind].selected.model_dump(),
                cv_balanced_accuracy=cv[kind].cv_balanced_accuracy,
                test=metrics,
                test_balanced_accuracy=balanced_accuracy(metrics),
                fit_seconds=t1 - t0,
                predict_seconds=t2 - t1,
                n_support=model.n_support,
                final_fit_converged=model.converged,
                cv_nonconverged_fits=cv[kind].nonconverged_fits,
                train_kernel=diag,
            )
        )
    geo = {
        f"g(rbf||{q})": geometric_difference(grams["rbf_svm"], grams[q])
        for q in QUANTUM_KINDS
        if q in grams and "rbf_svm" in grams
    }
    return E2Cell(
        n_train=n_train,
        n_dims=n_dims,
        seed=seed,
        sample_day_class_counts=_day_class_counts(sample),
        features=features.describe(),
        skipped_cv_folds=next(iter(cv.values())).skipped_folds,
        arms=arms,
        geometric_difference=geo,
        seconds=time.perf_counter() - started,
    )


def run_e2(
    train: pd.DataFrame,
    test: pd.DataFrame,
    policy: FeaturePolicy,
    config: QuantumExperimentConfig,
    progress: Progress | None = None,
) -> E2Result:
    started = time.perf_counter()
    test_index = stratified_sample(test, config.e2.test_sample_size, config.seed)
    test_sample = test.iloc[test_index]
    cells: list[E2Cell] = []
    total = len(config.e2.n_train) * len(config.e2.dims) * len(config.e2.seeds)
    for n in config.e2.n_train:
        for d in config.e2.dims:
            for s in config.e2.seeds:
                cell = run_e2_cell(train, test_sample, policy, config, n, d, s)
                cells.append(cell)
                if progress:
                    progress(f"E2 {len(cells)}/{total} N={n} d={d} seed={s}: {cell.seconds:.1f}s")
    counts = {str(k): int(v) for k, v in test_sample["label"].value_counts().sort_index().items()}
    return E2Result(cells, test_index, counts, time.perf_counter() - started)


def aggregate_e2(cells: list[E2Cell]) -> list[dict[str, Any]]:
    """Mean / std / 95% t-CI over seeds per (N, d, arm), plus paired zz - rbf differences."""
    rows: list[dict[str, Any]] = []
    keys = sorted({(c.n_train, c.n_dims) for c in cells})
    for n, d in keys:
        group = [c for c in cells if (c.n_train, c.n_dims) == (n, d)]
        kinds = [a.kind for a in group[0].arms]
        for kind in kinds:
            arms = [next(a for a in c.arms if a.kind == kind) for c in group]
            row: dict[str, Any] = {"n_train": n, "n_dims": d, "arm": kind}
            for name in SUMMARY_METRICS:
                values = [v for a in arms if (v := metric_value(a.test, name)) is not None]
                row[name] = mean_ci(values)
            rows.append(row)
        for q in QUANTUM_KINDS:
            if q in kinds and "rbf_svm" in kinds:
                row = {"n_train": n, "n_dims": d, "arm": f"paired:{q}-rbf_svm"}
                for name in SUMMARY_METRICS:
                    diffs = []
                    for c in group:
                        a = metric_value(next(x for x in c.arms if x.kind == q).test, name)
                        b = metric_value(next(x for x in c.arms if x.kind == "rbf_svm").test, name)
                        if a is not None and b is not None:
                            diffs.append(a - b)
                    row[name] = mean_ci(diffs)
                rows.append(row)
    return rows


# --- E3: second opinion on the uncertainty band --------------------------------------------


class FlipStats(HQCModel):
    n_band: int
    flips: int
    flips_to_correct: int
    flips_to_wrong: int


class DisagreementStats(HQCModel):
    n_band: int
    disagree: int
    classical_error_rate_when_disagree: float | None
    classical_error_rate_when_agree: float | None
    second_opinion_error_rate_when_disagree: float | None
    mean_abs_probability_difference: float | None


class LatencyStats(HQCModel):
    batch_rows: int
    batch_ms_per_event: float | None
    single_event_median_ms: float | None


class ArmBandResult(HQCModel):
    kind: str
    hyper: dict[str, float | None]
    cv_balanced_accuracy: float
    model_version: str
    n_support: int | None
    final_fit_converged: bool
    cv_nonconverged_fits: int
    fusion_coefficients: dict[str, float]
    second_opinion_alone: EvaluationBlock | None
    fused_on_band: EvaluationBlock | None
    fused_full_test: BinaryMetrics
    flips: FlipStats
    disagreement: DisagreementStats
    latency: LatencyStats


class E3BandResult(HQCModel):
    band: UncertaintyBand
    train_pool_rows: int
    train_pool_day_class_counts: dict[str, dict[str, int]]
    sample_rows: int
    sample_day_class_counts: dict[str, dict[str, int]]
    skipped_cv_folds: list[str]
    features: dict[str, Any]
    test_band_rows: int
    test_band_coverage: float
    test_band_label_counts: dict[str, int]
    classical_on_band: EvaluationBlock | None
    classical_full_test: BinaryMetrics
    arms: list[ArmBandResult]
    seconds: float


@dataclass
class E3BandRun:
    result: E3BandResult
    adjudicators: dict[str, Adjudicator]
    test_band_mask: np.ndarray
    outputs: dict[str, np.ndarray] = field(default_factory=dict)  # "<kind>.p_second", ...


def _block(
    frame: pd.DataFrame,
    p: np.ndarray,
    model: str,
    config: QuantumExperimentConfig,
    dataset_version: str,
    feature_version: str,
    subset: str,
) -> EvaluationBlock | None:
    if len(frame) == 0:
        return None
    return evaluate_block(
        frame.reset_index(drop=True),
        p,
        model=model,
        feature_set=config.classical_feature_set,
        subset=subset,
        dataset_version=dataset_version,
        feature_version=feature_version,
        threshold=config.threshold,
    )


def _single_event_latency(adj: Adjudicator, frame: pd.DataFrame, p: np.ndarray) -> float | None:
    n = min(LATENCY_SINGLE_EVENTS, len(frame))
    if n == 0:
        return None
    times = []
    for i in range(n):
        t0 = time.perf_counter()
        adj.run(frame.iloc[i : i + 1], p[i : i + 1])
        times.append((time.perf_counter() - t0) * 1000.0)
    return float(np.median(times))


def run_e3_band(
    train: pd.DataFrame,
    test: pd.DataFrame,
    p_oof: np.ndarray,
    p_test: np.ndarray,
    band: UncertaintyBand,
    policy: FeaturePolicy,
    config: QuantumExperimentConfig,
    classical: Detector,
    dataset_version: str,
    run_id: str | None = None,
) -> E3BandRun:
    started = time.perf_counter()
    reps, seed, t = config.feature_map_reps, config.seed, config.threshold
    in_pool = band.contains(p_oof)
    pool = train.loc[in_pool]
    p_pool = p_oof[in_pool]
    index = day_stratified_balanced_sample(pool, config.e3.n_train, seed, allow_fewer=True)
    sample, p_sample = pool.iloc[index], p_pool[index]
    y = _labels(sample)
    kinds = list(config.e3.kinds)
    cv = grouped_cv_select(
        sample, kinds, config.grid, policy, config.e3.n_dims, config.mutual_info_k, reps, seed
    )
    features = AngleFeatures(policy, config.e3.n_dims, config.mutual_info_k, seed).fit(sample)
    a_sample = features.transform(sample)

    test_mask = band.contains(p_test)
    test_band = test.loc[test_mask]
    p_band = p_test[test_mask]
    y_band, y_test = _labels(test_band), _labels(test)
    feature_version = classical.metadata.feature_version
    classical_block = _block(test_band, p_band, "classical_only", config, dataset_version,
                             feature_version, f"test_band_{band.name}")  # fmt: skip
    fingerprint = f"{features.describe()}|{dataset_version}|{band.model_dump_json()}|{len(sample)}"
    arms: list[ArmBandResult] = []
    adjudicators: dict[str, Adjudicator] = {}
    outputs: dict[str, np.ndarray] = {}
    for kind in kinds:
        outcome = cv[kind]
        model = TrainedModel(kind, outcome.selected, reps, seed).fit(a_sample, y)
        ok = np.isfinite(outcome.oof_decision)
        calibrator = PlattCalibrator(seed).fit(outcome.oof_decision[ok], y[ok])
        fusion = StackingFusion(seed).fit(p_sample[ok], outcome.oof_decision[ok], y[ok])
        meta = AdjudicatorMetadata(
            kind=kind,
            hyper=outcome.selected,
            feature_map=describe_feature_map(kind, outcome.selected, config.e3.n_dims, reps),
            backend=EXACT_BACKEND if kind in QUANTUM_KINDS else "classical (numpy/scikit-learn)",
            n_dims=config.e3.n_dims,
            band=band.name,
            band_lower=band.lower,
            band_upper=band.upper,
            training_rows=len(sample),
            training_malicious=int(y.sum()),
            sample_seed=seed,
            cv_balanced_accuracy=outcome.cv_balanced_accuracy,
            n_support=model.n_support,
            dataset_version=dataset_version,
            classical_model_version=classical.metadata.model_version,
            model_version=adjudicator_version(kind, outcome.selected, fingerprint),
            evaluation_run_id=run_id,
        )
        adj = Adjudicator(features, model, calibrator, fusion, meta)
        adjudicators[kind] = adj
        out = adj.run(test_band, p_band)
        outputs[f"{kind}.decision"] = out.decision
        outputs[f"{kind}.p_second"] = out.p_second
        outputs[f"{kind}.p_final"] = out.p_final
        p_full = p_test.copy()
        p_full[test_mask] = out.p_final
        cls_v, fused_v, q_v = p_band >= t, out.p_final >= t, out.p_second >= t
        flips = cls_v != fused_v
        disagree = q_v != cls_v
        cls_err, q_err = cls_v != y_band.astype(bool), q_v != y_band.astype(bool)

        def rate(err: np.ndarray, mask: np.ndarray) -> float | None:
            return float(err[mask].mean()) if mask.any() else None

        arms.append(
            ArmBandResult(
                kind=kind,
                hyper=outcome.selected.model_dump(),
                cv_balanced_accuracy=outcome.cv_balanced_accuracy,
                model_version=meta.model_version,
                n_support=model.n_support,
                final_fit_converged=model.converged,
                cv_nonconverged_fits=outcome.nonconverged_fits,
                fusion_coefficients=fusion.coefficients,
                second_opinion_alone=_block(test_band, out.p_second, f"{kind}_alone", config,
                                            dataset_version, feature_version,
                                            f"test_band_{band.name}"),
                fused_on_band=_block(test_band, out.p_final, f"classical+{kind}", config,
                                     dataset_version, feature_version, f"test_band_{band.name}"),
                fused_full_test=binary_metrics(y_test, p_full, t),
                flips=FlipStats(
                    n_band=len(test_band),
                    flips=int(flips.sum()),
                    flips_to_correct=int((flips & (fused_v == y_band.astype(bool))).sum()),
                    flips_to_wrong=int((flips & (fused_v != y_band.astype(bool))).sum()),
                ),
                disagreement=DisagreementStats(
                    n_band=len(test_band),
                    disagree=int(disagree.sum()),
                    classical_error_rate_when_disagree=rate(cls_err, disagree),
                    classical_error_rate_when_agree=rate(cls_err, ~disagree),
                    second_opinion_error_rate_when_disagree=rate(q_err, disagree),
                    mean_abs_probability_difference=float(disagreement(p_band, out.p_second).mean())
                    if len(test_band)
                    else None,
                ),
                latency=LatencyStats(
                    batch_rows=len(test_band),
                    batch_ms_per_event=out.seconds * 1000.0 / len(test_band)
                    if len(test_band)
                    else None,
                    single_event_median_ms=_single_event_latency(adj, test_band, p_band),
                ),
            )
        )  # fmt: skip
    result = E3BandResult(
        band=band,
        train_pool_rows=len(pool),
        train_pool_day_class_counts=_day_class_counts(pool),
        sample_rows=len(sample),
        sample_day_class_counts=_day_class_counts(sample),
        skipped_cv_folds=next(iter(cv.values())).skipped_folds,
        features=features.describe(),
        test_band_rows=len(test_band),
        test_band_coverage=float(test_mask.mean()),
        test_band_label_counts={
            str(k): int(v) for k, v in test_band["label"].value_counts().sort_index().items()
        },
        classical_on_band=classical_block,
        classical_full_test=binary_metrics(y_test, p_test, t),
        arms=arms,
        seconds=time.perf_counter() - started,
    )
    return E3BandRun(result, adjudicators, test_mask, outputs)


# --- E4: noise robustness ------------------------------------------------------------------


class NoiseResult(HQCModel):
    setting: NoiseSetting
    train_relative_frobenius_error: float
    train_mean_abs_error: float
    test_relative_frobenius_error: float
    test_mean_abs_error: float
    train_min_eigenvalue: float
    test: BinaryMetrics
    test_balanced_accuracy: float | None
    solver_converged: bool
    circuits: int
    seconds: float


class E4Result(HQCModel):
    n_train: int
    n_test: int
    n_dims: int
    hyper: dict[str, float | None]
    feature_map: str
    exact_test: BinaryMetrics
    exact_test_balanced_accuracy: float | None
    exact_solver_converged: bool
    settings: list[NoiseResult]
    seconds: float


def _relative_error(noisy: np.ndarray, exact: np.ndarray) -> tuple[float, float]:
    diff = noisy - exact
    return float(np.linalg.norm(diff) / np.linalg.norm(exact)), float(np.abs(diff).mean())


def run_e4(
    train: pd.DataFrame,
    test: pd.DataFrame,
    policy: FeaturePolicy,
    config: QuantumExperimentConfig,
    progress: Progress | None = None,
) -> E4Result:
    started = time.perf_counter()
    c, seed, reps = config.e4, config.seed, config.feature_map_reps
    sample = train.iloc[day_stratified_balanced_sample(train, c.n_train, seed)]
    test_sample = test.iloc[stratified_sample(test, c.n_test, seed)]
    y, y_test = _labels(sample), _labels(test_sample)
    hyper = grouped_cv_select(
        sample, ["zz_qsvm"], config.grid, policy, c.n_dims, config.mutual_info_k, reps, seed
    )["zz_qsvm"].selected
    features = AngleFeatures(policy, c.n_dims, config.mutual_info_k, seed).fit(sample)
    if hyper.alpha is None:
        raise ConfigurationError("zz_qsvm selection returned no alpha")
    a_tr = features.transform(sample) * hyper.alpha  # final rotation angles
    a_te = features.transform(test_sample) * hyper.alpha
    spec = feature_map_for("zz_qsvm", reps)
    e_tr, e_te = statevectors(a_tr, spec), statevectors(a_te, spec)
    k_tr, k_te = fidelity_kernel(e_tr, e_tr), fidelity_kernel(e_te, e_tr)

    def evaluate(k_train: np.ndarray, k_test: np.ndarray) -> tuple[BinaryMetrics, bool]:
        model = TrainedModel("zz_qsvm", hyper, reps, seed).fit_gram(k_train, y)
        support = model.svc.support_ if model.svc is not None else np.array([], dtype=int)
        decision = model.decision_from_gram(k_test[:, support])
        return binary_metrics(y_test, to_score("zz_qsvm", decision), 0.5), model.converged

    exact, exact_converged = evaluate(k_tr, k_te)
    results: list[NoiseResult] = []
    for setting in c.settings:
        t0 = time.perf_counter()
        estimator = NoisyKernelEstimator(spec, c.n_dims, setting, seed)
        n_tr = estimator.train_gram(a_tr)
        n_te = estimator.cross_gram(a_te, a_tr)
        metrics, converged = evaluate(n_tr, n_te)
        off = ~np.eye(len(n_tr), dtype=bool)
        tr_rel, _ = _relative_error(n_tr, k_tr)
        te_rel, te_mae = _relative_error(n_te, k_te)
        results.append(
            NoiseResult(
                setting=setting,
                train_relative_frobenius_error=tr_rel,
                train_mean_abs_error=float(np.abs(n_tr - k_tr)[off].mean()),
                test_relative_frobenius_error=te_rel,
                test_mean_abs_error=te_mae,
                train_min_eigenvalue=float(np.linalg.eigvalsh(n_tr).min()),
                test=metrics,
                test_balanced_accuracy=balanced_accuracy(metrics),
                solver_converged=converged,
                circuits=estimator.circuits_run,
                seconds=time.perf_counter() - t0,
            )
        )
        if progress:
            progress(f"E4 {setting.name}: {results[-1].seconds:.1f}s")
    return E4Result(
        n_train=len(sample),
        n_test=len(test_sample),
        n_dims=c.n_dims,
        hyper=hyper.model_dump(),
        feature_map=spec.describe(c.n_dims, hyper.alpha),
        exact_test=exact,
        exact_test_balanced_accuracy=balanced_accuracy(exact),
        exact_solver_converged=exact_converged,
        settings=results,
        seconds=time.perf_counter() - started,
    )
