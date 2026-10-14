"""Run tracking for Milestone 6 (same run-folder and SQLite conventions as Milestones 3-5).

``reports/runs/<run-id>/``: config.json, metrics.json, predictions.json, summary.md.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from pydantic import JsonValue

from hqc.common.provenance import ManifestArtifact
from hqc.common.schemas.base import DataOrigin, utc_now
from hqc.common.schemas.detection import DetectionResult, QuantumOpinion
from hqc.common.schemas.evaluation import (
    EnvironmentInfo,
    EvaluationResult,
    EvaluationStatus,
    EvaluationTask,
)
from hqc.detection.models import Detector
from hqc.detection.preprocessing import DaySplit
from hqc.detection.schemas import BinaryMetrics
from hqc.fusion.stacking import attach_quantum_opinion
from hqc.quantum.band import OOFFold, UncertaintyBand
from hqc.quantum.experiment import (
    PRIMARY_BAND,
    E2Result,
    E3BandRun,
    E4Result,
    QuantumExperimentConfig,
    aggregate_e2,
    balanced_accuracy,
)
from hqc.storage import Collection, Store

RUN_FILES = ("config.json", "metrics.json", "predictions.json", "summary.md")
EXAMPLES_IN_BAND = 10
EXAMPLES_OUT_OF_BAND = 5
NO_ADVANTAGE = (
    "No quantum advantage is claimed. Quantum kernels are simulated exactly on a CPU; results "
    "answer a matched-budget research question, and a null result is a valid result."
)


@dataclass(frozen=True)
class QuantumProvenance:
    run_id: str
    created_at: datetime
    git_commit: str | None
    git_dirty: bool | None
    environment: EnvironmentInfo
    runtime_s: float
    config_path: str
    manifest_entry: ManifestArtifact | None
    dataset_version: str
    file_sha256: dict[str, str]
    classical: dict[str, Any]
    model_dir: str | None


@dataclass
class QuantumRunResult:
    split: DaySplit
    oof_folds: list[OOFFold]
    bands: dict[str, UncertaintyBand]
    e2: E2Result
    e3: dict[str, E3BandRun]
    e4: E4Result
    reload_check: dict[str, Any]
    seconds: dict[str, float]


def make_quantum_run_id(now: datetime | None = None) -> str:
    return f"{(now or utc_now()).strftime('%Y%m%dT%H%M%SZ')}-quantum-adjudicator-cicids2017"


def _dump(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def _r(x: float | None, digits: int = 4) -> str:
    return "n/a" if x is None else f"{x:.{digits}f}"


def config_payload(
    config: QuantumExperimentConfig, result: QuantumRunResult, prov: QuantumProvenance
) -> dict[str, Any]:
    return {
        "run_id": prov.run_id,
        "created_at": prov.created_at.isoformat(),
        "task": "quantum-kernel second opinion for binary intrusion detection",
        "claim_policy": NO_ADVANTAGE,
        "config_file": prov.config_path,
        "config": config.model_dump(mode="json"),
        "dataset_provenance": prov.manifest_entry.model_dump(mode="json")
        if prov.manifest_entry
        else None,
        "dataset_version": prov.dataset_version,
        "file_sha256": prov.file_sha256,
        "split": {
            "train_days": list(result.split.train_days),
            "test_days": list(result.split.test_days),
            "train_files": list(result.split.train_files),
            "test_files": list(result.split.test_files),
            "policy": "whole days; no row-level mixing",
        },
        "classical_reference": prov.classical,
        "uncertainty_bands": {k: b.model_dump(mode="json") for k, b in result.bands.items()},
        "out_of_fold_folds": [f.model_dump(mode="json") for f in result.oof_folds],
        "simulation": "exact statevectors (NumPy, validated against qiskit 2.5.2 Statevector); "
        "noise study with qiskit-aer density-matrix simulation",
        "random_seed": config.seed,
        "environment": {
            "python_version": prov.environment.python_version,
            "platform": prov.environment.platform,
            "packages": prov.environment.packages,
        },
        "git_commit": prov.git_commit,
        "working_tree_dirty": prov.git_dirty,
        "model_dir": prov.model_dir,
    }


def metrics_payload(result: QuantumRunResult) -> dict[str, Any]:
    return {
        "claim_policy": NO_ADVANTAGE,
        "threshold_policy": "Milestone 5 threshold 0.5 unchanged; band half-widths, "
        "hyperparameters and fusion fitted on training days only",
        "uncertainty_bands": {k: b.model_dump(mode="json") for k, b in result.bands.items()},
        "out_of_fold_folds": [f.model_dump(mode="json") for f in result.oof_folds],
        "e2": {
            "test_sample_rows": len(result.e2.test_sample_index),
            "test_sample_label_counts": result.e2.test_sample_label_counts,
            "aggregate": aggregate_e2(result.e2.cells),
            "cells": [c.model_dump(mode="json") for c in result.e2.cells],
            "seconds": result.e2.seconds,
        },
        "e3": {k: r.result.model_dump(mode="json") for k, r in result.e3.items()},
        "e4": result.e4.model_dump(mode="json"),
        "reload_check": result.reload_check,
        "seconds": result.seconds,
    }


def _round(values: np.ndarray) -> list[float | None]:
    return [None if not np.isfinite(v) else round(float(v), 6) for v in values]


def predictions_payload(
    result: QuantumRunResult,
    test: pd.DataFrame,
    p_test: np.ndarray,
    classical: Detector,
    run_id: str,
) -> dict[str, Any]:
    primary = result.e3[PRIMARY_BAND]
    mask = primary.test_band_mask
    rows = test.loc[mask]
    columns: dict[str, Any] = {
        "source_file": rows["source_file"].tolist(),
        "row_number": rows["row_number"].astype(int).tolist(),
        "raw_label": rows["raw_label"].tolist(),
        "is_malicious": rows["is_malicious"].astype(int).tolist(),
        "p_classical": _round(p_test[mask]),
    }
    for band_name, run in result.e3.items():
        inside = run.test_band_mask[mask]
        columns[f"in_{band_name}_band"] = inside.astype(int).tolist()
        for key, values in run.outputs.items():
            full = np.full(int(mask.sum()), np.nan)
            full[inside] = values
            columns[f"{band_name}.{key}"] = _round(full)
    examples: list[DetectionResult] = []
    zz = primary.adjudicators.get("zz_qsvm")
    band_idx = np.flatnonzero(mask)[:EXAMPLES_IN_BAND]
    out_idx = np.flatnonzero(~mask)[:EXAMPLES_OUT_OF_BAND]
    p_zz = primary.outputs.get("zz_qsvm.p_second")
    for k, i in enumerate(band_idx):
        base = classical.to_results(test.iloc[[i]], p_test[[i]], include_dataset_label=True)[0]
        if zz is not None and p_zz is not None:
            base = attach_quantum_opinion(base, zz.opinion(float(p_zz[k]), None))
        examples.append(base)
    for i in out_idx:
        base = classical.to_results(test.iloc[[i]], p_test[[i]], include_dataset_label=True)[0]
        examples.append(attach_quantum_opinion(base, QuantumOpinion(gate_triggered=False)))
    return {
        "run_id": run_id,
        "note": "Test rows inside the PRIMARY uncertainty band (the secondary band is a subset). "
        "Labels are for offline evaluation only and are never model inputs. p_final is an "
        "evaluation arm; the system verdict remains the classical one.",
        "columns": columns,
        "detection_result_examples": [r.model_dump(mode="json") for r in examples],
    }


def _metric_row(name: str, m: BinaryMetrics) -> str:
    return (
        f"| {name} | {m.n} | {_r(m.precision)} | {_r(m.recall)} | {_r(m.f1)} | "
        f"{_r(m.roc_auc)} | {_r(m.pr_auc)} | {_r(m.benign_false_positive_rate)} | "
        f"{_r(balanced_accuracy(m))} |"
    )


def _ci(cell: dict[str, Any]) -> str:
    if cell.get("mean") is None:
        return "n/a"
    half = cell.get("ci95")
    return f"{cell['mean']:.3f}" + ("" if half is None else f" ± {half:.3f}")


def summary_markdown(
    config: QuantumExperimentConfig, result: QuantumRunResult, prov: QuantumProvenance
) -> str:
    header = "| arm | n | precision | recall | F1 | ROC-AUC | PR-AUC | benign FPR | bal. acc |"
    lines = [
        f"# Run {prov.run_id}",
        "",
        "Quantum-kernel second opinion on CIC-IDS2017 (whole-day holdout; Milestone 5 primary "
        f"detector `{config.primary_detector}` from run `{config.classical_run_id}` unchanged).",
        "",
        f"**{NO_ADVANTAGE}**",
        "",
        "## Uncertainty bands (training out-of-fold probabilities only)",
    ]
    for name, b in result.bands.items():
        lines.append(
            f"- {name}: target {b.target_coverage:.2f} -> [{b.lower:.4f}, {b.upper:.4f}], "
            f"train OOF coverage {b.train_oof_coverage:.4f} (n={b.train_oof_rows})"
        )
    lines += ["", "## Out-of-fold folds (primary configuration refitted per held-out day)"]
    lines += [
        f"- held out {f.held_out_day}: trained on {', '.join(f.training_days)} "
        f"({f.training_rows} rows), AUC {_r(f.held_out_roc_auc)}, {f.seconds:.1f}s"
        for f in result.oof_folds
    ]
    lines += [
        "",
        "## E2 matched budget (mean ± 95% t-CI over seeds; fixed stratified test sample of "
        f"{len(result.e2.test_sample_index)} rows)",
        "| N | d | arm | balanced acc | ROC-AUC | PR-AUC | recall | benign FPR |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in aggregate_e2(result.e2.cells):
        lines.append(
            f"| {row['n_train']} | {row['n_dims']} | {row['arm']} | "
            f"{_ci(row['balanced_accuracy'])} | {_ci(row['roc_auc'])} | {_ci(row['pr_auc'])} | "
            f"{_ci(row['recall'])} | {_ci(row['benign_false_positive_rate'])} |"
        )
    for name, run in result.e3.items():
        r = run.result
        lines += [
            "",
            f"## E3 second opinion, {name} band [{r.band.lower:.4f}, {r.band.upper:.4f}]",
            f"- train pool {r.train_pool_rows} rows {r.train_pool_day_class_counts}; sample "
            f"{r.sample_rows} {r.sample_day_class_counts}; skipped CV folds {r.skipped_cv_folds}",
            f"- test rows in band: {r.test_band_rows} (coverage {r.test_band_coverage:.4f}); "
            f"labels {r.test_band_label_counts}",
            "",
            header,
            "|---" * 9 + "|",
        ]
        if r.classical_on_band is not None:
            lines.append(_metric_row("classical only (band)", r.classical_on_band.metrics))
        for a in r.arms:
            if a.second_opinion_alone is not None:
                lines.append(_metric_row(f"{a.kind} alone (band)", a.second_opinion_alone.metrics))
            if a.fused_on_band is not None:
                lines.append(_metric_row(f"classical+{a.kind} (band)", a.fused_on_band.metrics))
        lines.append(_metric_row("classical only (all test rows)", r.classical_full_test))
        for a in r.arms:
            lines.append(_metric_row(f"classical+{a.kind} (all test rows)", a.fused_full_test))
        lines.append("")
        for a in r.arms:
            d = a.disagreement
            lines.append(
                f"- {a.kind}: hyper {a.hyper}, CV bal. acc {a.cv_balanced_accuracy:.4f}; final fit "
                f"converged {a.final_fit_converged}, capped CV fits {a.cv_nonconverged_fits}; "
                f"flips "
                f"{a.flips.flips} ({a.flips.flips_to_correct} to correct, "
                f"{a.flips.flips_to_wrong} to wrong); disagreements {d.disagree}, classical "
                f"error when disagree {_r(d.classical_error_rate_when_disagree)} vs agree "
                f"{_r(d.classical_error_rate_when_agree)}; latency "
                f"{_r(a.latency.batch_ms_per_event)} ms/event batch, "
                f"{_r(a.latency.single_event_median_ms)} ms single-event median"
            )
    e4 = result.e4
    lines += [
        "",
        f"## E4 noise ({e4.feature_map}, N_train={e4.n_train}, N_test={e4.n_test})",
        f"- exact statevector: balanced acc {_r(e4.exact_test_balanced_accuracy)}, "
        f"ROC-AUC {_r(e4.exact_test.roc_auc)}",
        "| setting | shots | p1 | p2 | readout | rel. Frobenius err (train / test) | "
        "min eig (train) | balanced acc | ROC-AUC |",
        "|---" * 9 + "|",
    ]
    for s in e4.settings:
        lines.append(
            f"| {s.setting.name} | {s.setting.shots} | {s.setting.p1} | {s.setting.p2} | "
            f"{s.setting.readout} | {s.train_relative_frobenius_error:.4f} / "
            f"{s.test_relative_frobenius_error:.4f} | {s.train_min_eigenvalue:.4f} | "
            f"{_r(s.test_balanced_accuracy)} | {_r(s.test.roc_auc)} |"
        )
    capped = [
        f"N={c.n_train} d={c.n_dims} seed={c.seed} {a.kind}: final converged "
        f"{a.final_fit_converged}, capped CV fits {a.cv_nonconverged_fits}"
        for c in result.e2.cells
        for a in c.arms
        if not a.final_fit_converged or a.cv_nonconverged_fits
    ]
    lines += ["", f"## Solver iteration cap reached (E2): {len(capped)} arm-cells"]
    lines += [f"- {line}" for line in capped]
    lines += [
        "",
        "## Provenance",
        f"- dataset version `{prov.dataset_version}`; git commit `{prov.git_commit}`; working "
        f"tree dirty: **{prov.git_dirty}**; runtime {prov.runtime_s:.1f} s.",
        f"- reload check: {result.reload_check}",
        "- CIC-IDS2017 labels are NOT ATT&CK techniques.",
    ]
    return "\n".join(lines) + "\n"


def write_quantum_run(
    reports_dir: Path,
    config: QuantumExperimentConfig,
    result: QuantumRunResult,
    prov: QuantumProvenance,
    test: pd.DataFrame,
    p_test: np.ndarray,
    classical: Detector,
) -> Path:
    run_dir = reports_dir / "runs" / prov.run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    _dump(run_dir / "config.json", config_payload(config, result, prov))
    _dump(run_dir / "metrics.json", metrics_payload(result))
    _dump(
        run_dir / "predictions.json",
        predictions_payload(result, test, p_test, classical, prov.run_id),
    )
    (run_dir / "summary.md").write_text(summary_markdown(config, result, prov), encoding="utf-8")
    return run_dir


def _put(metrics: dict[str, float], key: str, value: float | None) -> None:
    if value is not None and np.isfinite(value):
        metrics[key] = float(value)


def quantum_record(
    config: QuantumExperimentConfig,
    result: QuantumRunResult,
    prov: QuantumProvenance,
    run_dir: Path,
) -> EvaluationResult:
    metrics: dict[str, float] = {}
    for row in aggregate_e2(result.e2.cells):
        key = f"e2.n{row['n_train']}.d{row['n_dims']}.{row['arm']}"
        for name in ("balanced_accuracy", "roc_auc", "pr_auc"):
            _put(metrics, f"{key}.{name}.mean", row[name]["mean"])
    for band_name, run in result.e3.items():
        r = run.result
        _put(metrics, f"e3.{band_name}.test_band_coverage", r.test_band_coverage)
        if r.classical_on_band is not None:
            m = r.classical_on_band.metrics
            for name in ("roc_auc", "pr_auc", "recall", "benign_false_positive_rate"):
                _put(metrics, f"e3.{band_name}.classical.{name}", getattr(m, name))
        for a in r.arms:
            if a.fused_on_band is not None:
                m = a.fused_on_band.metrics
                for name in ("roc_auc", "pr_auc", "recall", "benign_false_positive_rate"):
                    _put(metrics, f"e3.{band_name}.fused_{a.kind}.{name}", getattr(m, name))
            _put(metrics, f"e3.{band_name}.fused_{a.kind}.flips", float(a.flips.flips))
    for s in result.e4.settings:
        _put(metrics, f"e4.{s.setting.name}.test_rel_frobenius", s.test_relative_frobenius_error)
        _put(metrics, f"e4.{s.setting.name}.balanced_accuracy", s.test_balanced_accuracy)
    preprocessing: dict[str, JsonValue] = {
        "angle_features": "Milestone 5 Preprocessor (same policy) refitted on each training "
        "sample -> top-k mutual information -> PCA(d) -> [0, pi]",
        "mutual_info_k": config.mutual_info_k,
        "bands": {k: b.model_dump(mode="json") for k, b in result.bands.items()},
    }
    return EvaluationResult(
        run_id=prov.run_id,
        task=EvaluationTask.QUANTUM_COMPARISON,
        status=EvaluationStatus.EVALUATED,
        created_at=prov.created_at,
        git_commit=prov.git_commit,
        git_dirty=prov.git_dirty,
        dataset_id="cicids2017-generated-labelled-flows",
        dataset_version=prov.dataset_version,
        data_origin=DataOrigin.REAL,
        attack_version=None,
        seed=config.seed,
        preprocessing_config=preprocessing,
        model_configuration={
            "grid": config.grid.model_dump(mode="json"),
            "e2": config.e2.model_dump(mode="json"),
            "e3": config.e3.model_dump(mode="json"),
            "e4": config.e4.model_dump(mode="json"),
            "classical_run_id": config.classical_run_id,
            "run_dir": str(run_dir),
            "model_dir": prov.model_dir,
        },
        metrics=metrics,
        train_sources=[f"day:{d}" for d in result.split.train_days]
        + [f"file:{f}" for f in result.split.train_files],
        test_sources=[f"day:{d}" for d in result.split.test_days]
        + [f"file:{f}" for f in result.split.test_files],
        runtime_s=prov.runtime_s,
        environment=prov.environment,
        notes=NO_ADVANTAGE,
    )


def store_quantum_record(store: Store, record: EvaluationResult) -> EvaluationResult:
    store.put(Collection.EVALUATION_RUNS, record)
    restored = store.get(Collection.EVALUATION_RUNS, record.run_id)
    if not isinstance(restored, EvaluationResult) or restored != record:
        raise RuntimeError("Stored evaluation record did not round-trip exactly")
    return restored
