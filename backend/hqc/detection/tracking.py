"""Run tracking for Milestone 5 (reuses the project run-folder and SQLite conventions).

``reports/runs/<run-id>/``: config.json, metrics.json, predictions.json, summary.md.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import JsonValue

from hqc.common.provenance import ManifestArtifact
from hqc.common.schemas.base import DataOrigin, utc_now
from hqc.common.schemas.evaluation import (
    EnvironmentInfo,
    EvaluationResult,
    EvaluationStatus,
    EvaluationTask,
)
from hqc.detection.dataset import CicDataset
from hqc.detection.experiment import ALL_TEST, FULL, DetectionConfig, DetectionExperimentResult
from hqc.detection.models import PRIMARY_DETECTOR
from hqc.storage import Collection, Store

RUN_FILES = ("config.json", "metrics.json", "predictions.json", "summary.md")
EXAMPLE_RESULTS = 20


@dataclass(frozen=True)
class DetectionProvenance:
    run_id: str
    created_at: datetime
    git_commit: str | None
    git_dirty: bool | None
    environment: EnvironmentInfo
    runtime_s: float
    config_path: str
    manifest_entry: ManifestArtifact | None
    model_dir: str | None


def make_detection_run_id(now: datetime | None = None) -> str:
    return f"{(now or utc_now()).strftime('%Y%m%dT%H%M%SZ')}-classical-detection-cicids2017"


def _dump(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def config_payload(
    config: DetectionConfig,
    dataset: CicDataset,
    result: DetectionExperimentResult,
    prov: DetectionProvenance,
) -> dict[str, Any]:
    return {
        "run_id": prov.run_id,
        "created_at": prov.created_at.isoformat(),
        "task": "binary intrusion detection (BENIGN vs MALICIOUS)",
        "config_file": prov.config_path,
        "config": config.model_dump(mode="json"),
        "dataset_provenance": prov.manifest_entry.model_dump(mode="json")
        if prov.manifest_entry
        else None,
        "dataset_version": result.dataset_version,
        "file_sha256": {f.file_name: f.sha256 for f in dataset.stats.files},
        "split": {
            "train_days": list(result.split.train_days),
            "test_days": list(result.split.test_days),
            "train_files": list(result.split.train_files),
            "test_files": list(result.split.test_files),
            "policy": "whole days; no row-level mixing",
        },
        "feature_policies": {
            fs.name: fs.policy.model_dump(mode="json") for fs in result.feature_sets
        },
        "preprocessing": {
            fs.name: {"version": fs.preprocessor.version, "fitted_on": "training days only"}
            for fs in result.feature_sets
        },
        "primary_detector": PRIMARY_DETECTOR,
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


def metrics_payload(dataset: CicDataset, result: DetectionExperimentResult) -> dict[str, Any]:
    return {
        "threshold_policy": "fixed 0.5; not tuned on test data",
        "evaluations": [b.model_dump(mode="json") for fs in result.feature_sets for b in fs.blocks],
        "duplicate_audit": {fs.name: fs.audit.summary() for fs in result.feature_sets},
        "training_warnings": {fs.name: fs.warnings for fs in result.feature_sets},
        "class_distribution": result.class_distribution,
        "dataset_statistics": dataset.stats.model_dump(mode="json"),
        "seconds": result.seconds,
    }


def predictions_payload(result: DetectionExperimentResult, run_id: str) -> dict[str, Any]:
    primary = next(fs for fs in result.feature_sets if fs.name == FULL)
    test = result.test_frame
    detector = primary.detectors[PRIMARY_DETECTOR]
    sample = test.head(EXAMPLE_RESULTS)
    examples = detector.to_results(
        sample, primary.probabilities[PRIMARY_DETECTOR][: len(sample)], include_dataset_label=True
    )
    return {
        "run_id": run_id,
        "feature_set": FULL,
        "note": "Columnar per-row test predictions (held-out days). raw_label/is_malicious are "
        "for offline evaluation only and are never model inputs.",
        "columns": {
            "source_file": test["source_file"].tolist(),
            "row_number": test["row_number"].astype(int).tolist(),
            "raw_label": test["raw_label"].tolist(),
            "is_malicious": test["is_malicious"].astype(int).tolist(),
            "feature_vector_seen_in_train": primary.audit.cross_split_mask.astype(int).tolist(),
            **{
                f"p_malicious_{name}": [round(float(v), 6) for v in p]
                for name, p in primary.probabilities.items()
            },
        },
        "detection_result_examples": [r.model_dump(mode="json") for r in examples],
    }


def _row(block: Any) -> str:
    m = block.metrics

    def f(x: float | None) -> str:
        return "n/a" if x is None else f"{x:.4f}"

    return (
        f"| {block.model} | {block.feature_set} | {block.subset} | {m.n} | {f(m.accuracy)} | "
        f"{f(m.precision)} | {f(m.recall)} | {f(m.f1)} | {f(m.roc_auc)} | {f(m.pr_auc)} | "
        f"{f(m.benign_false_positive_rate)} | {f(m.malicious_detection_rate)} |"
    )


def summary_markdown(
    config: DetectionConfig,
    dataset: CicDataset,
    result: DetectionExperimentResult,
    prov: DetectionProvenance,
) -> str:
    lines = [
        f"# Run {prov.run_id}",
        "",
        "Classical binary intrusion detection on CIC-IDS2017 (GeneratedLabelledFlows), "
        "whole-day holdout. Threshold fixed at "
        f"{config.threshold}; no tuning on test data. Primary detector (pre-registered): "
        f"`{PRIMARY_DETECTOR}`.",
        "",
        "**The test days contain attack types absent from the training days**, so low recall "
        "on those categories is an expected research finding (generalisation to unseen "
        "attack types), not a defect to hide.",
        "",
        "## Split (whole days)",
        f"- TRAIN days: {', '.join(result.split.train_days)} — files: "
        + ", ".join(f"`{f}`" for f in result.split.train_files),
        f"- TEST days: {', '.join(result.split.test_days)} — files: "
        + ", ".join(f"`{f}`" for f in result.split.test_files),
        "",
        "## Class distribution (normalised labels)",
        f"- train: {result.class_distribution['train']}",
        f"- test: {result.class_distribution['test']}",
        "",
        "## Results (MALICIOUS = positive class)",
        "| model | features | subset | n | accuracy | precision | recall | F1 | ROC-AUC | "
        "PR-AUC | benign FPR | malicious DR |",
        "|---" * 12 + "|",
        *[_row(b) for fs in result.feature_sets for b in fs.blocks],
        "",
        "## Confusion matrices (all test rows)",
    ]
    for fs in result.feature_sets:
        for b in fs.blocks:
            if b.subset == ALL_TEST:
                c = b.metrics.confusion
                lines.append(
                    f"- {b.model}/{fs.name}: TN={c.true_negative} FP={c.false_positive} "
                    f"FN={c.false_negative} TP={c.true_positive}"
                )
    lines += ["", "## Per-label predicted-MALICIOUS rate (all test rows)"]
    for fs in result.feature_sets:
        for b in fs.blocks:
            if b.subset == ALL_TEST:
                rates = ", ".join(
                    f"{k} {v['predicted_malicious_rate']:.4f} (n={int(v['n'])})"
                    for k, v in b.per_label_detection.items()
                )
                lines.append(f"- {b.model}/{fs.name}: {rates}")
    lines += ["", "## Duplicate audit (exact model-input vectors)"]
    lines += [f"- {fs.name}: {fs.audit.summary()}" for fs in result.feature_sets]
    lines += ["", "## Feature policy (primary)"]
    primary = next(fs for fs in result.feature_sets if fs.name == FULL)
    p = primary.policy
    lines += [
        f"- version `{p.version}`; USED_FEATURES ({len(p.used_features)}): "
        + ", ".join(p.used_features),
        f"- categorical: {p.categorical_features}",
        f"- DROPPED_IDENTIFIER_FEATURES: {sorted(p.dropped_identifier_features)}",
        f"- DROPPED_NON_NUMERIC_FEATURES: {sorted(p.dropped_non_numeric_features)}",
        f"- DROPPED_LEAKAGE_FEATURES: {sorted(p.dropped_leakage_features)}",
        f"- duplicate columns dropped: {sorted(p.dropped_duplicate_columns)}",
        f"- constant on training days: {sorted(p.dropped_constant_features)}",
        f"- shortcut risk (ablation): {sorted(p.shortcut_risk_features)}",
        "",
        "## Provenance",
        f"- dataset version `{result.dataset_version}`; git commit `{prov.git_commit}`; working "
        f"tree dirty: **{prov.git_dirty}**; runtime {prov.runtime_s:.1f} s.",
        "- CIC-IDS2017 labels are NOT ATT&CK techniques; mapping is a later milestone.",
    ]
    return "\n".join(lines) + "\n"


def write_detection_run(
    reports_dir: Path,
    config: DetectionConfig,
    dataset: CicDataset,
    result: DetectionExperimentResult,
    prov: DetectionProvenance,
) -> Path:
    run_dir = reports_dir / "runs" / prov.run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    _dump(run_dir / "config.json", config_payload(config, dataset, result, prov))
    _dump(run_dir / "metrics.json", metrics_payload(dataset, result))
    _dump(run_dir / "predictions.json", predictions_payload(result, prov.run_id))
    (run_dir / "summary.md").write_text(
        summary_markdown(config, dataset, result, prov), encoding="utf-8"
    )
    return run_dir


def detection_record(
    config: DetectionConfig,
    result: DetectionExperimentResult,
    prov: DetectionProvenance,
    run_dir: Path,
) -> EvaluationResult:
    metrics: dict[str, float] = {}
    for fs in result.feature_sets:
        for b in fs.blocks:
            key = f"{fs.name}.{b.model}.{b.subset}"
            m = b.metrics
            for name in ("accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc",
                         "benign_false_positive_rate", "malicious_detection_rate"):  # fmt: skip
                value = getattr(m, name)
                if value is not None:
                    metrics[f"{key}.{name}"] = float(value)
    preprocessing: dict[str, JsonValue] = {
        fs.name: {
            "feature_version": fs.policy.version,
            "preprocessing_version": fs.preprocessor.version,
        }
        for fs in result.feature_sets
    }
    return EvaluationResult(
        run_id=prov.run_id,
        task=EvaluationTask.DETECTION,
        status=EvaluationStatus.EVALUATED,
        created_at=prov.created_at,
        git_commit=prov.git_commit,
        git_dirty=prov.git_dirty,
        dataset_id="cicids2017-generated-labelled-flows",
        dataset_version=result.dataset_version,
        data_origin=DataOrigin.REAL,
        attack_version=None,
        seed=config.seed,
        preprocessing_config=preprocessing,
        model_configuration={
            "models": [m.model_dump(mode="json") for m in config.models],
            "primary_detector": PRIMARY_DETECTOR,
            "threshold": config.threshold,
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
        notes=(
            "CIC-IDS2017 labels are not ATT&CK techniques; test days contain unseen attack types."
        ),
    )


def store_detection_record(store: Store, record: EvaluationResult) -> EvaluationResult:
    store.put(Collection.EVALUATION_RUNS, record)
    restored = store.get(Collection.EVALUATION_RUNS, record.run_id)
    if not isinstance(restored, EvaluationResult) or restored != record:
        raise RuntimeError("Stored evaluation record did not round-trip exactly")
    return restored
