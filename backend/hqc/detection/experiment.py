"""Milestone 5 experiment: day-based holdout evaluation of classical detectors.

load CSVs -> whole-day split -> feature policy (train only) -> preprocessor (train only)
-> duplicate audit -> train LR / RF -> evaluate on held-out days (all rows, and rows
whose feature vector does not occur in training) -> destination-port ablation.
"""

from __future__ import annotations

import time
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml
from pydantic import Field, ValidationError

from hqc.common.errors import ConfigurationError
from hqc.common.schemas.base import HQCModel
from hqc.detection.dataset import CicDataset
from hqc.detection.evaluation import evaluate_block
from hqc.detection.models import Detector, ModelConfig, train_detector
from hqc.detection.preprocessing import (
    DaySplit,
    DuplicateAudit,
    Preprocessor,
    build_feature_policy,
    day_split,
    duplicate_audit,
    split_masks,
)
from hqc.detection.schemas import EvaluationBlock, FeaturePolicy

FULL = "full"
NO_DSTPORT = "no_destination_port"
ALL_TEST = "all_test_rows"
NO_CROSS_DUP = "test_rows_not_in_train"


class DetectionConfig(HQCModel):
    seed: int = Field(ge=0)
    dataset_dir: str
    threshold: float = Field(gt=0.0, lt=1.0)
    train_days: list[str] = Field(min_length=1)
    test_days: list[str] = Field(min_length=1)
    models: list[ModelConfig] = Field(min_length=1)
    ablation_drop_destination_port: bool = True
    run_rbf_svm: bool = False


def load_detection_config(path: Path) -> DetectionConfig:
    try:
        config = DetectionConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ConfigurationError(f"Invalid detection config {path}: {exc}") from exc
    if config.run_rbf_svm:
        raise ConfigurationError("RBF SVM is not implemented in Milestone 5 (see config comment)")
    if any(m.threshold != config.threshold for m in config.models):
        config = config.model_copy(
            update={
                "models": [
                    m.model_copy(update={"threshold": config.threshold}) for m in config.models
                ]
            }
        )
    return config


@dataclass
class FeatureSetResult:
    name: str
    policy: FeaturePolicy
    preprocessor: Preprocessor
    audit: DuplicateAudit
    detectors: dict[str, Detector]
    probabilities: dict[str, np.ndarray]
    blocks: list[EvaluationBlock]
    warnings: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class DetectionExperimentResult:
    split: DaySplit
    dataset_version: str
    class_distribution: dict[str, dict[str, int]]
    feature_sets: list[FeatureSetResult]
    test_frame: pd.DataFrame
    seconds: dict[str, float]


ProgressCallback = Callable[[str], None]


def class_distribution(frame: pd.DataFrame) -> dict[str, int]:
    return {str(k): int(v) for k, v in frame["label"].value_counts().sort_index().items()}


def run_feature_set(
    name: str,
    train: pd.DataFrame,
    test: pd.DataFrame,
    config: DetectionConfig,
    dataset_version: str,
    drop_destination_port: bool,
    progress: ProgressCallback | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> FeatureSetResult:
    policy = build_feature_policy(train, drop_destination_port=drop_destination_port)
    preprocessor = Preprocessor(policy).fit(train)  # TRAIN ROWS ONLY
    audit = duplicate_audit(train, test, policy)
    detectors: dict[str, Detector] = {}
    probabilities: dict[str, np.ndarray] = {}
    blocks: list[EvaluationBlock] = []
    caught: dict[str, list[str]] = {}
    keep = ~audit.cross_split_mask
    for model_config in config.models:
        with warnings.catch_warnings(record=True) as records:
            warnings.simplefilter("always")
            detector = train_detector(
                model_config,
                preprocessor,
                train,
                dataset_version,
                config.train_days,
                extra_metadata,
            )
        caught[model_config.name] = sorted({f"{w.category.__name__}: {w.message}" for w in records})
        p = detector.predict_proba(test)
        detectors[model_config.name] = detector
        probabilities[model_config.name] = p
        for subset, mask in ((ALL_TEST, np.ones(len(test), dtype=bool)), (NO_CROSS_DUP, keep)):
            blocks.append(
                evaluate_block(
                    test.loc[mask].reset_index(drop=True),
                    p[mask],
                    model=model_config.name,
                    feature_set=name,
                    subset=subset,
                    dataset_version=dataset_version,
                    feature_version=policy.version,
                    threshold=model_config.threshold,
                )
            )
        if progress:
            progress(
                f"{name}/{model_config.name}: trained in {detector.metadata.training_seconds:.1f}s"
            )
    return FeatureSetResult(
        name, policy, preprocessor, audit, detectors, probabilities, blocks, caught
    )


def run_detection_experiment(
    dataset: CicDataset,
    config: DetectionConfig,
    dataset_version: str,
    progress: ProgressCallback | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> DetectionExperimentResult:
    started = time.perf_counter()
    frame = dataset.frame
    split = day_split(frame, config.train_days, config.test_days)
    train_mask, test_mask = split_masks(frame, split)
    train = frame.loc[train_mask].reset_index(drop=True)
    test = frame.loc[test_mask].reset_index(drop=True)
    seconds: dict[str, float] = {}
    sets: list[FeatureSetResult] = []
    plans = [(FULL, False)] + (
        [(NO_DSTPORT, True)] if config.ablation_drop_destination_port else []
    )
    for name, drop in plans:
        t0 = time.perf_counter()
        sets.append(
            run_feature_set(
                name, train, test, config, dataset_version, drop, progress, extra_metadata
            )
        )
        seconds[name] = time.perf_counter() - t0
    seconds["total"] = time.perf_counter() - started
    return DetectionExperimentResult(
        split=split,
        dataset_version=dataset_version,
        class_distribution={"train": class_distribution(train), "test": class_distribution(test)},
        feature_sets=sets,
        test_frame=test,
        seconds=seconds,
    )
