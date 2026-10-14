"""Classical binary detectors (scikit-learn) with reproducible persistence.

Models are pre-declared (no test-set selection or tuning):
- ``logreg``: LogisticRegression, class_weight="balanced" (imbalance handled by weighting).
- ``random_forest``: RandomForestClassifier, class_weight="balanced_subsample".
The PRIMARY detector for Milestone 6 is pre-registered as ``random_forest``.

Artifacts are written with joblib (pickle-based): only load artifacts this project wrote.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

import joblib
import numpy as np
import pandas as pd
from pydantic import Field
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from hqc.common.errors import ModelCheckpointNotFoundError
from hqc.common.schemas.base import HQCModel, NonEmptyStr, UTCDatetime, Verdict, utc_now
from hqc.common.schemas.detection import DetectionResult, confidence_from_probability
from hqc.detection.preprocessing import Preprocessor

ModelName = Literal["logreg", "random_forest"]
PRIMARY_DETECTOR: ModelName = "random_forest"
DEFAULT_THRESHOLD = 0.5


class ModelConfig(HQCModel):
    name: ModelName
    seed: int = Field(ge=0)
    threshold: float = Field(default=DEFAULT_THRESHOLD, gt=0.0, lt=1.0)
    logreg_max_iter: int = Field(default=1000, ge=1)
    logreg_c: float = Field(default=1.0, gt=0.0)
    rf_n_estimators: int = Field(default=100, ge=1)
    rf_min_samples_leaf: int = Field(default=2, ge=1)
    rf_max_features: Literal["sqrt", "log2"] = "sqrt"
    n_jobs: int = -1


def build_estimator(config: ModelConfig) -> LogisticRegression | RandomForestClassifier:
    if config.name == "logreg":
        return LogisticRegression(
            C=config.logreg_c,
            class_weight="balanced",
            max_iter=config.logreg_max_iter,
            solver="lbfgs",
            random_state=config.seed,
        )
    return RandomForestClassifier(
        n_estimators=config.rf_n_estimators,
        min_samples_leaf=config.rf_min_samples_leaf,
        max_features=config.rf_max_features,
        class_weight="balanced_subsample",
        n_jobs=config.n_jobs,
        random_state=config.seed,
    )


class DetectorMetadata(HQCModel):
    model_type: NonEmptyStr
    model_name: NonEmptyStr
    model_version: NonEmptyStr
    training_dataset: NonEmptyStr
    dataset_version: NonEmptyStr
    feature_version: NonEmptyStr
    preprocessing_version: NonEmptyStr
    training_days: list[str]
    training_rows: int
    seed: int
    threshold: float
    config: ModelConfig
    trained_at: UTCDatetime = Field(default_factory=utc_now)
    training_seconds: float = 0.0
    git_commit: str | None = None
    git_dirty: bool | None = None
    package_versions: dict[str, str] = Field(default_factory=dict)
    primary_detector: bool = False
    evaluation_run_id: str | None = None
    notes: str | None = None


class Detector:
    """Preprocessor + fitted estimator + metadata."""

    def __init__(
        self,
        preprocessor: Preprocessor,
        estimator: LogisticRegression | RandomForestClassifier,
        metadata: DetectorMetadata,
    ) -> None:
        self.preprocessor = preprocessor
        self.estimator = estimator
        self.metadata = metadata

    def predict_proba(self, frame: pd.DataFrame) -> np.ndarray:
        """P(MALICIOUS) per row, in [0, 1]."""
        x = self.preprocessor.transform(frame)
        proba = self.estimator.predict_proba(x)
        classes = list(self.estimator.classes_)
        if 1 not in classes:
            return np.zeros(len(frame), dtype=np.float64)
        clipped: np.ndarray = np.clip(proba[:, classes.index(1)].astype(np.float64), 0.0, 1.0)
        return clipped

    def to_results(
        self,
        frame: pd.DataFrame,
        probabilities: np.ndarray | None = None,
        include_dataset_label: bool = False,
    ) -> list[DetectionResult]:
        """Typed results. The dataset label is attached only for offline evaluation."""
        p = self.predict_proba(frame) if probabilities is None else probabilities
        threshold = self.metadata.threshold
        results = []
        for i, (_, row) in enumerate(frame.iterrows()):
            p_mal = float(p[i])
            confidence = confidence_from_probability(p_mal)
            results.append(
                DetectionResult(
                    event_id=f"{row.get('source_file', 'flow')}:{row.get('row_number', i)}",
                    model_id=self.metadata.model_name,
                    model_version=self.metadata.model_version,
                    verdict=Verdict.MALICIOUS if p_mal >= threshold else Verdict.BENIGN,
                    p_malicious=p_mal,
                    confidence=confidence,
                    uncertainty=1.0 - confidence,
                    threshold=threshold,
                    flow_id=str(row["flow_id"]) if row.get("flow_id") else None,
                    feature_version=self.metadata.feature_version,
                    preprocessing_version=self.metadata.preprocessing_version,
                    dataset_label=str(row["label"]) if include_dataset_label else None,
                    evidence={
                        k: str(row[k])
                        for k in ("timestamp", "day", "source_file")
                        if k in row and row[k] != ""
                    },
                )
            )
        return results

    def save(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        stem = directory / self.metadata.model_name
        joblib.dump(self.estimator, stem.with_suffix(".joblib"), compress=3)
        self.preprocessor.save(directory / f"{self.metadata.model_name}.preprocessing.json")
        stem.with_suffix(".json").write_text(self.metadata.model_dump_json(indent=1) + "\n")
        return stem

    @classmethod
    def load(cls, directory: Path, name: str) -> Detector:
        stem = directory / name
        paths = [
            stem.with_suffix(".joblib"),
            stem.with_suffix(".json"),
            directory / f"{name}.preprocessing.json",
        ]
        if not all(p.is_file() for p in paths):
            raise ModelCheckpointNotFoundError(
                f"Incomplete detector artifacts for {name} in {directory}"
            )
        metadata = DetectorMetadata.model_validate_json(paths[1].read_text())
        preprocessor = Preprocessor.load(paths[2])
        if preprocessor.version != metadata.preprocessing_version:
            raise ModelCheckpointNotFoundError("Preprocessing version does not match the model")
        estimator = joblib.load(paths[0])
        return cls(preprocessor, estimator, metadata)


def train_detector(
    config: ModelConfig,
    preprocessor: Preprocessor,
    train: pd.DataFrame,
    dataset_version: str,
    training_days: Sequence[str],
    extra: dict[str, Any] | None = None,
) -> Detector:
    """Fit on training rows only (the preprocessor must already be fitted on them)."""
    x = preprocessor.transform(train)
    y = train["is_malicious"].to_numpy(dtype=np.int64)
    estimator = build_estimator(config)
    started = time.perf_counter()
    estimator.fit(x, y)
    seconds = time.perf_counter() - started
    version_payload = json.dumps(
        {
            "config": config.model_dump(mode="json"),
            "prep": preprocessor.version,
            "data": dataset_version,
        },
        sort_keys=True,
    )
    metadata = DetectorMetadata(
        model_type=type(estimator).__name__,
        model_name=config.name,
        model_version=f"{config.name}-{hashlib.sha256(version_payload.encode()).hexdigest()[:12]}",
        training_dataset="cicids2017-generated-labelled-flows",
        dataset_version=dataset_version,
        feature_version=preprocessor.policy.version,
        preprocessing_version=preprocessor.version,
        training_days=list(training_days),
        training_rows=len(train),
        seed=config.seed,
        threshold=config.threshold,
        config=config,
        training_seconds=seconds,
        primary_detector=config.name == PRIMARY_DETECTOR,
        **(extra or {}),
    )
    return Detector(preprocessor, estimator, metadata)
