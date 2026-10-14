"""Typed records for CIC-IDS2017 ingestion, feature policy and detection evaluation."""

from __future__ import annotations

from pydantic import Field

from hqc.common.schemas.base import HQCModel, NonEmptyStr


class FileReport(HQCModel):
    """What happened while reading one CSV file (measured, never assumed)."""

    file_name: NonEmptyStr
    sha256: NonEmptyStr
    size_bytes: int = Field(ge=0)
    day: NonEmptyStr
    encoding: NonEmptyStr
    rows_read: int = Field(ge=0, description="Data rows in the file (header excluded).")
    empty_rows_dropped: int = Field(ge=0, description="Rows with every field empty.")
    missing_label_rows_dropped: int = Field(ge=0, description="Non-empty rows without a label.")
    rows_kept: int = Field(ge=0)
    malformed_numeric_cells: dict[str, int] = Field(
        default_factory=dict, description="Non-empty cells that could not be parsed as numbers."
    )
    nan_cells: dict[str, int] = Field(default_factory=dict)
    infinite_cells: dict[str, int] = Field(default_factory=dict)
    raw_label_counts: dict[str, int] = Field(default_factory=dict)


class DatasetStats(HQCModel):
    dataset_id: NonEmptyStr = "cicids2017-generated-labelled-flows"
    files: list[FileReport]
    rows_total: int
    rows_per_day: dict[str, int]
    label_counts: dict[str, int]
    malicious_fraction: float


class FeaturePolicy(HQCModel):
    """Reproducible feature policy. Data-dependent parts are derived from TRAINING days only."""

    version: NonEmptyStr
    used_features: list[str] = Field(description="Numeric model inputs, in model order.")
    categorical_features: dict[str, list[str]] = Field(
        default_factory=dict, description="One-hot encoded features and their training categories."
    )
    dropped_identifier_features: dict[str, str]
    dropped_non_numeric_features: dict[str, str]
    dropped_leakage_features: dict[str, str]
    dropped_duplicate_columns: dict[str, str] = Field(default_factory=dict)
    dropped_constant_features: dict[str, str] = Field(default_factory=dict)
    shortcut_risk_features: dict[str, str] = Field(
        default_factory=dict, description="Used, but evaluated with an ablation."
    )


class ConfusionCounts(HQCModel):
    true_negative: int
    false_positive: int
    false_negative: int
    true_positive: int


class BinaryMetrics(HQCModel):
    n: int
    n_malicious: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float | None
    pr_auc: float | None
    benign_false_positive_rate: float | None
    malicious_detection_rate: float | None
    confusion: ConfusionCounts
    threshold: float


class EvaluationBlock(HQCModel):
    """Metrics of one model on one subset of the test split."""

    model: NonEmptyStr
    feature_set: NonEmptyStr
    subset: NonEmptyStr
    split: NonEmptyStr
    dataset_version: NonEmptyStr
    feature_version: NonEmptyStr
    metrics: BinaryMetrics
    per_label_detection: dict[str, dict[str, float]] = Field(
        default_factory=dict,
        description="Per raw label: n and fraction predicted MALICIOUS (recall for attacks, "
        "false-positive rate for BENIGN).",
    )
    per_day: dict[str, BinaryMetrics] = Field(default_factory=dict)
