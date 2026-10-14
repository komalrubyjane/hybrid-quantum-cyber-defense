"""Evaluation / experiment-run contract with built-in leakage guard."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, JsonValue, model_validator

from hqc.common.errors import DataLeakageError
from hqc.common.schemas.base import DataOrigin, HQCModel, NonEmptyStr, UTCDatetime, utc_now


class EvaluationTask(StrEnum):
    DETECTION = "detection"
    QUANTUM_COMPARISON = "quantum_comparison"
    CHAIN_PREDICTION = "chain_prediction"
    RISK = "risk"
    DEFENSE = "defense"
    END_TO_END = "end_to_end"


class EvaluationStatus(StrEnum):
    EVALUATED = "EVALUATED"
    NOT_EVALUATED = "NOT_EVALUATED"


class EnvironmentInfo(HQCModel):
    python_version: NonEmptyStr
    platform: NonEmptyStr
    executable: str | None = None
    packages: dict[str, str] = Field(default_factory=dict)


class EvaluationFold(HQCModel):
    """One train/test split of a cross-validated run; its sources must be disjoint."""

    fold_id: NonEmptyStr
    train_sources: list[NonEmptyStr]
    test_sources: list[NonEmptyStr] = Field(min_length=1)
    validation_sources: list[NonEmptyStr] = Field(
        default_factory=list,
        description="Inner validation sources (a subset of the outer-training data, "
        "excluded from inner training); must never overlap the test sources.",
    )

    @model_validator(mode="after")
    def _disjoint(self) -> EvaluationFold:
        overlap = set(self.train_sources) & set(self.test_sources)
        if overlap:
            raise DataLeakageError(
                f"Fold {self.fold_id}: sources in both train and test: {sorted(overlap)}"
            )
        val_test = set(self.validation_sources) & set(self.test_sources)
        if val_test:
            raise DataLeakageError(
                f"Fold {self.fold_id}: sources in both validation and test: {sorted(val_test)}"
            )
        return self


class EvaluationResult(HQCModel):
    """Machine-readable record of one experiment run.

    ``train_sources`` and ``test_sources`` are source identifiers (e.g. Attack Flow
    document IDs or dataset day files); overlapping sources are rejected. A
    cross-validated run lists every split in ``folds`` instead (each fold is checked).
    """

    run_id: NonEmptyStr
    task: EvaluationTask
    status: EvaluationStatus
    created_at: UTCDatetime = Field(default_factory=utc_now)
    git_commit: str | None = None
    git_dirty: bool | None = Field(
        default=None, description="True if the working tree had uncommitted changes."
    )
    dataset_id: NonEmptyStr
    dataset_version: NonEmptyStr
    data_origin: DataOrigin
    attack_version: str | None = None
    seed: int = Field(ge=0)
    preprocessing_config: dict[str, JsonValue] = Field(default_factory=dict)
    model_configuration: dict[str, JsonValue] = Field(default_factory=dict)
    metrics: dict[str, float] = Field(default_factory=dict)
    train_sources: list[NonEmptyStr] = Field(default_factory=list)
    test_sources: list[NonEmptyStr] = Field(default_factory=list)
    folds: list[EvaluationFold] = Field(default_factory=list)
    runtime_s: float | None = Field(default=None, ge=0.0)
    environment: EnvironmentInfo
    notes: str | None = None

    @model_validator(mode="after")
    def _guard(self) -> EvaluationResult:
        overlap = set(self.train_sources) & set(self.test_sources)
        if overlap:
            raise DataLeakageError(f"Sources present in both train and test: {sorted(overlap)}")
        fold_ids = [f.fold_id for f in self.folds]
        if len(fold_ids) != len(set(fold_ids)):
            raise ValueError("Duplicate fold_id values.")
        if self.status is EvaluationStatus.NOT_EVALUATED and self.metrics:
            raise ValueError("A NOT_EVALUATED run must not report metrics.")
        if self.status is EvaluationStatus.EVALUATED and not self.metrics:
            raise ValueError("An EVALUATED run must report at least one metric.")
        return self
