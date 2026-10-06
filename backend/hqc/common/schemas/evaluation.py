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


class EvaluationResult(HQCModel):
    """Machine-readable record of one experiment run.

    ``train_sources`` and ``test_sources`` are source identifiers (e.g. Attack Flow
    document IDs or dataset day files); overlapping sources are rejected.
    """

    run_id: NonEmptyStr
    task: EvaluationTask
    status: EvaluationStatus
    created_at: UTCDatetime = Field(default_factory=utc_now)
    git_commit: str | None = None
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
    runtime_s: float | None = Field(default=None, ge=0.0)
    environment: EnvironmentInfo
    notes: str | None = None

    @model_validator(mode="after")
    def _guard(self) -> EvaluationResult:
        overlap = set(self.train_sources) & set(self.test_sources)
        if overlap:
            raise DataLeakageError(f"Sources present in both train and test: {sorted(overlap)}")
        if self.status is EvaluationStatus.NOT_EVALUATED and self.metrics:
            raise ValueError("A NOT_EVALUATED run must not report metrics.")
        if self.status is EvaluationStatus.EVALUATED and not self.metrics:
            raise ValueError("An EVALUATED run must report at least one metric.")
        return self
