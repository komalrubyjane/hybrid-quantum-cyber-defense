"""Risk assessment contract. Scores are model-derived, never ground truth."""

from __future__ import annotations

from typing import Final, Literal

from pydantic import Field

from hqc.common.schemas.base import (
    HQCModel,
    NonEmptyStr,
    Probability,
    RiskLevel,
    TechniqueId,
    UTCDatetime,
    utc_now,
)

RISK_LABEL: Final = "MODEL-DERIVED RISK SCORE"


class RiskComponent(HQCModel):
    """One explainable contribution to the risk score."""

    name: NonEmptyStr
    value: Probability = Field(description="Normalised component value in [0, 1].")
    weight: float = Field(ge=0.0, allow_inf_nan=False)
    contribution: float = Field(ge=0.0, le=100.0, description="Points contributed to the score.")
    reason: NonEmptyStr


class RiskAssessment(HQCModel):
    """Explainable risk for an entity and/or chain."""

    assessment_id: NonEmptyStr
    entity_id: str | None = None
    chain_id: str | None = None
    score: float = Field(ge=0.0, le=100.0, allow_inf_nan=False)
    level: RiskLevel
    components: list[RiskComponent] = Field(min_length=1)
    reasons: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    uncertainty: Probability | None = None
    label: Literal["MODEL-DERIVED RISK SCORE"] = RISK_LABEL
    created_at: UTCDatetime = Field(default_factory=utc_now)
    # --- Milestone 7 additions (optional; backwards compatible) ---------------------
    observed_technique_ids: list[TechniqueId] = Field(default_factory=list)
    predicted_technique_ids: list[TechniqueId] = Field(
        default_factory=list, description="Top predicted next techniques (PREDICTED, not observed)."
    )
    model_versions: dict[str, str] = Field(default_factory=dict)
    policy_version: str | None = None
    quantum_disagreement: bool = False
    evidence_status: str | None = Field(
        default=None, description="Worst evidence status across the chain's detections."
    )
