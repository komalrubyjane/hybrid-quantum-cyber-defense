"""Risk assessment contract. Scores are model-derived, never ground truth."""

from __future__ import annotations

from typing import Final, Literal

from pydantic import Field

from hqc.common.schemas.base import (
    HQCModel,
    NonEmptyStr,
    Probability,
    RiskLevel,
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
