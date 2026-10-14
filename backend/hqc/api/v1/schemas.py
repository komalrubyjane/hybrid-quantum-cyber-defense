"""Request / response contracts of ``/api/v1`` (typed; unknown fields are rejected)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field

from hqc.common.schemas.base import DataOrigin, HQCModel, NonEmptyStr, Probability, UTCDatetime
from hqc.common.schemas.defense import DefenseRecommendation
from hqc.common.schemas.evaluation import EvaluationStatus, EvaluationTask
from hqc.common.schemas.intelligence import (
    IncidentChain,
    NextTechniquePrediction,
    Observation,
    ResourceContext,
)
from hqc.pipeline.intelligence import PipelineOutput

API_VERSION: Literal["v1"] = "v1"
MAX_OBSERVATIONS = 1000
MAX_RESOURCES = 1000
RECOMMENDATION_ONLY_NOTICE = (
    "RECOMMENDATION ONLY: the system executes nothing. Decisions are recorded for audit; any "
    "action is taken by humans outside this system."
)
NO_ADVANTAGE_NOTICE = "No quantum advantage is claimed; quantum kernels are simulated on a CPU."


class MetaResponse(HQCModel):
    api_version: Literal["v1"] = API_VERSION
    defense_mode: Literal["recommendation-only"] = "recommendation-only"
    attack_version: str
    vocabulary_version: str
    model_versions: dict[str, str]
    policy_versions: dict[str, str]
    claim_policy: str = NO_ADVANTAGE_NOTICE
    risk_label: Literal["MODEL-DERIVED RISK SCORE"] = "MODEL-DERIVED RISK SCORE"
    cic_label_policy: str = (
        "CIC-IDS2017 attack labels are not MITRE ATT&CK techniques; no such mapping is applied."
    )


class ReconstructRequest(HQCModel):
    observations: list[Observation] = Field(min_length=1, max_length=MAX_OBSERVATIONS)
    as_of: UTCDatetime | None = None


class PredictRequest(HQCModel):
    chain: IncidentChain
    as_of: UTCDatetime | None = None


class PredictResponse(HQCModel):
    prediction: NextTechniquePrediction
    high_impact_next_step_probability: Probability
    high_impact_tactics: list[str]


class RiskRequest(HQCModel):
    chain: IncidentChain
    prediction: NextTechniquePrediction | None = None
    high_impact_next_step_probability: Probability | None = None
    resources: list[ResourceContext] = Field(default_factory=list, max_length=MAX_RESOURCES)
    as_of: UTCDatetime | None = None


class AssessmentRequest(HQCModel):
    observations: list[Observation] = Field(min_length=1, max_length=MAX_OBSERVATIONS)
    resources: list[ResourceContext] = Field(default_factory=list, max_length=MAX_RESOURCES)
    as_of: UTCDatetime | None = None


class AssessmentRecord(HQCModel):
    assessment_id: NonEmptyStr
    created_at: UTCDatetime
    data_origin: DataOrigin
    output: PipelineOutput
    notice: str = RECOMMENDATION_ONLY_NOTICE


class AssessmentSummary(HQCModel):
    assessment_id: str
    created_at: datetime
    data_origin: DataOrigin
    incidents: int
    max_risk_score: float | None
    recommendations: int


class Decision(StrEnum):
    """Analyst workflow decisions. Recording a decision executes nothing."""

    ACKNOWLEDGED = "ACKNOWLEDGED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class DecisionRequest(HQCModel):
    decision: Decision
    analyst: NonEmptyStr = Field(max_length=200)
    note: str | None = Field(default=None, max_length=2000)


class DecisionRecord(HQCModel):
    decision_id: int
    assessment_id: str
    recommendation_id: str
    decision: Decision
    analyst: str
    note: str | None
    recorded_at: datetime
    executed: Literal[False] = False
    notice: str = RECOMMENDATION_ONLY_NOTICE


class RecommendationView(HQCModel):
    assessment_id: str
    recommendation: DefenseRecommendation
    decisions: list[DecisionRecord]
    latest_decision: Decision | None
    executed: Literal[False] = False


class RunSummary(HQCModel):
    """Stored evaluation record without internal paths, environment or configuration."""

    run_id: str
    task: EvaluationTask
    status: EvaluationStatus
    created_at: datetime
    dataset_id: str
    dataset_version: str
    data_origin: DataOrigin
    attack_version: str | None
    git_dirty: bool | None
    runtime_s: float | None
    metrics: dict[str, float]
    notes: str | None


class ErrorResponse(HQCModel):
    detail: str
