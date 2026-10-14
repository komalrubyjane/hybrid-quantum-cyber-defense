"""Defense recommendation contract. RECOMMENDATION ONLY: nothing here executes."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from hqc.common.schemas.base import (
    Disruption,
    HQCModel,
    MitigationId,
    NonEmptyStr,
    Probability,
    RiskLevel,
    TechniqueId,
    UTCDatetime,
    utc_now,
)


class DefenseAction(StrEnum):
    """The seven supported recommendation categories."""

    BLOCK_SUSPICIOUS_ACCESS = "block_suspicious_access"
    ISOLATE_AFFECTED_HOST = "isolate_affected_host"
    RESTRICT_COMMUNICATION = "restrict_communication"
    DISABLE_COMPROMISED_CREDENTIALS = "disable_compromised_credentials"
    INCREASE_MONITORING = "increase_monitoring"
    ESCALATE_SEVERITY = "escalate_severity"
    COLLECT_ADDITIONAL_EVIDENCE = "collect_additional_evidence"


class RecommendationStatus(StrEnum):
    """Analyst workflow state. Approval records a human decision; it executes nothing."""

    PROPOSED = "PROPOSED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class EvidenceRef(HQCModel):
    """Pointer to the evidence that triggered a recommendation."""

    kind: Literal["event", "detection", "chain_step", "prediction", "risk"]
    ref_id: NonEmptyStr
    description: NonEmptyStr


class DefenseRecommendation(HQCModel):
    """An advisory action for a human analyst to consider."""

    recommendation_id: NonEmptyStr
    action: DefenseAction
    target: NonEmptyStr = Field(description="Entity the analyst should consider acting on.")
    reason: NonEmptyStr
    triggering_evidence: list[EvidenceRef] = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=100.0, allow_inf_nan=False)
    risk_level: RiskLevel
    attack_mitigation_ids: list[MitigationId] = Field(default_factory=list)
    addresses_technique_ids: list[TechniqueId] = Field(default_factory=list)
    confidence: Probability
    priority: float = Field(ge=0.0, allow_inf_nan=False)
    disruption: Disruption
    reversible: bool
    requires_human_approval: Literal[True] = True
    status: RecommendationStatus = RecommendationStatus.PROPOSED
    created_at: UTCDatetime = Field(default_factory=utc_now)
    # --- Milestone 7 additions (optional; backwards compatible) ---------------------
    chain_id: str | None = None
    policy_version: str | None = None
    approval_note: str = Field(
        default="RECOMMENDATION ONLY - requires human approval; the system executes nothing.",
        min_length=1,
    )
