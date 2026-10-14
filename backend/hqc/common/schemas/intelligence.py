"""Milestone 7 intelligence contracts: evidence -> observation -> incident chain -> prediction.

Stage order (each stage has a typed contract):
    SecurityEvent -> DetectionEvidence -> TechniqueEvidence -> IncidentChain (AttackChain)
    -> NextTechniquePrediction (PredictionResult) -> RiskAssessment -> DefenseRecommendation

Rules encoded here:
- Dataset attack labels (e.g. CIC-IDS2017 "PortScan") are NOT ATT&CK techniques; technique
  evidence always names its source and the evidence behind the attribution.
- A quantum second opinion never changes the classical verdict. Disagreement sets
  ``quantum_disagreement`` and ``EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE`` unless independent
  technique evidence corroborates the event.
- OBSERVED, DOCUMENTED and PREDICTED steps live in separate fields and are never mixed.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from hqc.common.schemas.attack import AttackChain, AttackStep
from hqc.common.schemas.base import (
    DataOrigin,
    HQCModel,
    NonEmptyStr,
    Probability,
    StepProvenance,
    TacticId,
    TechniqueId,
    UTCDatetime,
    Verdict,
)
from hqc.common.schemas.detection import QuantumOpinion
from hqc.common.schemas.events import SecurityEvent
from hqc.common.schemas.prediction import PredictionResult


class EvidenceSource(StrEnum):
    """Where a technique attribution comes from. No source is trusted by default."""

    CLASSICAL_DETECTOR = "CLASSICAL_DETECTOR"
    QUANTUM_SECOND_OPINION = "QUANTUM_SECOND_OPINION"
    ATTACK_FLOW = "ATTACK_FLOW"
    SYNTHETIC_SCENARIO = "SYNTHETIC_SCENARIO"
    EXPLICIT_RULE = "EXPLICIT_RULE"


DETECTOR_SOURCES: frozenset[EvidenceSource] = frozenset(
    {EvidenceSource.CLASSICAL_DETECTOR, EvidenceSource.QUANTUM_SECOND_OPINION}
)
"""Sources that are NOT independent of the detection models (cannot corroborate them)."""


class TechniqueEvidence(HQCModel):
    """One piece of evidence that an ATT&CK technique occurred (or is documented)."""

    technique_id: TechniqueId
    tactic_id: TacticId | None = Field(
        default=None,
        description="Tactic the evidence attributes (must be a tactic of the technique).",
    )
    event_id: str | None = Field(default=None, description="Security event; None for ATTACK_FLOW.")
    timestamp: UTCDatetime | None = None
    confidence: Probability
    source: EvidenceSource
    evidence: list[NonEmptyStr] = Field(min_length=1, description="Why this attribution was made.")
    reference: NonEmptyStr = Field(
        description="Rule ID, scenario ID@version, Attack Flow document or detector version."
    )
    detection_model: str | None = None
    model_version: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> TechniqueEvidence:
        if self.source is EvidenceSource.ATTACK_FLOW:
            if self.event_id is not None:
                raise ValueError("ATTACK_FLOW evidence is documented CTI, not an observed event.")
        elif not self.event_id or self.timestamp is None:
            raise ValueError("Event-bound technique evidence needs event_id and timestamp.")
        if self.source in DETECTOR_SOURCES and not (self.detection_model and self.model_version):
            raise ValueError(
                "Detector-sourced evidence must name detection_model and model_version."
            )
        return self


class EvidenceStatus(StrEnum):
    NO_SECOND_OPINION = "NO SECOND OPINION"
    CONSISTENT = "CONSISTENT"
    NEEDS_ADDITIONAL_EVIDENCE = "NEEDS ADDITIONAL EVIDENCE"
    CORROBORATED_BY_INDEPENDENT_EVIDENCE = "CORROBORATED BY INDEPENDENT EVIDENCE"


class DetectionOrigin(StrEnum):
    MODEL_OUTPUT = "MODEL_OUTPUT"  # produced by a trained detector (Milestones 5-6)
    SYNTHETIC_FIXTURE = "SYNTHETIC_FIXTURE"  # hand-authored score in a synthetic scenario


class DetectionEvidence(HQCModel):
    """Classical decision plus optional quantum second opinion for one event."""

    event_id: NonEmptyStr
    timestamp: UTCDatetime
    origin: DetectionOrigin
    classical_model: NonEmptyStr
    classical_model_version: NonEmptyStr
    p_malicious: Probability
    threshold: Probability
    verdict: Verdict
    quantum: QuantumOpinion | None = None
    quantum_disagreement: bool = False
    evidence_status: EvidenceStatus = EvidenceStatus.NO_SECOND_OPINION

    @model_validator(mode="after")
    def _consistent(self) -> DetectionEvidence:
        expected = Verdict.MALICIOUS if self.p_malicious >= self.threshold else Verdict.BENIGN
        if self.verdict is not expected:
            raise ValueError("verdict must follow the classical probability and threshold.")
        triggered = self.quantum is not None and self.quantum.gate_triggered
        disagree = bool(triggered and self.quantum and self.quantum.verdict is not self.verdict)
        if self.quantum_disagreement != disagree:
            raise ValueError("quantum_disagreement must equal (quantum verdict != classical).")
        if not triggered and self.evidence_status is not EvidenceStatus.NO_SECOND_OPINION:
            raise ValueError("Without a triggered second opinion the status is NO SECOND OPINION.")
        if triggered and not disagree and self.evidence_status is not EvidenceStatus.CONSISTENT:
            raise ValueError("An agreeing second opinion has status CONSISTENT.")
        if disagree and self.evidence_status not in (
            EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE,
            EvidenceStatus.CORROBORATED_BY_INDEPENDENT_EVIDENCE,
        ):
            raise ValueError("Disagreement needs additional evidence unless corroborated.")
        return self


class Criticality(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ResourceContext(HQCModel):
    """Optional asset metadata. Criticality is never invented: absent means 'not provided'."""

    resource_id: NonEmptyStr
    resource_type: str | None = None
    criticality: Criticality | None = None
    owner: str | None = None
    environment: str | None = None


class CorrelationHints(HQCModel):
    """Explicit correlation identifiers supplied by the event source (never guessed)."""

    incident_id: str | None = None
    session_id: str | None = None


class Observation(HQCModel):
    """A security event with everything known about it before correlation."""

    event: SecurityEvent
    detection: DetectionEvidence | None = None
    techniques: list[TechniqueEvidence] = Field(default_factory=list)
    hints: CorrelationHints = Field(default_factory=CorrelationHints)

    @model_validator(mode="after")
    def _same_event(self) -> Observation:
        eid = self.event.event_id
        if self.detection is not None and self.detection.event_id != eid:
            raise ValueError("detection.event_id must match the event.")
        if any(t.event_id != eid for t in self.techniques):
            raise ValueError("Every technique evidence must reference this observation's event.")
        return self


class CorrelationStatus(StrEnum):
    CORRELATED = "CORRELATED"  # chain with >= 2 observations joined by documented rules
    STANDALONE = "STANDALONE"  # nothing correlated with it
    AMBIGUOUS = "AMBIGUOUS"  # matched several chains; kept apart rather than forced


class CorrelationDecision(HQCModel):
    event_id: NonEmptyStr
    chain_id: NonEmptyStr
    rule: NonEmptyStr = Field(description="Rule that joined the chain, or 'new_chain'/'ambiguous'.")
    matched_keys: list[str] = Field(default_factory=list)


class IncidentChain(HQCModel):
    """Reconstructed incident: observed steps, documented reference steps, and context."""

    chain_id: NonEmptyStr
    status: CorrelationStatus
    chain: AttackChain = Field(description="OBSERVED steps in arrival order (never re-sorted).")
    documented_steps: list[AttackStep] = Field(
        default_factory=list, description="DOCUMENTED CTI steps (e.g. Attack Flow); not events."
    )
    decisions: list[CorrelationDecision] = Field(min_length=1)
    resources: list[NonEmptyStr] = Field(default_factory=list)
    detections: list[DetectionEvidence] = Field(default_factory=list)
    out_of_vocabulary_technique_ids: list[str] = Field(
        default_factory=list, description="Observed IDs not active in ATT&CK 19.2 (<UNK>)."
    )
    data_origin: DataOrigin

    @model_validator(mode="after")
    def _provenance_separated(self) -> IncidentChain:
        if any(s.provenance is not StepProvenance.OBSERVED for s in self.chain.steps):
            raise ValueError("The incident chain holds OBSERVED steps only.")
        if any(s.provenance is not StepProvenance.DOCUMENTED for s in self.documented_steps):
            raise ValueError("documented_steps must be DOCUMENTED.")
        return self

    @property
    def observed_technique_ids(self) -> list[str]:
        return self.chain.technique_ids


class NextTechniquePrediction(HQCModel):
    """Prediction for a chain. Next-step probabilities and path scores are different things."""

    chain_id: NonEmptyStr
    result: PredictionResult
    context_tokens: list[str] = Field(
        min_length=1, description="Model input history: observed IDs, <UNK> for non-vocabulary."
    )
    model_versions: dict[str, str]
    beam_width: int = Field(ge=1)
    next_step_semantics: Literal[
        "NEXT-STEP PROBABILITY: model P(next technique | observed history); not calibrated"
    ] = "NEXT-STEP PROBABILITY: model P(next technique | observed history); not calibrated"
    path_score_semantics: Literal[
        "PATH SCORE: joint model probability of one exact continuation; summed beam scores are a "
        "LOWER BOUND, not a calibrated probability of reaching a tactic"
    ] = (
        "PATH SCORE: joint model probability of one exact continuation; summed beam scores are a "
        "LOWER BOUND, not a calibrated probability of reaching a tactic"
    )
    per_model_top_k: dict[str, list[tuple[str, float]]] = Field(default_factory=dict)
    provenance: Literal["PREDICTED"] = "PREDICTED"
