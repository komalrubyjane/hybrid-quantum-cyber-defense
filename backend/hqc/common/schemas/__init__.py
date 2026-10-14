"""Typed data contracts shared by every pipeline stage.

Stages communicate only through these models; free-form dicts are not passed
between modules.
"""

from hqc.common.schemas.attack import (
    AttackChain,
    ATTACKDataComponent,
    ATTACKMitigation,
    AttackStep,
    ATTACKTactic,
    ATTACKTechnique,
    TechniqueCandidate,
)
from hqc.common.schemas.base import (
    SCHEMA_VERSION,
    DataOrigin,
    Disruption,
    HQCModel,
    RiskLevel,
    StepProvenance,
    Verdict,
)
from hqc.common.schemas.defense import (
    DefenseAction,
    DefenseRecommendation,
    EvidenceRef,
    RecommendationStatus,
)
from hqc.common.schemas.detection import (
    DetectionResult,
    QuantumOpinion,
    confidence_from_probability,
)
from hqc.common.schemas.evaluation import (
    EnvironmentInfo,
    EvaluationFold,
    EvaluationResult,
    EvaluationStatus,
    EvaluationTask,
)
from hqc.common.schemas.events import (
    APIEvent,
    AuthenticationEvent,
    AuthOutcome,
    BaseSecurityEvent,
    NetworkFlow,
    SecurityEvent,
    SystemEvent,
    parse_security_event,
)
from hqc.common.schemas.intelligence import (
    CorrelationDecision,
    CorrelationHints,
    CorrelationStatus,
    Criticality,
    DetectionEvidence,
    DetectionOrigin,
    EvidenceSource,
    EvidenceStatus,
    IncidentChain,
    NextTechniquePrediction,
    Observation,
    ResourceContext,
    TechniqueEvidence,
)
from hqc.common.schemas.prediction import (
    NextTechniqueProbability,
    PredictedPath,
    PredictionResult,
)
from hqc.common.schemas.risk import RISK_LABEL, RiskAssessment, RiskComponent

__all__ = [
    "RISK_LABEL",
    "SCHEMA_VERSION",
    "APIEvent",
    "ATTACKDataComponent",
    "ATTACKMitigation",
    "ATTACKTactic",
    "ATTACKTechnique",
    "AttackChain",
    "AttackStep",
    "AuthOutcome",
    "AuthenticationEvent",
    "BaseSecurityEvent",
    "CorrelationDecision",
    "CorrelationHints",
    "CorrelationStatus",
    "Criticality",
    "DataOrigin",
    "DefenseAction",
    "DefenseRecommendation",
    "DetectionEvidence",
    "DetectionOrigin",
    "DetectionResult",
    "Disruption",
    "EnvironmentInfo",
    "EvaluationFold",
    "EvaluationResult",
    "EvaluationStatus",
    "EvaluationTask",
    "EvidenceRef",
    "EvidenceSource",
    "EvidenceStatus",
    "HQCModel",
    "IncidentChain",
    "NetworkFlow",
    "NextTechniquePrediction",
    "NextTechniqueProbability",
    "Observation",
    "PredictedPath",
    "PredictionResult",
    "QuantumOpinion",
    "RecommendationStatus",
    "ResourceContext",
    "RiskAssessment",
    "RiskComponent",
    "RiskLevel",
    "SecurityEvent",
    "StepProvenance",
    "SystemEvent",
    "TechniqueCandidate",
    "TechniqueEvidence",
    "Verdict",
    "confidence_from_probability",
    "parse_security_event",
]
