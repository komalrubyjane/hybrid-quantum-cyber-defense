"""Technique and detection evidence (Milestone 7).

CIC-IDS2017 ATTACK LABELS ARE NOT MITRE ATT&CK TECHNIQUES. This module deliberately has no
dataset-label -> technique table; :func:`technique_evidence_from_dataset_label` always
refuses. Technique evidence must come from an explicit source: a documented rule, an
annotated synthetic scenario, Attack Flow (documented CTI), or a detector that itself emits
techniques (none in this project yet).

Quantum second opinion: it never changes the classical verdict. If it disagrees, the event
is ``NEEDS ADDITIONAL EVIDENCE`` unless INDEPENDENT technique evidence (any non-detector
source) with confidence >= ``EvidencePolicy.corroboration_min_confidence`` exists for the
same event, in which case it is ``CORROBORATED BY INDEPENDENT EVIDENCE``.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Literal, NoReturn

import yaml
from pydantic import Field, ValidationError, field_validator

from hqc.attack_chain.catalog import TechniqueCatalog
from hqc.common.errors import ConfigurationError
from hqc.common.schemas.base import (
    HQCModel,
    NonEmptyStr,
    Probability,
    TacticId,
    TechniqueId,
    Verdict,
)
from hqc.common.schemas.detection import DetectionResult, QuantumOpinion
from hqc.common.schemas.events import SecurityEvent
from hqc.common.schemas.intelligence import (
    DETECTOR_SOURCES,
    DetectionEvidence,
    DetectionOrigin,
    EvidenceSource,
    EvidenceStatus,
    TechniqueEvidence,
)

EVIDENCE_POLICY_VERSION = "evidence-policy-v1"
DATASETS_WITHOUT_TECHNIQUE_MAPPING: frozenset[str] = frozenset({"cicids2017", "unsw-nb15"})


class EvidenceValidationError(ValueError):
    """Technique evidence contradicts the ATT&CK knowledge base."""


class NoDocumentedMappingError(ValueError):
    """A dataset label was offered as an ATT&CK technique without a documented mapping."""


class EvidencePolicy(HQCModel):
    version: str = EVIDENCE_POLICY_VERSION
    corroboration_min_confidence: Probability = 0.7


def technique_evidence_from_dataset_label(dataset: str, label: str) -> NoReturn:
    """Always refuses: dataset attack labels are not ATT&CK techniques (Milestone 7 rule)."""
    raise NoDocumentedMappingError(
        f"{dataset!r} label {label!r} is not an ATT&CK technique. CIC-IDS2017 attack labels != "
        "MITRE ATT&CK techniques; no undocumented mapping table is provided. Use an explicit "
        "documented rule or annotated evidence instead."
    )


def check_evidence(evidence: TechniqueEvidence, catalog: TechniqueCatalog) -> bool:
    """Validate against ATT&CK; returns True if the technique is active in the vocabulary.

    Inactive / unknown (but well-formed) IDs are kept and become ``<UNK>`` for prediction.
    A tactic attribution that is not a tactic of an active technique is an error.
    """
    active = catalog.is_active(evidence.technique_id)
    if evidence.tactic_id is not None and active:
        allowed = {t.tactic_id for t in catalog.tactics(evidence.technique_id)}
        if allowed and evidence.tactic_id not in allowed:
            raise EvidenceValidationError(
                f"{evidence.tactic_id} is not a tactic of {evidence.technique_id} "
                f"in ATT&CK {catalog.attack_version} (allowed: {sorted(allowed)})"
            )
    return active


# --- explicit, documented rules -------------------------------------------------------------

FORBIDDEN_RULE_FIELDS = frozenset({"ground_truth_label"})


class RuleCondition(HQCModel):
    """``field`` is an event attribute or ``details.<key>`` (SystemEvent)."""

    field: NonEmptyStr
    equals: str | None = None
    one_of: list[str] | None = None

    @field_validator("field")
    @classmethod
    def _not_a_label(cls, value: str) -> str:
        if value in FORBIDDEN_RULE_FIELDS:
            raise ValueError("Rules may not read dataset labels (evaluation-only field).")
        return value


class TechniqueRule(HQCModel):
    rule_id: NonEmptyStr
    technique_id: TechniqueId
    tactic_id: TacticId | None = None
    event_type: Literal["network_flow", "authentication", "system", "api"]
    conditions: list[RuleCondition] = Field(min_length=1)
    confidence: Probability
    rationale: NonEmptyStr
    references: list[NonEmptyStr] = Field(min_length=1)
    status: Literal["illustrative", "validated"]


class RuleSet(HQCModel):
    version: NonEmptyStr
    rules: list[TechniqueRule] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> RuleSet:
        try:
            return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise ConfigurationError(f"Invalid technique rule set {path}: {exc}") from exc


def _field_value(event: SecurityEvent, name: str) -> str | None:
    if name.startswith("details."):
        details = getattr(event, "details", None)
        return details.get(name.split(".", 1)[1]) if isinstance(details, dict) else None
    value = getattr(event, name, None)
    if value is None:
        return None
    return value.value if hasattr(value, "value") else str(value)


def _matches(event: SecurityEvent, rule: TechniqueRule) -> bool:
    if event.event_type != rule.event_type:
        return False
    for cond in rule.conditions:
        value = _field_value(event, cond.field)
        if value is None:
            return False
        if cond.equals is not None and value != cond.equals:
            return False
        if cond.one_of is not None and value not in cond.one_of:
            return False
    return True


def apply_rules(event: SecurityEvent, rules: RuleSet) -> list[TechniqueEvidence]:
    """Technique evidence from every matching rule (rule order preserved)."""
    out = []
    for rule in rules.rules:
        if _matches(event, rule):
            out.append(
                TechniqueEvidence(
                    technique_id=rule.technique_id,
                    tactic_id=rule.tactic_id,
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    confidence=rule.confidence,
                    source=EvidenceSource.EXPLICIT_RULE,
                    evidence=[f"rule {rule.rule_id} ({rule.status}): {rule.rationale}"],
                    reference=f"{rules.version}:{rule.rule_id}",
                )
            )
    return out


# --- detection evidence and the disagreement rule ------------------------------------------


def evidence_status(
    quantum: QuantumOpinion | None,
    classical_verdict_malicious: bool,
    techniques: Sequence[TechniqueEvidence],
    policy: EvidencePolicy,
) -> tuple[bool, EvidenceStatus]:
    """(quantum_disagreement, status). Disagreement never escalates on its own."""
    if quantum is None or not quantum.gate_triggered or quantum.verdict is None:
        return False, EvidenceStatus.NO_SECOND_OPINION
    disagree = (quantum.verdict is Verdict.MALICIOUS) != classical_verdict_malicious
    if not disagree:
        return False, EvidenceStatus.CONSISTENT
    independent = [
        t
        for t in techniques
        if t.source not in DETECTOR_SOURCES and t.confidence >= policy.corroboration_min_confidence
    ]
    if independent:
        return True, EvidenceStatus.CORROBORATED_BY_INDEPENDENT_EVIDENCE
    return True, EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE


def build_detection_evidence(
    *,
    event_id: str,
    timestamp: datetime,
    origin: DetectionOrigin,
    classical_model: str,
    classical_model_version: str,
    p_malicious: float,
    threshold: float,
    quantum: QuantumOpinion | None,
    techniques: Sequence[TechniqueEvidence],
    policy: EvidencePolicy,
) -> DetectionEvidence:
    malicious = p_malicious >= threshold
    disagree, status = evidence_status(quantum, malicious, techniques, policy)
    return DetectionEvidence(
        event_id=event_id,
        timestamp=timestamp,
        origin=origin,
        classical_model=classical_model,
        classical_model_version=classical_model_version,
        p_malicious=p_malicious,
        threshold=threshold,
        verdict=Verdict.MALICIOUS if malicious else Verdict.BENIGN,
        quantum=quantum,
        quantum_disagreement=disagree,
        evidence_status=status,
    )


def detection_evidence_from_result(
    result: DetectionResult,
    timestamp: datetime,
    policy: EvidencePolicy,
    techniques: Sequence[TechniqueEvidence] = (),
) -> DetectionEvidence:
    """Adapter for Milestone 5/6 ``DetectionResult`` objects (the verdict is kept as-is)."""
    threshold = result.threshold if result.threshold is not None else 0.5
    evidence = build_detection_evidence(
        event_id=result.event_id,
        timestamp=timestamp,
        origin=DetectionOrigin.MODEL_OUTPUT,
        classical_model=result.model_id,
        classical_model_version=result.model_version,
        p_malicious=result.p_malicious,
        threshold=threshold,
        quantum=result.quantum,
        techniques=techniques,
        policy=policy,
    )
    if evidence.verdict is not result.verdict:
        raise ValueError("DetectionResult verdict is inconsistent with its probability/threshold")
    return evidence
