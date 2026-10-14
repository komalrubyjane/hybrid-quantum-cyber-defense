"""SYNTHETIC multi-stage scenarios for integration testing (never real-world claims).

A scenario file holds hand-authored events, hand-authored (SYNTHETIC_FIXTURE) detector
scores and explicit ATT&CK annotations. ``validate_scenario`` checks every technique is an
active ATT&CK technique of the configured version and every annotated tactic is one of that
technique's tactics in the knowledge base.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, ValidationError

from hqc.attack_chain.catalog import TechniqueCatalog
from hqc.attack_chain.evidence import EvidencePolicy, build_detection_evidence, check_evidence
from hqc.common.errors import ConfigurationError
from hqc.common.schemas.base import (
    HQCModel,
    NonEmptyStr,
    Probability,
    TacticId,
    TechniqueId,
    Verdict,
)
from hqc.common.schemas.detection import QuantumOpinion, confidence_from_probability
from hqc.common.schemas.events import parse_security_event
from hqc.common.schemas.intelligence import (
    CorrelationHints,
    DetectionOrigin,
    EvidenceSource,
    Observation,
    ResourceContext,
    TechniqueEvidence,
)

SYNTHETIC_CLASSICAL_MODEL = "synthetic-fixture-classical"
SYNTHETIC_BACKEND = "synthetic-fixture (no quantum model was run)"


class ScenarioAnnotation(HQCModel):
    technique_id: TechniqueId
    tactic_id: TacticId
    confidence: Probability
    evidence: list[NonEmptyStr] = Field(min_length=1)


class ScenarioDetection(HQCModel):
    """Hand-authored detector scores (SYNTHETIC_FIXTURE); not produced by any trained model."""

    p_malicious: Probability
    threshold: Probability = 0.5
    quantum_p_malicious: Probability | None = None


class ScenarioObservation(HQCModel):
    event: dict[str, Any]
    detection: ScenarioDetection | None = None
    annotations: list[ScenarioAnnotation] = Field(default_factory=list)
    hints: CorrelationHints = Field(default_factory=CorrelationHints)


class ExpectedChain(HQCModel):
    event_ids: list[NonEmptyStr] = Field(min_length=1)
    status: Literal["CORRELATED", "STANDALONE", "AMBIGUOUS"]


class ScenarioExpectations(HQCModel):
    chains: list[ExpectedChain]
    unmapped_event_ids: list[str] = Field(default_factory=list)
    evidence_status: dict[str, str] = Field(default_factory=dict)


class SyntheticScenario(HQCModel):
    scenario_id: NonEmptyStr
    version: NonEmptyStr
    data_origin: Literal["SYNTHETIC"]
    notice: NonEmptyStr
    description: NonEmptyStr
    attack_version: NonEmptyStr
    as_of: datetime
    resources: list[ResourceContext] = Field(default_factory=list)
    observations: list[ScenarioObservation] = Field(min_length=1)
    expected: ScenarioExpectations

    @property
    def reference(self) -> str:
        return f"{self.scenario_id}@{self.version}"


def load_scenario(path: Path) -> tuple[SyntheticScenario, str]:
    """Scenario and the SHA-256 of its file (the scenario version fingerprint)."""
    try:
        raw = path.read_bytes()
        return SyntheticScenario.model_validate(json.loads(raw)), hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, ValidationError) as exc:
        raise ConfigurationError(f"Invalid scenario {path}: {exc}") from exc


def validate_scenario(scenario: SyntheticScenario, catalog: TechniqueCatalog) -> list[str]:
    """Raise if any annotation is not an active technique / valid tactic; return the IDs."""
    if scenario.attack_version != catalog.attack_version:
        raise ConfigurationError("Scenario and catalog ATT&CK versions differ")
    ids = []
    for obs in scenario.observations:
        for a in obs.annotations:
            if not catalog.is_active(a.technique_id):
                raise ConfigurationError(
                    f"{a.technique_id} is not an active ATT&CK {catalog.attack_version} technique"
                )
            if a.tactic_id not in {t.tactic_id for t in catalog.tactics(a.technique_id)}:
                raise ConfigurationError(f"{a.tactic_id} is not a tactic of {a.technique_id}")
            ids.append(a.technique_id)
    return ids


def build_observations(
    scenario: SyntheticScenario, catalog: TechniqueCatalog, policy: EvidencePolicy
) -> list[Observation]:
    """Typed observations in the scenario's ARRIVAL order (not sorted)."""
    observations = []
    for item in scenario.observations:
        event = parse_security_event(item.event)
        techniques = [
            TechniqueEvidence(
                technique_id=a.technique_id,
                tactic_id=a.tactic_id,
                event_id=event.event_id,
                timestamp=event.timestamp,
                confidence=a.confidence,
                source=EvidenceSource.SYNTHETIC_SCENARIO,
                evidence=list(a.evidence),
                reference=scenario.reference,
            )
            for a in item.annotations
        ]
        for ev in techniques:
            check_evidence(ev, catalog)
        detection = None
        if item.detection is not None:
            d = item.detection
            quantum = None
            if d.quantum_p_malicious is not None:
                q = d.quantum_p_malicious
                quantum = QuantumOpinion(
                    gate_triggered=True,
                    verdict=Verdict.MALICIOUS if q >= d.threshold else Verdict.BENIGN,
                    p_malicious=q,
                    confidence=confidence_from_probability(q),
                    backend=SYNTHETIC_BACKEND,
                    feature_map="synthetic-fixture",
                )
            detection = build_detection_evidence(
                event_id=event.event_id,
                timestamp=event.timestamp,
                origin=DetectionOrigin.SYNTHETIC_FIXTURE,
                classical_model=SYNTHETIC_CLASSICAL_MODEL,
                classical_model_version=scenario.reference,
                p_malicious=d.p_malicious,
                threshold=d.threshold,
                quantum=quantum,
                techniques=techniques,
                policy=policy,
            )
        observations.append(
            Observation(event=event, detection=detection, techniques=techniques, hints=item.hints)
        )
    return observations
