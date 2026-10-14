"""Dynamic, explainable MODEL-DERIVED RISK SCORE (0-100) for an incident chain.

    score = sum_i  weight_i * value_i,   value_i in [0, 1],   sum_i weight_i = 100

Components (``RiskPolicy``, version ``risk-policy-v1``; weights are a documented POLICY
choice, not fitted to outcomes; there is no risk ground truth):

- detection (25): max classical P(malicious) over the chain's detections (0 if none);
- technique_confidence (15): mean confidence of the observed steps;
- tactic_progression (25): (max matrix order of observed tactics + 1) / number of tactics;
- predicted_high_impact (15): primary-model P(next technique has an Exfiltration/Impact
  tactic), a NEXT-STEP PROBABILITY that is not calibrated;
- asset_criticality (10): max provided criticality of the chain's resources (0.5 if none);
- recency (10): 0.5 ** (hours since the last observed step / half-life 6 h);
- quantum_second_opinion (0): disagreement share; INFORMATIONAL ONLY, never adds points.

Thresholds (fixed before any evaluation): LOW < 25 <= MEDIUM < 50 <= HIGH < 75 <= CRITICAL.
These are engineering labels, not probabilities.

Quantum: the second opinion contributes 0 points by construction, so disagreement can never
raise risk. It sets ``quantum_disagreement``, the worst ``evidence_status`` and the
``uncertainty`` (share of detections that NEED ADDITIONAL EVIDENCE).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import datetime

from pydantic import Field, model_validator

from hqc.attack_chain.catalog import TechniqueCatalog
from hqc.common.schemas.base import HQCModel, RiskLevel, TacticId, utc_now
from hqc.common.schemas.intelligence import (
    Criticality,
    EvidenceStatus,
    IncidentChain,
    NextTechniquePrediction,
    ResourceContext,
)
from hqc.common.schemas.risk import RiskAssessment, RiskComponent

RISK_POLICY_VERSION = "risk-policy-v1"
TOTAL_WEIGHT = 100.0
STATUS_SEVERITY = (
    EvidenceStatus.NO_SECOND_OPINION,
    EvidenceStatus.CONSISTENT,
    EvidenceStatus.CORROBORATED_BY_INDEPENDENT_EVIDENCE,
    EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE,
)


class RiskWeights(HQCModel):
    detection: float = Field(default=25.0, ge=0.0)
    technique_confidence: float = Field(default=15.0, ge=0.0)
    tactic_progression: float = Field(default=25.0, ge=0.0)
    predicted_high_impact: float = Field(default=15.0, ge=0.0)
    asset_criticality: float = Field(default=10.0, ge=0.0)
    recency: float = Field(default=10.0, ge=0.0)

    @model_validator(mode="after")
    def _sum_to_100(self) -> RiskWeights:
        total = math.fsum(self.model_dump().values())
        if abs(total - TOTAL_WEIGHT) > 1e-9:
            raise ValueError(f"Risk weights must sum to 100 (got {total})")
        return self


class RiskThresholds(HQCModel):
    medium: float = 25.0
    high: float = 50.0
    critical: float = 75.0

    @model_validator(mode="after")
    def _ordered(self) -> RiskThresholds:
        if not 0.0 < self.medium < self.high < self.critical < TOTAL_WEIGHT:
            raise ValueError("Thresholds must satisfy 0 < medium < high < critical < 100")
        return self

    def level(self, score: float) -> RiskLevel:
        if score >= self.critical:
            return RiskLevel.CRITICAL
        if score >= self.high:
            return RiskLevel.HIGH
        if score >= self.medium:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW


class RiskPolicy(HQCModel):
    version: str = RISK_POLICY_VERSION
    weights: RiskWeights = Field(default_factory=RiskWeights)
    thresholds: RiskThresholds = Field(default_factory=RiskThresholds)
    high_impact_tactics: list[TacticId] = Field(default_factory=lambda: ["TA0010", "TA0040"])
    criticality_values: dict[Criticality, float] = Field(
        default_factory=lambda: {
            Criticality.LOW: 0.25,
            Criticality.MEDIUM: 0.5,
            Criticality.HIGH: 0.75,
            Criticality.CRITICAL: 1.0,
        }
    )
    default_criticality_value: float = Field(default=0.5, ge=0.0, le=1.0)
    recency_half_life_hours: float = Field(default=6.0, gt=0.0)


def worst_status(statuses: Sequence[EvidenceStatus]) -> EvidenceStatus | None:
    return max(statuses, key=STATUS_SEVERITY.index) if statuses else None


class RiskService:
    """Chain + prediction (+ optional asset context) -> RiskAssessment. No HTTP."""

    def __init__(self, policy: RiskPolicy, catalog: TechniqueCatalog) -> None:
        self.policy = policy
        self.catalog = catalog

    def _progression(self, incident: IncidentChain) -> tuple[float, str]:
        orders: list[tuple[int, str]] = []
        for step in incident.chain.steps:
            tactics = self.catalog.tactics(step.technique_id)
            if step.tactic_id is not None:
                chosen = [t for t in tactics if t.tactic_id == step.tactic_id]
            else:
                chosen = tactics[:1]  # earliest (most conservative) matrix position
            orders += [(t.order, t.shortname) for t in chosen]
        if not orders:
            return 0.0, "no tactic information for the observed techniques"
        order, name = max(orders)
        reason = f"furthest observed tactic: {name} (matrix position {order})"
        return (order + 1) / self.catalog.tactic_count, reason

    def assess(
        self,
        incident: IncidentChain,
        prediction: NextTechniquePrediction | None,
        high_impact_probability: float | None,
        resources: Mapping[str, ResourceContext] | None = None,
        as_of: datetime | None = None,
    ) -> RiskAssessment:
        now = as_of or utc_now()
        p = self.policy
        w = p.weights
        steps = incident.chain.steps
        last_seen = max(s.timestamp for s in steps if s.timestamp is not None)
        if now < last_seen:
            raise ValueError("as_of is earlier than the chain's latest evidence")
        detections = incident.detections

        det = max((d.p_malicious for d in detections), default=0.0)
        conf = math.fsum(s.confidence for s in steps) / len(steps)
        prog, prog_reason = self._progression(incident)
        impact = high_impact_probability if high_impact_probability is not None else 0.0
        known = [
            p.criticality_values[r.criticality]
            for rid in incident.resources
            if (r := (resources or {}).get(rid)) is not None and r.criticality is not None
        ]
        crit = max(known) if known else p.default_criticality_value
        age_h = (now - last_seen).total_seconds() / 3600.0
        recency = 0.5 ** (age_h / p.recency_half_life_hours)
        disagreements = sum(d.quantum_disagreement for d in detections)
        needs = sum(
            d.evidence_status is EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE for d in detections
        )

        def comp(name: str, value: float, weight: float, reason: str) -> RiskComponent:
            v = min(1.0, max(0.0, value))
            return RiskComponent(
                name=name, value=v, weight=weight, contribution=round(weight * v, 6), reason=reason
            )

        components = [
            comp("detection", det, w.detection,
                 f"max classical P(malicious) {det:.3f} over {len(detections)} detection(s)"
                 if detections else "no detector evidence for this chain"),
            comp("technique_confidence", conf, w.technique_confidence,
                 f"mean confidence of {len(steps)} observed step(s)"),
            comp("tactic_progression", prog, w.tactic_progression, prog_reason),
            comp("predicted_high_impact", impact, w.predicted_high_impact,
                 f"model P(next technique in {p.high_impact_tactics}) = {impact:.4f} "
                 "(NEXT-STEP PROBABILITY, not calibrated)"
                 if high_impact_probability is not None else "no prediction available"),
            comp("asset_criticality", crit, w.asset_criticality,
                 f"max provided criticality value {crit}" if known
                 else f"criticality not provided; neutral default {p.default_criticality_value}"),
            comp("recency", recency, w.recency,
                 f"{age_h:.2f} h since the latest observed step (half-life "
                 f"{p.recency_half_life_hours} h)"),
            RiskComponent(
                name="quantum_second_opinion",
                value=disagreements / len(detections) if detections else 0.0,
                weight=0.0,
                contribution=0.0,
                reason=f"informational only (0 points): {disagreements} classical/quantum "
                f"disagreement(s); {needs} event(s) NEED ADDITIONAL EVIDENCE",
            ),
        ]  # fmt: skip
        score = round(min(TOTAL_WEIGHT, math.fsum(c.contribution for c in components)), 4)
        level = p.thresholds.level(score)
        predicted = (
            [n.technique_id for n in prediction.result.next_step] if prediction is not None else []
        )
        status = worst_status([d.evidence_status for d in detections])
        reasons = [f"{c.name}: {c.contribution:.2f} pts ({c.reason})" for c in components]
        versions = dict(prediction.model_versions) if prediction is not None else {}
        versions.update(
            {f"detector:{d.classical_model}": d.classical_model_version for d in detections}
        )
        versions.update(
            {
                f"quantum:{d.quantum.feature_map or d.quantum.backend}": d.quantum.backend or "n/a"
                for d in detections
                if d.quantum is not None and d.quantum.gate_triggered
            }
        )
        return RiskAssessment(
            assessment_id=f"risk-{incident.chain_id}",
            entity_id=incident.resources[0] if incident.resources else None,
            chain_id=incident.chain_id,
            score=score,
            level=level,
            components=components,
            reasons=reasons,
            affected_assets=list(incident.resources),
            uncertainty=needs / len(detections) if detections else None,
            created_at=now,
            observed_technique_ids=incident.observed_technique_ids,
            predicted_technique_ids=predicted,
            model_versions=versions,
            policy_version=p.version,
            quantum_disagreement=disagreements > 0,
            evidence_status=status.value if status is not None else None,
        )
