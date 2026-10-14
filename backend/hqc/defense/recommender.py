"""Adaptive defense RECOMMENDATIONS (policy ``defense-policy-v1``). Nothing here executes.

Every output is a ``DefenseRecommendation`` with ``requires_human_approval = True`` and status
``PROPOSED``. This module performs no I/O, process, network, firewall, account or host
operations (enforced by tests/guardrails/test_defense_no_execution.py).

Deterministic policy (by MODEL-DERIVED risk level):

| level    | recommended actions                                                              |
|----------|----------------------------------------------------------------------------------|
| LOW      | increase_monitoring (continue monitoring)                                        |
| MEDIUM   | collect_additional_evidence, increase_monitoring                                 |
| HIGH     | restrict_communication (pending approval), escalate_severity, increase_monitoring|
| CRITICAL | isolate_affected_host and block_suspicious_access (pending approval),            |
|          | escalate_severity, disable_compromised_credentials (pending approval; only if a  |
|          | credential-access or lateral-movement step names an account)                     |

Modifiers:
- Evidence status NEEDS ADDITIONAL EVIDENCE (unresolved classical/quantum disagreement):
  collect_additional_evidence is always added and the HIGH-disruption actions (isolate,
  block, disable credentials) are WITHHELD: a CRITICAL chain gets the HIGH plan (restrict
  pending approval, escalate, monitor) plus evidence collection. A disagreement therefore
  never escalates the response on its own.
- block_suspicious_access targets only addresses seen in initial-access (src_ip) or
  exfiltration (dst_ip) steps; if there are none it is not recommended.

Targets: the resource of the most recent observed step (isolate / restrict / escalate /
monitor), the addresses above (block), accounts on TA0006 / TA0008 steps (credentials), the
resources of events that need evidence (collect).
Priority = risk score x action urgency (table below); confidence = mean step confidence x
(1 - uncertainty).
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import datetime

from hqc.attack_chain.catalog import TechniqueCatalog
from hqc.common.schemas.base import Disruption, HQCModel, RiskLevel, utc_now
from hqc.common.schemas.defense import DefenseAction, DefenseRecommendation, EvidenceRef
from hqc.common.schemas.intelligence import (
    EvidenceStatus,
    IncidentChain,
    NextTechniquePrediction,
    Observation,
)
from hqc.common.schemas.risk import RISK_LABEL, RiskAssessment

DEFENSE_POLICY_VERSION = "defense-policy-v1"
INITIAL_ACCESS, CREDENTIAL_ACCESS, LATERAL_MOVEMENT, EXFILTRATION = (
    "TA0001",
    "TA0006",
    "TA0008",
    "TA0010",
)

A = DefenseAction
# action -> (disruption, reversible, urgency)
ACTION_PROFILE: dict[DefenseAction, tuple[Disruption, bool, float]] = {
    A.INCREASE_MONITORING: (Disruption.NONE, True, 0.3),
    A.COLLECT_ADDITIONAL_EVIDENCE: (Disruption.NONE, True, 0.5),
    A.RESTRICT_COMMUNICATION: (Disruption.MEDIUM, True, 0.7),
    A.DISABLE_COMPROMISED_CREDENTIALS: (Disruption.HIGH, True, 0.75),
    A.BLOCK_SUSPICIOUS_ACCESS: (Disruption.MEDIUM, True, 0.8),
    A.ISOLATE_AFFECTED_HOST: (Disruption.HIGH, True, 0.85),
    A.ESCALATE_SEVERITY: (Disruption.NONE, True, 0.9),
}
WITHHELD_WHEN_EVIDENCE_NEEDED = frozenset(
    {A.ISOLATE_AFFECTED_HOST, A.BLOCK_SUSPICIOUS_ACCESS, A.DISABLE_COMPROMISED_CREDENTIALS}
)
LEVEL_ACTIONS: dict[RiskLevel, tuple[DefenseAction, ...]] = {
    RiskLevel.LOW: (A.INCREASE_MONITORING,),
    RiskLevel.MEDIUM: (A.COLLECT_ADDITIONAL_EVIDENCE, A.INCREASE_MONITORING),
    RiskLevel.HIGH: (A.RESTRICT_COMMUNICATION, A.ESCALATE_SEVERITY, A.INCREASE_MONITORING),
    RiskLevel.CRITICAL: (
        A.ISOLATE_AFFECTED_HOST,
        A.BLOCK_SUSPICIOUS_ACCESS,
        A.ESCALATE_SEVERITY,
        A.DISABLE_COMPROMISED_CREDENTIALS,
    ),
}


class DefensePolicy(HQCModel):
    version: str = DEFENSE_POLICY_VERSION


class DefenseRecommendationService:
    """Risk + chain + evidence -> recommendations for a human analyst. Executes nothing."""

    def __init__(self, policy: DefensePolicy, catalog: TechniqueCatalog) -> None:
        self.policy = policy
        self.catalog = catalog

    def planned_actions(self, level: RiskLevel, needs_evidence: bool) -> list[DefenseAction]:
        """Deterministic action plan for a risk level and evidence state."""
        if not needs_evidence:
            return list(LEVEL_ACTIONS[level])
        # Unresolved disagreement: never escalate disruption on it. CRITICAL falls back to the
        # HIGH plan (no high-disruption action); every level adds evidence collection.
        base = RiskLevel.HIGH if level is RiskLevel.CRITICAL else level
        planned = [a for a in LEVEL_ACTIONS[base] if a not in WITHHELD_WHEN_EVIDENCE_NEEDED]
        if A.COLLECT_ADDITIONAL_EVIDENCE not in planned:
            planned.append(A.COLLECT_ADDITIONAL_EVIDENCE)
        return planned

    def recommend(
        self,
        incident: IncidentChain,
        risk: RiskAssessment,
        prediction: NextTechniquePrediction | None,
        observations: Sequence[Observation],
        as_of: datetime | None = None,
    ) -> list[DefenseRecommendation]:
        now = as_of or utc_now()
        by_event = {o.event.event_id: o for o in observations}
        steps = incident.chain.steps
        needs = [
            d.event_id
            for d in incident.detections
            if d.evidence_status is EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE
        ]
        latest = by_event.get(steps[-1].event_id or "")
        latest_resource = latest.event.entity_id if latest else incident.resources[0]
        observed = incident.observed_technique_ids
        predicted = [n.technique_id for n in prediction.result.next_step[:1]] if prediction else []
        mitigations = sorted(
            {m for t in [*observed, *predicted] for m in self.catalog.mitigation_ids(t)}
        )
        uncertainty = risk.uncertainty or 0.0
        confidence = min(
            1.0, max(0.0, math.fsum(s.confidence for s in steps) / len(steps) * (1.0 - uncertainty))
        )
        base_refs = [
            EvidenceRef(
                kind="risk",
                ref_id=risk.assessment_id,
                description=f"{RISK_LABEL} {risk.score:.1f} ({risk.level.value})",
            )
        ]
        base_refs += [
            EvidenceRef(
                kind="chain_step",
                ref_id=s.event_id or incident.chain_id,
                description=f"OBSERVED {s.technique_id} ({s.tactic_id})",
            )
            for s in steps
        ]
        if prediction is not None and prediction.result.next_step:
            top = prediction.result.next_step[0]
            base_refs.append(
                EvidenceRef(
                    kind="prediction",
                    ref_id=prediction.result.prediction_id,
                    description=f"PREDICTED next {top.technique_id} "
                    f"(next-step probability {top.probability:.3f})",
                )
            )

        def addresses(tactic: str, attr: str) -> list[str]:
            out = []
            for s in steps:
                obs = by_event.get(s.event_id or "")
                value = getattr(obs.event, attr, None) if obs else None
                if s.tactic_id == tactic and value is not None:
                    out.append(str(value))
            return out

        targets: dict[DefenseAction, list[str]] = {
            A.BLOCK_SUSPICIOUS_ACCESS: sorted(
                set(addresses(INITIAL_ACCESS, "src_ip") + addresses(EXFILTRATION, "dst_ip"))
            ),
            A.DISABLE_COMPROMISED_CREDENTIALS: sorted(
                set(addresses(CREDENTIAL_ACCESS, "user") + addresses(LATERAL_MOVEMENT, "user"))
            ),
            A.COLLECT_ADDITIONAL_EVIDENCE: sorted(
                {by_event[e].event.entity_id for e in needs if e in by_event} or {latest_resource}
            ),
        }
        reasons = {
            A.INCREASE_MONITORING: "continue / increase monitoring of the affected resource",
            A.COLLECT_ADDITIONAL_EVIDENCE: "classical and quantum opinions disagree without "
            "independent corroboration, or risk is MEDIUM: collect more evidence before acting"
            if needs
            else "MEDIUM risk: collect more evidence before acting",
            A.RESTRICT_COMMUNICATION: "HIGH risk: consider restricting suspicious communication "
            "of the affected resource (pending human approval)",
            A.ESCALATE_SEVERITY: "escalate to a SOC analyst for review",
            A.ISOLATE_AFFECTED_HOST: "CRITICAL risk: consider isolating the resource pending "
            "human approval",
            A.BLOCK_SUSPICIOUS_ACCESS: "CRITICAL risk: consider blocking the suspicious address "
            "pending human approval",
            A.DISABLE_COMPROMISED_CREDENTIALS: "CRITICAL risk with credential-access / "
            "lateral-movement evidence: consider resetting or disabling the account pending "
            "human approval",
        }
        recommendations: list[DefenseRecommendation] = []
        for action in self.planned_actions(risk.level, bool(needs)):
            disruption, reversible, urgency = ACTION_PROFILE[action]
            refs = list(base_refs)
            if action is A.COLLECT_ADDITIONAL_EVIDENCE:
                refs += [
                    EvidenceRef(
                        kind="detection",
                        ref_id=e,
                        description="NEEDS ADDITIONAL EVIDENCE (quantum disagreement)",
                    )
                    for e in needs
                ]
            for target in targets.get(action, [latest_resource]):
                recommendations.append(
                    DefenseRecommendation(
                        recommendation_id=f"rec-{incident.chain_id}-{action.value}-{target}",
                        action=action,
                        target=target,
                        reason=f"{reasons[action]}. {RISK_LABEL}: {risk.score:.1f} "
                        f"({risk.level.value}); evidence status: {risk.evidence_status}.",
                        triggering_evidence=refs,
                        risk_score=risk.score,
                        risk_level=risk.level,
                        attack_mitigation_ids=mitigations,
                        addresses_technique_ids=sorted(set(observed + predicted)),
                        confidence=confidence,
                        priority=round(risk.score * urgency, 4),
                        disruption=disruption,
                        reversible=reversible,
                        created_at=now,
                        chain_id=incident.chain_id,
                        policy_version=self.policy.version,
                    )
                )
        order = list(ACTION_PROFILE)
        return sorted(recommendations, key=lambda r: (-r.priority, order.index(r.action), r.target))
