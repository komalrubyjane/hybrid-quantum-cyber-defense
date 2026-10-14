"""End-to-end intelligence pipeline built from the four independent services.

observations -> AttackChainService -> PredictionService -> RiskService
             -> DefenseRecommendationService

Every stage exchanges typed contracts. The classical verdict is never changed; predicted
steps stay in the prediction; recommendations require human approval and execute nothing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from pydantic import Field

from hqc.attack_chain.reconstruction import AttackChainService
from hqc.common.schemas.base import HQCModel, NonEmptyStr, utc_now
from hqc.common.schemas.defense import DefenseRecommendation
from hqc.common.schemas.intelligence import (
    IncidentChain,
    NextTechniquePrediction,
    Observation,
    ResourceContext,
)
from hqc.common.schemas.risk import RiskAssessment
from hqc.defense.recommender import DefenseRecommendationService
from hqc.prediction.service import PredictionService
from hqc.risk.engine import RiskService


class IncidentAssessment(HQCModel):
    chain: IncidentChain
    prediction: NextTechniquePrediction
    high_impact_next_step_probability: float = Field(ge=0.0, le=1.0)
    risk: RiskAssessment
    recommendations: list[DefenseRecommendation]


class PipelineOutput(HQCModel):
    as_of: datetime
    incidents: list[IncidentAssessment]
    unmapped_event_ids: list[str]
    policy_versions: dict[str, str]


class RiskPoint(HQCModel):
    after_event_id: NonEmptyStr
    chain_id: NonEmptyStr
    score: float
    level: str
    observed_technique_ids: list[str]


class IntelligencePipeline:
    def __init__(
        self,
        chains: AttackChainService,
        prediction: PredictionService,
        risk: RiskService,
        defense: DefenseRecommendationService,
    ) -> None:
        self.chains = chains
        self.prediction = prediction
        self.risk = risk
        self.defense = defense

    @property
    def policy_versions(self) -> dict[str, str]:
        return {
            "correlation": self.chains.policy.version,
            "risk": self.risk.policy.version,
            "defense": self.defense.policy.version,
        }

    def run(
        self,
        observations: Sequence[Observation],
        resources: Mapping[str, ResourceContext] | None = None,
        as_of: datetime | None = None,
    ) -> PipelineOutput:
        now = as_of or utc_now()
        rebuilt = self.chains.reconstruct(observations, as_of=now)
        incidents = []
        for incident in rebuilt.chains:
            prediction = self.prediction.predict(incident, as_of=now)
            impact = self.prediction.tactic_probability(
                incident, self.risk.policy.high_impact_tactics, self.risk.catalog
            )
            risk = self.risk.assess(incident, prediction, impact, resources, as_of=now)
            recs = self.defense.recommend(incident, risk, prediction, observations, as_of=now)
            incidents.append(
                IncidentAssessment(
                    chain=incident,
                    prediction=prediction,
                    high_impact_next_step_probability=impact,
                    risk=risk,
                    recommendations=recs,
                )
            )
        return PipelineOutput(
            as_of=now,
            incidents=incidents,
            unmapped_event_ids=rebuilt.unmapped_event_ids,
            policy_versions=self.policy_versions,
        )

    def risk_trajectory(
        self,
        observations: Sequence[Observation],
        resources: Mapping[str, ResourceContext] | None = None,
    ) -> list[RiskPoint]:
        """Risk of the chain containing each new event, using only events seen so far."""
        points = []
        for i, obs in enumerate(observations):
            if not obs.techniques:
                continue
            seen = observations[: i + 1]
            out = self.run(seen, resources, as_of=obs.event.timestamp)
            incident = next(
                a
                for a in out.incidents
                if obs.event.event_id in {s.event_id for s in a.chain.chain.steps}
            )
            points.append(
                RiskPoint(
                    after_event_id=obs.event.event_id,
                    chain_id=incident.chain.chain_id,
                    score=incident.risk.score,
                    level=incident.risk.level.value,
                    observed_technique_ids=incident.chain.observed_technique_ids,
                )
            )
        return points
