"""Storage abstraction: typed collections of pipeline records.

Each collection stores exactly one contract type (or the SecurityEvent union) and
derives the record key from the record itself, so callers never pass raw dicts.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, TypeAdapter

from hqc.common.schemas import (
    APIEvent,
    AttackChain,
    AuthenticationEvent,
    DefenseRecommendation,
    DetectionResult,
    EvaluationResult,
    NetworkFlow,
    PredictionResult,
    RiskAssessment,
    SecurityEvent,
    SystemEvent,
)


class Collection(StrEnum):
    SECURITY_EVENTS = "security_events"
    DETECTION_RESULTS = "detection_results"
    ATTACK_CHAINS = "attack_chains"
    PREDICTIONS = "predictions"
    RISK_ASSESSMENTS = "risk_assessments"
    RECOMMENDATIONS = "recommendations"
    EVALUATION_RUNS = "evaluation_runs"


@dataclass(frozen=True)
class CollectionSpec:
    """How records of one collection are typed, keyed and (de)serialised."""

    types: tuple[type[BaseModel], ...]
    key: Callable[[Any], str]
    adapter: TypeAdapter[Any]
    immutable: bool = False


def _detection_key(r: DetectionResult) -> str:
    return f"{r.event_id}:{r.model_id}:{r.model_version}"


COLLECTION_SPECS: dict[Collection, CollectionSpec] = {
    Collection.SECURITY_EVENTS: CollectionSpec(
        (NetworkFlow, AuthenticationEvent, SystemEvent, APIEvent),
        lambda r: r.event_id,
        TypeAdapter(SecurityEvent),
    ),
    Collection.DETECTION_RESULTS: CollectionSpec(
        (DetectionResult,), _detection_key, TypeAdapter(DetectionResult)
    ),
    Collection.ATTACK_CHAINS: CollectionSpec(
        (AttackChain,), lambda r: r.chain_id, TypeAdapter(AttackChain)
    ),
    Collection.PREDICTIONS: CollectionSpec(
        (PredictionResult,), lambda r: r.prediction_id, TypeAdapter(PredictionResult)
    ),
    Collection.RISK_ASSESSMENTS: CollectionSpec(
        (RiskAssessment,), lambda r: r.assessment_id, TypeAdapter(RiskAssessment)
    ),
    Collection.RECOMMENDATIONS: CollectionSpec(
        (DefenseRecommendation,),
        lambda r: r.recommendation_id,
        TypeAdapter(DefenseRecommendation),
    ),
    # Evaluation runs are write-once so experiment records cannot be silently altered.
    Collection.EVALUATION_RUNS: CollectionSpec(
        (EvaluationResult,), lambda r: r.run_id, TypeAdapter(EvaluationResult), immutable=True
    ),
}


class Store(Protocol):
    """Minimal persistence interface used by the pipeline and API."""

    def put(self, collection: Collection, record: BaseModel) -> str:
        """Insert or update a record; returns its key."""
        ...

    def get(self, collection: Collection, key: str) -> BaseModel:
        """Return the record or raise RecordNotFoundError."""
        ...

    def list(self, collection: Collection, limit: int = 100, offset: int = 0) -> list[BaseModel]:
        """Return records in insertion order."""
        ...

    def count(self, collection: Collection) -> int:
        """Number of records in a collection."""
        ...

    def close(self) -> None:
        """Release resources."""
        ...
