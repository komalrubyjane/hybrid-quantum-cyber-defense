"""``/api/v1`` routes over the Milestone 7 services. RECOMMENDATION ONLY; nothing executes.

Methods: GET for reading (including recommendations), POST for computations, for storing an
assessment, and for appending an analyst decision. There is no PUT / PATCH / DELETE.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from hqc.api.v1.schemas import (
    AssessmentRecord,
    AssessmentRequest,
    AssessmentSummary,
    Decision,
    DecisionRecord,
    DecisionRequest,
    ErrorResponse,
    MetaResponse,
    PredictRequest,
    PredictResponse,
    RecommendationView,
    ReconstructRequest,
    RiskRequest,
    RunSummary,
)
from hqc.api.v1.services import ApiServices, ServiceProvider
from hqc.api.v1.state import ApiStateStore
from hqc.attack_chain.reconstruction import ChainReconstruction
from hqc.common.errors import RecordNotFoundError
from hqc.common.schemas.base import DataOrigin, Disruption, utc_now
from hqc.common.schemas.defense import DefenseRecommendation
from hqc.common.schemas.evaluation import EvaluationResult
from hqc.common.schemas.risk import RiskAssessment
from hqc.pipeline.scenario import SyntheticScenario, load_scenario
from hqc.storage import Collection, Store

router = APIRouter(prefix="/api/v1", tags=["v1"])
ERRORS: dict[int | str, dict[str, object]] = {
    404: {"model": ErrorResponse},
    409: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
    503: {"model": ErrorResponse},
}


def get_services(request: Request) -> ApiServices:
    provider: ServiceProvider = request.app.state.services
    return provider.get()


def get_state(request: Request) -> ApiStateStore:
    state: ApiStateStore = request.app.state.api_state
    return state


def get_evaluation_store(request: Request) -> Store:
    store: Store = request.app.state.evaluation_store
    return store


Services = Annotated[ApiServices, Depends(get_services)]
State = Annotated[ApiStateStore, Depends(get_state)]
Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0)]


def _unprocessable(exc: Exception) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc))


# --- metadata ---------------------------------------------------------------------------


@router.get("/meta", response_model=MetaResponse, responses=ERRORS)
def meta(services: Services) -> MetaResponse:
    """Versions of the knowledge base, models and policies; the API's safety contract."""
    pipeline = services.pipeline
    return MetaResponse(
        attack_version=services.attack_version,
        vocabulary_version=services.vocabulary_version,
        model_versions=pipeline.prediction.model_versions,
        policy_versions=pipeline.policy_versions,
    )


@router.get("/scenarios/synthetic", response_model=SyntheticScenario, responses=ERRORS)
def synthetic_scenario(services: Services) -> SyntheticScenario:
    """The SYNTHETIC integration scenario (hand-authored; never real-world data)."""
    if services.scenario_path is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No synthetic scenario configured")
    try:
        return load_scenario(services.scenario_path)[0]
    except Exception as exc:  # configuration problem, reported without paths
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="Synthetic scenario unavailable"
        ) from exc


# --- stateless service endpoints -----------------------------------------------------------


@router.post("/chains/reconstruct", response_model=ChainReconstruction, responses=ERRORS)
def reconstruct(body: ReconstructRequest, services: Services) -> ChainReconstruction:
    """Correlate observations (arrival order, never sorted) into incident chains."""
    try:
        return services.pipeline.chains.reconstruct(body.observations, as_of=body.as_of)
    except ValueError as exc:
        raise _unprocessable(exc) from exc


@router.post("/predictions", response_model=PredictResponse, responses=ERRORS)
def predict(body: PredictRequest, services: Services) -> PredictResponse:
    """Next-technique probabilities and beam path scores (PREDICTED, never observed)."""
    pipeline = services.pipeline
    tactics = pipeline.risk.policy.high_impact_tactics
    try:
        prediction = pipeline.prediction.predict(body.chain, as_of=body.as_of)
        impact = pipeline.prediction.tactic_probability(body.chain, tactics, pipeline.risk.catalog)
    except ValueError as exc:
        raise _unprocessable(exc) from exc
    return PredictResponse(
        prediction=prediction,
        high_impact_next_step_probability=impact,
        high_impact_tactics=list(tactics),
    )


@router.post("/risk/assess", response_model=RiskAssessment, responses=ERRORS)
def assess_risk(body: RiskRequest, services: Services) -> RiskAssessment:
    """MODEL-DERIVED RISK SCORE for one chain (quantum evidence contributes 0 points)."""
    resources = {r.resource_id: r for r in body.resources}
    try:
        return services.pipeline.risk.assess(
            body.chain,
            body.prediction,
            body.high_impact_next_step_probability,
            resources,
            as_of=body.as_of,
        )
    except ValueError as exc:
        raise _unprocessable(exc) from exc


# --- assessments (stored, immutable) -------------------------------------------------------


def _summary(record: AssessmentRecord) -> AssessmentSummary:
    incidents = record.output.incidents
    return AssessmentSummary(
        assessment_id=record.assessment_id,
        created_at=record.created_at,
        data_origin=record.data_origin,
        incidents=len(incidents),
        max_risk_score=max((a.risk.score for a in incidents), default=None),
        recommendations=sum(len(a.recommendations) for a in incidents),
    )


@router.post(
    "/assessments",
    response_model=AssessmentRecord,
    status_code=status.HTTP_201_CREATED,
    responses=ERRORS,
)
def create_assessment(
    body: AssessmentRequest, services: Services, state: State
) -> AssessmentRecord:
    """Run the full pipeline on the submitted observations and store the (immutable) result."""
    resources = {r.resource_id: r for r in body.resources}
    try:
        output = services.pipeline.run(body.observations, resources, as_of=body.as_of)
    except ValueError as exc:
        raise _unprocessable(exc) from exc
    synthetic = any(o.event.data_origin is DataOrigin.SYNTHETIC for o in body.observations)
    record = AssessmentRecord(
        assessment_id=f"asm-{uuid.uuid4().hex[:16]}",
        created_at=utc_now(),
        data_origin=DataOrigin.SYNTHETIC if synthetic else DataOrigin.REAL,
        output=output,
    )
    state.add_assessment(record)
    return record


@router.get("/assessments", response_model=list[AssessmentSummary])
def list_assessments(
    state: State, limit: Limit = 50, offset: Offset = 0
) -> list[AssessmentSummary]:
    return [_summary(r) for r in state.list_assessments(limit, offset)]


def _assessment(state: ApiStateStore, assessment_id: str) -> AssessmentRecord:
    record = state.get_assessment(assessment_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    return record


@router.get("/assessments/{assessment_id}", response_model=AssessmentRecord, responses=ERRORS)
def get_assessment(assessment_id: str, state: State) -> AssessmentRecord:
    return _assessment(state, assessment_id)


# --- recommendations (GET only) and analyst decisions (append-only) ----------------------


def _recommendation(record: AssessmentRecord, recommendation_id: str) -> DefenseRecommendation:
    for incident in record.output.incidents:
        for rec in incident.recommendations:
            if rec.recommendation_id == recommendation_id:
                return rec
    raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Recommendation not found")


def _view(
    state: ApiStateStore, assessment_id: str, rec: DefenseRecommendation
) -> RecommendationView:
    decisions = state.decisions(assessment_id, rec.recommendation_id)
    return RecommendationView(
        assessment_id=assessment_id,
        recommendation=rec,
        decisions=decisions,
        latest_decision=decisions[-1].decision if decisions else None,
    )


@router.get(
    "/assessments/{assessment_id}/recommendations",
    response_model=list[RecommendationView],
    responses=ERRORS,
)
def list_recommendations(assessment_id: str, state: State) -> list[RecommendationView]:
    """Recommendations of an assessment (each requires human approval; none is executed)."""
    record = _assessment(state, assessment_id)
    return [
        _view(state, assessment_id, rec)
        for incident in record.output.incidents
        for rec in incident.recommendations
    ]


@router.get(
    "/assessments/{assessment_id}/recommendations/{recommendation_id}",
    response_model=RecommendationView,
    responses=ERRORS,
)
def get_recommendation(
    assessment_id: str, recommendation_id: str, state: State
) -> RecommendationView:
    rec = _recommendation(_assessment(state, assessment_id), recommendation_id)
    return _view(state, assessment_id, rec)


@router.get(
    "/assessments/{assessment_id}/recommendations/{recommendation_id}/decisions",
    response_model=list[DecisionRecord],
    responses=ERRORS,
)
def list_decisions(
    assessment_id: str, recommendation_id: str, state: State
) -> list[DecisionRecord]:
    _recommendation(_assessment(state, assessment_id), recommendation_id)
    return state.decisions(assessment_id, recommendation_id)


@router.post(
    "/assessments/{assessment_id}/recommendations/{recommendation_id}/decisions",
    response_model=DecisionRecord,
    status_code=status.HTTP_201_CREATED,
    responses=ERRORS,
)
def record_decision(
    assessment_id: str, recommendation_id: str, body: DecisionRequest, state: State
) -> DecisionRecord:
    """Append an analyst decision to the audit log. RECORDED ONLY - nothing is executed.

    Approving a HIGH-disruption recommendation requires an earlier ACKNOWLEDGED decision
    (two-step acknowledgement).
    """
    rec = _recommendation(_assessment(state, assessment_id), recommendation_id)
    if body.decision is Decision.APPROVED and rec.disruption is Disruption.HIGH:
        prior = state.decisions(assessment_id, recommendation_id)
        if not any(d.decision is Decision.ACKNOWLEDGED for d in prior):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail="HIGH-disruption recommendations must be ACKNOWLEDGED before APPROVED",
            )
    return state.add_decision(
        assessment_id, recommendation_id, body.decision, body.analyst, body.note
    )


# --- stored evaluation runs (read-only) ------------------------------------------------------


def _run_summary(record: EvaluationResult) -> RunSummary:
    return RunSummary(
        run_id=record.run_id,
        task=record.task,
        status=record.status,
        created_at=record.created_at,
        dataset_id=record.dataset_id,
        dataset_version=record.dataset_version,
        data_origin=record.data_origin,
        attack_version=record.attack_version,
        git_dirty=record.git_dirty,
        runtime_s=record.runtime_s,
        metrics=record.metrics,
        notes=record.notes,
    )


@router.get("/runs", response_model=list[RunSummary])
def list_runs(
    store: Annotated[Store, Depends(get_evaluation_store)], limit: Limit = 50, offset: Offset = 0
) -> list[RunSummary]:
    """Stored experiment records (summaries only: no paths, environment or configuration)."""
    records = store.list(Collection.EVALUATION_RUNS, limit=limit, offset=offset)
    return [_run_summary(r) for r in records if isinstance(r, EvaluationResult)]


@router.get("/runs/{run_id}", response_model=RunSummary, responses=ERRORS)
def get_run(run_id: str, store: Annotated[Store, Depends(get_evaluation_store)]) -> RunSummary:
    try:
        record = store.get(Collection.EVALUATION_RUNS, run_id)
    except RecordNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Run not found") from exc
    if not isinstance(record, EvaluationResult):  # pragma: no cover - collection is typed
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Run not found")
    return _run_summary(record)
