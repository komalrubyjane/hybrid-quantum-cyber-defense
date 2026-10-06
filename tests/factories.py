"""Builders for valid example instances of every data contract (test use only).

All values are placeholders for schema testing; none are experimental results.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from hqc.common.schemas import (
    APIEvent,
    AttackChain,
    AttackStep,
    ATTACKTechnique,
    AuthenticationEvent,
    AuthOutcome,
    DataOrigin,
    DefenseAction,
    DefenseRecommendation,
    DetectionResult,
    Disruption,
    EnvironmentInfo,
    EvaluationResult,
    EvaluationStatus,
    EvaluationTask,
    EvidenceRef,
    NetworkFlow,
    NextTechniqueProbability,
    PredictedPath,
    PredictionResult,
    QuantumOpinion,
    RiskAssessment,
    RiskComponent,
    RiskLevel,
    StepProvenance,
    SystemEvent,
    TechniqueCandidate,
    Verdict,
)

T0 = datetime(2026, 1, 15, 9, 0, tzinfo=UTC)
_COMMON = {
    "source_dataset": "synthetic-test",
    "data_origin": DataOrigin.SYNTHETIC,
    "entity_id": "host-a.example.test",
}


def network_flow(event_id: str = "nf-1") -> NetworkFlow:
    return NetworkFlow(
        event_id=event_id,
        timestamp=T0,
        src_ip="192.0.2.1",
        dst_ip="198.51.100.2",
        src_port=50000,
        dst_port=443,
        protocol="tcp",
        duration_s=1.5,
        features={"fwd_packets": 10.0, "bwd_packets": 8.0},
        **_COMMON,
    )


def auth_event(event_id: str = "au-1") -> AuthenticationEvent:
    return AuthenticationEvent(
        event_id=event_id, timestamp=T0, user="alice", outcome=AuthOutcome.FAILURE, **_COMMON
    )


def system_event(event_id: str = "sy-1") -> SystemEvent:
    return SystemEvent(
        event_id=event_id,
        timestamp=T0,
        host="host-a.example.test",
        action="process_start",
        **_COMMON,
    )


def api_event(event_id: str = "ap-1") -> APIEvent:
    return APIEvent(
        event_id=event_id,
        timestamp=T0,
        client_id="c1",
        endpoint="/login",
        method="POST",
        status_code=401,
        **_COMMON,
    )


def detection_result(with_quantum: bool = True, agree: bool = True) -> DetectionResult:
    quantum = None
    if with_quantum:
        quantum = QuantumOpinion(
            gate_triggered=True,
            verdict=Verdict.MALICIOUS if agree else Verdict.BENIGN,
            p_malicious=0.6 if agree else 0.4,
            confidence=0.6,
            backend="statevector",
            feature_map="zz",
        )
    return DetectionResult(
        event_id="nf-1",
        model_id="placeholder-detector",
        model_version="0",
        verdict=Verdict.MALICIOUS,
        p_malicious=0.55,
        confidence=0.55,
        quantum=quantum,
    )


def technique() -> ATTACKTechnique:
    return ATTACKTechnique(
        technique_id="T1059.004",
        name="Unix Shell",
        tactic_ids=["TA0002"],
        is_subtechnique=True,
        parent_id="T1059",
        mitigation_ids=["M1038"],
        attack_version="19.2",
    )


def attack_step(
    tid: str = "T1190",
    minutes: int = 0,
    provenance: StepProvenance = StepProvenance.OBSERVED,
    event_id: str | None = "e-1",
) -> AttackStep:
    return AttackStep(
        technique_id=tid,
        timestamp=T0 + timedelta(minutes=minutes),
        event_id=event_id,
        confidence=0.8,
        source="test",
        provenance=provenance,
        alternative_candidates=[
            TechniqueCandidate(technique_id="T1133", confidence=0.2, mapping_source="test")
        ],
    )


def attack_chain() -> AttackChain:
    return AttackChain(
        chain_id="chain-1",
        entity_ids=["host-a.example.test"],
        steps=[
            attack_step("T1190", 0, event_id="e-1"),
            attack_step("T1059.004", 5, event_id="e-2"),
        ],
        data_origin=DataOrigin.SYNTHETIC,
        attack_version="19.2",
    )


def prediction_result() -> PredictionResult:
    return PredictionResult(
        prediction_id="pred-1",
        chain_id="chain-1",
        observed_prefix=["T1190", "T1059.004"],
        next_step=[
            NextTechniqueProbability(technique_id="T1003", probability=0.5),
            NextTechniqueProbability(technique_id="T1110.001", probability=0.3),
        ],
        paths=[
            PredictedPath(
                technique_ids=["T1003", "T1021.004"],
                probability=0.2,
                cumulative_log_score=-1.6,
                length=2,
            )
        ],
        horizon=3,
        model_id="placeholder-predictor",
        vocabulary_version="vocab-0",
        attack_version="19.2",
    )


def risk_assessment() -> RiskAssessment:
    return RiskAssessment(
        assessment_id="risk-1",
        entity_id="host-a.example.test",
        score=50.0,
        level=RiskLevel.MEDIUM,
        components=[
            RiskComponent(
                name="detection", value=0.5, weight=1.0, contribution=50.0, reason="placeholder"
            )
        ],
    )


def recommendation() -> DefenseRecommendation:
    return DefenseRecommendation(
        recommendation_id="rec-1",
        action=DefenseAction.COLLECT_ADDITIONAL_EVIDENCE,
        target="host-a.example.test",
        reason="classical/quantum disagreement",
        triggering_evidence=[EvidenceRef(kind="detection", ref_id="nf-1", description="x")],
        risk_score=50.0,
        risk_level=RiskLevel.MEDIUM,
        confidence=0.5,
        priority=1.0,
        disruption=Disruption.NONE,
        reversible=True,
    )


def evaluation_result(**overrides: object) -> EvaluationResult:
    data: dict[str, object] = {
        "run_id": "run-1",
        "task": EvaluationTask.CHAIN_PREDICTION,
        "status": EvaluationStatus.NOT_EVALUATED,
        "dataset_id": "synthetic-test",
        "dataset_version": "0",
        "data_origin": DataOrigin.SYNTHETIC,
        "attack_version": "19.2",
        "seed": 42,
        "train_sources": ["flow-a", "flow-b"],
        "test_sources": ["flow-c"],
        "environment": EnvironmentInfo(python_version="3.11.9", platform="test"),
    }
    data.update(overrides)
    return EvaluationResult.model_validate(data)
