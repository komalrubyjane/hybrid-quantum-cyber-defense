"""Serialization round-trips and validation rules for every data contract."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import BaseModel, ValidationError

import factories as f
from hqc.common.errors import InvalidEventSchemaError
from hqc.common.schemas import (
    RISK_LABEL,
    AttackChain,
    ATTACKTechnique,
    DefenseAction,
    DefenseRecommendation,
    EvaluationStatus,
    NetworkFlow,
    NextTechniqueProbability,
    PredictedPath,
    PredictionResult,
    QuantumOpinion,
    StepProvenance,
    TechniqueCandidate,
    parse_security_event,
)

BUILDERS: list[Callable[[], BaseModel]] = [
    f.network_flow,
    f.auth_event,
    f.system_event,
    f.api_event,
    f.detection_result,
    f.technique,
    f.attack_step,
    f.attack_chain,
    f.prediction_result,
    f.risk_assessment,
    f.recommendation,
    f.evaluation_result,
]


@pytest.mark.parametrize("build", BUILDERS, ids=lambda b: b.__name__)
def test_json_round_trip(build: Callable[[], BaseModel]) -> None:
    original = build()
    restored = type(original).model_validate_json(original.model_dump_json())
    assert restored == original


@pytest.mark.parametrize("build", BUILDERS, ids=lambda b: b.__name__)
def test_extra_fields_rejected(build: Callable[[], BaseModel]) -> None:
    payload = build().model_dump(mode="json")
    payload["unexpected_field"] = 1
    with pytest.raises(ValidationError):
        type(build()).model_validate(payload)


# --- events -----------------------------------------------------------------


@pytest.mark.parametrize(
    "build", [f.network_flow, f.auth_event, f.system_event, f.api_event], ids=lambda b: b.__name__
)
def test_security_event_union_dispatch(build: Callable[[], BaseModel]) -> None:
    event = build()
    parsed = parse_security_event(event.model_dump_json())
    assert type(parsed) is type(event)
    assert parsed == event


def test_unknown_event_type_raises_clear_error() -> None:
    payload = f.network_flow().model_dump(mode="json")
    payload["event_type"] = "telepathy"
    with pytest.raises(InvalidEventSchemaError):
        parse_security_event(payload)


def test_naive_timestamp_rejected() -> None:
    payload = f.network_flow().model_dump(mode="json")
    payload["timestamp"] = "2026-01-15T09:00:00"
    with pytest.raises(InvalidEventSchemaError):
        parse_security_event(payload)


def test_timestamp_normalised_to_utc() -> None:
    plus_two = timezone(timedelta(hours=2))
    flow = f.network_flow().model_copy(update={})
    flow.timestamp = datetime(2026, 1, 15, 11, 0, tzinfo=plus_two)
    assert flow.timestamp.utcoffset() == timedelta(0)
    assert flow.timestamp.hour == 9


@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_non_finite_flow_features_rejected(bad: float) -> None:
    payload = f.network_flow().model_dump()
    payload["features"] = {"x": bad}
    with pytest.raises(ValidationError):
        NetworkFlow.model_validate(payload)


def test_invalid_port_and_ip_rejected() -> None:
    payload = f.network_flow().model_dump(mode="json")
    with pytest.raises(InvalidEventSchemaError):
        parse_security_event({**payload, "dst_port": 70000})
    with pytest.raises(InvalidEventSchemaError):
        parse_security_event({**payload, "src_ip": "999.1.1.1"})


# --- ATT&CK identifiers -------------------------------------------------------


@pytest.mark.parametrize("tid", ["T1059", "T1059.004", "T0001"])
def test_valid_technique_id_formats(tid: str) -> None:
    TechniqueCandidate(technique_id=tid, confidence=0.5, mapping_source="t")


@pytest.mark.parametrize(
    "tid", ["Command and Scripting Interpreter", "t1059", "T159", "T1059.4", "TA0002", ""]
)
def test_invalid_technique_ids_rejected(tid: str) -> None:
    with pytest.raises(ValidationError):
        TechniqueCandidate(technique_id=tid, confidence=0.5, mapping_source="t")


def test_subtechnique_parent_consistency() -> None:
    data = f.technique().model_dump()
    with pytest.raises(ValidationError):
        ATTACKTechnique.model_validate({**data, "parent_id": "T1003"})
    with pytest.raises(ValidationError):
        ATTACKTechnique.model_validate({**data, "is_subtechnique": False})
    with pytest.raises(ValidationError):
        ATTACKTechnique.model_validate(
            {**data, "technique_id": "T1059", "is_subtechnique": False, "parent_id": "T1000"}
        )


# --- attack chains --------------------------------------------------------------


def test_chain_preserves_given_order() -> None:
    chain = f.attack_chain()
    assert chain.technique_ids == ["T1190", "T1059.004"]


def test_chain_rejects_out_of_order_timestamps_instead_of_sorting() -> None:
    steps = [f.attack_step("T1059.004", 10, event_id="e-2"), f.attack_step("T1190", 0)]
    with pytest.raises(ValidationError, match="non-decreasing"):
        AttackChain(chain_id="c", steps=steps, data_origin="SYNTHETIC", attack_version="19.2")


def test_observed_step_requires_event_id() -> None:
    with pytest.raises(ValidationError, match="OBSERVED"):
        f.attack_step(event_id=None)


def test_inferred_step_without_event_allowed() -> None:
    step = f.attack_step(provenance=StepProvenance.INFERRED, event_id=None)
    assert step.provenance is StepProvenance.INFERRED


def test_predicted_steps_not_allowed_in_chain() -> None:
    predicted = f.attack_step("T1003", 20, provenance=StepProvenance.PREDICTED, event_id=None)
    with pytest.raises(ValidationError, match="PredictionResult"):
        AttackChain(
            chain_id="c",
            steps=[f.attack_step(), predicted],
            data_origin="SYNTHETIC",
            attack_version="19.2",
        )


# --- prediction -----------------------------------------------------------------


def test_prediction_distribution_must_not_exceed_one() -> None:
    data = f.prediction_result().model_dump()
    data["next_step"] = [
        {"technique_id": "T1003", "probability": 0.7},
        {"technique_id": "T1110", "probability": 0.6},
    ]
    with pytest.raises(ValidationError, match="sum"):
        PredictionResult.model_validate(data)


def test_prediction_rejects_duplicates_and_unsorted() -> None:
    data = f.prediction_result().model_dump()
    data["next_step"] = [
        {"technique_id": "T1003", "probability": 0.2},
        {"technique_id": "T1003", "probability": 0.1},
    ]
    with pytest.raises(ValidationError, match="duplicate"):
        PredictionResult.model_validate(data)
    data["next_step"] = [
        NextTechniqueProbability(technique_id="T1003", probability=0.1).model_dump(),
        NextTechniqueProbability(technique_id="T1110", probability=0.2).model_dump(),
    ]
    with pytest.raises(ValidationError, match="descending"):
        PredictionResult.model_validate(data)


def test_predicted_path_length_and_horizon() -> None:
    with pytest.raises(ValidationError, match="length"):
        PredictedPath(technique_ids=["T1003"], probability=0.1, cumulative_log_score=-2.3, length=2)
    data = f.prediction_result().model_dump()
    data["horizon"] = 1
    with pytest.raises(ValidationError, match="horizon"):
        PredictionResult.model_validate(data)


def test_prediction_provenance_is_fixed() -> None:
    data = f.prediction_result().model_dump()
    data["provenance"] = "OBSERVED"
    with pytest.raises(ValidationError):
        PredictionResult.model_validate(data)


# --- detection / quantum ----------------------------------------------------------


def test_quantum_disagreement_requests_evidence() -> None:
    assert f.detection_result(agree=True).needs_additional_evidence is False
    disagreeing = f.detection_result(agree=False)
    assert disagreeing.quantum_agrees is False
    assert disagreeing.needs_additional_evidence is True
    # Disagreement never changes the classical verdict.
    assert disagreeing.verdict.value == "MALICIOUS"


def test_quantum_opinion_consistency() -> None:
    with pytest.raises(ValidationError):
        QuantumOpinion(gate_triggered=True)
    with pytest.raises(ValidationError):
        QuantumOpinion(gate_triggered=False, p_malicious=0.5)
    assert QuantumOpinion(gate_triggered=False).verdict is None


def test_detection_without_quantum_has_no_agreement() -> None:
    result = f.detection_result(with_quantum=False)
    assert result.quantum_agrees is None
    assert result.needs_additional_evidence is False


# --- risk / defense / evaluation -----------------------------------------------------


def test_risk_label_is_model_derived() -> None:
    assert f.risk_assessment().label == RISK_LABEL == "MODEL-DERIVED RISK SCORE"
    data = f.risk_assessment().model_dump()
    with pytest.raises(ValidationError):
        type(f.risk_assessment()).model_validate({**data, "label": "GROUND TRUTH"})
    with pytest.raises(ValidationError):
        type(f.risk_assessment()).model_validate({**data, "score": 101})


def test_recommendation_always_requires_human_approval() -> None:
    rec = f.recommendation()
    assert rec.requires_human_approval is True
    with pytest.raises(ValidationError):
        DefenseRecommendation.model_validate({**rec.model_dump(), "requires_human_approval": False})


def test_seven_defense_categories() -> None:
    assert {a.value for a in DefenseAction} == {
        "block_suspicious_access",
        "isolate_affected_host",
        "restrict_communication",
        "disable_compromised_credentials",
        "increase_monitoring",
        "escalate_severity",
        "collect_additional_evidence",
    }


def test_evaluation_rejects_train_test_source_overlap() -> None:
    with pytest.raises(ValidationError, match="both train and test"):
        f.evaluation_result(train_sources=["flow-a"], test_sources=["flow-a"])


def test_evaluation_metric_status_consistency() -> None:
    with pytest.raises(ValidationError, match="NOT_EVALUATED"):
        f.evaluation_result(metrics={"top1": 0.1})
    with pytest.raises(ValidationError, match="EVALUATED"):
        f.evaluation_result(status=EvaluationStatus.EVALUATED)
