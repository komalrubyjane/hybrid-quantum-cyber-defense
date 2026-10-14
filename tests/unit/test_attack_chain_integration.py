"""Milestone 7: technique evidence, ATT&CK validation, correlation and chain reconstruction."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from hqc.attack_chain.catalog import KnowledgeBaseCatalog, vocabulary_token
from hqc.attack_chain.evidence import (
    EvidencePolicy,
    EvidenceValidationError,
    NoDocumentedMappingError,
    RuleCondition,
    RuleSet,
    apply_rules,
    build_detection_evidence,
    check_evidence,
    detection_evidence_from_result,
    evidence_status,
    technique_evidence_from_dataset_label,
)
from hqc.attack_chain.reconstruction import (
    AttackChainService,
    ChainOrderError,
    CorrelationPolicy,
)
from hqc.common.errors import ConfigurationError
from hqc.common.schemas import (
    CorrelationHints,
    CorrelationStatus,
    DetectionEvidence,
    DetectionOrigin,
    DetectionResult,
    EvidenceSource,
    EvidenceStatus,
    IncidentChain,
    Observation,
    QuantumOpinion,
    StepProvenance,
    TechniqueEvidence,
    Verdict,
    parse_security_event,
)
from hqc.common.schemas.attack import AttackStep
from hqc.prediction.vocabulary import UNK_TOKEN
from m7_fixtures import make_vocabulary, scenario, scenario_observations, static_catalog
from prediction_fixtures import mini_kb, mini_vocabulary

T0 = datetime(2026, 1, 15, 9, 0, tzinfo=UTC)
POLICY = EvidencePolicy()


def event(eid: str, minutes: float, entity: str = "h1", **extra: Any) -> Any:
    payload = {
        "event_type": "system",
        "event_id": eid,
        "timestamp": (T0 + timedelta(minutes=minutes)).isoformat(),
        "source_dataset": "unit",
        "data_origin": "SYNTHETIC",
        "entity_id": entity,
        "host": extra.pop("host", entity),
        "action": "process_start",
        **extra,
    }
    return parse_security_event(payload)


def evidence(
    eid: str, minutes: float, technique: str = "T1059.004", **kw: Any
) -> TechniqueEvidence:
    base: dict[str, Any] = {
        "technique_id": technique,
        "event_id": eid,
        "timestamp": T0 + timedelta(minutes=minutes),
        "confidence": 0.8,
        "source": EvidenceSource.SYNTHETIC_SCENARIO,
        "evidence": ["unit"],
        "reference": "unit@1",
    }
    base.update(kw)
    return TechniqueEvidence(**base)


def obs(eid: str, minutes: float, entity: str = "h1", technique: str | None = "T1059.004",
        hints: CorrelationHints | None = None, **extra: Any) -> Observation:  # fmt: skip
    techniques = [evidence(eid, minutes, technique)] if technique else []
    return Observation(
        event=event(eid, minutes, entity, **extra),
        techniques=techniques,
        hints=hints or CorrelationHints(),
    )


def quantum(p: float) -> QuantumOpinion:
    return QuantumOpinion(
        gate_triggered=True,
        verdict=Verdict.MALICIOUS if p >= 0.5 else Verdict.BENIGN,
        p_malicious=p,
        confidence=max(p, 1 - p),
    )


# --- technique evidence -----------------------------------------------------------------


def test_technique_evidence_contract() -> None:
    with pytest.raises(ValidationError, match="documented CTI"):
        evidence("e1", 0, source=EvidenceSource.ATTACK_FLOW)
    with pytest.raises(ValidationError, match="event_id and timestamp"):
        evidence("e1", 0, timestamp=None)
    with pytest.raises(ValidationError, match="detection_model"):
        evidence("e1", 0, source=EvidenceSource.CLASSICAL_DETECTOR)
    with pytest.raises(ValidationError):
        evidence("e1", 0, technique="PortScan")  # dataset labels are not technique IDs
    with pytest.raises(ValidationError):
        evidence("e1", 0, evidence=[])
    flow = evidence("x", 0, source=EvidenceSource.ATTACK_FLOW, event_id=None, timestamp=None)
    assert flow.event_id is None
    detector = evidence("e1", 0, source=EvidenceSource.QUANTUM_SECOND_OPINION,
                        detection_model="zz_qsvm", model_version="zz-1")  # fmt: skip
    assert detector.detection_model == "zz_qsvm"


def test_attack_validation_against_catalog() -> None:
    catalog = static_catalog()
    assert check_evidence(evidence("e", 0, "T1098.004", tactic_id="TA0003"), catalog)
    with pytest.raises(EvidenceValidationError, match="not a tactic"):
        check_evidence(evidence("e", 0, "T1190", tactic_id="TA0010"), catalog)
    # Well-formed but not an active 19.2 technique: kept, becomes <UNK> for prediction.
    assert not check_evidence(evidence("e", 0, "T9999", tactic_id="TA0001"), catalog)
    vocab = make_vocabulary()
    assert vocabulary_token("T1190", vocab) == "T1190"
    assert vocabulary_token("T9999", vocab) == UNK_TOKEN
    assert vocabulary_token(UNK_TOKEN, vocab) == UNK_TOKEN


def test_cic_labels_are_never_mapped_to_techniques() -> None:
    for label in ("PortScan", "DDoS", "Web Attack - XSS"):
        with pytest.raises(NoDocumentedMappingError, match="not an ATT&CK technique"):
            technique_evidence_from_dataset_label("cicids2017", label)


def test_knowledge_base_catalog() -> None:
    kb = mini_kb()
    catalog = KnowledgeBaseCatalog(kb, mini_vocabulary(kb))
    assert catalog.attack_version == kb.version().attack_version
    assert catalog.is_active("T1059") and not catalog.is_active("T1086")  # revoked
    assert catalog.tactics("T1059")
    assert catalog.tactics("T9999") == [] and catalog.mitigation_ids("T9999") == []
    assert catalog.mitigation_ids("T1059") == sorted(catalog.mitigation_ids("T1059"))
    assert catalog.tactic_count == len(kb.get_all_tactics())
    with pytest.raises(ValueError, match="versions differ"):
        KnowledgeBaseCatalog(kb, make_vocabulary())


# --- explicit rules ------------------------------------------------------------------------


def rule_set(tmp_path: Path) -> RuleSet:
    path = tmp_path / "rules.yaml"
    path.write_text(
        """
version: unit-rules-1
rules:
  - rule_id: R1
    technique_id: T1059.004
    tactic_id: TA0002
    event_type: system
    conditions:
      - {field: action, equals: process_start}
      - {field: process_name, one_of: [sh, bash]}
      - {field: details.parent_process, equals: app-server}
    confidence: 0.7
    rationale: shell started by a web application server
    references: ["https://attack.mitre.org/techniques/T1059/004/"]
    status: illustrative
"""
    )
    return RuleSet.load(path)


def test_explicit_rules(tmp_path: Path) -> None:
    rules = rule_set(tmp_path)
    hit = event("e1", 0, process_name="sh", details={"parent_process": "app-server"})
    miss = event("e2", 0, process_name="python", details={"parent_process": "app-server"})
    no_details = event("e3", 0, process_name="sh")
    [ev] = apply_rules(hit, rules)
    assert ev.source is EvidenceSource.EXPLICIT_RULE and ev.reference == "unit-rules-1:R1"
    assert ev.event_id == "e1" and "illustrative" in ev.evidence[0]
    assert apply_rules(miss, rules) == [] and apply_rules(no_details, rules) == []
    flow = parse_security_event(
        {"event_type": "network_flow", "event_id": "f", "timestamp": T0.isoformat(),
         "source_dataset": "u", "data_origin": "SYNTHETIC", "entity_id": "h"}
    )  # fmt: skip
    assert apply_rules(flow, rules) == []
    with pytest.raises(ValidationError, match="dataset labels"):
        RuleCondition(field="ground_truth_label", equals="PortScan")
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: x\nrules: [{rule_id: R}]\n")
    with pytest.raises(ConfigurationError):
        RuleSet.load(bad)


def test_rule_on_enum_field(tmp_path: Path) -> None:
    rules = RuleSet.model_validate(
        {
            "version": "u",
            "rules": [
                {
                    "rule_id": "A1",
                    "technique_id": "T1110.001",
                    "event_type": "authentication",
                    "conditions": [{"field": "outcome", "equals": "FAILURE"}],
                    "confidence": 0.3,
                    "rationale": "failed login",
                    "references": ["ref"],
                    "status": "illustrative",
                }
            ],
        }
    )
    auth = parse_security_event(
        {"event_type": "authentication", "event_id": "a", "timestamp": T0.isoformat(),
         "source_dataset": "u", "data_origin": "SYNTHETIC", "entity_id": "h", "user": "u",
         "outcome": "FAILURE"}
    )  # fmt: skip
    assert len(apply_rules(auth, rules)) == 1


# --- detection evidence and the disagreement rule ------------------------------------------


def test_evidence_status_rules() -> None:
    strong = [evidence("e", 0, confidence=0.9)]
    weak = [evidence("e", 0, confidence=0.5)]
    detector_only = [
        evidence("e", 0, confidence=0.99, source=EvidenceSource.CLASSICAL_DETECTOR,
                 detection_model="rf", model_version="rf-1")
    ]  # fmt: skip
    assert evidence_status(None, True, strong, POLICY) == (False, EvidenceStatus.NO_SECOND_OPINION)
    idle = QuantumOpinion(gate_triggered=False)
    assert evidence_status(idle, True, [], POLICY)[1] is EvidenceStatus.NO_SECOND_OPINION
    assert evidence_status(quantum(0.9), True, [], POLICY) == (False, EvidenceStatus.CONSISTENT)
    assert evidence_status(quantum(0.1), True, [], POLICY) == (
        True,
        EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE,
    )
    assert (
        evidence_status(quantum(0.1), True, weak, POLICY)[1]
        is EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE
    )
    assert evidence_status(quantum(0.1), True, detector_only, POLICY)[1] is (
        EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE
    )  # detector evidence is not independent of the detectors
    assert evidence_status(quantum(0.9), False, strong, POLICY) == (
        True,
        EvidenceStatus.CORROBORATED_BY_INDEPENDENT_EVIDENCE,
    )


def make_detection(
    p: float, q: float | None, techniques: list[TechniqueEvidence]
) -> DetectionEvidence:
    return build_detection_evidence(
        event_id="e", timestamp=T0, origin=DetectionOrigin.SYNTHETIC_FIXTURE,
        classical_model="rf", classical_model_version="rf-1", p_malicious=p, threshold=0.5,
        quantum=quantum(q) if q is not None else None, techniques=techniques, policy=POLICY,
    )  # fmt: skip


def test_detection_evidence_keeps_classical_verdict() -> None:
    d = make_detection(0.62, 0.2, [])
    assert d.verdict is Verdict.MALICIOUS and d.quantum_disagreement
    assert d.evidence_status is EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE
    benign = make_detection(0.3, 0.9, [])
    assert benign.verdict is Verdict.BENIGN  # quantum MALICIOUS does not flip it
    with pytest.raises(ValidationError, match="verdict must follow"):
        DetectionEvidence.model_validate({**d.model_dump(), "verdict": Verdict.BENIGN})
    with pytest.raises(ValidationError, match="quantum_disagreement"):
        DetectionEvidence.model_validate({**d.model_dump(), "quantum_disagreement": False})
    with pytest.raises(ValidationError, match="unless corroborated"):
        DetectionEvidence.model_validate(
            {**d.model_dump(), "evidence_status": EvidenceStatus.CONSISTENT}
        )
    agree = make_detection(0.8, 0.9, [])
    with pytest.raises(ValidationError, match="CONSISTENT"):
        DetectionEvidence.model_validate(
            {**agree.model_dump(), "evidence_status": EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE}
        )
    none = make_detection(0.8, None, [])
    with pytest.raises(ValidationError, match="NO SECOND OPINION"):
        DetectionEvidence.model_validate(
            {**none.model_dump(), "evidence_status": EvidenceStatus.CONSISTENT}
        )


def test_adapter_for_milestone_5_6_detection_results() -> None:
    result = DetectionResult(
        event_id="Friday.csv:7", model_id="random_forest", model_version="random_forest-abc",
        verdict=Verdict.MALICIOUS, p_malicious=0.7, confidence=0.7, threshold=0.5,
        quantum=quantum(0.2),
    )  # fmt: skip
    d = detection_evidence_from_result(result, T0, POLICY)
    assert d.origin is DetectionOrigin.MODEL_OUTPUT and d.verdict is Verdict.MALICIOUS
    assert d.evidence_status is EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE
    no_threshold = result.model_copy(update={"threshold": None, "quantum": None})
    assert detection_evidence_from_result(no_threshold, T0, POLICY).threshold == 0.5
    inconsistent = result.model_copy(update={"verdict": Verdict.BENIGN})
    with pytest.raises(ValueError, match="inconsistent"):
        detection_evidence_from_result(inconsistent, T0, POLICY)


def test_observation_requires_matching_event_ids() -> None:
    o = obs("e1", 0)
    with pytest.raises(ValidationError, match="reference this observation"):
        Observation(event=o.event, techniques=[evidence("other", 0)])
    with pytest.raises(ValidationError, match=r"detection\.event_id"):
        Observation(event=o.event, detection=make_detection(0.9, None, []))


# --- correlation and reconstruction --------------------------------------------------------


def service(**kw: Any) -> AttackChainService:
    return AttackChainService(static_catalog(), CorrelationPolicy(**kw))


def test_scenario_reconstruction() -> None:
    observations = scenario_observations()
    result = service().reconstruct(observations, as_of=scenario().as_of)
    assert result.unmapped_event_ids == ["syn-ms-e02"]  # no technique evidence -> no step
    main, standalone = result.chains
    assert [s.event_id for s in main.chain.steps] == [
        "syn-ms-e01", "syn-ms-e03", "syn-ms-e04", "syn-ms-e05", "syn-ms-e06", "syn-ms-e08",
    ]  # fmt: skip
    assert main.status is CorrelationStatus.CORRELATED
    assert [d.rule for d in main.decisions] == ["new_chain"] + ["shared_resource"] * 5
    assert main.resources == ["db-01.example.test", "web-01.example.test"]
    assert all(s.provenance is StepProvenance.OBSERVED for s in main.chain.steps)
    assert main.chain.data_origin.value == "SYNTHETIC" and main.chain.created_at == scenario().as_of
    assert len(main.detections) == 6
    assert standalone.status is CorrelationStatus.STANDALONE
    assert standalone.observed_technique_ids == ["T1110.001"]


def test_arrival_order_is_preserved_and_never_sorted() -> None:
    late_first = [obs("a", 10), obs("b", 5)]  # same resource, second is older
    with pytest.raises(ChainOrderError, match="not re-sorted"):
        service().reconstruct(late_first)
    unrelated = [obs("a", 10, "h1"), obs("b", 5, "h2")]  # different chains: allowed as given
    chains = service().reconstruct(unrelated).chains
    assert [c.chain.steps[0].event_id for c in chains] == ["a", "b"]


def test_time_window_and_correlation_rules() -> None:
    out = service(window_minutes=30).reconstruct([obs("a", 0), obs("b", 45)])
    assert [c.status for c in out.chains] == [CorrelationStatus.STANDALONE] * 2
    inc = CorrelationHints
    explicit = service().reconstruct([
        obs("a", 0, "h1", hints=inc(incident_id="I1")),
        obs("b", 1, "h1", hints=inc(incident_id="I2")),  # same host, different incident
        obs("c", 2, "h9", hints=inc(incident_id="I1")),  # other host, same incident
    ])  # fmt: skip
    first = explicit.chains[0]
    assert [s.event_id for s in first.chain.steps] == ["a", "c"]
    assert first.decisions[1].rule == "incident_id"
    session = service().reconstruct([
        obs("a", 0, "h1", hints=inc(session_id="S")), obs("b", 1, "h2", hints=inc(session_id="S")),
    ])  # fmt: skip
    assert session.chains[0].decisions[1].rule == "session_id"
    accounts = service().reconstruct([obs("a", 0, "h1", user="bob"), obs("b", 1, "h2", user="bob")])
    assert accounts.chains[0].decisions[1].rule == "shared_account"
    no_accounts = service(use_accounts=False).reconstruct(
        [obs("a", 0, "h1", user="bob"), obs("b", 1, "h2", user="bob")]
    )
    assert len(no_accounts.chains) == 2


def test_ip_addresses_alone_do_not_correlate() -> None:
    def flow(eid: str, minutes: float, entity: str) -> Observation:
        e = parse_security_event(
            {"event_type": "network_flow", "event_id": eid,
             "timestamp": (T0 + timedelta(minutes=minutes)).isoformat(), "source_dataset": "u",
             "data_origin": "SYNTHETIC", "entity_id": entity, "src_ip": "192.0.2.1"}
        )  # fmt: skip
        return Observation(event=e, techniques=[evidence(eid, minutes, "T1041")])

    assert len(service().reconstruct([flow("a", 0, "h1"), flow("b", 1, "h2")]).chains) == 2


def test_ambiguous_events_are_not_forced_into_a_chain() -> None:
    out = service().reconstruct([
        obs("a", 0, "h1"), obs("b", 1, "h2"),
        obs("c", 2, "h1", host="h2"),  # names both hosts
    ])  # fmt: skip
    assert len(out.chains) == 3
    ambiguous = out.chains[2]
    assert ambiguous.status is CorrelationStatus.AMBIGUOUS
    assert ambiguous.decisions[0].rule == "ambiguous"
    assert ambiguous.decisions[0].matched_keys == ["chain-a", "chain-b"]
    assert [len(c.chain.steps) for c in out.chains] == [1, 1, 1]


def test_primary_evidence_alternatives_and_unknown_techniques() -> None:
    e = event("a", 0)
    both = Observation(
        event=e,
        techniques=[
            evidence("a", 0, "T1059.004", confidence=0.6),
            evidence("a", 0, "T9999", confidence=0.9),
            evidence("a", 0, "T1053.003", confidence=0.6, source=EvidenceSource.EXPLICIT_RULE),
        ],
    )
    [chain] = service().reconstruct([both]).chains
    step = chain.chain.steps[0]
    assert step.technique_id == "T9999" and step.tactic_id is None
    assert chain.out_of_vocabulary_technique_ids == ["T9999"]
    assert [c.technique_id for c in step.alternative_candidates] == ["T1059.004", "T1053.003"]
    assert step.alternative_candidates[1].mapping_source.startswith("EXPLICIT_RULE:")
    tie = Observation(
        event=e,
        techniques=[
            evidence("a", 0, "T1059.004", confidence=0.6),
            evidence("a", 0, "T1053.003", confidence=0.6, source=EvidenceSource.EXPLICIT_RULE),
        ],
    )
    tied = service().reconstruct([tie]).chains[0].chain.steps[0]
    assert tied.technique_id == "T1053.003"  # EXPLICIT_RULE precedes SYNTHETIC_SCENARIO on ties
    assert tied.tactic_id is None  # multi-tactic technique without an attributed tactic
    single = service().reconstruct([obs("b", 0, technique="T1190")]).chains[0].chain.steps[0]
    assert single.tactic_id == "TA0001"  # inferred only when the technique has one tactic


def test_documented_steps_stay_separate() -> None:
    svc = service()
    [incident] = svc.reconstruct([obs("a", 0)]).chains
    doc = evidence("x", 0, "T1041", source=EvidenceSource.ATTACK_FLOW, event_id=None,
                   timestamp=None, reference="attack-flow:Doc")  # fmt: skip
    updated = svc.attach_documented(incident, [doc])
    assert [s.provenance for s in updated.documented_steps] == [StepProvenance.DOCUMENTED]
    assert updated.observed_technique_ids == incident.observed_technique_ids
    with pytest.raises(ValueError, match="ATTACK_FLOW"):
        svc.attach_documented(incident, [evidence("a", 0)])
    observed = incident.chain.steps[0]
    with pytest.raises(ValidationError, match="OBSERVED steps only"):
        IncidentChain.model_validate(
            {**incident.model_dump(), "chain": {**incident.chain.model_dump(),
             "steps": [{**observed.model_dump(), "provenance": "INFERRED"}]}}
        )  # fmt: skip
    with pytest.raises(ValidationError, match="documented_steps must be DOCUMENTED"):
        IncidentChain.model_validate(
            {**incident.model_dump(), "documented_steps": [observed.model_dump()]}
        )
    with pytest.raises(ValidationError, match="PREDICTED steps cannot"):
        AttackStep(technique_id="T1041", confidence=0.5, source="model", event_id="a",
                   provenance=StepProvenance.PREDICTED)  # fmt: skip
