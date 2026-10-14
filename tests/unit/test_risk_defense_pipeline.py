"""Milestone 7: prediction integration, risk engine, recommendation policy, synthetic end-to-end."""

from __future__ import annotations

import json
import math
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from hqc.attack_chain.evidence import EvidencePolicy
from hqc.attack_chain.reconstruction import AttackChainService
from hqc.common.errors import ConfigurationError
from hqc.common.repro import environment_info
from hqc.common.schemas import (
    Criticality,
    DefenseAction,
    DefenseRecommendation,
    EvidenceStatus,
    IncidentChain,
    ResourceContext,
    RiskLevel,
)
from hqc.common.schemas.base import utc_now
from hqc.common.schemas.risk import RISK_LABEL
from hqc.defense.recommender import (
    ACTION_PROFILE,
    LEVEL_ACTIONS,
    WITHHELD_WHEN_EVIDENCE_NEEDED,
    DefensePolicy,
    DefenseRecommendationService,
)
from hqc.pipeline.checks import _without_quantum, integration_checks, stored_output_policy_check
from hqc.pipeline.config import load_integration_config
from hqc.pipeline.scenario import load_scenario, validate_scenario
from hqc.pipeline.tracking import (
    RUN_FILES,
    IntegrationProvenance,
    IntegrationRun,
    integration_record,
    make_integration_run_id,
    store_integration_record,
    write_integration_run,
)
from hqc.prediction.base import OutputSpace
from hqc.prediction.baselines import UniformModel
from hqc.prediction.service import PredictionService
from hqc.prediction.vocabulary import UNK_TOKEN
from hqc.risk.engine import RiskPolicy, RiskService, RiskThresholds, RiskWeights, worst_status
from hqc.storage import SQLiteStore
from m7_fixtures import (
    INTEGRATION_CONFIG,
    SCENARIO_PATH,
    make_models,
    make_pipeline,
    make_prediction_service,
    make_vocabulary,
    scenario,
    scenario_observations,
    static_catalog,
)

RESOURCES = {r.resource_id: r for r in scenario().resources}


def incidents() -> tuple[IncidentChain, IncidentChain]:
    out = AttackChainService(static_catalog()).reconstruct(
        scenario_observations(), as_of=scenario().as_of
    )
    main, standalone = out.chains
    return main, standalone


# --- prediction ---------------------------------------------------------------------------


def test_prediction_service_outputs() -> None:
    svc = make_prediction_service()
    main, _ = incidents()
    pred = svc.predict(main, as_of=scenario().as_of)
    r = pred.result
    assert r.provenance == "PREDICTED" and pred.provenance == "PREDICTED"
    assert r.observed_prefix == main.observed_technique_ids
    probs = [n.probability for n in r.next_step]
    assert len(probs) == 3 and probs == sorted(probs, reverse=True)
    assert all(n.technique_id != UNK_TOKEN for n in r.next_step)
    assert set(pred.per_model_top_k) == {"B1", "M1", "LSTM", "HYBRID"}
    assert [t for t, _ in pred.per_model_top_k["HYBRID"]] == [n.technique_id for n in r.next_step]
    assert len(r.paths) == 3 and all(p.length == r.horizon == 2 for p in r.paths)
    assert all(math.isclose(p.probability, math.exp(p.cumulative_log_score)) for p in r.paths)
    assert "LOWER BOUND" in pred.path_score_semantics and "NEXT-STEP" in pred.next_step_semantics
    # The hybrid's distribution is exactly 0.5 * Markov + 0.5 * uniform (Milestone 4 fusion).
    m1 = svc.models["M1"].distribution(pred.context_tokens)
    expected = 0.5 * m1[svc.space.position("T1105")] + 0.5 / svc.space.size
    assert dict(pred.per_model_top_k["HYBRID"]).get("T1105", expected) == pytest.approx(expected)


def test_unknown_techniques_become_unk_in_history() -> None:
    svc = make_prediction_service()
    main, _ = incidents()
    step = main.chain.steps[0].model_copy(update={"technique_id": "T9999"})
    altered = main.model_copy(
        update={"chain": main.chain.model_copy(update={"steps": [step, *main.chain.steps[1:]]})}
    )
    assert svc.context(altered)[0] == UNK_TOKEN
    assert svc.predict(altered).result.observed_prefix[0] == "T9999"


def test_tactic_probability_matches_manual_sum() -> None:
    svc = make_prediction_service()
    catalog = static_catalog()
    main, _ = incidents()
    dist = svc.models["HYBRID"].distribution(svc.context(main))
    manual = math.fsum(
        p for t, p in zip(svc.space.tokens, dist, strict=True) if t in ("T1041", "T1486")
    )
    assert svc.tactic_probability(main, ["TA0010", "TA0040"], catalog) == pytest.approx(manual)


def test_prediction_service_validation() -> None:
    vocab = make_vocabulary()
    models = make_models(vocab)
    with pytest.raises(ValueError, match="Primary model"):
        PredictionService(models, "NOPE", vocab, {})
    other = make_vocabulary().from_technique_ids(["T1190", "T1041"], "19.2")
    with pytest.raises(ValueError, match="versions differ"):
        PredictionService(models, "HYBRID", other, {})
    mixed = {**models, "other": UniformModel(OutputSpace(other))}
    with pytest.raises(ValueError, match="one output space"):
        PredictionService(mixed, "HYBRID", vocab, {})
    assert OutputSpace(vocab).size == len(vocab.index_to_token) - 2


# --- risk ---------------------------------------------------------------------------------


def risk_service() -> RiskService:
    return RiskService(RiskPolicy(), static_catalog())


def test_risk_formula_and_label() -> None:
    main, _ = incidents()
    svc = risk_service()
    risk = svc.assess(main, None, 0.2, RESOURCES, as_of=scenario().as_of)
    assert risk.label == RISK_LABEL == "MODEL-DERIVED RISK SCORE"
    assert risk.score == pytest.approx(
        math.fsum(c.weight * c.value for c in risk.components), abs=1e-3
    )
    by_name = {c.name: c for c in risk.components}
    assert by_name["detection"].value == pytest.approx(0.91)  # max classical P(malicious)
    assert by_name["technique_confidence"].value == pytest.approx(
        (0.9 + 0.85 + 0.6 + 0.8 + 0.75 + 0.7) / 6
    )
    assert by_name["tactic_progression"].value == pytest.approx(14 / 15)  # exfiltration, order 13
    assert by_name["predicted_high_impact"].value == pytest.approx(0.2)
    assert by_name["asset_criticality"].value == 0.75  # db-01 HIGH
    age_h = (scenario().as_of - main.chain.steps[-1].timestamp).total_seconds() / 3600  # type: ignore[operator]
    assert by_name["recency"].value == pytest.approx(0.5 ** (age_h / 6.0))
    assert by_name["quantum_second_opinion"].contribution == 0.0
    assert risk.quantum_disagreement and risk.evidence_status == "NEEDS ADDITIONAL EVIDENCE"
    assert risk.uncertainty == pytest.approx(1 / 6)
    assert risk.observed_technique_ids == main.observed_technique_ids
    assert risk.policy_version == "risk-policy-v1"
    assert "detector:synthetic-fixture-classical" in risk.model_versions


def test_quantum_never_changes_the_risk_score() -> None:
    main, _ = incidents()
    svc = risk_service()
    base = svc.assess(main, None, 0.1, RESOURCES, as_of=scenario().as_of).score
    for flip in (False, True):
        variant = _without_quantum(main, flip)
        assert svc.assess(variant, None, 0.1, RESOURCES, as_of=scenario().as_of).score == base


def test_risk_thresholds_are_fixed_engineering_labels() -> None:
    t = RiskThresholds()
    cases = [(0, "LOW"), (24.99, "LOW"), (25, "MEDIUM"), (49.99, "MEDIUM"), (50, "HIGH"),
             (74.99, "HIGH"), (75, "CRITICAL"), (100, "CRITICAL")]  # fmt: skip
    assert [t.level(s).value for s, _ in cases] == [lv for _, lv in cases]
    with pytest.raises(ValidationError, match="Thresholds"):
        RiskThresholds(medium=50, high=40, critical=75)
    with pytest.raises(ValidationError, match="sum to 100"):
        RiskWeights(detection=50)


def test_risk_defaults_and_edge_cases() -> None:
    main, standalone = incidents()
    svc = risk_service()
    neutral = svc.assess(standalone, None, None, {}, as_of=scenario().as_of)
    comps = {c.name: c for c in neutral.components}
    assert (
        comps["asset_criticality"].value == 0.5
        and "not provided" in comps["asset_criticality"].reason
    )
    assert comps["predicted_high_impact"].value == 0.0 and neutral.predicted_technique_ids == []
    assert neutral.evidence_status == "NO SECOND OPINION" and not neutral.quantum_disagreement
    no_detect = standalone.model_copy(update={"detections": []})
    bare = svc.assess(no_detect, None, None, None, as_of=scenario().as_of)
    assert bare.uncertainty is None and bare.evidence_status is None
    assert {c.name: c for c in bare.components}["detection"].value == 0.0
    with pytest.raises(ValueError, match="earlier"):
        svc.assess(main, None, None, None, as_of=scenario().as_of - timedelta(hours=1))
    later = svc.assess(main, None, 0.0, RESOURCES, as_of=scenario().as_of + timedelta(hours=6))
    recency = {c.name: c for c in later.components}["recency"]
    age_h = 6 + (scenario().as_of - main.chain.steps[-1].timestamp).total_seconds() / 3600  # type: ignore[operator]
    assert recency.value == pytest.approx(0.5 ** (age_h / 6.0))
    unknown = main.model_copy(update={"chain": main.chain.model_copy(update={
        "steps": [s.model_copy(update={"technique_id": "T9999", "tactic_id": None})
                  for s in main.chain.steps]})})  # fmt: skip
    progression = {
        c.name: c for c in svc.assess(unknown, None, 0.0, None, as_of=scenario().as_of).components
    }
    assert progression["tactic_progression"].value == 0.0
    critical = {
        "web-01.example.test": ResourceContext(
            resource_id="web-01.example.test", criticality=Criticality.CRITICAL
        )
    }
    assert {
        c.name: c for c in svc.assess(main, None, 0.0, critical, as_of=scenario().as_of).components
    }["asset_criticality"].value == 1.0
    assert worst_status([]) is None
    assert worst_status([EvidenceStatus.CONSISTENT, EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE]) is (
        EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE
    )


# --- defense ------------------------------------------------------------------------------


def defense() -> DefenseRecommendationService:
    return DefenseRecommendationService(DefensePolicy(), static_catalog())


def test_policy_table_is_deterministic() -> None:
    d = defense()
    assert d.planned_actions(RiskLevel.LOW, False) == [DefenseAction.INCREASE_MONITORING]
    assert d.planned_actions(RiskLevel.MEDIUM, False) == [
        DefenseAction.COLLECT_ADDITIONAL_EVIDENCE, DefenseAction.INCREASE_MONITORING,
    ]  # fmt: skip
    assert d.planned_actions(RiskLevel.CRITICAL, False) == list(LEVEL_ACTIONS[RiskLevel.CRITICAL])
    for level in RiskLevel:
        plan = d.planned_actions(level, True)
        assert DefenseAction.COLLECT_ADDITIONAL_EVIDENCE in plan
        assert not set(plan) & WITHHELD_WHEN_EVIDENCE_NEEDED
    assert d.planned_actions(RiskLevel.CRITICAL, True) == [
        DefenseAction.RESTRICT_COMMUNICATION, DefenseAction.ESCALATE_SEVERITY,
        DefenseAction.INCREASE_MONITORING, DefenseAction.COLLECT_ADDITIONAL_EVIDENCE,
    ]  # fmt: skip
    assert set(ACTION_PROFILE) == set(DefenseAction)


def recommend(main: IncidentChain, level_score: float, needs: bool) -> list[DefenseRecommendation]:
    svc = risk_service()
    chain = main if needs else _without_quantum(main, flip=False)
    risk = svc.assess(chain, None, 0.0, RESOURCES, as_of=scenario().as_of)
    risk = risk.model_copy(
        update={"score": level_score, "level": RiskThresholds().level(level_score)}
    )
    pred = make_prediction_service().predict(chain)
    return defense().recommend(chain, risk, pred, scenario_observations(), as_of=scenario().as_of)


def test_critical_recommendations_without_unresolved_disagreement() -> None:
    main, _ = incidents()
    recs = recommend(main, 90.0, needs=False)
    actions = {(r.action, r.target) for r in recs}
    assert (DefenseAction.ISOLATE_AFFECTED_HOST, "db-01.example.test") in actions
    assert (DefenseAction.BLOCK_SUSPICIOUS_ACCESS, "203.0.113.50") in actions  # initial access src
    assert (DefenseAction.BLOCK_SUSPICIOUS_ACCESS, "198.51.100.77") in actions  # exfil destination
    assert (DefenseAction.DISABLE_COMPROMISED_CREDENTIALS, "svc-backup") in actions
    assert (DefenseAction.ESCALATE_SEVERITY, "db-01.example.test") in actions
    for r in recs:
        assert r.requires_human_approval is True and r.status.value == "PROPOSED"
        assert r.policy_version == "defense-policy-v1" and r.chain_id == main.chain_id
        assert "RECOMMENDATION ONLY" in r.approval_note and RISK_LABEL in r.reason
        assert r.triggering_evidence and r.risk_score == 90.0
        assert r.attack_mitigation_ids == sorted(r.attack_mitigation_ids)
    priorities = [r.priority for r in recs]
    assert priorities == sorted(priorities, reverse=True)
    assert recs[0].action is DefenseAction.ESCALATE_SEVERITY
    assert len({r.recommendation_id for r in recs}) == len(recs)


def test_unresolved_disagreement_withholds_disruptive_actions() -> None:
    main, _ = incidents()
    recs = recommend(main, 90.0, needs=True)
    assert not {r.action for r in recs} & WITHHELD_WHEN_EVIDENCE_NEEDED
    collect = [r for r in recs if r.action is DefenseAction.COLLECT_ADDITIONAL_EVIDENCE]
    assert [r.target for r in collect] == ["web-01.example.test"]  # e04's resource
    assert any(
        ref.kind == "detection" and ref.ref_id == "syn-ms-e04"
        for ref in collect[0].triggering_evidence
    )
    assert collect[0].confidence < recommend(main, 90.0, needs=False)[0].confidence  # uncertainty


def test_low_and_medium_and_no_block_target() -> None:
    main, standalone = incidents()
    low = recommend(main, 10.0, needs=False)
    assert {r.action for r in low} == {DefenseAction.INCREASE_MONITORING}
    risk = risk_service().assess(standalone, None, 0.0, {}, as_of=scenario().as_of)
    critical = risk.model_copy(update={"score": 80.0, "level": RiskLevel.CRITICAL})
    recs = defense().recommend(
        standalone, critical, None, scenario_observations(), as_of=scenario().as_of
    )
    actions = {r.action for r in recs}
    assert DefenseAction.BLOCK_SUSPICIOUS_ACCESS not in actions  # no initial-access/exfil address
    assert (DefenseAction.DISABLE_COMPROMISED_CREDENTIALS in actions) is True  # alice, TA0006


def test_recommendations_can_never_skip_human_approval() -> None:
    main, _ = incidents()
    rec = recommend(main, 60.0, needs=False)[0]
    with pytest.raises(ValidationError):
        DefenseRecommendation.model_validate({**rec.model_dump(), "requires_human_approval": False})
    for name in dir(defense()):
        assert not name.startswith(("execute", "apply_", "enforce", "run_", "block_", "isolate_"))


# --- end-to-end synthetic scenario ---------------------------------------------------------


def test_synthetic_end_to_end_pipeline_and_checks() -> None:
    sc = scenario()
    observations = scenario_observations()
    pipeline = make_pipeline()
    out = pipeline.run(observations, RESOURCES, as_of=sc.as_of)
    assert out.unmapped_event_ids == ["syn-ms-e02"]
    assert out.policy_versions == {"correlation": "correlation-v1", "risk": "risk-policy-v1",
                                   "defense": "defense-policy-v1"}  # fmt: skip
    main = out.incidents[0]
    assert (
        main.risk.quantum_disagreement and main.risk.evidence_status == "NEEDS ADDITIONAL EVIDENCE"
    )
    assert all(r.requires_human_approval for a in out.incidents for r in a.recommendations)
    checks = integration_checks(out, sc, observations, pipeline, RESOURCES)
    assert len(checks) == 13 and all(c.passed for c in checks), [c for c in checks if not c.passed]
    trajectory = pipeline.risk_trajectory(observations, RESOURCES)
    assert [p.after_event_id for p in trajectory] == [
        "syn-ms-e01", "syn-ms-e03", "syn-ms-e04", "syn-ms-e05",
        "syn-ms-e06", "syn-ms-e07", "syn-ms-e08",
    ]  # fmt: skip
    assert trajectory[-1].observed_technique_ids == main.chain.observed_technique_ids


def test_checks_detect_a_broken_expectation() -> None:
    sc = scenario()
    observations = scenario_observations()
    pipeline = make_pipeline()
    out = pipeline.run(observations, RESOURCES, as_of=sc.as_of)
    wrong = sc.model_copy(
        update={"expected": sc.expected.model_copy(update={"unmapped_event_ids": []})}
    )
    failed = [
        c.name
        for c in integration_checks(out, wrong, observations, pipeline, RESOURCES)
        if not c.passed
    ]
    assert failed == ["unmapped_events_produce_no_step"]


def test_stored_output_policy_check() -> None:
    s = stored_output_policy_check(
        "run", [0.9, 0.9, 0.2, 0.7], [0.8, 0.1, None, 0.4], 0.5, EvidencePolicy()
    )
    assert (s.rows, s.disagreements, s.needs_additional_evidence, s.consistent) == (3, 2, 2, 1)
    assert "Not a performance metric" in s.note


def test_scenario_and_config_loading(tmp_path: Path) -> None:
    sc, sha = load_scenario(SCENARIO_PATH)
    assert (
        sc.data_origin == "SYNTHETIC"
        and len(sha) == 64
        and sc.reference == "synthetic-multistage@1"
    )
    ids = validate_scenario(sc, static_catalog())
    assert ids[0] == "T1190" and "T1041" in ids
    with pytest.raises(ConfigurationError, match="not an active"):
        validate_scenario(sc, static_catalog(active=["T1190"]))
    bad_tactic = json.loads(SCENARIO_PATH.read_text())
    bad_tactic["observations"][0]["annotations"][0]["tactic_id"] = "TA0010"
    path = tmp_path / "s.json"
    path.write_text(json.dumps(bad_tactic))
    with pytest.raises(ConfigurationError, match="not a tactic"):
        validate_scenario(load_scenario(path)[0], static_catalog())
    other_version = sc.model_copy(update={"attack_version": "18.0"})
    with pytest.raises(ConfigurationError, match="versions differ"):
        validate_scenario(other_version, static_catalog())
    (tmp_path / "broken.json").write_text("{}")
    with pytest.raises(ConfigurationError):
        load_scenario(tmp_path / "broken.json")
    config = load_integration_config(INTEGRATION_CONFIG)
    assert config.prediction.primary_model == "HYBRID" and config.prediction.beam_width == 10
    assert config.risk.thresholds == RiskThresholds() and config.risk.weights == RiskWeights()
    assert config.evidence.corroboration_min_confidence == 0.7
    (tmp_path / "bad.yaml").write_text("attack_version: 19.2\n")
    with pytest.raises(ConfigurationError):
        load_integration_config(tmp_path / "bad.yaml")


def test_integration_tracking(tmp_path: Path) -> None:
    sc = scenario()
    observations = scenario_observations()
    pipeline = make_pipeline()
    out = pipeline.run(observations, RESOURCES, as_of=sc.as_of)
    run = IntegrationRun(
        output=out,
        trajectory=pipeline.risk_trajectory(observations, RESOURCES),
        checks=integration_checks(out, sc, observations, pipeline, RESOURCES),
        stored_check=stored_output_policy_check("m6", [0.9], [0.1], 0.5, EvidencePolicy()),
        config={"unit": True},
    )
    now = utc_now()
    prov = IntegrationProvenance(
        run_id=make_integration_run_id(now), created_at=now, git_commit=None, git_dirty=None,
        environment=environment_info(), runtime_s=1.0,
        versions={"attack_version": "19.2", "risk_policy": "risk-policy-v1"},
        scenario_reference=sc.reference, scenario_sha256="0" * 64,
    )  # fmt: skip
    run_dir = write_integration_run(tmp_path, run, prov)
    assert sorted(p.name for p in run_dir.iterdir()) == sorted(RUN_FILES)
    summary = (run_dir / "summary.md").read_text()
    assert (
        "SYNTHETIC" in summary
        and "requires human approval" in summary
        and "MODEL-DERIVED" in summary
    )
    results = json.loads((run_dir / "results.json").read_text())
    assert results["stored_output_policy_check"]["rows"] == 1
    record = integration_record(run, prov, run_dir)
    assert record.task.value == "end_to_end" and record.data_origin.value == "SYNTHETIC"
    assert record.metrics["checks_passed"] == record.metrics["checks_total"] == 13.0
    with SQLiteStore(":memory:") as store:
        assert store_integration_record(store, record) == record
    no_stored = IntegrationRun(out, run.trajectory, run.checks, None, {})
    assert "stored_m6.rows" not in integration_record(no_stored, prov, run_dir).metrics
