"""Integration correctness checks for Milestone 7 (correctness of the plumbing, NOT security
performance: no detection, prediction or risk accuracy is claimed from a synthetic scenario).

Also: the disagreement-policy check on STORED Milestone 6 outputs (real CIC-IDS2017 band
rows), which measures how the evidence-status rule behaves, not how good it is.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from hqc.attack_chain.evidence import EvidencePolicy, evidence_status
from hqc.common.schemas.base import HQCModel, StepProvenance, Verdict
from hqc.common.schemas.detection import QuantumOpinion, confidence_from_probability
from hqc.common.schemas.intelligence import (
    DetectionEvidence,
    EvidenceStatus,
    IncidentChain,
    Observation,
    ResourceContext,
)
from hqc.common.schemas.risk import RISK_LABEL
from hqc.defense.recommender import WITHHELD_WHEN_EVIDENCE_NEEDED
from hqc.pipeline.intelligence import IntelligencePipeline, PipelineOutput
from hqc.pipeline.scenario import SyntheticScenario
from hqc.prediction.vocabulary import UNK_TOKEN


class CheckResult(HQCModel):
    name: str
    passed: bool
    detail: str


def _check(name: str, passed: bool, detail: str) -> CheckResult:
    return CheckResult(name=name, passed=bool(passed), detail=detail)


def _without_quantum(incident: IncidentChain, flip: bool) -> IncidentChain:
    """Same chain with the quantum opinion removed (flip=False) or inverted (flip=True)."""
    detections: list[DetectionEvidence] = []
    for d in incident.detections:
        if flip and d.quantum is not None and d.quantum.p_malicious is not None:
            q = 1.0 - d.quantum.p_malicious
            opinion: QuantumOpinion | None = QuantumOpinion(
                gate_triggered=True,
                verdict=Verdict.MALICIOUS if q >= d.threshold else Verdict.BENIGN,
                p_malicious=q,
                confidence=confidence_from_probability(q),
                backend=d.quantum.backend,
            )
            disagree = opinion is not None and opinion.verdict is not d.verdict
            status = (
                EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE if disagree else EvidenceStatus.CONSISTENT
            )
        else:
            opinion, disagree, status = None, False, EvidenceStatus.NO_SECOND_OPINION
        detections.append(
            d.model_copy(
                update={
                    "quantum": opinion,
                    "quantum_disagreement": disagree,
                    "evidence_status": status,
                }
            )
        )
    return incident.model_copy(update={"detections": detections})


def integration_checks(
    output: PipelineOutput,
    scenario: SyntheticScenario,
    observations: Sequence[Observation],
    pipeline: IntelligencePipeline,
    resources: Mapping[str, ResourceContext],
) -> list[CheckResult]:
    results: list[CheckResult] = []
    arrival = {o.event.event_id: i for i, o in enumerate(observations)}
    got = sorted(
        ([s.event_id or "" for s in a.chain.chain.steps], a.chain.status.value)
        for a in output.incidents
    )
    want = sorted((e.event_ids, e.status) for e in scenario.expected.chains)
    results.append(_check("chains_match_expected", got == want, f"got {got}"))
    results.append(
        _check(
            "unmapped_events_produce_no_step",
            output.unmapped_event_ids == scenario.expected.unmapped_event_ids,
            f"unmapped {output.unmapped_event_ids}",
        )
    )
    statuses = {
        o.event.event_id: o.detection.evidence_status.value for o in observations if o.detection
    }
    results.append(
        _check(
            "evidence_status_match_expected",
            statuses == scenario.expected.evidence_status,
            f"{statuses}",
        )
    )
    in_order = all(
        [arrival[s.event_id or ""] for s in a.chain.chain.steps]
        == sorted(arrival[s.event_id or ""] for s in a.chain.chain.steps)
        for a in output.incidents
    )
    results.append(_check("arrival_order_preserved", in_order, "steps follow arrival order"))
    separated = all(
        all(s.provenance is StepProvenance.OBSERVED for s in a.chain.chain.steps)
        and a.prediction.result.provenance == "PREDICTED"
        and a.prediction.provenance == "PREDICTED"
        for a in output.incidents
    )
    results.append(_check("observed_and_predicted_separated", separated, "chain=OBSERVED only"))

    pred_ok, pred_detail = True, []
    for a in output.incidents:
        r = a.prediction.result
        probs = [n.probability for n in r.next_step]
        ok = (
            probs == sorted(probs, reverse=True)
            and math.fsum(probs) <= 1.0 + 1e-9
            and all(n.technique_id != UNK_TOKEN for n in r.next_step)
            and all(p.length == r.horizon for p in r.paths)
            and all(
                math.isclose(p.probability, math.exp(p.cumulative_log_score), rel_tol=1e-9)
                for p in r.paths
            )
            and a.prediction.context_tokens
            == [
                t if t in pipeline.prediction.vocabulary else UNK_TOKEN
                for t in a.chain.observed_technique_ids
            ]
        )
        pred_ok &= ok
        pred_detail.append(f"{a.chain.chain_id}: top-{len(probs)} sum {math.fsum(probs):.4f}")
    results.append(_check("prediction_outputs_valid", pred_ok, "; ".join(pred_detail)))

    risk_ok, label_ok, quantum_ok = True, True, True
    for a in output.incidents:
        risk = a.risk
        recomputed = math.fsum(c.weight * c.value for c in risk.components)
        risk_ok &= math.isclose(recomputed, risk.score, abs_tol=1e-3)
        risk_ok &= risk.level is pipeline.risk.policy.thresholds.level(risk.score)
        label_ok &= risk.label == RISK_LABEL
        for flip in (False, True):
            variant = _without_quantum(a.chain, flip)
            other = pipeline.risk.assess(
                variant, a.prediction, a.high_impact_next_step_probability, resources,
                as_of=output.as_of,
            )  # fmt: skip
            quantum_ok &= other.score == risk.score
    results.append(_check("risk_formula_recomputed", risk_ok, "score = sum(weight x value); level"))
    results.append(_check("risk_label_model_derived", label_ok, RISK_LABEL))
    results.append(
        _check(
            "quantum_never_changes_risk",
            quantum_ok,
            "score identical with quantum removed / inverted",
        )
    )
    verdict_ok = all(
        o.detection.verdict
        is (
            Verdict.MALICIOUS
            if o.detection.p_malicious >= o.detection.threshold
            else Verdict.BENIGN
        )
        for o in observations
        if o.detection
    )
    results.append(
        _check("classical_verdict_unchanged", verdict_ok, "verdict = classical p >= threshold")
    )

    approval_ok, withheld_ok, plan_ok = True, True, True
    for a in output.incidents:
        recs = a.recommendations
        approval_ok &= all(r.requires_human_approval and r.status.value == "PROPOSED" for r in recs)
        needs = a.risk.evidence_status == EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE.value
        if needs:
            withheld_ok &= not any(r.action in WITHHELD_WHEN_EVIDENCE_NEEDED for r in recs)
        planned = set(pipeline.defense.planned_actions(a.risk.level, needs))
        plan_ok &= {r.action for r in recs} <= planned
    results.append(_check("recommendations_require_human_approval", approval_ok, "all PROPOSED"))
    results.append(
        _check(
            "no_disruptive_action_on_unresolved_disagreement", withheld_ok, "isolate/block withheld"
        )
    )
    results.append(
        _check("recommendations_follow_policy", plan_ok, "actions within the policy plan")
    )
    return results


class StoredOutputPolicyCheck(HQCModel):
    source_run_id: str
    rows: int
    disagreements: int
    needs_additional_evidence: int
    consistent: int
    note: str


def stored_output_policy_check(
    run_id: str,
    p_classical: Sequence[float],
    p_quantum: Sequence[float | None],
    threshold: float,
    policy: EvidencePolicy,
) -> StoredOutputPolicyCheck:
    """Apply the evidence-status rule to stored Milestone 6 outputs (no technique evidence)."""
    counts = {s: 0 for s in EvidenceStatus}
    disagreements = rows = 0
    for pc, pq in zip(p_classical, p_quantum, strict=True):
        if pq is None:
            continue
        rows += 1
        opinion = QuantumOpinion(
            gate_triggered=True,
            verdict=Verdict.MALICIOUS if pq >= threshold else Verdict.BENIGN,
            p_malicious=pq,
            confidence=confidence_from_probability(pq),
        )
        malicious = pc >= threshold
        disagree, status = evidence_status(opinion, malicious, [], policy)
        disagreements += disagree
        counts[status] += 1
    return StoredOutputPolicyCheck(
        source_run_id=run_id,
        rows=rows,
        disagreements=disagreements,
        needs_additional_evidence=counts[EvidenceStatus.NEEDS_ADDITIONAL_EVIDENCE],
        consistent=counts[EvidenceStatus.CONSISTENT],
        note="Policy behaviour on real stored M5/M6 band outputs; no technique evidence exists "
        "for CIC flows (CIC labels are not ATT&CK techniques), so no disagreement can be "
        "corroborated. Not a performance metric.",
    )
