"""Run tracking for the Milestone 7 integration demo (project run-folder + SQLite conventions).

``reports/runs/<run-id>/``: config.json, results.json, summary.md. Recorded numbers are
integration-check outcomes and pipeline OUTPUTS on a SYNTHETIC scenario, never security
performance metrics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from hqc.common.schemas.base import DataOrigin, utc_now
from hqc.common.schemas.evaluation import (
    EnvironmentInfo,
    EvaluationResult,
    EvaluationStatus,
    EvaluationTask,
)
from hqc.pipeline.checks import CheckResult, StoredOutputPolicyCheck
from hqc.pipeline.intelligence import PipelineOutput, RiskPoint
from hqc.storage import Collection, Store

RUN_FILES = ("config.json", "results.json", "summary.md")
SYNTHETIC_NOTICE = (
    "SYNTHETIC scenario: events, detector scores and ATT&CK annotations are hand-authored for "
    "integration testing. Outputs demonstrate the pipeline, not real-world performance."
)


@dataclass(frozen=True)
class IntegrationProvenance:
    run_id: str
    created_at: datetime
    git_commit: str | None
    git_dirty: bool | None
    environment: EnvironmentInfo
    runtime_s: float
    versions: dict[str, str]
    scenario_reference: str
    scenario_sha256: str


@dataclass
class IntegrationRun:
    output: PipelineOutput
    trajectory: list[RiskPoint]
    checks: list[CheckResult]
    stored_check: StoredOutputPolicyCheck | None
    config: dict[str, Any]


def make_integration_run_id(now: datetime | None = None) -> str:
    return f"{(now or utc_now()).strftime('%Y%m%dT%H%M%SZ')}-integration-synthetic-multistage"


def _dump(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def summary_markdown(run: IntegrationRun, prov: IntegrationProvenance) -> str:
    lines = [
        f"# Run {prov.run_id}",
        "",
        f"**{SYNTHETIC_NOTICE}**",
        "",
        f"Scenario `{prov.scenario_reference}` (sha256 `{prov.scenario_sha256[:12]}`), as of "
        f"{run.output.as_of.isoformat()}.",
        "",
        "## Versions",
        *[f"- {k}: `{v}`" for k, v in sorted(prov.versions.items())],
        "",
        "## Integration checks",
        "| check | passed | detail |",
        "|---|---|---|",
        *[f"| {c.name} | {'yes' if c.passed else '**NO**'} | {c.detail} |" for c in run.checks],
        "",
        f"Unmapped events (no technique evidence, no step): {run.output.unmapped_event_ids}",
    ]
    for a in run.output.incidents:
        risk = a.risk
        lines += [
            "",
            f"## {a.chain.chain_id} ({a.chain.status.value})",
            f"- OBSERVED: {' -> '.join(a.chain.observed_technique_ids)}; resources "
            f"{a.chain.resources}; correlation {[d.rule for d in a.chain.decisions]}",
            f"- PREDICTED next (NEXT-STEP PROBABILITY, {a.prediction.result.model_id}): "
            + ", ".join(
                f"{n.technique_id} {n.probability:.4f}" for n in a.prediction.result.next_step
            ),
            "- PATH SCORES (beam width "
            f"{a.prediction.beam_width}, horizon {a.prediction.result.horizon}; not calibrated): "
            + "; ".join(
                f"{' -> '.join(p.technique_ids)} {p.probability:.2e}"
                for p in a.prediction.result.paths[:3]
            ),
            f"- {risk.label}: **{risk.score:.2f} ({risk.level.value})**; evidence status "
            f"{risk.evidence_status}; quantum disagreement {risk.quantum_disagreement}; "
            f"uncertainty {risk.uncertainty}",
            "",
            "| component | value | weight | points | reason |",
            "|---|---|---|---|---|",
            *[
                f"| {c.name} | {c.value:.4f} | {c.weight:g} | {c.contribution:.2f} | {c.reason} |"
                for c in risk.components
            ],
            "",
            "Recommendations (RECOMMENDATION ONLY; each requires human approval):",
            *[
                f"- [{r.priority:.1f}] {r.action.value} -> {r.target} (disruption "
                f"{r.disruption.value}, confidence {r.confidence:.2f}, approval required: "
                f"{r.requires_human_approval}, status {r.status.value})"
                for r in a.recommendations
            ],
        ]
    lines += ["", "## Risk trajectory (each point uses only events seen so far)"]
    lines += [
        f"- after {p.after_event_id}: {p.chain_id} {p.score:.2f} {p.level} "
        f"({' -> '.join(p.observed_technique_ids)})"
        for p in run.trajectory
    ]
    if run.stored_check is not None:
        s = run.stored_check
        lines += [
            "",
            "## Disagreement policy on stored Milestone 6 outputs (REAL data; policy behaviour)",
            f"- run `{s.source_run_id}`: {s.rows} band rows with a quantum opinion; "
            f"{s.disagreements} disagreements -> {s.needs_additional_evidence} NEEDS ADDITIONAL "
            f"EVIDENCE; {s.consistent} CONSISTENT. {s.note}",
        ]
    lines += [
        "",
        "## Provenance",
        f"- git commit `{prov.git_commit}`; working tree dirty: **{prov.git_dirty}**; runtime "
        f"{prov.runtime_s:.1f} s.",
        "- CIC-IDS2017 labels are NOT ATT&CK techniques; no such mapping is used.",
    ]
    return "\n".join(lines) + "\n"


def write_integration_run(
    reports_dir: Path, run: IntegrationRun, prov: IntegrationProvenance
) -> Path:
    run_dir = reports_dir / "runs" / prov.run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    _dump(
        run_dir / "config.json",
        {
            "run_id": prov.run_id,
            "created_at": prov.created_at.isoformat(),
            "task": "Milestone 7 synthetic end-to-end integration",
            "notice": SYNTHETIC_NOTICE,
            "config": run.config,
            "versions": prov.versions,
            "scenario": {"reference": prov.scenario_reference, "sha256": prov.scenario_sha256},
            "environment": {
                "python_version": prov.environment.python_version,
                "platform": prov.environment.platform,
                "packages": prov.environment.packages,
            },
            "git_commit": prov.git_commit,
            "working_tree_dirty": prov.git_dirty,
        },
    )
    _dump(
        run_dir / "results.json",
        {
            "notice": SYNTHETIC_NOTICE,
            "output": run.output.model_dump(mode="json"),
            "risk_trajectory": [p.model_dump(mode="json") for p in run.trajectory],
            "integration_checks": [c.model_dump(mode="json") for c in run.checks],
            "stored_output_policy_check": run.stored_check.model_dump(mode="json")
            if run.stored_check
            else None,
        },
    )
    (run_dir / "summary.md").write_text(summary_markdown(run, prov), encoding="utf-8")
    return run_dir


def integration_record(
    run: IntegrationRun, prov: IntegrationProvenance, run_dir: Path
) -> EvaluationResult:
    metrics: dict[str, float] = {
        "checks_total": float(len(run.checks)),
        "checks_passed": float(sum(c.passed for c in run.checks)),
    }
    for a in run.output.incidents:
        metrics[f"output.{a.chain.chain_id}.risk_score"] = a.risk.score
        metrics[f"output.{a.chain.chain_id}.recommendations"] = float(len(a.recommendations))
    if run.stored_check is not None:
        s = run.stored_check
        metrics["stored_m6.rows"] = float(s.rows)
        metrics["stored_m6.disagreements"] = float(s.disagreements)
        metrics["stored_m6.needs_additional_evidence"] = float(s.needs_additional_evidence)
    return EvaluationResult(
        run_id=prov.run_id,
        task=EvaluationTask.END_TO_END,
        status=EvaluationStatus.EVALUATED,
        created_at=prov.created_at,
        git_commit=prov.git_commit,
        git_dirty=prov.git_dirty,
        dataset_id="synthetic-multistage",
        dataset_version=f"{prov.scenario_reference}-{prov.scenario_sha256[:12]}",
        data_origin=DataOrigin.SYNTHETIC,
        attack_version=prov.versions.get("attack_version"),
        seed=0,
        preprocessing_config={},
        model_configuration={"versions": dict(prov.versions), "run_dir": str(run_dir)},
        metrics=metrics,
        runtime_s=prov.runtime_s,
        environment=prov.environment,
        notes=SYNTHETIC_NOTICE + " Metrics are check counts and pipeline outputs.",
    )


def store_integration_record(store: Store, record: EvaluationResult) -> EvaluationResult:
    store.put(Collection.EVALUATION_RUNS, record)
    restored = store.get(Collection.EVALUATION_RUNS, record.run_id)
    if not isinstance(restored, EvaluationResult) or restored != record:
        raise RuntimeError("Stored evaluation record did not round-trip exactly")
    return restored
