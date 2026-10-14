"""Milestone 7: SYNTHETIC end-to-end integration demo (events -> ... -> recommendations).

Usage:
    python evaluation/run_integration_demo.py

Loads the ATT&CK 19.2 KB, the committed vocabulary and the stored Milestone 3/4 prediction
artifacts (nothing is retrained), runs the synthetic scenario through the pipeline, runs the
integration checks, applies the disagreement policy to the stored Milestone 6 band outputs,
and writes reports/runs/<run-id>/ plus an END_TO_END record in SQLite. Nothing is executed:
every defense output is a recommendation requiring human approval.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from hqc.common.logging import configure_logging
from hqc.common.repro import environment_info, git_commit, git_working_tree_dirty
from hqc.common.schemas.base import utc_now
from hqc.config import PROJECT_ROOT, get_settings
from hqc.detection.models import DetectorMetadata
from hqc.pipeline.checks import integration_checks, stored_output_policy_check
from hqc.pipeline.config import build_pipeline, load_integration_config
from hqc.pipeline.scenario import build_observations, load_scenario, validate_scenario
from hqc.pipeline.tracking import (
    IntegrationProvenance,
    IntegrationRun,
    integration_record,
    make_integration_run_id,
    store_integration_record,
    write_integration_run,
)
from hqc.quantum.adjudicator import AdjudicatorFile
from hqc.storage import SQLiteStore

DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "integration.yaml"


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    configure_logging(settings.log_level, json_output=False)
    started = time.perf_counter()
    created_at = utc_now()
    run_id = make_integration_run_id(created_at)
    config = load_integration_config(args.config)
    built = build_pipeline(config, settings, PROJECT_ROOT)
    scenario, scenario_sha = load_scenario(PROJECT_ROOT / config.scenario)
    validate_scenario(scenario, built.catalog)
    observations = build_observations(scenario, built.catalog, config.evidence)
    resources = {r.resource_id: r for r in scenario.resources}

    output = built.pipeline.run(observations, resources, as_of=scenario.as_of)
    trajectory = built.pipeline.risk_trajectory(observations, resources)
    checks = integration_checks(output, scenario, observations, built.pipeline, resources)

    # Stored Milestone 5/6 outputs (read-only): versions + disagreement-policy behaviour.
    models = settings.resolve(settings.models_dir) / "generated"
    reports = settings.resolve(settings.reports_dir)
    detector = DetectorMetadata.model_validate_json(
        (models / "detection" / config.classical_run_id / "full" / "random_forest.json").read_text()
    )
    adjudicator = AdjudicatorFile.model_validate_json(
        (
            models / "quantum" / config.quantum_run_id / "primary" / "zz_qsvm" / "adjudicator.json"
        ).read_text()
    )
    columns = json.loads(
        (reports / "runs" / config.quantum_run_id / "predictions.json").read_text()
    )["columns"]
    stored = stored_output_policy_check(
        config.quantum_run_id,
        columns["p_classical"],
        columns["primary.zz_qsvm.p_second"],
        detector.threshold,
        config.evidence,
    )
    versions = {
        "attack_version": built.catalog.attack_version,
        "vocabulary": built.vocabulary.vocabulary_version,
        **{f"prediction:{k}": v for k, v in built.pipeline.prediction.model_versions.items()},
        "classical_detector": f"{detector.model_version} (run {config.classical_run_id})",
        "quantum_model": f"{adjudicator.metadata.model_version} (run {config.quantum_run_id})",
        "evidence_policy": config.evidence.version,
        "correlation_policy": config.correlation.version,
        "risk_policy": config.risk.version,
        "defense_policy": config.defense.version,
        "scenario": f"{scenario.reference} sha256:{scenario_sha[:12]}",
    }
    run = IntegrationRun(
        output=output,
        trajectory=trajectory,
        checks=checks,
        stored_check=stored,
        config=config.model_dump(mode="json"),
    )
    prov = IntegrationProvenance(
        run_id=run_id,
        created_at=created_at,
        git_commit=git_commit(PROJECT_ROOT),
        git_dirty=git_working_tree_dirty(PROJECT_ROOT),
        environment=environment_info(),
        runtime_s=time.perf_counter() - started,
        versions=versions,
        scenario_reference=scenario.reference,
        scenario_sha256=scenario_sha,
    )
    run_dir = write_integration_run(reports, run, prov)
    with SQLiteStore(settings.resolve(settings.db_path)) as store:
        store_integration_record(store, integration_record(run, prov, run_dir))
    failed = [c.name for c in checks if not c.passed]
    print(f"checks passed {len(checks) - len(failed)}/{len(checks)}; failed: {failed}")
    print(f"run {run_id} -> {run_dir.relative_to(PROJECT_ROOT)} ({prov.runtime_s:.1f} s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
