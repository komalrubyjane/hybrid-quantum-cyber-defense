"""Milestone 5: classical binary intrusion detection on CIC-IDS2017 (day-based holdout).

Usage:
    python scripts/register_cicids2017.py        # once, after placing the archive
    python evaluation/run_classical_detection.py

Writes reports/runs/<run-id>/, models under models/generated/detection/<run-id>/ and an
EvaluationResult in SQLite. Verifies extracted CSVs against the manifest first.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from hqc.common.errors import DatasetNotFoundError, MalformedSourceDataError
from hqc.common.logging import configure_logging
from hqc.common.provenance import load_manifest, sha256_file
from hqc.common.repro import (
    environment_info,
    git_commit,
    git_working_tree_dirty,
    package_versions,
    set_global_seed,
)
from hqc.common.schemas.base import utc_now
from hqc.config import PROJECT_ROOT, get_settings
from hqc.detection.dataset import load_cic_dataset
from hqc.detection.experiment import load_detection_config, run_detection_experiment
from hqc.detection.registration import CIC_EXTRACTED_ARTIFACT_ID, CIC_RAW_ARTIFACT_ID
from hqc.detection.tracking import (
    DetectionProvenance,
    detection_record,
    make_detection_run_id,
    store_detection_record,
    write_detection_run,
)
from hqc.mitre.paths import manifest_path
from hqc.storage import SQLiteStore

DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "classical_detection.yaml"


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    configure_logging(settings.log_level, json_output=False)
    config = load_detection_config(args.config)
    set_global_seed(config.seed)
    started = time.perf_counter()
    created_at = utc_now()
    run_id = make_detection_run_id(created_at)
    commit, dirty = git_commit(PROJECT_ROOT), git_working_tree_dirty(PROJECT_ROOT)

    manifest = load_manifest(manifest_path(settings))
    raw_entry = manifest.get(CIC_RAW_ARTIFACT_ID)
    csv_entry = manifest.get(CIC_EXTRACTED_ARTIFACT_ID)
    if raw_entry is None or csv_entry is None:
        raise DatasetNotFoundError("CIC-IDS2017 not registered; run scripts/register_cicids2017.py")
    dataset_dir = PROJECT_ROOT / config.dataset_dir
    for entry in csv_entry.files:
        if sha256_file(dataset_dir / entry.name) != entry.sha256:
            raise MalformedSourceDataError(f"Checksum mismatch for {entry.name}")
    dataset_version = f"cicids2017-gen-labelled-flows-zip-{(raw_entry.sha256 or '')[:12]}"

    dataset = load_cic_dataset(dataset_dir)
    print(f"loaded {dataset.stats.rows_total} rows from {len(dataset.stats.files)} files")
    extra = {
        "git_commit": commit,
        "git_dirty": dirty,
        "package_versions": package_versions(),
        "evaluation_run_id": run_id,
    }
    result = run_detection_experiment(
        dataset, config, dataset_version, progress=print, extra_metadata=extra
    )

    model_dir = settings.resolve(settings.models_dir) / "generated" / "detection" / run_id
    for fs in result.feature_sets:
        for detector in fs.detectors.values():
            detector.save(model_dir / fs.name)
    prov = DetectionProvenance(
        run_id=run_id,
        created_at=created_at,
        git_commit=commit,
        git_dirty=dirty,
        environment=environment_info(),
        runtime_s=time.perf_counter() - started,
        config_path=str(args.config.resolve().relative_to(PROJECT_ROOT)),
        manifest_entry=raw_entry,
        model_dir=str(model_dir.relative_to(PROJECT_ROOT)),
    )
    run_dir = write_detection_run(
        settings.resolve(settings.reports_dir), config, dataset, result, prov
    )
    with SQLiteStore(settings.resolve(settings.db_path)) as store:
        store_detection_record(store, detection_record(config, result, prov, run_dir))
    print(f"run {run_id} -> {run_dir.relative_to(PROJECT_ROOT)} ({prov.runtime_s:.1f} s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
