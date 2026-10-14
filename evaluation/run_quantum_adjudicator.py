"""Milestone 6: quantum-kernel second opinion on CIC-IDS2017 (exact local simulation).

Usage:
    python evaluation/run_quantum_adjudicator.py

Reads (never modifies) the Milestone 5 run and primary detector named in the config, verifies
the CSV checksums and that the reloaded primary detector reproduces the stored Milestone 5 test
predictions, then runs the out-of-fold band derivation and experiments E2-E4. Writes
reports/runs/<run-id>/, adjudicators under models/generated/quantum/<run-id>/ and an
EvaluationResult in SQLite. No quantum advantage is claimed.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np

from hqc.common.errors import (
    ConfigurationError,
    DatasetNotFoundError,
    MalformedSourceDataError,
    ModelCheckpointNotFoundError,
)
from hqc.common.logging import configure_logging
from hqc.common.provenance import load_manifest, sha256_file
from hqc.common.repro import environment_info, git_commit, git_working_tree_dirty, set_global_seed
from hqc.common.schemas.base import utc_now
from hqc.config import PROJECT_ROOT, get_settings
from hqc.detection.dataset import load_cic_dataset
from hqc.detection.experiment import DetectionConfig
from hqc.detection.models import Detector
from hqc.detection.preprocessing import day_split, split_masks
from hqc.detection.registration import CIC_EXTRACTED_ARTIFACT_ID, CIC_RAW_ARTIFACT_ID
from hqc.mitre.paths import manifest_path
from hqc.quantum.experiment import load_quantum_config
from hqc.quantum.pipeline import run_quantum_experiment
from hqc.quantum.tracking import (
    QuantumProvenance,
    make_quantum_run_id,
    quantum_record,
    store_quantum_record,
    write_quantum_run,
)
from hqc.storage import SQLiteStore

DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "quantum_adjudicator.yaml"
PREDICTION_TOLERANCE = 1e-6  # Milestone 5 stores probabilities rounded to 6 decimals


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    configure_logging(settings.log_level, json_output=False)
    config = load_quantum_config(args.config)
    set_global_seed(config.seed)
    started = time.perf_counter()
    created_at = utc_now()
    run_id = make_quantum_run_id(created_at)
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

    # --- Milestone 5 reference (read-only) ------------------------------------------------
    reports = settings.resolve(settings.reports_dir)
    classical_run = reports / "runs" / config.classical_run_id
    m5_config = json.loads((classical_run / "config.json").read_text())
    detection_config = DetectionConfig.model_validate(m5_config["config"])
    if detection_config.threshold != config.threshold:
        raise ConfigurationError("Threshold differs from the Milestone 5 run")
    if (detection_config.train_days, detection_config.test_days) != (
        config.train_days,
        config.test_days,
    ):
        raise ConfigurationError("Day split differs from the Milestone 5 run")
    if m5_config["dataset_version"] != dataset_version:
        raise ConfigurationError("Dataset version differs from the Milestone 5 run")
    classical_model_config = next(
        m for m in detection_config.models if m.name == config.primary_detector
    )
    detector_dir = (
        settings.resolve(settings.models_dir)
        / "generated"
        / "detection"
        / config.classical_run_id
        / config.classical_feature_set
    )
    classical = Detector.load(detector_dir, config.primary_detector)
    meta = classical.metadata
    if not meta.primary_detector or meta.evaluation_run_id != config.classical_run_id:
        raise ModelCheckpointNotFoundError("Loaded detector is not the Milestone 5 primary")

    dataset = load_cic_dataset(dataset_dir)
    frame = dataset.frame
    split = day_split(frame, config.train_days, config.test_days)
    train_mask, test_mask = split_masks(frame, split)
    train = frame.loc[train_mask].reset_index(drop=True)
    test = frame.loc[test_mask].reset_index(drop=True)
    print(f"loaded {len(frame)} rows; train {len(train)}, test {len(test)}", flush=True)

    p_test = classical.predict_proba(test)
    stored = json.loads((classical_run / "predictions.json").read_text())["columns"]
    same_rows = (
        stored["source_file"] == test["source_file"].tolist()
        and stored["row_number"] == test["row_number"].astype(int).tolist()
    )
    stored_p = np.asarray(stored[f"p_malicious_{config.primary_detector}"], dtype=np.float64)
    max_diff = float(np.max(np.abs(stored_p - p_test)))
    if not same_rows or max_diff > PREDICTION_TOLERANCE:
        raise ModelCheckpointNotFoundError(
            f"Primary detector does not reproduce Milestone 5 predictions (max diff {max_diff})"
        )
    del stored
    print(f"primary detector reproduces Milestone 5 predictions (max diff {max_diff:.2e})")

    model_dir = settings.resolve(settings.models_dir) / "generated" / "quantum" / run_id
    result = run_quantum_experiment(
        split,
        train,
        test,
        classical,
        p_test,
        classical_model_config,
        config,
        dataset_version,
        model_dir=model_dir,
        run_id=run_id,
        progress=lambda msg: print(msg, flush=True),
    )
    prov = QuantumProvenance(
        run_id=run_id,
        created_at=created_at,
        git_commit=commit,
        git_dirty=dirty,
        environment=environment_info(),
        runtime_s=time.perf_counter() - started,
        config_path=str(args.config.resolve().relative_to(PROJECT_ROOT)),
        manifest_entry=raw_entry,
        dataset_version=dataset_version,
        file_sha256={f.file_name: f.sha256 for f in dataset.stats.files},
        classical={
            "run_id": config.classical_run_id,
            "detector": config.primary_detector,
            "model_version": meta.model_version,
            "preprocessing_version": meta.preprocessing_version,
            "feature_version": meta.feature_version,
            "model_dir": str(detector_dir.relative_to(PROJECT_ROOT)),
            "reproduces_stored_predictions": True,
            "max_abs_difference_vs_stored": max_diff,
            "read_only": True,
        },
        model_dir=str(model_dir.relative_to(PROJECT_ROOT)),
    )
    run_dir = write_quantum_run(reports, config, result, prov, test, p_test, classical)
    with SQLiteStore(settings.resolve(settings.db_path)) as store:
        store_quantum_record(store, quantum_record(config, result, prov, run_dir))
    print(f"run {run_id} -> {run_dir.relative_to(PROJECT_ROOT)} ({prov.runtime_s:.1f} s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
