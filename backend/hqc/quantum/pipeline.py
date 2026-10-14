"""Milestone 6 orchestration: OOF probabilities -> bands -> E2 / E3 / E4 -> artifacts.

Inputs are the whole-day train / test frames, the (read-only) Milestone 5 primary detector
and its test probabilities. Nothing here re-trains or modifies the primary detector.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from hqc.detection.models import Detector, ModelConfig
from hqc.detection.preprocessing import DaySplit
from hqc.quantum.adjudicator import Adjudicator
from hqc.quantum.band import derive_band, out_of_fold_probabilities
from hqc.quantum.experiment import (
    PRIMARY_BAND,
    SECONDARY_BAND,
    Progress,
    QuantumExperimentConfig,
    run_e2,
    run_e3_band,
    run_e4,
)
from hqc.quantum.tracking import QuantumRunResult


def run_quantum_experiment(
    split: DaySplit,
    train: pd.DataFrame,
    test: pd.DataFrame,
    classical: Detector,
    p_test: np.ndarray,
    classical_config: ModelConfig,
    config: QuantumExperimentConfig,
    dataset_version: str,
    model_dir: Path | None = None,
    run_id: str | None = None,
    progress: Progress | None = None,
) -> QuantumRunResult:
    if set(train["day"]) & set(test["day"]):
        raise ValueError("Train and test frames share a day")
    if len(p_test) != len(test):
        raise ValueError("p_test must align with the test frame")
    seconds: dict[str, float] = {}
    t0 = time.perf_counter()
    oof = out_of_fold_probabilities(
        train, classical_config, dataset_version, config.train_days, progress
    )
    seconds["out_of_fold"] = time.perf_counter() - t0
    u, t = config.uncertainty, config.threshold
    bands = {
        PRIMARY_BAND: derive_band(oof.p, u.primary_band_coverage, t, PRIMARY_BAND),
        SECONDARY_BAND: derive_band(oof.p, u.secondary_band_coverage, t, SECONDARY_BAND),
    }
    policy = classical.preprocessor.policy
    t0 = time.perf_counter()
    e2 = run_e2(train, test, policy, config, progress)
    seconds["e2"] = time.perf_counter() - t0
    e3 = {}
    for name, band in bands.items():
        if progress:
            progress(
                f"E3 {name}: band [{band.lower:.4f}, {band.upper:.4f}] (train OOF coverage "
                f"{band.train_oof_coverage:.4f}); test rows in band "
                f"{int(band.contains(p_test).sum())}, train rows in band "
                f"{int(band.contains(oof.p).sum())}"
            )
        t0 = time.perf_counter()
        e3[name] = run_e3_band(
            train, test, oof.p, p_test, band, policy, config, classical, dataset_version, run_id
        )
        seconds[f"e3.{name}"] = time.perf_counter() - t0
        if progress:
            progress(f"E3 {name}: {e3[name].result.test_band_rows} test rows in band")
    t0 = time.perf_counter()
    e4 = run_e4(train, test, policy, config, progress)
    seconds["e4"] = time.perf_counter() - t0

    reload_check: dict[str, Any] = {"performed": False}
    if model_dir is not None:
        for name, run in e3.items():
            for kind, adj in run.adjudicators.items():
                adj.save(model_dir / name / kind)
        primary = e3[PRIMARY_BAND]
        mask = primary.test_band_mask
        reloaded = Adjudicator.load(model_dir / PRIMARY_BAND / "zz_qsvm")
        again = reloaded.run(test.loc[mask], p_test[mask]).decision
        stored = primary.outputs["zz_qsvm.decision"]
        diff = float(np.max(np.abs(again - stored))) if len(stored) else 0.0
        reload_check = {
            "performed": True,
            "artifact": f"{PRIMARY_BAND}/zz_qsvm",
            "rows": int(mask.sum()),
            "max_abs_decision_difference": diff,
            "identical": diff == 0.0,
        }
    return QuantumRunResult(
        split=split,
        oof_folds=oof.folds,
        bands=bands,
        e2=e2,
        e3=e3,
        e4=e4,
        reload_check=reload_check,
        seconds=seconds,
    )
