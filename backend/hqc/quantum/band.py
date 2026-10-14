"""Uncertainty band of the classical detector, derived ONLY from training out-of-fold scores.

Out-of-fold probabilities: for each training day, the Milestone 5 primary configuration
(``random_forest``, same feature-policy and preprocessing procedure) is refitted on the OTHER
training days and scores the held-out day. Test days are never used.

Band: ``|p - threshold| <= h`` where ``h`` is the ``coverage``-quantile of the out-of-fold
margins ``|p_oof - threshold|`` (the ``ceil(coverage * n)``-th smallest margin). It is a
fixed probability interval ``[threshold - h, threshold + h]``; the coverage it achieves on
the test days is a measured outcome, never a tuning target.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import numpy as np
import pandas as pd
from pydantic import Field
from sklearn.metrics import roc_auc_score

from hqc.common.schemas.base import HQCModel
from hqc.detection.models import ModelConfig, train_detector
from hqc.detection.preprocessing import Preprocessor, build_feature_policy

BAND_SOURCE = "training out-of-fold probabilities (leave-one-training-day-out)"


class UncertaintyBand(HQCModel):
    name: str
    target_coverage: float = Field(gt=0.0, lt=1.0)
    threshold: float = Field(gt=0.0, lt=1.0)
    half_width: float = Field(ge=0.0)
    lower: float = Field(ge=0.0, le=1.0)
    upper: float = Field(ge=0.0, le=1.0)
    train_oof_rows: int = Field(ge=1)
    train_oof_coverage: float = Field(ge=0.0, le=1.0)
    derived_from: str = BAND_SOURCE

    def contains(self, p: np.ndarray) -> np.ndarray:
        mask: np.ndarray = (p >= self.lower) & (p <= self.upper)
        return mask


def derive_band(p_oof: np.ndarray, coverage: float, threshold: float, name: str) -> UncertaintyBand:
    p = np.asarray(p_oof, dtype=np.float64)
    if p.ndim != 1 or not len(p) or np.any(~np.isfinite(p)):
        raise ValueError("Out-of-fold probabilities must be a non-empty finite 1-D array")
    if not 0.0 < coverage < 1.0:
        raise ValueError("coverage must be in (0, 1)")
    margins = np.sort(np.abs(p - threshold))
    k = max(1, math.ceil(coverage * len(p)))
    half_width = float(margins[k - 1])
    lower, upper = max(0.0, threshold - half_width), min(1.0, threshold + half_width)
    band = UncertaintyBand(
        name=name,
        target_coverage=coverage,
        threshold=threshold,
        half_width=half_width,
        lower=lower,
        upper=upper,
        train_oof_rows=len(p),
        train_oof_coverage=0.0,
    )
    achieved = float(band.contains(p).mean())
    return band.model_copy(update={"train_oof_coverage": achieved})


class OOFFold(HQCModel):
    held_out_day: str
    training_days: list[str]
    training_rows: int
    held_out_rows: int
    feature_version: str
    preprocessing_version: str
    model_version: str
    held_out_roc_auc: float | None
    seconds: float


@dataclass
class OutOfFold:
    p: np.ndarray
    folds: list[OOFFold]


def out_of_fold_probabilities(
    train: pd.DataFrame,
    model_config: ModelConfig,
    dataset_version: str,
    train_days: Sequence[str],
    progress: Callable[[str], None] | None = None,
) -> OutOfFold:
    """Leave-one-training-day-out P(MALICIOUS) for every training row."""
    p = np.full(len(train), np.nan)
    folds: list[OOFFold] = []
    days = train["day"].to_numpy()
    for held_out in train_days:
        mask = days == held_out
        others = [d for d in train_days if d != held_out]
        fit_rows = train.loc[~mask]
        started = time.perf_counter()
        policy = build_feature_policy(fit_rows)
        preprocessor = Preprocessor(policy).fit(fit_rows)
        detector = train_detector(model_config, preprocessor, fit_rows, dataset_version, others)
        held = train.loc[mask]
        p_held = detector.predict_proba(held)
        p[mask] = p_held
        y_held = held["is_malicious"].to_numpy(dtype=np.int64)
        auc = float(roc_auc_score(y_held, p_held)) if len(np.unique(y_held)) == 2 else None
        folds.append(
            OOFFold(
                held_out_day=held_out,
                training_days=others,
                training_rows=len(fit_rows),
                held_out_rows=int(mask.sum()),
                feature_version=policy.version,
                preprocessing_version=preprocessor.version,
                model_version=detector.metadata.model_version,
                held_out_roc_auc=auc,
                seconds=time.perf_counter() - started,
            )
        )
        if progress:
            progress(f"oof fold {held_out}: {folds[-1].seconds:.1f}s, AUC {auc}")
    if np.any(np.isnan(p)):
        raise ValueError("Some training rows were not scored out-of-fold (day not in train_days)")
    return OutOfFold(p=p, folds=folds)
