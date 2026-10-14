"""Hyperparameter selection by leave-one-TRAINING-day-out cross-validation.

The angle features are refitted inside every fold on the fold's training rows. Candidates are
scored by the balanced accuracy of the POOLED out-of-fold predictions (scale-free across
folds); ties go to the earliest candidate in the fixed grid order. A fold whose training
rows contain a single class is skipped and recorded. No test-day data is ever involved.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from hqc.detection.dataset import DAY_ORDER
from hqc.detection.schemas import FeaturePolicy
from hqc.quantum.features import AngleFeatures
from hqc.quantum.models import (
    KERNEL_KINDS,
    ForestSettings,
    Hyper,
    HyperGrid,
    ModelKind,
    TrainedModel,
    embed,
    gram,
    hyper_candidates,
)


@dataclass(frozen=True)
class Fold:
    held_out_day: str
    train_idx: np.ndarray
    val_idx: np.ndarray


def leave_one_day_out(days: np.ndarray) -> list[Fold]:
    present = [d for d in DAY_ORDER if d in set(days)]
    if len(present) < 2:
        raise ValueError("Grouped CV needs at least two training days")
    folds = []
    for d in present:
        val = np.flatnonzero(days == d)
        train = np.flatnonzero(days != d)
        if np.intersect1d(val, train).size:
            raise AssertionError("Fold overlap")  # pragma: no cover - defensive
        folds.append(Fold(d, train, val))
    return folds


def balanced_accuracy(y: np.ndarray, predicted: np.ndarray) -> float:
    """Mean per-class recall over the classes present in ``y`` (as scikit-learn)."""
    return float(np.mean([(predicted[y == c] == c).mean() for c in np.unique(y)]))


@dataclass
class CVOutcome:
    kind: ModelKind
    selected: Hyper
    cv_balanced_accuracy: float
    candidate_scores: list[tuple[Hyper, float]]
    oof_decision: np.ndarray  # selected candidate; NaN where a row was never validated
    skipped_folds: list[str] = field(default_factory=list)
    nonconverged_fits: int = 0  # solver hit its iteration cap (any candidate, any fold)


def grouped_cv_select(
    sample: pd.DataFrame,
    kinds: Sequence[ModelKind],
    grid: HyperGrid,
    policy: FeaturePolicy,
    n_dims: int,
    k_mutual_info: int,
    reps: int,
    seed: int,
    forest: ForestSettings | None = None,
) -> dict[ModelKind, CVOutcome]:
    y = sample["is_malicious"].to_numpy(dtype=np.int64)
    folds = leave_one_day_out(sample["day"].to_numpy())
    candidates = {k: hyper_candidates(k, grid) for k in kinds}
    oof = {k: np.full((len(candidates[k]), len(sample)), np.nan) for k in kinds}
    skipped: list[str] = []
    nonconverged = dict.fromkeys(kinds, 0)
    for fold in folds:
        y_tr = y[fold.train_idx]
        if len(np.unique(y_tr)) < 2:
            skipped.append(fold.held_out_day)
            continue
        tr_rows = sample.iloc[fold.train_idx]
        feats = AngleFeatures(policy, n_dims, k_mutual_info, seed).fit(tr_rows)
        a_tr = feats.transform(tr_rows)
        a_va = feats.transform(sample.iloc[fold.val_idx])
        for kind in kinds:
            cached_key: tuple[float | None, float | None] | None = None
            k_tr = k_va = np.empty((0, 0))
            for j, hyper in enumerate(candidates[kind]):
                if kind in KERNEL_KINDS:
                    key = (hyper.alpha, hyper.gamma)
                    if key != cached_key:  # candidates are grouped by alpha / gamma
                        e_tr = embed(kind, hyper, a_tr, reps)
                        e_va = embed(kind, hyper, a_va, reps)
                        k_tr, k_va = gram(kind, hyper, e_tr, e_tr), gram(kind, hyper, e_va, e_tr)
                        cached_key = key
                    model = TrainedModel(kind, hyper, reps, seed).fit_gram(k_tr, y_tr)
                    support = model.svc.support_ if model.svc is not None else np.array([])
                    decision = model.decision_from_gram(k_va[:, support])
                else:
                    model = TrainedModel(kind, hyper, reps, seed, forest).fit(a_tr, y_tr)
                    decision = model.decision(a_va)
                oof[kind][j, fold.val_idx] = decision
                nonconverged[kind] += not model.converged
    if len(skipped) == len(folds):
        raise ValueError("Every CV fold was skipped (single-class training folds)")
    outcomes: dict[ModelKind, CVOutcome] = {}
    for kind in kinds:
        validated = ~np.isnan(oof[kind][0])
        scores = [
            balanced_accuracy(y[validated], (row[validated] >= 0).astype(np.int64))
            for row in oof[kind]
        ]
        best = int(np.argmax(scores))  # first maximum = earliest candidate
        outcomes[kind] = CVOutcome(
            kind=kind,
            selected=candidates[kind][best],
            cv_balanced_accuracy=scores[best],
            candidate_scores=list(zip(candidates[kind], scores, strict=True)),
            oof_decision=oof[kind][best].copy(),
            skipped_folds=list(skipped),
            nonconverged_fits=nonconverged[kind],
        )
    return outcomes
