"""Binary detection metrics on the held-out test days (fixed threshold, no test tuning).

- precision / recall / F1 for the MALICIOUS class; accuracy;
- ROC-AUC and PR-AUC (average precision), threshold-free; None if only one class present;
- benign false-positive rate = FP / (FP + TN); malicious detection rate = TP / (TP + FN);
- per raw label: fraction predicted MALICIOUS (attack recall; for BENIGN, the FPR);
- per test day.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score

from hqc.detection.schemas import BinaryMetrics, ConfusionCounts, EvaluationBlock


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def binary_metrics(y_true: np.ndarray, p_malicious: np.ndarray, threshold: float) -> BinaryMetrics:
    if y_true.shape != p_malicious.shape or y_true.ndim != 1:
        raise ValueError("y_true and p_malicious must be 1-D arrays of equal length")
    if np.any((p_malicious < 0) | (p_malicious > 1)) or np.any(~np.isfinite(p_malicious)):
        raise ValueError("Probabilities must be finite and in [0, 1]")
    y_pred = (p_malicious >= threshold).astype(np.int64)
    tn, fp, fn, tp = (int(v) for v in confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel())
    both_classes = len(np.unique(y_true)) == 2
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    return BinaryMetrics(
        n=len(y_true),
        n_malicious=int(y_true.sum()),
        accuracy=_safe_div(tp + tn, len(y_true)),
        precision=precision,
        recall=recall,
        f1=_safe_div(2 * precision * recall, precision + recall),
        roc_auc=float(roc_auc_score(y_true, p_malicious)) if both_classes else None,
        pr_auc=float(average_precision_score(y_true, p_malicious)) if both_classes else None,
        benign_false_positive_rate=_safe_div(fp, fp + tn) if (fp + tn) else None,
        malicious_detection_rate=recall if (tp + fn) else None,
        confusion=ConfusionCounts(
            true_negative=tn, false_positive=fp, false_negative=fn, true_positive=tp
        ),
        threshold=threshold,
    )


def evaluate_block(
    test: pd.DataFrame,
    p_malicious: np.ndarray,
    *,
    model: str,
    feature_set: str,
    subset: str,
    dataset_version: str,
    feature_version: str,
    threshold: float,
) -> EvaluationBlock:
    y = test["is_malicious"].to_numpy(dtype=np.int64)
    predicted = p_malicious >= threshold
    per_label: dict[str, dict[str, float]] = {}
    for label, idx in test.groupby("label", sort=True).indices.items():
        per_label[str(label)] = {
            "n": float(len(idx)),
            "predicted_malicious_rate": float(predicted[idx].mean()),
        }
    per_day = {
        str(day): binary_metrics(y[idx], p_malicious[idx], threshold)
        for day, idx in test.groupby("day", sort=True).indices.items()
    }
    return EvaluationBlock(
        model=model,
        feature_set=feature_set,
        subset=subset,
        split="test (held-out days)",
        dataset_version=dataset_version,
        feature_version=feature_version,
        metrics=binary_metrics(y, p_malicious, threshold),
        per_label_detection=per_label,
        per_day=per_day,
    )
