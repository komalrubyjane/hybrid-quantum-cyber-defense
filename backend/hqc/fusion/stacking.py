"""Score-level fusion of the classical detector and a second-opinion adjudicator.

- ``PlattCalibrator``: P(MALICIOUS) from an adjudicator decision value (logistic fit).
- ``StackingFusion``: logit(p_final) = a * logit(p_classical) + b * decision + c.
Both are fitted on TRAINING out-of-fold values only (out-of-fold classical probabilities and
out-of-fold adjudicator decisions). ``p_final`` is an evaluation arm: the system's decision
stays the classical verdict, and ``attach_quantum_opinion`` never alters it.
"""

from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression

from hqc.common.schemas.detection import DetectionResult, QuantumOpinion

LOGIT_EPS = 1e-6


def logit(p: np.ndarray, eps: float = LOGIT_EPS) -> np.ndarray:
    q = np.clip(np.asarray(p, dtype=np.float64), eps, 1.0 - eps)
    out: np.ndarray = np.log(q / (1.0 - q))
    return out


def _check(y: np.ndarray, *columns: np.ndarray) -> None:
    if len(np.unique(y)) != 2:
        raise ValueError("Fusion fitting needs both classes")
    if any(len(c) != len(y) or np.any(~np.isfinite(c)) for c in columns):
        raise ValueError("Fusion inputs must be finite and aligned with y")


class PlattCalibrator:
    def __init__(self, seed: int = 0) -> None:
        self.model = LogisticRegression(C=1.0, random_state=seed)

    def fit(self, decision: np.ndarray, y: np.ndarray) -> PlattCalibrator:
        _check(y, decision)
        self.model.fit(decision.reshape(-1, 1), y)
        return self

    def predict(self, decision: np.ndarray) -> np.ndarray:
        p: np.ndarray = self.model.predict_proba(decision.reshape(-1, 1))[:, 1]
        return p


class StackingFusion:
    def __init__(self, seed: int = 0) -> None:
        self.model = LogisticRegression(C=1.0, random_state=seed)

    @staticmethod
    def _x(p_classical: np.ndarray, decision: np.ndarray) -> np.ndarray:
        return np.column_stack([logit(p_classical), np.asarray(decision, dtype=np.float64)])

    def fit(self, p_classical: np.ndarray, decision: np.ndarray, y: np.ndarray) -> StackingFusion:
        _check(y, p_classical, decision)
        self.model.fit(self._x(p_classical, decision), y)
        return self

    def predict(self, p_classical: np.ndarray, decision: np.ndarray) -> np.ndarray:
        p: np.ndarray = self.model.predict_proba(self._x(p_classical, decision))[:, 1]
        return p

    @property
    def coefficients(self) -> dict[str, float]:
        a, b = (float(v) for v in self.model.coef_[0])
        return {
            "logit_p_classical": a,
            "adjudicator_decision": b,
            "intercept": float(self.model.intercept_[0]),
        }


def disagreement(p_classical: np.ndarray, p_second: np.ndarray) -> np.ndarray:
    d: np.ndarray = np.abs(np.asarray(p_classical) - np.asarray(p_second))
    return d


def attach_quantum_opinion(result: DetectionResult, opinion: QuantumOpinion) -> DetectionResult:
    """Return a copy carrying the second opinion; the classical decision is unchanged."""
    updated = result.model_copy(update={"quantum": opinion})
    if (updated.verdict, updated.p_malicious, updated.confidence) != (
        result.verdict,
        result.p_malicious,
        result.confidence,
    ):
        raise AssertionError("The classical verdict must never be overwritten")  # pragma: no cover
    return updated
