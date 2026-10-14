"""Model arms for the matched-budget comparison, all on the same angle features.

Kernel arms use ``sklearn.svm.SVC(kernel="precomputed")`` (one solver for all kernels):
- ``zz_qsvm``    fidelity kernel of the entangling ZZ feature map (bandwidth alpha, C);
- ``z_qsvm``     fidelity kernel of the product Z feature map, a classically computable control;
- ``rbf_svm``    RBF kernel (gamma, C);
- ``linear_svm`` linear kernel (C).
Non-kernel arms: ``logreg`` (C) and ``random_forest`` (fixed Milestone 5 settings).

``score`` returns a value in [0, 1] with decision threshold 0.5: sigmoid(decision) for margin
models (monotone, so ROC/PR-AUC equal those of the raw decision), P(MALICIOUS) for the forest.
Inference for kernel arms uses the support vectors only.

Solver safety: libsvm's default is an UNLIMITED number of SMO iterations, and on some
rank-deficient precomputed Gram matrices with large C (observed: linear kernel, C=100, d=8)
it cycles forever. Every SVC is therefore capped at ``SVC_MAX_ITER`` iterations; a fit that
hits the cap is flagged ``converged = False`` and counted in the reported results.
"""

from __future__ import annotations

import warnings
from typing import Literal

import numpy as np
from pydantic import Field
from scipy.special import expit
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC

from hqc.common.schemas.base import HQCModel
from hqc.quantum.feature_maps import FeatureMapSpec, statevectors
from hqc.quantum.kernels import fidelity_kernel, linear_kernel, rbf_kernel

ModelKind = Literal["zz_qsvm", "z_qsvm", "rbf_svm", "linear_svm", "logreg", "random_forest"]
QUANTUM_KINDS: tuple[ModelKind, ...] = ("zz_qsvm", "z_qsvm")
KERNEL_KINDS: tuple[ModelKind, ...] = ("zz_qsvm", "z_qsvm", "rbf_svm", "linear_svm")
ALL_KINDS: tuple[ModelKind, ...] = (*KERNEL_KINDS, "logreg", "random_forest")
SCORE_THRESHOLD = 0.5
SVC_MAX_ITER = 1_000_000
INFERENCE_CHUNK = 20_000  # rows per kernel block at inference (memory bound)
LOGREG_MAX_ITER = 2000


class HyperGrid(HQCModel):
    c: list[float] = Field(min_length=1)
    alpha: list[float] = Field(min_length=1)
    rbf_gamma: list[float] = Field(min_length=1)


class Hyper(HQCModel):
    c: float | None = None
    alpha: float | None = None
    gamma: float | None = None


class ForestSettings(HQCModel):
    n_estimators: int = 100
    min_samples_leaf: int = 2
    max_features: Literal["sqrt", "log2"] = "sqrt"


def hyper_candidates(kind: ModelKind, grid: HyperGrid) -> list[Hyper]:
    """Candidates in a fixed order (ties in CV go to the earliest)."""
    if kind in QUANTUM_KINDS:
        return [Hyper(c=c, alpha=a) for a in grid.alpha for c in grid.c]
    if kind == "rbf_svm":
        return [Hyper(c=c, gamma=g) for g in grid.rbf_gamma for c in grid.c]
    if kind in ("linear_svm", "logreg"):
        return [Hyper(c=c) for c in grid.c]
    return [Hyper()]


def feature_map_for(kind: ModelKind, reps: int) -> FeatureMapSpec:
    return FeatureMapSpec(kind="zz" if kind == "zz_qsvm" else "z", reps=reps)


def embed(kind: ModelKind, hyper: Hyper, angles: np.ndarray, reps: int) -> np.ndarray:
    """Statevectors for quantum kinds (angles * alpha); the angles themselves otherwise."""
    if kind in QUANTUM_KINDS:
        if hyper.alpha is None:
            raise ValueError(f"{kind} needs alpha")
        return statevectors(angles * hyper.alpha, feature_map_for(kind, reps))
    return angles


def gram(kind: ModelKind, hyper: Hyper, ea: np.ndarray, eb: np.ndarray) -> np.ndarray:
    if kind in QUANTUM_KINDS:
        return fidelity_kernel(ea, eb)
    if kind == "rbf_svm":
        if hyper.gamma is None:
            raise ValueError("rbf_svm needs gamma")
        return rbf_kernel(ea, eb, hyper.gamma)
    if kind == "linear_svm":
        return linear_kernel(ea, eb)
    raise ValueError(f"{kind} is not a kernel model")


class TrainedModel:
    """A fitted arm. Kernel arms keep only support-vector embeddings for inference."""

    def __init__(
        self,
        kind: ModelKind,
        hyper: Hyper,
        reps: int,
        seed: int,
        forest: ForestSettings | None = None,
    ) -> None:
        self.kind = kind
        self.hyper = hyper
        self.reps = reps
        self.seed = seed
        self.forest = forest or ForestSettings()
        self.svc: SVC | None = None
        self.support: np.ndarray | None = None
        self.dual: np.ndarray | None = None
        self.intercept = 0.0
        self.converged = True
        self.estimator: LogisticRegression | RandomForestClassifier | None = None

    def fit(self, angles: np.ndarray, y: np.ndarray) -> TrainedModel:
        if len(np.unique(y)) != 2:
            raise ValueError("Training data must contain both classes")
        if self.kind in KERNEL_KINDS:
            e = embed(self.kind, self.hyper, angles, self.reps)
            self.fit_gram(gram(self.kind, self.hyper, e, e), y)
            if self.svc is None:
                raise RuntimeError("SVC fit failed")
            self.support = e[self.svc.support_]
            return self
        if self.kind == "logreg":
            self.estimator = LogisticRegression(
                C=self.hyper.c or 1.0, max_iter=LOGREG_MAX_ITER, random_state=self.seed
            )
        else:
            self.estimator = RandomForestClassifier(
                n_estimators=self.forest.n_estimators,
                min_samples_leaf=self.forest.min_samples_leaf,
                max_features=self.forest.max_features,
                n_jobs=-1,
                random_state=self.seed,
            )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ConvergenceWarning)
            self.estimator.fit(angles, y)
        self.converged = not any(issubclass(w.category, ConvergenceWarning) for w in caught)
        return self

    def fit_gram(self, kernel: np.ndarray, y: np.ndarray) -> TrainedModel:
        """Fit the SVC on a precomputed training Gram matrix (support kept by ``fit``)."""
        svc = SVC(kernel="precomputed", C=self.hyper.c or 1.0, max_iter=SVC_MAX_ITER)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ConvergenceWarning)
            svc.fit(kernel, y)
        self.converged = not any(issubclass(w.category, ConvergenceWarning) for w in caught)
        self.svc = svc
        self.dual = svc.dual_coef_[0].astype(np.float64)
        self.intercept = float(svc.intercept_[0])
        return self

    def decision_from_gram(self, kernel_to_support: np.ndarray) -> np.ndarray:
        if self.dual is None:
            raise RuntimeError("Model is not fitted")
        decision: np.ndarray = kernel_to_support @ self.dual + self.intercept
        return decision

    def decision(self, angles: np.ndarray) -> np.ndarray:
        """Real-valued decision; >= 0 means MALICIOUS for margin models."""
        if self.kind in KERNEL_KINDS:
            if self.support is None:
                raise RuntimeError("Model is not fitted")
            out = np.empty(len(angles), dtype=np.float64)
            for start in range(0, len(angles), INFERENCE_CHUNK):  # bounded memory
                e = embed(self.kind, self.hyper, angles[start : start + INFERENCE_CHUNK], self.reps)
                k = gram(self.kind, self.hyper, e, self.support)
                out[start : start + len(e)] = self.decision_from_gram(k)
            return out
        if self.estimator is None:
            raise RuntimeError("Model is not fitted")
        if isinstance(self.estimator, LogisticRegression):
            lr_decision: np.ndarray = self.estimator.decision_function(angles)
            return lr_decision
        p = self.estimator.predict_proba(angles)[:, list(self.estimator.classes_).index(1)]
        forest_decision: np.ndarray = p.astype(np.float64) - SCORE_THRESHOLD
        return forest_decision

    def score(self, angles: np.ndarray) -> np.ndarray:
        return to_score(self.kind, self.decision(angles))

    @property
    def n_support(self) -> int | None:
        return None if self.support is None else len(self.support)


def to_score(kind: ModelKind, decision: np.ndarray) -> np.ndarray:
    if kind == "random_forest":
        forest: np.ndarray = np.clip(decision + SCORE_THRESHOLD, 0.0, 1.0)
        return forest
    margin: np.ndarray = expit(decision)
    return margin
