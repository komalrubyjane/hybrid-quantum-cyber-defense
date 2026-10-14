"""Low-dimensional angle features for the kernel models (fitted on the training sample only).

frame -> Milestone 5 ``Preprocessor`` (same feature policy; refitted on the sample rows:
+/-inf -> NaN -> median, standardise, one-hot protocol) -> top-k features by mutual
information with the label -> PCA(d) -> min-max to [0, pi] (test values clipped).

Every fitted quantity (medians, means, stds, MI ranking, PCA basis, min/max) comes from the
rows passed to ``fit``. Every model arm in a comparison uses the same fitted features.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.feature_selection import mutual_info_classif

from hqc.detection.preprocessing import Preprocessor
from hqc.detection.schemas import FeaturePolicy

ANGLE_RANGE = np.pi


class AngleFeatures:
    def __init__(self, policy: FeaturePolicy, n_dims: int, k_mutual_info: int, seed: int) -> None:
        if n_dims < 1 or k_mutual_info < n_dims:
            raise ValueError("Need 1 <= n_dims <= k_mutual_info")
        self.policy = policy
        self.n_dims = n_dims
        self.k_mutual_info = k_mutual_info
        self.seed = seed
        self.preprocessor: Preprocessor | None = None
        self.selected: np.ndarray | None = None
        self.mutual_information: np.ndarray | None = None
        self.pca: PCA | None = None
        self.low: np.ndarray | None = None
        self.high: np.ndarray | None = None
        self.fit_rows = 0

    @property
    def fitted(self) -> bool:
        return self.pca is not None

    def fit(self, frame: pd.DataFrame) -> AngleFeatures:
        y = frame["is_malicious"].to_numpy(dtype=np.int64)
        if len(np.unique(y)) != 2:
            raise ValueError("AngleFeatures.fit needs both classes")
        preprocessor = Preprocessor(self.policy).fit(frame)
        x = preprocessor.transform(frame).astype(np.float64)
        k = min(self.k_mutual_info, x.shape[1])
        if k < self.n_dims or len(frame) < self.n_dims:
            raise ValueError("Too few features or rows for the requested dimension")
        mi = mutual_info_classif(x, y, random_state=self.seed)
        selected = np.sort(np.argsort(-mi, kind="stable")[:k])
        pca = PCA(n_components=self.n_dims, svd_solver="full", random_state=self.seed)
        z = pca.fit_transform(x[:, selected])
        self.preprocessor = preprocessor
        self.mutual_information = mi
        self.selected = selected
        self.pca = pca
        self.low = z.min(axis=0)
        self.high = z.max(axis=0)
        self.fit_rows = len(frame)
        return self

    def transform(self, frame: pd.DataFrame) -> np.ndarray:
        """Angles in [0, pi], shape (n, n_dims)."""
        if (
            self.preprocessor is None
            or self.selected is None
            or self.pca is None
            or self.low is None
            or self.high is None
        ):
            raise RuntimeError("AngleFeatures must be fitted on training rows first")
        x = self.preprocessor.transform(frame).astype(np.float64)
        z = self.pca.transform(x[:, self.selected])
        span = np.where(self.high > self.low, self.high - self.low, 1.0)
        scaled = (z - self.low) / span
        angles: np.ndarray = np.clip(scaled, 0.0, 1.0) * ANGLE_RANGE
        return angles

    def describe(self) -> dict[str, object]:
        names = self.preprocessor.feature_names if self.preprocessor else []
        chosen = [names[i] for i in self.selected] if self.selected is not None else []
        return {
            "n_dims": self.n_dims,
            "k_mutual_info": self.k_mutual_info,
            "fit_rows": self.fit_rows,
            "selected_features": chosen,
            "preprocessing_version": self.preprocessor.version if self.preprocessor else None,
            "pca_explained_variance_ratio": [
                round(float(v), 6) for v in self.pca.explained_variance_ratio_
            ]
            if self.pca is not None
            else None,
        }
