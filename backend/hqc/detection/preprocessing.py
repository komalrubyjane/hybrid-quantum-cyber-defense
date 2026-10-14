"""Day-based split, feature policy, train-only preprocessing and duplicate audit.

Leakage rules implemented here:
- Splits are WHOLE DAYS (no row-level mixing); every file must belong to exactly one side.
- Every data-dependent choice (constant columns, duplicate-column check, protocol
  categories, imputation medians, scaling statistics) is computed on TRAINING rows only.
- Identifiers (flow ID, IPs, timestamp, source port) and label-derived/bookkeeping
  columns are never model inputs.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from hqc.common.errors import DataLeakageError, FeatureSchemaMismatchError
from hqc.detection.dataset import NUMERIC_FLOW_COLUMNS
from hqc.detection.schemas import FeaturePolicy

FEATURE_POLICY_VERSION = "cicids2017-features-v1"
PREPROCESSING_FORMAT = "1"

IDENTIFIER_FEATURES: dict[str, str] = {
    "flow_id": "Concatenation of IPs, ports and protocol: a per-flow identifier that lets a "
    "model memorise individual flows instead of behaviour.",
    "source_ip": "Host identity of the lab network; attacker IPs are fixed per day, so it "
    "would act as a label proxy and not transfer to other networks.",
    "destination_ip": "Host identity (victim IPs are fixed per scenario); label proxy.",
    "timestamp": "Capture time; attacks occur in known time windows, so time encodes the "
    "label and breaks the day-based holdout.",
    "source_port": "Mostly ephemeral client ports chosen by the OS; identifier-like, no "
    "stable behavioural meaning.",
}
LEAKAGE_FEATURES: dict[str, str] = {
    "raw_label": "Ground truth (original label).",
    "label": "Ground truth (normalised label).",
    "is_malicious": "Ground truth (binary target).",
    "day": "Split key; constant within a day and therefore a label proxy.",
    "source_file": "File name encodes the day and attack scenario.",
    "row_number": "Position within a file; ordering artefact.",
}
SHORTCUT_RISK: dict[str, str] = {
    "destination_port": "Service port is meaningful network context but is a documented "
    "shortcut in CIC-IDS2017 (attacks target few ports); evaluated with an ablation "
    "that drops it.",
}
CATEGORICAL = "protocol"


# --- day split ------------------------------------------------------------------------------


@dataclass(frozen=True)
class DaySplit:
    train_days: tuple[str, ...]
    test_days: tuple[str, ...]
    train_files: tuple[str, ...]
    test_files: tuple[str, ...]


def day_split(frame: pd.DataFrame, train_days: Sequence[str], test_days: Sequence[str]) -> DaySplit:
    """Whole-day split derived from the files actually present."""
    if set(train_days) & set(test_days):
        raise DataLeakageError(f"Days in both train and test: {set(train_days) & set(test_days)}")
    present = set(frame["day"].unique())
    for day in (*train_days, *test_days):
        if day not in present:
            raise FeatureSchemaMismatchError(f"Configured day {day} has no data")
    unassigned = present - set(train_days) - set(test_days)
    if unassigned:
        raise FeatureSchemaMismatchError(f"Days present but not assigned: {sorted(unassigned)}")
    files = frame.groupby("source_file", sort=True)["day"].first()
    return DaySplit(
        train_days=tuple(train_days),
        test_days=tuple(test_days),
        train_files=tuple(str(f) for f, d in files.items() if d in train_days),
        test_files=tuple(str(f) for f, d in files.items() if d in test_days),
    )


def split_masks(frame: pd.DataFrame, split: DaySplit) -> tuple[pd.Series, pd.Series]:
    train = frame["day"].isin(split.train_days)
    test = frame["day"].isin(split.test_days)
    if bool((train & test).any()):
        raise DataLeakageError("A row is assigned to both splits")
    return train, test


# --- feature policy ------------------------------------------------------------------------


def build_feature_policy(train: pd.DataFrame, drop_destination_port: bool = False) -> FeaturePolicy:
    """Derive the policy from TRAINING rows only."""
    duplicates: dict[str, str] = {}
    if "fwd_header_length__dup1" in train:
        a = train["fwd_header_length"].to_numpy()
        b = train["fwd_header_length__dup1"].to_numpy()
        if np.array_equal(a, b, equal_nan=True):
            duplicates["fwd_header_length__dup1"] = (
                "Second 'Fwd Header Length' column in the CICFlowMeter header; identical to "
                "fwd_header_length on every training row."
            )
    candidates = ["destination_port", *NUMERIC_FLOW_COLUMNS]
    if drop_destination_port:
        candidates.remove("destination_port")
    constant: dict[str, str] = {}
    used: list[str] = []
    for column in candidates:
        if column in duplicates:
            continue
        values = train[column].to_numpy(dtype=np.float64)
        finite = values[np.isfinite(values)]
        if finite.size == 0 or float(finite.min()) == float(finite.max()):
            constant[column] = "Constant (or entirely non-finite) on the training days."
            continue
        used.append(column)
    protocols = sorted({str(int(v)) for v in train[CATEGORICAL].dropna().unique()})
    dropped_identifier = dict(IDENTIFIER_FEATURES)
    if drop_destination_port:
        dropped_identifier["destination_port"] = "Dropped in the destination-port ablation."
    return FeaturePolicy(
        version=FEATURE_POLICY_VERSION + ("-no-dstport" if drop_destination_port else ""),
        used_features=used,
        categorical_features={CATEGORICAL: protocols},
        dropped_identifier_features=dropped_identifier,
        dropped_non_numeric_features={},
        dropped_leakage_features=dict(LEAKAGE_FEATURES),
        dropped_duplicate_columns=duplicates,
        dropped_constant_features=constant,
        shortcut_risk_features={} if drop_destination_port else dict(SHORTCUT_RISK),
    )


# --- preprocessing -------------------------------------------------------------------------


class Preprocessor:
    """Train-only fitted transform: +/-inf -> NaN -> training median; standardise with
    training mean/std; one-hot protocol with training categories (unseen -> all zeros)."""

    def __init__(self, policy: FeaturePolicy) -> None:
        self.policy = policy
        self.medians: list[float] | None = None
        self.means: list[float] | None = None
        self.stds: list[float] | None = None

    @property
    def fitted(self) -> bool:
        return self.medians is not None

    @property
    def feature_names(self) -> list[str]:
        cats = self.policy.categorical_features.get(CATEGORICAL, [])
        return [*self.policy.used_features, *[f"{CATEGORICAL}={c}" for c in cats]]

    def _numeric(self, frame: pd.DataFrame) -> np.ndarray:
        missing = [c for c in self.policy.used_features if c not in frame]
        if missing:
            raise FeatureSchemaMismatchError(f"Input lacks policy features {missing}")
        x = frame[self.policy.used_features].to_numpy(dtype=np.float64, copy=True)
        x[~np.isfinite(x)] = np.nan
        return x

    def fit(self, train: pd.DataFrame) -> Preprocessor:
        x = self._numeric(train)
        medians = np.nanmedian(x, axis=0)
        medians = np.where(np.isnan(medians), 0.0, medians)
        x = np.where(np.isnan(x), medians, x)
        stds = x.std(axis=0)
        self.medians = medians.tolist()
        self.means = x.mean(axis=0).tolist()
        self.stds = np.where(stds > 0, stds, 1.0).tolist()
        return self

    def transform(self, frame: pd.DataFrame) -> np.ndarray:
        if self.medians is None or self.means is None or self.stds is None:
            raise RuntimeError("Preprocessor must be fitted on training data first")
        x = self._numeric(frame)
        medians = np.asarray(self.medians)
        x = np.where(np.isnan(x), medians, x)
        x = (x - np.asarray(self.means)) / np.asarray(self.stds)
        cats = self.policy.categorical_features.get(CATEGORICAL, [])
        protocol = frame[CATEGORICAL].to_numpy(dtype=np.float64)
        onehot = np.zeros((len(frame), len(cats)), dtype=np.float64)
        for j, cat in enumerate(cats):
            onehot[:, j] = protocol == float(cat)
        return np.hstack([x, onehot]).astype(np.float32)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": PREPROCESSING_FORMAT,
            "policy": self.policy.model_dump(mode="json"),
            "medians": self.medians,
            "means": self.means,
            "stds": self.stds,
        }

    @property
    def version(self) -> str:
        """Content hash of the fitted parameters (changes if anything changes)."""
        digest = hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()
        return f"prep-{PREPROCESSING_FORMAT}-{digest[:12]}"

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {**self.to_dict(), "version": self.version}
        path.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> Preprocessor:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("format") != PREPROCESSING_FORMAT:
            raise FeatureSchemaMismatchError(f"Unsupported preprocessing format in {path}")
        pre = cls(FeaturePolicy.model_validate(payload["policy"]))
        pre.medians, pre.means, pre.stds = payload["medians"], payload["means"], payload["stds"]
        if payload.get("version") != pre.version:
            raise FeatureSchemaMismatchError(
                f"Preprocessing file {path} failed its integrity check"
            )
        return pre


# --- duplicate audit -----------------------------------------------------------------------


def feature_row_hashes(frame: pd.DataFrame, policy: FeaturePolicy) -> np.ndarray:
    """64-bit hash of each row's model-input values (NaN/inf handled consistently)."""
    columns = [*policy.used_features, CATEGORICAL]
    hashed: np.ndarray = pd.util.hash_pandas_object(frame[columns], index=False).to_numpy()
    return hashed


@dataclass(frozen=True)
class DuplicateAudit:
    train_rows: int
    test_rows: int
    duplicate_rows_within_train: int
    duplicate_rows_within_test: int
    test_rows_with_feature_vector_in_train: int
    cross_split_rows_with_conflicting_label: int
    cross_split_mask: np.ndarray

    def summary(self) -> dict[str, int]:
        return {
            "train_rows": self.train_rows,
            "test_rows": self.test_rows,
            "duplicate_rows_within_train": self.duplicate_rows_within_train,
            "duplicate_rows_within_test": self.duplicate_rows_within_test,
            "test_rows_with_feature_vector_in_train": self.test_rows_with_feature_vector_in_train,
            "cross_split_rows_with_conflicting_label": self.cross_split_rows_with_conflicting_label,
        }


def duplicate_audit(
    train: pd.DataFrame, test: pd.DataFrame, policy: FeaturePolicy
) -> DuplicateAudit:
    """Exact duplicate model-input vectors within and across splits (rows are kept; the
    cross-split mask lets evaluation also report results without those test rows)."""
    h_train = feature_row_hashes(train, policy)
    h_test = feature_row_hashes(test, policy)
    train_set = set(h_train.tolist())
    cross = np.fromiter((h in train_set for h in h_test.tolist()), dtype=bool, count=len(h_test))
    labels_by_hash: dict[int, set[int]] = {}
    for h, y in zip(h_train.tolist(), train["is_malicious"].tolist(), strict=True):
        labels_by_hash.setdefault(h, set()).add(int(y))
    conflicts = sum(
        1
        for h, y, c in zip(
            h_test.tolist(), test["is_malicious"].tolist(), cross.tolist(), strict=True
        )
        if c and labels_by_hash[h] != {int(y)}
    )
    return DuplicateAudit(
        train_rows=len(train),
        test_rows=len(test),
        duplicate_rows_within_train=int(len(h_train) - len(train_set)),
        duplicate_rows_within_test=int(len(h_test) - len(set(h_test.tolist()))),
        test_rows_with_feature_vector_in_train=int(cross.sum()),
        cross_split_rows_with_conflicting_label=int(conflicts),
        cross_split_mask=cross,
    )
