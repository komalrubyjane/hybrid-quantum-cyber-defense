"""Deterministic samples for the small-budget kernel experiments.

``day_stratified_balanced_sample``: N/2 benign + N/2 malicious training rows. Within each
class the quota is split as evenly as possible across the training days that contain that
class (capacity-capped, remainder redistributed), so every leave-one-day-out training fold
keeps both classes when the data allow it.

``stratified_sample``: proportional to the original label (used for the fixed test sample).
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
import pandas as pd

from hqc.detection.dataset import DAY_ORDER


def _allocate(quota: int, capacity: Sequence[int]) -> list[int]:
    """Split ``quota`` as evenly as possible over strata with the given capacities."""
    if quota > sum(capacity):
        raise ValueError(f"Requested {quota} rows but only {sum(capacity)} are available")
    taken = [0] * len(capacity)
    remaining = quota
    while remaining > 0:
        open_strata = [i for i, c in enumerate(capacity) if taken[i] < c]
        share, extra = divmod(remaining, len(open_strata))
        for rank, i in enumerate(open_strata):
            add = min(share + (1 if rank < extra else 0), capacity[i] - taken[i])
            taken[i] += add
            remaining -= add
    return taken


def day_stratified_balanced_sample(
    frame: pd.DataFrame, n: int, seed: int, allow_fewer: bool = False
) -> np.ndarray:
    """Sorted positional indices into ``frame`` (columns ``day``, ``is_malicious``)."""
    if n < 2:
        raise ValueError("n must be at least 2")
    rng = np.random.default_rng(seed)
    y = frame["is_malicious"].to_numpy(dtype=bool)
    day = frame["day"].to_numpy()
    days = [d for d in DAY_ORDER if d in set(day)]
    per_class = {False: n // 2, True: n - n // 2}
    if allow_fewer:
        smallest = min(int((y == c).sum()) for c in (False, True))
        per_class = {c: min(q, smallest) for c, q in per_class.items()}
    chosen: list[np.ndarray] = []
    for cls in (False, True):
        pools = [np.flatnonzero((y == cls) & (day == d)) for d in days]
        pools = [p for p in pools if len(p)]
        counts = _allocate(per_class[cls], [len(p) for p in pools])
        chosen += [rng.choice(p, size=k, replace=False) for p, k in zip(pools, counts, strict=True)]
    return np.sort(np.concatenate(chosen)).astype(np.int64)


def stratified_sample(frame: pd.DataFrame, n: int, seed: int, by: str = "label") -> np.ndarray:
    """Proportional stratified sample (largest-remainder rounding); sorted indices."""
    if n > len(frame):
        raise ValueError("Sample larger than the frame")
    rng = np.random.default_rng(seed)
    groups = frame.groupby(by, sort=True).indices
    labels = sorted(groups, key=str)
    sizes = np.array([len(groups[k]) for k in labels], dtype=np.float64)
    exact = sizes / sizes.sum() * n
    counts = np.floor(exact).astype(int)
    for i in np.argsort(-(exact - counts), kind="stable")[: n - counts.sum()]:
        counts[i] += 1
    parts = [
        rng.choice(groups[k], size=int(c), replace=False)
        for k, c in zip(labels, counts, strict=True)
        if c
    ]
    return np.sort(np.concatenate(parts)).astype(np.int64)
