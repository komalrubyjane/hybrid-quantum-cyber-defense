"""Group-aware leave-one-group-out (LOGO) splitting.

A *group* is the Milestone 2 ``source_group`` (variants of one document share a group,
e.g. both OpenClaw documents). Every group is held out exactly once; no document or
group may appear on both sides of a split.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from hqc.common.errors import DataLeakageError
from hqc.common.schemas.evaluation import EvaluationFold


@dataclass(frozen=True)
class Fold:
    index: int
    test_group: str
    train_groups: tuple[str, ...]
    test_documents: tuple[str, ...]
    train_documents: tuple[str, ...]

    @property
    def fold_id(self) -> str:
        return f"fold-{self.index:02d}"

    def sources(self) -> tuple[list[str], list[str]]:
        """(train, test) source identifiers covering both groups and documents."""
        train = [f"group:{g}" for g in self.train_groups] + [
            f"document:{d}" for d in self.train_documents
        ]
        test = [f"group:{self.test_group}"] + [f"document:{d}" for d in self.test_documents]
        return train, test

    def to_record(self) -> EvaluationFold:
        """Schema record; its validator rejects any train/test overlap."""
        train, test = self.sources()
        return EvaluationFold(fold_id=self.fold_id, train_sources=train, test_sources=test)


def assert_disjoint(fold: Fold) -> None:
    """Raise DataLeakageError if any group or document is on both sides."""
    if fold.test_group in fold.train_groups:
        raise DataLeakageError(f"{fold.fold_id}: test group {fold.test_group!r} is in training")
    shared = set(fold.test_documents) & set(fold.train_documents)
    if shared:
        raise DataLeakageError(f"{fold.fold_id}: documents on both sides: {sorted(shared)}")


def leave_one_group_out(group_of_document: Mapping[str, str]) -> list[Fold]:
    """One fold per group, in sorted group order (deterministic)."""
    groups = sorted(set(group_of_document.values()))
    if len(groups) < 2:
        raise ValueError("Leave-one-group-out needs at least two groups")
    folds: list[Fold] = []
    for index, test_group in enumerate(groups):
        fold = Fold(
            index=index,
            test_group=test_group,
            train_groups=tuple(g for g in groups if g != test_group),
            test_documents=tuple(
                sorted(d for d, g in group_of_document.items() if g == test_group)
            ),
            train_documents=tuple(
                sorted(d for d, g in group_of_document.items() if g != test_group)
            ),
        )
        assert_disjoint(fold)
        folds.append(fold)
    return folds


def inner_validation_groups(
    train_groups: Sequence[str],
    fraction: float,
    min_groups: int,
    seed: int,
    fold_id: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Deterministic (inner_train, validation) split of OUTER-TRAINING groups only.

    Groups are ordered by SHA-256 of ``seed|fold_id|group`` (fold-specific, not
    alphabetical) and the first ``max(min_groups, round(fraction * n))`` become
    validation groups; at least one group always remains for inner training.
    """
    groups = sorted(set(train_groups))
    if len(groups) < 2:
        raise ValueError("Need at least two training groups for an inner validation split")
    if not 0.0 < fraction < 1.0 or min_groups < 1:
        raise ValueError("Invalid inner validation configuration")
    n_val = min(len(groups) - 1, max(min_groups, round(fraction * len(groups))))
    ranked = sorted(
        groups, key=lambda g: hashlib.sha256(f"{seed}|{fold_id}|{g}".encode()).hexdigest()
    )
    validation = tuple(sorted(ranked[:n_val]))
    inner_train = tuple(g for g in groups if g not in validation)
    return inner_train, validation
