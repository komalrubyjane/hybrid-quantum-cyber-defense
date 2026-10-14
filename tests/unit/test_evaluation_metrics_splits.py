"""Metrics (hand-calculated), bootstrap intervals and group-aware splits."""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from hqc.common.errors import DataLeakageError
from hqc.common.schemas import EvaluationFold
from hqc.evaluation.metrics import (
    METRIC_NAMES,
    InstanceScore,
    bootstrap_ci,
    log_loss,
    mean_metrics,
    paired_difference,
    score_distribution,
    summarize,
    tactics_overlap,
    tie_aware_hit,
    tie_aware_reciprocal_rank,
)
from hqc.evaluation.splits import Fold, assert_disjoint, leave_one_group_out
from hqc.prediction.base import OutputSpace
from prediction_fixtures import mini_kb, mini_vocabulary

TACTICS = {"T1003": ["TA0006", "TA0007"], "T1059": ["TA0002"], "T1059.001": ["TA0002"]}


@pytest.fixture(scope="module")
def space() -> OutputSpace:
    return OutputSpace(mini_vocabulary(mini_kb()))  # [T1003, T1059, T1059.001, T1059.004]


# --- instance scoring ------------------------------------------------------------------------


def test_score_with_tie_hand_calculated(space: OutputSpace) -> None:
    # Order by (-p, index): T1059 (0.4), T1059.001 (0.4), T1003 (0.1), T1059.004 (0.1).
    score = score_distribution([0.1, 0.4, 0.4, 0.1], space, "T1059.001", TACTICS)
    assert (score.rank, score.n_greater, score.n_tied) == (2, 0, 1)
    assert [t for t, _ in score.top] == ["T1059", "T1059.001", "T1003", "T1059.004"]
    m = score.metrics()
    assert m["top1"] == 0.0 and m["top3"] == 1.0 and m["top5"] == 1.0
    assert m["mrr"] == 0.5
    assert m["top1_tie_aware"] == 0.5
    assert m["mrr_tie_aware"] == pytest.approx((1 + 0.5) / 2)
    assert m["log_loss"] == pytest.approx(-math.log(0.4))
    assert m["tactic_top1"] == 1.0  # T1059 and T1059.001 share TA0002
    assert set(m) == set(METRIC_NAMES)


def test_score_rank_and_tactic_miss(space: OutputSpace) -> None:
    score = score_distribution([0.1, 0.6, 0.2, 0.1], space, "T1003", TACTICS)
    assert score.rank == 3 and score.n_greater == 2 and score.n_tied == 1
    m = score.metrics()
    assert m["top1"] == 0.0 and m["top3"] == 1.0 and m["mrr"] == pytest.approx(1 / 3)
    assert m["top3_tie_aware"] == pytest.approx(0.5)  # rank 3 or 4 equally likely
    assert m["tactic_top1"] == 0.0  # T1059 (TA0002) vs T1003 (TA0006, TA0007)


def test_uniform_deterministic_vs_tie_aware(space: OutputSpace) -> None:
    score = score_distribution([0.25] * 4, space, "T1059.004", TACTICS)
    assert score.rank == 4  # deterministic: vocabulary-index order
    m = score.metrics()
    assert m["top1"] == 0.0 and m["top1_tie_aware"] == pytest.approx(0.25)
    assert m["mrr_tie_aware"] == pytest.approx((1 + 1 / 2 + 1 / 3 + 1 / 4) / 4)


def test_tactics_overlap_rule() -> None:
    assert tactics_overlap("T1003", "T1003", TACTICS)
    assert not tactics_overlap("T1003", "T1059", TACTICS)
    assert not tactics_overlap("T9999", "T1059", TACTICS)  # no tactics -> miss


def test_metric_edge_cases() -> None:
    assert tie_aware_hit(0, 0, 1) == 1.0 and tie_aware_hit(5, 0, 3) == 0.0
    assert tie_aware_reciprocal_rank(0, 0) == 1.0
    for bad in (0.0, -0.1, 1.5):
        with pytest.raises(ValueError):
            log_loss(bad)
    with pytest.raises(ValueError):
        tie_aware_hit(-1, 0, 1)
    with pytest.raises(ValueError):
        mean_metrics([])


# --- aggregation / bootstrap -------------------------------------------------------------------


def _score(rank: int, p: float) -> InstanceScore:
    return InstanceScore(p, rank, rank - 1, 0, (("T1059", p),), False)


def test_mean_metrics() -> None:
    m = mean_metrics([_score(1, 0.5), _score(2, 0.25)])
    assert m["top1"] == 0.5 and m["mrr"] == pytest.approx(0.75)
    assert m["log_loss"] == pytest.approx((math.log(2) + math.log(4)) / 2)


def test_bootstrap_ci_properties() -> None:
    values = [0.1, 0.2, 0.3, 0.9]
    a = bootstrap_ci(values, 2000, seed=7)
    assert a == bootstrap_ci(values, 2000, seed=7)  # deterministic
    assert min(values) <= a[0] <= sum(values) / 4 <= a[1] <= max(values)
    assert bootstrap_ci([0.4] * 5, 500, seed=1) == (0.4, 0.4)
    for bad in ([], [0.1]):
        if not bad:
            with pytest.raises(ValueError):
                bootstrap_ci(bad, 100, 1)
    with pytest.raises(ValueError):
        bootstrap_ci([0.1], 0, 1)


def test_summarize_and_paired_difference() -> None:
    s = summarize([0.2, 0.4], 1000, seed=3)
    assert s.mean == pytest.approx(0.3) and s.std == pytest.approx(math.sqrt(0.02)) and s.n == 2
    assert summarize([0.5], 100, seed=3).std == 0.0
    a = {"g1": 0.5, "g2": 0.6, "g3": 0.7}
    b = {"g1": 0.1, "g2": 0.2, "g3": 0.3, "only_b": 1.0}
    diff = paired_difference(a, b, 1000, seed=5)
    assert diff.mean == pytest.approx(0.4) and diff.n == 3 and diff.ci_excludes_zero
    unclear = paired_difference({"g1": 0.1, "g2": -0.1}, {"g1": 0.0, "g2": 0.0}, 1000, seed=5)
    assert not unclear.ci_excludes_zero


# --- splits ------------------------------------------------------------------------------------

GROUPS = {
    "OpenClaw": "OpenClaw Command & Control via Prompt Injection",
    "OpenClaw Command & Control via Prompt Injection": (
        "OpenClaw Command & Control via Prompt Injection"
    ),
    "CISA AA22-138B VMWare Workspace (TA1)": "CISA AA22-138B VMWare Workspace",
    "CISA AA22-138B VMWare Workspace (TA2)": "CISA AA22-138B VMWare Workspace",
    "SolarWinds": "SolarWinds",
}


def test_every_group_held_out_exactly_once() -> None:
    folds = leave_one_group_out(GROUPS)
    assert sorted(f.test_group for f in folds) == sorted(set(GROUPS.values()))
    assert [f.index for f in folds] == [0, 1, 2]
    for fold in folds:
        assert fold.test_group not in fold.train_groups
        assert not set(fold.test_documents) & set(fold.train_documents)
        assert set(fold.test_documents) | set(fold.train_documents) == set(GROUPS)


def test_variant_documents_stay_together() -> None:
    folds = {f.test_group: f for f in leave_one_group_out(GROUPS)}
    openclaw = folds["OpenClaw Command & Control via Prompt Injection"]
    assert set(openclaw.test_documents) == {
        "OpenClaw",
        "OpenClaw Command & Control via Prompt Injection",
    }
    cisa = folds["CISA AA22-138B VMWare Workspace"]
    assert len(cisa.test_documents) == 2
    assert not any("CISA" in d for d in cisa.train_documents)


def test_fold_records_reject_overlap() -> None:
    fold = leave_one_group_out(GROUPS)[0]
    record = fold.to_record()
    assert record.fold_id == "fold-00"
    train, test = fold.sources()
    assert f"group:{fold.test_group}" in test and not set(train) & set(test)
    with pytest.raises(ValidationError, match="both train and test"):
        EvaluationFold(fold_id="x", train_sources=["group:a", "group:b"], test_sources=["group:a"])


def test_assert_disjoint_detects_leaks() -> None:
    leaky = Fold(0, "A", ("A", "B"), ("a1",), ("b1",))
    with pytest.raises(DataLeakageError):
        assert_disjoint(leaky)
    shared_doc = Fold(0, "A", ("B",), ("x",), ("x",))
    with pytest.raises(DataLeakageError):
        assert_disjoint(shared_doc)


def test_requires_two_groups() -> None:
    with pytest.raises(ValueError):
        leave_one_group_out({"d1": "only"})
