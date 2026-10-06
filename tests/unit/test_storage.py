"""Storage abstraction (SQLite)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import BaseModel

import factories as f
from hqc.common.errors import RecordNotFoundError, StorageError
from hqc.common.schemas import NetworkFlow, RecommendationStatus
from hqc.storage import Collection, SQLiteStore

CASES: list[tuple[Collection, Callable[[], BaseModel]]] = [
    (Collection.SECURITY_EVENTS, f.network_flow),
    (Collection.SECURITY_EVENTS, f.auth_event),
    (Collection.DETECTION_RESULTS, f.detection_result),
    (Collection.ATTACK_CHAINS, f.attack_chain),
    (Collection.PREDICTIONS, f.prediction_result),
    (Collection.RISK_ASSESSMENTS, f.risk_assessment),
    (Collection.RECOMMENDATIONS, f.recommendation),
    (Collection.EVALUATION_RUNS, f.evaluation_result),
]


@pytest.mark.parametrize(("collection", "build"), CASES, ids=lambda x: getattr(x, "__name__", x))
def test_put_get_round_trip(
    store: SQLiteStore, collection: Collection, build: Callable[[], BaseModel]
) -> None:
    record = build()
    key = store.put(collection, record)
    restored = store.get(collection, key)
    assert type(restored) is type(record)
    assert restored == record


def test_every_collection_covered() -> None:
    assert {c for c, _ in CASES} == set(Collection)


def test_wrong_record_type_rejected(store: SQLiteStore) -> None:
    with pytest.raises(TypeError):
        store.put(Collection.ATTACK_CHAINS, f.network_flow())


def test_missing_record_raises(store: SQLiteStore) -> None:
    with pytest.raises(RecordNotFoundError):
        store.get(Collection.PREDICTIONS, "nope")


def test_upsert_updates_mutable_records(store: SQLiteStore) -> None:
    rec = f.recommendation()
    store.put(Collection.RECOMMENDATIONS, rec)
    store.put(
        Collection.RECOMMENDATIONS, rec.model_copy(update={"status": RecommendationStatus.APPROVED})
    )
    assert store.count(Collection.RECOMMENDATIONS) == 1
    restored = store.get(Collection.RECOMMENDATIONS, rec.recommendation_id)
    assert getattr(restored, "status") is RecommendationStatus.APPROVED  # noqa: B009


def test_evaluation_runs_are_write_once(store: SQLiteStore) -> None:
    store.put(Collection.EVALUATION_RUNS, f.evaluation_result())
    with pytest.raises(StorageError, match="write-once"):
        store.put(Collection.EVALUATION_RUNS, f.evaluation_result(notes="altered"))


def test_list_preserves_insertion_order_and_paginates(store: SQLiteStore) -> None:
    for i in (3, 1, 2):
        store.put(Collection.SECURITY_EVENTS, f.network_flow(f"nf-{i}"))
    ids = [getattr(r, "event_id") for r in store.list(Collection.SECURITY_EVENTS)]  # noqa: B009
    assert ids == ["nf-3", "nf-1", "nf-2"]
    page = store.list(Collection.SECURITY_EVENTS, limit=1, offset=1)
    assert [getattr(r, "event_id") for r in page] == ["nf-1"]  # noqa: B009
    with pytest.raises(ValueError):
        store.list(Collection.SECURITY_EVENTS, limit=-1)


def test_file_backed_store_persists(tmp_path: Path) -> None:
    db = tmp_path / "sub" / "hqc.sqlite3"
    with SQLiteStore(db) as s:
        s.put(Collection.SECURITY_EVENTS, f.network_flow())
    with SQLiteStore(db) as s:
        restored = s.get(Collection.SECURITY_EVENTS, "nf-1")
    assert isinstance(restored, NetworkFlow)
