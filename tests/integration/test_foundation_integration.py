"""Milestone 1 integration: synthetic events -> typed contracts -> storage -> reload.

The full event→detection→mapping→chain→prediction→risk→defense integration test is
added once those stages exist (Milestone 7+).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hqc.common.schemas import SecurityEvent
from hqc.storage import Collection, SQLiteStore

pytestmark = pytest.mark.integration


def test_synthetic_events_persist_and_reload_in_order(
    tmp_path: Path, synthetic_events: list[SecurityEvent]
) -> None:
    db = tmp_path / "hqc.sqlite3"
    with SQLiteStore(db) as store:
        for event in synthetic_events:
            store.put(Collection.SECURITY_EVENTS, event)
    with SQLiteStore(db) as store:
        reloaded = store.list(Collection.SECURITY_EVENTS)
    assert reloaded == synthetic_events
    assert [type(e).__name__ for e in reloaded] == [
        "APIEvent",
        "SystemEvent",
        "AuthenticationEvent",
        "AuthenticationEvent",
        "NetworkFlow",
    ]
