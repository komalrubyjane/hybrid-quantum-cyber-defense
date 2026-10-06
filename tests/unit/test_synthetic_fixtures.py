"""The development fixture is valid, ordered and explicitly synthetic."""

from __future__ import annotations

import re
from typing import Any

from hqc.common.schemas import AttackChain, AttackStep, DataOrigin, SecurityEvent, StepProvenance
from hqc.common.schemas.base import TECHNIQUE_ID_REGEX

DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")


def test_fixture_labelled_synthetic(
    synthetic_scenario: dict[str, Any], synthetic_events: list[SecurityEvent]
) -> None:
    assert synthetic_scenario["data_origin"] == "SYNTHETIC"
    assert "SYNTHETIC" in synthetic_scenario["notice"]
    assert all(e.data_origin is DataOrigin.SYNTHETIC for e in synthetic_events)


def test_fixture_uses_only_documentation_addresses(synthetic_events: list[SecurityEvent]) -> None:
    for event in synthetic_events:
        for field in ("src_ip", "dst_ip"):
            ip = getattr(event, field, None)
            if ip is not None:
                assert str(ip).startswith(DOC_NETS), f"{event.event_id}.{field}={ip}"


def test_fixture_events_chronological(synthetic_events: list[SecurityEvent]) -> None:
    times = [e.timestamp for e in synthetic_events]
    assert times == sorted(times)


def test_expected_chain_ids_valid_and_linked(
    synthetic_scenario: dict[str, Any], synthetic_events: list[SecurityEvent]
) -> None:
    event_ids = [e.event_id for e in synthetic_events]
    expected = synthetic_scenario["expected_chain"]
    assert [s["event_id"] for s in expected] == event_ids
    assert all(re.match(TECHNIQUE_ID_REGEX, s["technique_id"]) for s in expected)


def test_expected_chain_builds_valid_attack_chain(
    synthetic_scenario: dict[str, Any], synthetic_events: list[SecurityEvent]
) -> None:
    by_id = {e.event_id: e for e in synthetic_events}
    steps = [
        AttackStep(
            technique_id=s["technique_id"],
            tactic_id=s["tactic_id"],
            timestamp=by_id[s["event_id"]].timestamp,
            event_id=s["event_id"],
            confidence=1.0,
            source="fixture:expected_chain",
            provenance=StepProvenance.OBSERVED,
        )
        for s in synthetic_scenario["expected_chain"]
    ]
    chain = AttackChain(
        chain_id=synthetic_scenario["scenario_id"],
        steps=steps,
        data_origin=DataOrigin.SYNTHETIC,
        attack_version="19.2",
    )
    assert chain.technique_ids == ["T1190", "T1059.004", "T1110.001", "T1021.004", "T1041"]
