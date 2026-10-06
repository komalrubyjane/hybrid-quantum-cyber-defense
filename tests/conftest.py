"""Shared pytest fixtures. Tests never need downloaded datasets."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from hqc.common.schemas import SecurityEvent, parse_security_event
from hqc.config import Settings, get_settings
from hqc.storage import SQLiteStore

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SYNTHETIC_DIR = FIXTURES_DIR / "synthetic"


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove project env vars so a developer's shell or .env cannot leak into tests."""
    for key in list(os.environ):
        if key.startswith("HQC_") or key == "ATTACK_VERSION":
            monkeypatch.delenv(key, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None, environment="test", log_json=True)  # type: ignore[call-arg]


@pytest.fixture
def store() -> Iterator[SQLiteStore]:
    with SQLiteStore(":memory:") as s:
        yield s


@pytest.fixture(scope="session")
def synthetic_scenario() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((SYNTHETIC_DIR / "scenario_basic.json").read_text())
    return data


@pytest.fixture(scope="session")
def synthetic_events(synthetic_scenario: dict[str, Any]) -> list[SecurityEvent]:
    return [parse_security_event(e) for e in synthetic_scenario["events"]]
