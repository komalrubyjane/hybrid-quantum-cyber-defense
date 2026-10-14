"""Milestone 8 API with the REAL local ATT&CK KB and stored artifacts (skips if absent).

Uses in-memory API state; the project's evaluation store is only read.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from hqc.api.server import create_api_app
from hqc.api.v1.state import ApiStateStore
from hqc.config import Settings
from hqc.mitre.paths import processed_kb_path
from hqc.storage import SQLiteStore

pytestmark = [pytest.mark.integration, pytest.mark.requires_data]


def test_real_services_through_the_api() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    if not processed_kb_path(settings, settings.attack_version).is_file():
        pytest.skip("processed ATT&CK knowledge base not available")
    models = settings.resolve(settings.models_dir) / "generated" / "attack_prediction"
    if not models.is_dir():
        pytest.skip("stored prediction artifacts not available")
    with SQLiteStore(":memory:") as runs:
        client = TestClient(
            create_api_app(settings, state=ApiStateStore(":memory:"), evaluation_store=runs)
        )
        meta = client.get("/api/v1/meta").json()
        assert meta["attack_version"] == "19.2" and "alpha=0.7" in meta["model_versions"]["HYBRID"]
        scenario = client.get("/api/v1/scenarios/synthetic").json()
        chains = client.post(
            "/api/v1/chains/reconstruct",
            json={"observations": _observations(client, scenario), "as_of": scenario["as_of"]},
        )
        assert chains.status_code == 200
        assert [c["status"] for c in chains.json()["chains"]] == ["CORRELATED", "STANDALONE"]


def _observations(client: TestClient, scenario: dict[str, object]) -> list[dict[str, object]]:
    """Typed observations built server-side are not exposed; rebuild them like the pipeline."""
    from hqc.attack_chain.evidence import EvidencePolicy
    from hqc.config import PROJECT_ROOT
    from hqc.pipeline.config import build_pipeline, load_integration_config
    from hqc.pipeline.scenario import SyntheticScenario, build_observations

    config = load_integration_config(PROJECT_ROOT / "configs" / "integration.yaml")
    built = build_pipeline(config, Settings(_env_file=None), PROJECT_ROOT)  # type: ignore[call-arg]
    observations = build_observations(
        SyntheticScenario.model_validate(scenario), built.catalog, EvidencePolicy()
    )
    return [o.model_dump(mode="json") for o in observations]
