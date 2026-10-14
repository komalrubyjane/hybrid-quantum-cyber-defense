"""Milestone 7 on the REAL local ATT&CK 19.2 KB and stored Milestone 3/4 artifacts.

Structural assertions only: the synthetic scenario's integration checks pass with the real
models, and the test fixture's ATT&CK facts match the knowledge base. Skips if absent.
"""

from __future__ import annotations

import pytest

from hqc.config import PROJECT_ROOT, Settings
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.paths import processed_kb_path
from hqc.pipeline.checks import integration_checks
from hqc.pipeline.config import build_pipeline, load_integration_config
from hqc.pipeline.scenario import build_observations, load_scenario, validate_scenario
from m7_fixtures import INTEGRATION_CONFIG, SCENARIO_TACTICS, TACTICS

pytestmark = [pytest.mark.integration, pytest.mark.requires_data]


def _settings() -> Settings:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    if not processed_kb_path(settings, settings.attack_version).is_file():
        pytest.skip("processed ATT&CK knowledge base not available")
    return settings


def test_fixture_attack_facts_match_the_knowledge_base() -> None:
    kb = AttackKnowledgeBase.load(_settings())
    assert kb.version().attack_version == "19.2"
    for technique, tactic_ids in SCENARIO_TACTICS.items():
        assert kb.get_technique(technique).is_active
        tactics = kb.get_tactics(technique)
        assert [t.tactic_id for t in tactics] == tactic_ids
        for t in tactics:
            assert (t.shortname, t.order) == (
                TACTICS[t.tactic_id].shortname,
                TACTICS[t.tactic_id].order,
            )


def test_real_pipeline_passes_integration_checks() -> None:
    settings = _settings()
    config = load_integration_config(INTEGRATION_CONFIG)
    models = settings.resolve(settings.models_dir) / "generated" / "attack_prediction"
    if not (models / config.prediction.lstm_run_id).is_dir():
        pytest.skip("stored Milestone 4 artifacts not available")
    built = build_pipeline(config, settings, PROJECT_ROOT)
    scenario, _ = load_scenario(PROJECT_ROOT / config.scenario)
    validate_scenario(scenario, built.catalog)
    observations = build_observations(scenario, built.catalog, config.evidence)
    resources = {r.resource_id: r for r in scenario.resources}
    out = built.pipeline.run(observations, resources, as_of=scenario.as_of)
    checks = integration_checks(out, scenario, observations, built.pipeline, resources)
    assert all(c.passed for c in checks), [c for c in checks if not c.passed]
    versions = built.pipeline.prediction.model_versions
    assert {"B1", "M1", "LSTM", "HYBRID"} <= set(versions) and "alpha=0.7" in versions["HYBRID"]
    assert all(r.requires_human_approval for a in out.incidents for r in a.recommendations)
