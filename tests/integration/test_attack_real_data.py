"""Checks against the REAL downloaded ATT&CK / Attack Flow data.

Data files are git-ignored, so these tests skip when they are absent (e.g. fresh clone
before running the fetch scripts). The committed vocabulary is always validated.
"""

from __future__ import annotations

import json

import pytest

from hqc.common.provenance import load_manifest, sha256_file
from hqc.config import Settings
from hqc.mitre.attack_flow import load_attack_flow_file
from hqc.mitre.attack_flow_corpus import build_corpus
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.paths import (
    RAW_ATTACK_FLOW_ARTIFACT_ID,
    manifest_path,
    processed_kb_artifact_id,
    processed_kb_path,
    raw_attack_artifact_id,
    raw_attack_flow_dir,
    vocabulary_path,
)
from hqc.prediction.vocabulary import TechniqueVocabulary

pytestmark = [pytest.mark.integration, pytest.mark.requires_data]


@pytest.fixture(scope="module")
def real_settings() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture(scope="module")
def real_kb(real_settings: Settings) -> AttackKnowledgeBase:
    path = processed_kb_path(real_settings, real_settings.attack_version)
    if not path.is_file():
        pytest.skip(
            "processed ATT&CK KB not built (run scripts/fetch_attack.py, build_attack_kb.py)"
        )
    return AttackKnowledgeBase.load(real_settings)


def test_committed_vocabulary_is_valid(real_settings: Settings) -> None:
    path = vocabulary_path(real_settings, real_settings.attack_version)
    vocab = TechniqueVocabulary.load(path, expected_attack_version=real_settings.attack_version)
    assert vocab.index_to_token[:2] == ["<PAD>", "<UNK>"]
    assert vocab.size > 500


def test_kb_version_and_shape(real_kb: AttackKnowledgeBase, real_settings: Settings) -> None:
    meta = real_kb.version()
    assert meta.attack_version == real_settings.attack_version
    assert meta.collection_name == "Enterprise ATT&CK"
    tactic_ids = [t.tactic_id for t in real_kb.get_all_tactics()]
    assert len(tactic_ids) == meta.counts["tactics"] == len(set(tactic_ids))
    active = real_kb.get_techniques()
    assert len(active) == meta.counts["techniques_active"]
    for technique in active:
        if technique.is_subtechnique:
            assert technique.parent_id is not None
            assert real_kb.get_technique(technique.parent_id).is_active
        for tactic in technique.tactic_ids:
            assert tactic in tactic_ids
    assert real_kb.get_technique("T1059.004").parent_id == "T1059"


def test_kb_provenance_matches_manifest(
    real_kb: AttackKnowledgeBase, real_settings: Settings
) -> None:
    version = real_settings.attack_version
    manifest = load_manifest(manifest_path(real_settings))
    raw = manifest.get(raw_attack_artifact_id(version))
    processed = manifest.get(processed_kb_artifact_id(version))
    assert raw is not None and processed is not None
    assert real_kb.version().source_sha256 == raw.sha256
    assert sha256_file(processed_kb_path(real_settings, version)) == processed.sha256
    raw_path = real_settings.resolve(real_settings.data_dir) / "external" / "attack"
    raw_file = raw_path / f"enterprise-attack-{version}.json"
    if raw_file.is_file():
        assert sha256_file(raw_file) == raw.sha256


def test_committed_vocabulary_matches_knowledge_base(
    real_kb: AttackKnowledgeBase, real_settings: Settings
) -> None:
    committed = TechniqueVocabulary.load(
        vocabulary_path(real_settings, real_settings.attack_version)
    )
    assert committed == TechniqueVocabulary.from_knowledge_base(real_kb)


@pytest.fixture(scope="module")
def flow_dir(real_settings: Settings):  # type: ignore[no-untyped-def]
    directory = raw_attack_flow_dir(real_settings)
    if not any(directory.glob("*.json")):
        pytest.skip("Attack Flow corpus not downloaded (run scripts/fetch_attack_flow.py)")
    return directory


def test_attack_flow_files_match_manifest(flow_dir, real_settings: Settings) -> None:  # type: ignore[no-untyped-def]
    raw = load_manifest(manifest_path(real_settings)).get(RAW_ATTACK_FLOW_ARTIFACT_ID)
    assert raw is not None and raw.files
    for entry in raw.files:
        assert sha256_file(flow_dir / entry.name) == entry.sha256


def test_real_flow_preserves_source_graph_order(flow_dir) -> None:  # type: ignore[no-untyped-def]
    """Independent re-walk of one real document's graph equals the parser output."""
    path = flow_dir / "Conti Ransomware.json"
    doc = load_attack_flow_file(path, "test")
    bundle = json.loads(path.read_text())
    by_id = {o["id"]: o for o in bundle["objects"]}
    flow = next(o for o in bundle["objects"] if o["type"] == "attack-flow")
    node = by_id[flow["start_refs"][0]]
    expected: list[str] = []
    # Follow the first effect reference at every step: this is the first enumerated path.
    seen: set[str] = set()
    while node["id"] not in seen:
        seen.add(node["id"])
        if node["type"] == "attack-action" and str(node.get("technique_id", "")).startswith("T"):
            expected.append(node["technique_id"].strip())
        refs = node.get("effect_refs") or node.get("on_true_refs") or node.get("on_false_refs")
        if not refs:
            break
        node = by_id[refs[0]]
    assert doc.sequences[0].technique_ids == expected
    assert any(s.technique_ids != sorted(s.technique_ids) for s in doc.sequences)


def test_corpus_summary_report_is_current(  # type: ignore[no-untyped-def]
    flow_dir, real_kb: AttackKnowledgeBase, real_settings: Settings
) -> None:
    report = (
        real_settings.resolve(real_settings.reports_dir)
        / "datasets"
        / ("attack_flow_corpus_summary.json")
    )
    raw = load_manifest(manifest_path(real_settings)).get(RAW_ATTACK_FLOW_ARTIFACT_ID)
    assert raw is not None
    fresh = build_corpus(flow_dir, raw.version, kb=real_kb).summary
    assert json.loads(report.read_text()) == fresh.model_dump(mode="json")
    assert fresh.documents_included < fresh.documents_total  # Example Attack Tree excluded
