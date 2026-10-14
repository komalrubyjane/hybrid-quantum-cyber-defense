"""ATT&CK STIX normalisation and the typed knowledge-base API (offline fixtures)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import stix_builders as sb
from hqc.common.errors import (
    DatasetNotFoundError,
    InvalidTechniqueIdError,
    MalformedSourceDataError,
    MissingRequiredFieldError,
    UnknownTechniqueError,
    UnsupportedAttackVersionError,
)
from hqc.config import Settings
from hqc.mitre.build import build_kb_file, serialize_kb
from hqc.mitre.knowledge_base import AttackKnowledgeBase, validate_technique_id
from hqc.mitre.models import KnowledgeBaseData
from hqc.mitre.paths import processed_kb_path
from hqc.mitre.stix_parser import parse_attack_bundle


@pytest.fixture
def kb_data() -> KnowledgeBaseData:
    return parse_attack_bundle(sb.attack_bundle(), expected_version=sb.TEST_VERSION)


@pytest.fixture
def kb(kb_data: KnowledgeBaseData) -> AttackKnowledgeBase:
    return AttackKnowledgeBase.from_data(kb_data)


# --- lookups ------------------------------------------------------------------------


def test_get_technique_returns_typed_object(kb: AttackKnowledgeBase) -> None:
    t = kb.get_technique("T1059.004")
    assert t.name == "Unix Shell"
    assert t.tactic_ids == ["TA0002"]
    assert t.is_subtechnique and t.parent_id == "T1059"
    assert t.mitigation_ids == ["M1038"]
    assert t.attack_version == sb.TEST_VERSION
    assert t.url == "https://attack.mitre.org/techniques/T1059.004"


@pytest.mark.parametrize("bad", ["Command and Scripting Interpreter", "t1059", "T59", "", "M1038"])
def test_invalid_technique_id_raises(kb: AttackKnowledgeBase, bad: str) -> None:
    with pytest.raises(InvalidTechniqueIdError):
        kb.get_technique(bad)


def test_unknown_but_well_formed_id_raises_unknown(kb: AttackKnowledgeBase) -> None:
    with pytest.raises(UnknownTechniqueError):
        kb.get_technique("T1234")
    assert issubclass(UnknownTechniqueError, InvalidTechniqueIdError)
    assert kb.has_technique("T1003") and not kb.has_technique("T1234")


def test_get_techniques_active_by_default_sorted(kb: AttackKnowledgeBase) -> None:
    ids = [t.technique_id for t in kb.get_techniques()]
    assert ids == ["T1003", "T1059", "T1059.001", "T1059.004"]
    everything = [t.technique_id for t in kb.get_techniques(True, True)]
    assert {"T1086", "T1999", "T1059.999"} <= set(everything)


def test_get_subtechniques(kb: AttackKnowledgeBase) -> None:
    subs = [t.technique_id for t in kb.get_subtechniques("T1059")]
    assert subs == ["T1059.001", "T1059.004"]  # revoked T1059.999 excluded
    assert kb.get_subtechniques("T1003") == []
    with pytest.raises(InvalidTechniqueIdError):
        kb.get_subtechniques("T1059.001")


def test_get_mitigations(kb: AttackKnowledgeBase) -> None:
    assert [m.mitigation_id for m in kb.get_mitigations("T1059")] == [
        "M1038"
    ]  # deprecated rel ignored
    assert [m.mitigation_id for m in kb.get_mitigations("T1003")] == ["M1026"]
    assert kb.get_mitigations("T1059.001") == []
    assert kb.get_mitigation("M1038").technique_ids == ["T1059", "T1059.004"]
    with pytest.raises(MalformedSourceDataError):
        kb.get_mitigation("M9999")


def test_get_tactics_in_matrix_order(kb: AttackKnowledgeBase) -> None:
    tactics = kb.get_tactics("T1003")
    assert [t.tactic_id for t in tactics] == ["TA0006", "TA0007"]
    assert [t.order for t in kb.get_all_tactics()] == [0, 1, 2]
    assert [t.tactic_id for t in kb.get_all_tactics()] == ["TA0002", "TA0006", "TA0007"]
    assert kb.get_tactic("TA0002").shortname == "execution"
    with pytest.raises(MalformedSourceDataError):
        kb.get_tactic("TA9999")


def test_detection_strategies_and_data_components(kb: AttackKnowledgeBase) -> None:
    t = kb.get_technique("T1003")
    assert t.detection_strategy_ids == ["DET0001"]
    assert t.data_component_ids == ["DC0032"]
    assert [c.name for c in kb.get_data_components("T1003")] == ["Process Creation"]


def test_version_metadata(kb: AttackKnowledgeBase) -> None:
    meta = kb.version()
    assert meta.attack_version == sb.TEST_VERSION
    assert meta.attack_spec_version == "3.3.0"
    assert meta.counts["techniques_active"] == 4
    assert meta.counts["techniques_revoked"] == 2
    assert meta.counts["techniques_deprecated"] == 1
    assert meta.skipped["course_of_action_legacy_or_inactive"] == 1
    assert meta.skipped["inactive_subtechnique_parent_from_id"] == 1


def test_revoked_and_deprecated_resolution(kb: AttackKnowledgeBase) -> None:
    old = kb.get_technique("T1086")
    assert old.revoked and old.revoked_by == "T1059.001"
    resolved = kb.resolve_current("T1086")
    assert resolved is not None and resolved.technique_id == "T1059.001"
    assert kb.resolve_current("T1999") is None  # deprecated, no replacement
    assert kb.resolve_current("T1003") is kb.get_technique("T1003")


def test_validate_technique_id_helper() -> None:
    assert validate_technique_id("T1059.004") == "T1059.004"
    with pytest.raises(InvalidTechniqueIdError):
        validate_technique_id(123)  # type: ignore[arg-type]


# --- malformed source data ---------------------------------------------------------------


def test_not_a_bundle() -> None:
    with pytest.raises(MalformedSourceDataError):
        parse_attack_bundle({"type": "report"}, sb.TEST_VERSION)
    with pytest.raises(MalformedSourceDataError):
        parse_attack_bundle({"type": "bundle", "objects": []}, sb.TEST_VERSION)
    with pytest.raises(MalformedSourceDataError):
        parse_attack_bundle({"type": "bundle", "objects": [{"no": "id"}]}, sb.TEST_VERSION)


def test_version_mismatch_is_malformed() -> None:
    with pytest.raises(MalformedSourceDataError, match="declares ATT&CK"):
        parse_attack_bundle(sb.attack_bundle(), expected_version="19.2")


def test_missing_required_fields() -> None:
    bundle = sb.mutate(sb.attack_bundle(), "attack-pattern--t1003", name=None)
    with pytest.raises(MissingRequiredFieldError):
        parse_attack_bundle(bundle, sb.TEST_VERSION)
    bundle = sb.mutate(sb.attack_bundle(), "attack-pattern--t1003", external_references=[])
    with pytest.raises(MissingRequiredFieldError):
        parse_attack_bundle(bundle, sb.TEST_VERSION)
    bundle = sb.mutate(sb.attack_bundle(), "x-mitre-collection--1", x_mitre_version=None)
    with pytest.raises(MissingRequiredFieldError):
        parse_attack_bundle(bundle, sb.TEST_VERSION)


def test_active_subtechnique_without_parent_link_fails() -> None:
    bundle = sb.attack_bundle()
    bundle["objects"] = [o for o in bundle["objects"] if o["id"] != "relationship--s2"]
    with pytest.raises(MissingRequiredFieldError, match=r"T1059\.004"):
        parse_attack_bundle(bundle, sb.TEST_VERSION)


def test_active_technique_with_unknown_tactic_fails() -> None:
    phases = [{"kill_chain_name": "mitre-attack", "phase_name": "time-travel"}]
    bundle = sb.mutate(sb.attack_bundle(), "attack-pattern--t1003", kill_chain_phases=phases)
    with pytest.raises(MalformedSourceDataError, match="unknown tactic"):
        parse_attack_bundle(bundle, sb.TEST_VERSION)


def test_duplicate_and_invalid_technique_ids_fail() -> None:
    dup = sb.mutate(
        sb.attack_bundle(),
        "attack-pattern--t1003",
        external_references=[{"source_name": "mitre-attack", "external_id": "T1059"}],
    )
    with pytest.raises(MalformedSourceDataError, match="Duplicate"):
        parse_attack_bundle(dup, sb.TEST_VERSION)
    bad = sb.mutate(
        sb.attack_bundle(),
        "attack-pattern--t1003",
        external_references=[{"source_name": "mitre-attack", "external_id": "X1"}],
    )
    with pytest.raises(MalformedSourceDataError, match="invalid ID"):
        parse_attack_bundle(bad, sb.TEST_VERSION)


def test_matrix_problems_fail() -> None:
    bundle = sb.mutate(sb.attack_bundle(), "x-mitre-matrix--1", tactic_refs=["x-mitre-tactic--zzz"])
    with pytest.raises(MalformedSourceDataError, match="unknown tactic"):
        parse_attack_bundle(bundle, sb.TEST_VERSION)
    bundle = sb.attack_bundle()
    bundle["objects"] = [o for o in bundle["objects"] if o["type"] != "x-mitre-matrix"]
    with pytest.raises(MalformedSourceDataError, match="exactly one"):
        parse_attack_bundle(bundle, sb.TEST_VERSION)


def test_subtechnique_parent_mismatch_fails() -> None:
    bundle = sb.mutate(sb.attack_bundle(), "relationship--s2", target_ref="attack-pattern--t1003")
    with pytest.raises(MalformedSourceDataError, match=r"T1059\.004"):
        parse_attack_bundle(bundle, sb.TEST_VERSION)


# --- persistence / determinism -------------------------------------------------------------


def _write_raw(tmp_path: Path) -> Path:
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(sb.attack_bundle()))
    return raw


def test_build_is_deterministic_and_round_trips(tmp_path: Path) -> None:
    raw = _write_raw(tmp_path)
    out1, out2 = tmp_path / "a.kb.json", tmp_path / "b.kb.json"
    data = build_kb_file(raw, out1, sb.TEST_VERSION, source_url="https://example.test/x")
    build_kb_file(raw, out2, sb.TEST_VERSION, source_url="https://example.test/x")
    assert out1.read_bytes() == out2.read_bytes()
    assert data.metadata.source_sha256 is not None and len(data.metadata.source_sha256) == 64
    loaded = AttackKnowledgeBase.from_file(out1, expected_version=sb.TEST_VERSION)
    assert loaded.data == data
    assert serialize_kb(loaded.data) == serialize_kb(data)


def test_build_missing_or_invalid_raw(tmp_path: Path) -> None:
    with pytest.raises(DatasetNotFoundError):
        build_kb_file(tmp_path / "absent.json", tmp_path / "o.json", sb.TEST_VERSION)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(MalformedSourceDataError):
        build_kb_file(bad, tmp_path / "o.json", sb.TEST_VERSION)


def test_from_file_errors(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedAttackVersionError, match="No processed"):
        AttackKnowledgeBase.from_file(tmp_path / "missing.kb.json")
    out = tmp_path / "kb.json"
    build_kb_file(_write_raw(tmp_path), out, sb.TEST_VERSION)
    with pytest.raises(UnsupportedAttackVersionError, match="requested"):
        AttackKnowledgeBase.from_file(out, expected_version="19.2")
    corrupt = tmp_path / "corrupt.kb.json"
    corrupt.write_text('{"metadata": {}}')
    with pytest.raises(MalformedSourceDataError):
        AttackKnowledgeBase.from_file(corrupt)
    payload = json.loads(out.read_text())
    payload["metadata"]["kb_format_version"] = "999"
    old = tmp_path / "old.kb.json"
    old.write_text(json.dumps(payload))
    with pytest.raises(MalformedSourceDataError, match="format"):
        AttackKnowledgeBase.from_file(old)


def test_load_uses_configured_version(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, data_dir=tmp_path, attack_version=sb.TEST_VERSION)  # type: ignore[call-arg]
    with pytest.raises(UnsupportedAttackVersionError):
        AttackKnowledgeBase.load(settings)
    build_kb_file(
        _write_raw(tmp_path), processed_kb_path(settings, sb.TEST_VERSION), sb.TEST_VERSION
    )
    assert AttackKnowledgeBase.load(settings).version().attack_version == sb.TEST_VERSION
