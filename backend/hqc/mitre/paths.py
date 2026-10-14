"""Canonical local paths and manifest IDs for ATT&CK / Attack Flow artifacts."""

from __future__ import annotations

from pathlib import Path

from hqc.config import Settings


def manifest_path(settings: Settings) -> Path:
    return settings.resolve(settings.data_dir) / "MANIFEST.yaml"


def raw_attack_path(settings: Settings, version: str) -> Path:
    """RAW (observed source) ATT&CK bundle, byte-for-byte as downloaded."""
    return (
        settings.resolve(settings.data_dir)
        / "external"
        / "attack"
        / (f"enterprise-attack-{version}.json")
    )


def processed_kb_path(settings: Settings, version: str) -> Path:
    """PROCESSED (normalised) knowledge base."""
    return (
        settings.resolve(settings.data_dir)
        / "processed"
        / "attack"
        / (f"enterprise-attack-{version}.kb.json")
    )


def raw_attack_flow_dir(settings: Settings) -> Path:
    return settings.resolve(settings.data_dir) / "external" / "attack_flow" / "stix"


def processed_attack_flow_path(settings: Settings) -> Path:
    return settings.resolve(settings.data_dir) / "processed" / "attack_flow" / "sequences.json"


def vocabulary_path(settings: Settings, version: str) -> Path:
    """DERIVED vocabulary artifact (small; tracked in git)."""
    return (
        settings.resolve(settings.models_dir)
        / "attack_prediction"
        / "vocabulary"
        / (f"technique-vocabulary-attack-{version}.json")
    )


def raw_attack_artifact_id(version: str) -> str:
    return f"attack-enterprise-{version}-stix"


def processed_kb_artifact_id(version: str) -> str:
    return f"attack-enterprise-{version}-kb"


RAW_ATTACK_FLOW_ARTIFACT_ID = "attack-flow-corpus-stix"
PROCESSED_ATTACK_FLOW_ARTIFACT_ID = "attack-flow-corpus-sequences"


def vocabulary_artifact_id(version: str) -> str:
    return f"technique-vocabulary-attack-{version}"
