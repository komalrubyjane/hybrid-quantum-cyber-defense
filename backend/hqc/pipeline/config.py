"""Integration configuration and the factory that wires the stored artifacts into services."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import Field, ValidationError

from hqc.attack_chain.catalog import KnowledgeBaseCatalog
from hqc.attack_chain.evidence import EvidencePolicy
from hqc.attack_chain.reconstruction import AttackChainService, CorrelationPolicy
from hqc.common.errors import ConfigurationError
from hqc.common.schemas.base import HQCModel, NonEmptyStr
from hqc.config import Settings
from hqc.defense.recommender import DefensePolicy, DefenseRecommendationService
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.pipeline.intelligence import IntelligencePipeline
from hqc.prediction.service import PredictionConfig, PredictionService
from hqc.prediction.vocabulary import TechniqueVocabulary
from hqc.risk.engine import RiskPolicy, RiskService


class IntegrationConfig(HQCModel):
    attack_version: NonEmptyStr
    vocabulary: NonEmptyStr
    scenario: NonEmptyStr
    prediction: PredictionConfig
    evidence: EvidencePolicy = Field(default_factory=EvidencePolicy)
    correlation: CorrelationPolicy = Field(default_factory=CorrelationPolicy)
    risk: RiskPolicy = Field(default_factory=RiskPolicy)
    defense: DefensePolicy = Field(default_factory=DefensePolicy)
    classical_run_id: NonEmptyStr
    quantum_run_id: NonEmptyStr


def load_integration_config(path: Path) -> IntegrationConfig:
    try:
        return IntegrationConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ConfigurationError(f"Invalid integration config {path}: {exc}") from exc


@dataclass
class BuiltPipeline:
    pipeline: IntelligencePipeline
    catalog: KnowledgeBaseCatalog
    vocabulary: TechniqueVocabulary


def build_pipeline(config: IntegrationConfig, settings: Settings, root: Path) -> BuiltPipeline:
    """Load the ATT&CK KB, committed vocabulary and stored prediction artifacts (no training)."""
    vocabulary = TechniqueVocabulary.load(
        root / config.vocabulary, expected_attack_version=config.attack_version
    )
    kb = AttackKnowledgeBase.load(settings)
    catalog = KnowledgeBaseCatalog(kb, vocabulary)
    prediction = PredictionService.from_artifacts(
        config.prediction,
        vocabulary,
        settings.resolve(settings.models_dir),
        settings.resolve(settings.reports_dir),
    )
    pipeline = IntelligencePipeline(
        AttackChainService(catalog, config.correlation),
        prediction,
        RiskService(config.risk, catalog),
        DefenseRecommendationService(config.defense, catalog),
    )
    return BuiltPipeline(pipeline, catalog, vocabulary)
