"""Milestone 7 test fixtures (no downloaded data needed).

``SCENARIO_TACTICS`` lists the ATT&CK 19.2 tactics (ID, shortname, matrix order) of the
synthetic scenario's techniques as recorded in the local 19.2 knowledge base; a
``requires_data`` test checks these facts against the real KB. Mitigation IDs here are TEST
VALUES only (not claimed ATT&CK facts). Prediction models are real project classes fitted on
a tiny hand-made instance set (TEST FIXTURE, not CTI).
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from hqc.attack_chain.catalog import StaticCatalog
from hqc.attack_chain.evidence import EvidencePolicy
from hqc.attack_chain.reconstruction import AttackChainService, CorrelationPolicy
from hqc.common.schemas.attack import ATTACKTactic
from hqc.common.schemas.intelligence import Observation
from hqc.defense.recommender import DefensePolicy, DefenseRecommendationService
from hqc.pipeline.intelligence import IntelligencePipeline
from hqc.pipeline.scenario import SyntheticScenario, build_observations, load_scenario
from hqc.prediction.base import NextTechniqueModel, OutputSpace
from hqc.prediction.baselines import UniformModel, frequency_model
from hqc.prediction.dataset import WeightedInstance
from hqc.prediction.fusion import HybridModel
from hqc.prediction.markov import InterpolatedMarkovModel, MarkovCounts, MarkovParams
from hqc.prediction.service import PredictionService
from hqc.prediction.vocabulary import TechniqueVocabulary
from hqc.risk.engine import RiskPolicy, RiskService

ROOT = Path(__file__).parents[1]
SCENARIO_PATH = ROOT / "configs" / "scenarios" / "synthetic_multistage_v1.json"
INTEGRATION_CONFIG = ROOT / "configs" / "integration.yaml"

TACTICS = {
    t[0]: ATTACKTactic(tactic_id=t[0], name=t[1], shortname=t[1], order=t[2])
    for t in [
        ("TA0001", "initial-access", 2),
        ("TA0002", "execution", 3),
        ("TA0003", "persistence", 4),
        ("TA0004", "privilege-escalation", 5),
        ("TA0006", "credential-access", 8),
        ("TA0008", "lateral-movement", 10),
        ("TA0010", "exfiltration", 13),
        ("TA0011", "command-and-control", 12),
        ("TA0040", "impact", 14),
    ]
}
SCENARIO_TACTICS: dict[str, list[str]] = {
    "T1190": ["TA0001"],
    "T1059.004": ["TA0002"],
    "T1098.004": ["TA0003", "TA0004"],
    "T1003.008": ["TA0006"],
    "T1021.004": ["TA0008"],
    "T1110.001": ["TA0006"],
    "T1041": ["TA0010"],
    "T1486": ["TA0040"],
    "T1105": ["TA0011"],
    "T1053.003": ["TA0002", "TA0003", "TA0004"],
}
TEST_MITIGATIONS = {"T1190": ["M1048"], "T1041": ["M1031", "M1057"], "T1105": ["M1031"]}


def static_catalog(active: Sequence[str] | None = None) -> StaticCatalog:
    return StaticCatalog(
        version="19.2",
        active=frozenset(active if active is not None else SCENARIO_TACTICS),
        technique_tactics={t: [TACTICS[x] for x in ts] for t, ts in SCENARIO_TACTICS.items()},
        technique_mitigations=TEST_MITIGATIONS,
    )


def make_vocabulary() -> TechniqueVocabulary:
    return TechniqueVocabulary.from_technique_ids(SCENARIO_TACTICS, "19.2")


def make_models(vocabulary: TechniqueVocabulary) -> dict[str, NextTechniqueModel]:
    space = OutputSpace(vocabulary)
    instances = [
        WeightedInstance(("T1190",), "T1059.004", 1.0),
        WeightedInstance(("T1190", "T1059.004"), "T1105", 1.0),
        WeightedInstance(("T1003.008",), "T1021.004", 1.0),
        WeightedInstance(("T1021.004",), "T1041", 1.0),
        WeightedInstance(("T1041",), "T1486", 1.0),
        WeightedInstance(("<UNK>",), "T1105", 1.0),
    ]
    counts = MarkovCounts.from_instances(instances)
    b1 = frequency_model(counts, beta=1.0, space=space)
    m1 = InterpolatedMarkovModel(
        counts, MarkovParams(max_order=1, weights=(1.0,), alpha=1.0, beta=1.0), space, "M1"
    )
    uniform = UniformModel(space)
    return {"B1": b1, "M1": m1, "LSTM": uniform, "HYBRID": HybridModel(m1, uniform, 0.5)}


def make_prediction_service(vocabulary: TechniqueVocabulary | None = None) -> PredictionService:
    vocab = vocabulary or make_vocabulary()
    return PredictionService(
        make_models(vocab),
        "HYBRID",
        vocab,
        {"HYBRID": "test-hybrid", "vocabulary": vocab.vocabulary_version},
        top_k=3,
        beam_width=3,
        horizon=2,
    )


def make_pipeline(catalog: StaticCatalog | None = None) -> IntelligencePipeline:
    cat = catalog or static_catalog()
    return IntelligencePipeline(
        AttackChainService(cat, CorrelationPolicy()),
        make_prediction_service(),
        RiskService(RiskPolicy(), cat),
        DefenseRecommendationService(DefensePolicy(), cat),
    )


def scenario() -> SyntheticScenario:
    return load_scenario(SCENARIO_PATH)[0]


def scenario_observations(catalog: StaticCatalog | None = None) -> list[Observation]:
    return build_observations(scenario(), catalog or static_catalog(), EvidencePolicy())
