"""Small hand-built corpus for prediction tests (TEST FIXTURE, not real CTI).

Built through the real Milestone 2 code path (STIX flows -> build_corpus) on the mini
ATT&CK-like KB from ``stix_builders`` (active: T1003, T1059, T1059.001, T1059.004;
revoked T1086 -> T1059.001; deprecated T1999).

Documents / groups:
- "Alpha" and "Alpha (TA2)" share group "Alpha".
    Alpha:       T1059 -> T1086(revoked) -> T1003 -> T1003   (repeat)
    Alpha (TA2): T1059 -> T1003
- "Beta": T1003 -> T0866(unknown) -> T1059 -> T1999(deprecated)
- "Gamma": branching with a shared prefix:
    T1059 -> T1003 -> T1059.004
    T1059 -> T1003 -> T1059.001
- "Delta": single technique T1059 (no prediction instances).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import stix_builders as sb
from hqc.evaluation.chain_prediction import ExperimentConfig, ModelSpec
from hqc.mitre.attack_flow_corpus import AttackFlowCorpus, build_corpus
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.stix_parser import parse_attack_bundle
from hqc.prediction.base import OutputSpace
from hqc.prediction.dataset import PredictionDataset, build_dataset
from hqc.prediction.markov import MarkovParams
from hqc.prediction.vocabulary import TechniqueVocabulary


def chain(ids: list[str]) -> list[dict[str, object]]:
    return [
        sb.action(f"n{i}", t, [f"n{i + 1}"] if i + 1 < len(ids) else None)
        for i, t in enumerate(ids)
    ]


FLOWS: dict[str, dict[str, object]] = {
    "Alpha": sb.flow_bundle(chain(["T1059", "T1086", "T1003", "T1003"]), ["n0"], name="Alpha"),
    "Alpha (TA2)": sb.flow_bundle(chain(["T1059", "T1003"]), ["n0"], name="Alpha (TA2)"),
    "Beta": sb.flow_bundle(chain(["T1003", "T0866", "T1059", "T1999"]), ["n0"], name="Beta"),
    "Gamma": sb.flow_bundle(
        [
            sb.action("a", "T1059", ["b"]),
            sb.action("b", "T1003", ["c", "d"]),
            sb.action("c", "T1059.004"),
            sb.action("d", "T1059.001"),
        ],
        ["a"],
        name="Gamma",
    ),
    "Delta": sb.flow_bundle(chain(["T1059"]), ["n0"], name="Delta"),
}


def mini_kb() -> AttackKnowledgeBase:
    return AttackKnowledgeBase.from_data(parse_attack_bundle(sb.attack_bundle(), sb.TEST_VERSION))


def mini_vocabulary(kb: AttackKnowledgeBase) -> TechniqueVocabulary:
    return TechniqueVocabulary.from_knowledge_base(kb)


def write_flows(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, bundle in FLOWS.items():
        (directory / f"{name}.json").write_text(json.dumps(bundle))
    return directory


def mini_corpus(tmp_path: Path, kb: AttackKnowledgeBase) -> AttackFlowCorpus:
    return build_corpus(write_flows(tmp_path / "flows"), "test-corpus@1", kb=kb)


def mini_dataset(tmp_path: Path) -> tuple[PredictionDataset, OutputSpace, AttackKnowledgeBase]:
    kb = mini_kb()
    vocabulary = mini_vocabulary(kb)
    dataset = build_dataset(mini_corpus(tmp_path, kb), kb, vocabulary)
    return dataset, OutputSpace(vocabulary), kb


def small_markov_config(**overrides: Any) -> ExperimentConfig:
    """Tiny Milestone 3 config (fast) shared by Milestone 3 and 4 tests."""
    grid1 = [MarkovParams(max_order=1, weights=(1.0,), alpha=a, beta=1.0) for a in (0.5, 5.0)]
    grid2 = [
        MarkovParams(max_order=2, weights=(0.5, 0.5), alpha=a, beta=b)
        for a in (0.5, 5.0)
        for b in (0.1, 10.0)
    ]
    data: dict[str, Any] = {
        "seed": 1,
        "bootstrap_resamples": 200,
        "confidence": 0.95,
        "selection_metric": "log_loss",
        "primary_weighting": "document",
        "ablation_weightings": ["raw", "unique"],
        "models": [
            ModelSpec(name="B0"),
            ModelSpec(
                name="B1",
                grid=[
                    MarkovParams(max_order=0, weights=(), alpha=1.0, beta=b) for b in (0.1, 10.0)
                ],
            ),
            ModelSpec(name="M1", grid=grid1),
            ModelSpec(name="M2", grid=grid2),
        ],
        "comparisons": [("M2", "B1"), ("B1", "B0")],
    }
    data.update(overrides)
    return ExperimentConfig.model_validate(data)
