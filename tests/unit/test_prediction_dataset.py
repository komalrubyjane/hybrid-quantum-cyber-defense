"""Dataset construction: ID cleanup, instances, deduplication, weighting."""

from __future__ import annotations

import math
from collections import defaultdict
from pathlib import Path

import pytest

import stix_builders as sb
from hqc.common.errors import DatasetNotFoundError, MalformedSourceDataError
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.stix_parser import parse_attack_bundle
from hqc.prediction.dataset import (
    IdNormalizer,
    PredictionDataset,
    Weighting,
    build_dataset,
    load_corpus,
)
from hqc.prediction.vocabulary import UNK_TOKEN, TechniqueVocabulary
from prediction_fixtures import mini_corpus, mini_dataset, mini_kb, mini_vocabulary


@pytest.fixture
def ds(tmp_path: Path) -> PredictionDataset:
    return mini_dataset(tmp_path)[0]


def _by_doc(ds: PredictionDataset) -> dict[str, list[tuple[tuple[str, ...], str, int]]]:
    out: dict[str, list[tuple[tuple[str, ...], str, int]]] = defaultdict(list)
    for i in ds.instances:
        out[i.document_id].append((i.prefix, i.target, i.multiplicity))
    return out


def test_revoked_id_replaced_by_kb_successor(ds: PredictionDataset) -> None:
    [record] = ds.stats.remapped_ids
    assert (record.original, record.replacement) == ("T1086", "T1059.001")
    assert record.occurrences == 1 and record.documents == ["Alpha"]
    assert ds.stats.revoked_ids_remapped == 1 and ds.stats.remap_occurrences == 1
    alpha = _by_doc(ds)["Alpha"]
    assert (("T1059",), "T1059.001", 1) in alpha  # the replacement, not T1086
    assert not any("T1086" in p or t == "T1086" for p, t, _ in alpha)


def test_unknown_and_deprecated_ids_become_unk(ds: PredictionDataset) -> None:
    reasons = {u.original: u.reason for u in ds.stats.unknown_ids}
    assert reasons == {"T0866": "not in knowledge base", "T1999": "deprecated"}
    beta = _by_doc(ds)["Beta"]
    # T0866 and T1999 targets are dropped; <UNK> stays in the prefix of the next step.
    assert beta == [(("T1003", UNK_TOKEN), "T1059", 1)]
    assert ds.stats.unk_targets_dropped == 2
    assert all(i.target != UNK_TOKEN for i in ds.instances)


def test_order_repeats_and_first_position(ds: PredictionDataset) -> None:
    alpha = _by_doc(ds)["Alpha"]
    assert [(p, t) for p, t, _ in alpha] == [
        (("T1059",), "T1059.001"),
        (("T1059", "T1059.001"), "T1003"),
        (("T1059", "T1059.001", "T1003"), "T1003"),  # repeat preserved
    ]
    assert all(len(i.prefix) >= 1 for i in ds.instances)  # first technique never a target


def test_duplicate_instances_collapsed_with_multiplicity(ds: PredictionDataset) -> None:
    gamma = _by_doc(ds)["Gamma"]
    assert gamma == [
        (("T1059",), "T1003", 2),  # shared by both branches
        (("T1059", "T1003"), "T1059.004", 1),
        (("T1059", "T1003"), "T1059.001", 1),
    ]
    s = ds.stats
    assert s.raw_instances == 3 + 1 + 1 + 4  # Alpha, Alpha (TA2), Beta, Gamma
    assert s.unique_instances == 8
    assert s.collapsed_duplicates == 1
    assert s.collapse_percentage == pytest.approx(100 / 9, abs=1e-3)


def test_same_prefix_in_different_documents_not_collapsed(ds: PredictionDataset) -> None:
    keys = [(i.prefix, i.target) for i in ds.instances if i.prefix == ("T1059",)]
    docs = {i.document_id for i in ds.instances if i.prefix == ("T1059",) and i.target == "T1003"}
    assert docs == {"Alpha (TA2)", "Gamma"}
    assert len(keys) == 3


def test_groups_and_statistics(ds: PredictionDataset) -> None:
    assert ds.groups == ["Alpha", "Beta", "Delta", "Gamma"]
    assert ds.group_of_document["Alpha (TA2)"] == "Alpha"
    assert ds.stats.groups_without_instances == ["Delta"]
    assert ds.stats.documents == 5 and ds.stats.source_groups == 4
    assert ds.stats.active_techniques == 4
    assert ds.stats.attack_version == sb.TEST_VERSION
    assert set(ds.instances_by_group()) == set(ds.groups)
    assert sum(ds.stats.largest_documents_share.values()) <= 1.0
    assert {d.document_id: d.raw_instances for d in ds.stats.per_document}["Delta"] == 0


def test_weighting_schemes(ds: PredictionDataset) -> None:
    per_doc: dict[str, float] = defaultdict(float)
    for i in ds.instances:
        per_doc[i.document_id] += ds.weight(i, Weighting.DOCUMENT)
    assert all(math.isclose(v, 1.0) for v in per_doc.values())  # each document totals 1
    shared = next(i for i in ds.instances if i.multiplicity == 2)
    assert ds.weight(shared, Weighting.RAW) == 2.0
    assert ds.weight(shared, Weighting.UNIQUE) == 1.0
    assert ds.weight(shared, Weighting.DOCUMENT) == pytest.approx(2 / 4)
    totals = ds.weighting_totals()
    assert totals == {"document": 4.0, "raw": 9.0, "unique": 8.0}
    weighted = ds.weighted(ds.instances, Weighting.RAW)
    assert [w.weight for w in weighted] == [float(i.multiplicity) for i in ds.instances]


def test_processed_corpus_not_modified(tmp_path: Path) -> None:
    kb = mini_kb()
    corpus = mini_corpus(tmp_path, kb)
    before = corpus.model_dump_json()
    build_dataset(corpus, kb, mini_vocabulary(kb))
    assert corpus.model_dump_json() == before


def test_normalizer_rejects_version_mismatch() -> None:
    kb = mini_kb()
    other = TechniqueVocabulary.from_technique_ids(["T1059"], attack_version="19.2")
    with pytest.raises(MalformedSourceDataError):
        IdNormalizer(kb, other)


def test_revoked_without_successor_is_unknown() -> None:
    bundle = sb.attack_bundle()
    bundle["objects"] = [o for o in bundle["objects"] if o["id"] != "relationship--r1"]
    kb = AttackKnowledgeBase.from_data(parse_attack_bundle(bundle, sb.TEST_VERSION))
    norm = IdNormalizer(kb, mini_vocabulary(kb)).normalize("T1086")
    assert (norm.token, norm.kind, norm.reason) == (
        UNK_TOKEN,
        "unknown",
        "revoked without active successor",
    )


def test_load_corpus_errors(tmp_path: Path) -> None:
    with pytest.raises(DatasetNotFoundError):
        load_corpus(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    with pytest.raises(MalformedSourceDataError):
        load_corpus(bad)


def test_empty_corpus_rejected(tmp_path: Path) -> None:
    kb = mini_kb()
    corpus = mini_corpus(tmp_path, kb)
    empty = corpus.model_copy(update={"documents": []})
    with pytest.raises(DatasetNotFoundError):
        build_dataset(empty, kb, mini_vocabulary(kb))
