"""Deterministic technique vocabulary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import stix_builders as sb
from hqc.common.errors import InvalidTechniqueIdError, MalformedSourceDataError
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.stix_parser import parse_attack_bundle
from hqc.prediction.vocabulary import PAD_TOKEN, UNK_TOKEN, TechniqueVocabulary

IDS = ["T1059.004", "T1003", "T1566.001", "T1059"]


@pytest.fixture
def vocab() -> TechniqueVocabulary:
    return TechniqueVocabulary.from_technique_ids(IDS, attack_version="19.2")


def test_layout_and_special_tokens(vocab: TechniqueVocabulary) -> None:
    assert vocab.index_to_token == [
        PAD_TOKEN,
        UNK_TOKEN,
        "T1003",
        "T1059",
        "T1059.004",
        "T1566.001",
    ]
    assert vocab.special_tokens == {"<PAD>": 0, "<UNK>": 1}
    assert (vocab.pad_index, vocab.unk_index, vocab.size) == (0, 1, 6)
    assert vocab.token_to_index["T1059.004"] == 4
    assert vocab.vocabulary_version.startswith("v1-attack-19.2-")
    assert vocab.vocabulary_version.endswith(vocab.content_sha256[:12])
    assert not any(" " in t for t in vocab.index_to_token)  # no technique-name tokens


def test_deterministic_regardless_of_input_order_and_duplicates() -> None:
    a = TechniqueVocabulary.from_technique_ids(IDS, "19.2")
    b = TechniqueVocabulary.from_technique_ids([*reversed(IDS), "T1003"], "19.2")
    assert a == b
    assert a.model_dump_json() == b.model_dump_json()


def test_version_changes_with_content_or_attack_version(vocab: TechniqueVocabulary) -> None:
    other = TechniqueVocabulary.from_technique_ids([*IDS, "T1041"], "19.2")
    assert other.vocabulary_version != vocab.vocabulary_version
    assert TechniqueVocabulary.from_technique_ids(IDS, "19.1").vocabulary_version != (
        vocab.vocabulary_version
    )


def test_encode_preserves_sequence_order(vocab: TechniqueVocabulary) -> None:
    seq = ["T1566.001", "T1059.004", "T1003", "T1059.004"]
    encoded = vocab.encode(seq)
    assert encoded == [5, 4, 2, 4]
    assert vocab.decode(encoded) == seq


def test_unknown_and_malformed_ids(vocab: TechniqueVocabulary) -> None:
    assert vocab.index_of("T1486") == vocab.unk_index
    assert "T1486" not in vocab and "T1003" in vocab and 5 not in vocab
    with pytest.raises(InvalidTechniqueIdError):
        vocab.index_of("T1486", on_unknown="error")
    with pytest.raises(InvalidTechniqueIdError):
        vocab.encode(["Command and Scripting Interpreter"])
    with pytest.raises(InvalidTechniqueIdError):
        TechniqueVocabulary.from_technique_ids(["not-an-id"], "19.2")


@pytest.mark.parametrize("bad", [[-1], [6], [99]])
def test_decode_rejects_out_of_range(vocab: TechniqueVocabulary, bad: list[int]) -> None:
    with pytest.raises(ValueError):
        vocab.decode(bad)


def test_vocabulary_is_immutable(vocab: TechniqueVocabulary) -> None:
    with pytest.raises(ValidationError):
        vocab.attack_version = "1.0"


def test_from_knowledge_base_uses_only_active_techniques() -> None:
    kb = AttackKnowledgeBase.from_data(parse_attack_bundle(sb.attack_bundle(), sb.TEST_VERSION))
    vocab = TechniqueVocabulary.from_knowledge_base(kb)
    assert vocab.index_to_token[2:] == ["T1003", "T1059", "T1059.001", "T1059.004"]
    assert "T1086" not in vocab and "T1999" not in vocab  # revoked / deprecated
    assert vocab.attack_version == sb.TEST_VERSION


def test_save_load_round_trip(tmp_path: Path, vocab: TechniqueVocabulary) -> None:
    path = tmp_path / "v.json"
    vocab.save(path)
    assert TechniqueVocabulary.load(path, expected_attack_version="19.2") == vocab
    with pytest.raises(MalformedSourceDataError, match="expected"):
        TechniqueVocabulary.load(path, expected_attack_version="18.0")


@pytest.mark.parametrize(
    "tamper",
    [
        lambda d: d["token_to_index"].update({"T1003": 3}),
        lambda d: d["index_to_token"].reverse(),
        lambda d: d.update(content_sha256="0" * 64),
        lambda d: d.update(vocabulary_version="v1-attack-19.2-wrong"),
        lambda d: d["special_tokens"].update({"<PAD>": 1}),
        lambda d: d.update(scope="something-else"),
    ],
)
def test_tampered_files_rejected(tmp_path: Path, vocab: TechniqueVocabulary, tamper) -> None:  # type: ignore[no-untyped-def]
    data = json.loads(vocab.model_dump_json())
    tamper(data)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data))
    with pytest.raises(MalformedSourceDataError):
        TechniqueVocabulary.load(path)


def test_unsorted_technique_tokens_rejected(vocab: TechniqueVocabulary) -> None:
    data = json.loads(vocab.model_dump_json())
    tokens = data["index_to_token"]
    tokens[2], tokens[3] = tokens[3], tokens[2]
    data["token_to_index"] = {t: i for i, t in enumerate(tokens)}
    with pytest.raises(ValidationError, match="ascending"):
        TechniqueVocabulary.model_validate(data)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(MalformedSourceDataError):
        TechniqueVocabulary.load(tmp_path / "nope.json")
