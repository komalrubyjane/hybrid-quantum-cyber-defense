"""LSTM predictor: encoding, shapes, normalisation, determinism, early stopping, checkpoints."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import pytest

from hqc.common.errors import ModelCheckpointNotFoundError
from hqc.prediction import lstm as lstm_mod
from hqc.prediction.base import OutputSpace, check_distribution
from hqc.prediction.dataset import WeightedInstance
from hqc.prediction.lstm import (
    LSTMCheckpointMetadata,
    LSTMConfig,
    LSTMPredictor,
    NextTechniqueLSTM,
    build_training_tensors,
    build_validation_sets,
    encode_context,
    load_checkpoint,
    save_checkpoint,
    train_lstm,
    validation_loss,
)
from hqc.prediction.vocabulary import PAD_TOKEN, UNK_TOKEN, TechniqueVocabulary
from prediction_fixtures import mini_kb, mini_vocabulary

torch = lstm_mod.torch


def cfg(**overrides: Any) -> LSTMConfig:
    base: dict[str, Any] = {
        "embedding_dim": 8,
        "hidden_dim": 8,
        "num_layers": 1,
        "dropout": 0.0,
        "learning_rate": 0.05,
        "weight_decay": 0.0,
        "context_length": 3,
        "batch_size": 4,
        "max_epochs": 6,
        "patience": 2,
        "min_delta": 0.0,
        "seed": 7,
        "num_threads": 1,
    }
    base.update(overrides)
    return LSTMConfig.model_validate(base)


@pytest.fixture(scope="module")
def vocab() -> TechniqueVocabulary:
    return mini_vocabulary(mini_kb())


@pytest.fixture(scope="module")
def space(vocab: TechniqueVocabulary) -> OutputSpace:
    return OutputSpace(vocab)


TRAIN = [
    WeightedInstance(("T1059",), "T1003", 1.0),
    WeightedInstance(("T1059",), "T1003", 0.5),
    WeightedInstance(("T1003",), "T1059", 1.0),
    WeightedInstance(("T1059", "T1003"), "T1059.004", 1.0),
    WeightedInstance((UNK_TOKEN, "T1003"), "T1059.001", 1.0),
]


def test_encode_context_truncates_and_maps_unk(vocab: TechniqueVocabulary) -> None:
    idx = vocab.token_to_index
    assert encode_context(("T1003", "T1059", "T1059.004"), vocab, 2) == [
        idx["T1059"],
        idx["T1059.004"],
    ]
    assert encode_context((UNK_TOKEN, "T9999"), vocab, 5) == [idx[UNK_TOKEN], idx[UNK_TOKEN]]
    with pytest.raises(ValueError):
        encode_context((), vocab, 3)
    with pytest.raises(ValueError):
        encode_context((PAD_TOKEN,), vocab, 3)


def test_future_target_never_in_input(vocab: TechniqueVocabulary, space: OutputSpace) -> None:
    """[T1, T2, T3] -> T4: the encoded input must not contain T4."""
    sequence = ["T1059", "T1003", "T1059.001", "T1059.004"]
    instance = WeightedInstance(tuple(sequence[:3]), sequence[3], 1.0)
    tensors = build_training_tensors([instance], vocab, space, context_length=10)
    row = tensors.tokens[0][: int(tensors.lengths[0])].tolist()
    assert row == [vocab.token_to_index[t] for t in sequence[:3]]
    assert vocab.token_to_index["T1059.004"] not in row
    assert int(tensors.targets[0]) == space.index["T1059.004"]


def test_training_tensors_merge_and_validate(
    vocab: TechniqueVocabulary, space: OutputSpace
) -> None:
    t = build_training_tensors(TRAIN, vocab, space, context_length=1)
    # ("T1059",)->T1003 merged (1.5); (UNK,"T1003") truncated to ("T1003",) -> distinct target.
    assert t.size == 4
    assert sorted(t.weights.tolist()) == [1.0, 1.0, 1.0, 1.5]
    assert int(t.lengths.max()) == 1
    with pytest.raises(ValueError):
        build_training_tensors([WeightedInstance(("T1059",), UNK_TOKEN, 1.0)], vocab, space, 3)


def test_model_shapes_and_deterministic_init(
    vocab: TechniqueVocabulary, space: OutputSpace
) -> None:
    lstm_mod.configure_determinism(cfg())
    a = NextTechniqueLSTM(vocab.size, space.size, cfg())
    lstm_mod.configure_determinism(cfg())
    b = NextTechniqueLSTM(vocab.size, space.size, cfg())
    for (ka, va), (kb, vb) in zip(a.state_dict().items(), b.state_dict().items(), strict=True):
        assert ka == kb and torch.equal(va, vb)
    tokens = torch.tensor([[2, 3, 0], [4, 0, 0]])
    logits = a(tokens, torch.tensor([2, 1]))
    assert tuple(logits.shape) == (2, space.size)  # outputs = active techniques only


def test_training_is_reproducible(vocab: TechniqueVocabulary, space: OutputSpace) -> None:
    data = build_training_tensors(TRAIN, vocab, space, 3)
    r1 = train_lstm(cfg(), data, vocab, space, fixed_epochs=4)
    r2 = train_lstm(cfg(), data, vocab, space, fixed_epochs=4)
    assert [e.train_loss for e in r1.history] == [e.train_loss for e in r2.history]
    for va, vb in zip(r1.model.state_dict().values(), r2.model.state_dict().values(), strict=True):
        assert torch.equal(va, vb)
    assert r1.best_epoch == 4 and len(r1.history) == 4 and r1.best_validation_loss is None


def test_train_argument_contract(vocab: TechniqueVocabulary, space: OutputSpace) -> None:
    data = build_training_tensors(TRAIN, vocab, space, 3)
    vsets = build_validation_sets({"g": [(("T1059",), "T1003")]}, 3)
    with pytest.raises(ValueError):
        train_lstm(cfg(), data, vocab, space)
    with pytest.raises(ValueError):
        train_lstm(cfg(), data, vocab, space, validation=vsets, fixed_epochs=2)
    with pytest.raises(ValueError):
        train_lstm(cfg(), build_training_tensors([], vocab, space, 3), vocab, space, fixed_epochs=1)


def test_early_stopping_uses_validation_loss_only(
    vocab: TechniqueVocabulary, space: OutputSpace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scripted validation losses decide the best epoch, regardless of training loss."""
    scripted = iter([3.0, 2.0, 2.5, 2.6, 2.7, 2.8])
    seen_sets: list[Any] = []

    def fake_validation_loss(model: Any, sets: Any, *args: Any) -> float:
        seen_sets.append(sets)
        return next(scripted)

    monkeypatch.setattr(lstm_mod, "validation_loss", fake_validation_loss)
    data = build_training_tensors(TRAIN, vocab, space, 3)
    vsets = build_validation_sets({"val": [(("T1003",), "T1059")]}, 3)
    result = train_lstm(cfg(patience=2), data, vocab, space, validation=vsets)
    assert result.best_epoch == 2 and result.best_validation_loss == 2.0
    assert len(result.history) == 4  # stopped after 2 epochs without improvement
    assert all(s is vsets for s in seen_sets)  # only the validation sets were evaluated


def test_real_validation_loss_is_group_macro(
    vocab: TechniqueVocabulary, space: OutputSpace
) -> None:
    data = build_training_tensors(TRAIN, vocab, space, 3)
    model = train_lstm(cfg(), data, vocab, space, fixed_epochs=2).model
    sets = build_validation_sets(
        {"a": [(("T1059",), "T1003")] * 2, "b": [(("T1003",), "T1059")], "empty": []}, 3
    )
    assert [s.group for s in sets] == ["a", "b"]
    predictor = LSTMPredictor(model, cfg(), vocab, space)
    expected = (
        -math.log(predictor.prob(("T1059",), "T1003"))
        - math.log(predictor.prob(("T1003",), "T1059"))
    ) / 2
    assert validation_loss(model, sets, vocab, space, 3) == pytest.approx(expected)


def test_predictor_distribution(vocab: TechniqueVocabulary, space: OutputSpace) -> None:
    data = build_training_tensors(TRAIN, vocab, space, 3)
    model = train_lstm(cfg(), data, vocab, space, fixed_epochs=3).model
    predictor = LSTMPredictor(model, cfg(), vocab, space)
    dist = predictor.distribution(("T1059", UNK_TOKEN))
    check_distribution(dist, space)  # exactly the 4 active techniques: no PAD / UNK outputs
    assert len(dist) == space.size == 4
    assert predictor.prob(("T1059", UNK_TOKEN), "T1003") == dist[space.index["T1003"]]
    assert predictor.context_window == 3 and predictor.name == "LSTM"
    predictor.prefetch([("T1059",), ("T1003",)])
    assert predictor.distribution(("T1059",)) == predictor.distribution(("T1003", "T1059")[-1:])
    with pytest.raises(KeyError):
        predictor.prob(("T1059",), UNK_TOKEN)
    other = OutputSpace(TechniqueVocabulary.from_technique_ids(["T1059"], vocab.attack_version))
    with pytest.raises(ValueError):
        LSTMPredictor(model, cfg(), vocab, other)


def test_checkpoint_round_trip(
    tmp_path: Path, vocab: TechniqueVocabulary, space: OutputSpace
) -> None:
    trained = train_lstm(
        cfg(), build_training_tensors(TRAIN, vocab, space, 3), vocab, space, fixed_epochs=2
    )
    meta = LSTMCheckpointMetadata(
        attack_version=vocab.attack_version,
        vocabulary_version=vocab.vocabulary_version,
        output_size=space.size,
        training_groups=["a", "b"],
        validation_groups=["c"],
        test_group="d",
        hyperparameters=cfg(),
        seed=7,
        best_epoch=2,
        epochs_trained=2,
        selection="test",
        package_versions={"torch": torch.__version__},
        git_commit="c" * 40,
        git_dirty=True,
    )
    path = tmp_path / "ckpt" / "fold-00"
    save_checkpoint(trained.model, meta, path)
    assert path.with_suffix(".pt").is_file() and path.with_suffix(".json").is_file()
    model, loaded = load_checkpoint(path, vocab, space)
    assert loaded == meta and loaded.test_group == "d" and loaded.git_dirty is True
    a = LSTMPredictor(trained.model, cfg(), vocab, space).distribution(("T1059",))
    b = LSTMPredictor(model, cfg(), vocab, space).distribution(("T1059",))
    assert a == b
    with pytest.raises(ModelCheckpointNotFoundError):
        load_checkpoint(tmp_path / "missing", vocab, space)
    other = TechniqueVocabulary.from_technique_ids(["T1059"], vocab.attack_version)
    with pytest.raises(ValueError):
        load_checkpoint(path, other, OutputSpace(other))
