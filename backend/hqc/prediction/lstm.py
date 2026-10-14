"""Small LSTM next-technique predictor (PyTorch, CPU, deterministic).

Input: the last ``context_length`` vocabulary indices of the observed prefix (oldest
first; ``<UNK>`` allowed, ``<PAD>`` only as padding). The target is never part of the
input: examples are built from ``PredictionInstance.prefix`` only.
Output: a softmax over the OUTPUT SPACE (the 697 active techniques), so ``<PAD>`` and
``<UNK>`` can never be predicted.

Training uses weighted cross-entropy with document-normalised weights (the Milestone 3
primary policy). Identical (context, target) examples are merged by summing weights,
which leaves the weighted loss unchanged. Early stopping uses ONLY the supplied
validation sets; with no validation set, training runs a fixed number of epochs.
"""

from __future__ import annotations

import copy
import math
import warnings
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import Field

from hqc.common.errors import ModelCheckpointNotFoundError
from hqc.common.schemas.base import HQCModel, NonEmptyStr, UTCDatetime, utc_now
from hqc.prediction.base import Context, OutputSpace
from hqc.prediction.dataset import WeightedInstance
from hqc.prediction.vocabulary import PAD_TOKEN, UNK_TOKEN, TechniqueVocabulary

with warnings.catch_warnings():  # torch warns when NumPy is absent; NumPy is not used
    warnings.simplefilter("ignore", UserWarning)
    import torch
    from torch import nn

LSTM_NAME = "LSTM"
ContextKey = tuple[str, ...]


class LSTMConfig(HQCModel):
    """Architecture and optimisation settings (one candidate)."""

    embedding_dim: int = Field(ge=4, le=256)
    hidden_dim: int = Field(ge=4, le=512)
    num_layers: int = Field(ge=1, le=3)
    dropout: float = Field(ge=0.0, lt=1.0)
    learning_rate: float = Field(gt=0.0, lt=1.0)
    weight_decay: float = Field(ge=0.0)
    context_length: int = Field(ge=1, le=64)
    batch_size: int = Field(ge=1, le=4096)
    max_epochs: int = Field(ge=1, le=500)
    patience: int = Field(ge=1)
    min_delta: float = Field(ge=0.0)
    seed: int = Field(ge=0)
    num_threads: int = Field(ge=1, le=64)


def configure_determinism(config: LSTMConfig) -> None:
    """Seed torch and force deterministic CPU kernels."""
    torch.manual_seed(config.seed)
    torch.set_num_threads(config.num_threads)
    torch.use_deterministic_algorithms(True)


def encode_context(prefix: Context, vocabulary: TechniqueVocabulary, length: int) -> list[int]:
    """Indices of the last ``length`` prefix tokens. Never includes anything after the prefix."""
    tokens = list(prefix[-length:])
    if not tokens:
        raise ValueError("A prediction needs at least one observed technique")
    if PAD_TOKEN in tokens:
        raise ValueError("<PAD> cannot appear in an observed prefix")
    return [vocabulary.token_to_index[UNK_TOKEN if t not in vocabulary else t] for t in tokens]


class NextTechniqueLSTM(nn.Module):
    """Embedding -> LSTM -> dropout -> linear over the output space."""

    def __init__(self, vocab_size: int, output_size: int, config: LSTMConfig) -> None:
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, config.embedding_dim, padding_idx=0)
        self.lstm = nn.LSTM(
            config.embedding_dim,
            config.hidden_dim,
            num_layers=config.num_layers,
            batch_first=True,
            dropout=config.dropout if config.num_layers > 1 else 0.0,
        )
        self.dropout = nn.Dropout(config.dropout)
        self.output = nn.Linear(config.hidden_dim, output_size)

    def forward(self, tokens: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        """``tokens``: (batch, time) right-padded with 0; returns logits (batch, outputs)."""
        packed = nn.utils.rnn.pack_padded_sequence(
            self.embedding(tokens), lengths.cpu(), batch_first=True, enforce_sorted=False
        )
        _, (hidden, _) = self.lstm(packed)
        logits: torch.Tensor = self.output(self.dropout(hidden[-1]))
        return logits


# --- tensors ------------------------------------------------------------------------------


@dataclass
class ExampleTensors:
    tokens: torch.Tensor
    lengths: torch.Tensor
    targets: torch.Tensor
    weights: torch.Tensor

    @property
    def size(self) -> int:
        return int(self.targets.shape[0])


def _pad(rows: Sequence[list[int]], length: int) -> tuple[torch.Tensor, torch.Tensor]:
    tokens = torch.zeros(len(rows), length, dtype=torch.long)
    lengths = torch.zeros(len(rows), dtype=torch.long)
    for r, ids in enumerate(rows):
        tokens[r, : len(ids)] = torch.tensor(ids, dtype=torch.long)
        lengths[r] = len(ids)
    return tokens, lengths


def build_training_tensors(
    instances: Sequence[WeightedInstance],
    vocabulary: TechniqueVocabulary,
    space: OutputSpace,
    context_length: int,
) -> ExampleTensors:
    """Merge identical (truncated context, target) examples by summing weights."""
    merged: dict[tuple[ContextKey, str], float] = defaultdict(float)
    for instance in instances:
        if instance.target not in space:
            raise ValueError(f"Target {instance.target} is not a predictable technique")
        merged[(tuple(instance.prefix[-context_length:]), instance.target)] += instance.weight
    keys = sorted(merged, key=lambda k: (k[0], space.index[k[1]]))  # deterministic order
    tokens, lengths = _pad(
        [encode_context(k[0], vocabulary, context_length) for k in keys], context_length
    )
    return ExampleTensors(
        tokens=tokens,
        lengths=lengths,
        targets=torch.tensor([space.index[k[1]] for k in keys], dtype=torch.long),
        weights=torch.tensor([merged[k] for k in keys], dtype=torch.float64).float(),
    )


@dataclass
class ValidationSet:
    """Unique evaluation instances of one validation group, counted per (context, target)."""

    group: str
    pairs: Counter[tuple[ContextKey, str]]


def build_validation_sets(
    instances_by_group: Mapping[str, Sequence[tuple[Sequence[str], str]]], context_length: int
) -> list[ValidationSet]:
    return [
        ValidationSet(
            group=g,
            pairs=Counter((tuple(prefix[-context_length:]), target) for prefix, target in items),
        )
        for g, items in sorted(instances_by_group.items())
        if items
    ]


# --- training ------------------------------------------------------------------------------


class EpochRecord(HQCModel):
    epoch: int
    train_loss: float
    validation_loss: float | None = None


@dataclass
class TrainedLSTM:
    model: NextTechniqueLSTM
    config: LSTMConfig
    history: list[EpochRecord] = field(default_factory=list)
    best_epoch: int = 0
    best_validation_loss: float | None = None


def _batch_probabilities(
    model: NextTechniqueLSTM,
    contexts: Sequence[ContextKey],
    vocabulary: TechniqueVocabulary,
    length: int,
) -> torch.Tensor:
    tokens, lengths = _pad([encode_context(c, vocabulary, length) for c in contexts], length)
    model.eval()
    with torch.no_grad():
        return torch.softmax(model(tokens, lengths).double(), dim=-1)


def validation_loss(
    model: NextTechniqueLSTM,
    sets: Sequence[ValidationSet],
    vocabulary: TechniqueVocabulary,
    space: OutputSpace,
    length: int,
) -> float:
    """Mean over groups of the per-group mean log loss (unique instances count once)."""
    per_group: list[float] = []
    for vset in sets:
        keys = list(vset.pairs)
        contexts = sorted({k[0] for k in keys})
        probs = _batch_probabilities(model, contexts, vocabulary, length)
        row = {c: i for i, c in enumerate(contexts)}
        total = sum(vset.pairs.values())
        loss = math.fsum(
            n * -math.log(float(probs[row[ctx], space.index[target]]))
            for (ctx, target), n in vset.pairs.items()
        )
        per_group.append(loss / total)
    return math.fsum(per_group) / len(per_group)


def train_lstm(
    config: LSTMConfig,
    train: ExampleTensors,
    vocabulary: TechniqueVocabulary,
    space: OutputSpace,
    validation: Sequence[ValidationSet] | None = None,
    fixed_epochs: int | None = None,
) -> TrainedLSTM:
    """Train with early stopping on ``validation`` or for exactly ``fixed_epochs``."""
    if (validation is None) == (fixed_epochs is None):
        raise ValueError("Provide exactly one of validation (early stopping) or fixed_epochs")
    if train.size == 0:
        raise ValueError("No training examples")
    configure_determinism(config)
    model = NextTechniqueLSTM(vocabulary.size, space.size, config)
    optimizer = torch.optim.Adam(
        model.parameters(), lr=config.learning_rate, weight_decay=config.weight_decay
    )
    generator = torch.Generator().manual_seed(config.seed)
    epochs = fixed_epochs if fixed_epochs is not None else config.max_epochs
    result = TrainedLSTM(model=model, config=config)
    best_state = copy.deepcopy(model.state_dict())
    best_loss = math.inf
    stale = 0
    for epoch in range(1, epochs + 1):
        model.train()
        order = torch.randperm(train.size, generator=generator)
        loss_sum = 0.0
        weight_sum = 0.0
        for start in range(0, train.size, config.batch_size):
            idx = order[start : start + config.batch_size]
            logits = model(train.tokens[idx], train.lengths[idx])
            per_example = nn.functional.cross_entropy(logits, train.targets[idx], reduction="none")
            weights = train.weights[idx]
            loss = (per_example * weights).sum() / weights.sum()
            optimizer.zero_grad()
            loss.backward()  # type: ignore[no-untyped-call]
            optimizer.step()
            loss_sum += float((per_example.detach() * weights).sum())
            weight_sum += float(weights.sum())
        record = EpochRecord(epoch=epoch, train_loss=loss_sum / weight_sum)
        if validation is not None:
            record.validation_loss = validation_loss(
                model, validation, vocabulary, space, config.context_length
            )
            if record.validation_loss < best_loss - config.min_delta:
                best_loss = record.validation_loss
                best_state = copy.deepcopy(model.state_dict())
                result.best_epoch = epoch
                stale = 0
            else:
                stale += 1
        result.history.append(record)
        if validation is not None and stale >= config.patience:
            break
    if validation is not None:
        model.load_state_dict(best_state)
        result.best_validation_loss = best_loss
    else:
        result.best_epoch = epochs
    model.eval()
    return result


# --- predictor ------------------------------------------------------------------------------


class LSTMPredictor:
    """Wraps a trained network as a :class:`NextTechniqueModel` (cached per context)."""

    def __init__(
        self,
        model: NextTechniqueLSTM,
        config: LSTMConfig,
        vocabulary: TechniqueVocabulary,
        space: OutputSpace,
        name: str = LSTM_NAME,
    ) -> None:
        if space.vocabulary_version != vocabulary.vocabulary_version:
            raise ValueError("Output space and vocabulary versions differ")
        self._model = model
        self.config = config
        self._vocabulary = vocabulary
        self._space = space
        self._name = name
        self._cache: dict[ContextKey, list[float]] = {}

    @property
    def name(self) -> str:
        return self._name

    @property
    def space(self) -> OutputSpace:
        return self._space

    @property
    def context_window(self) -> int:
        return self.config.context_length

    def prefetch(self, contexts: Sequence[Context]) -> None:
        """Batch-compute distributions for many contexts (performance only)."""
        keys = sorted(
            {tuple(c[-self.config.context_length :]) for c in contexts} - set(self._cache)
        )
        if not keys:
            return
        probs = _batch_probabilities(
            self._model, keys, self._vocabulary, self.config.context_length
        )
        for i, key in enumerate(keys):
            row = probs[i]
            self._cache[key] = [float(p) for p in (row / row.sum()).tolist()]

    def distribution(self, context: Context) -> list[float]:
        key = tuple(context[-self.config.context_length :])
        if key not in self._cache:
            self.prefetch([key])
        return list(self._cache[key])

    def prob(self, context: Context, target: str) -> float:
        return self.distribution(context)[self._space.position(target)]


# --- checkpoints ---------------------------------------------------------------------------


class LSTMCheckpointMetadata(HQCModel):
    model_type: NonEmptyStr = "lstm-next-technique"
    attack_version: NonEmptyStr
    vocabulary_version: NonEmptyStr
    output_size: int
    training_groups: list[str]
    validation_groups: list[str]
    test_group: str | None
    hyperparameters: LSTMConfig
    seed: int
    trained_at: UTCDatetime = Field(default_factory=utc_now)
    best_epoch: int
    epochs_trained: int
    selection: NonEmptyStr = Field(
        description="How the configuration / epoch count were chosen (inner validation only)."
    )
    package_versions: dict[str, str]
    git_commit: str | None
    git_dirty: bool | None
    evaluation_run_id: str | None = None


def save_checkpoint(model: NextTechniqueLSTM, metadata: LSTMCheckpointMetadata, path: Path) -> None:
    """Writes ``<path>.pt`` (state dict) and ``<path>.json`` (metadata)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), path.with_suffix(".pt"))
    path.with_suffix(".json").write_text(
        metadata.model_dump_json(indent=1) + "\n", encoding="utf-8"
    )


def load_checkpoint(
    path: Path, vocabulary: TechniqueVocabulary, space: OutputSpace
) -> tuple[NextTechniqueLSTM, LSTMCheckpointMetadata]:
    meta_path, state_path = path.with_suffix(".json"), path.with_suffix(".pt")
    if not meta_path.is_file() or not state_path.is_file():
        raise ModelCheckpointNotFoundError(f"LSTM checkpoint incomplete or missing at {path}")
    metadata = LSTMCheckpointMetadata.model_validate_json(meta_path.read_text(encoding="utf-8"))
    if metadata.vocabulary_version != vocabulary.vocabulary_version:
        raise ValueError("Checkpoint was trained with a different vocabulary")
    model = NextTechniqueLSTM(vocabulary.size, space.size, metadata.hyperparameters)
    model.load_state_dict(torch.load(state_path, weights_only=True))
    model.eval()
    return model, metadata
