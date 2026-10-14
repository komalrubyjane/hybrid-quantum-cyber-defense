"""Milestone 4: nested evaluation of LSTM, Markov+LSTM fusion and beam search.

Per outer fold (one held-out source group), using ONLY the outer-training groups:

1. Inner split: deterministic validation groups (``splits.inner_validation_groups``).
2. LSTM: train every pre-registered candidate on the inner-training groups with early
   stopping on the validation groups; select the lowest validation loss.
3. Inner Markov: M1 vs M2 tuned by inner LOGO over the inner-training groups.
4. Fusion alpha: chosen on the validation groups (inner LSTM + inner Markov).
5. Final models on ALL outer-training groups: LSTM retrained for the selected best
   epoch; Markov (M1/M2, inner-LOGO tuned); B1 (for beam-search reference).
6. Single evaluation on the outer test group: single-step metrics, a REPORT-ONLY test
   alpha sweep, and beam-search multi-step metrics.

B0/B1/M1/M2 are recomputed with the Milestone 3 code on the same instances and checked
against the stored Milestone 3 run.
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError

from hqc.common.errors import ConfigurationError, DataLeakageError
from hqc.common.schemas.base import HQCModel, NonEmptyStr
from hqc.evaluation.chain_prediction import (
    ComparisonResult,
    ExperimentConfig,
    MetricSummary,
    ModelSpec,
    build_group_data,
    fit_model,
    load_experiment_config,
    run_experiment,
)
from hqc.evaluation.metrics import (
    METRIC_NAMES,
    InstanceScore,
    paired_difference,
    score_distribution,
    summarize,
)
from hqc.evaluation.multistep import (
    MultiStepBuild,
    MultiStepScore,
    build_multistep_instances,
    multistep_metric_names,
    score_multistep,
)
from hqc.evaluation.splits import (
    Fold,
    assert_disjoint,
    inner_validation_groups,
    leave_one_group_out,
)
from hqc.evaluation.tuning import GroupData, tune
from hqc.prediction.base import NextTechniqueModel, OutputSpace
from hqc.prediction.dataset import PredictionDataset, PredictionInstance, Weighting
from hqc.prediction.fusion import HybridModel
from hqc.prediction.lstm import (
    EpochRecord,
    LSTMConfig,
    LSTMPredictor,
    TrainedLSTM,
    build_training_tensors,
    build_validation_sets,
    train_lstm,
)
from hqc.prediction.markov import InterpolatedMarkovModel, MarkovCounts, MarkovParams
from hqc.prediction.vocabulary import TechniqueVocabulary

MARKOV_SELECTED = "MARKOV"
LSTM = "LSTM"
HYBRID = "HYBRID"
BASELINE_MODELS = ("B0", "B1", "M1", "M2")
NEW_MODELS = (MARKOV_SELECTED, LSTM, HYBRID)
MARKOV_COMPONENTS = ("M1", "M2")

# --- configuration --------------------------------------------------------------------------


class InnerValidationConfig(HQCModel):
    fraction: float = Field(gt=0.0, lt=1.0)
    min_groups: int = Field(ge=1)


class BeamConfig(HQCModel):
    beam_width: int = Field(ge=1)
    horizons: list[int] = Field(min_length=1)
    hit_ks: list[int] = Field(min_length=1)
    models: list[NonEmptyStr]


class SequenceConfig(HQCModel):
    seed: int = Field(ge=0)
    bootstrap_resamples: int = Field(ge=100)
    confidence: float = Field(gt=0.0, lt=1.0)
    weighting: Weighting
    markov_config: NonEmptyStr
    reference_run: str | None = None
    inner_validation: InnerValidationConfig
    lstm_candidates: list[LSTMConfig] = Field(min_length=1)
    fusion_alphas: list[float] = Field(min_length=2)
    beam_search: BeamConfig
    comparisons: list[tuple[str, str]]


def load_sequence_config(path: Path, project_root: Path) -> tuple[SequenceConfig, ExperimentConfig]:
    """Load the Milestone 4 config and the referenced Milestone 3 (Markov) config."""
    try:
        raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
        lstm = raw.pop("lstm")
        shared = {**lstm["shared"], "seed": raw["seed"]}
        raw["lstm_candidates"] = [{**shared, **c} for c in lstm["candidates"]]
        config = SequenceConfig.model_validate(raw)
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValidationError) as exc:
        raise ConfigurationError(f"Invalid sequence config {path}: {exc}") from exc
    if (
        any(not 0.0 <= a <= 1.0 for a in config.fusion_alphas)
        or 0.0 not in config.fusion_alphas
        or (1.0 not in config.fusion_alphas)
    ):
        raise ConfigurationError("fusion_alphas must lie in [0, 1] and include 0 and 1")
    if max(config.beam_search.hit_ks) > config.beam_search.beam_width:
        raise ConfigurationError("hit_ks cannot exceed beam_width")
    markov = load_experiment_config(project_root / config.markov_config, primary=config.weighting)
    markov = markov.model_copy(update={"ablation_weightings": []})
    names = {m.name for m in markov.models}
    if not set(MARKOV_COMPONENTS) | {"B1"} <= names:
        raise ConfigurationError("Markov config must define B1, M1 and M2")
    known = set(BASELINE_MODELS) | set(NEW_MODELS)
    for a, b in config.comparisons:
        if a not in known or b not in known:
            raise ConfigurationError(f"Unknown model in comparison {a} vs {b}")
    if not set(config.beam_search.models) <= {"B1", *NEW_MODELS}:
        raise ConfigurationError("beam_search.models must be among B1, MARKOV, LSTM, HYBRID")
    return config, markov


# --- results --------------------------------------------------------------------------------


class CandidateRecord(HQCModel):
    index: int
    config: LSTMConfig
    best_epoch: int
    epochs_run: int
    best_validation_loss: float


class FoldRecord(HQCModel):
    fold_id: NonEmptyStr
    test_group: NonEmptyStr
    train_groups: list[str]
    inner_train_groups: list[str]
    validation_groups: list[str]
    n_test_instances: int
    candidates: list[CandidateRecord] = Field(default_factory=list)
    selected_candidate: int | None = None
    final_epochs: int | None = None
    inner_markov: str | None = None
    final_markov: str | None = None
    final_markov_params: MarkovParams | None = None
    final_b1_params: MarkovParams | None = None
    alpha_validation_loss: dict[str, float] = Field(default_factory=dict)
    selected_alpha: float | None = None
    checkpoint: str | None = None
    seconds: float = 0.0


class ModelSummary(HQCModel):
    model: NonEmptyStr
    macro: dict[str, MetricSummary]
    micro: dict[str, float]
    per_group: dict[str, dict[str, float]]
    per_group_instances: dict[str, int]


class MultiStepSummary(ModelSummary):
    horizon: int


@dataclass(frozen=True)
class SingleStepRecord:
    instance: PredictionInstance
    fold_id: str
    model: str
    score: InstanceScore


@dataclass
class FoldOutcome:
    record: FoldRecord
    scores: dict[str, list[InstanceScore]]
    alpha_sweep: dict[float, list[InstanceScore]]
    multistep: dict[tuple[str, int], list[MultiStepScore]]
    predictions: list[SingleStepRecord]
    histories: dict[str, list[EpochRecord]]


@dataclass
class SequenceExperimentResult:
    folds: list[Fold]
    fold_records: list[FoldRecord]
    single_step: list[ModelSummary]
    comparisons: list[ComparisonResult]
    alpha_sweep: dict[str, dict[str, MetricSummary]]
    multistep: list[MultiStepSummary]
    multistep_builds: dict[int, MultiStepBuild]
    baseline_reproduction: dict[str, float | None]
    predictions: list[SingleStepRecord]
    multistep_predictions: dict[tuple[str, int], list[MultiStepScore]]
    histories: dict[str, dict[str, list[EpochRecord]]]
    skipped_folds: list[str]
    seconds: float = 0.0
    notes: list[str] = field(default_factory=list)


ProgressCallback = Callable[[str], None]
CheckpointWriter = Callable[[Fold, FoldRecord, TrainedLSTM], str]

# --- helpers --------------------------------------------------------------------------------


def select_markov(
    specs: Sequence[ModelSpec], train_data: Mapping[str, GroupData], space: OutputSpace
) -> tuple[InterpolatedMarkovModel, str, MarkovParams]:
    """Pick M1 or M2 by inner-LOGO log loss (ties / no score -> the simpler M1)."""
    best: tuple[float, int, str, MarkovParams] | None = None
    for order, spec in enumerate(specs):
        tuning = tune(spec.grid, train_data, space, spec.name)
        score = min(tuning.candidate_scores)
        key = (math.inf if math.isnan(score) else score, order, spec.name, tuning.selected)
        if best is None or key[:2] < best[:2]:
            best = key
    assert best is not None
    _, _, name, params = best
    counts = MarkovCounts.merge([d.counts for d in train_data.values()])
    return InterpolatedMarkovModel(counts, params, space, MARKOV_SELECTED), name, params


def group_mean_log_loss(
    probability: Callable[[tuple[str, ...], str], float],
    instances_by_group: Mapping[str, Sequence[PredictionInstance]],
) -> float:
    per_group = []
    for items in instances_by_group.values():
        if items:
            per_group.append(
                math.fsum(-math.log(probability(i.prefix, i.target)) for i in items) / len(items)
            )
    return math.fsum(per_group) / len(per_group)


def _score_model(
    model: NextTechniqueModel,
    instances: Sequence[PredictionInstance],
    window: int,
    space: OutputSpace,
    tactics: Mapping[str, Sequence[str]],
) -> list[InstanceScore]:
    cache: dict[tuple[tuple[str, ...], str], InstanceScore] = {}
    out = []
    for inst in instances:
        key = (inst.prefix[-window:], inst.target)
        if key not in cache:
            cache[key] = score_distribution(
                model.distribution(inst.prefix), space, inst.target, tactics
            )
        out.append(cache[key])
    return out


def summarize_rows(
    name: str,
    rows_by_group: Mapping[str, Sequence[Mapping[str, float]]],
    metrics: Sequence[str],
    resamples: int,
    seed: int,
) -> tuple[dict[str, MetricSummary], dict[str, float], dict[str, dict[str, float]], dict[str, int]]:
    per_group = {
        g: {m: math.fsum(r[m] for r in rows) / len(rows) for m in metrics}
        for g, rows in sorted(rows_by_group.items())
        if rows
    }
    every = [r for rows in rows_by_group.values() for r in rows]
    macro = {}
    for m in metrics:
        s = summarize([per_group[g][m] for g in per_group], resamples, seed)
        macro[m] = MetricSummary(
            mean=s.mean, std=s.std, ci_low=s.ci_low, ci_high=s.ci_high, n_groups=s.n
        )
    micro = {m: math.fsum(r[m] for r in every) / len(every) for m in metrics}
    return macro, micro, per_group, {g: len(r) for g, r in sorted(rows_by_group.items()) if r}


# --- one fold ------------------------------------------------------------------------------


def run_fold(
    fold: Fold,
    dataset: PredictionDataset,
    by_group: Mapping[str, Sequence[PredictionInstance]],
    group_data: Mapping[str, GroupData],
    vocabulary: TechniqueVocabulary,
    space: OutputSpace,
    tactics: Mapping[str, Sequence[str]],
    config: SequenceConfig,
    markov_config: ExperimentConfig,
    builds: Mapping[int, MultiStepBuild],
    checkpoint_writer: CheckpointWriter | None = None,
) -> FoldOutcome:
    started = time.perf_counter()
    assert_disjoint(fold)
    test = list(by_group[fold.test_group])
    train_groups = [g for g in fold.train_groups if by_group.get(g)]
    if fold.test_group in train_groups:
        raise DataLeakageError(f"{fold.fold_id}: test group among training groups")
    inner_train, validation = inner_validation_groups(
        train_groups,
        config.inner_validation.fraction,
        config.inner_validation.min_groups,
        config.seed,
        fold.fold_id,
    )
    record = FoldRecord(
        fold_id=fold.fold_id,
        test_group=fold.test_group,
        train_groups=list(fold.train_groups),
        inner_train_groups=list(inner_train),
        validation_groups=list(validation),
        n_test_instances=len(test),
    )
    specs = {m.name: m for m in markov_config.models}
    markov_specs = [specs[n] for n in MARKOV_COMPONENTS]
    weighting = config.weighting

    # 2. LSTM candidates: inner training + early stopping on validation groups only.
    inner_instances = [i for g in inner_train for i in by_group[g]]
    val_by_group = {g: list(by_group[g]) for g in validation}
    histories: dict[str, list[EpochRecord]] = {}
    trained: list[TrainedLSTM] = []
    tensor_cache: dict[int, Any] = {}
    for index, candidate in enumerate(config.lstm_candidates):
        length = candidate.context_length
        if length not in tensor_cache:
            tensor_cache[length] = (
                build_training_tensors(
                    dataset.weighted(inner_instances, weighting), vocabulary, space, length
                ),
                build_validation_sets(
                    {g: [(i.prefix, i.target) for i in v] for g, v in val_by_group.items()}, length
                ),
            )
        examples, val_sets = tensor_cache[length]
        result = train_lstm(candidate, examples, vocabulary, space, validation=val_sets)
        trained.append(result)
        histories[f"candidate-{index}"] = result.history
        record.candidates.append(
            CandidateRecord(
                index=index,
                config=candidate,
                best_epoch=result.best_epoch,
                epochs_run=len(result.history),
                best_validation_loss=float(result.best_validation_loss or math.inf),
            )
        )
    selected = min(record.candidates, key=lambda c: (c.best_validation_loss, c.index))
    record.selected_candidate = selected.index
    chosen = config.lstm_candidates[selected.index]
    inner_lstm = LSTMPredictor(trained[selected.index].model, chosen, vocabulary, space)

    # 3./4. Inner Markov (inner-training groups only) and alpha on validation groups.
    inner_markov, inner_name, _ = select_markov(
        markov_specs, {g: group_data[g] for g in inner_train}, space
    )
    record.inner_markov = inner_name
    inner_lstm.prefetch([i.prefix for v in val_by_group.values() for i in v])
    p_lstm = {
        (i.prefix, i.target): inner_lstm.prob(i.prefix, i.target)
        for v in val_by_group.values()
        for i in v
    }
    p_markov = {
        (i.prefix, i.target): inner_markov.prob(i.prefix, i.target)
        for v in val_by_group.values()
        for i in v
    }
    best_alpha: tuple[float, float] | None = None
    for alpha in config.fusion_alphas:

        def mixed(prefix: tuple[str, ...], target: str, a: float = alpha) -> float:
            return a * p_lstm[(prefix, target)] + (1 - a) * p_markov[(prefix, target)]

        loss = group_mean_log_loss(mixed, val_by_group)
        record.alpha_validation_loss[f"{alpha:.2f}"] = loss
        if best_alpha is None or (loss, alpha) < best_alpha:
            best_alpha = (loss, alpha)
    assert best_alpha is not None
    record.selected_alpha = best_alpha[1]

    # 5. Final models on all outer-training groups.
    all_train = [i for g in train_groups for i in by_group[g]]
    final_tensors = build_training_tensors(
        dataset.weighted(all_train, weighting), vocabulary, space, chosen.context_length
    )
    final = train_lstm(
        chosen, final_tensors, vocabulary, space, fixed_epochs=max(1, selected.best_epoch)
    )
    record.final_epochs = len(final.history)
    histories["final"] = final.history
    lstm_model = LSTMPredictor(final.model, chosen, vocabulary, space)
    train_data = {g: group_data[g] for g in fold.train_groups}
    markov, markov_name, markov_params = select_markov(markov_specs, train_data, space)
    record.final_markov, record.final_markov_params = markov_name, markov_params
    b1_model, b1_tuning = fit_model(specs["B1"], train_data, space)
    record.final_b1_params = b1_tuning.selected if b1_tuning else None
    window = max(chosen.context_length, markov_params.max_order)
    hybrid = HybridModel(markov, lstm_model, record.selected_alpha, context_window=window)
    if checkpoint_writer is not None:
        record.checkpoint = checkpoint_writer(fold, record, final)

    # 6. Single evaluation on the outer test group.
    lstm_model.prefetch([i.prefix for i in test])
    windows = {
        MARKOV_SELECTED: max(1, markov_params.max_order),
        LSTM: chosen.context_length,
        HYBRID: window,
    }
    models: dict[str, NextTechniqueModel] = {
        MARKOV_SELECTED: markov,
        LSTM: lstm_model,
        HYBRID: hybrid,
    }
    scores = {
        name: _score_model(m, test, windows[name], space, tactics) for name, m in models.items()
    }
    predictions = [
        SingleStepRecord(inst, fold.fold_id, name, scores[name][n])
        for name in models
        for n, inst in enumerate(test)
    ]
    sweep = {
        alpha: _score_model(
            HybridModel(markov, lstm_model, alpha, context_window=window),
            test,
            window,
            space,
            tactics,
        )
        for alpha in config.fusion_alphas
    }
    beam_models: dict[str, tuple[NextTechniqueModel, int]] = {
        "B1": (b1_model, 0),
        MARKOV_SELECTED: (markov, markov_params.max_order),
        LSTM: (lstm_model, chosen.context_length),
        HYBRID: (hybrid, window),
    }
    multistep: dict[tuple[str, int], list[MultiStepScore]] = {}
    for horizon in config.beam_search.horizons:
        instances = builds[horizon].by_group.get(fold.test_group, [])
        for name in config.beam_search.models:
            model, ctx = beam_models[name]
            multistep[(name, horizon)] = score_multistep(
                model,
                instances,
                horizon,
                config.beam_search.beam_width,
                config.beam_search.hit_ks,
                ctx,
            )
    record.seconds = time.perf_counter() - started
    return FoldOutcome(record, scores, sweep, multistep, predictions, histories)


# --- whole experiment ------------------------------------------------------------------------


def _reproduction_check(
    baseline: Sequence[ModelSummary], reference_metrics: Path | None, weighting: Weighting
) -> dict[str, float | None]:
    """Max |difference| of per-group metrics vs the stored Milestone 3 run (None if absent)."""
    if reference_metrics is None or not reference_metrics.is_file():
        return {m.model: None for m in baseline}
    stored = json.loads(reference_metrics.read_text(encoding="utf-8"))
    stored_models = stored["results"][weighting.value]["models"]
    out: dict[str, float | None] = {}
    for model in baseline:
        ref = stored_models[model.model]["per_group"]
        if set(ref) != set(model.per_group):
            out[model.model] = math.inf  # different group sets: not a reproduction
            continue
        diffs = [
            abs(model.per_group[g][m] - ref[g][m]) for g in model.per_group for m in METRIC_NAMES
        ]
        out[model.model] = max(diffs) if diffs else 0.0
    return out


def run_sequence_experiment(
    dataset: PredictionDataset,
    vocabulary: TechniqueVocabulary,
    space: OutputSpace,
    tactics: Mapping[str, Sequence[str]],
    config: SequenceConfig,
    markov_config: ExperimentConfig,
    reference_metrics: Path | None = None,
    checkpoint_writer: CheckpointWriter | None = None,
    progress: ProgressCallback | None = None,
    fold_limit: int | None = None,
) -> SequenceExperimentResult:
    started = time.perf_counter()
    folds = leave_one_group_out(dataset.group_of_document)
    by_group = dataset.instances_by_group()
    group_data = build_group_data(dataset, config.weighting)
    builds = {
        h: build_multistep_instances(dataset.sequences, h) for h in config.beam_search.horizons
    }

    # Milestone 3 baselines recomputed on identical instances (Milestone 3 code path).
    base = run_experiment(dataset, space, tactics, markov_config)
    base_models = base.weighting_results[0].models
    baseline = [
        ModelSummary(
            model=m.model,
            macro=m.macro,
            micro=m.micro,
            per_group=m.per_group,
            per_group_instances=m.per_group_instances,
        )
        for m in base_models
    ]
    reproduction = _reproduction_check(baseline, reference_metrics, config.weighting)
    if progress:
        progress(f"baselines recomputed; reproduction max|diff| = {reproduction}")

    evaluated = [f for f in folds if by_group.get(f.test_group)]
    skipped = [f.fold_id for f in folds if not by_group.get(f.test_group)]
    if fold_limit is not None:
        evaluated = evaluated[:fold_limit]
    outcomes: list[FoldOutcome] = []
    for fold in evaluated:
        outcome = run_fold(
            fold,
            dataset,
            by_group,
            group_data,
            vocabulary,
            space,
            tactics,
            config,
            markov_config,
            builds,
            checkpoint_writer,
        )
        outcomes.append(outcome)
        if progress:
            r = outcome.record
            progress(
                f"{fold.fold_id} ({fold.test_group}): cand={r.selected_candidate} "
                f"epochs={r.final_epochs} markov={r.final_markov} alpha={r.selected_alpha} "
                f"[{r.seconds:.1f}s]"
            )

    resamples, seed = config.bootstrap_resamples, config.seed
    single: list[ModelSummary] = list(baseline)
    per_group_by_model = {m.model: m.per_group for m in baseline}
    for name in NEW_MODELS:
        rows = {o.record.test_group: [s.metrics() for s in o.scores[name]] for o in outcomes}
        macro, micro, per_group, counts = summarize_rows(name, rows, METRIC_NAMES, resamples, seed)
        single.append(
            ModelSummary(
                model=name,
                macro=macro,
                micro=micro,
                per_group=per_group,
                per_group_instances=counts,
            )
        )
        per_group_by_model[name] = per_group

    comparisons: list[ComparisonResult] = []
    for a, b in config.comparisons:
        for metric in METRIC_NAMES:
            groups = set(per_group_by_model[a]) & set(per_group_by_model[b])
            diff = paired_difference(
                {g: per_group_by_model[a][g][metric] for g in groups},
                {g: per_group_by_model[b][g][metric] for g in groups},
                resamples,
                seed,
            )
            comparisons.append(
                ComparisonResult(
                    model_a=a,
                    model_b=b,
                    metric=metric,
                    mean_difference=diff.mean,
                    ci_low=diff.ci_low,
                    ci_high=diff.ci_high,
                    n_groups=diff.n,
                    ci_excludes_zero=diff.ci_excludes_zero,
                )
            )

    sweep: dict[str, dict[str, MetricSummary]] = {}
    for alpha in config.fusion_alphas:
        rows = {o.record.test_group: [s.metrics() for s in o.alpha_sweep[alpha]] for o in outcomes}
        macro, _, _, _ = summarize_rows(f"alpha={alpha}", rows, METRIC_NAMES, resamples, seed)
        sweep[f"{alpha:.2f}"] = macro

    multistep: list[MultiStepSummary] = []
    multistep_predictions: dict[tuple[str, int], list[MultiStepScore]] = {}
    for horizon in config.beam_search.horizons:
        names = multistep_metric_names(horizon, config.beam_search.hit_ks)
        for model_name in config.beam_search.models:
            key = (model_name, horizon)
            rows = {
                o.record.test_group: [s.metrics for s in o.multistep[key]]
                for o in outcomes
                if o.multistep[key]
            }
            multistep_predictions[key] = [s for o in outcomes for s in o.multistep[key]]
            if not rows:
                continue
            macro, micro, per_group, counts = summarize_rows(
                model_name, rows, names, resamples, seed
            )
            multistep.append(
                MultiStepSummary(
                    model=model_name,
                    horizon=horizon,
                    macro=macro,
                    micro=micro,
                    per_group=per_group,
                    per_group_instances=counts,
                )
            )

    return SequenceExperimentResult(
        folds=folds,
        fold_records=[o.record for o in outcomes],
        single_step=single,
        comparisons=comparisons,
        alpha_sweep=sweep,
        multistep=multistep,
        multistep_builds=builds,
        baseline_reproduction=reproduction,
        predictions=[p for o in outcomes for p in o.predictions],
        multistep_predictions=multistep_predictions,
        histories={o.record.fold_id: o.histories for o in outcomes},
        skipped_folds=skipped,
        seconds=time.perf_counter() - started,
    )
