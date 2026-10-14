"""Nested leave-one-group-out evaluation of next-technique baselines.

For every weighting scheme and every outer fold (one held-out source group):

    outer-training groups --(inner LOGO, tuning.tune)--> hyperparameters
    fit on all outer-training groups --> score every unique instance of the test group

Only the outer-training groups are passed to the tuner. Evaluation instances are the
unique (document, full prefix, target) triples; each counts once. Multi-step / beam-
search metrics are NOT evaluated in this milestone.
"""

from __future__ import annotations

import itertools
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError, model_validator

from hqc.common.errors import ConfigurationError, DataLeakageError
from hqc.common.schemas.base import HQCModel, NonEmptyStr
from hqc.evaluation.metrics import (
    METRIC_NAMES,
    InstanceScore,
    mean_metrics,
    paired_difference,
    score_distribution,
    summarize,
)
from hqc.evaluation.splits import Fold, assert_disjoint, leave_one_group_out
from hqc.evaluation.tuning import GroupData, PairKey, TuningResult, pair_key, tune
from hqc.prediction.base import NextTechniqueModel, OutputSpace
from hqc.prediction.baselines import UNIFORM_NAME, UniformModel
from hqc.prediction.dataset import PredictionDataset, PredictionInstance, Weighting
from hqc.prediction.markov import InterpolatedMarkovModel, MarkovCounts, MarkovParams

MULTI_STEP_STATUS = "NOT EVALUATED"

# --- configuration ------------------------------------------------------------------------


class ModelSpec(HQCModel):
    name: NonEmptyStr
    grid: list[MarkovParams] = Field(default_factory=list)


class ExperimentConfig(HQCModel):
    seed: int = Field(ge=0)
    bootstrap_resamples: int = Field(ge=100)
    confidence: float = Field(gt=0.0, lt=1.0)
    selection_metric: str
    primary_weighting: Weighting
    ablation_weightings: list[Weighting]
    models: list[ModelSpec] = Field(min_length=1)
    comparisons: list[tuple[str, str]] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> ExperimentConfig:
        if self.selection_metric != "log_loss":
            raise ValueError("Only log_loss selection is implemented")
        if self.primary_weighting in self.ablation_weightings:
            raise ValueError("The primary weighting must not also be an ablation")
        names = [m.name for m in self.models]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate model names")
        for a, b in self.comparisons:
            if a not in names or b not in names:
                raise ValueError(f"Comparison {a} vs {b} references an unknown model")
        for spec in self.models:
            if spec.name != UNIFORM_NAME and not spec.grid:
                raise ValueError(f"Model {spec.name} needs a hyperparameter grid")
        return self

    @property
    def weightings(self) -> list[Weighting]:
        return [self.primary_weighting, *self.ablation_weightings]


def _expand_product(spec: Mapping[str, Sequence[Any]]) -> list[dict[str, Any]]:
    keys = list(spec)
    return [dict(zip(keys, combo, strict=True)) for combo in itertools.product(*spec.values())]


def load_experiment_config(path: Path, primary: Weighting | None = None) -> ExperimentConfig:
    """Load the YAML config; ``primary`` swaps the primary weighting with an ablation."""
    try:
        raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
        models = []
        for m in raw.get("models", []):
            grid = list(m.get("grid", []))
            for key in ("grid_product", "grid_product_extra"):
                if key in m:
                    grid.extend(_expand_product(m[key]))
            models.append({"name": m["name"], "grid": grid})
        raw["models"] = models
        config = ExperimentConfig.model_validate(raw)
    except (OSError, yaml.YAMLError, KeyError, ValidationError) as exc:
        raise ConfigurationError(f"Invalid experiment config {path}: {exc}") from exc
    if primary is not None and primary != config.primary_weighting:
        others = [w for w in config.weightings if w != primary]
        config = config.model_copy(
            update={"primary_weighting": primary, "ablation_weightings": others}
        )
    return config


# --- results ------------------------------------------------------------------------------


class MetricSummary(HQCModel):
    mean: float
    std: float
    ci_low: float
    ci_high: float
    n_groups: int


class ComparisonResult(HQCModel):
    model_a: NonEmptyStr
    model_b: NonEmptyStr
    metric: NonEmptyStr
    mean_difference: float = Field(description="mean over groups of (a - b)")
    ci_low: float
    ci_high: float
    n_groups: int
    ci_excludes_zero: bool


class FoldModelResult(HQCModel):
    fold_id: NonEmptyStr
    test_group: NonEmptyStr
    n_test_instances: int
    selected_params: MarkovParams | None = None
    inner_groups: int = 0
    best_inner_log_loss: float | None = None


class ModelResult(HQCModel):
    model: NonEmptyStr
    weighting: Weighting
    macro: dict[str, MetricSummary]
    micro: dict[str, float]
    per_group: dict[str, dict[str, float]]
    per_group_instances: dict[str, int]
    folds: list[FoldModelResult]


class WeightingResult(HQCModel):
    weighting: Weighting
    weighting_total: float
    models: list[ModelResult]
    comparisons: list[ComparisonResult]


@dataclass(frozen=True)
class PredictionRecord:
    instance: PredictionInstance
    fold_id: str
    model: str
    score: InstanceScore


@dataclass
class ExperimentResult:
    folds: list[Fold]
    weighting_results: list[WeightingResult]
    predictions: list[PredictionRecord]
    skipped_folds: list[str]


# --- execution ----------------------------------------------------------------------------

ProgressCallback = Callable[[str], None]


def build_group_data(dataset: PredictionDataset, weighting: Weighting) -> dict[str, GroupData]:
    """Per-group count tables (training) and evaluation pairs (unique instances)."""
    data: dict[str, GroupData] = {}
    for group, instances in dataset.instances_by_group().items():
        counts = MarkovCounts.from_instances(dataset.weighted(instances, weighting))
        pairs: Counter[PairKey] = Counter(pair_key(i.prefix, i.target) for i in instances)
        data[group] = GroupData(counts=counts, eval_pairs=pairs)
    return data


def fit_model(
    spec: ModelSpec,
    train_data: Mapping[str, GroupData],
    space: OutputSpace,
) -> tuple[NextTechniqueModel, TuningResult | None]:
    """Tune (inner LOGO on ``train_data`` only) and fit one model on all of it."""
    if spec.name == UNIFORM_NAME:
        return UniformModel(space), None
    tuning = tune(spec.grid, train_data, space, spec.name)
    counts = MarkovCounts.merge(list(d.counts for d in train_data.values()))
    return InterpolatedMarkovModel(counts, tuning.selected, space, spec.name), tuning


def run_experiment(
    dataset: PredictionDataset,
    space: OutputSpace,
    tactics: Mapping[str, Sequence[str]],
    config: ExperimentConfig,
    progress: ProgressCallback | None = None,
) -> ExperimentResult:
    folds = leave_one_group_out(dataset.group_of_document)
    by_group = dataset.instances_by_group()
    totals = dataset.weighting_totals()
    predictions: list[PredictionRecord] = []
    skipped = [f.fold_id for f in folds if not by_group.get(f.test_group)]
    results: list[WeightingResult] = []

    for weighting in config.weightings:
        group_data = build_group_data(dataset, weighting)
        scores: dict[str, dict[str, list[InstanceScore]]] = {m.name: {} for m in config.models}
        fold_results: dict[str, list[FoldModelResult]] = {m.name: [] for m in config.models}
        for fold in folds:
            assert_disjoint(fold)
            test_instances = by_group.get(fold.test_group, [])
            train_data = {g: group_data[g] for g in fold.train_groups}
            if fold.test_group in train_data:  # defensive: never reachable after assert
                raise DataLeakageError(f"{fold.fold_id}: test group in training data")
            for spec in config.models:
                if not test_instances:
                    fold_results[spec.name].append(
                        FoldModelResult(
                            fold_id=fold.fold_id, test_group=fold.test_group, n_test_instances=0
                        )
                    )
                    continue
                model, tuning = fit_model(spec, train_data, space)
                cache: dict[PairKey, InstanceScore] = {}
                group_scores: list[InstanceScore] = []
                for instance in test_instances:
                    key = pair_key(instance.prefix, instance.target)
                    score = cache.get(key)
                    if score is None:
                        dist = model.distribution(instance.prefix)
                        score = score_distribution(dist, space, instance.target, tactics)
                        cache[key] = score
                    group_scores.append(score)
                    if weighting is config.primary_weighting:
                        predictions.append(
                            PredictionRecord(instance, fold.fold_id, spec.name, score)
                        )
                scores[spec.name][fold.test_group] = group_scores
                fold_results[spec.name].append(
                    FoldModelResult(
                        fold_id=fold.fold_id,
                        test_group=fold.test_group,
                        n_test_instances=len(test_instances),
                        selected_params=tuning.selected if tuning else None,
                        inner_groups=len(tuning.inner_groups) if tuning else 0,
                        best_inner_log_loss=min(tuning.candidate_scores) if tuning else None,
                    )
                )
            if progress:
                progress(f"{weighting.value}: {fold.fold_id} ({fold.test_group}) done")
        results.append(_aggregate(weighting, totals[weighting.value], scores, fold_results, config))
    return ExperimentResult(folds, results, predictions, skipped)


def _aggregate(
    weighting: Weighting,
    weighting_total: float,
    scores: dict[str, dict[str, list[InstanceScore]]],
    fold_results: dict[str, list[FoldModelResult]],
    config: ExperimentConfig,
) -> WeightingResult:
    models: list[ModelResult] = []
    per_group_by_model: dict[str, dict[str, dict[str, float]]] = {}
    for spec in config.models:
        by_group = scores[spec.name]
        per_group = {g: mean_metrics(s) for g, s in sorted(by_group.items())}
        per_group_by_model[spec.name] = per_group
        all_scores = [s for group_scores in by_group.values() for s in group_scores]
        macro: dict[str, MetricSummary] = {}
        for metric in METRIC_NAMES:
            summary = summarize(
                [per_group[g][metric] for g in per_group], config.bootstrap_resamples, config.seed
            )
            macro[metric] = MetricSummary(
                mean=summary.mean,
                std=summary.std,
                ci_low=summary.ci_low,
                ci_high=summary.ci_high,
                n_groups=summary.n,
            )
        models.append(
            ModelResult(
                model=spec.name,
                weighting=weighting,
                macro=macro,
                micro=mean_metrics(all_scores),
                per_group=per_group,
                per_group_instances={g: len(s) for g, s in sorted(by_group.items())},
                folds=fold_results[spec.name],
            )
        )
    comparisons: list[ComparisonResult] = []
    for a, b in config.comparisons:
        for metric in METRIC_NAMES:
            diff = paired_difference(
                {g: m[metric] for g, m in per_group_by_model[a].items()},
                {g: m[metric] for g, m in per_group_by_model[b].items()},
                config.bootstrap_resamples,
                config.seed,
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
    return WeightingResult(
        weighting=weighting, weighting_total=weighting_total, models=models, comparisons=comparisons
    )
