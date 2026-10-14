"""Experiment tracking: ``reports/runs/<run-id>/`` files and the SQLite record.

Files written per run (the directory must not already exist):
    config.json       configuration, environment, provenance (git commit + dirty flag)
    metrics.json      macro / micro / per-group results, ablations, comparisons, statistics
    predictions.json  every evaluation instance (once) and each model's top-5 + rank
    summary.md        human-readable protocol, results, TRAIN/TEST SOURCES per fold
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import JsonValue

from hqc.common.schemas.base import DataOrigin, utc_now
from hqc.common.schemas.evaluation import (
    EnvironmentInfo,
    EvaluationResult,
    EvaluationStatus,
    EvaluationTask,
)
from hqc.evaluation.chain_prediction import (
    MULTI_STEP_STATUS,
    ExperimentConfig,
    ExperimentResult,
    ModelResult,
    WeightingResult,
)
from hqc.evaluation.metrics import LOWER_IS_BETTER, METRIC_NAMES
from hqc.prediction.dataset import DatasetStats
from hqc.storage import Collection, Store

RUN_FILES = ("config.json", "metrics.json", "predictions.json", "summary.md")
HEADLINE_METRICS = ("top1", "top3", "top5", "mrr", "log_loss", "tactic_top1")
COMPARISON_METRICS = ("top1", "top5", "mrr", "log_loss")


@dataclass(frozen=True)
class RunProvenance:
    run_id: str
    created_at: datetime
    seed: int
    git_commit: str | None
    git_dirty: bool | None
    environment: EnvironmentInfo
    runtime_s: float
    config_path: str
    corpus_sha256: str | None


def make_run_id(weighting: str, now: datetime | None = None) -> str:
    stamp = (now or utc_now()).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-markov-baselines-{weighting}"


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def _grid_bounds(config: ExperimentConfig) -> dict[str, dict[str, tuple[float, float]]]:
    bounds: dict[str, dict[str, tuple[float, float]]] = {}
    for spec in config.models:
        if spec.grid:
            bounds[spec.name] = {
                p: (min(getattr(g, p) for g in spec.grid), max(getattr(g, p) for g in spec.grid))
                for p in ("alpha", "beta")
            }
    return bounds


def boundary_selections(
    config: ExperimentConfig, result: WeightingResult
) -> dict[str, dict[str, int]]:
    """How many folds selected the minimum / maximum grid value of alpha and beta."""
    bounds = _grid_bounds(config)
    out: dict[str, dict[str, int]] = {}
    for model in result.models:
        if model.model not in bounds:
            continue
        counts: dict[str, int] = {}
        for fold in model.folds:
            if fold.selected_params is None:
                continue
            for param, (low, high) in bounds[model.model].items():
                value = getattr(fold.selected_params, param)
                if low != high and value == low:
                    counts[f"{param}_at_min"] = counts.get(f"{param}_at_min", 0) + 1
                if low != high and value == high:
                    counts[f"{param}_at_max"] = counts.get(f"{param}_at_max", 0) + 1
        out[model.model] = counts
    return out


# --- payloads ---------------------------------------------------------------------------


def config_payload(
    config: ExperimentConfig, stats: DatasetStats, prov: RunProvenance
) -> dict[str, Any]:
    return {
        "run_id": prov.run_id,
        "created_at": prov.created_at.isoformat(),
        "task": "next-technique prediction (single step)",
        "models": [m.name for m in config.models],
        "weighting_primary": config.primary_weighting.value,
        "weighting_ablations": [w.value for w in config.ablation_weightings],
        "hyperparameter_grid": {
            m.name: [g.model_dump(mode="json") for g in m.grid] for m in config.models
        },
        "selection_metric": config.selection_metric,
        "bootstrap_resamples": config.bootstrap_resamples,
        "confidence": config.confidence,
        "random_seed": prov.seed,
        "config_file": prov.config_path,
        "dataset_id": stats.dataset_id,
        "dataset_version": f"{stats.corpus_version}/format-{stats.dataset_format_version}",
        "processed_corpus_sha256": prov.corpus_sha256,
        "attack_version": stats.attack_version,
        "vocabulary_version": stats.vocabulary_version,
        "id_cleanup": {
            "revoked_ids_remapped": stats.revoked_ids_remapped,
            "remap_occurrences": stats.remap_occurrences,
            "remapped": [r.model_dump(mode="json") for r in stats.remapped_ids],
            "unknown": [u.model_dump(mode="json") for u in stats.unknown_ids],
            "unk_targets_dropped": stats.unk_targets_dropped,
        },
        "environment": {
            "python_version": prov.environment.python_version,
            "platform": prov.environment.platform,
            "packages": prov.environment.packages,
        },
        "git_commit": prov.git_commit,
        "working_tree_dirty": prov.git_dirty,
        "provenance_note": (
            "git_commit alone does NOT identify the exact source when working_tree_dirty is true"
        ),
        "multi_step": MULTI_STEP_STATUS,
    }


def _model_payload(model: ModelResult) -> dict[str, Any]:
    return {
        "macro": {k: v.model_dump(mode="json") for k, v in model.macro.items()},
        "micro": model.micro,
        "per_group": model.per_group,
        "per_group_instances": model.per_group_instances,
        "folds": [f.model_dump(mode="json") for f in model.folds],
    }


def metrics_payload(
    config: ExperimentConfig, result: ExperimentResult, stats: DatasetStats
) -> dict[str, Any]:
    primary, *ablations = result.weighting_results
    return {
        "metric_definitions": "see docs/EVALUATION.md (deterministic ranks; tie-aware variants)",
        "aggregation": "macro = mean over source groups (primary); micro = mean over instances",
        "primary_weighting": primary.weighting.value,
        "results": {
            wr.weighting.value: {
                "weighting_total": wr.weighting_total,
                "models": {m.model: _model_payload(m) for m in wr.models},
                "comparisons": [c.model_dump(mode="json") for c in wr.comparisons],
                "boundary_selections": boundary_selections(config, wr),
            }
            for wr in result.weighting_results
        },
        "ablation_weightings": [w.weighting.value for w in ablations],
        "dataset_statistics": stats.model_dump(mode="json"),
        "folds_total": len(result.folds),
        "folds_without_test_instances": result.skipped_folds,
        "multi_step": MULTI_STEP_STATUS,
    }


def predictions_payload(result: ExperimentResult, run_id: str) -> dict[str, Any]:
    instances: dict[int, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for record in result.predictions:
        inst = record.instance
        if inst.instance_id not in instances:
            instances[inst.instance_id] = {
                "instance_id": inst.instance_id,
                "document": inst.document_id,
                "group": inst.source_group,
                "fold": record.fold_id,
                "prefix": list(inst.prefix),
                "true_next": inst.target,
                "raw_multiplicity": inst.multiplicity,
            }
        rows.append(
            {
                "instance_id": inst.instance_id,
                "model": record.model,
                "fold": record.fold_id,
                "top5": [[t, p] for t, p in record.score.top],
                "p_true": record.score.p_target,
                "true_rank": record.score.rank,
            }
        )
    return {
        "run_id": run_id,
        "weighting": result.weighting_results[0].weighting.value,
        "note": "Instances listed once; predictions reference instance_id. No sensitive data.",
        "instances": list(instances.values()),
        "predictions": rows,
    }


def _fmt(value: float) -> str:
    return f"{value:.4f}"


def _results_table(wr: WeightingResult) -> list[str]:
    header = "| Model | " + " | ".join(HEADLINE_METRICS) + " |"
    lines = [header, "|---" * (len(HEADLINE_METRICS) + 1) + "|"]
    for model in wr.models:
        cells = [
            f"{_fmt(model.macro[m].mean)} [{_fmt(model.macro[m].ci_low)}, "
            f"{_fmt(model.macro[m].ci_high)}]"
            for m in HEADLINE_METRICS
        ]
        lines.append(f"| {model.model} | " + " | ".join(cells) + " |")
    return lines


def _micro_table(wr: WeightingResult) -> list[str]:
    lines = ["| Model | " + " | ".join(HEADLINE_METRICS) + " |"]
    lines.append("|---" * (len(HEADLINE_METRICS) + 1) + "|")
    for model in wr.models:
        lines.append(
            f"| {model.model} | "
            + " | ".join(_fmt(model.micro[m]) for m in HEADLINE_METRICS)
            + " |"
        )
    return lines


def _comparison_lines(wr: WeightingResult) -> list[str]:
    lines = []
    for c in wr.comparisons:
        if c.metric not in COMPARISON_METRICS:
            continue
        better = "lower is better" if c.metric in LOWER_IS_BETTER else "higher is better"
        verdict = (
            "95% CI excludes 0" if c.ci_excludes_zero else "95% CI includes 0: difference unclear"
        )
        lines.append(
            f"- {c.model_a} - {c.model_b}, {c.metric} ({better}): "
            f"{c.mean_difference:+.4f} [{c.ci_low:+.4f}, {c.ci_high:+.4f}] over "
            f"{c.n_groups} groups — {verdict}"
        )
    return lines


def summary_markdown(
    config: ExperimentConfig, result: ExperimentResult, stats: DatasetStats, prov: RunProvenance
) -> str:
    primary = result.weighting_results[0]
    lines = [
        f"# Run {prov.run_id}",
        "",
        "Next-technique prediction baselines (B0 uniform, B1 frequency, M1 first-order Markov, "
        "M2 variable-order Markov) on the MITRE Attack Flow corpus.",
        "",
        f"**multi-step: {MULTI_STEP_STATUS}** (beam search is Milestone 4).",
        "",
        "## Protocol",
        f"- Outer: leave-one-group-out over {stats.source_groups} source groups "
        f"({len(result.folds)} folds; folds without instances: {len(result.skipped_folds)}).",
        "- Inner: leave-one-group-out over the outer-training groups only; hyperparameters "
        "minimise mean group log loss; ties -> first grid entry.",
        f"- Primary weighting: **{primary.weighting.value}**; ablations: "
        f"{', '.join(w.weighting.value for w in result.weighting_results[1:]) or 'none'}.",
        "- Evaluation instances: unique (document, full prefix, next technique); each counts once.",
        f"- Macro = mean over groups (primary), 95% bootstrap CI ({config.bootstrap_resamples} "
        f"resamples of groups, seed {config.seed}); micro = mean over instances.",
        "",
        "## Dataset",
        f"- ATT&CK {stats.attack_version}; vocabulary {stats.vocabulary_version}; "
        f"{stats.active_techniques} active techniques.",
        f"- {stats.documents} documents, {stats.source_groups} groups, "
        f"{stats.sequences} sequences.",
        f"- Raw instances {stats.raw_instances}; unique {stats.unique_instances}; collapsed "
        f"{stats.collapsed_duplicates} ({stats.collapse_percentage}%).",
        f"- Revoked IDs remapped: {stats.revoked_ids_remapped} ({stats.remap_occurrences} "
        f"occurrences); unknown IDs: {len(stats.unknown_ids)}; <UNK> targets dropped: "
        f"{stats.unk_targets_dropped}.",
        f"- Skew (share of raw instances): {stats.largest_documents_share}.",
        f"- Groups without instances: {stats.groups_without_instances}.",
        "",
        f"## Macro results — weighting = {primary.weighting.value} (mean [95% CI])",
        *_results_table(primary),
        "",
        "## Micro results (mean over instances)",
        *_micro_table(primary),
        "",
        "## Paired comparisons (macro, bootstrap over groups)",
        *_comparison_lines(primary),
        "",
        "## Ablations (macro means)",
    ]
    for wr in result.weighting_results[1:]:
        lines += [f"### weighting = {wr.weighting.value}", *_results_table(wr), ""]
        lines += [*_comparison_lines(wr), ""]
    lines += [
        "## Hyperparameter boundary selections (folds)",
        *[
            f"- {wr.weighting.value}: {boundary_selections(config, wr)}"
            for wr in result.weighting_results
        ],
        "",
        "## Folds: TRAIN SOURCES / TEST SOURCES",
    ]
    for fold in result.folds:
        lines += [
            f"### {fold.fold_id}",
            f"- TEST SOURCES: group `{fold.test_group}`; documents: "
            + ", ".join(f"`{d}`" for d in fold.test_documents),
            "- TRAIN SOURCES: groups: " + ", ".join(f"`{g}`" for g in fold.train_groups),
            "",
        ]
    lines += [
        "## Provenance",
        f"- git commit `{prov.git_commit}`; working tree dirty: **{prov.git_dirty}** "
        "(a dirty tree means the commit hash alone does not identify the source).",
        f"- Python {prov.environment.python_version}; runtime {prov.runtime_s:.1f} s.",
    ]
    return "\n".join(lines) + "\n"


# --- writing ------------------------------------------------------------------------------


def write_run(
    reports_dir: Path,
    config: ExperimentConfig,
    result: ExperimentResult,
    stats: DatasetStats,
    prov: RunProvenance,
) -> Path:
    run_dir = reports_dir / "runs" / prov.run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    _write_json(run_dir / "config.json", config_payload(config, stats, prov))
    _write_json(run_dir / "metrics.json", metrics_payload(config, result, stats))
    _write_json(run_dir / "predictions.json", predictions_payload(result, prov.run_id))
    (run_dir / "summary.md").write_text(
        summary_markdown(config, result, stats, prov), encoding="utf-8"
    )
    return run_dir


def flat_metrics(result: ExperimentResult) -> dict[str, float]:
    out: dict[str, float] = {}
    for wr in result.weighting_results:
        for model in wr.models:
            prefix = f"{wr.weighting.value}.{model.model}"
            for metric in METRIC_NAMES:
                summary = model.macro[metric]
                out[f"{prefix}.macro.{metric}"] = summary.mean
                out[f"{prefix}.macro.{metric}.ci_low"] = summary.ci_low
                out[f"{prefix}.macro.{metric}.ci_high"] = summary.ci_high
                out[f"{prefix}.micro.{metric}"] = model.micro[metric]
    return out


def evaluation_record(
    config: ExperimentConfig,
    result: ExperimentResult,
    stats: DatasetStats,
    prov: RunProvenance,
    run_dir: Path,
) -> EvaluationResult:
    preprocessing: dict[str, JsonValue] = {
        "weighting_primary": config.primary_weighting.value,
        "weighting_ablations": [w.value for w in config.ablation_weightings],
        "revoked_ids_remapped": stats.revoked_ids_remapped,
        "remap_occurrences": stats.remap_occurrences,
        "unknown_ids": [u.original for u in stats.unknown_ids],
        "unk_targets_dropped": stats.unk_targets_dropped,
        "raw_instances": stats.raw_instances,
        "unique_instances": stats.unique_instances,
        "vocabulary_version": stats.vocabulary_version,
        "processed_corpus_sha256": prov.corpus_sha256,
    }
    model_configuration: dict[str, JsonValue] = {
        "models": [m.name for m in config.models],
        "grid_sizes": {m.name: len(m.grid) for m in config.models},
        "selection_metric": config.selection_metric,
        "outer_split": "leave-one-group-out",
        "inner_split": "leave-one-group-out over outer-training groups",
        "folds": len(result.folds),
        "folds_without_test_instances": list(result.skipped_folds),
        "run_dir": str(run_dir),
    }
    return EvaluationResult(
        run_id=prov.run_id,
        task=EvaluationTask.CHAIN_PREDICTION,
        status=EvaluationStatus.EVALUATED,
        created_at=prov.created_at,
        git_commit=prov.git_commit,
        git_dirty=prov.git_dirty,
        dataset_id=stats.dataset_id,
        dataset_version=f"{stats.corpus_version}/format-{stats.dataset_format_version}",
        data_origin=DataOrigin.REAL,
        attack_version=stats.attack_version,
        seed=prov.seed,
        preprocessing_config=preprocessing,
        model_configuration=model_configuration,
        metrics=flat_metrics(result),
        folds=[f.to_record() for f in result.folds],
        runtime_s=prov.runtime_s,
        environment=prov.environment,
        notes=f"multi-step: {MULTI_STEP_STATUS}",
    )


def store_record(store: Store, record: EvaluationResult) -> EvaluationResult:
    """Persist the record (write-once) and return what was read back."""
    store.put(Collection.EVALUATION_RUNS, record)
    restored = store.get(Collection.EVALUATION_RUNS, record.run_id)
    if not isinstance(restored, EvaluationResult) or restored != record:
        raise RuntimeError("Stored evaluation record did not round-trip exactly")
    return restored
