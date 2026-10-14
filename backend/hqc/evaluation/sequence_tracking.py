"""Run tracking for Milestone 4 (LSTM / hybrid / beam search).

``reports/runs/<run-id>/``: config.json, metrics.json, predictions.json,
training_history.json, summary.md (with TRAIN / VALIDATION / TEST SOURCES per fold).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import JsonValue

from hqc.common.schemas.base import DataOrigin, utc_now
from hqc.common.schemas.evaluation import (
    EnvironmentInfo,
    EvaluationFold,
    EvaluationResult,
    EvaluationStatus,
    EvaluationTask,
)
from hqc.evaluation.chain_prediction import ExperimentConfig
from hqc.evaluation.metrics import LOWER_IS_BETTER, METRIC_NAMES
from hqc.evaluation.multistep import NOT_EVALUATED, multistep_metric_names
from hqc.evaluation.sequence_experiment import (
    ModelSummary,
    SequenceConfig,
    SequenceExperimentResult,
)
from hqc.prediction.dataset import DatasetStats
from hqc.storage import Collection, Store

RUN_FILES = (
    "config.json",
    "metrics.json",
    "predictions.json",
    "training_history.json",
    "summary.md",
)
HEADLINE = ("top1", "top3", "top5", "mrr", "log_loss", "tactic_top1")


@dataclass(frozen=True)
class SequenceProvenance:
    run_id: str
    created_at: datetime
    git_commit: str | None
    git_dirty: bool | None
    environment: EnvironmentInfo
    runtime_s: float
    config_path: str
    corpus_sha256: str | None
    checkpoint_dir: str | None


def make_sequence_run_id(now: datetime | None = None) -> str:
    return f"{(now or utc_now()).strftime('%Y%m%dT%H%M%SZ')}-lstm-hybrid-beam-document"


def _dump(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def _summary_payload(m: ModelSummary) -> dict[str, Any]:
    return {
        "macro": {k: v.model_dump(mode="json") for k, v in m.macro.items()},
        "micro": m.micro,
        "per_group": m.per_group,
        "per_group_instances": m.per_group_instances,
    }


def multistep_status(result: SequenceExperimentResult, config: SequenceConfig) -> dict[str, Any]:
    return {
        "beam_search_path_metrics": "EVALUATED",
        "horizons": config.beam_search.horizons,
        "beam_width": config.beam_search.beam_width,
        "instances": {str(h): b.instances for h, b in result.multistep_builds.items()},
        "skipped_unk_continuations": {
            str(h): b.skipped_unk_continuations for h, b in result.multistep_builds.items()
        },
        **NOT_EVALUATED,
    }


def config_payload(
    config: SequenceConfig, markov: ExperimentConfig, stats: DatasetStats, prov: SequenceProvenance
) -> dict[str, Any]:
    return {
        "run_id": prov.run_id,
        "created_at": prov.created_at.isoformat(),
        "task": "next-technique prediction (single + multi-step)",
        "config_file": prov.config_path,
        "sequence_config": config.model_dump(mode="json"),
        "markov_grids": {m.name: len(m.grid) for m in markov.models},
        "weighting": config.weighting.value,
        "random_seed": config.seed,
        "dataset_id": stats.dataset_id,
        "dataset_version": f"{stats.corpus_version}/format-{stats.dataset_format_version}",
        "processed_corpus_sha256": prov.corpus_sha256,
        "attack_version": stats.attack_version,
        "vocabulary_version": stats.vocabulary_version,
        "id_cleanup": {
            "revoked_ids_remapped": stats.revoked_ids_remapped,
            "remap_occurrences": stats.remap_occurrences,
            "unknown_ids": [u.original for u in stats.unknown_ids],
            "unk_targets_dropped": stats.unk_targets_dropped,
        },
        "environment": {
            "python_version": prov.environment.python_version,
            "platform": prov.environment.platform,
            "packages": prov.environment.packages,
        },
        "git_commit": prov.git_commit,
        "working_tree_dirty": prov.git_dirty,
        "checkpoint_dir": prov.checkpoint_dir,
        "device": "cpu",
    }


def metrics_payload(
    config: SequenceConfig, result: SequenceExperimentResult, stats: DatasetStats
) -> dict[str, Any]:
    return {
        "aggregation": "macro = mean over source groups (primary); micro = mean over instances",
        "single_step": {m.model: _summary_payload(m) for m in result.single_step},
        "comparisons": [c.model_dump(mode="json") for c in result.comparisons],
        "fusion_alpha_test_sweep_REPORT_ONLY": {
            a: {k: v.model_dump(mode="json") for k, v in macro.items()}
            for a, macro in result.alpha_sweep.items()
        },
        "multistep": [
            {"horizon": m.horizon, "model": m.model, **_summary_payload(m)}
            for m in result.multistep
        ],
        "multistep_status": multistep_status(result, config),
        "baseline_reproduction_max_abs_diff_vs_milestone3": result.baseline_reproduction,
        "folds": [r.model_dump(mode="json") for r in result.fold_records],
        "folds_without_test_instances": result.skipped_folds,
        "dataset_statistics": stats.model_dump(mode="json"),
    }


def predictions_payload(result: SequenceExperimentResult, run_id: str) -> dict[str, Any]:
    instances: dict[int, dict[str, Any]] = {}
    rows = []
    for rec in result.predictions:
        inst = rec.instance
        instances.setdefault(
            inst.instance_id,
            {
                "instance_id": inst.instance_id,
                "document": inst.document_id,
                "group": inst.source_group,
                "fold": rec.fold_id,
                "prefix": list(inst.prefix),
                "true_next": inst.target,
            },
        )
        rows.append(
            {
                "instance_id": inst.instance_id,
                "model": rec.model,
                "top5": [[t, p] for t, p in rec.score.top],
                "p_true": rec.score.p_target,
                "true_rank": rec.score.rank,
            }
        )
    multistep = [
        {
            "model": model,
            "horizon": horizon,
            "document": s.instance.document_id,
            "group": s.instance.source_group,
            "prefix_last10": list(s.instance.prefix[-10:]),
            "prefix_length": len(s.instance.prefix),
            "true_continuations": [list(f) for f in s.instance.futures],
            "top3_paths": [[list(p.technique_ids), p.log_probability] for p in s.top_paths],
            "metrics": s.metrics,
        }
        for (model, horizon), scores in result.multistep_predictions.items()
        if model in ("LSTM", "HYBRID")
        for s in scores
    ]
    return {
        "run_id": run_id,
        "note": "Single-step rows for MARKOV/LSTM/HYBRID (B0-M2 rows are in the Milestone 3 "
        "run); multi-step rows for LSTM and HYBRID. No sensitive data.",
        "instances": list(instances.values()),
        "single_step": rows,
        "multistep": multistep,
    }


def history_payload(result: SequenceExperimentResult) -> dict[str, Any]:
    return {
        fold: {name: [e.model_dump(mode="json") for e in hist] for name, hist in runs.items()}
        for fold, runs in result.histories.items()
    }


def _f(x: float) -> str:
    return f"{x:.4f}"


def _table(models: Sequence[ModelSummary], metrics: Sequence[str]) -> list[str]:
    lines = ["| Model | " + " | ".join(metrics) + " |", "|---" * (len(metrics) + 1) + "|"]
    for m in models:
        cells = [
            f"{_f(m.macro[k].mean)} [{_f(m.macro[k].ci_low)}, {_f(m.macro[k].ci_high)}]"
            for k in metrics
        ]
        lines.append(f"| {m.model} | " + " | ".join(cells) + " |")
    return lines


def summary_markdown(
    config: SequenceConfig,
    result: SequenceExperimentResult,
    stats: DatasetStats,
    prov: SequenceProvenance,
) -> str:
    lines = [
        f"# Run {prov.run_id}",
        "",
        "LSTM, Markov+LSTM fusion (HYBRID) and beam search vs Milestone 3 baselines, on the MITRE "
        "Attack Flow corpus. Primary weighting: document.",
        "",
        "## Protocol",
        f"- Outer leave-one-group-out: {stats.source_groups} groups, {len(result.fold_records)} "
        f"evaluated folds, skipped (no instances): {result.skipped_folds}.",
        "- Inner (outer-training groups only): validation groups "
        f"({config.inner_validation.fraction:.0%}, min {config.inner_validation.min_groups}) for "
        "LSTM selection, early stopping and fusion alpha; inner LOGO for Markov (M1 vs M2).",
        f"- {len(config.lstm_candidates)} pre-registered LSTM candidates; final LSTM retrained "
        "on all outer-training groups for the selected best epoch.",
        f"- 95% CI: bootstrap over groups ({config.bootstrap_resamples} resamples, "
        f"seed {config.seed}).",
        f"- Milestone 3 baseline reproduction (max |diff| of per-group metrics): "
        f"{result.baseline_reproduction}",
        "",
        "## Single-step results (macro mean [95% CI])",
        *_table(result.single_step, HEADLINE),
        "",
        "## Micro (mean over instances)",
        "| Model | " + " | ".join(HEADLINE) + " |",
        "|---" * (len(HEADLINE) + 1) + "|",
        *[
            f"| {m.model} | " + " | ".join(_f(m.micro[k]) for k in HEADLINE) + " |"
            for m in result.single_step
        ],
        "",
        "## Paired comparisons (macro, bootstrap over groups)",
    ]
    for c in result.comparisons:
        if c.metric not in ("top1", "top5", "mrr", "log_loss"):
            continue
        better = "lower is better" if c.metric in LOWER_IS_BETTER else "higher is better"
        verdict = (
            "95% CI excludes 0" if c.ci_excludes_zero else "95% CI includes 0: difference unclear"
        )
        lines.append(
            f"- {c.model_a} - {c.model_b}, {c.metric} ({better}): {c.mean_difference:+.4f} "
            f"[{c.ci_low:+.4f}, {c.ci_high:+.4f}] over {c.n_groups} groups — {verdict}"
        )
    lines += ["", "## Fusion alpha sweep on TEST groups (REPORT ONLY, never used for selection)"]
    lines += ["| alpha | top1 | mrr | log_loss |", "|---|---|---|---|"]
    for a, macro in result.alpha_sweep.items():
        lines.append(
            f"| {a} | {_f(macro['top1'].mean)} | {_f(macro['mrr'].mean)} | "
            f"{_f(macro['log_loss'].mean)} |"
        )
    lines += ["", "## Multi-step (beam search) — macro mean [95% CI]"]
    for horizon in config.beam_search.horizons:
        names = multistep_metric_names(horizon, config.beam_search.hit_ks)
        models = [m for m in result.multistep if m.horizon == horizon]
        lines += [
            f"### H = {horizon} (beam width {config.beam_search.beam_width})",
            *_table(models, names),
            "",
        ]
    lines += ["### Not evaluated", *[f"- {k}: {v}" for k, v in NOT_EVALUATED.items()], ""]
    lines += ["## Selected hyperparameters per fold"]
    lines += [
        "| fold | test group | LSTM cand | epochs | Markov | alpha |",
        "|---|---|---|---|---|---|",
    ]
    for r in result.fold_records:
        lines.append(
            f"| {r.fold_id} | {r.test_group} | {r.selected_candidate} | {r.final_epochs} | "
            f"{r.final_markov} | {r.selected_alpha} |"
        )
    lines += ["", "## Folds: TRAIN / VALIDATION / TEST SOURCES"]
    for r in result.fold_records:
        lines += [
            f"### {r.fold_id}",
            f"- TEST SOURCES: `{r.test_group}`",
            "- VALIDATION SOURCES: " + ", ".join(f"`{g}`" for g in r.validation_groups),
            "- TRAIN SOURCES (inner training): "
            + ", ".join(f"`{g}`" for g in r.inner_train_groups),
            "- TRAIN SOURCES (final model, all outer-training groups): "
            + ", ".join(f"`{g}`" for g in r.train_groups),
            "",
        ]
    lines += [
        "## Provenance",
        f"- git commit `{prov.git_commit}`; working tree dirty: **{prov.git_dirty}**.",
        f"- runtime {prov.runtime_s:.1f} s; device CPU; checkpoints: `{prov.checkpoint_dir}`.",
    ]
    return "\n".join(lines) + "\n"


def write_sequence_run(
    reports_dir: Path,
    config: SequenceConfig,
    markov: ExperimentConfig,
    result: SequenceExperimentResult,
    stats: DatasetStats,
    prov: SequenceProvenance,
) -> Path:
    run_dir = reports_dir / "runs" / prov.run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    _dump(run_dir / "config.json", config_payload(config, markov, stats, prov))
    _dump(run_dir / "metrics.json", metrics_payload(config, result, stats))
    _dump(run_dir / "predictions.json", predictions_payload(result, prov.run_id))
    _dump(run_dir / "training_history.json", history_payload(result))
    (run_dir / "summary.md").write_text(
        summary_markdown(config, result, stats, prov), encoding="utf-8"
    )
    return run_dir


def sequence_record(
    config: SequenceConfig,
    result: SequenceExperimentResult,
    stats: DatasetStats,
    prov: SequenceProvenance,
    run_dir: Path,
) -> EvaluationResult:
    metrics: dict[str, float] = {}
    for m in result.single_step:
        for k in METRIC_NAMES:
            metrics[f"single.{m.model}.macro.{k}"] = m.macro[k].mean
            metrics[f"single.{m.model}.micro.{k}"] = m.micro[k]
    for ms in result.multistep:
        for k, v in ms.macro.items():
            metrics[f"multistep.h{ms.horizon}.{ms.model}.macro.{k}"] = v.mean
    folds = [
        EvaluationFold(
            fold_id=r.fold_id,
            train_sources=[f"group:{g}" for g in r.train_groups],
            validation_sources=[f"group:{g}" for g in r.validation_groups],
            test_sources=[f"group:{r.test_group}"],
        )
        for r in result.fold_records
    ]
    preprocessing: dict[str, JsonValue] = {
        "weighting": config.weighting.value,
        "vocabulary_version": stats.vocabulary_version,
        "revoked_ids_remapped": stats.revoked_ids_remapped,
        "unk_targets_dropped": stats.unk_targets_dropped,
        "processed_corpus_sha256": prov.corpus_sha256,
    }
    model_configuration: dict[str, JsonValue] = {
        "models": [m.model for m in result.single_step],
        "lstm_candidates": len(config.lstm_candidates),
        "fusion_alphas": list(config.fusion_alphas),
        "beam_width": config.beam_search.beam_width,
        "horizons": list(config.beam_search.horizons),
        "run_dir": str(run_dir),
        "checkpoint_dir": prov.checkpoint_dir,
        "baseline_reproduction": {k: v for k, v in result.baseline_reproduction.items()},
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
        seed=config.seed,
        preprocessing_config=preprocessing,
        model_configuration=model_configuration,
        metrics=metrics,
        folds=folds,
        runtime_s=prov.runtime_s,
        environment=prov.environment,
        notes="; ".join(f"{k}: {v}" for k, v in NOT_EVALUATED.items()),
    )


def store_sequence_record(store: Store, record: EvaluationResult) -> EvaluationResult:
    store.put(Collection.EVALUATION_RUNS, record)
    restored = store.get(Collection.EVALUATION_RUNS, record.run_id)
    if not isinstance(restored, EvaluationResult) or restored != record:
        raise RuntimeError("Stored evaluation record did not round-trip exactly")
    return restored
