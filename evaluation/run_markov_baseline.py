"""Milestone 3: leakage-free next-technique baselines (B0, B1, M1, M2).

Usage:
    python evaluation/run_markov_baseline.py                     # primary: document weighting
    python evaluation/run_markov_baseline.py --weighting raw     # raw counts as primary
    python evaluation/run_markov_baseline.py --weighting unique  # distinct transitions as primary

Every run evaluates all weightings (primary + ablations), writes
reports/runs/<run-id>/ and stores the EvaluationResult in SQLite. It also saves models
fitted on ALL groups (for later milestones) under models/generated/; their
generalisation estimate is the cross-validated result of this run, nothing else.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from hqc.common.logging import configure_logging, get_logger
from hqc.common.provenance import load_manifest, sha256_file
from hqc.common.repro import environment_info, git_commit, git_working_tree_dirty, set_global_seed
from hqc.common.schemas.base import utc_now
from hqc.config import PROJECT_ROOT, get_settings
from hqc.evaluation.chain_prediction import (
    ExperimentResult,
    build_group_data,
    fit_model,
    load_experiment_config,
    run_experiment,
)
from hqc.evaluation.prerequisites import require_processed_corpus, run_cli
from hqc.evaluation.tracking import (
    RunProvenance,
    evaluation_record,
    make_run_id,
    store_record,
    write_run,
)
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.paths import (
    manifest_path,
    vocabulary_path,
)
from hqc.prediction.base import OutputSpace
from hqc.prediction.dataset import PredictionDataset, Weighting, build_dataset, load_corpus
from hqc.prediction.markov import (
    InterpolatedMarkovModel,
    MarkovModelArtifact,
    MarkovModelMetadata,
)
from hqc.prediction.vocabulary import TechniqueVocabulary
from hqc.storage import SQLiteStore

DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "chain_prediction.yaml"
log = get_logger("evaluation.run_markov_baseline")


def save_full_models(
    dataset: PredictionDataset,
    space: OutputSpace,
    result: ExperimentResult,
    config_path: Path,
    weighting: Weighting,
    run_id: str,
    seed: int,
    out_dir: Path,
) -> list[Path]:
    """Tune on all groups (inner LOGO) and fit B1/M1/M2 on all groups."""
    config = load_experiment_config(config_path, primary=weighting)
    data = build_group_data(dataset, weighting)
    primary = result.weighting_results[0]
    saved: list[Path] = []
    for spec in config.models:
        if not spec.grid:
            continue
        model, _ = fit_model(spec, data, space)
        assert isinstance(model, InterpolatedMarkovModel)
        summary = next(m for m in primary.models if m.model == spec.name)
        metadata = MarkovModelMetadata(
            model_type="interpolated-markov",
            model_name=spec.name,
            training_dataset=dataset.stats.dataset_id,
            dataset_version=dataset.stats.corpus_version,
            attack_version=dataset.stats.attack_version,
            vocabulary_version=dataset.stats.vocabulary_version,
            weighting=weighting.value,
            hyperparameters=model.params,
            training_groups=sorted(data),
            seed=seed,
            evaluation_run_id=run_id,
            evaluation_summary={
                f"macro_{k}": summary.macro[k].mean for k in ("top1", "top5", "mrr", "log_loss")
            },
            notes="Fitted on all groups; generalisation estimate = the run's nested LOGO CV.",
        )
        path = out_dir / f"{spec.name}.json"
        MarkovModelArtifact.from_model(model, metadata).save(path)
        saved.append(path)
    return saved


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--weighting", choices=[w.value for w in Weighting], default="document")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--no-save-models", action="store_true")
    args = parser.parse_args()
    configure_logging(settings.log_level, json_output=False)
    weighting = Weighting(args.weighting)
    config = load_experiment_config(args.config, primary=weighting)
    set_global_seed(config.seed)
    started = time.perf_counter()
    created_at = utc_now()

    manifest = load_manifest(manifest_path(settings))
    corpus_path = require_processed_corpus(settings, manifest)
    corpus_sha = sha256_file(corpus_path)

    kb = AttackKnowledgeBase.load(settings)
    vocabulary = TechniqueVocabulary.load(
        vocabulary_path(settings, settings.attack_version), settings.attack_version
    )
    dataset = build_dataset(load_corpus(corpus_path), kb, vocabulary)
    space = OutputSpace(vocabulary)
    tactics = {t.technique_id: list(t.tactic_ids) for t in kb.get_techniques()}
    log.info("dataset built", extra={"stage": "prediction", **dataset.weighting_totals()})

    result = run_experiment(dataset, space, tactics, config, progress=print)
    run_id = make_run_id(weighting.value, created_at)
    prov = RunProvenance(
        run_id=run_id,
        created_at=created_at,
        seed=config.seed,
        git_commit=git_commit(PROJECT_ROOT),
        git_dirty=git_working_tree_dirty(PROJECT_ROOT),
        environment=environment_info(),
        runtime_s=time.perf_counter() - started,
        config_path=str(args.config.resolve().relative_to(PROJECT_ROOT)),
        corpus_sha256=corpus_sha,
    )
    run_dir = write_run(settings.resolve(settings.reports_dir), config, result, dataset.stats, prov)
    with SQLiteStore(settings.resolve(settings.db_path)) as store:
        store_record(store, evaluation_record(config, result, dataset.stats, prov, run_dir))

    if not args.no_save_models:
        model_dir = (
            settings.resolve(settings.models_dir) / "generated" / "attack_prediction" / run_id
        )
        for path in save_full_models(
            dataset, space, result, args.config, weighting, run_id, config.seed, model_dir
        ):
            print(f"saved model {path.relative_to(PROJECT_ROOT)}")

    print(f"run {run_id} -> {run_dir.relative_to(PROJECT_ROOT)} ({prov.runtime_s:.1f} s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
