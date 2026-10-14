"""Milestone 4: LSTM + Markov/LSTM fusion + beam search (nested LOGO, CPU).

Usage:
    python evaluation/run_sequence_models.py [--fold-limit N]

Writes reports/runs/<run-id>/ (new run ID; the Milestone 3 run is never modified),
per-fold LSTM checkpoints under models/generated/attack_prediction/<run-id>/lstm/,
and an EvaluationResult in SQLite. ``--fold-limit`` is for smoke tests only.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from hqc.common.logging import configure_logging
from hqc.common.provenance import load_manifest, sha256_file
from hqc.common.repro import (
    environment_info,
    git_commit,
    git_working_tree_dirty,
    package_versions,
    set_global_seed,
)
from hqc.common.schemas.base import utc_now
from hqc.config import PROJECT_ROOT, get_settings
from hqc.evaluation.prerequisites import require_processed_corpus, run_cli
from hqc.evaluation.sequence_experiment import (
    FoldRecord,
    load_sequence_config,
    run_sequence_experiment,
)
from hqc.evaluation.sequence_tracking import (
    SequenceProvenance,
    make_sequence_run_id,
    sequence_record,
    store_sequence_record,
    write_sequence_run,
)
from hqc.evaluation.splits import Fold
from hqc.mitre.knowledge_base import AttackKnowledgeBase
from hqc.mitre.paths import (
    manifest_path,
    vocabulary_path,
)
from hqc.prediction.base import OutputSpace
from hqc.prediction.dataset import build_dataset, load_corpus
from hqc.prediction.lstm import LSTMCheckpointMetadata, TrainedLSTM, save_checkpoint
from hqc.prediction.vocabulary import TechniqueVocabulary
from hqc.storage import SQLiteStore

DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "sequence_prediction.yaml"


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--fold-limit", type=int, default=None)
    args = parser.parse_args()
    configure_logging(settings.log_level, json_output=False)
    config, markov = load_sequence_config(args.config, PROJECT_ROOT)
    set_global_seed(config.seed)
    started = time.perf_counter()
    created_at = utc_now()
    run_id = make_sequence_run_id(created_at)
    commit, dirty = git_commit(PROJECT_ROOT), git_working_tree_dirty(PROJECT_ROOT)

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
    checkpoint_dir = (
        settings.resolve(settings.models_dir) / "generated" / "attack_prediction" / run_id / "lstm"
    )
    versions = package_versions()

    def write_checkpoint(fold: Fold, record: FoldRecord, trained: TrainedLSTM) -> str:
        metadata = LSTMCheckpointMetadata(
            attack_version=vocabulary.attack_version,
            vocabulary_version=vocabulary.vocabulary_version,
            output_size=space.size,
            training_groups=list(record.train_groups),
            validation_groups=list(record.validation_groups),
            test_group=fold.test_group,
            hyperparameters=trained.config,
            seed=trained.config.seed,
            best_epoch=trained.best_epoch,
            epochs_trained=len(trained.history),
            selection=(
                f"candidate {record.selected_candidate} chosen by inner validation loss; "
                "retrained on all outer-training groups for the inner best epoch"
            ),
            package_versions=versions,
            git_commit=commit,
            git_dirty=dirty,
            evaluation_run_id=run_id,
        )
        path = checkpoint_dir / fold.fold_id
        save_checkpoint(trained.model, metadata, path)
        return str(path.relative_to(PROJECT_ROOT))

    reference = (
        settings.resolve(settings.reports_dir)
        / "runs"
        / (config.reference_run or "")
        / "metrics.json"
    )
    result = run_sequence_experiment(
        dataset,
        vocabulary,
        space,
        tactics,
        config,
        markov,
        reference_metrics=reference if config.reference_run else None,
        checkpoint_writer=write_checkpoint,
        progress=print,
        fold_limit=args.fold_limit,
    )
    prov = SequenceProvenance(
        run_id=run_id,
        created_at=created_at,
        git_commit=commit,
        git_dirty=dirty,
        environment=environment_info(),
        runtime_s=time.perf_counter() - started,
        config_path=str(args.config.resolve().relative_to(PROJECT_ROOT)),
        corpus_sha256=corpus_sha,
        checkpoint_dir=str(checkpoint_dir.relative_to(PROJECT_ROOT)),
    )
    run_dir = write_sequence_run(
        settings.resolve(settings.reports_dir), config, markov, result, dataset.stats, prov
    )
    with SQLiteStore(settings.resolve(settings.db_path)) as store:
        store_sequence_record(store, sequence_record(config, result, dataset.stats, prov, run_dir))
    print(f"run {run_id} -> {run_dir.relative_to(PROJECT_ROOT)} ({prov.runtime_s:.1f} s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
