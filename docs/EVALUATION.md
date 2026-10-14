# Evaluation protocol

Applies to next-technique prediction: Milestone 3 baselines and Milestone 4 LSTM, fusion and beam search. Detection (Milestone 5) and the quantum second opinion (Milestone 6) use whole-day holdouts with leave-one-training-day-out tuning; see `CLASSICAL_DETECTION.md` and `QUANTUM_ADJUDICATOR.md`.

## Outer split: leave-one-group-out
- **Unit:** the Milestone 2 `source_group`, derived from the flow name with variant labels stripped. Both OpenClaw documents form one group, as do the three CISA AA22-138B variants.
- **Folds:** **37 groups → 37 folds**, sorted by group name. Each group is held out exactly once.
- **Empty fold:** 1 fold (OpenClaw) has no evaluation instances. It is held out but contributes no metrics, so macro statistics use **36 groups**.
- **Disjointness enforcement, at three levels:**
  - `assert_disjoint`, per fold.
  - The `EvaluationFold` schema validator.
  - The stored `EvaluationResult` carries all 37 folds with their train/test sources as `group:` and `document:` identifiers.

## Inner tuning (nested)
For each outer fold, `hqc.evaluation.tuning.tune` receives **only the outer-training groups**:
1. Inner leave-one-group-out over those groups. Each inner fold fits counts on the other training groups and scores the held-out training group.
2. The selection criterion is the mean over inner groups of the per-group mean **log loss**. Ties go to the first grid entry.
3. The selected configuration is refit on all outer-training groups.
4. That model is scored **once** on the outer test group.

The outer test group never influences hyperparameters, smoothing, weighting choice, the vocabulary (built from the KB) or preprocessing. A regression test spies on every `tune()` call and asserts it receives exactly the outer-training groups.

### Grids
The grids are in `configs/chain_prediction.yaml`; sizes are B1 7, M1 70, M2 495.

**Grid history:**
- The initial grids were widened *before* the real run.
- Reason: a timing trial (3 folds, inner tuning on training groups only, no outer scores computed) selected boundary values.
- In the real run, selections were **still at the maximum smoothing in every fold**. That is reported as a limitation; the grid was not widened again after seeing outer results.

## Metrics (`hqc.evaluation.metrics`)
| Metric | Definition |
|---|---|
| top-k (k = 1, 3, 5) | 1 if the true technique's rank ≤ k. Rank uses probability descending, with ties broken by vocabulary index |
| MRR | mean of 1/rank |
| log loss | −ln P(true technique), natural log. P > 0 is guaranteed by smoothing |
| next-tactic accuracy | 1 if the top-1 technique shares **at least one** ATT&CK tactic with the true technique ("any-overlap"; no single tactic is invented). No tactics counts as a miss |
| tie-aware top-k / MRR | expected value if tied outputs were randomly ordered. Diagnostic only, important for B0 |

All metrics are tested against hand-calculated examples (`tests/unit/test_evaluation_metrics_splits.py`).

## Aggregation and uncertainty
- **Macro (primary):** the mean over groups of the per-group mean, so every group has equal influence.
- **Micro:** the mean over all unique evaluation instances. It is dominated by Turla, so it is shown but never replaces macro.
- **Spread:** sample standard deviation over groups.
- **95% CI:** percentile bootstrap over groups, with 10,000 resamples and seed 42 (deterministic, nearest-rank).
- **Paired comparisons** (e.g. M2 − B1) are bootstrapped over the same groups. "CI excludes 0" is reported as a detected difference; otherwise the summary says **"difference unclear"**.

## Ablations
Every run evaluates all three training weightings: document (primary), raw and unique, with all four models and the same folds. A run's `--weighting` flag only chooses which one is primary (and which gets the `predictions.json` entries).

## Run folder: `reports/runs/<run-id>/` (git-ignored)
| File | Contents |
|---|---|
| `config.json` | Run ID, models, weightings, full grids, seed, dataset ID/version, processed-corpus SHA-256, ATT&CK and vocabulary versions, ID-cleanup counts, Python/package versions, git commit, **`working_tree_dirty`** |
| `metrics.json` | Macro (mean, std, CI), micro, per-group metrics and instance counts, per-fold selected hyperparameters, comparisons, boundary-selection counts, all ablations, dataset statistics |
| `predictions.json` | Every unique evaluation instance once (document, group, fold, prefix, true next, raw multiplicity) and, per model, the top-5 with probabilities, P(true) and true rank |
| `summary.md` | Protocol, dataset statistics, tables, comparisons, boundary selections, **TRAIN SOURCES / TEST SOURCES for every fold**, provenance, and `multi-step: NOT EVALUATED` |

The same run is stored as an `EvaluationResult` in SQLite (`data/hqc.sqlite3`, git-ignored). It is write-once, and the round trip is verified on write.

## How to read results
- **Compare with B0 and B1 first.** A sequence model is only useful if it beats B1, the context-free frequency baseline, on macro metrics with a paired CI excluding 0.
- **Treat log loss and ranking metrics separately.** Smoothing changes log loss strongly but barely changes B1's ranking.
- **Look at per-group results.** Many groups have few instances, and a macro mean can hide large variation.
- **Check `working_tree_dirty`.** If it is true, the git commit alone doesn't identify the exact source state.

## Milestone 4 additions
- **Inner validation groups** (about 20% of the outer-training groups with instances, minimum 2, fold-specific SHA-256 order) are used only for:
  - LSTM candidate selection;
  - early stopping;
  - fusion α.
- **Inner LOGO over the inner-training groups** selects the Markov component (M1 vs M2) used for α. The final Markov component is selected by inner LOGO over all outer-training groups.
- **Final LSTM:** retrained on all outer-training groups for the inner best epoch.
- **Never used for selection:**
  - the test-set α sweep, which is report-only;
  - beam width and horizons, which are fixed in advance.
- **Baseline reproduction:** B0/B1/M1/M2 are recomputed on identical instances, and the per-group maximum absolute difference from the stored Milestone 3 run is reported.
- **Multi-step metrics** (`path_hit@k`, `step{j}_acc`, `true_path_nll`) use branching-aware ground truth. The calibrated reach probability is **NOT EVALUATED** (see `LSTM.md`).
- **Run folder:** adds `training_history.json`, and `summary.md` lists **TRAIN / VALIDATION / TEST SOURCES** per fold.

## Commands
```bash
python evaluation/run_markov_baseline.py                    # primary: document weighting (+ raw, unique ablations)
python evaluation/run_markov_baseline.py --weighting raw
python evaluation/run_markov_baseline.py --weighting unique
python evaluation/run_sequence_models.py                    # Milestone 4 (measured 518 s on an Apple M4 CPU)
```
