# LSTM, Markov+LSTM fusion and beam search (Milestone 4)

Status: **implemented and evaluated** (run `20261006T181005Z-lstm-hybrid-beam-document`).

**Research question:** does sequence learning add predictive information beyond the context-free frequency (B1) and Markov baselines, on *unseen* Attack Flow source groups?

## Data and protocol
Everything from Milestone 3 is reused unchanged:
- ATT&CK 19.2, vocabulary `v1-attack-19.2-f42457f4db96`, `source_group` definitions, ID clean-up (11 revoked IDs remapped; `<UNK>` for unknown IDs, never a target).
- The 43,179 unique evaluation instances.
- **Outer leave-one-group-out** (37 groups; 36 have instances).

The B0/B1/M1/M2 baselines are recomputed with the Milestone 3 code inside the Milestone 4 run and checked against the stored Milestone 3 run, which is never modified (§ reproduction check).

## LSTM (`hqc.prediction.lstm`)
**Architecture:** `Embedding(699, E, padding_idx=<PAD>) → LSTM(E, H, layers) → Dropout → Linear(H, 697)`, then softmax.
- The output layer covers only the **697 active techniques**, so `<PAD>` and `<UNK>` can never be predicted.
- **Input:** the last `context_length` vocabulary indices of the observed prefix, oldest first. `<UNK>` may appear; `<PAD>` is padding only, handled with packed sequences.
- **No future leakage:** examples are built from `PredictionInstance.prefix` only, and a test checks `[T1, T2, T3] → T4` never contains T4 in the input.

**Training:**
- **Loss:** weighted cross-entropy with **document-normalised weights** (each document totals 1), the accepted Milestone 3 policy. There is no oversampling, and test data is never touched.
- **Merging:** identical (truncated context, target) examples are merged by summing weights, which leaves the weighted loss unchanged.
- **Optimiser:** Adam with weight decay.
- **Determinism:** seeded `torch` and shuffling generator, `torch.use_deterministic_algorithms(True)`, fixed thread count, **CPU only**. Apple MPS is available on this machine but not used, because it is not deterministic.

**Early stopping:** on inner-validation loss only, with patience 3, `min_delta` 1e-4 and at most 25 epochs. The best-epoch weights are restored.

**Candidates:** 8 configurations, pre-registered in `configs/sequence_prediction.yaml`. They are a fixed subset of the requested example grid that covers every listed value: embedding {32, 64}, hidden {64, 128}, layers {1, 2}, dropout {0, 0.2}, learning rate {1e-3, 3e-4}, weight decay {0, 1e-4}, context {3, 5, 10}. Batch size is 128.

## Nested selection inside each outer fold
All of the following use **only the outer-training groups**:
1. **Inner validation groups:** about 20% of the outer-training groups that have instances (minimum 2), chosen by SHA-256 of `seed|fold|group`. The order is deterministic and fold-specific, not alphabetical.
2. **LSTM selection:** each candidate trains on the inner-training groups with early stopping on the validation groups. The lowest validation loss wins (ties go to the first candidate).
3. **Inner Markov:** M1 vs M2, tuned by inner leave-one-group-out over the **inner-training** groups with the Milestone 3 grids. This keeps the validation groups unseen by the Markov component used to choose α.
4. **Fusion α ∈ {0, 0.1, …, 1}:** minimises validation macro log loss of `α·P_LSTM + (1−α)·P_Markov`. Ties go to the smaller α.
5. **Final models on all outer-training groups:**
   - the selected LSTM, retrained for the selected best epoch;
   - Markov (M1 vs M2 by inner LOGO over all outer-training groups);
   - B1 (for the beam-search reference).
6. **Single evaluation on the outer test group.**

**Leakage tests** spy on every training, tuning and validation entry point and assert that the fold's test group never appears. Candidate training only ever sees validation groups for early stopping; the final model trains for a fixed number of epochs without validation.

## Fusion (`hqc.prediction.fusion`)
`P_hybrid = α·P_LSTM + (1−α)·P_Markov`, renormalised with the shared `normalize`. α = 0 returns the Markov distribution and α = 1 the LSTM distribution *exactly*. A test confirms the α = 0 and α = 1 endpoints of the test-set sweep equal the MARKOV and LSTM rows.

The **test-set α sweep** in the run is **report-only**. It is never used for any selection.

## Beam search (`hqc.prediction.beam_search`)
- Expands every partial path with every output technique using `model.distribution(observed prefix + generated path)` only.
- Scores by cumulative log probability, breaks ties by vocabulary-index order, and returns paths of exactly `horizon` steps with rank, probability and log probability.
- The observed prefix is never modified, and repeated techniques are allowed.
- **Settings:** beam width 10, horizons H ∈ {2, 3}, hit@k for k ∈ {1, 5, 10}. These are fixed in advance, with no tuning.

## Multi-step evaluation (`hqc.evaluation.multistep`)
- **Ground truth:** the true continuation `t(i+1)..t(i+H)` of the same source path.
- **Branching:** Attack Flow branches, so one (document, prefix) may have several true continuations, kept as alternatives.
- **Skipped:** continuations containing `<UNK>`, and prefixes with fewer than H remaining steps.

| Metric | Definition |
|---|---|
| `path_hit@k` | Any of the top-k beam paths equals any true continuation exactly |
| `step{j}_acc` | Step j of the top-1 beam path equals step j of any true continuation |
| `true_path_nll` | Mean over true continuations of −log P(continuation \| prefix) / H, by the chain rule. This scores the given path; it does not generate |

**Ground-truth isolation:** generated beams never depend on the true continuation, and a test confirms identical beams for different ground truths.

**NOT EVALUATED:**
- **Probability of reaching Impact or Exfiltration within H steps.** Beam search yields only a lower bound on that marginal probability. A calibrated estimate needs Monte Carlo rollouts or exact enumeration.
- **Monte Carlo rollouts.** Deferred.

## Checkpoints
`models/generated/attack_prediction/<run-id>/lstm/<fold>.pt` plus `.json`, git-ignored.

The metadata records:
- model type, ATT&CK and vocabulary versions;
- training, validation and test groups;
- hyperparameters, seed, training date, best epoch and epochs trained;
- the selection rule, package versions, git commit and dirty flag.

## Run artifacts
`reports/runs/<run-id>/` contains `config.json`, `metrics.json`, `predictions.json`, `training_history.json` (every candidate's and the final model's per-epoch train and validation loss), and `summary.md` (with **TRAIN / VALIDATION / TEST SOURCES** for every fold). The run is also stored as an `EvaluationResult` in SQLite, with `validation_sources` per fold.

## Measured results — run `20261006T181005Z-lstm-hybrid-beam-document`
CPU, 518.4 s in total. Macro is the mean over the **36 groups with instances**, shown as [95% bootstrap CI over groups]. Copied from the run's `summary.md` and `metrics.json`.

**Baseline reproduction:** B0/B1/M1/M2 recomputed inside this run match the stored Milestone 3 run exactly (maximum per-group difference 0.0).

### Single step
| Model | top-1 | top-3 | top-5 | MRR | log loss | next-tactic |
|---|---|---|---|---|---|---|
| B0 | 0.0046 [0.0000, 0.0139] | 0.0086 | 0.0102 | 0.0166 | 6.5468 | 0.1526 |
| B1 | **0.0736** [0.0435, 0.1070] | 0.1135 | 0.1325 | 0.1205 | **5.7239** [5.4802, 5.9630] | 0.1526 |
| M1 | 0.0498 [0.0288, 0.0733] | 0.1181 | 0.1380 | 0.1091 | 5.8526 | 0.1551 |
| M2 | 0.0521 [0.0300, 0.0765] | **0.1189** | 0.1368 | 0.1110 | 6.2348 | **0.1563** |
| MARKOV (selected) | identical to M1 (M1 chosen in all 36 folds) | | | | | |
| LSTM | 0.0711 [0.0413, 0.1037] | 0.0973 | **0.1621** [0.1114, 0.2187] | **0.1218** [0.0900, 0.1558] | 5.8963 [5.6668, 6.1165] | 0.1541 |
| HYBRID | 0.0573 [0.0331, 0.0847] | 0.1120 | 0.1560 [0.1059, 0.2086] | 0.1149 | 5.7355 [5.5069, 5.9561] | 0.1534 |

### Paired comparisons (macro difference [95% CI])
| Comparison | top-1 | top-5 | MRR | log loss (lower is better) |
|---|---|---|---|---|
| LSTM − B1 | −0.0025 [−0.0063, +0.0000] unclear | **+0.0296 [+0.0059, +0.0554]** | +0.0013 unclear | +0.1724 [+0.0475, +0.2939] (LSTM worse) |
| LSTM − M2 | +0.0190 [+0.0042, +0.0370] | +0.0253 unclear | +0.0108 unclear | −0.3385 [−0.5736, −0.1325] (LSTM better) |
| LSTM − MARKOV | +0.0214 [+0.0031, +0.0420] | +0.0240 unclear | +0.0126 unclear | +0.0437 unclear |
| HYBRID − B1 | −0.0163 [−0.0334, −0.0026] | +0.0235 unclear | −0.0056 unclear | +0.0116 unclear |
| HYBRID − LSTM | −0.0138 [−0.0308, −0.0008] | −0.0061 unclear | −0.0069 unclear | −0.1607 [−0.2133, −0.1096] (HYBRID better) |
| HYBRID − MARKOV | +0.0076 unclear | +0.0180 unclear | +0.0057 unclear | −0.1171 [−0.2072, −0.0347] (HYBRID better) |

### Interpretation (measured)
- **The LSTM's only clear gain over B1 is top-5 accuracy** (+0.030). Top-1 and MRR differences are unclear, and **its log loss is worse than B1's**.
- **The LSTM's top-1 is effectively the frequency baseline.** It ranks T1105 (Ingress Tool Transfer) first for **99.9%** of test instances, which is also B1's constant prediction. Learned context changes only ranks 2–5.
- **LSTM vs Markov:** the LSTM beats M1/M2 on top-1 and beats M2 on log loss.
- **Fusion:**
  - HYBRID improves log loss over both components (vs LSTM −0.16, vs MARKOV −0.12, CIs exclude 0).
  - HYBRID does **not** beat B1 on any metric (log loss difference unclear), and its top-1 is lower than both B1's and the LSTM's.
  - **Fusion did not produce a model better than the frequency baseline.**
- **Per group (LSTM vs B1):**
  - top-5: better in 9, worse in 7, tied in 20;
  - log loss: better in 12, worse in 24;
  - top-1: better in 0, worse in 2;
  - HYBRID beats B1 on log loss in 14 of 36 groups.
  - Turla Carbon: LSTM top-5 0.266 vs B1 0.156. Turla Snake and SolarWinds: LSTM top-5 is lower than B1's.
- **Answer to the research question:** on unseen source groups, sequence learning added a small, statistically detectable improvement in top-5 ranking. It did not improve top-1, MRR or log loss over the context-free frequency baseline.

### Fusion α
- **Selected on inner validation:** 0.7 (14 folds), 0.6 (10), 0.5 (5), 0.8 (3), 0.3 (2), 0.4 (1), 0.9 (1).
- **Report-only test sweep, not used for selection:**
  - log loss is lowest near α ≈ 0.5 (5.7151);
  - top-1 rises monotonically to α = 1 (0.0711);
  - the endpoints equal the MARKOV (α = 0) and LSTM (α = 1) rows, as required.

### Multi-step (beam width 10; macro mean)
| H | Model | path_hit@1 | path_hit@5 | path_hit@10 | step-1 acc | last-step acc | true-path NLL/step |
|---|---|---|---|---|---|---|---|
| 2 | B1 | 0.0075 | 0.0340 | 0.0440 | 0.0885 | 0.0738 | 5.7941 |
| 2 | MARKOV | 0.0000 | 0.0085 | 0.0132 | 0.0528 | 0.0362 | 5.9051 |
| 2 | LSTM | 0.0075 | 0.0203 | 0.0374 | 0.0885 | 0.0738 | 5.9583 |
| 2 | HYBRID | 0.0049 | 0.0127 | 0.0289 | 0.0727 | 0.0564 | **5.7895** |
| 3 | B1 | 0.0000 | 0.0000 | 0.0033 | 0.1072 | 0.0569 | **5.7718** |
| 3 | MARKOV | 0.0000 | 0.0000 | 0.0000 | 0.0745 | 0.0139 | 5.8934 |
| 3 | LSTM | 0.0000 | 0.0000 | 0.0015 | 0.1072 | 0.0569 | 5.9370 |
| 3 | HYBRID | 0.0000 | 0.0000 | 0.0000 | 0.0994 | 0.0436 | 5.7803 |

- **Multi-step accuracy is very low for every model.** Exact 3-step path matches are essentially zero.
- The LSTM's top beam path is (T1105, T1105) for 34,516 of 34,517 H = 2 prefixes, so its step accuracies equal B1's.
- **No model beats B1 at multi-step prediction.**
- **Instances:** 34,517 (H = 2) and 31,171 (H = 3). Continuations containing `<UNK>` were skipped: 12,310 and 18,465 raw continuations.
- **Reach-probability metric and Monte Carlo rollouts:** NOT EVALUATED (see above).

### Selected hyperparameters
- **LSTM candidates** (index into the config): 6 (9 folds), 5 (7), 4 (6), 1 (5), 0 (5), 2 (4). Candidates 3 and 7 were never selected.
- **Final epochs:** median 3 (range 2–10).
- **Markov:** M1 in every fold, both at the inner and the final stage.
- **B1 β:** 10000 in every fold (the grid maximum; see the Milestone 3 limitation).
- Full per-fold details are in `metrics.json` → `folds`.

## Limitations
1. **Collapse to the marginal at top-1.** The LSTM learned little beyond the global frequency ordering at rank 1 (T1105 first in 99.9% of instances). Larger models were not tried, by design, given the data size.
2. **Small candidate set and early stopping.** There are 8 pre-registered candidates. Candidate 7 (lr 3e-4, context 3) reached the 25-epoch cap in all 36 folds. It was never selected, but it may have been under-trained. Selected models stopped early (median best epoch 3), consistent with fast overfitting to the few training groups.
3. **Inner validation is a single split** (about 20% of training groups), not inner LOGO, for runtime reasons. Selection is therefore noisier than the Markov tuning.
4. **Data:** 36 evaluable groups, heavily skewed (Turla); cross-document generalisation only.
5. **Multi-step:**
   - branching makes several continuations valid, so step accuracy is set-based;
   - `<UNK>` continuations were skipped;
   - reach probability and Monte Carlo rollouts were not evaluated.
6. **Inherited Markov limitation:** the B1/Markov smoothing optimum lies at the grid boundary (see `ATTACK_CHAIN_PREDICTION.md`, limitation 1).
7. **Artifact size:** `predictions.json` is 211 MB (git-ignored).
