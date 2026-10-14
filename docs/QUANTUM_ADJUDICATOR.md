# Quantum-kernel second opinion (Milestone 6)

Status: **implemented and evaluated** on the real CIC-IDS2017. Run `20261007T053257Z-quantum-adjudicator-cicids2017`, CPU, 962 s.

**No quantum advantage is claimed.** All quantum kernels are simulated exactly on a CPU (4–8 qubits). The research question is narrow:

> At matched data and feature budgets, does an entangling quantum kernel change detection quality compared with an RBF-SVM (and other classical arms), and with no second opinion at all?

A null result is a valid result.

The Milestone 5 primary detector (`random_forest`, run `20261006T195110Z-classical-detection-cicids2017`) stays the decision-maker, with its threshold of 0.5. It is loaded **read-only** and is not retrained. The run first checks that the reloaded model reproduces the stored Milestone 5 test predictions.

## Pipeline
```
Milestone 5 primary RF ──> p_classical (test days, unchanged)
                               │
       training out-of-fold p ─┴─> uncertainty bands |p - 0.5| <= h   (h from TRAINING OOF only)
                                        │
             band rows ──> angle features ──> kernel SVM ──> Platt ──> p_second ──> QuantumOpinion
                                                     └──────> stacking with p_classical ──> p_final
                                                              (evaluation arm only)
```

### Out-of-fold probabilities and uncertainty bands (`hqc.quantum.band`)
- **Out-of-fold scores:** for each training day (Monday, Tuesday, Wednesday), the Milestone 5 primary configuration is refitted on the *other two* training days, with the same feature-policy and preprocessing procedure, and scores the held-out day.
  - Monday contains no attacks, so its fold has no ROC-AUC.
  - Each held-out day's attack types are unseen by that fold's model, which mirrors the test situation.
- **Bands:** `|p − 0.5| ≤ h`. Here `h` is the `coverage` quantile of the out-of-fold margins `|p_oof − 0.5|`.
  - Config: `primary_band_coverage: 0.10` (the primary band) and `secondary_band_coverage: 0.05`.
  - **Every threshold is derived exclusively from training out-of-fold probabilities.** The band's coverage on the test days is a measured outcome, never a tuning target.

### Angle features (`hqc.quantum.features`), fitted on each training sample only
1. Milestone 5 `Preprocessor` with the same feature policy, *refitted on the sample rows*: ±∞ → NaN → median, standardise, one-hot protocol.
2. Top-16 features by mutual information with the label.
3. PCA(d).
4. Min–max to [0, π], with test values clipped.

Every model arm in a comparison uses the same fitted features.

### Feature maps and kernels (`hqc.quantum.feature_maps`, `kernels`)
- **`zz_qsvm` (main model):** fidelity kernel `K(x, y) = |⟨ψ(x)|ψ(y)⟩|²` of Qiskit's `zz_feature_map(d, reps=2, entanglement="linear")`, applied to angles × bandwidth α. This is an entangling feature map.
- **`z_qsvm` (control):** `z_feature_map`, a product state. Its kernel factorises over qubits and is classically computable. A test checks the closed form `∏ cos²(xᵢ − yᵢ)` for reps=1.
- **Simulation:** statevectors come from our own batched NumPy implementation. The phase layers are diagonal, plus Hadamard layers.
  - **Validation:** tests check them against `qiskit.quantum_info.Statevector` of the Qiskit 2.5.2 circuits to 1e-10, including global phase. The measured agreement is about 1e-15.
- **Classical arms on the same features:**
  - `rbf_svm`, tuned over γ and C;
  - `linear_svm` and `logreg`, tuned over C;
  - `random_forest`, with the fixed Milestone 5 settings.
- **One solver:** every SVM uses `sklearn.svm.SVC(kernel="precomputed")`. Inference uses support vectors only.
- **Diagnostics:**
  - kernel–target alignment;
  - off-diagonal mean and standard deviation (a concentration check);
  - minimum eigenvalue;
  - **geometric difference** `g(K_RBF ‖ K_Q)` (Huang et al., 2021; trace-normalised, λ = 1e-3).

### Hyperparameter selection (`hqc.quantum.cv`)
- **Folds:** leave-one-training-day-out. The angle features are refitted inside every fold.
- **Criterion:** balanced accuracy of the pooled out-of-fold predictions.
- **Ties:** go to the earliest candidate in the fixed grid order.
- **Grid** (as approved; not expanded):
  - C ∈ {0.1, 1, 10, 100}
  - α ∈ {0.05, 0.1, 0.25, 0.5, 1}
  - γ ∈ {0.01, 0.03, 0.1, 0.3, 1, 3}
- **No test-day data** is ever used.

### Solver and memory safety
- **Iteration cap:** libsvm's default is an unlimited number of SMO iterations. On the real data it **cycled indefinitely** for one rank-deficient linear Gram matrix (`linear_svm`, C=100, d=8), which aborted the first attempt.
  - Every SVC is now capped at 1,000,000 iterations.
  - A fit that hits the cap is flagged and reported, never hidden.
- **Chunked inference:** kernel inference runs in blocks of 20,000 rows, because the test bands contain hundreds of thousands of rows. This is numerically identical to unchunked inference (tested).
- **Aborted attempts:** neither change alters the grid, data or selection rule. The two aborted attempts wrote no outputs.

### Sampling (`hqc.quantum.sampling`)
- **Training samples:** day-stratified and balanced. Half are benign and half malicious; each class's quota is split evenly across the training days that contain that class. This way every leave-one-day-out training fold keeps both classes.
- **E2 test sample:** one fixed stratified sample (proportional to label) of the Thursday–Friday test days, seed 42.

### Fusion (`hqc.fusion.stacking`)
- **`p_second`:** Platt calibration of the adjudicator's out-of-fold decision values.
- **`p_final`:** `logit(p_final) = a·logit(p_classical) + b·decision + c`.
- **Fitting:** both are fitted on the training band sample's *out-of-fold* values only.
- **What is attached to results:** `p_final` is an **evaluation arm**. `attach_quantum_opinion` adds the `QuantumOpinion` to a `DetectionResult` and is guaranteed (and tested) never to change the classical verdict. Classical/quantum disagreement means "collect more evidence".

## Experiments
- **E2, matched budget:**
  - Arms: `zz_qsvm`, `z_qsvm`, `rbf_svm`, `linear_svm`, `logreg`, `random_forest`.
  - Grid: N_train ∈ {100, 250, 500, 1000, 2000} × d ∈ {4, 6, 8} × 5 seeds.
  - Evaluated on a fixed 10,000-row stratified test sample.
  - Reported: mean ± 95% t-CI over seeds, plus **paired** `zz − rbf` and `z − rbf` differences.
- **E3, second opinion in use:**
  - Adjudicators `rbf_svm`, `zz_qsvm` and `z_qsvm` (d = 8, N = 2000 from the training band).
  - Applied to the test rows that the primary RF places in each band.
  - Reported:
    - band and whole-test metrics for classical-only, second-opinion-alone and fused;
    - verdict flips (to correct or wrong);
    - disagreement versus classical error;
    - latency per event, both batched and for a single event.
- **E4, noise (reduced, 8 settings):**
  - Setup: ZZ kernel, d = 4, N_train = N_test = 200, Aer density-matrix simulation of the compute–uncompute circuit.
  - Shots-only settings at 256, 1024 and 4096 shots.
  - Depolarizing (p1, p2) plus readout settings: low (1e-4, 1e-3, 1%), mid (1e-3, 1e-2, 1%) and mid with 3% readout, each at 1024 shots; high (1e-2, 5e-2, 3%) at 1024 and 4096 shots.
  - Reported: kernel error versus the exact kernel, minimum eigenvalue, and the accuracy change.

## Measured results (run `20261007T053257Z-quantum-adjudicator-cicids2017`)
**Integrity checks:**
- The reloaded Milestone 5 primary detector reproduces its stored test predictions (max difference 5.0e-7, which is the 6-decimal rounding).
- The reloaded `primary/zz_qsvm` adjudicator reproduces its 351,705 test decisions exactly.
- SQLite record: task `quantum_comparison`, 416 metrics, train and test sources disjoint.

### Out-of-fold scores and the uncertainty bands
**Out-of-fold folds** (the primary configuration refitted without the held-out day):

| Held-out day | ROC-AUC |
|---|---|
| Monday | n/a (no attacks) |
| Tuesday | 0.674 |
| Wednesday | 0.503 |

Each held-out day's attack types are unseen by its fold model.

| Band | Target coverage | Band (from training OOF) | Train OOF coverage | **Test rows in band** |
|---|---|---|---|---|
| primary | 0.10 | [0.0000418, 0.9999582] | 0.0986 | **351,705 (30.3%)** |
| secondary | 0.05 | [0.0100, 0.9900] | 0.0488 | **218,363 (18.8%)** |

- **Finding 1: the out-of-fold Random Forest probabilities are extremely polarised.** About 90% of training rows score essentially exactly 0 or 1. The "10% least certain" training rows are therefore *any row without a unanimous tree vote*.
- **Finding 2: the test distribution shift is visible.** The same fixed bands capture 3–4× more test rows than training rows (30% vs 10%; 19% vs 5%).
  - The primary band holds almost all DDoS (127,933 of 128,027), 47% of PortScan (74,205), and all web brute-force and XSS flows.
  - Per the approved protocol, the bands were **not** re-tuned on test data.

### E2: matched budget (fixed 10,000-row stratified test sample; mean ± 95% t-CI over 5 seeds)
**Sample composition:** 7,495 benign; 1,367 PortScan; 1,102 DDoS; 17 Bot; 13 Web Brute Force; 6 XSS. Every value is in `summary.md` and `metrics.json`.

Selected cells (balanced accuracy / ROC-AUC / PR-AUC):

| N | d | zz_qsvm (entangling) | z_qsvm (product, classical) | rbf_svm | random_forest |
|---|---|---|---|---|---|
| 100 | 4 | 0.732 / 0.803 / 0.536 | 0.790 / 0.835 / 0.641 | 0.804 / 0.832 / 0.608 | 0.721 / 0.836 / 0.595 |
| 500 | 4 | 0.834 / 0.868 / 0.736 | 0.828 / 0.868 / 0.730 | **0.845** / 0.873 / 0.703 | 0.783 / **0.894** / **0.778** |
| 1000 | 4 | 0.830 / 0.877 / 0.734 | 0.836 / 0.877 / 0.758 | **0.848** / 0.883 / 0.719 | 0.711 / 0.886 / 0.781 |
| 2000 | 4 | 0.779 / 0.807 / 0.678 | 0.823 / 0.855 / 0.745 | **0.827** / 0.859 / 0.700 | 0.727 / 0.877 / 0.796 |
| 2000 | 8 | 0.684 / 0.705 / 0.572 | 0.716 / 0.704 / 0.630 | 0.718 / 0.643 / 0.572 | 0.710 / **0.895** / **0.811** |

**Paired ZZ − RBF differences (same samples and seeds):**
- **In no cell is the entangling kernel significantly better than the RBF-SVM** on balanced accuracy, ROC-AUC or PR-AUC; every 95% CI includes 0 or lies below it.
- It is significantly **worse** in 5 (cell, metric) combinations:

  | N | d | Metric | ZZ − RBF |
  |---|---|---|---|
  | 100 | 4 | balanced accuracy | −0.072 ± 0.044 |
  | 100 | 6 | ROC-AUC | −0.065 ± 0.037 |
  | 1000 | 4 | balanced accuracy | −0.018 ± 0.016 |
  | 2000 | 4 | balanced accuracy | −0.047 ± 0.024 |
  | 2000 | 4 | ROC-AUC | −0.052 ± 0.043 |

**Other observations:**
- **The classically computable product (Z) map** sometimes ranks better than the RBF kernel, e.g. N=2000, d=8: ROC-AUC +0.061 ± 0.027, PR-AUC +0.058 ± 0.033. Because this kernel is classically computable, **this is not evidence for quantum advantage**.
- **Threshold-free ranking:** the Random Forest on the same angle features is the best ranker at larger N (ROC-AUC up to 0.895, PR-AUC up to 0.811). However, it has the lowest recall, so the arms trade recall against benign FPR differently.
- **Effect of dimension:** at N=2000, the ZZ, Z and RBF arms all get worse as d increases from 4 to 8 (e.g. ZZ balanced accuracy 0.779 → 0.747 → 0.684).
- **Kernel diagnostics** (training Gram, at the selected hyperparameters):
  - **Geometric difference g(K_RBF ‖ K_ZZ):** large, with means 6–67 per (N, d) cell, versus g(K_RBF ‖ K_Z) ≈ 2–8. So the ZZ kernel *is* geometrically different from the RBF kernel, and the theoretical precondition for a possible advantage is met. Measured performance shows that difference does **not** translate into better detection on this task.
  - **Concentration:** across individual fits, ZZ off-diagonal means range from 0.10 to 0.89, with wide spread. Averaged per (N, d) cell they are about 0.28–0.41, with standard deviation about 0.30–0.40, so no exponential concentration at d ≤ 8.
  - **Kernel–target alignment** is low for every kernel (0.005–0.21 across all fits).

### E3: second opinion on the bands (d=8, N=2000 day-stratified balanced training-band sample)
| Arm (primary band, n=351,705) | Precision | Recall | F1 | ROC-AUC | PR-AUC | Benign FPR | Bal. acc |
|---|---|---|---|---|---|---|---|
| classical only | 0.9955 | 0.4038 | 0.5745 | 0.7843 | 0.8643 | 0.0026 | 0.7006 |
| classical + rbf_svm | 0.7232 | 0.8704 | 0.7900 | 0.8394 | 0.8872 | 0.4619 | 0.7042 |
| classical + **zz_qsvm** | 0.6964 | 0.8041 | 0.7464 | 0.7833 | 0.8307 | 0.4861 | 0.6590 |
| classical + z_qsvm | 0.7113 | 0.9337 | 0.8075 | 0.8435 | 0.8954 | 0.5255 | 0.7041 |

| Whole test set (1,162,213 rows; out-of-band rows keep the classical score) | Precision | Recall | ROC-AUC | PR-AUC | Benign FPR | Bal. acc |
|---|---|---|---|---|---|---|
| classical only | 0.9955 | 0.2834 | 0.8097 | 0.6900 | 0.0004 | 0.6415 |
| classical + rbf_svm | 0.7232 | 0.6109 | 0.8163 | 0.7060 | 0.0781 | 0.7664 |
| classical + **zz_qsvm** | 0.6964 | 0.5644 | 0.8096 | **0.6664** | 0.0822 | 0.7411 |
| classical + z_qsvm | 0.7113 | 0.6554 | 0.8168 | 0.7118 | 0.0889 | 0.7832 |

- **Fusion trades the detector's very low false-positive rate for recall.**
  - Every fused arm roughly doubles whole-test recall, but raises the benign FPR from 0.04% to 7.8–8.9%, i.e. tens of thousands of extra false alerts.
  - Cause: the fusion is fitted on a balanced training-band sample, and the test band is far larger and differently composed than the training band.
  - Threshold-free ranking barely moves (ROC-AUC 0.810 → 0.810–0.817).
- **The entangling ZZ adjudicator is the weakest of the three.** Its fused PR-AUC (0.666) is *below* classical-only (0.690); the RBF and the classically computable Z map are better.
- **Secondary band** (n=218,363; full table in `summary.md`):
  - ZZ fusion is worse than classical-only: band balanced accuracy 0.496 vs 0.755, whole-test 0.591 vs 0.642.
  - The Z map *alone* ranks inversely on test (ROC-AUC 0.134), a severe failure under distribution shift; fused with the classical score, it recovers (0.786).
- **The disagreement signal is informative in the primary band but not stable.**

  | Band | Arm | Classical error when the second opinion disagrees | … when it agrees |
  |---|---|---|---|
  | primary | ZZ | 0.52 | 0.21 |
  | primary | RBF | 0.56 | 0.14 |
  | primary | Z | 0.56 | 0.07 |
  | secondary | ZZ | 0.37 | 0.33 |
  | secondary | Z | 0.02 | 0.60 (inverted) |
- **Verdict flips** (fused vs classical verdict, primary band):

  | Arm | Flips | To correct | To wrong |
  |---|---|---|---|
  | ZZ | 153,064 | 81,803 | 71,261 |
  | RBF | 163,026 | 95,339 | 67,687 |
  | Z | 185,344 | 108,285 | 77,059 |

- **Latency** (Apple M4 CPU, exact simulation):

  | Arm | Batched (ms/event) | Single event, median (ms) |
  |---|---|---|
  | ZZ | 0.023 | 1.01 |
  | RBF | 0.004 | 0.57 |

- **Selected hyperparameters (primary band):** ZZ C=0.1, α=0.1; RBF C=100, γ=1.0; Z C=100, α=0.5. All final fits converged.

### E4: noise (ZZ, d=4, α=1, N_train = N_test = 200, one seed)
**Exact statevector baseline:** balanced accuracy 0.757, ROC-AUC 0.725.

| Setting | Relative kernel error (train / test) | Min eigenvalue (train) | Bal. acc | ROC-AUC |
|---|---|---|---|---|
| 256 shots | 0.043 / 0.047 | −0.47 | 0.673 | 0.718 |
| 1024 shots | 0.022 / 0.023 | −0.23 | 0.720 | 0.701 |
| 4096 shots | 0.011 / 0.012 | −0.11 | 0.743 | 0.714 |
| low noise, 1024 | 0.065 / 0.066 | −0.19 | 0.713 | 0.671 |
| mid noise, 1024 | 0.240 / 0.244 | −0.03 | 0.723 | 0.689 |
| mid noise + 3% readout, 1024 | 0.295 / 0.299 | 0.02 | 0.710 | 0.686 |
| high noise, 1024 | 0.729 / 0.739 | 0.51 | 0.610 | 0.660 |
| high noise, 4096 | 0.728 / 0.739 | 0.63 | 0.607 | 0.672 |

- **Shot noise:** kernel error falls as about 1/√shots (halving with every 4× more shots). Shot noise alone makes the Gram matrix indefinite: its minimum eigenvalue is negative.
- **Depolarizing noise:** it shrinks off-diagonal fidelities toward the maximally-mixed value, a systematic bias that more shots cannot remove. High noise costs about 0.15 balanced accuracy.
- **Caveat:** with N=200 and one seed, differences of a few points are within noise.

### Solver iteration cap (reported)
**6 of 450** E2 arm-cells hit the iteration cap, all `linear_svm`:
- 3 final fits did not converge: N=100 d=8 seed 4; N=250 d=8 seed 4; N=2000 d=6 seed 2.
- 3 cells had 1–2 capped CV fits.

No quantum, RBF, E3 or E4 fit hit the cap.

## Interpretation
- **No quantum advantage.** On this task, at matched budgets, the entangling ZZ quantum kernel is never significantly better than the RBF-SVM, and is sometimes significantly worse.
  - As a second opinion, it is the weakest adjudicator tested.
  - The product Z map, which is classically computable, does as well as or better than ZZ, so any benefit seen here does not depend on entanglement.
  - This is a valid null result. It is consistent with the large geometric difference: the ZZ kernel's geometry is different from the RBF kernel's, but not better aligned with these labels.
- **The second-opinion design works mechanically but is not an improvement at this operating point.**
  - The band derived from training out-of-fold scores covers 30% of test traffic, not 10%.
  - Fusion buys recall at a large false-positive cost.
  - The disagreement signal identifies classical errors in the primary band (ZZ: 0.52 vs 0.21) but is unreliable in the secondary band.
- **The classical verdict remains the system decision.** The `QuantumOpinion` is attached for evidence collection only.

## Limitations
- **Hyperparameters at the grid edge:** many selections are at an edge of the approved grid. In E2 this applies to 58/75 ZZ, 69/75 Z, 66/75 RBF, 56/75 linear SVM and 57/75 LR selections; it is mostly C=100, α=1.0 and γ=3.0. **The grid was not expanded**, as instructed, so better optima may lie outside it for every arm.
- **Fixed test sample:** E2 uses a single 10,000-row test sample. It has very few Bot and web-attack flows and no Infiltration or SQL-injection flows.
- **Single seed:** E3 and E4 use one seed.
- **Prior mismatch in fusion:** the fusion is fitted on a balanced sample, so it does not correct for the band's real prevalence.
- **Different classical scores for fitting and testing:** the stacking uses the fold RFs' out-of-fold probabilities when fitting, and the primary RF's probabilities at test.
- **Small noise study:** E4 uses N=200, d=4, a reduced 8-setting grid (as approved) and an idealised noise model (uniform depolarizing and readout, no device topology).
- **Simulation only:** all results are exact simulation on a CPU, so they say nothing about real hardware.
- **Labels:** CIC-IDS2017 labels are not ATT&CK techniques.
