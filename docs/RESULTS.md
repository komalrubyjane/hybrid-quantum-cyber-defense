# Final results (Milestone 10)

Every number below was extracted by `evaluation/build_final_report.py` from the stored run folders under `reports/runs/`. Nothing is typed in by hand, and nothing was re-run for this report.

**Where to find the outputs:**
- **Machine-readable:** `artifacts/final/results.json` and `artifacts/final/tables/*.csv`.
- **Human-readable:** `artifacts/final/tables.md`.
- **Figures:** `artifacts/final/figures/*.svg`.

**Significance:** stated only where a paired test with a 95% CI excluding 0 exists. CIs are shown only where they were measured.

| Milestone | Run | Data |
|---|---|---|
| M3 | `20261006T173740Z-markov-baselines-document` | ATT&CK 19.2 + Attack Flow corpus (`main@8b6ca28bc13b`) |
| M4 | `20261006T181005Z-lstm-hybrid-beam-document` | same |
| M5 | `20261006T195110Z-classical-detection-cicids2017` | CIC-IDS2017 GeneratedLabelledFlows (zip SHA-256 `7bdbef28…d150ea27a`) |
| M6 | `20261007T053257Z-quantum-adjudicator-cicids2017` | same + the stored M5 primary detector |
| M7 | `20261007T083826Z-integration-synthetic-multistage` | **SYNTHETIC** scenario |

## 1. Attack-chain prediction (M3/M4)
**Protocol:**
- Nested leave-one-group-out over 37 Attack Flow source groups, of which 36 are evaluable (fold-22 has no test instance).
- Document weighting; tuning on inner folds only.
- Results are the macro mean over groups with a 95% bootstrap CI.

| Model | Top-1 | Top-5 | MRR | Log loss |
|---|---|---|---|---|
| B0 uniform | 0.0046 [0.000, 0.014] | 0.0102 [0.001, 0.024] | 0.0166 [0.010, 0.027] | 6.547 |
| **B1 frequency** | **0.0736** [0.043, 0.107] | 0.1325 [0.089, 0.180] | 0.1205 [0.088, 0.156] | **5.724** [5.480, 5.963] |
| M1 first-order Markov | 0.0498 [0.029, 0.073] | 0.1380 [0.097, 0.182] | 0.1091 [0.083, 0.137] | 5.853 [5.589, 6.112] |
| M2 variable-order Markov | 0.0521 [0.030, 0.076] | 0.1368 [0.095, 0.181] | 0.1110 [0.084, 0.139] | 6.235 [5.852, 6.622] |
| LSTM | 0.0711 [0.041, 0.104] | **0.1621** [0.111, 0.219] | **0.1218** [0.090, 0.156] | 5.896 [5.667, 6.117] |
| HYBRID (α·LSTM + (1−α)·M1) | 0.0573 [0.033, 0.085] | 0.1560 [0.106, 0.209] | 0.1149 [0.087, 0.145] | 5.736 [5.507, 5.956] |

**Paired differences** (95% CI; **significant** = CI excludes 0):

| Comparison | Top-1 | Top-5 | MRR | Log loss |
|---|---|---|---|---|
| LSTM − B1 | −0.0025 (n.s.) | **+0.0296** [0.006, 0.055] | +0.0013 (n.s.) | **+0.172** [0.047, 0.294] (LSTM worse) |
| HYBRID − B1 | **−0.0163** [−0.033, −0.003] (HYBRID worse) | +0.0235 (n.s.) | −0.0056 (n.s.) | +0.012 [−0.075, 0.096] (n.s.) |
| HYBRID − LSTM | **−0.0138** (HYBRID worse) | −0.0061 (n.s.) | −0.0069 (n.s.) | **−0.161** [−0.213, −0.110] (HYBRID better) |

**Findings:**
- The LSTM improves only top-5 over B1, by about +0.030.
- The hybrid improves log loss relative to the **LSTM**, but **not** relative to B1: there is no significant difference.
- The hybrid is significantly worse than B1 on top-1.
- The LSTM ranks **T1105** first in 99.9% of test instances, the same as B1's constant prediction.

**Multi-step** (beam width 10, macro mean):
- Exact H = 3 path hits are essentially zero: path_hit@10 is 0.0033 (B1), 0.0015 (LSTM) and 0.0 (HYBRID, MARKOV).
- At H = 2, path_hit@10 is at most 0.044 (B1).
- Reach probabilities for Impact or Exfiltration were **not evaluated**: beam scores are only lower bounds.

**These results do not establish strong multi-step attack-chain prediction.**

## 2. CIC-IDS2017 classical detection (M5)
**Data and setup:**
- **Rows:** 2,830,743 flows (8 CSVs), 19.7% malicious.
- **Split:** whole-day, train Monday–Wednesday (1,668,530) and test Thursday–Friday (1,162,213). No test attack type occurs in training.
- **Threshold:** fixed at 0.5.
- **Primary detector:** Random Forest, pre-registered.
- **Runs:** single run; no CIs exist.

| Model / features (all test rows) | Precision | Recall | F1 | ROC-AUC | PR-AUC | Benign FPR |
|---|---|---|---|---|---|---|
| **Random Forest / full (primary)** | **0.9955** | 0.2834 | 0.4412 | 0.8097 | 0.6900 | **0.0004** |
| Logistic Regression / full | 0.8206 | 0.4582 | 0.5880 | 0.7184 | 0.6426 | 0.0335 |
| Logistic Regression / no destination port | 0.5926 | 0.7073 | 0.6449 | 0.9008 | 0.7144 | 0.1625 |
| Random Forest / no destination port | 0.9892 | 0.2517 | 0.4012 | 0.8893 | 0.7116 | 0.0009 |

**Detection by attack type (primary RF, fraction flagged malicious):**

| Label | Fraction |
|---|---|
| DDoS | 0.633 |
| Web Brute Force | 0.615 |
| XSS | 0.716 |
| SQL injection (n=21) | 0.143 |
| **PortScan** | **0.0009** |
| **Bot** | **0.000** |
| **Infiltration** | **0.000** |

The RF misses essentially all port scans, botnet traffic and infiltration.

**Duplicate feature vectors (full features):**
- 69,459 test rows (6.0%) have a feature vector that also occurs in training; 83 of those carry a conflicting label.
- Excluding them leaves recall unchanged (RF 0.2834 → 0.2834). Precision and PR-AUC rise slightly: RF PR-AUC 0.6900 → 0.7011.

**Destination-port ablation:**
- Removing destination port improves threshold-free ranking for both models: RF ROC-AUC 0.810 → 0.889, LR 0.718 → 0.901. This is consistent with destination port acting as a shortcut that does not transfer to unseen attack types.
- The primary detector was pre-registered and was not changed.

## 3. Quantum second opinion (M6)
**Setup:**
- Exact statevector fidelity kernels computed with a batched NumPy implementation, validated to about 1e-15 against `qiskit==2.5.2` `Statevector`.
- `qiskit-aer==0.17.2` is used for the noise study only.
- Kernels: an entangling ZZ map, plus a non-entangling Z map as a control.
- Classifier: `sklearn` SVC on precomputed kernels.

**Uncertainty bands** (derived only from training out-of-fold probabilities):

| Band | Interval | Train OOF coverage | Test coverage |
|---|---|---|---|
| primary (target 10%) | [0.000042, 0.999958] | 9.9% | **30.3%** (351,705 rows) |
| secondary (target 5%) | [0.01, 0.99] | 4.9% | **18.8%** (218,363 rows) |

**E2, matched budget** (5 seeds × N ∈ {100, 250, 500, 1000, 2000} × d ∈ {4, 6, 8}; mean ± 95% t-CI; the full grid is in `tables/quantum_matched_budget.csv` and `figures/06_quantum_matched_budget.svg`):
- **ZZ never significantly beat the RBF-SVM** on balanced accuracy, ROC-AUC or PR-AUC.
- **ZZ was significantly worse in five (cell, metric) cases** (ZZ − RBF):

  | N | d | Metric | Difference |
  |---|---|---|---|
  | 100 | 4 | balanced accuracy | −0.072 ± 0.044 |
  | 100 | 6 | ROC-AUC | −0.065 ± 0.037 |
  | 1000 | 4 | balanced accuracy | −0.018 ± 0.016 |
  | 2000 | 4 | balanced accuracy | −0.047 ± 0.024 |
  | 2000 | 4 | ROC-AUC | −0.052 ± 0.043 |
- The classically computable Z control performed comparably to ZZ. No paired ZZ–Z test was run.

**E3, fusion on the primary band** (whole test set, single seed):

| Arm | Precision | Recall | F1 | ROC-AUC | PR-AUC | Benign FPR |
|---|---|---|---|---|---|---|
| RF alone | 0.9955 | 0.2834 | 0.4412 | 0.8097 | 0.6900 | 0.0004 |
| RF + ZZ | 0.6964 | 0.5644 | 0.6235 | 0.8096 | **0.6664** | 0.0822 |
| RF + RBF | 0.7232 | 0.6109 | 0.6623 | 0.8163 | 0.7060 | 0.0781 |
| RF + Z | 0.7113 | 0.6554 | 0.6822 | 0.8168 | 0.7118 | 0.0889 |

- **ZZ is the weakest second opinion.**
- Fused recall rises only with roughly a 200× increase in benign FPR (0.04% → 7.8–8.9%).
- RF + ZZ PR-AUC falls below RF alone. This is **not** an unconditional improvement.
- On the secondary band, RF + ZZ recall (0.208) falls *below* RF alone (0.283).

**E4, noise** (ZZ, d = 4, N_train = N_test = 200, single seed):
- **Shot noise:** relative kernel error roughly halves for every 4× more shots. Train: 4.3% → 2.2% → 1.1%; test: 4.7% → 2.3% → 1.2% (256 → 1024 → 4096 shots).
- **High depolarizing + readout noise** (p1 = 0.01, p2 = 0.05, readout 3%): relative kernel error **0.73** (train) / **0.74** (test). Balanced accuracy falls from **0.757** (exact) to **0.61**.

**Conclusion: no quantum advantage was observed under the tested conditions.**

## 4. Integration demonstration (M7, SYNTHETIC)
**This is a synthetic demonstration, NOT a real-world validated attack-chain dataset evaluation.** The scenario's events, detector scores and ATT&CK annotations are hand-authored.

| Chain | Observed (in arrival order) | Top next (next-step probability) | MODEL-DERIVED risk | Recommendations (all PROPOSED, approval required) |
|---|---|---|---|---|
| chain-syn-ms-e01 (correlated) | T1190 → T1059.004 → T1098.004 → T1003.008 → T1021.004 → T1041 | T1105 (0.0904) | **76.45 CRITICAL** (NEEDS ADDITIONAL EVIDENCE) | escalate; restrict communication; collect evidence; monitor |
| chain-syn-ms-e07 (standalone failed login) | T1110.001 | T1105 (0.0238) | 44.38 MEDIUM | collect evidence; monitor |

**Risk progression of the main chain:** 57.19 (after the first event) → 58.63 → 59.13 → 65.93 → 71.72 → 76.55 (after exfiltration).

**Checks:**
- Integration checks: 13/13 passed.
- **Disagreement policy on stored real M6 outputs:** 152,041 of 351,705 band rows disagree, and all become NEEDS ADDITIONAL EVIDENCE. This is policy behaviour, not performance.
- **M10 end-to-end validation** (`artifacts/final/e2e_validation.json`): 17/17 checks passed through the API. The live risk score, 76.4492, reproduces the stored M7 run exactly.

## Figures
| File | Content |
|---|---|
| `01_prediction_top1_top5.svg`, `02_prediction_mrr.svg`, `03_prediction_log_loss.svg` | Prediction metrics with 95% CIs (points and whiskers; no bars) |
| `04_detection_precision_recall_f1.svg`, `05_detection_auc.svg` | CIC-IDS2017 detectors (single run; no CIs exist) |
| `06_quantum_matched_budget.svg` | E2 balanced accuracy vs N for d = 4/6/8, with 95% t-CIs |
| `07_quantum_fusion_tradeoff.svg` | E3 precision / recall / benign FPR / PR-AUC |
| `08_shot_noise.svg`, `09_depolarizing_noise.svg` | E4 kernel error and balanced accuracy |
| `10_architecture.svg` | As-built pipeline |
