# Classical intrusion detection (Milestone 5)

Status: **implemented and evaluated** on the real CIC-IDS2017. Run `20261006T195110Z-classical-detection-cicids2017`, CPU, 192.9 s.

**Task:** binary detection, BENIGN vs MALICIOUS (MALICIOUS is the positive class). The original CIC-IDS2017 label is kept separately for analysis and is **never** a model input.

## Split: whole days (Option A, approved)
| Side | Days | Attack types present |
|---|---|---|
| Train | Monday, Tuesday, Wednesday | benign; FTP/SSH brute force (Patator); DoS (Hulk, GoldenEye, slowloris, Slowhttptest); Heartbleed |
| Test | Thursday, Friday | benign; web attacks (brute force, XSS, SQL injection); infiltration; botnet; port scan; DDoS |

Confirmed from the real label counts. **Train** (1,668,530 rows): BENIGN 1,402,023; DoS Hulk 231,073; DoS GoldenEye 10,293; FTP-Patator 7,938; SSH-Patator 5,897; DoS slowloris 5,796; DoS Slowhttptest 5,499; Heartbleed 11. **Test** (1,162,213 rows): BENIGN 871,074; PortScan 158,930; DDoS 128,027; Bot 1,966; Web Attack – Brute Force 1,507; XSS 652; Infiltration 36; SQL Injection 21. **No test attack type occurs in training.**

- **No row-level mixing.** `day_split` derives the split from the files present and fails if a configured day has no data, if a day is unassigned, or if a day appears on both sides.
- **This test distribution is deliberately much harder.** None of the test-day attack types occur in training, so the experiment measures **generalisation to unseen attack types**. Low recall on those categories is an **expected research finding**, and it is reported per attack label rather than hidden.

## Feature policy (`hqc.detection.preprocessing`, version `cicids2017-features-v1`)
Every data-dependent choice is made on **training days only**.

| Category | Columns | Reason |
|---|---|---|
| **DROPPED_IDENTIFIER_FEATURES** | `flow_id`, `source_ip`, `destination_ip`, `timestamp`, `source_port` | Flow and host identity, capture time and ephemeral ports let a model memorise flows or scenario timing (label proxies); they don't transfer |
| **DROPPED_LEAKAGE_FEATURES** | `raw_label`, `label`, `is_malicious`, `day`, `source_file`, `row_number` | Ground truth or split and bookkeeping keys |
| **DROPPED_NON_NUMERIC_FEATURES** | none expected (all remaining inputs are numeric) | n/a |
| Duplicate column | `fwd_header_length__dup1` | Dropped only if identical to `fwd_header_length` on every training row |
| Constant on training days | measured: `bwd_avg_bulk_rate`, `bwd_avg_bytes_bulk`, `bwd_avg_packets_bulk`, `bwd_psh_flags`, `bwd_urg_flags`, `cwe_flag_count`, `fwd_avg_bulk_rate`, `fwd_avg_bytes_bulk`, `fwd_avg_packets_bulk`, `fwd_urg_flags` | No information |
| **USED_FEATURES** | **67** numeric features (`destination_port` plus 66 flow statistics; the full list is in the run's `config.json`) plus `protocol` one-hot with training categories {0, 6, 17} | Behavioural flow features |
| Shortcut risk | `destination_port` | Meaningful service context, but a documented CIC-IDS2017 shortcut. A **no-destination-port ablation** is run |

## Preprocessing (train-only)
- **Steps:** ±∞ → NaN → training-day median; standardise with training mean and std; one-hot `protocol` with training categories (unseen protocols map to all zeros).
- **Determinism:** the column order is fixed.
- **Persistence:** saved as JSON with a content-hash version, verified on load.
- **Regression test:** poisoning the test data cannot change any fitted parameter, while fitting on train plus test *would* change them (`test_preprocessor_is_fitted_on_training_only`).

## Duplicate audit
Exact duplicate model-input vectors are hashed and counted:
- within training;
- within test;
- **test rows whose vector also occurs in training**, and how many of those carry a conflicting label.

**Policy:** rows are kept. Every model is evaluated on **all test rows** and on **test rows whose vector never occurs in training**.

## Models (pre-declared; no hyperparameter search; fixed threshold 0.5)
| Name | Estimator | Imbalance handling |
|---|---|---|
| `logreg` | LogisticRegression(lbfgs, C=1, max_iter=1000) | `class_weight="balanced"` |
| `random_forest` (**primary detector, pre-registered**) | RandomForestClassifier(100 trees, min_samples_leaf=2, max_features=sqrt) | `class_weight="balanced_subsample"` |

- **Seeds:** fixed (42). There is no oversampling.
- **Primary detector:** chosen *before* the run; it is never selected on test results.
- **Why no RBF SVM:** it is not run, because prediction on about a million test flows is impractical. Milestone 6 compares an RBF-SVM against the quantum kernel on matched small budgets.

## Detection results (`DetectionResult`)
Each result carries:
- verdict, P(MALICIOUS), threshold, confidence and uncertainty;
- model name and version, feature-policy version, preprocessing version;
- flow ID and evidence (timestamp, day, source file).

`dataset_label` is attached **only** for offline evaluation. The `quantum` slot is reserved for the Milestone 6 second opinion.

## Evaluation and tracking
- **Metrics:** accuracy, precision, recall, F1, ROC-AUC, PR-AUC, confusion matrix, benign false-positive rate and malicious detection rate. They are reported per model, feature set (full or no-destination-port), test subset, test day and **attack label**, together with the split, dataset version and feature version.
- **Run folder:** `reports/runs/<run-id>/` contains config.json (provenance, SHA-256, feature policy, split, configs, seed, environment, git commit and dirty flag), metrics.json, predictions.json (per-row test predictions plus example `DetectionResult`s) and summary.md.
- **SQLite record:** day and file sources, checked to be disjoint.
- **Models:** saved to `models/generated/detection/<run-id>/` (git-ignored).

## Measured results (held-out Thursday–Friday; threshold 0.5)
| Model | Features | Test subset | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | Benign FPR | Malicious DR |
|---|---|---|---|---|---|---|---|---|---|---|
| logreg | full | all rows (1,162,213) | 0.8392 | 0.8206 | 0.4582 | 0.5880 | 0.7184 | 0.6426 | 0.0335 | 0.4582 |
| **random_forest (primary)** | full | all rows | 0.8202 | **0.9955** | 0.2834 | 0.4412 | 0.8097 | 0.6900 | **0.0004** | 0.2834 |
| logreg | no dst-port | all rows | 0.8049 | 0.5926 | **0.7073** | **0.6449** | **0.9008** | **0.7144** | 0.1625 | 0.7073 |
| random_forest | no dst-port | all rows | 0.8119 | 0.9892 | 0.2517 | 0.4012 | 0.8893 | 0.7116 | 0.0009 | 0.2517 |

The test subset that excludes rows whose feature vector occurs in training (1,092,754 rows; 1,035,943 without destination port) leaves recall essentially unchanged, while precision and PR-AUC rise somewhat. Primary RF: precision 0.9979, recall 0.2834, PR-AUC 0.7011. LR full: precision 0.8729, PR-AUC 0.6614. LR no-dst-port: precision 0.6538, PR-AUC 0.7602. RF no-dst-port: precision 0.9927, PR-AUC 0.7413. Every value is in `metrics.json`.

**Confusion matrices (all test rows):**
- logreg/full: TN 841,911, FP 29,163, FN 157,750, TP 133,389.
- **random_forest/full:** TN 870,697, FP 377, FN 208,626, TP 82,513.
- logreg/no-dst-port: TN 729,523, FP 141,551, FN 85,220, TP 205,919.
- random_forest/no-dst-port: TN 870,276, FP 798, FN 217,870, TP 73,269.

**Fraction of each test label predicted MALICIOUS (primary RF / LR, full features):**

| Label | RF | LR |
|---|---|---|
| DDoS | 0.633 | 0.9995 |
| PortScan | 0.0009 | 0.034 |
| Bot | 0.000 | 0.0005 |
| Web Attack – Brute Force | 0.615 | 0.0007 |
| Web Attack – XSS | 0.716 | 0.032 |
| Web Attack – Sql Injection (n=21) | 0.143 | 0.095 |
| Infiltration (n=36) | 0.000 | 0.056 |
| BENIGN (false-positive rate) | 0.0004 | 0.0335 |

### Interpretation (measured)
- **Generalisation to unseen attack types is poor, and unevenly so.**
  - The primary RF is very precise (precision 0.9955, benign FPR 0.04%) but detects only **28%** of test attacks.
  - It catches a majority of DDoS and two web-attack types.
  - It detects essentially **no** port scans, botnet traffic or infiltration. As expected, the detector recognises behaviour resembling the training attacks (DoS, brute force) and misses genuinely different behaviour.
- **Model trade-off:**
  - LR has higher recall (0.458, driven almost entirely by DDoS), at an 84× higher benign FPR (3.35%).
  - On threshold-free ranking, RF is better (ROC-AUC 0.810 vs 0.718; PR-AUC 0.690 vs 0.643).
- **Destination port acts as a shortcut that hurts generalisation here.** Removing it improves threshold-free ranking for both models (RF ROC-AUC 0.810 → 0.889, PR-AUC 0.690 → 0.712; LR ROC-AUC 0.718 → 0.901, PR-AUC 0.643 → 0.714). At the fixed 0.5 threshold, the operating points change: LR's recall rises to 0.707 but its FPR to 16%. **The primary detector was pre-registered and is not changed after seeing these results.**
- **Per day:**
  - Thursday (web attacks and infiltration) and Friday (bot, port scan, DDoS) behave very differently: RF recall is 0.630 on Thursday and 0.281 on Friday; LR recall is 0.012 and 0.462.
  - Per-day PR-AUC is reported in `metrics.json`.
- **Duplicates (full features):**
  - 69,459 test rows (6.0%) have a feature vector that also occurs in training, 83 of them with a conflicting label.
  - Duplicates within training: 156,896; within test: 144,153.
  - Excluding the cross-split duplicates leaves recall unchanged. Precision and PR-AUC rise modestly (most for LR, whose benign FPR falls from 0.0335 to 0.0242).
- **Not tested:** no other thresholds were tried, by design. Milestone 6 uses the probability band around the threshold as the "uncertain" region for the quantum second opinion.

### Artifacts
- **Models:** `models/generated/detection/<run-id>/{full,no_destination_port}/{logreg,random_forest}.{joblib,json,preprocessing.json}`, 10 MB in total, git-ignored.
- **Reload check:** the reloaded primary RF reproduces the stored test predictions exactly.
- **Metadata:** model and preprocessing versions (`random_forest-3d06e050dc23`, `prep-1-60d957f32bf9`), training days, seed, git commit and dirty flag, package versions.

## Limitations
- CIC-IDS2017 is an IDS dataset, not an ATT&CK attack-chain dataset, and its labels are **not** ATT&CK technique mappings.
- The day-based holdout is used instead of random row splitting to reduce leakage. The test set therefore contains unseen attack types and is much harder.
- Classical results say nothing about quantum advantage. In Milestone 6 the classical detector stays the primary decision-maker, and quantum analysis is only a second opinion on uncertain cases.
- Known dataset issues (label noise, duplicates, CICFlowMeter artefacts) are documented in the literature. The duplicate audit quantifies the duplicates.
