# Repository Analysis

**Project:** Hybrid Quantum-AI Intelligence Framework for Cyberattack Chain Prediction and Adaptive Defense
**Date of analysis:** 2026-10-06
**Scope:** Read-only analysis of the five reference repositories in the workspace. Nothing in them was modified, executed, trained or installed.

## How to read this document

- **Existing** means the behaviour is actually present in the repository's code or committed notebook outputs. It is verified by reading the source, the notebook outputs or the data files.
- **Claimed** means the README or markdown states it, but the code or outputs don't show it.
- **Proposed** means something for our project. Proposals live in `FINAL_ARCHITECTURE.md` and `INTEGRATION_PLAN.md`, not here.
- When a number is quoted below (for example an accuracy figure), it comes from that repository's committed output or README. We did not re-run anything, and none of these numbers are our results.

| # | Repository | Commit analysed | Upstream |
|---|---|---|---|
| R1 | MITRE-ATTACK-based-Attack-Chain-Prediction | `e188cc6` (2026-06-23) | github.com/mayank02raj/MITRE-ATTACK-based-Attack-Chain-Prediction |
| R2 | cyber-risk-intelligence-platform (CRIDAP) | `2750511` (2026-04-05) | github.com/Hack-Break/cyber-risk-intelligence-platform |
| R3 | Hybrid-Network-Intrusion-Detection-ML-QML | `6b4dc5d` (2026-09-30) | github.com/Sifat192/Hybrid-Network-Intrusion-Detection-ML-QML |
| R4 | PI-VQC-IntrusionDetection | `4a0acea` (2026-05-30) | github.com/Arxivory/PI-VQC-IntrusionDetection |
| R5 | Cyberattack-Prediction-and-Adaptive-Cyber-Defense | `40e313e` (2026-07-30) | github.com/boxcode59-source/Cyberattack-Prediction-and-Adaptive-Cyber-Defense |

---

## R1 — MITRE-ATTACK-based-Attack-Chain-Prediction

### 1. Purpose
This repository forecasts multi-stage adversary progressions over MITRE ATT&CK techniques. It uses a 2-layer LSTM trained on campaign-derived chains and a first-order Markov model trained on Unit42 and Attack Flow sequences, combined with beam-search expansion and a 0–10 risk score. The README presents it as supporting a SECRYPT 2026 paper. The README is inconsistent about status: it says "ACCEPTED" in the badge and summary, but "Under review" in the paper and BibTeX sections.

### 2. Structure (actual)
```
AP&Prob&RS_2.py                      1,309 lines  original pipeline (EPOCHS=50)
Ap_Rs_Prob_50_50_80_20.py            1,654 lines  + 3 training scenarios (EPOCHS=30)
AP_Prob_Rs_3_Scenarios_Latest.py     1,871 lines  latest version (EPOCHS=50) + NCISS error analysis
README.md                            30 KB
Attack flows/                        39 MITRE Attack Flow v2/STIX 2.1 JSON documents
Enterprise attack csvs/enterprise-attack-v16.0.xls   16.8 MB (sheets: techniques, tactics, software,
                                     groups, campaigns, mitigations, relationships, datasources, citations)
MITRE Campaign severity score/MITRE_Campaign_Severity_Scores.csv   50 rows
playbook_viewer-master-2/            vendored copy of pan-unit42/playbook_viewer (own MIT LICENSE)
    playbook_json/                   85 Unit42 STIX 2.0 bundles
    js/, css/, index.html            static viewer web app
    scripts/                         3 small helper scripts (Unit42's own)
```
There is **no** `requirements.txt`, `LICENSE`, `data/README.md`, `train_lstm.py`, `train_markov.py`, `generate_forecasts.py`, `score_risks.py` or `evaluate_nciss.py`. The README's quick-start refers to all of these, but none exist in the repository.

### 3–4. Important files and entry points
The only entry points are the three monolithic scripts. Each runs top to bottom at module level when executed (`python AP_Prob_Rs_3_Scenarios_Latest.py`), so none of them can be imported as a library. Paths are hard-coded to `/Users/mayankraj/Desktop/RESEARCH/...` and can be overridden with environment variables. Of the three, `AP_Prob_Rs_3_Scenarios_Latest.py` is the most complete. The other two are earlier copy-evolved versions with near-identical bodies.

### 5. Main functions and classes (Latest script)
| Function / class | Role |
|---|---|
| `unit42_sequences_from_file`, `load_unit42_sequences` | Parse Unit42 STIX bundles and bucket `attack-pattern` objects by kill-chain phase. Sequences are generated as **permutations within tactic buckets** (Cartesian product, capped at 25 permutations per bucket and 200 chains per file) |
| `af_sequences_from_file`, `load_attack_flow_sequences` | DFS over Attack Flow `start_refs → effect_refs / on_true_refs / on_false_refs`, extracting `attack-action` technique names (capped at 5,000 paths per file) |
| `train_markov_from_sequences` | First-order start and transition probabilities from raw counts, with no smoothing |
| `markov_chain_prob` | Product of transition probabilities, floored at 1e-12 |
| `expand_with_markov` | Beam expansion (top-k=10 next steps, beam=50, max length 20) |
| `techniques_for_campaign`, `bucket_by_tactic`, `generate_campaign_chains_for_row` | Build tactic-ordered chains from ATT&CK campaign→technique relationships, expanding parents to sub-techniques |
| `NextStepLSTM(nn.Module)` | Embedding(128) → LSTM(256, 2 layers, dropout 0.2) → Linear(vocab), with packed sequences |
| `chain_prob_lstm` | Product of the LSTM's next-step probabilities along a chain |
| `step_likelihood`, `step_detectability`, `score_chain` | Risk components (see §15) |
| `map_label_to_attacks_generic`, `produce_anchor_predictions_for_tech` | Map IDS dataset labels (CICIDS / ACI-IoT) to ATT&CK technique names and expand forward with Markov |
| `train_lstm_scenario`, `score_chain_with_model`, `calculate_error_rates` | 100% / 50-50 / 80-20 scenario training and MAE against the severity CSV |

### 6. ML/DL models
- 2-layer LSTM next-technique classifier (PyTorch), AdamW, lr 3e-3, batch 64, 50 epochs.
- First-order Markov chain (count-based).

### 7. Quantum ML
None.

### 8. Preprocessing and feature engineering
- Parses the ATT&CK Excel export and builds three maps: STIX ID→name, TID→name and name→tactics.
- Builds the sub-technique↔parent map from `relationships` rows of type "subtechnique-of".
- Uses a fixed 14-tactic order (reconnaissance … impact).
- **Vocabulary is technique *names*, not IDs.**

### 9–10. Datasets and schemas
| Data | Format / schema | Notes |
|---|---|---|
| ATT&CK Enterprise v16.0 | `.xls` (legacy BIFF; needs `xlrd`). Sheets used: `techniques` (ID, STIX ID, name, tactics), `relationships` (source ref, target ref, relationship type), `campaigns` (ID, STIX ID, name) | The `mitigations` sheet is present but unused |
| Attack Flow corpus | 39 STIX 2.1 bundles. 916 `attack-action` (with `technique_id`, `tactic_id`, `effect_refs`), 143 `attack-condition`, 112 `attack-operator` | Authored by the MITRE Center for Threat-Informed Defense (per `identity` objects). **These are the only sequences with genuine causal ordering.** |
| Unit42 playbooks | 85 STIX 2.0 bundles: 1,431 `attack-pattern`, 3,367 `course-of-action`, 37,124 relationships (11,399 `mitigates`), 9,275 indicators; 291 unique TIDs | **No temporal order** inside a bundle. R1 synthesises order via tactic-bucket permutations. Courses of action are mostly Palo Alto product-specific (e.g. "Deploy XSOAR Playbook…", WildFire settings) |
| `MITRE_Campaign_Severity_Scores.csv` | `Campaign_ID, Campaign_Name, Sector/Focus, NCISS_Score (0–100), Rationale` (50 rows) | Provenance is undocumented. The free-text rationales suggest the authors assigned these scores themselves. It is **not** an official CISA dataset |
| ACI-IoT-2023 / CICIDS | Optional `DATASET_PATH` CSV with a label column | Not included in the repository |

### 11. Training pipeline
Excel → campaign chains → (prefix, target) pairs with a sliding window → **random 90/10 split at the pair level** → LSTM. Step 9 re-trains under 100%, 50/50 and 80/20 splits, again at the pair level.

### 12. Inference pipeline
Seed prefix (the first 3 techniques of up to 800 campaign chains) → Markov beam expansion → per-chain LSTM probability and risk score → CSV/XLSX catalogs. A dataset-anchored mode starts the expansion from techniques mapped from IDS labels.

### 13. Attack-chain logic
Campaign chains are **tactic-ordered permutations** of the technique set attributed to a campaign. They are not observed sequences: within-tactic order is random, and cross-tactic order is imposed by the fixed tactic list. Markov transitions come from Unit42 (also permutations) and Attack Flow (real order).

### 14. MITRE ATT&CK mapping
- Strong at the knowledge-base level: ATT&CK v16, parent/sub-technique expansion and campaign relationships.
- Weak at the IDS-label → technique level. `LABEL_TO_ATTACK` / `CICIDS_TO_ATTACK` use names, and several of those names **are not valid ATT&CK technique names**, so string matching silently fails:
  - `"Network DoS"`: the real name is "Network Denial of Service", T1498.
  - `"Command and Control"`: this is a tactic, not a technique.
  - `"Exploitation of Public-Facing Application"`: the real name is "Exploit Public-Facing Application", T1190.
- Some mappings are semantically questionable. For example, Slowloris → "Application Layer Protocol" (T1071, a C2 technique) should be Endpoint DoS: Service Exhaustion Flood, T1499.002.

### 15. Risk scoring
In `score_chain`, each step's likelihood L_i is resolved in priority order: EPSS → CAPEC → LSTM next-step probability → default 0.1. A step listed in KEV gets +0.1. Detectability is D_i = 1 − coverage. The chain likelihood is the geometric mean of the L_i, and the final score is `final = min(10, 10 · L_chain · I/10)` with I = 10 by default.

Observed in code:
1. **Detectability is computed but never enters `final_risk`.**
2. `CAPEC_LIKELIHOOD` is never populated.
3. The EPSS, KEV and D3FEND CSVs default to empty, and none are shipped, so in practice risk ≈ 10 × geometric mean of the LSTM step probabilities, with 0.1 for the first step.
4. EPSS is a CVE-level score. No CVE→technique mapping is provided.

### 16. Adaptive defense
The README's case study describes defensive actions such as credential reset and LSASS auditing. **No defense code exists.**

### 17–19. Dashboard, API, storage
- Dashboard and API: none of R1's own. The vendored Unit42 playbook viewer is a static JS visualiser for STIX playbooks.
- Storage: CSV/XLSX files written to timestamped folders.

### 20. Configuration
Module-level constants plus environment variables: `ATTACK_FILE`, `UNIT42_REPO_DIR`, `ATTACK_FLOW_STIX_DIR`, `OUT_ROOT`, `EPSS_CSV`, `KEV_CSV`, `DETECTION_CSV`, `SEVERITY_CSV`, `OCTAVE_IMPACT`, `DATASET_PATH`, `DATASET_LABEL`, `POST_MARKOV_*`, `RUN_THREE_SCENARIOS`.

### 21. Dependencies (inferred from imports)
pandas, numpy, torch, tqdm, matplotlib, xlrd (for .xls), xlsxwriter. The README targets Python 3.11 and PyTorch 2.2.1. No dependency file is provided.

### 22–25. Models, notebooks, tests, Docker
No checkpoints are committed; the LSTM is not saved. There are no notebooks, no tests and no Docker configuration.

### 26. Documentation quality
The README is extensive and well written, but **it does not match the repository**: it describes scripts and data folders that don't exist, results that can't be regenerated from the committed code (for example, Pearson/Spearman are never computed), and an inconsistent publication status. There are no inline API docs.

### 27. Missing or incomplete
- The modular scripts, requirements file, license and data README are missing.
- EPSS, KEV, CAPEC and D3FEND inputs are missing.
- No model persistence and no correlation metrics.
- **Evaluation leakage.** Train and validation split at the (prefix, target) pair level over chains that are permutations of the same 33 campaigns' technique sets, so near-duplicate prefixes appear on both sides.
- The NCISS error analysis scores *all* chains, training chains included.
- The README itself lists further limitations: no leave-one-campaign-out evaluation and coverage measured at tactic level rather than technique level.

### 28. Duplicates with other repos
- Attack-chain construction: compare R2 `chain_builder.py` and R5 `trace_id`.
- Risk scoring: R2 (0–100) and R5 (MC-dropout risk) also score risk, on different scales.

### 29. Integration conflicts
- Name-based vocabulary.
- A different risk scale (0–10) from R2 (0–100) and R5 (0–1).
- Scripts execute on import.
- Absolute paths.
- The legacy `.xls` format.

### 30. Reusable (subject to license; see the audit)
- **Ideas only:** hybrid Markov+LSTM, constrained beam search, Attack Flow DFS extraction, parent→sub-technique expansion, the likelihood/impact risk framing.
- **Data:** obtain the third-party data from upstream sources rather than from this repository: ATT&CK, the Attack Flow corpus and the Unit42 playbooks.

---

## R2 — cyber-risk-intelligence-platform (CRIDAP)

### 1. Purpose
A hackathon SOC platform. It ingests normalized log events, runs Isolation Forest anomaly detection, correlates anomalies into per-entity chains, computes 0–100 entity risk, applies five privacy rules, and produces rule-based defense recommendations. Results are served through FastAPI to a static dashboard.

### 2. Structure
```
src/ingestion/log_parser.py        LogParser (JSON / CSV / .log → normalized dict)
src/detection/anomaly_detector.py  AnomalyDetector (StandardScaler + IsolationForest), AnomalyAlert dataclass
src/correlation/chain_builder.py   AttackChainBuilder (per-entity 1-hour window)
src/scoring/risk_scorer.py         RiskScorer (weighted 0–100)
src/privacy/privacy_monitor.py     PrivacyMonitor (PRIV-001..005)
src/advisor/defense_advisor.py     DefenseAdvisor (7 rule table)
src/dashboard/api.py               FastAPI app (reads output/results.json)
scripts/run_pipeline.py            CLI orchestrator → output/results.json
tests/test_pipeline.py             10 pytest unit tests
data/sample_logs/sample_events.json   40 synthetic events, 22 entities
index.html                         80 KB single-page dashboard (Three.js r128 + GSAP from cdnjs)
docs/architecture.md, CONTRIBUTING.md, Dockerfile, docker-compose.yml, vercel.json, LICENSE (MIT)
```

### 3–4. Entry points
- `python scripts/run_pipeline.py --log-dir data/sample_logs/`
- `uvicorn src.dashboard.api:app`
- `pytest tests/`
- The Docker CMD runs the pipeline; docker-compose defines a pipeline service and a dashboard service.

### 5. Key classes and functions
`LogParser._normalize()` produces a 15-field event schema:
- Identity and time: `id, timestamp, user, device, entity_type, source`
- Behaviour counters: `failed_logins_1h, unique_ips_accessed, data_transferred_mb, off_hours, new_device, privilege_level, api_calls_per_min, lateral_hops, historical_incidents`

The other components:
- `AnomalyDetector.detect()` and the `_classify_anomaly_type()` heuristic thresholds.
- `AttackChainBuilder.build_chains()` and `_label_chain()`.
- `RiskScorer.score()`.
- `PrivacyMonitor.analyze()`.
- `DefenseAdvisor.recommend()`.

### 6. ML/DL
- Isolation Forest (200 trees, contamination 0.05), fit and scored on the same batch.
- The module docstring mentions an Autoencoder and the README mentions LSTM. **Neither exists.**

### 7. Quantum
None.

### 8. Preprocessing
- Field-name aliasing with defaults.
- StandardScaler over 8 behavioural features.

### 9–10. Dataset
- 40 hand-written synthetic events in the schema above. No public dataset.

### 11–12. Training and inference
Unsupervised `fit_predict` on each batch, with no persistence. Inference happens in the same call.

### 13. Attack-chain logic
- Groups anomalies per entity into 1-hour windows.
- **Re-sorts each chain by the `STAGE_ORDER` heuristic rather than by timestamp**, which destroys the observed order.
- Labels each chain with fixed string patterns.

### 14. MITRE
None in the code. The dashboard shows hard-coded T1566 and T1078 text.

### 15. Risk scoring
`100 × (0.35·avg_severity + 0.20·min(alerts/10,1) + 0.15·min(priv/5,1) + 0.20·min(MB/1000,1) + 0.10·min(hist/5,1))`, with levels LOW <35, MEDIUM <60, HIGH <80, and CRITICAL otherwise. "Data sensitivity" is approximated by data volume.

### 16. Adaptive defense
A seven-rule table: MFA, isolate endpoint, password reset, block session, reduce privileges, increase monitoring and patch prioritization. All outputs are text recommendations; nothing executes.

Bugs found:
- The `privilege_level` lookup reads `rs.get("privilege_level")`, but the risk-score dicts never contain that key, so the reduce-privileges rule can never fire.
- The `privacy_alerts` argument is accepted but unused.

### 17. Dashboard
`index.html` is mostly a marketing and landing page with animated Three.js and canvas visuals driven by `Math.random()`. The kill-chain section is static text. Live widgets fetch `/summary`, `/risk-scores` and `/privacy-alerts`.

`const API` is hard-coded to `https://cyber-risk-intelligence-platform-1.onrender.com`, while the status text says `127.0.0.1:8000`.

### 18. Backend/API
FastAPI with GET endpoints `/`, `/summary`, `/risk-scores`, `/attack-chains`, `/privacy-alerts`, `/recommendations` and `/entity/{name}`. It serves a precomputed `output/results.json`.

Issues:
- CORS is `*`.
- `app.mount("/static", StaticFiles(directory="."))` exposes the entire working directory, including `output/` and any `.env`, over HTTP.

### 19. Storage
JSON file. The commented requirements mention SQLAlchemy and Postgres, but nothing uses them.

### 20. Config
Module constants for thresholds and weights. `python-dotenv` is listed but unused.

### 21. Dependencies
numpy, pandas, scikit-learn, loguru, fastapi, uvicorn, pydantic, httpx, python-dotenv, pytest, pytest-cov. The Dockerfile uses python:3.11-slim.

### 22–23. Models and notebooks
None.

### 24. Tests
10 shallow unit tests covering types, ranges and two advisor rules. The chain builder is imported but untested.

### 25. Docker/deploy
Dockerfile, docker-compose (pipeline + dashboard) and Vercel static hosting for `index.html`.

### 26. Documentation
Clear README and architecture doc. Several claims overstate the implementation: LSTM, Autoencoder, "one-click deployment", "zero-day".

### 27. Missing
- Real datasets, MITRE mapping, persistence, a streaming or live pipeline, auth and validation.
- The chain builder never yields chains on the sample data (the README's expected output shows "0 chains").

### 28. Duplicates
- Isolation Forest (also R5).
- Chain correlation (R1, R5).
- Defense rules (R5 DRPRE).

### 29. Conflicts
- Behavioural log schema vs flow-feature datasets (R3, R4).
- Anomaly-type strings vs ATT&CK IDs.
- The 0–100 risk scale.

### 30. Reusable
MIT-licensed. Candidates:
- Module decomposition.
- The FastAPI endpoint shape.
- The entity-risk weighted formula (as a design pattern).
- The privacy rules.
- The rule-table advisor pattern.
- Test layout.

---

## R3 — Hybrid-Network-Intrusion-Detection-ML-QML

### 1. Purpose
A notebook comparing classical classifiers with a Qiskit QSVC for binary intrusion detection on CIC-IDS2017.

### 2. Structure
```
Hybrid_Network_Intrusion_Detection_ML_QML.ipynb  (80 cells, outputs committed; kernel "quantumml", Python 3.11.15)
README.md, LICENSE (MIT, © 2026 Sifat Bhatia), requirements.txt, .gitignore
dataset/dataset_link.md   → Kaggle "chethuhn/network-intrusion-dataset" (CIC-IDS2017 MachineLearningCVE CSVs)
hybrid-intrusion-detection-workflow.png
```
The README references an `environment.yml` that does not exist, and its clone URL is a placeholder (`your-username`).

### 3–5. Entry point and code
The notebook only; there are no functions or classes. Steps:
1. `glob("*.csv")` loads 8 CSVs, 2,830,743 rows × 79 columns.
2. Strip and lowercase column names.
3. Replace inf with NaN (4,376 inf values) and `dropna`.
4. Binary label (BENIGN=0).
5. Balanced sample of 50k benign and 50k attack.
6. 80/20 split and StandardScaler.
7. Train RF, LR and SVC.
8. Select the top-20 features by RF importance.
9. Refit StandardScaler, then PCA(8) on all 100k rows.
10. QSVC on a **100-row subsample** (80 train / 20 test).

### 6. Classical ML (committed outputs, accuracy only)
| Model | Accuracy (outputs) |
|---|---|
| RandomForest (78 features) | 0.99805 |
| LogisticRegression | 0.9304 |
| SVC (RBF) | 0.95725 |
| RF on PCA(8) of top-20 features | 0.9946 |

### 7. Quantum ML
- `ZFeatureMap(feature_dimension=8, reps=1)` → `FidelityQuantumKernel` → `QSVC`.
- Result: training time 78.7 s; **accuracy 0.9 on 20 test samples** (18/20).
- Qiskit 2.4.1. The output shows a DeprecationWarning: the `ZFeatureMap` class is deprecated since Qiskit 2.1 and will be removed in 3.0.

Technical notes:
1. ZFeatureMap has **no entangling gates**. The fidelity kernel is a product of single-qubit overlaps, so it can be computed classically in closed form and cannot provide quantum advantage.
2. PCA outputs (range ≈ −3…+8) are fed directly as rotation angles without rescaling, so angles wrap periodically.
3. There is no classical baseline at the same 100-sample, 8-feature budget, so the 0.9 is not comparable with the classical numbers.

### 8. Preprocessing
- Inf/NaN removal.
- No duplicate removal, although the markdown claims it.
- `destination port` is kept as a feature; it is a known shortcut feature in CIC-IDS2017.
- Scaler and PCA are fit on all 100k rows before the split, a mild leakage.

### 9–10. Dataset
CIC-IDS2017 (MachineLearningCVE), 79 columns, 15 labels. BENIGN 2,271,320; DoS Hulk 230,124; PortScan 158,804; DDoS 128,025; … Infiltration 36, SQL Injection 21, Heartbleed 11. The data is not shipped.

### 11–12. Training and inference
Notebook cells only. Accuracy is the only metric: no precision, recall, F1, ROC-AUC or confusion matrices.

### 13–20. Other aspects
No attack-chain logic, MITRE mapping, risk scoring, defense, dashboard, API, storage or configuration.

### 21. Dependencies
numpy, pandas, matplotlib, seaborn, scikit-learn, qiskit, qiskit-machine-learning, qiskit-aer, qiskit-algorithms, jupyter, ipykernel. Unpinned. The outputs show numpy 2.4.6, scipy 1.17.1, scikit-learn 1.9.0 and qiskit 2.4.1.

### 22–25. Models, tests, Docker
No saved models, no tests, no Docker.

### 26. Documentation
A good conceptual workflow diagram. The README's "Results" section contains no numbers.

### 27. Missing
- Proper metrics.
- Stratified multi-seed evaluation.
- A matched-budget comparison.
- Noise simulation.
- Persistence.

### 28. Duplicates
The quantum-kernel SVM duplicates R4's QKSVM. Classical detection overlaps with R2, R4 and R5.

### 29. Conflicts
Deprecated Qiskit API usage. Feature schema specific to CIC-IDS2017.

### 30. Reusable
MIT-licensed. Candidates:
- CIC-IDS2017 loading and cleaning steps.
- The RF-importance → PCA → angle-encoding reduction idea.
- The QSVC wiring. Re-implement with `zz_feature_map` / function APIs.

---

## R4 — PI-VQC-IntrusionDetection

### 1. Purpose
A competition notebook (QCSP XQubit). It implements a Physics-Informed VQC with an Ising-inspired ansatz (ZZ couplings plus a transverse-field RX layer), parameter-shift and ADAM training, a QKSVM baseline, and NISQ noise simulation on UNSW-NB15.

### 2. Structure
```
QML_PhysicsInformed_XQubit_Project.ipynb   (Colab, Python 3.12.3; Qiskit 2.4.1, Aer 0.17.2, qiskit-machine-learning 0.9.0)
README.md
```
There is no LICENSE, requirements file or dataset.

### 3–5. Code
Notebook functions:
- `build_pivqc` (RY angle encoding; per layer: CNOT–RZ(2γ)–CNOT on nearest-neighbour edges, then RX(2β)).
- `expectation` (exact ⟨Z₀⟩ via `Statevector`).
- `compute_loss` (MSE against ±1 labels).
- `param_shift_grad`.
- `adam_train` (40 epochs, batch 20).
- `noisy_expectation` (AerSimulator + NoiseModel).
- `sweep_noise`.
- `estimate_grad_norms`.

Configuration: N_QUBITS=4, N_LAYERS=2, N_TRAIN=500, N_TEST=200, SHOTS=512.

### 6–7. Models (committed outputs)
| Model | Accuracy | "F1 (attack)" |
|---|---|---|
| Classical SVM (RBF, C=10) | 0.850 | 0.860 |
| QKSVM (RY angle-encoding fidelity kernel) | 0.850 | 0.860 |
| PI-VQC (ideal) | **0.290** | 0.290 |
| PI-VQC (noisy, p1=0.01, p2=0.05, ro=0.02) | 0.290 | 0.290 |

**Critical defects verified in the code and outputs:**
1. **The parameter-shift gradient is identically zero.** The parameters enter the gates as `RZ(2θ)` / `RX(2θ)`, but the shift used is ±π/2 on θ, which shifts the gate angle by ±π. Since R(φ+π) and R(φ−π) differ only by a global phase, L(θ+π/2) = L(θ−π/2) exactly. The debug output confirms `lp == lm, grad_val=0.0000` on every step, and the training loss stays constant at 1.5099 for all 40 epochs. **The VQC was never trained.** Its 0.29 accuracy is the random initialisation, which happens to fall below chance. (The correct shift for an `R(2θ)` parameterisation is ±π/4, with the gradient formula adjusted accordingly.)
2. **The "generic ansatz" gradient norms are fabricated.** They are computed as `n * np.random.uniform(0.1, 0.4)` of the Ising norms. Both measured means are 0.0000. The README and Conclusion claims that the Ising ansatz "produces larger gradient norms" are **not supported** by any experiment.
3. "NISQ degradation measurable" is not supported either: degradation is +0.000 because the model is untrained. The claim of "recovers for p2<0.02" has no corresponding output.
4. `f1_score(..., pos_label=-1)` computes F1 for the **Normal** class but labels it "F1 (attack)".
5. SMOTE, MinMax and PCA are fit on the full dataset **before** the train/test split, so synthetic SMOTE points leak into the test set.
6. The QKSVM feature map is RY-only, a product state. Its kernel equals ∏ cos²((xᵢ−x′ᵢ)/2), which is classically computable in closed form.
7. The README says UNSW-NB15 is "~85% normal". The loaded training split is 37,000 normal vs 45,332 attack (45% / 55%).

### 8. Preprocessing
One-hot encoding of proto/service/state (giving 191 columns), MinMax, SMOTE, PCA(4), then rescaling to [0, π].

### 9–10. Dataset
UNSW-NB15 `UNSW_NB15_training-set.csv` (82,332 × 43) via `kagglehub` ("mrwellsdavid/unsw-nb15"). There is a synthetic fallback if the file is missing.

### 11–12. Training and inference
In-notebook only.

### 13–20. Other aspects
None: no attack-chain logic, MITRE mapping, risk, defense, dashboard, API, storage or configuration.

### 21. Dependencies
qiskit, qiskit-aer, qiskit-machine-learning, scikit-learn, pandas, matplotlib, seaborn, imbalanced-learn, pylatexenc, kagglehub.

### 22–25. Models, tests, Docker
No saved models, tests or Docker.

### 26. Documentation
The mathematical exposition is strong (Ising decomposition, the parameter-shift rule, the noise model). The results and conclusions contradict the notebook's own outputs. An AI-assistance disclaimer is included.

### 27. Missing
- Working gradient training.
- A license.
- Seeds and multi-seed runs.
- A real ablation against a generic ansatz.

### 28. Duplicates
QKSVM duplicates R3's QSVC.

### 29. Conflicts
- ±1 vs 0/1 labels.
- Python 3.12 Colab vs our 3.11 target.

### 30. Reusable
**Reference only** (no license). Valuable ideas: the Ising-structured ansatz design, the Aer noise-model setup (depolarizing + readout), and the noise sweep methodology. These must be re-implemented independently, and the gradient bug must not be carried over.

---

## R5 — Cyberattack-Prediction-and-Adaptive-Cyber-Defense

### 1. Purpose
A Colab-exported script with a 9-stage "Generative AI-Assisted Lightweight Deep Convolutional Learning" pipeline. It covers multi-source acquisition, data refinement, a CNN detector, a temporal threat-evolution model, a template "Gen-AI" report, a risk and response engine, a recovery planner, continual learning and explainability.

### 2. Structure
```
generative_ai_assisted_lightweight_deep_convolutional_learning_for_cyberattack_prediction_and_adaptive_cyber_defense.py  (1,020 lines)
README.md (2 lines)
```
There is no LICENSE, requirements file, data or outputs.

### 3–4. Entry point
`python <script>.py` runs `run_pipeline()`.

### 5. Classes and functions
| Stage | Component |
|---|---|
| 1 | `_generate_synthetic_source`, `acquire_multi_source_data` (USE_SYNTHETIC_DATA=True; CSV paths for CICIDS2017, CSE-CIC-IDS2018 and UNSW-NB15 are all `None`) |
| 2 | `ACDR` (KNNImputer → IsolationForest noise removal → session aggregation → frequency encoding → QuantileTransformer → mutual information + RFE(LogReg) selecting 8 features) |
| 3 | `GhostConv`, `ECA`, `MultiScalePyramid`, `ASPPLite`, `LiteHDCNet` (1-D CNN over the feature vector → 64-d embedding), `ThreatDetector` |
| 4 | `TemporalConvBlock` (causal dilated TCN), `LinearTemporalAttention`, `TTEM` (stage head + learnable 6×6 transition matrix + severity head) |
| 5 | `VectorKnowledgeDB` (TF-IDF over 5 tactic descriptions), `CRGM` (**f-string template**, not an LLM) |
| 6 | `DRPRE` (MC-Dropout "Bayesian" risk = p_attack·(1−σ); severity→action policy; `zero_trust_enforcement` returns *simulated* log strings) |
| 7 | `ACRP` (checkpoint rollback selection, simulated validation) |
| 8 | `EWC`, `ConceptDriftDetector` (per-feature KS test, α=0.01, drift if >30% of features drift), `ExperienceReplayBuffer`, `incremental_update` |
| 9 | `integrated_gradients`, `shap_attribution` (KernelExplainer, with IG fallback), `counterfactual_explanation`, `TemperatureScaler` |

### 6. ML/DL
- 1-D lightweight CNN (Ghost conv, ECA attention, multi-scale and atrous pyramids).
- TCN with linear attention.
- Isolation Forest, KNN imputation, MI+RFE.

### 7. Quantum
None.

### 8. Preprocessing
See Stage 2. All fitting (imputer, IsolationForest, quantile transform, feature selection) happens on the full dataset **before** the train/val/test split, which is leakage. `ACDR.transform` exists but is never used.

### 9–10. Dataset
**Synthetic only:**
- 3 × 3,000 packets, log-normal and Poisson features shifted for the attack class.
- `attack_stage` is drawn **uniformly at random** per attack packet from 5 stages, with a fixed tactic map.
- Sessions are groups of 8 rows.

### 11. Training
Detector: Adam, 6 epochs, accuracy only. **`TTEM` is instantiated and run but never trained.** Its next-stage predictions and severity are outputs of randomly initialised weights, and the synthetic stage labels contain no sequential structure to learn anyway.

### 12. Inference
One 16-sample "window" taken from `X_test[:16]` (not a real temporal sequence) goes through TTEM, then the template report, DRPRE and ACRP.

### 13. Attack-chain logic
A learnable transition matrix blended 60/40 with the stage head. It is untrained.

### 14. MITRE
5 tactic IDs (TA0043, TA0002, TA0008, TA0003, TA0010). "Exploitation" is mapped to TA0002, which is the Execution tactic. No technique level.

### 15. Risk
MC-Dropout over 20 passes, `risk = mean_p_attack × (1 − mean_std)`. Note that `model.train()` also switches BatchNorm to training mode and **updates the running statistics** during risk estimation, which is a side effect.

### 16. Adaptive defense
- A severity → action policy: Critical = isolate host + revoke credentials; High = restrict access + DPI; Medium = increase monitoring; Low = log only.
- Enforcement is simulated: it returns strings such as "deny-all ACL applied".
- The design intent reads as autonomous enforcement. **That intent conflicts with our recommendation-only requirement.**

### 17–20. Dashboard, API, storage, config
None. The "dashboard" is a printed dict. Configuration lives in module constants.

### 21. Dependencies
numpy, pandas, scipy, scikit-learn, torch, with optional shap.

### 22–25. Models, notebooks, tests, Docker
No saved models, notebooks, tests or Docker.

### 26. Documentation
A two-line README. The docstrings are reasonable.

### 27. Missing
- Real data, TTEM training, evaluation beyond accuracy, a license.
- Correct EWC: the Fisher information is computed on the *new* data rather than the previous task's data.

### 28. Duplicates
- Isolation Forest (R2).
- Risk scoring (R1, R2).
- Defense policy (R2).
- Chain or temporal modelling (R1).

### 29. Conflicts
- A 6-stage coarse taxonomy vs ATT&CK techniques.
- Autonomous-enforcement semantics.

### 30. Reusable
**Reference only** (no license). The underlying methods are standard, published techniques that we can re-implement independently and cite: MC-Dropout uncertainty, KS drift detection, temperature scaling, Integrated Gradients, counterfactual search, EWC, replay buffers and TCN.

---

## Cross-repository findings

### Duplicate functionality
| Capability | R1 | R2 | R3 | R4 | R5 |
|---|---|---|---|---|---|
| Binary detection | – | IsolationForest (unsupervised) | RF / LR / SVC / QSVC | SVM / QKSVM / VQC | 1-D CNN |
| Quantum kernel SVM | – | – | ZFeatureMap QSVC | RY QKSVM | – |
| Chain building | campaign permutations, Attack Flow DFS | per-entity 1-hour window | – | – | 2-s `trace_id` window |
| Next-step prediction | LSTM + Markov + beam | – | – | – | TTEM (untrained) |
| Risk | 0–10 likelihood × impact | 0–100 weighted entity | – | – | 0–1 MC-dropout |
| Defense | text only (README) | 7-rule table | – | – | 4-level policy (simulated enforcement) |
| API / UI | (Unit42 viewer, vendored) | FastAPI + static HTML | – | – | – |

### Integration conflicts to resolve in our design
1. **Identifier vocabulary.** We will standardise on ATT&CK **technique IDs**. The alternatives in the repos are technique names (R1), free-text anomaly types (R2), coarse stages (R5) and binary labels (R3, R4).
2. **Risk scales.** The repos use 0–10, 0–100 and 0–1. We need one canonical scale with documented transforms.
3. **Label conventions.** {0,1} vs {−1,+1}.
4. **Execution model.** Module-level scripts and notebooks vs an importable package.
5. **Qiskit API churn.** The `ZFeatureMap` class is deprecated (Qiskit 2.1+). The kernel and QSVC APIs come from qiskit-machine-learning 0.9.x.
6. **Python versions.** 3.10+ (R2), 3.11 (R1, R3), 3.12 (R4). Our target is 3.11.
7. **Hard-coded absolute paths** (R1) and Windows paths (R3 outputs).
8. **Data leakage patterns.** These recur across four of the five repositories (R1, R3, R4, R5), and our evaluation design must prevent all of them: preprocessing fit before splitting, SMOTE before splitting, and pair-level splits of augmented chains.
9. **Defense semantics.** R5 models autonomous enforcement. We require recommendation-only output with a human approval step.
