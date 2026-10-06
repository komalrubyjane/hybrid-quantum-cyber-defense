# Repository Comparison

Legend:
- ✅ implemented and working as described
- ⚠️ implemented with significant defects or limitations
- 📝 claimed in docs only (no code)
- — absent

Details and evidence for every cell are in `REPOSITORY_ANALYSIS.md`.

## Main comparison table

| Dimension | R1 MITRE Attack-Chain | R2 CRIDAP | R3 Hybrid ML-QML | R4 PI-VQC | R5 Cyberattack-Prediction |
|---|---|---|---|---|---|
| **Purpose** | Forecast ATT&CK technique sequences and score their risk | Hackathon SOC pipeline: logs → anomalies → risk → advice → API/UI | Classical vs QSVC intrusion detection notebook | Physics-informed VQC + QKSVM + noise study notebook | 9-stage "Gen-AI-assisted" CNN detection/prediction/defense script |
| **Detection** | — | ⚠️ IsolationForest, fit and score on the same batch | ✅ RF / LR / SVC (accuracy only); ⚠️ QSVC on 100 samples | ✅ RBF SVM, QKSVM; ⚠️ VQC never trained (zero gradients) | ⚠️ 1-D CNN on synthetic data, preprocessing leakage |
| **Attack-chain prediction** | ✅ Markov beam + LSTM rescoring; ⚠️ leaky evaluation | — (correlation only) | — | — | ⚠️ TTEM untrained, random stage labels |
| **LSTM** | ✅ 2-layer, 256 hidden units, 128-d embeddings | 📝 README only | — | — | — (TCN + linear attention instead) |
| **Markov model** | ✅ first-order, unsmoothed | — | — | — | ⚠️ learnable 6×6 transition matrix (untrained) |
| **MITRE ATT&CK** | ✅ v16 KB, technique/sub-technique, campaigns; ⚠️ invalid names in IDS-label map | 📝 dashboard text only | — | — | ⚠️ 5 tactic IDs, one mis-mapped |
| **Quantum ML** | — | — | ⚠️ ZFeatureMap fidelity QSVC (product state, deprecated class) | ⚠️ RY QKSVM (product state); VQC with broken parameter-shift; ✅ Aer noise model | — |
| **Risk scoring** | ⚠️ 0–10: geometric-mean likelihood × OCTAVE impact (detectability unused) | ✅ 0–100 weighted entity score (heuristic) | — | — | ⚠️ 0–1 MC-dropout "Bayesian" risk (BatchNorm side effect) |
| **Adaptive defense** | 📝 README case study | ⚠️ 7-rule recommendation table (one rule unreachable) | — | — | ⚠️ severity → action policy with *simulated enforcement* |
| **Dashboard** | — (vendored Unit42 viewer only) | ⚠️ static Three.js landing page, mostly random animation, hard-coded remote API | — | — | — |
| **API** | — | ⚠️ FastAPI GET endpoints over a JSON file; `StaticFiles(".")` exposure | — | — | — |
| **Dataset** | ATT&CK v16 `.xls`, 39 Attack Flow, 85 Unit42 STIX (all local); optional CICIDS / ACI-IoT | 40 synthetic events | CIC-IDS2017 (external, Kaggle mirror) | UNSW-NB15 training split (external, Kaggle) | Synthetic only |
| **Training pipeline** | ⚠️ monolithic script, pair-level random split, 3 scenarios | ⚠️ unsupervised refit per run | ⚠️ notebook, single seed, accuracy only | ⚠️ notebook; SMOTE/PCA before split | ⚠️ script; fit before split |
| **Tests** | — | ✅ 10 shallow unit tests | — | — | — |
| **Docker / deploy** | — | ✅ Dockerfile, compose, Vercel | — | — | — |
| **License** | **None** (pending review) | **MIT** | **MIT** | **None** | **None** |
| **Reuse suitability** | **Reference only** (algorithms reimplemented; data from upstream) | **High for structure, low for code quality.** Adapt with attribution | **Medium.** Adapt loading/cleaning; rewrite QML | **Reference only** (ideas: Ising ansatz, noise sweep) | **Reference only** (ideas: uncertainty, drift, calibration, XAI) |

## Strongest reference for each component

| Component | Strongest reference | Why | Runner-up | How we use it |
|---|---|---|---|---|
| Data ingestion / normalized event schema | **R2** `LogParser` | Only repo with a defined, aliased event schema and multi-format parsing | R5 multi-source merge | Adapt the pattern (MIT); extend it to flow datasets and ATT&CK fields |
| Preprocessing (flow datasets) | **R3** (CIC-IDS2017 inf/NaN handling, scaling, RF-importance → PCA) | Real dataset, real counts | R4 (one-hot + PCA + angle rescale to [0, π]) | Re-implement as a fitted-on-train-only sklearn `Pipeline` |
| Classical detection | **R3** (RF / LR / SVC on CIC-IDS2017) | Real data and standard baselines | R2 IsolationForest (unsupervised option) | Re-implement with full metrics and multi-seed runs |
| Quantum kernel | **R3 / R4** (FidelityQuantumKernel + SVC) | Working wiring with Qiskit 2.4.x / qiskit-ml 0.9 | — | Re-implement with **entangling** `zz_feature_map`, statevector kernel and matched classical baselines |
| Variational QML / noise simulation | **R4** (concepts only) | Ising ansatz + Aer depolarizing/readout noise design | — | Independent implementation; correct gradients (or Qiskit `EstimatorQNN` gradients) |
| MITRE ATT&CK knowledge base | **R1** | v16 parsing, sub-technique expansion, campaign relationships | R5 tactic table | Own loader over the official STIX 2.1 JSON |
| Attack sequence corpora | **R1** (Attack Flow DFS, Unit42 parsing) | Only source of ordered technique sequences | — | Own parsers over upstream data; weight Attack Flow (true order) above permutation-derived sequences |
| Attack-chain reconstruction from alerts | **R2** `AttackChainBuilder` (entity + time window) | Only alert → chain correlator | R5 `trace_id` | Re-implement; keep timestamp order (R2 re-sorts by stage) |
| Next-step / multi-step prediction | **R1** (Markov + LSTM + beam) | Only working sequence predictor | R5 TTEM (architecture idea only) | Independent implementation with smoothing, interpolation and leakage-free evaluation |
| Risk scoring | **R1** (likelihood × impact for forecasts) + **R2** (entity context weights) | Complementary: R1 scores *future chains*, R2 scores *entities now* | R5 uncertainty discount | Unified, documented, configurable model |
| Adaptive defense | **R2** `DefenseAdvisor` (rule table, recommendation-only) | Simple, safe, testable | R5 severity policy; Unit42 courses of action; ATT&CK `mitigations` sheet | Knowledge-driven recommender (ATT&CK mitigations + action catalog) with mandatory human approval |
| Uncertainty / calibration / drift / XAI | **R5** (concepts) | Only repo touching these | — | Independent implementation from the original papers (post-MVP) |
| API | **R2** FastAPI | Working endpoint layout | — | Rewrite with Pydantic schemas, no wildcard static mount, live pipeline |
| Dashboard | **R2** (layout ideas only) | Only UI | Unit42 viewer (chain visualisation idea) | New SOC dashboard driven entirely by API data |
| Tests / CI / Docker | **R2** | Only repo with tests and containers | — | Expand substantially |

## Overall verdict

- **No repository is a complete or reliable base.** R1 is the strongest *research* reference: it has the richest data and the most relevant prediction logic, but it is unlicensed and its evaluation leaks. R2 is the strongest *engineering skeleton*, but it is shallow. R3 is the only repo with a working classical-vs-quantum pipeline on real data, albeit a minimal one.
- **The quantum references are weak.** Both kernels use product-state feature maps that can be computed classically in closed form, R3 tests on 20 samples, and R4's VQC never trained. Our quantum component must be designed from first principles with rigorous controls (see `FINAL_ARCHITECTURE.md` §Quantum).
- **R5's ideas** (uncertainty, drift, calibration, explainability) are useful for later phases, but none of its code or results can be relied on.
