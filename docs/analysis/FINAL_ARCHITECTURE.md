# Final Architecture — Hybrid Quantum-AI Intelligence Framework

**Status:** PROPOSED design. Nothing in this document is implemented yet.
**Targets:**
- Python 3.11
- Local-first execution on a laptop CPU; a GPU is optional
- Qiskit simulators only for the initial phase
- Defensive, recommendation-only outputs

This is an **original system**. It reuses ideas from the five reference repositories, and code only where the license permits (R2, R3 under MIT, with attribution). Algorithms seen in R1, R4 and R5 are re-implemented independently from the published literature (see `LICENSE_AND_REUSE_AUDIT.md`).

---

## 1. Design principles

1. **One canonical vocabulary.** Every layer above detection speaks in **ATT&CK technique IDs** (e.g. `T1110.001`), carrying a confidence and a provenance. We never use technique names as keys, because name-based keys caused silent mapping failures in R1.
2. **Typed data contracts between stages.** Pydantic models (§4) form the only interface between modules. Any stage can be swapped (classical vs quantum, Markov vs LSTM) without touching the others.
3. **Leakage-free by construction.** Every transformer is fit inside a train-only `Pipeline`. Splits are made *before* any resampling or fitting. Sequence data is split by **source document or campaign group**, never by (prefix, target) pair. Four of the five references leaked.
4. **The quantum component has a measurable job,** and it is always evaluated against a classical model doing the *same* job under the *same* budget.
5. **Recommendation-only defense.** The defense layer emits data objects. It has no executors, no network clients for firewalls or EDR, and no credential APIs, and every recommendation requires human approval.
6. **Reproducibility.** Every run records its config hash, seed, git commit, data checksums and package versions. Every number in a report comes from a stored run.
7. **Separate "observed" from "predicted" everywhere.** This applies to the API, the risk score and the dashboard.

---

## 2. End-to-end pipeline

```
 Network / security events (CIC-IDS2017 flows, UNSW-NB15 flows, JSON logs, synthetic scenarios)
        │
 [1] Ingestion ─────────── dataset adapters → canonical Event; batch or timestamp-ordered replay ("simulated stream")
        │
 [2] Preprocessing ─────── cleaning (inf/NaN/dupes), identifier removal, train-fit scaler/selector; per-dataset FeatureSpec
        │
 [3] Classical detection ─ binary p_attack + attack-family classifier (RF / HistGradientBoosting; LR baseline), calibrated
        │
 [4] Quantum-AI analysis ─ Quantum Kernel Adjudicator on events in the classical ambiguity band → p_quantum, disagreement
        │                   score-level fusion → p_final, uncertainty
 [5] MITRE mapping ─────── attack-family → ATT&CK techniques (curated YAML table, with confidence and rationale) → Alert
        │
 [6] Chain reconstruction  per-entity (host / IP / user) time-windowed, timestamp-ordered technique sequence → AttackChain
        │
 [7] Chain prediction ──── hybrid smoothed-Markov + LSTM next-technique model; beam search + Monte-Carlo rollouts → Forecast
        │
 [8] Dynamic risk ──────── entity risk = f(detection confidence, kill-chain progress, forecast expected harm, asset criticality)
        │
 [9] Defense recommender ─ ATT&CK mitigations + action catalog → ranked Recommendations (requires_human_approval = true)
        │
[10] API + SOC dashboard ─ FastAPI (REST) → React dashboard; analyst decisions are recorded, never executed
```

Offline (training) side:
- Detection models, the quantum adjudicator and the sequence models are trained by `training/` CLIs into versioned artifacts under `models/`.
- The ATT&CK knowledge base and sequence corpora are built by `scripts/` from pinned upstream sources.

---

## 3. Module architecture

| Package (`backend/hqc/…`) | Responsibility | Key components (proposed) | Reference inspiration |
|---|---|---|---|
| `core/` | Config, schemas, logging, seeding, run metadata | `config.py` (pydantic-settings + YAML), `schemas.py`, `seed.py`, `runinfo.py` | — |
| `ingestion/` | Dataset adapters → `Event`; replay streamer | `cicids2017.py`, `unsw_nb15.py`, `jsonlog.py` (R2-style schema), `synthetic.py`, `replay.py` | R2 `LogParser` (MIT), R3 loading |
| `preprocessing/` | Cleaning, feature specs, train-only pipelines | `cleaning.py`, `feature_specs/`, `pipeline.py` | R3, R4 |
| `detection/` | Classical models, calibration, ambiguity band | `models.py`, `calibration.py`, `band.py`, `anomaly.py` (IsolationForest, optional) | R3, R2 |
| `quantum/` | Feature maps, kernels, adjudicator, noise models, (stretch) VQC | `feature_maps.py`, `kernels.py`, `adjudicator.py`, `noise.py`, `vqc.py` | R3 wiring, R4 concepts |
| `fusion/` | Classical + quantum score fusion, uncertainty | `stacking.py`, `uncertainty.py` | R5 concepts |
| `mitre/` | ATT&CK knowledge base, label → technique mapping | `kb.py` (STIX 2.1 loader), `mapping.py`, `mappings/*.yaml` | R1 concepts |
| `attack_chain/` | Alert correlation → chains | `reconstruct.py`, `windowing.py` | R2 concept |
| `prediction/` | Corpora, vocab, Markov, LSTM, hybrid, search | `corpus.py`, `vocab.py`, `markov.py`, `lstm.py`, `hybrid.py`, `search.py` | R1 concepts |
| `risk/` | Entity and forecast risk | `entity_risk.py`, `forecast_risk.py`, `levels.py` | R1 + R2 |
| `defense/` | Recommendation engine + guardrails | `catalog.py`, `recommender.py`, `guardrails.py` | R2 (MIT), ATT&CK mitigations |
| `storage/` | SQLite persistence + audit log | `db.py`, `repositories.py` | — |
| `pipeline/` | Orchestration (batch and replay) | `orchestrator.py` | R2 `run_pipeline` |
| `api/` | FastAPI app, routers, response schemas | `app.py`, `routers/*.py` | R2 endpoints |

---

## 4. Canonical data contracts (Pydantic v2, proposed)

```text
Event              event_id, ts (UTC), source_dataset, src_ip, dst_ip, src_port, dst_port, proto,
                   entity_id, features: dict[str, float], raw_label: str | None (ground truth, eval only)
DetectionResult    event_id, p_attack_classical, family_pred, family_proba, in_ambiguity_band: bool, model_version
QuantumAssessment  event_id, p_attack_quantum, kernel_backend ("statevector" | "aer_noisy"), n_support, latency_ms
Alert              alert_id, event_ids, entity_id, ts, p_final, uncertainty, family,
                   techniques: list[TechniqueEvidence{tid, tactic_ids, confidence, source="mapping:<table>@<ver>"}]
AttackChain        chain_id, entity_id, window_start, window_end,
                   steps: list[ChainStep{ts, tid, tactic_id, confidence, alert_ids}], max_tactic_stage
Forecast           chain_id, prefix_tids, horizon, model_versions,
                   next_step: list[{tid, p}], paths: list[{tids, p, p_markov, p_lstm}],
                   reach_probabilities: dict[tactic_id, P(reached within horizon)], entropy, support_flag
RiskAssessment     entity_id, ts, score_0_100, level, components{detection, progression, forecast, context},
                   asset_criticality, explanation
Recommendation     rec_id, entity_id, action_type, title, rationale, addresses{observed: [tid], predicted: [tid]},
                   attack_mitigations: [M-ID], priority, confidence, disruption, reversible: bool,
                   requires_human_approval: true (constant), status (proposed|acknowledged|approved|rejected), audit
```

---

## 5. Quantum component (Phase 6)

### 5.1 Approaches found in the references

| Approach | Where | Assessment |
|---|---|---|
| Quantum feature map — ZFeatureMap (no entanglement) | R3 | The fidelity kernel factorises into single-qubit terms and is classically computable in closed form, so it is useful only as a **control**. Deprecated class API |
| Quantum kernel with RY angle encoding | R4 | Also a product state: K = ∏cos²(Δxᵢ/2). Classically trivial; a control only |
| QSVC (`qiskit_machine_learning.algorithms.QSVC`) | R3 | Correct wiring, but tested on 20 samples, with unscaled angles and no matched baseline |
| Variational Quantum Classifier (Ising ansatz, parameter-shift, ADAM) | R4 | The ansatz idea is sound. The implementation's gradients were identically zero, so the model never trained. VQCs carry barren-plateau and optimisation risk and are costly under simulation |
| Hybrid quantum-classical | R3 (comparison only), R4 (softmax head claimed, not implemented) | No real fusion exists in any reference |
| Noise simulation | R4 (Aer depolarizing + readout) | A good design, but it was never meaningfully exercised |

### 5.2 Recommendation: one primary approach

**Primary: a Quantum Kernel Adjudicator.** This is a fidelity quantum-kernel SVM with an **entangling ZZ-type feature map**, simulated locally. It is applied as a second-opinion classifier to the events that the classical detector finds ambiguous, and fused with the classical score.

- **Why a kernel and not a VQC:** training is a convex SVM problem, with no barren-plateau optimisation. Results are deterministic under statevector simulation, it works at small N, and its cost is predictable. It also has a natural, exactly matched classical twin (an RBF-kernel SVM), which makes a fair comparison possible.
- **Clear purpose in the pipeline:** classical detectors are confident on most traffic. The adjudicator spends quantum (simulated) compute only on the **hard, low-margin cases**, which keeps cost bounded. Its output has three uses:
  1. It refines `p_final` via stacking.
  2. It produces a **classical/quantum disagreement signal** that feeds `uncertainty`.
  3. That uncertainty drives the defense layer's **"collect additional evidence"** recommendation.

  The component therefore changes downstream decisions in a measurable way.
- **No claim of quantum advantage.** The research question is: *"At matched data and feature budgets, does an entangling quantum kernel adjudicator change detection quality on ambiguous cases compared with an RBF-SVM adjudicator and with no adjudicator?"* A null result is a valid result.

### 5.3 Specification

| Item | Proposed setting |
|---|---|
| Input events | Those with `p_attack_classical ∈ [τ_lo, τ_hi]`. The band is tuned on validation so it covers roughly 5–10% of events. The training pool is out-of-fold band cases from the classical model's cross-validation |
| Features | d ∈ {4, 6, 8} (default 8). Train-only pipeline: robust scale → feature selection (mutual information) → PCA(d) → scale to [0, π]. Then multiply by a **bandwidth α** chosen by CV from {0.05, 0.1, 0.25, 0.5, 1.0} to avoid exponential kernel concentration |
| Feature map | `zz_feature_map(d, reps=2, entanglement="linear")` (Qiskit 2.x function API). Controls: `z_feature_map` (product, classically simulable) and the RBF kernel |
| Kernel evaluation | Exact statevector fidelity kernel (qiskit-machine-learning `FidelityStatevectorKernel`, or equivalently cached statevectors with Gram = abs(Ψ Ψ†)²). Budget: N_train ≤ 2,000 balanced samples |
| Classifier | `sklearn.svm.SVC(kernel="precomputed")`. C tuned by CV. Platt or isotonic calibration on a held-out fold |
| Inference cost | One statevector per event plus n_SV inner products against cached support vectors. Latency is measured and reported |
| Fusion | Logistic stacking on validation: logit(p_final) = a·logit(p_cls) + b·logit(p_q) + c. Disagreement = abs(p_cls − p_q) |
| Noise study (secondary) | Aer `NoiseModel` with depolarizing p1 ∈ {1e-4, 1e-3, 1e-2}, p2 ∈ {1e-3, 1e-2, 5e-2}, readout {1%, 3%}, and shots {256, 1024, 4096}. Measures kernel-matrix error ‖K_noisy − K_exact‖ and the accuracy change, on N ≤ 300 because of cost |
| Diagnostics | Kernel-target alignment; off-diagonal kernel variance (concentration check); **geometric difference g(K_classical ‖ K_quantum)** (Huang et al., 2021), an a-priori indicator of whether a quantum kernel *could* outperform the classical one on this data |
| Stretch (post-MVP) | VQC with an Ising-style ansatz (our own implementation) using **correct** gradients (Qiskit `ParamShiftEstimatorGradient` or statevector autodiff), plus a measured gradient-variance vs qubit/layer study. No fabricated comparisons |
| Hardware | Not in scope. The backend interface leaves room for an IBM Runtime backend later |

---

## 6. MITRE ATT&CK mapping and chain reconstruction

### 6.1 Knowledge base
- **Source:** the official ATT&CK Enterprise STIX 2.1 bundle, version-pinned (v16.x to match R1, or the latest stable release; this is a decision for the user).
- **Contents:**
  - Techniques and sub-techniques, tactics, the parent map, and deprecated/revoked flags.
  - Mitigations (`course-of-action`) and `mitigates` relationships.
  - Campaign→technique and group→technique `uses` relationships.
- **Storage:** a cached Parquet/JSON index.

### 6.2 Detection-label → technique mapping
The mapping is a curated YAML table per dataset, with `tid`, `confidence ∈ {high, medium, low}`, `rationale` and `reviewer`. A test asserts that every TID exists in the pinned KB and is not revoked; this test is the fix for R1's invalid names.

Initial proposal for CIC-IDS2017 (all entries to be reviewed):

| CIC-IDS2017 label | Proposed TID(s) | Confidence |
|---|---|---|
| PortScan | T1046 Network Service Discovery | high |
| FTP-Patator, SSH-Patator | T1110.001 Brute Force: Password Guessing | high |
| Web Attack – Brute Force | T1110 Brute Force | high |
| Web Attack – Sql Injection | T1190 Exploit Public-Facing Application | high |
| Web Attack – XSS | T1190 (target-side view) | medium |
| DoS Hulk, GoldenEye, slowloris, Slowhttptest | T1499 Endpoint Denial of Service (sub-technique to be reviewed: .002 / .003) | medium |
| DDoS (LOIC) | T1498 Network Denial of Service / T1499 | medium |
| Bot (Ares) | T1071.001 Application Layer Protocol: Web Protocols | medium |
| Heartbleed | T1190 | medium |
| Infiltration | T1204.002 User Execution: Malicious File → T1046 (internal scan) | low |

UNSW-NB15 categories get a similar table, with mostly low or medium confidence (Fuzzers, Generic and Analysis map poorly).

### 6.3 Chain reconstruction
1. Group alerts by `entity_id`. Policy: the victim host for inbound attacks, the source host for outbound or lateral activity. This is configurable.
2. Use a sliding inactivity-gap window (default: a 30-minute gap closes a chain, and a chain spans at most 24 hours).
3. Order steps by **timestamp**. Unlike R2, we do not re-sort by a stage heuristic.
4. Collapse consecutive duplicate TIDs, keeping counts and first/last time.
5. Track the maximum tactic stage reached.

**Known limitation.** Flow datasets expose only a handful of techniques (recon, brute force, exploit-public-facing, DoS, C2), so reconstructed chains from CIC-IDS2017 will be **short**. The prediction model therefore operates over the full ATT&CK vocabulary learned from CTI corpora, and observed techniques act as **anchors** (§7). Synthetic scenarios (§9.3) supply longer chains for end-to-end evaluation.

---

## 7. Attack-chain prediction architecture (Phase 7)

### 7.1 Training corpora (ordered by trust)
| Corpus | Order quality | How we use it |
|---|---|---|
| MITRE Attack Flow (39 docs, upstream) | **Real causal order** (`effect_refs`) | Primary sequence data. DFS paths are deduplicated; AND/OR operators are documented. **The held-out evaluation set comes from here** |
| Unit42 playbooks (85 bundles, upstream) | No order (sets) | Technique **co-occurrence prior** only. Optional tactic-ordered pseudo-sequences, flagged `synthetic_order=True` and used only in an ablation |
| ATT&CK campaigns and groups `uses` | No order (sets) | Co-occurrence prior. Optional tactic-ordered pseudo-sequences (R1-style), ablation only |
| Synthetic scenarios (§9.3) | Generated from Attack Flow paths | Pre-training augmentation and end-to-end tests. Never used as the sole evaluation |

### 7.2 Sequence encoding
- Tokens are TIDs at sub-technique level, plus `<BOS>`, `<EOS>` and `<UNK>`.
- **Hierarchical backoff:** sub-technique → parent → tactic.
- Each token carries tactic features, encoded as a multi-hot vector over 14 tactics, which is concatenated to the embedding in the LSTM.
- The vocabulary is frozen per KB version, and its hash is stored with every model.

### 7.3 Models
| ID | Model | Notes |
|---|---|---|
| B0 | Unigram / most-frequent-next | Baseline |
| B1 | Tactic-progression heuristic | Baseline: the next technique is the most frequent technique of the next tactic |
| M1 | **Smoothed variable-order Markov** (order 1–3), interpolated Kneser-Ney or Witten-Bell, with hierarchical backoff to parent and tactic transitions | Fixes R1's unsmoothed first-order model, which gives zero probability to any unseen transition |
| M2 | **LSTM** (or GRU; chosen empirically): emb 64–128, hidden 128–256, 1–2 layers, dropout 0.3, plus an auxiliary next-tactic head | Small, to suit the data scale. Early stopping on grouped validation |
| **M3 (final)** | **Hybrid interpolation:** P(t \| prefix) = λ·P_LSTM + (1−λ)·P_Markov, optionally multiplied by a co-occurrence prior P_co(t \| prefix-set)^β and renormalised. λ and β are tuned on grouped validation | One proper distribution rather than R1's "Markov generates, LSTM rescores" |

### 7.4 Multi-step prediction and search
- **Beam search** over M3 with width B (default 16) and horizon H ≤ 5 (default 3). The R1 README itself notes that variance grows sharply beyond 8–12 steps.
- Scores are length-normalised log probabilities. There is a soft penalty for immediate repeats and a soft (not hard) penalty for tactic regression. Real attack flows do revisit Discovery, so hard constraints would be wrong.
- **Monte-Carlo rollouts** (e.g. 2,000 per prefix) estimate calibrated **reach probabilities**: P(tactic X, or technique Y, is reached within H steps). Beam search returns *the most likely paths*; rollouts answer *how likely is impact or exfiltration*, which is what risk needs.
- **Out-of-support handling:** if the prefix contains unseen TIDs, back off and set `support_flag="low"`. Low support raises uncertainty and is surfaced in the UI.

### 7.5 Risk-aware prediction
- Probability and risk are kept as **separate fields**. Path ranking is by probability.
- A "risk-aware view" ranks by expected harm = P(path) × severity(path), with a probability floor (e.g. P ≥ 0.01) so that rare, catastrophic-looking paths don't dominate.
- severity(path) uses a configurable tactic/technique severity table (Impact and Exfiltration high, Discovery low) and asset criticality.

### 7.6 Anchoring detections to the predictor
`AttackChain.steps` are mapped TIDs with confidences. Prediction conditions on the **expected prefix** under confidence: sample K prefixes by mapping confidence, or use the top mapping when confidence is high. This uncertainty is then propagated into `Forecast.entropy`.

---

## 8. Dynamic risk scoring and adaptive defense (Phase 8)

### 8.1 Entity risk (0–100, configurable in `configs/risk.yaml`)

```
S_det   = calibrated max p_final over the entity's alerts in the window, × (1 − κ·uncertainty)
S_prog  = (max tactic stage reached) / 13                       # kill-chain progression, 14 tactics indexed 0–13
S_fore  = Σ_tactic  w_tactic · P(reach tactic within H)          # from the Forecast rollouts
S_ctx   = bounded context factors (privilege, off-hours, data volume, history), inspired by R2
C       = asset criticality ∈ [0,1] (inventory config; default 0.5)

score   = 100 · clip( (0.5 + 0.5·C) · (w1·S_det + w2·S_prog + w3·S_fore + w4·S_ctx), 0, 1 )
level   = LOW < 35 ≤ MEDIUM < 60 ≤ HIGH < 80 ≤ CRITICAL          # thresholds as in R2, configurable
```

Each component is returned alongside the score, together with a template explanation. The weights are initial, documented guesses. They will be studied with sensitivity analysis (§10), not presented as ground truth.

### 8.2 Defense recommendation engine (recommendation-only)

**Inputs:**
- Observed TIDs and predicted TIDs (with probabilities and reach probabilities).
- The risk level.
- Uncertainty and disagreement.
- Entity and asset context.

**Candidate generation:**
1. **Action catalog** (`configs/defense_actions.yaml`). Each action type declares its triggers (TIDs or tactics), disruption level, reversibility and prerequisites:

| Action type | Example triggers (observed or predicted) | Disruption |
|---|---|---|
| `block_suspicious_access` | T1190, T1110, T1133; Initial Access / Credential Access | medium |
| `isolate_affected_host` | Lateral Movement (T1021, T1570), Impact (T1486), C2 (T1071) **and** risk ≥ HIGH | high |
| `restrict_communication` | C2 (T1071, T1572, T1090), Exfiltration (T1041, T1048) | medium |
| `disable_compromised_credentials` | T1078, T1003, T1558, successful T1110 | high |
| `increase_monitoring` | Discovery (T1046, T1087), risk ≥ MEDIUM | low |
| `escalate_severity` | risk ≥ HIGH, or P(reach Impact/Exfiltration) ≥ θ | none |
| `collect_additional_evidence` | High uncertainty or **classical/quantum disagreement**; low-confidence mappings | none |

2. **ATT&CK mitigations.** The `mitigates` relationships from the pinned KB attach M-IDs (e.g. M1032 MFA, M1030 Network Segmentation) to the observed and predicted TIDs. These are vendor-neutral; Unit42's courses of action are product-specific and are not used for recommendations.

**Ranking:**
`priority = level_weight(risk) × coverage × urgency ÷ disruption_cost`, where:
- `coverage` is the probability mass of observed plus predicted techniques that the action addresses.
- `urgency` is higher when high-severity tactics are predicted within fewer steps.

Results are deduplicated per entity and rate-limited.

**Guardrails (enforced in code and tests):**
- Recommendations are plain data. The defense package has **no** executors and no network or credential clients.
- `requires_human_approval` is constant `true`.
- High-disruption actions require an explicit two-step analyst acknowledgement in the UI.
- The API exposes only `GET` for recommendations and `POST` for analyst decisions. Decisions are stored in an append-only audit table and are not executed.
- A test scans `hqc.defense` imports and fails on any import of `subprocess`, `socket`, `paramiko`, `requests`, or firewall or cloud SDKs.
- Recommendation text describes *what an analyst should consider* (e.g. "consider isolating host X pending investigation"). It never contains exploit steps or offensive content.

---

## 9. Dataset strategy (Phase 9)

### 9.1 Choices
| Role | Dataset | Why |
|---|---|---|
| **Primary (detection)** | **CIC-IDS2017** (official UNB MachineLearningCVE CSVs) | Real flows with 14 attack labels, many of which map to ATT&CK (T1046, T1110, T1190, T1499, T1071); used by R3 and R1's label map; per-day files allow **temporal holdout** |
| **Secondary validation** | **UNSW-NB15** (official training/testing split) | An independent lab, feature set and attack taxonomy; used by R4. We evaluate the *pipeline design* on it with its own adapter. We do not transfer models across feature schemas |
| **Sequence knowledge** | ATT&CK STIX 2.1, Attack Flow corpus, Unit42 playbooks (all from upstream, pinned) | The only ordered or semi-ordered technique data available |
| **Synthetic scenarios** | Our generator: sample a chain from Attack Flow paths and assign entities and timestamps, then emit Events; detection-observable techniques draw feature vectors from matching CIC-IDS2017 class distributions | Needed because **no public dataset links per-entity network flows to multi-stage ATT&CK chains**. Provides ground-truth chains for end-to-end evaluation. Always reported separately from real-data results |

Known data caveats, handled in preprocessing and reported:
- CIC-IDS2017 has duplicates, inf/NaN values, the shortcut feature `Destination Port` (run as an ablation), and published label-quality issues (we evaluate whether to use a corrected relabelling; decision deferred).
- Classes are extremely rare: Heartbleed 11, SQL injection 21, Infiltration 36.

### 9.2 Data flow, using one CIC-IDS2017 row as the example
```
CSV row (78 flow features + Label="SSH-Patator", Monday..Friday file)
 → ingestion.cicids2017: strip and normalise column names; build Event{ts from day file + row order or the
   timestamped variant, src/dst IP if available, features, raw_label}
 → preprocessing: drop identifiers; inf→NaN→drop or impute (train-fit); dedupe; train-only scaler + selector
 → detection: RF p_attack=0.97, family="BruteForce"  (outside the band → no quantum call)
   (a borderline event with p=0.55 → quantum adjudicator → p_q=0.81 → fused p_final=0.74, disagreement=0.26)
 → mitre.mapping: "SSH-Patator" → T1110.001 (high), tactic TA0006
 → attack_chain: entity 192.168.10.50, chain [T1046 (09:02), T1110.001 (09:20)], max stage = Credential Access
 → prediction: next-step top-3 {T1078 0.31, T1021.004 0.18, T1059.004 0.09}; P(reach Lateral Movement ≤3) = 0.42
 → risk: S_det 0.97, S_prog 0.46, S_fore 0.38, C 0.8 → score 71 (HIGH) + component breakdown
 → defense: [block_suspicious_access (SSH from source), disable_compromised_credentials (if a T1078 indicator),
            increase_monitoring (host), escalate_severity] + M1032, M1036 … — all "proposed", requires approval
 → API /entities/{id}, /chains/{id}, /forecasts/{id}, /recommendations → dashboard
```
The probabilities above are **illustrative placeholders that show the data shape. They are not results.**

### 9.3 Splits
- **CIC-IDS2017:**
  - (a) stratified random split, for comparability with the literature;
  - (b) **temporal / day-based holdout**, the headline result;
  - (c) per-attack-family holdout as a robustness check.
- **UNSW-NB15:** the official train/test files.
- **Sequences:** grouped K-fold by source document (leave-one-flow-out over Attack Flow), plus a campaign-group holdout.

---

## 10. Evaluation strategy (Phase 10)

**No result is pre-filled. Every table is generated from stored runs.** Each comparison uses at least 5 seeds or repeated stratified splits and reports mean ± std with 95% CIs. We use paired tests (McNemar on predictions, Wilcoxon signed-rank on per-seed metrics) and report effect sizes.

### 10.1 Detection: Classical vs Quantum vs Hybrid
| Exp | Question | Arms | Budget |
|---|---|---|---|
| E1 | Classical ceiling on full data | LR, RF, HistGB, (MLP) | Full train split |
| E2 | **Matched-budget comparison** | RBF-SVM, linear SVM, LR, RF, small MLP **vs** QSVC-ZZ (entangling) **vs** QSVC-Z (product-map control) | N_train ∈ {100, 250, 500, 1000, 2000}; d ∈ {4, 6, 8}; identical preprocessing and seeds |
| E3 | **Hybrid adjudication** (the system's actual use) | Classical only / classical + RBF-SVM adjudicator / classical + quantum adjudicator / classical + Z-map adjudicator | Same ambiguity band, same N |
| E4 | Noise robustness | Statevector vs Aer-noisy kernel (sweeps in §5.3) | N ≤ 300 |
| E5 (stretch) | VQC trainability | Ising-style VQC vs hardware-efficient ansatz: gradient variance vs qubits and layers; accuracy | 4–8 qubits |

**Metrics:**
- Accuracy, precision, recall, F1 (attack class and macro).
- ROC-AUC and **PR-AUC** (needed for imbalance), FPR at 95% TPR, per-family recall.
- Calibration (ECE, Brier).
- Detection latency (p50/p95 ms per event and per 1k events).
- Training time, peak memory, model size.
- Quantum-specific: qubits, circuit depth, 2-qubit gate count, kernel evaluations, shots, plus kernel diagnostics (alignment, concentration, geometric difference).

### 10.2 Attack-chain prediction
- **Arms:** B0, B1, M1, M2, M3, plus data-source ablations: AF only; AF + Unit42 pseudo-order; AF + campaign pseudo-order; with and without the co-occurrence prior.
- **Metrics:**
  - Next-step **top-1/3/5/10 accuracy**, MRR, NLL / perplexity.
  - Next-tactic accuracy.
  - Multi-step **hit@k within horizon H** (does the true future technique appear in the top-k paths within H steps), and normalised edit distance of the best path.
  - Reach-probability calibration (ECE for P(reach tactic)).
  - Inference latency per prefix.
- **Protocol:** grouped CV by source document. No pair-level random split (that was R1's leakage).

### 10.3 Risk prediction quality
There is no public ground-truth risk label, so we will **not** claim accuracy against one. Instead we report:
- (a) On synthetic scenarios with **pre-registered** severity labels: Spearman ρ and Kendall τ between score and label, and precision@k of the highest-risk entities.
- (b) Monotonicity and property tests: more progression gives higher risk, all else equal.
- (c) Global sensitivity analysis over the weights (one-at-a-time sweeps plus Sobol indices).
- (d) Lead time: how many steps before an Impact or Exfiltration step the entity first crosses HIGH.

### 10.4 Defense recommendations
- **Mitigation coverage@k:** fraction of the *actual next* techniques (held-out flows and synthetic scenarios) addressed by the top-k recommendations.
- Recommendation stability.
- Analyst-facing latency.
- Guardrail tests: all must pass.

### 10.5 End-to-end
On synthetic scenarios and the CIC-IDS2017 temporal holdout:
- Chain-reconstruction precision and recall of TIDs, plus edit distance.
- Time-to-first-alert.
- Forecast lead time.
- Pipeline throughput (events/s) on a laptop CPU.

---

## 11. Technology stack (proposed; pin exact versions after an install test on Python 3.11)

| Area | Choice |
|---|---|
| Core | numpy, pandas, pyarrow, scikit-learn, scipy, pydantic v2, pydantic-settings, PyYAML |
| Deep learning | PyTorch (CPU wheel by default) |
| Quantum | qiskit 2.x, qiskit-aer, qiskit-machine-learning 0.9.x. The references used Qiskit 2.4.1, Aer 0.17.2 and qiskit-ml 0.9.0, but compatibility on Python 3.11 must be verified. Use function-style feature maps (`zz_feature_map`, `z_feature_map`) |
| ATT&CK | Plain JSON STIX parsing. `stix2` / `mitreattack-python` only if needed |
| API | FastAPI, uvicorn |
| Storage | SQLite via SQLAlchemy 2; Parquet for datasets and features |
| Frontend | React + Vite + TypeScript, ECharts or Recharts, plus an ATT&CK matrix heatmap component |
| Quality | pytest, pytest-cov, hypothesis (property tests for risk), ruff, mypy, pre-commit |
| Repro | `Makefile`, seed utility, run-metadata JSON. MLflow optional later |
| Packaging | `pyproject.toml`. Separate extras: `[quantum]`, `[dl]`, `[api]`, `[dev]`. Lock file for exact pins |

---

## 12. Final project folder structure

This modifies the proposed structure. The changes are explained after the tree.

```
project-root/
├── backend/
│   └── hqc/                       # installable package (pip install -e .)
│       ├── core/                  # config, schemas (data contracts), seeding, run metadata, logging
│       ├── ingestion/             # dataset adapters (cicids2017, unsw_nb15, jsonlog, synthetic) + replay
│       ├── preprocessing/         # cleaning, feature specs, train-only pipelines
│       ├── detection/             # classical models, calibration, ambiguity band, optional anomaly detector
│       ├── quantum/               # feature maps, kernels, adjudicator, noise models, (stretch) vqc
│       ├── fusion/                # classical+quantum stacking, uncertainty
│       ├── mitre/                 # ATT&CK STIX KB loader, label→technique mapping (+ mappings/*.yaml)
│       ├── attack_chain/          # alert correlation → AttackChain
│       ├── prediction/            # corpora, vocab, markov, lstm, hybrid, beam/rollout search
│       ├── risk/                  # entity + forecast risk
│       ├── defense/               # action catalog, recommender, guardrails (recommendation-only)
│       ├── storage/               # SQLite models, repositories, audit log
│       ├── pipeline/              # orchestrator (batch + replay)
│       └── api/                   # FastAPI app + routers
├── frontend/                      # React + Vite + TS SOC dashboard (API-driven only)
├── configs/                       # default.yaml, detection.yaml, quantum.yaml, prediction.yaml, risk.yaml,
│                                  # defense_actions.yaml, mappings/ (or link to hqc/mitre/mappings)
├── data/                          # git-ignored: raw/, interim/, processed/, external/ (ATT&CK, Attack Flow, Unit42)
│   └── MANIFEST.yaml              # committed: source URL, version, date, SHA-256, license per artifact
├── models/                        # git-ignored artifacts + committed model cards (*.md) and registry.yaml
├── training/                      # CLIs: train_detector.py, train_adjudicator.py, train_sequence.py
├── evaluation/                    # experiment runners E1–E5 + metrics + report generation; results/ (git-ignored)
├── notebooks/                     # exploration only; no logic that the package depends on
├── tests/                         # unit/, integration/, guardrails/, fixtures/ (tiny synthetic data)
├── scripts/                       # download_*.py, build_attack_kb.py, build_corpora.py, verify_manifest.py
├── docs/                          # these analysis docs + design docs + model cards + THIRD_PARTY_NOTICES.md
├── docker/                        # Dockerfile(s), docker-compose.yml (api + frontend)
├── pyproject.toml                 # deps + extras; requirements*.txt generated from lock for convenience
├── Makefile                       # setup, data, train, eval, test, lint, serve
└── README.md
```

**Changes from the proposed structure, and why:**
- `backend/hqc/` is an installable package, so tests, training CLIs and the API import the same code. R1's scripts couldn't be imported at all.
- `mitre/` is split from `attack_chain/`. The knowledge base and mappings are shared by prediction, risk and defense.
- `fusion/` is added, so the quantum layer stays independent of classical detection and the hybrid logic is explicit.
- `storage/` and `pipeline/` are added.
- `datasets/` is renamed to `data/`, with a committed `MANIFEST.yaml`. No data goes in git.
- `docker/` is added; `tests/guardrails/` enforces the recommendation-only policy.

**Open placement decision (for the user):** the five reference repos currently sit at the workspace root, and per instructions they won't be moved. There are two options:
- **Option A:** make the workspace root the project root and git-ignore the five reference folders. Pytest `testpaths` and ruff `exclude` must then be set so their files aren't picked up.
- **Option B (recommended):** create the project in a new folder (e.g. `hqc-framework/`), copy these `docs/` into it, and treat the five repos as external references. This keeps git history, test discovery and linting clean.
