# Final evaluation — Hybrid Quantum-AI Intelligence Framework for Cyberattack Chain Prediction and Adaptive Defense

**Milestone 10.** This is the final research result of a defensive research prototype. The detailed numbers are in `RESULTS.md`, limitations in `LIMITATIONS.md`, provenance in `REPRODUCIBILITY.md`, and the as-built design in `FINAL_ARCHITECTURE.md`. Every number in this report comes from stored runs, through `evaluation/build_final_report.py` into `artifacts/final/`.

**How M10 was produced:**
- **Nothing was retrained, no hyperparameter was changed, and no M3–M7 evaluation was re-run.**
- New in M10:
  - the consolidation and figure script;
  - a lightweight end-to-end validation (`evaluation/validate_end_to_end.py`);
  - an opt-in live dashboard ↔ API test;
  - documentation.

## 1. Problem
**Goal:** support SOC analysts by connecting several pieces of evidence:
- network-flow intrusion detection;
- structured attack knowledge (MITRE ATT&CK);
- attack-stage prediction;
- an explainable risk score;
- defense **recommendations** that a human approves.

**Research questions:**
- Can ATT&CK / Attack Flow sequences support next-technique prediction beyond simple baselines?
- How well do classical detectors generalise to unseen attack types?
- Does an entangling quantum-kernel second opinion change detection quality at matched budgets?
- Can these parts be integrated so that observed, predicted and model-derived information stay distinct and no action is ever executed automatically?

## 2. Architecture
**Pipeline** (see `FINAL_ARCHITECTURE.md`): events → classical detection (+ quantum second opinion) → ATT&CK technique evidence → order-preserving incident chains → next-technique prediction → MODEL-DERIVED risk → PROPOSED recommendations → versioned FastAPI → React dashboard.

**Component maturity:**
- **Evaluated on real data:** detection, quantum second opinion and prediction.
- **Demonstrated on a synthetic scenario:** integration, risk and defense.

## 3. Data
| Data | Use | Version / integrity |
|---|---|---|
| MITRE ATT&CK Enterprise STIX 2.1 | Knowledge base, vocabulary | **19.2**, SHA-256 in `data/MANIFEST.yaml` |
| Attack Flow corpus | Ordered technique sequences (37 groups) | `main@8b6ca28bc13b`, 41 files with SHA-256 |
| CIC-IDS2017 GeneratedLabelledFlows | Detection, quantum experiments | zip SHA-256 `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a`; 2,830,743 flows |
| Synthetic multi-stage scenario | Integration demonstration only | `synthetic-multistage@1` (hand-authored; SYNTHETIC) |

All checksums were re-verified in M10 (54 files, all match).

## 4. ATT&CK knowledge base
- ATT&CK 19.2: 697 active techniques, 15 tactics, mitigations, detection strategies and data components.
- Technique IDs are validated against it: inactive IDs become `<UNK>` and are never prediction targets.
- **CIC-IDS2017 labels are not mapped to ATT&CK techniques.** That refusal is enforced in code.

## 5. Classical detection (M5)
**Protocol:**
- Whole-day holdout: train Monday–Wednesday, test Thursday–Friday. No test attack type occurs in training.
- Fixed 0.5 threshold; train-only preprocessing; pre-registered primary Random Forest.

**Results:**
- **Primary Random Forest:** precision **0.9955**, recall **0.2834**, F1 0.4412, ROC-AUC 0.8097, PR-AUC 0.6900, benign FPR **0.0004**.
- **Logistic Regression:** recall 0.4582 at benign FPR 0.0335.
- **Missed attack types:** the RF misses essentially all PortScan, Bot and Infiltration flows.
- **Destination-port ablation:** it improves ranking (ROC-AUC 0.810 → 0.889), which points to a shortcut feature.
- **Duplicates:** cross-split duplicates (6.0%, 83 with conflicting labels) do not change recall.

**Interpretation:** a very precise detector with poor generalisation to unseen attack types.

## 6. Attack prediction (M3/M4)
**Protocol:** nested leave-one-group-out over 36 evaluable Attack Flow groups, with 95% bootstrap CIs.

**Results:**
- **Strongest on top-1 and log loss:** the frequency baseline B1 (top-1 0.0736, log loss 5.724).
- **LSTM:**
  - It is significantly better than B1 **only on top-5** (+0.030).
  - Its log loss is significantly worse (+0.172).
  - It ranks T1105 first in 99.9% of instances.
- **Hybrid:**
  - It improves log loss over the LSTM (−0.161).
  - It is not better than B1 on log loss.
  - It is significantly worse than B1 on top-1.
- **Multi-step:** beam search (width 10) has essentially zero exact 3-step path accuracy.

**Interpretation:** the ordered-sequence data supports only weak next-step prediction, and **strong multi-step attack-chain prediction is not established**.

## 7. Quantum second opinion (M6)
**Setup:**
- Exact statevector fidelity kernels, with the NumPy implementation validated against Qiskit 2.5.2.
- An entangling ZZ map, a non-entangling Z control, and classical baselines on the same features.

**E2, matched budget:**
- ZZ never significantly beat the RBF-SVM, and was significantly worse in five (cell, metric) cases.
- The classically computable Z control was comparable to ZZ.

**E3, second opinion on the training-derived uncertainty band:**
- That band covers 30.3% of test traffic, against a 10% target.
- Fusion raises whole-test recall (RF 0.283 → RF+ZZ 0.564, RF+RBF 0.611, RF+Z 0.655), but only by raising benign FPR from 0.04% to 7.8–8.9%.
- RF+ZZ PR-AUC (0.666) is **below** RF alone (0.690).
- ZZ is the weakest second opinion. This is **not** an unconditional improvement.

**E4, noise:**
- Kernel error roughly halves for every 4× more shots.
- High depolarizing + readout noise gives 73–74% kernel error and cuts balanced accuracy from 0.757 to 0.61.

**No quantum advantage was observed under the tested conditions.**

## 8. Risk engine (M7)
- **Output:** a 0–100 **MODEL-DERIVED RISK SCORE** from a documented, fixed policy.
- **Weights:** detection 25, technique confidence 15, tactic progression 25, predicted high-impact 15, asset criticality 10, recency 10; **quantum 0**.
- **Thresholds:** 25 / 50 / 75.
- It is not calibrated and has no ground truth.

## 9. Adaptive defense (M7)
- **Policy:** deterministic, by risk level.
- **Disagreement handling:** with an unresolved classical/quantum disagreement, disruptive proposals (isolate, block, disable credentials) are withheld and evidence collection is added.
- **Approval:** every recommendation is PROPOSED and requires human approval.
- **Execution:** the system executes nothing.

## 10. FastAPI (M8)
- `/api/v1` offers stateless computations, immutable stored assessments, GET-only recommendations and append-only analyst decisions.
- Approving a HIGH-disruption recommendation requires a prior acknowledgement; otherwise the API returns 409.
- Responses always report `executed: false`, and there is no execution endpoint.

## 11. React dashboard (M9)
- **Pages:** overview, assessment submission and detail, MITRE IDs, evaluation runs.
- **Clear distinctions:** observed vs predicted steps, the model-derived risk label, the classical verdict next to the quantum second opinion, and recommendations vs recorded decisions.
- **Types:** generated from the API's OpenAPI document, with a backend contract-drift test.

## 12. Evaluation methodology
| Area | Method |
|---|---|
| Prediction | Nested leave-one-group-out with grouped folds (no source-group leakage), document weighting, bootstrap CIs, paired differences |
| Detection | Whole-day holdout, fixed threshold, pre-registered primary model, duplicate audit, destination-port ablation |
| Quantum | Thresholds and hyperparameters from training days only (leave-one-training-day-out), matched budgets, 5 seeds with t-CIs (E2), paired ZZ–RBF tests |
| Integration | Deterministic synthetic scenario with 13 integration checks; disagreement policy applied to stored real M6 outputs |
| M10 | End-to-end API workflow validation (17/17) and an opt-in live dashboard test (passed against a running API on a scratch database) |

## 13. Results
See `RESULTS.md` and `artifacts/final/` (tables, 10 SVG figures, `results.json`).

**Verification of the claims supplied for M10:** each was checked against the stored runs.

| Claim | Status |
|---|---|
| M3/M4/M5/M6/M7 figures in the brief | **Confirmed** |
| "Hybrid improved log loss relative to LSTM/B1" | **Corrected.** Better than the LSTM (−0.161, significant); **not** better than B1 (+0.012, CI [−0.075, 0.096]); significantly worse than B1 on top-1 |
| "Z control matched or beat ZZ" | **Refined** to "comparable". No paired ZZ–Z test was run, and ZZ was nominally higher in some cells |
| Shot noise "4.3% → 1.1%" | These are the **training**-kernel errors; the test-kernel errors are 4.7% → 1.2% |
| "~73% kernel bias" | Measured as relative Frobenius kernel error: 0.729 (train), 0.739 (test) |

## 14. Limitations
See `LIMITATIONS.md` (25 items). The most important:
- weak and frequency-dominated attack prediction;
- poor detection of unseen attack types;
- integration validated only synthetically;
- uncalibrated, heuristic risk and recommendations;
- no authentication;
- simulation-only, noise-sensitive quantum kernels with no observed advantage;
- results produced from uncommitted code.

## 15. Security boundaries
| Check | Result |
|---|---|
| Backend tests | **488 passed** (99% coverage) |
| Guardrail tests (defense + API AST scans, route contracts) | **56 passed** |
| Frontend tests | **53 passed**, 1 opt-in live test skipped by default (it passed against a running API) |
| Dashboard static security scan | Included in the frontend tests |
| Ruff, ruff format, strict mypy, TypeScript strict, ESLint, production build | All clean |

**Additional M10 checks:**
- The only backend `subprocess` use is a fixed-argument, shell-free, read-only `git status` for run provenance. It is not reachable from the API.
- Network access exists only in the allowlisted official-source downloader, which scripts use.
- There are no SSH, firewall, account or cloud libraries.
- The API runs with debug off, and wildcard CORS is rejected.
- No secrets were found; only `.env.example` files exist.
- No executable recommendation endpoint exists.

## 16. Reproducibility
Every reported result is class **B**, reproducible by re-running an existing evaluation, or class **A**, the tables and figures generated from stored artifacts. The M7 demo and M10 validation are class **D**, synthetic. No result is class **C**. See `REPRODUCIBILITY.md`.

**Main caveat:** all runs were produced from an uncommitted working tree (`c2813d4` + changes). A source fingerprint was recorded; committing and re-running is recommended for full provenance.

## 17. Final conclusion
A complete hybrid Quantum-AI cyber-intelligence framework was implemented end to end, from typed events to an analyst dashboard:

| Part | Role |
|---|---|
| Classical machine learning | Provides the primary intrusion-detection capability. The pre-registered Random Forest is very precise on unseen CIC-IDS2017 days, but recalls only 28% of unseen attack traffic |
| Markov / LSTM models | Provide attack-stage prediction experiments over ATT&CK / Attack Flow. They do not beat a frequency baseline on top-1, gain only on top-5, and do not establish multi-step attack-chain prediction |
| ATT&CK 19.2 and Attack Flow | Provide the structured attack knowledge and the technique vocabulary |
| Integration layer (M7) | Connects detection evidence, order-preserving attack chains, prediction, a model-derived risk score and defense recommendations, keeping observed, predicted and model-derived information distinct. It has been demonstrated **only on a synthetic scenario** |
| FastAPI layer | Exposes the intelligence pipeline |
| React dashboard | Provides analyst-facing visualisation |

**Human approval is mandatory, and no defense action is ever executed automatically.**

**The quantum component was evaluated as a second opinion.** Under the tested matched-budget conditions (exact simulation, 4–8 qubits), the entangling quantum kernel did **not** demonstrate an advantage over classical baselines:
- it was never significantly better than an RBF-SVM;
- it was sometimes significantly worse;
- it was the weakest fused adjudicator.

It should therefore be described as an **experimental adjudication component, not a superior detector**. The system is a research prototype for decision support, **not autonomous cyber defense**.
