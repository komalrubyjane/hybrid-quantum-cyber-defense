# Attack-chain integration (Milestone 7)

Status: **implemented**. It was exercised end to end on a **SYNTHETIC** scenario in run `20261007T083826Z-integration-synthetic-multistage`, where all 13 integration checks passed.

Milestone 7 is the intelligence integration layer. It connects the existing components and retrains nothing: Milestones 3–6 are reused through their stored artifacts. Every stage exchanges typed contracts.

```
SecurityEvent ─► DetectionEvidence ─► TechniqueEvidence ─► IncidentChain (AttackChain)
   (M1)        (M5 classical + M6 quantum)  (explicit sources)    (observed, order-preserving)
        ─► NextTechniquePrediction ─► RiskAssessment ─► DefenseRecommendation
           (M3/M4 models, beam)        (RISK_ENGINE.md)   (ADAPTIVE_DEFENSE.md; approval required)
```

**Python services** (no HTTP; Milestone 8 will wrap them with FastAPI):

| Service | Module | Role |
|---|---|---|
| `AttackChainService` | `hqc.attack_chain.reconstruction` | Correlates evidence into chains and reconstructs them |
| `PredictionService` | `hqc.prediction.service` | Predicts next techniques and paths |
| `RiskService` | `hqc.risk.engine` | Scores risk |
| `DefenseRecommendationService` | `hqc.defense.recommender` | Produces recommendations |

They are composed by `hqc.pipeline.intelligence.IntelligencePipeline` and configured in `configs/integration.yaml`. The demo runner is `evaluation/run_integration_demo.py`.

## Evidence (`hqc.attack_chain.evidence`, `hqc.common.schemas.intelligence`)
**CIC-IDS2017 attack labels ≠ MITRE ATT&CK techniques.**
- There is **no** label → technique table.
- `technique_evidence_from_dataset_label()` always raises `NoDocumentedMappingError`.
- Explicit rules may not read the evaluation-only `ground_truth_label` field.

`TechniqueEvidence` fields:
- `technique_id` and an optional `tactic_id`;
- `event_id` and `timestamp` (required unless the source is Attack Flow);
- `confidence`;
- `source`, a non-empty `evidence` list and a `reference`;
- `detection_model` / `model_version`, required for detector-sourced evidence.

**Sources** (none is trusted by default; quantum output is *not* treated as more trustworthy):

| Source | Meaning |
|---|---|
| `EXPLICIT_RULE` | Documented rule (`RuleSet` YAML: conditions, confidence, rationale, references, status `illustrative`/`validated`). No production rule set ships yet, so the engine is tested with illustrative rules |
| `SYNTHETIC_SCENARIO` | Explicit annotation in a synthetic scenario |
| `ATTACK_FLOW` | Documented CTI; becomes `DOCUMENTED` steps, never observed ones |
| `CLASSICAL_DETECTOR`, `QUANTUM_SECOND_OPINION` | Reserved for detectors that emit techniques. Our detectors emit only BENIGN/MALICIOUS, so they never produce technique evidence here |

**Validation against ATT&CK 19.2:**
- The tactic must be one of the technique's tactics in the KB.
- "Active" means present in the committed technique vocabulary (697 active techniques).
- Well-formed IDs that are not active are kept, but are listed as `out_of_vocabulary_technique_ids` and become `<UNK>` in the prediction history.
- No ATT&CK relationship is invented: revoked-by links are **not** followed automatically.

**`DetectionEvidence`** carries:
- the classical model, version, P(malicious), threshold and verdict;
- the optional M6 `QuantumOpinion`;
- `quantum_disagreement` and `evidence_status`.

The adapter `detection_evidence_from_result()` accepts real M5/M6 `DetectionResult`s. **The classical verdict is never changed.**

**Evidence status rule** (`evidence-policy-v1`):

| Situation | Status |
|---|---|
| No triggered second opinion | `NO SECOND OPINION` |
| Agreement | `CONSISTENT` |
| Disagreement | `NEEDS ADDITIONAL EVIDENCE` |
| Disagreement, plus independent (non-detector) technique evidence for the same event with confidence ≥ 0.7 | `CORROBORATED BY INDEPENDENT EVIDENCE` |

## Correlation and reconstruction (`hqc.attack_chain.reconstruction`, `correlation-v1`)
Observations are processed in **arrival order** and are never sorted.

An observation joins an open chain whose last observation is at most 120 minutes earlier, using the first matching documented rule:
1. `incident_id`: equal explicit IDs. This rule is decisive: different incident IDs never join, even on a shared host.
2. `session_id`: equal explicit IDs.
3. `shared_resource`: an entity, host or target host in common.
4. `shared_account`: a user account in common (can be disabled).

IP addresses are recorded as context but never correlate on their own, because of NAT and shared addresses.

| Situation | Outcome |
|---|---|
| No match | New chain; `STANDALONE` if nothing ever joins it |
| Several matching chains | New chain marked `AMBIGUOUS`; chains are **never merged** and an event is never forced in |
| Event older than the chain it matches | `ChainOrderError`. The M1 `AttackChain` contract rejects non-chronological chains, and nothing is re-sorted to make a chain valid |
| Event without technique evidence | No step is produced (nothing is fabricated); listed as `unmapped_event_ids` |

**Steps:**
- **Primary technique:** each observation produces one OBSERVED step whose technique is the highest-confidence evidence. Ties go to `EXPLICIT_RULE`, then `SYNTHETIC_SCENARIO`, then the others, then the ID.
- **Alternatives:** other evidence is kept as `alternative_candidates`.
- **Tactic:** taken from the evidence, or inferred only when the technique has exactly one tactic.
- **Provenance is separated:**
  - `IncidentChain.chain` holds OBSERVED steps only (validated);
  - `documented_steps` holds DOCUMENTED Attack Flow steps (`attach_documented`);
  - predicted steps live only in `NextTechniquePrediction` (the M1 `AttackChain` rejects PREDICTED steps).

## Prediction integration (`hqc.prediction.service`)
**Reused artifacts; nothing is retrained:**
- **M3:** `B1.json` and `M1.json`, fitted on all 37 groups.
- **M4:** the LSTM checkpoint `fold-00`, held-out group "Black Basta Ransomware".
- **Hybrid:** `α·LSTM + (1−α)·M1` with **α = 0.7**, fold-00's own inner-validation choice. It is also the most common choice across M4 folds (14 of 36), and fold-00 fused M1, which is verified on load.

This composed configuration is a deployment choice and **was not separately evaluated**. Generalisation estimates remain the M3/M4 nested-LOGO results, where the frequency baseline B1 was strongest on top-1.

| Output | Meaning |
|---|---|
| **NEXT-STEP PROBABILITY** | Top-k (5) `P(next | observed history)` for each model (B1, M1, LSTM, HYBRID). The primary model is HYBRID. `<UNK>` can appear in the history but is never a target |
| **PATH SCORE** | Beam search (width 10, horizon 3) over the primary model. Each path's joint model probability. Summed path scores are a **lower bound**, not a calibrated probability of reaching a tactic, so "probability of reaching Impact/Exfiltration" is **not evaluated** (as in M4) |

Only the chain's observed technique IDs are the model input. Documented and predicted steps are never included, so no future or test information is used.

## Synthetic scenario (`configs/scenarios/synthetic_multistage_v1.json`)
**SYNTHETIC: hand-authored events, detector scores and ATT&CK annotations. No model produced the scores, no real attack is described, and nothing is ever executed.**

**Main chain** (Linux web-server compromise):

| Event | Technique | Tactic |
|---|---|---|
| e01 | T1190 | Initial Access |
| e03 | T1059.004 | Execution |
| e04 | T1098.004 | Persistence |
| e05 | T1003.008 | Credential Access |
| e06 | T1021.004 | Lateral Movement |
| e08 | T1041 | Exfiltration |

**Other events:**
- an unrelated failed mailbox login (e07, T1110.001, standalone);
- a benign request without technique evidence (e02, unmapped).

**Validation:** every technique is active in ATT&CK 19.2, and every annotated tactic is one of its tactics in the KB. This is checked at run time and by a `requires_data` test.

**Not a documented incident:** none of the five consecutive technique transitions occurs in the project's Attack Flow corpus. 5 of the 6 techniques appear individually; T1098.004 never does. The chain is a plausible synthetic construction.

**Disagreement cases are deliberately included:**
- **e03:** quantum disagrees, but the annotation (confidence 0.85) corroborates it → `CORROBORATED BY INDEPENDENT EVIDENCE`.
- **e04:** quantum disagrees and the annotation confidence is only 0.6 → `NEEDS ADDITIONAL EVIDENCE`.

## Measured integration results (run `20261007T083826Z-integration-synthetic-multistage`)
**Integration checks (13/13 passed):**
- chains, statuses, unmapped events and evidence statuses match the scenario's expectations;
- arrival order is preserved;
- observed and predicted steps are separated;
- prediction outputs are valid (sorted, sum ≤ 1, no `<UNK>` targets, path score = exp(log score), history mapping);
- the risk formula recomputes and the level matches the thresholds;
- the risk label is "MODEL-DERIVED";
- the **risk score is identical with the quantum opinion removed or inverted**;
- the classical verdict is unchanged;
- every recommendation is PROPOSED and requires human approval;
- disruptive actions are withheld on unresolved disagreement;
- recommendations stay within the policy plan.

**Main chain** (as of 09:35):
- **Prediction:** HYBRID's top next step is T1105 (0.090). That is a generic, frequent technique, consistent with M3/M4, where frequency dominated.
- **Risk:** **76.45, CRITICAL**, with evidence status NEEDS ADDITIONAL EVIDENCE (because of e04).
- **Recommendations:** escalate, restrict communication pending approval, collect evidence (web-01), monitor. Isolation and blocking were withheld.

**Standalone failed login:** 44.38 MEDIUM.

**Risk trajectory** (each point uses only events seen so far):

| After event | Score | Level |
|---|---|---|
| e01 | 57.19 | HIGH |
| e03 | 58.63 | HIGH |
| e04 | 59.13 | HIGH |
| e05 | 65.93 | HIGH |
| e06 | 71.72 | HIGH |
| e08 | 76.55 | CRITICAL |

**Stored M6 outputs (real data; policy behaviour, not performance):**
- Applying the evidence rule to the 351,705 primary-band test rows with a ZZ opinion gives 152,041 disagreements. All of them become `NEEDS ADDITIONAL EVIDENCE`, because CIC flows have no technique evidence. This matches M6's reported disagreement count.

**Not evaluated:**
- detection, technique attribution, prediction or risk accuracy on real multi-stage incidents (no such labelled data exists in the project);
- calibration of path scores or of reach probabilities.

## Limitations
- The scenario is small and synthetic, so it tests plumbing, not security performance.
- No validated explicit-rule set exists yet, so technique evidence for real traffic is currently unavailable by design.
- Correlation is rule-based with a fixed 120-minute window. The scenario shows it can chain hosts through a shared host, but it has not been validated on real incident data.
- The prediction models were trained on 37 Attack Flow documents, so predictions are generic (dominated by frequent techniques such as T1105).
