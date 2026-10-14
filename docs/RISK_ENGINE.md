# Risk engine (Milestone 7)

Module: `hqc.risk.engine`, policy `risk-policy-v1`, configured in `configs/integration.yaml`.

**The output is a MODEL-DERIVED RISK SCORE**, a 0–100 engineering score.
- It is not a probability, not a certainty and not ground truth.
- The `RiskAssessment.label` field is fixed to `MODEL-DERIVED RISK SCORE`.
- There is no risk ground truth in this project, so the weights are a documented **policy choice**, not fitted.
- The weights and thresholds were fixed before any evaluation and were not tuned on the scenario's outputs.

## Formula
```
score = Σ weight_i × value_i,      value_i ∈ [0, 1],   Σ weight_i = 100   (validated)
```

| Component | Weight | Value |
|---|---|---|
| `detection` | 25 | Max **classical** P(malicious) over the chain's detections (0 if none) |
| `technique_confidence` | 15 | Mean confidence of the chain's observed steps |
| `tactic_progression` | 25 | (Furthest observed matrix position + 1) / number of tactics. ATT&CK 19.2 has 15 tactics, positions 0 (reconnaissance) to 14 (impact). It uses the attributed tactic, or the earliest tactic if none was attributed |
| `predicted_high_impact` | 15 | Primary-model (HYBRID) P(next technique has an Exfiltration TA0010 or Impact TA0040 tactic), summed over the **full** next-step distribution. It is a next-step probability, **not calibrated** |
| `asset_criticality` | 10 | Max **provided** criticality of the chain's resources (LOW 0.25, MEDIUM 0.5, HIGH 0.75, CRITICAL 1.0). Criticality is never invented: with none provided, the neutral default is 0.5 |
| `recency` | 10 | 0.5^(hours since the latest observed step / 6 h half-life). An `as_of` earlier than the evidence is rejected |
| `quantum_second_opinion` | **0** | Share of disagreements. **Informational only; contributes 0 points by construction** |

Each component is returned as a `RiskComponent` with its value, weight, points and a human-readable reason. Model versions (prediction, detector) and the policy version are recorded on the assessment.

## Thresholds (engineering labels, fixed in advance)
| Score | Level |
|---|---|
| 0 – <25 | LOW |
| 25 – <50 | MEDIUM |
| 50 – <75 | HIGH |
| 75 – 100 | CRITICAL |

## Quantum evidence
- The quantum second opinion is one signal among several, and it **can never raise the score**: it has weight 0.
- On disagreement, the assessment records:
  - `quantum_disagreement = true`;
  - the worst `evidence_status` across the chain;
  - `uncertainty`, the share of detections that NEED ADDITIONAL EVIDENCE.
- Those fields drive the evidence-collection recommendation and the withholding of disruptive actions (see `ADAPTIVE_DEFENSE.md`).
- **Tested:** the score is identical with the quantum opinion removed or inverted, both in unit tests and in the integration checks.

## Example (SYNTHETIC scenario, run `20261007T083826Z-integration-synthetic-multistage`)
Main chain: T1190 → T1059.004 → T1098.004 → T1003.008 → T1021.004 → T1041.

| Component | Value | Points |
|---|---|---|
| detection | 0.910 | 22.75 |
| technique_confidence | 0.767 | 11.50 |
| tactic_progression | 0.933 (exfiltration) | 23.33 |
| predicted_high_impact | 0.097 | 1.46 |
| asset_criticality | 0.75 (db-01 HIGH) | 7.50 |
| recency | 0.990 | 9.90 |
| quantum_second_opinion | 0.333 (2 disagreements) | 0.00 |
| **Total** | | **76.45 (CRITICAL)** |

These numbers come from hand-authored synthetic inputs and demonstrate the arithmetic only.

## Limitations
- The weights and the 6-hour half-life are policy assumptions without empirical calibration.
- **Weak single events can score MEDIUM.** Tactic progression uses the attributed tactic regardless of its confidence, so a single weak credential-access event can reach MEDIUM: the synthetic failed login (confidence 0.4, P = 0.30) scored 44.38. This was observed after the policy was fixed and is reported rather than tuned away.
- `predicted_high_impact` inherits the prediction models' limitations: there are only 37 training documents, and the probabilities are uncalibrated.
- Asset criticality depends entirely on operator-provided metadata.
