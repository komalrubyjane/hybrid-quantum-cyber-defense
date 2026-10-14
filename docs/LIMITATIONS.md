# Limitations (Milestone 10)

These limitations are stated plainly so the results are not over-interpreted. The numbers are in `RESULTS.md`.

## Attack-chain prediction
1. **Small, skewed training data.** The ordered-sequence corpus is 37 Attack Flow documents (36 evaluable groups), and CIs are wide. Pseudo-ordered sources were used only as ablations.
2. **Attack Flow distribution skew.** A few techniques dominate the corpus. The frequency baseline B1 is the strongest model on top-1 and log loss.
3. **T1105 dominance.** The LSTM ranks T1105 (Ingress Tool Transfer) first for 99.9% of test instances, the same as B1. Learned context changes only ranks 2–5, so the LSTM's only significant gain over B1 is top-5 (+0.030). Its log loss is significantly worse.
4. **Weak multi-step prediction.** With beam width 10, exact 3-step path hits are essentially zero for every model. Path scores are joint model probabilities: their sums are lower bounds, and reach probabilities for Impact or Exfiltration were **not evaluated**.
5. **Hybrid fusion is not better than the baseline.** It improves log loss over the LSTM but is not better than B1, and it is significantly worse than B1 on top-1.

## Detection data (CIC-IDS2017)
6. **Age and domain.** CIC-IDS2017 is a 2017 lab capture with scripted attacks. It does not represent current enterprise traffic, encrypted-traffic analytics or cloud workloads.
7. **Duplicate feature vectors.** 6.0% of test rows have a feature vector also seen in training, 83 with conflicting labels. The audit shows recall is unaffected, but duplicates remain a known dataset issue.
8. **Destination-port shortcut.** Removing destination port improved ROC-AUC (RF 0.810 → 0.889), consistent with a shortcut that does not generalise. The pre-registered primary detector keeps the full feature set.
9. **Poor recall on unseen attack types.** The whole-day split makes every test attack type unseen in training. The primary RF has precision 0.9955 but recall 0.283, and detects essentially no PortScan (0.09%), Bot (0%) or Infiltration (0%) flows. SQL injection (21 flows) and Infiltration (36) are too rare for stable estimates.
10. **Single run, no CIs** for the detectors; the threshold was fixed at 0.5 and never tuned.

## Integration, risk and defense
11. **The end-to-end integration is synthetic only.** M7 was demonstrated on one hand-authored scenario. No public dataset links per-entity network events to labelled multi-stage ATT&CK chains, so chain reconstruction, technique attribution and end-to-end accuracy were **not evaluated on real data**. None of the scenario's technique transitions occurs in the Attack Flow corpus.
12. **No technique evidence for real traffic.** CIC labels are deliberately not mapped to ATT&CK techniques, and no validated explicit-rule set exists. Real CIC flows therefore produce no attack-chain steps.
13. **Heuristic, uncalibrated risk score.** The MODEL-DERIVED RISK SCORE is a documented weighted policy (weights 25/15/25/15/10/10, thresholds 25/50/75), not fitted to outcomes; there is no risk ground truth. A single weak credential-access event can reach MEDIUM (44.38).
14. **Heuristic defense recommendations.** The action table, urgencies and confidence formula are engineering choices, not validated with analysts or incidents. Targets come from event fields only (no asset inventory).

## System and operations
15. **No real-world operational deployment.** The system was never run against live traffic or in a SOC.
16. **No authenticated analyst identity.** The analyst name on decisions is free text. There is no authentication or authorisation, and the audit log records claims, not verified identities.
17. **Localhost / internal-only API assumption.** Without authentication, rate limiting or TLS configuration, the API and dashboard must run on localhost or a trusted internal network only.
18. **No streaming ingestion.** Assessments are synchronous batch requests (≤ 1,000 observations); there is no replay or streaming pipeline.
19. **No validated real-time production workload.** Latency was measured only for the quantum adjudicator (about 1 ms per event single-shot, simulated). No throughput or load testing was done.
20. **Source provenance.** Every stored run records commit `c2813d4` with a *dirty* working tree: M3–M7 were produced by uncommitted code. A source fingerprint is recorded in `artifacts/final/reproducibility.json`, but full provenance requires committing and re-running.

## Quantum component
21. **Simulation, not hardware.** All quantum kernels were simulated exactly on a CPU (4–8 qubits). Nothing ran on quantum hardware, fault-tolerant or otherwise.
22. **Noise sensitivity.** Under realistic depolarizing and readout noise, the kernel error reaches 73–74% and balanced accuracy drops from 0.757 to 0.61. Shot noise also makes the Gram matrix indefinite.
23. **No quantum advantage observed.** The entangling ZZ kernel never significantly beat the RBF-SVM and was significantly worse in five cases. As a fused second opinion it was the weakest adjudicator, lowering PR-AUC relative to RF alone. Hyperparameters often sat at the grid edges, and the approved grid was not expanded.
24. **Narrow band design.** The training-derived uncertainty bands covered 3–4× more test traffic than intended (30% vs 10%), reflecting distribution shift.

## Interpretation
25. **Not autonomous cyber defense.** The system produces recommendations for human analysts. It executes no action; every recommendation requires human approval, and approval only records a decision. It must not be described or deployed as an autonomous defense system.
