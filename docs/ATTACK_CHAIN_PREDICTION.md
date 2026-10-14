# Attack-chain prediction (Milestone 3: baselines)

Status: Milestone 3 baselines **implemented and evaluated** (single step). Milestone 4 adds the LSTM, Markov+LSTM fusion and beam-search multi-step evaluation; see the Milestone 4 section below and `LSTM.md`.

## Problem
Given an observed, ordered prefix of ATT&CK techniques `T1, …, Tn` from one attack-flow path, predict the next technique `T(n+1)`. Every instance has at least one observed technique; the first technique of a sequence is never a target.

**Research question:** how much next-technique predictive information does the ordered MITRE Attack Flow corpus contain *before* adding an LSTM or a quantum component?

## Dataset construction (`hqc.prediction.dataset`)
**Input:**
- The processed Attack Flow corpus (Milestone 2, read-only; the SHA-256 is checked against the manifest).
- The ATT&CK 19.2 KB.
- The committed vocabulary `v1-attack-19.2-f42457f4db96`, used unchanged.

### ID normalisation
This is a separate, logged transformation; the processed corpus is not modified.

| Source ID | Action | Measured on the real corpus |
|---|---|---|
| In the vocabulary (active) | kept | n/a |
| Revoked with an active successor | replaced via the KB `revoked-by` link (`AttackKnowledgeBase.resolve_current`) | **11 IDs, 3,841 occurrences** |
| Unknown / deprecated / no successor | `<UNK>` | **3 IDs** (T0834, T0866, T1533) |

`<UNK>` may appear in a prefix. It is never a target and never an output. Instances whose target is `<UNK>` are dropped and counted: **6,155 dropped targets**.

### Instances, deduplication and weighting
- **Instances:** for each sequence and each position `i ≥ 1`, one instance is (prefix `t1..ti`, target `t(i+1)`). Order and repeats are preserved.
- **Deduplication** applies to evaluation-instance construction only. Instances with the same (document, full prefix, target) collapse into one unique instance with a raw `multiplicity`. Different documents, prefixes or targets are never merged.
  - Measured: **327,034 raw instances → 43,179 unique**, with 283,855 collapsed (**86.8%**).
- **Training weighting:**
  - **document (primary):** weight = multiplicity / raw instances of the document, so every document has total weight 1. The measured total is 38.0, i.e. 40 included documents minus the 2 OpenClaw documents that yield no instances.
  - **raw (ablation A):** weight = multiplicity (raw path counts). Total 327,034.
  - **unique (ablation B):** weight 1 per distinct (prefix, target) transition per document. Total 43,179.
- **Evaluation weighting:** every unique instance counts once, independent of the training weighting.

### Corpus skew (measured)
The two Turla emulation plans produce **60.3% and 28.7% of raw instances** respectively. Cobalt Kitty contributes 4.8% and SolarWinds 4.1%. The dataset is **not balanced**. The group `OpenClaw Command & Control via Prompt Injection` has **no instances**: its sequences contain a single ATT&CK technique, because most of its actions are MITRE ATLAS IDs.

## Models (`hqc.prediction.baselines`, `hqc.prediction.markov`)
All models output a distribution over exactly the **697 active techniques** (`OutputSpace`; no `<PAD>` or `<UNK>`). Every distribution passes through one `normalize()` routine. Ranking ties are broken by vocabulary-index order. There is no randomness.

| ID | Model | Formula (`s` = mean training weight per instance, `u = 1/697`) |
|---|---|---|
| B0 | Uniform | `P(t) = u` |
| B1 | Frequency (order 0) | `P0(t) = (U(t) + β·s·u) / (N + β·s)`, where `U` is the weighted target counts |
| M1 | First-order Markov | `P1(t \| c1) = (C(c1,t) + α·s·P0(t)) / (C(c1) + α·s)` |
| M2 | Variable-order Markov (K = 2 or 3) | `Pk(t \| ck) = (C(ck,t) + α·s·P(k-1)(t)) / (C(ck) + α·s)`, and `P = Σk wk·Pk` with `Σ wk = 1` |

**Smoothing and fallback:**
- Every level is a convex combination of the level below and observed counts, so no technique ever gets zero probability.
- If a context `ck` was never seen, or the prefix is shorter than `k`, then `Pk = P(k-1)`.
- The fallback order is therefore: longest seen context → shorter context → frequency → uniform.
- `α` and `β` are in *pseudo-instances* (scaled by `s`), so the same grid is meaningful under every weighting. A unit test confirms that scaling all weights leaves predictions unchanged.
- `<UNK>` is an ordinary context token.

**Persistence:** models are saved as JSON with a model card under `models/generated/attack_prediction/<run-id>/` (git-ignored).

## Measured results — run `20261006T173740Z-markov-baselines-document`
Primary weighting = document. Macro = mean over the **36 groups with instances**, shown as [95% bootstrap CI over groups]. Copied from `reports/runs/<run-id>/summary.md`; the run folder is git-ignored but reproducible.

| Model | top-1 | top-3 | top-5 | MRR | log loss | next-tactic |
|---|---|---|---|---|---|---|
| B0 | 0.0046 [0.0000, 0.0139] | 0.0086 [0.0000, 0.0218] | 0.0102 [0.0005, 0.0235] | 0.0166 [0.0097, 0.0272] | 6.5468 | 0.1526 [0.1104, 0.1963] |
| B1 | **0.0736** [0.0435, 0.1070] | 0.1135 [0.0724, 0.1593] | 0.1325 [0.0890, 0.1797] | **0.1205** [0.0879, 0.1556] | **5.7239** [5.4802, 5.9630] | 0.1526 [0.1104, 0.1963] |
| M1 | 0.0498 [0.0288, 0.0733] | 0.1181 [0.0805, 0.1575] | **0.1380** [0.0965, 0.1820] | 0.1091 [0.0831, 0.1365] | 5.8526 [5.5894, 6.1123] | 0.1551 [0.1201, 0.1909] |
| M2 | 0.0521 [0.0300, 0.0765] | **0.1189** [0.0806, 0.1594] | 0.1368 [0.0949, 0.1811] | 0.1110 [0.0843, 0.1389] | 6.2348 [5.8516, 6.6215] | **0.1563** [0.1207, 0.1922] |

### Interpretation (measured, not extrapolated)
- **B1 > B0 on every metric** (paired 95% CIs exclude 0). The corpus carries a strong *marginal* signal: some techniques are far more common than others.
- **Sequence context did not help in this evaluation.** Against B1:
  - M1 and M2 are **worse on top-1** (M2 − B1 = −0.0215 [−0.0399, −0.0061]) and **worse on log loss** (M2 − B1 = +0.51 [+0.35, +0.68]).
  - The **top-5 and MRR differences are statistically unclear** (CIs include 0).
  - **M2 vs M1:** no clear difference on ranking metrics; M2 has worse log loss.
- **Ablations agree.** Under raw and unique weighting, B1 again leads on top-1 and MRR, and M1/M2 are never clearly better.
- **Per group (top-1, M2 vs B1):** M2 better in 4 groups, B1 better in 10, tied in 22. In 14 of 36 groups, both have top-1 = 0. M2 has lower log loss than B1 in only 4 of 36 groups.
- **B1 always predicts the same technique.** Its top-1 is T1105 (Ingress Tool Transfer) for every instance. B0's deterministic top-1 is always T1001, because of ID-order tie-breaking. Both are Command and Control (TA0011) techniques, which is why their tactic accuracy is identical.
- **Hyperparameters hit the grid boundary in every fold** (all 36 folds, all weightings): maximum smoothing (`α` = 1000; `β` = 10000 for B1/M1, 1000 for M2). M2 always chose K = 2, w = (0.9, 0.1). Log-loss tuning pushes toward ignoring context and flattening predictions, and the **reported B1/M1/M2 log losses are therefore not at an interior optimum.** Widening the grid again *after* seeing outer results would be result-informed tuning, so it was not done. See limitation 1.

## Milestone 4 summary (details in `LSTM.md`)
Run `20261006T181005Z-lstm-hybrid-beam-document` uses the same 36 groups and instances, and reproduces the baselines exactly.

| Model | top-1 | top-5 | MRR | log loss |
|---|---|---|---|---|
| B1 | **0.0736** | 0.1325 | 0.1205 | **5.7239** |
| M1 / MARKOV | 0.0498 | 0.1380 | 0.1091 | 5.8526 |
| LSTM | 0.0711 | **0.1621** | **0.1218** | 5.8963 |
| HYBRID | 0.0573 | 0.1560 | 0.1149 | 5.7355 |

**Findings:**
- **LSTM vs B1:** the LSTM improves top-5 over B1 (+0.030, CI excludes 0). It is unclear on top-1 and MRR, and worse on log loss.
- **LSTM top-1 collapses to the marginal:** it ranks T1105 first for 99.9% of instances.
- **Fusion vs B1:** fusion improves log loss over both components but does not beat B1.
- **Multi-step:** beam-search accuracy is very low for all models, and no model beats B1.

## Limitations
1. **Smoothing-grid boundary (accepted limitation).** "The Markov hyperparameter tuner selected the maximum available smoothing in every fold. The baseline experiment therefore suggests that contextual information was not useful under the tested grid, but the smoothing grid boundary prevents treating the selected value as a fully optimized interior solution." No expanded-grid experiment was run (decision recorded at the start of Milestone 4), and the Milestone 3 run is kept unchanged.
2. **Small, skewed data.** There are 36 evaluable groups. Turla dominates the raw counts, and per-group results range from 7 to 17,948 instances.
3. **Cross-document generalisation only.** Leave-one-group-out tests prediction for an *unseen* campaign or incident. Within-document repetition is deliberately not rewarded.
4. **The Attack Flow path view.** Branches are enumerated as separate sequences, and skipped non-technique or ATLAS actions (`gap_before`) are not modelled.
5. **Single step only.** Multi-step metrics are NOT EVALUATED.
6. **Tie-break artefact for B0.** Deterministic top-k for B0 reflects technique-ID order. Tie-aware variants are reported in `metrics.json` (e.g. B0 tie-aware top-1 = 1/697).
