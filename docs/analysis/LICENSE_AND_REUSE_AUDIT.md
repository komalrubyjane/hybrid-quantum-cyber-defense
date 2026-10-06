# License and Reuse Audit

**Date:** 2026-10-06. **Method:** We inspected each repository's files (`LICENSE`, README license sections, headers) at the commits listed in `REPOSITORY_ANALYSIS.md`. Statements about third-party datasets and corpora that we could **not** verify from local files are marked **[verify upstream]**. They reflect our understanding of the published terms and must be confirmed against the official source before we redistribute anything.

> This audit is an engineering assessment, not legal advice. If the project will be published commercially or as a product, have the conclusions confirmed by your institution's research office or counsel.

## Summary

| Repo | LICENSE file | License | Code reuse decision |
|---|---|---|---|
| R1 MITRE-ATTACK-based-Attack-Chain-Prediction | **No** (the vendored `playbook_viewer-master-2/LICENSE` is Unit42's, not R1's) | README: "License status is **pending institutional review**… please contact the corresponding author before using, redistributing, or building on this code." Produced under DoD Cooperative Agreement W911NF-22-2-0160 | **REFERENCE ONLY — LICENSE/REUSE STATUS REQUIRES VERIFICATION** |
| R2 cyber-risk-intelligence-platform | Yes | MIT, "Copyright (c) 2024 Cyber Risk Intelligence Platform" | **Reusable with attribution** |
| R3 Hybrid-Network-Intrusion-Detection-ML-QML | Yes | MIT, "Copyright (c) 2026 Sifat Bhatia" | **Reusable with attribution** |
| R4 PI-VQC-IntrusionDetection | **No** | None stated. By default no reuse rights are granted (all rights reserved) | **REFERENCE ONLY — LICENSE/REUSE STATUS REQUIRES VERIFICATION** |
| R5 Cyberattack-Prediction-and-Adaptive-Cyber-Defense | **No** | None stated (all rights reserved by default) | **REFERENCE ONLY — LICENSE/REUSE STATUS REQUIRES VERIFICATION** |

## Per-repository detail

### R1 — MITRE-ATTACK-based-Attack-Chain-Prediction
- **Status:** **REFERENCE ONLY — LICENSE/REUSE STATUS REQUIRES VERIFICATION**
- **Evidence:** There is no top-level LICENSE. The README section "License and release terms" says the license is pending institutional review (UMass Dartmouth ORA, USMA) and asks users to contact the author before using or building on the code. The README badge reads "license-see below".
- **Attribution:** If we cite the method, we cite the paper: Raj, Kul, Bastian, Fiondella, *MITRE ATT&CK-based Attack Chain Prediction using Hybrid LSTM-Markov Models for Cyber Risk Assessment*, SECRYPT 2026. The README is inconsistent on whether the paper is accepted or under review, so verify the final citation.
- **What we may do:**
  - Read the code to understand the design.
  - Cite the paper.
  - Independently implement **standard, published algorithms** that the paper also uses: first-order Markov chains, LSTM next-token prediction, beam search, geometric-mean aggregation, DFS over a graph. Implementing these ourselves is not copying R1.
- **What we may not do (until a license is posted or written permission is obtained):**
  - Copy, translate or paraphrase R1's code line by line.
  - Copy its configuration constants as a package.
  - Copy its README text.
  - Use `MITRE_Campaign_Severity_Scores.csv`. It is R1-authored and unlicensed, and its provenance is undocumented.
- **Bundled third-party content inside R1.** Its license is governed by the original owners, not by R1. Obtain all of it from upstream rather than from R1's copy:

| Content in R1 | Owner / upstream | License | Use |
|---|---|---|---|
| `playbook_viewer-master-2/` (code + 85 `playbook_json` bundles) | Palo Alto Networks Unit 42, github.com/pan-unit42/playbook_viewer | MIT, "Copyright (c) 2018 pan-unit42" (LICENSE file present locally) | Reusable with the MIT notice. Download from upstream; pin the commit |
| `Attack flows/*.json` (39 files) | MITRE Center for Threat-Informed Defense (identity objects name "MITRE Center for Threat-Informed Defense" plus individual authors), Attack Flow project | Apache-2.0 for the CTID attack-flow repository **[verify upstream]** | Reusable with the Apache-2.0 NOTICE. Download from upstream; pin the version |
| `enterprise-attack-v16.0.xls` | The MITRE Corporation, ATT&CK | ATT&CK Terms of Use: royalty-free license to use, reproduce and make derivatives, provided MITRE's copyright designation and license are reproduced **[verify upstream]** | Use the official ATT&CK **STIX 2.1 JSON** (mitre-attack/attack-stix-data) instead of R1's re-saved `.xls` (whose metadata shows "Last Saved By: Mayank Raj") |

### R2 — cyber-risk-intelligence-platform
- **License:** MIT. LICENSE file present; the README states MIT.
- **Attribution requirement:** Include the copyright notice "Copyright (c) 2024 Cyber Risk Intelligence Platform" and the MIT permission text in every copy or substantial portion. We will keep a `THIRD_PARTY_NOTICES.md` and add a header comment in any file that contains adapted code.
- **Reuse:** Permitted. **Planned use is limited:** the module decomposition, the endpoint naming, the weighted entity-risk formula pattern, the privacy rule definitions and the rule-table advisor pattern. Most code will be rewritten because of the defects listed in the analysis: the unreachable privilege rule, chain re-sorting, and the `StaticFiles(".")` exposure.
- **Dashboard assets:** `index.html` loads Three.js and GSAP from cdnjs (MIT-licensed libraries) and the devicon SVGs (MIT) from jsDelivr, plus Google Fonts (OFL/Apache). We do not plan to reuse it.
- **Data:** `sample_events.json` is synthetic and covered by the same MIT license. It is usable as a test fixture with attribution.

### R3 — Hybrid-Network-Intrusion-Detection-ML-QML
- **License:** MIT, "Copyright (c) 2026 Sifat Bhatia". LICENSE file present.
- **Attribution requirement:** Keep the copyright and permission notice in adapted portions.
- **Reuse:** Permitted. The notebook code is mostly short library calls (pandas cleaning, scikit-learn, Qiskit QSVC wiring). We will re-implement it as modules and credit R3 for the workflow in `THIRD_PARTY_NOTICES.md`.
- **Workflow diagram PNG:** Covered by MIT. We do not plan to reuse it.

### R4 — PI-VQC-IntrusionDetection
- **Status:** **REFERENCE ONLY — LICENSE/REUSE STATUS REQUIRES VERIFICATION**
- **Evidence:** No LICENSE file and no license statement in the README. The notebook names the author (Vince Aivan Rumalay, 2026) and includes an AI-assistance disclaimer.
- **What we may do:**
  - Implement our own Ising-inspired (ZZ + transverse-field) ansatz. This is a standard construction in the literature: QAOA-style and TFIM Trotter circuits.
  - Implement our own Aer noise models.
  - Cite the notebook as related work.
- **Do not:**
  - Copy notebook cells or text.
  - Reproduce its `param_shift_grad`. Besides the license issue, it is **mathematically wrong** for `R(2θ)` parameterisations (see the analysis).

### R5 — Cyberattack-Prediction-and-Adaptive-Cyber-Defense
- **Status:** **REFERENCE ONLY — LICENSE/REUSE STATUS REQUIRES VERIFICATION**
- **Evidence:** No LICENSE file. The README is two lines.
- **What we may do:** Independently implement the standard techniques it uses. These come from the literature, and we will cite the original papers:
  - MC-Dropout (Gal & Ghahramani 2016)
  - Temperature scaling (Guo et al. 2017)
  - Integrated Gradients (Sundararajan et al. 2017)
  - EWC (Kirkpatrick et al. 2017)
  - GhostNet (Han et al. 2020)
  - ECA (Wang et al. 2020)
  - KS-test drift detection
  - TCN (Bai et al. 2018)
- **Do not:** Copy its classes or orchestration code.

## Datasets and knowledge sources: separate licenses

| Source | Used by | License / terms (summary) | Redistribution plan |
|---|---|---|---|
| CIC-IDS2017 (UNB Canadian Institute for Cybersecurity) | R3 (via Kaggle mirror "chethuhn/network-intrusion-dataset"), R1 label map | Free for research. Use requires citing Sharafaldin, Lashkari & Ghorbani, ICISSP 2018 **[verify upstream terms on unb.ca/cic]** | **Do not commit** the data. Use a download script from the official UNB source plus a SHA-256 manifest. Mirrors may carry different terms, so prefer the official source |
| UNSW-NB15 (UNSW Canberra, Moustafa & Slay 2015) | R4 (Kaggle mirror "mrwellsdavid/unsw-nb15") | Free for academic research. Commercial use requires contacting the authors. Citation required **[verify upstream]** | Do not commit. Download script plus checksum |
| MITRE ATT&CK Enterprise (STIX 2.1) | R1 | ATT&CK Terms of Use; reproduce the © MITRE notice **[verify upstream]** | Downloaded and version-pinned. The notice goes in `THIRD_PARTY_NOTICES.md` |
| MITRE Attack Flow corpus | R1 | Apache-2.0 **[verify upstream]** | Downloaded and version-pinned, with NOTICE |
| Unit42 Playbook Viewer bundles | R1 | MIT, © 2018 pan-unit42 (verified locally) | Downloaded and commit-pinned, with MIT notice |
| MITRE D3FEND (optional, later) | R1 (mentioned only) | MITRE terms of use **[verify upstream]** | Optional |
| FIRST EPSS, CISA KEV, MITRE CAPEC (optional, later) | R1 (mentioned only) | EPSS: free with attribution. KEV: U.S. government publication. CAPEC: MITRE terms **[verify upstream]** | Optional. Note that EPSS and KEV are **CVE-level**, so mapping them to ATT&CK techniques needs its own documented mapping |
| ACI-IoT-2023 (Army Cyber Institute) | R1 (mentioned only) | **[verify upstream]** | Not planned for the MVP |
| `MITRE_Campaign_Severity_Scores.csv` | R1 | Unlicensed, provenance undocumented | **Do not use** |
| R2 `sample_events.json` | R2 | MIT | Allowed as a test fixture with attribution |

## Reuse rules for the implementation phase

1. **No code is copied from R1, R4 or R5.** Implementations of shared standard algorithms are written from the original papers and our own design documents. This is reflected in the commit history and in design docs that predate the code.
2. **Code adapted from R2 or R3** gets a header comment naming the source repo, commit and MIT notice, plus an entry in `THIRD_PARTY_NOTICES.md`.
3. **No dataset is committed to git.** `data/` is git-ignored. `scripts/download_*.py` fetches from official sources, and `data/MANIFEST.yaml` records source URL, version, retrieval date, SHA-256 and license.
4. **Knowledge bases are version-pinned:** ATT&CK version, Attack Flow release and Unit42 commit. We record the © notices.
5. **Before publication** (paper or code release), re-run this audit. If R1's authors publish a license, we can re-evaluate it as a reference implementation for direct comparison.
6. **Required action for the user:** confirm whether you intend to contact the R1, R4 and R5 authors for permission. The project plan does **not** depend on it.
