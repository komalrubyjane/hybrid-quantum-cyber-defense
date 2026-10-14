# Third-party notices

This repository contains no third-party source code. It includes small derived artifacts (technique vocabulary, corpus summary) containing identifiers from the sources below, and its scripts download those sources locally.

## MITRE ATT&CK®
Used for: the knowledge base (downloaded, not committed), technique IDs in `models/attack_prediction/vocabulary/` and in `reports/datasets/`.

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

License (from `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/LICENSE.txt`): The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy. ATT&CK® is a registered trademark of The MITRE Corporation. See the full license text, including its disclaimers, at the URL above.

## MITRE Attack Flow (Center for Threat-Informed Defense)
Used for: the ordered sequence corpus (downloaded, not committed), document names and per-document statistics in `reports/datasets/attack_flow_corpus_summary.json`.

Source: https://github.com/center-for-threat-informed-defense/attack-flow, licensed under the **Apache License 2.0** (https://www.apache.org/licenses/LICENSE-2.0). Copyright the respective Attack Flow contributors / The MITRE Corporation.

## CIC-IDS2017 (UNB Canadian Institute for Cybersecurity)
Used for: detection experiments (Milestones 5–6). The data is downloaded manually through the official registration form and is never committed. Citation: I. Sharafaldin, A. Habibi Lashkari, A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.

## Qiskit and Qiskit Aer (installed dependencies, not vendored)
Used for: reference feature-map circuits, `Statevector` validation and the Aer noise study (Milestone 6). `qiskit==2.5.2` and `qiskit-aer==0.17.2` are licensed under the **Apache License 2.0** (https://www.apache.org/licenses/LICENSE-2.0). Copyright IBM and the Qiskit contributors. No Qiskit source code is copied into this repository. The batched NumPy feature-map implementation is our own, validated against Qiskit's output.

## Reference repositories
No code from the five analysed reference repositories is included (see `docs/analysis/LICENSE_AND_REUSE_AUDIT.md`).
