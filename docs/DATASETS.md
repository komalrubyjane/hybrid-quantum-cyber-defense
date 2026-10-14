# Datasets and external knowledge sources

Datasets are never committed to git. Large datasets are never downloaded without explicit user approval. Every download is recorded in `data/MANIFEST.yaml` (source URL, version, retrieval time, SHA-256, size, license).

| Source | Role | Status | Approx. size | Terms (summary, verify at source) |
|---|---|---|---|---|
| MITRE ATT&CK Enterprise **19.2** (STIX 2.1, official `mitre-attack/attack-stix-data`) | Knowledge base, technique vocabulary | **Downloaded (Milestone 2)**: 53,835,637 bytes, SHA-256 `dc1639ca…c3d8f4` | 53.8 MB | ATT&CK Terms of Use (reproduce © MITRE notice; see `THIRD_PARTY_NOTICES.md`) |
| MITRE Attack Flow corpus (CTID; STIX exports from the official project site; document list at `main@8b6ca28`) | Ordered technique sequences (prediction training and evaluation) | **Downloaded (Milestone 2)**: 41 files, 1,644,316 bytes, per-file SHA-256 in the manifest | 1.6 MB | Apache-2.0 (verified via the GitHub repository license) |
| Unit42 playbooks (`pan-unit42/playbook_viewer`) | Unordered co-occurrence only (never treated as ordered) | Not downloaded (optional, later) | ~40 MB | MIT, © 2018 pan-unit42 |
| CIC-IDS2017 `GeneratedLabelledFlows.zip` (UNB CIC; downloaded manually through the official registration form) | Primary detection dataset | **Registered (Milestone 5)**: 283,876,488 bytes, SHA-256 `7bdbef28…d150ea27a`, 8 CSVs, 2,830,743 flows | 0.28 GB zip / 1.2 GB CSV | Publicly available to researchers; citation required (see `CIC_IDS2017.md`) |
| UNSW-NB15 (UNSW Canberra, official source) | Secondary validation (planned in the analysis) | **Not used**: never downloaded or evaluated | ≈ 100–600 MB depending on files | Academic research use with citation [verify] |
| Synthetic fixtures (`tests/fixtures/synthetic/`) | Development and tests | **Present**, labelled SYNTHETIC | KB | Authored in this repository |

## ATT&CK version
- **Selected:** `ATTACK_VERSION=19.2`.
- **Verified 2026-10-06:** 19.2 is listed in the official index, release modified 2026-08-05. The bundle itself declares `x_mitre_version 19.2`.
- **Policy:** `scripts/fetch_attack.py` refuses unpublished versions and lists the available ones. It never substitutes a version.
- **Recording:** every evaluation run stores `attack_version`. The processed KB stores the version and the RAW SHA-256, and the vocabulary stores both as well.

## Derived artifacts (Milestone 2)
| Artifact | Kind | Size | SHA-256 | Tracked |
|---|---|---|---|---|
| `data/processed/attack/enterprise-attack-19.2.kb.json` | PROCESSED | 2,088,388 B | `5c5c2fe1…432a2ffb` | no |
| `data/processed/attack_flow/sequences.json` | PROCESSED | 71,614,071 B | see manifest | no |
| `models/attack_prediction/vocabulary/technique-vocabulary-attack-19.2.json` | DERIVED | 23,003 B | `7971d411…d85ed2a9` | **yes** |
| `reports/datasets/attack_flow_corpus_summary.json` | DERIVED (report) | ~27 KB | n/a | **yes** |

Rebuild everything with the five commands in `ATTACK_KNOWLEDGE_BASE.md`. The processed KB and vocabulary rebuild byte-identically from the same RAW input.

## Local layout
```
data/
├── README.md          # tracked
├── MANIFEST.yaml      # tracked: source URL, version, retrieval date, SHA-256, license per artifact
├── raw/               # ignored: downloaded originals
├── external/          # ignored: ATT&CK, Attack Flow, Unit42
├── interim/           # ignored
└── processed/         # ignored
```
