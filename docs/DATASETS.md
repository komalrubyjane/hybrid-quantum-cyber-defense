# Datasets and external knowledge sources

**Nothing has been downloaded yet.** Datasets are never committed to git, and they are never downloaded automatically: large downloads require explicit user approval.

| Source | Role | Status | Approx. size | Terms (summary, verify at source) |
|---|---|---|---|---|
| MITRE ATT&CK Enterprise (STIX 2.1, official `mitre-attack/attack-stix-data`) | Knowledge base, technique vocabulary | Not downloaded. Version must be **verified** in Milestone 2 | tens of MB | ATT&CK Terms of Use (reproduce © MITRE notice) |
| MITRE Attack Flow corpus (official CTID repository) | Ordered technique sequences (prediction training and evaluation) | Not downloaded (Milestone 2) | small (< 10 MB) | Apache-2.0 [verify] |
| Unit42 playbooks (`pan-unit42/playbook_viewer`) | Unordered co-occurrence only (never treated as ordered) | Optional | ~40 MB | MIT, © 2018 pan-unit42 |
| CIC-IDS2017 (UNB CIC, official source) | Primary detection dataset | **Requires approval** (Milestone 5) | ≈ 1 GB+ (CSVs) | Research use with citation [verify] |
| UNSW-NB15 (UNSW Canberra, official source) | Secondary validation | **Requires approval** (Milestone 10) | ≈ 100–600 MB depending on files | Academic research use with citation [verify] |
| Synthetic fixtures (`tests/fixtures/synthetic/`) | Development and tests | **Present**, labelled SYNTHETIC | KB | Authored in this repository |

## ATT&CK version
- **Planned:** `ATTACK_VERSION=19.2` (user-specified).
- **Verified:** **not yet.** Before the knowledge base is built (Milestone 2), the official release list is checked. If 19.2 isn't available, work **stops** and the discrepancy is reported to the user; the version is never changed silently.
- **Recording:** every evaluation run stores `attack_version` (`EvaluationResult.attack_version`). Processed knowledge-base files will store version, source URL, download date and checksum.

## Local layout (planned)
```
data/
├── README.md          # tracked
├── MANIFEST.yaml      # tracked: source URL, version, retrieval date, SHA-256, license per artifact
├── raw/               # ignored: downloaded originals
├── external/          # ignored: ATT&CK, Attack Flow, Unit42
├── interim/           # ignored
└── processed/         # ignored
```
