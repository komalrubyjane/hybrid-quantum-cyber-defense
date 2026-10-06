# Synthetic fixtures

**SYNTHETIC DATA. These files are hand-authored for development and tests.**

- No file here comes from real traffic. Results computed on these fixtures must never be reported as real-world results.
- Addresses use the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Hostnames use the reserved `.test` TLD.
- Every event carries `"data_origin": "SYNTHETIC"`.
- `expected_chain` labels are illustrative ATT&CK technique IDs. Until the knowledge base exists (Milestone 2), they are checked only for **format**, not for existence in a specific ATT&CK version (`technique_labels_validated_against_kb: false`).

| File | Purpose |
|---|---|
| `scenario_basic.json` | A 5-stage ordered scenario: Initial Access → Execution → Credential Access → Lateral Movement → Exfiltration |

Fixtures are loaded in tests through `tests/conftest.py`.
