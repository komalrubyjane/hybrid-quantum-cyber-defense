# CIC-IDS2017 (Milestone 5 dataset)

Status: **registered and ingested** (registration and run `20261006T195110Z-classical-detection-cicids2017`).

## What it is (and is not)
- CIC-IDS2017 is a **network intrusion-detection dataset**: labelled bidirectional flows produced by CICFlowMeter from 5 days of lab traffic (3–7 July 2017).
- It is **not** an ATT&CK attack-chain dataset. Its labels (e.g. "DoS Hulk", "PortScan") are attack *scenarios or tools*, **not ATT&CK techniques**. No label is mapped to a technique in this milestone. Any mapping (Milestone 7) needs explicit, documented evidence and will produce *candidate* techniques with confidence.

## Provenance
- **Official source:** UNB Canadian Institute for Cybersecurity, https://www.unb.ca/cic/datasets/ids-2017.html. The download page, `https://cicresearch.ca/CICDataset/CIC-IDS-2017/`, requires a registration form.
- **File used:** `GeneratedLabelledFlows.zip`. It contains 8 per-day CSVs with Flow ID, IPs, ports, protocol, timestamp, 77 flow features and the label. The PCAPs and `MachineLearningCSV.zip` are not used.
- **Retrieval:** downloaded **manually by the user** through the official form (no third-party mirror), placed at `data/raw/cicids2017/GeneratedLabelledFlows.zip`, then registered with `python scripts/register_cicids2017.py`.
- **What registration does:**
  - verifies the archive is a valid zip;
  - extracts only CSV members, rejecting absolute or `..` paths, to `data/external/cicids2017/`;
  - records the source URL, retrieval date (archive modification time), archive SHA-256 and size, plus per-CSV SHA-256 and size, in `data/MANIFEST.yaml` (artifacts `cicids2017-generated-labelled-flows-zip` and `-csv`).
- **Integrity at run time:** every run re-checks each CSV's SHA-256 against the manifest before loading.
- **Git:** raw and extracted data are **git-ignored and never committed**.
- **Citation (required by UNB):** I. Sharafaldin, A. Habibi Lashkari, A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.

## Ingestion (`hqc.detection.dataset`)
- **File order:** recursive discovery, ordered by weekday then file name. The weekday is parsed from the file name.
- **Columns:**
  - names are normalised, e.g. `" Flow Bytes/s"` → `flow_bytes_s`;
  - the header must equal the expected 85-column schema, otherwise `FeatureSchemaMismatchError` is raised. **Nothing is dropped silently.**
  - the duplicated `Fwd Header Length` column becomes `fwd_header_length__dup1`.
- **Encoding:** UTF-8 first, then cp1252, then latin-1. The encoding used is recorded per file.
- **Rows:** fully empty rows and rows without a label are dropped and **counted** per file.
- **Numeric cells:** pandas' C parser handles numbers ("Infinity" becomes ∞). Non-empty unparsable cells become NaN and are **counted as malformed**. NaN and ±∞ are counted per column. Imputation happens later, on training days only.
- **Labels:**
  - `raw_label` is preserved exactly;
  - `label` is normalised (whitespace; the mojibake/dash in "Web Attack – …" becomes "-");
  - `is_malicious = label != "BENIGN"`.

## Measured statistics
**Archive:** `GeneratedLabelledFlows.zip`, 283,876,488 bytes, SHA-256 `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a`. Retrieved (archive modification time) 2026-10-06T19:45:11Z. It contains 8 CSVs, about 1.2 GB unzipped; per-file SHA-256 values are in `data/MANIFEST.yaml`.

| File | Encoding | Rows read | Empty rows dropped | Rows kept |
|---|---|---|---|---|
| Monday-WorkingHours | utf-8 | 529,918 | 0 | 529,918 |
| Tuesday-WorkingHours | utf-8 | 445,909 | 0 | 445,909 |
| Wednesday-workingHours | utf-8 | 692,703 | 0 | 692,703 |
| Thursday-…-Morning-WebAttacks | **cp1252** | 458,968 | **288,602** | 170,366 |
| Thursday-…-Afternoon-Infilteration | utf-8 | 288,602 | 0 | 288,602 |
| Friday-WorkingHours-Morning | utf-8 | 191,033 | 0 | 191,033 |
| Friday-…-Afternoon-PortScan | utf-8 | 286,467 | 0 | 286,467 |
| Friday-…-Afternoon-DDos | utf-8 | 225,745 | 0 | 225,745 |
| **Total** | | | | **2,830,743** |

- **Cell quality:** no rows lacked a label, and there were **no malformed numeric cells**.
- **Non-finite values** occur only in `flow_bytes_s` (NaN and ±∞) and `flow_packets_s` (±∞), for example Wednesday: 1,008 NaN and 289 ∞ in `flow_bytes_s`, 1,297 ∞ in `flow_packets_s`. Per-file counts are in `metrics.json`.
- **Labels** (normalised): BENIGN 2,273,097; DoS Hulk 231,073; PortScan 158,930; DDoS 128,027; DoS GoldenEye 10,293; FTP-Patator 7,938; SSH-Patator 5,897; DoS slowloris 5,796; DoS Slowhttptest 5,499; Bot 1,966; Web Attack – Brute Force 1,507; Web Attack – XSS 652; Infiltration 36; Web Attack – Sql Injection 21; Heartbleed 11. The malicious fraction is 19.7%.
