# ATT&CK knowledge base, Attack Flow corpus and technique vocabulary

Status: **implemented (Milestone 2)**. Nothing here involves ML. The `hqc.mitre` package depends only on the standard library, Pydantic and the project's common modules.

## Observed source data vs derived data

| Layer | What it is | Where | In git? |
|---|---|---|---|
| **OBSERVED SOURCE DATA (RAW)** | Official files byte-for-byte as downloaded | `data/external/attack/`, `data/external/attack_flow/stix/` | No (ignored); checksums in `data/MANIFEST.yaml` |
| **DERIVED / NORMALISED (PROCESSED)** | Deterministic transformations of RAW data | `data/processed/attack/*.kb.json`, `data/processed/attack_flow/sequences.json` | No (ignored; rebuildable), checksums in manifest |
| **DERIVED (modelling artifact)** | Technique vocabulary | `models/attack_prediction/vocabulary/technique-vocabulary-attack-19.2.json` | **Yes** (23 KB) |
| **DERIVED (report)** | Corpus summary statistics | `reports/datasets/attack_flow_corpus_summary.json` | **Yes** (27 KB) |

## Selected ATT&CK version: **19.2**

The version was checked on 2026-10-06 against MITRE's official index (`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json`):
- **19.2 is published** and is the latest Enterprise release.
- The next versions down are 19.1 and 19.0.
- The release was modified on `2026-08-05T21:33:58.496Z`, and the bundle declares `x_mitre_version = 19.2` with ATT&CK spec 3.3.0.

**No version substitution happened.** `scripts/fetch_attack.py` refuses any version that isn't in the official index and lists the available ones instead.

### Notable 19.x changes reflected in the data
- There are **15 tactics**. TA0005 is now named **"Stealth"**, and a new tactic, **TA0112 "Defense Impairment"**, was added.
- Several techniques were revoked in favour of new IDs, for example T1562 → T1685 and T1562.001 → T1685.
- **Data sources are deprecated** (all 38 `x-mitre-data-source` objects). Detection coverage is expressed as *detection strategies* (`DET####`), whose analytics reference *data components* (`DC####`). The KB records both per technique, instead of the legacy data-source list.

## Ingestion pipeline

```bash
python scripts/fetch_attack.py            # verify version in official index, download, record SHA-256
python scripts/build_attack_kb.py         # RAW -> PROCESSED KB (checks RAW checksum first)
python scripts/fetch_attack_flow.py       # official Attack Flow STIX corpus, per-file SHA-256
python scripts/build_attack_flow_corpus.py  # ordered sequences + summary report
python scripts/build_vocabulary.py        # versioned vocabulary (tracked)
```

Downloads go through `hqc.common.download`, which enforces three things:
- **An allowlist of official URL prefixes:** MITRE `attack-stix-data` and the CTID `attack-flow` repository, API and site. The CIC-IDS2017 and UNSW-NB15 hosts are deliberately not on it.
- **Certificate-verified TLS** using the certifi CA bundle.
- **Atomic writes.**

## Normalised KB representation (`hqc.mitre.models.KnowledgeBaseData`)

| Field | Content |
|---|---|
| `metadata` | KB format version, ATT&CK version and spec version, collection name and modified date, source URL and SHA-256, counts, and intentionally skipped objects by reason |
| `tactics` | `ATTACKTactic`: ID, name, shortname, matrix order |
| `techniques` | `ATTACKTechnique`: ID, name, tactic IDs, sub-technique flag and parent, description, platforms, mitigation IDs, detection strategy IDs, data component IDs, deprecated/revoked/revoked_by, STIX ID, URL |
| `mitigations` | `ATTACKMitigation`: `M####`, name, description, techniques |
| `data_components` | `ATTACKDataComponent`: `DC####`, name |
| `relationships` | `subtechnique-of`, `mitigates`, `revoked-by`, expressed with ATT&CK IDs |

### Normalisation rules
1. Techniques are keyed by their **ATT&CK ID**. Names are display metadata only.
2. Revoked and deprecated techniques are kept but flagged, so old IDs can be explained and resolved (`resolve_current`).
3. The 224 legacy `course-of-action` objects with `T`-style IDs (all deprecated) are skipped and counted.
4. Revoked or deprecated relationships are ignored.
5. Errors fail loudly:
   - An active technique with an unknown tactic, or an active sub-technique without a parent link, raises an error.
   - Duplicate IDs, malformed IDs, or a version mismatch raise an error.
   - Only *inactive* sub-techniques may take their parent from the ID structure (16 cases, counted).
6. **Determinism:** the output contains no timestamps, keys are sorted, and the catalog is ordered by ID. Rebuilding from the same RAW file is byte-identical, which is verified by test and by hand.

### Measured contents of ATT&CK 19.2 (from `metadata.counts`)
| Item | Count |
|---|---|
| Tactics | 15 |
| Techniques (all objects) | 858 |
| Active techniques | **697** (222 parents + 475 sub-techniques) |
| Revoked / deprecated techniques | 149 / 12 |
| Mitigations (`M####`) | 44 |
| Data components (active) | 106 |
| Relationships retained | 2,074 |

## Knowledge base API (`hqc.mitre.AttackKnowledgeBase`)

```python
kb = AttackKnowledgeBase.load(settings)          # loads data/processed/attack/enterprise-attack-<v>.kb.json
kb.version()                                     # KBMetadata (version, source SHA-256, counts)
kb.get_technique("T1059.004")                    # ATTACKTechnique
kb.get_techniques(include_revoked=False, include_deprecated=False)
kb.get_subtechniques("T1059")                    # active subs only
kb.get_mitigations("T1059.004")                  # [ATTACKMitigation]
kb.get_tactics("T1003")                          # [ATTACKTactic] in matrix order
kb.get_data_components("T1003")                  # [ATTACKDataComponent]
kb.resolve_current("T1562")                      # follows revoked-by (a DERIVED mapping)
```

| Error | When |
|---|---|
| `InvalidTechniqueIdError` | The string isn't of the form `Txxxx` or `Txxxx.yyy` |
| `UnknownTechniqueError` (subclass of the above) | The ID is well-formed but absent from the loaded version |
| `UnsupportedAttackVersionError` | No processed KB exists for the configured version, or the file contains a different version |
| `MalformedSourceDataError` | The STIX, KB file or manifest is structurally invalid |
| `MissingRequiredFieldError` | A required field is missing in the source data |

## Attack Flow corpus

**Source:** MITRE Center for Threat-Informed Defense, `center-for-threat-informed-defense/attack-flow`, licensed **Apache-2.0**.
- The document list is `corpus/*.afb` at `main` commit `8b6ca28bc13beb871f3a4c5fa029b96c6394f874` (2026-09-24).
- The STIX 2.1 exports come from the official project site, `https://center-for-threat-informed-defense.github.io/attack-flow/corpus/<name>.json`, which is built from `main`.

**Why not the v3.2.0 tag?** The tag ships only `.afb` files, the builder's internal format. Every corpus file was also modified after v3.2.0, and one flow was added. We use STIX, the documented interchange format, and record the upstream commit plus each file's SHA-256. The trade-off is that the site isn't version-pinned: re-downloading later may give different bytes, which the checksums will detect.

### How ordering is extracted (`hqc.mitre.attack_flow`)
- Ordering comes **only** from the encoded graph:
  - `start_refs`
  - `attack-action.effect_refs`
  - `attack-operator.effect_refs`
  - `attack-condition.on_true_refs`, then `on_false_refs`
- Each maximal path from a start node is one sequence. Branches are visited **in the order their references appear in the source**.
- Never applied:
  - **No sorting** by ID or name.
  - **No chronology from co-occurrence.** Predecessors joined by an AND operator produce separate paths and are never chained to each other.
  - **No ordering from object position.**
- `execution_start` timestamps (present on 46 actions) are stored as source metadata. They aren't used for ordering, and they aren't converted to `AttackStep.timestamp`.
- **Actions without a technique (62) or with non-ATT&CK techniques (36, MITRE ATLAS `AML.*`)** remain in `action_ids`, but produce no step. The number skipped immediately before each step is kept as `gap_before`.
- **Cycles** (2 documents): a path stops before revisiting a node and is flagged `cycle_truncated` (5 paths).
- **Unreachable actions** (3) are counted and not sequenced. Dangling references are rejected as malformed; there are none in the corpus.
- **Duplicates** of the same technique within a path are preserved.
- **Exclusion policy:** scope `attack-tree` is excluded by default. This affects only "Example Attack Tree", a tutorial flow.
- **Leakage grouping:** `source_group` is derived from the **flow name** with a trailing parenthetical variant label stripped. This groups the three CISA AA22-138B variants and the two OpenClaw documents (`OpenClaw.json` and `OpenClaw Command & Control via Prompt Injection.json`). Splits in Milestone 3 must use `source_group`.

### Output and provenance
Each `FlowSequence` retains:
- `sequence_id`, `document_id`, `source_group`
- `source_file`, `source_sha256`, `source_version` (`main@8b6ca28bc13b`)
- `flow_id` (STIX), `flow_name`, `scope`
- `path_index`, ordered `action_ids`
- steps (`position`, `action_id`, `technique_id`, `tactic_id`, `gap_before`)
- `cycle_truncated`, `parser_version`

`FlowSequence.to_attack_chain(attack_version)` produces the shared `AttackChain`. Each step has provenance **`DOCUMENTED`** (a new enum value: explicitly encoded in curated CTI, not an observed security event), confidence 1.0, no timestamp, and the evidence strings above.

### Measured corpus statistics (`reports/datasets/attack_flow_corpus_summary.json`)
| Item | Value |
|---|---|
| Documents downloaded / included | 41 / 40 (Example Attack Tree excluded) |
| Source groups (for splitting) | 37 |
| Ordered sequences (paths) | 7,432 |
| Unique ATT&CK technique IDs | 236 |
| …active in 19.2 / revoked / unknown | 222 / 11 / 3 |
| Sequence length (techniques) | min 1, median 62, mean 45.8, max 69 |

**Important skew:** four documents contribute 6,836 of the 7,432 paths (92%): Turla Carbon 3,072, Turla Snake 1,540, Cobalt Kitty 1,440 and SolarWinds 784. Branch enumeration multiplies heavily-branched flows, and 5 documents yield a single path. Milestone 3 evaluation must therefore report per-document or per-group results, consider per-document weighting, and split strictly by `source_group`.

**Technique IDs that need attention.** The processed corpus keeps them exactly as written; no silent remapping is done.
- **Revoked in 19.2 (11):**
  - T1063 → T1518.001
  - T1070.001 → T1685.005
  - T1070.002 → T1685.006
  - T1076 → T1021.001
  - T1183 → T1546.012
  - T1562 → T1685
  - T1562.001 → T1685
  - T1562.002 → T1685.001
  - T1562.004 → T1686
  - T1562.009 → T1688
  - T1574.002 → T1574.001
- **Unknown to the Enterprise 19.2 KB (3):** T0834 and T0866 (ICS-domain IDs), and T1533 (not present in the 19.2 bundle).
- How these are mapped (remap revoked IDs via `revoked-by`, map unknown IDs to `<UNK>`) is an explicit, recorded Milestone 3 decision.

## Technique vocabulary

File: `models/attack_prediction/vocabulary/technique-vocabulary-attack-19.2.json`. Version **`v1-attack-19.2-f42457f4db96`**, 699 tokens.

```json
{
  "format_version": "1",
  "vocabulary_version": "v1-attack-19.2-<sha256[:12]>",
  "attack_version": "19.2",
  "attack_kb_source_sha256": "<RAW bundle SHA-256>",
  "scope": "attack-enterprise-active-techniques",
  "special_tokens": {"<PAD>": 0, "<UNK>": 1},
  "index_to_token": ["<PAD>", "<UNK>", "T1001", "T1001.001", "..."],
  "token_to_index": {"<PAD>": 0, "<UNK>": 1, "T1001": 2, "...": 0},
  "content_sha256": "<sha256 of the ordered token list>"
}
```

- **Contents:** `<PAD>` (padding for batched sequence models), `<UNK>` (anything outside the vocabulary), then all **697 active** Enterprise techniques and sub-techniques. There are no name tokens. `<BOS>`/`<EOS>` are not included; if Milestone 3 or 4 genuinely needs them, the vocabulary version will be bumped.
- **Determinism:** technique tokens are sorted by ID to assign stable indices. This is a catalog order, not a chronology. The same KB always gives the same mapping: the version string embeds the content hash, and loading rejects any file whose mappings, hash, order or special tokens disagree.
- **Leakage-safe:** the vocabulary is built from the KB, not from the Attack Flow corpus, so it doesn't depend on which documents are training or test.

## Known limitations
1. **The Attack Flow STIX source is not version-pinned.** It is reproducible through recorded checksums and locally kept raw files, not by re-download.
2. **Path enumeration over-weights branchy documents** (see the skew above). The maximal-path view also treats each branch as an independent sequence.
3. **Non-technique and ATLAS actions are skipped,** with `gap_before` recorded, so "adjacent" techniques in a sequence may have unmodelled steps between them.
4. **Revoked and unknown IDs are not yet remapped.** That is deferred to Milestone 3 as an explicit, logged step.
5. **The processed corpus file is 72 MB,** because every path keeps its full ordered action-ID provenance. It is git-ignored and rebuilds in about 2 s.
6. **Scope is the Enterprise domain only.** ICS and Mobile technique IDs in flows are reported as unknown.
7. **`source_group` is name-based.** Unrelated reports about the same malware family (e.g. the three Conti documents) remain separate groups, which is documented here so evaluation can decide.
