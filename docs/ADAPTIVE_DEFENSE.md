# Adaptive defense recommendations (Milestone 7)

Module: `hqc.defense.recommender`, policy `defense-policy-v1`.

**RECOMMENDATION ONLY.** The system produces structured `DefenseRecommendation` objects for a human analyst and executes nothing:
- no shell or subprocess;
- no SSH;
- no firewall, route or IAM changes;
- no account disabling;
- no process killing;
- no agent deployment.

Every recommendation has:
- `requires_human_approval = True`, a schema literal that cannot be set to false;
- `status = PROPOSED`;
- an approval note stating that the system executes nothing.

Each recommendation also carries:
- action type, reason, risk score and level, and a confidence;
- supporting evidence (references to the risk assessment, observed steps, the prediction and the detections);
- affected resource (`target`), priority, disruption and reversibility;
- ATT&CK mitigation IDs of the observed and top-predicted techniques, taken from the KB;
- `generated_at` (`created_at`) and the chain and policy versions.

## Action categories (the seven M1 categories, unchanged)
The M1 contract and its test fix exactly seven categories. The M7 example names map onto them as follows:

| M7 example name | Category used |
|---|---|
| INCREASE_MONITORING | `increase_monitoring` |
| COLLECT_ADDITIONAL_EVIDENCE | `collect_additional_evidence` |
| ESCALATE_TO_SOC_ANALYST | `escalate_severity` |
| RESTRICT_SUSPICIOUS_COMMUNICATION | `restrict_communication` (pending approval) |
| ISOLATE_RESOURCE_PENDING_APPROVAL | `isolate_affected_host` (pending approval) |
| BLOCK_SUSPICIOUS_SOURCE_PENDING_APPROVAL | `block_suspicious_access` (pending approval) |
| REQUIRE_ADDITIONAL_AUTHENTICATION | **not added**: adding an eighth category would change the M1 contract and break its test. Credential risk is covered by `disable_compromised_credentials` (pending approval, CRITICAL only) |

## Policy (deterministic)
| Model-derived risk level | Recommended actions |
|---|---|
| LOW | `increase_monitoring` (continue monitoring) |
| MEDIUM | `collect_additional_evidence`, `increase_monitoring` |
| HIGH | `restrict_communication`, `escalate_severity`, `increase_monitoring` |
| CRITICAL | `isolate_affected_host`, `block_suspicious_access`, `escalate_severity`, `disable_compromised_credentials` |

**Unresolved disagreement** (evidence status `NEEDS ADDITIONAL EVIDENCE` anywhere in the chain):
- `collect_additional_evidence` is always added.
- High-disruption actions (isolate, block, disable credentials) are **withheld**: a CRITICAL chain receives the HIGH plan plus evidence collection.
- A classical/quantum disagreement therefore never escalates the response on its own.

**Targets:**

| Action | Target |
|---|---|
| isolate, restrict, escalate, monitor | Resource of the most recent observed step |
| block | Addresses seen in initial-access (`src_ip`) or exfiltration (`dst_ip`) steps; none means no block recommendation |
| credentials | Accounts on credential-access or lateral-movement steps |
| collect evidence | Resources of the events needing evidence |

**Priority** = risk score × action urgency:

| Action | Urgency |
|---|---|
| monitor | 0.3 |
| collect | 0.5 |
| restrict | 0.7 |
| credentials | 0.75 |
| block | 0.8 |
| isolate | 0.85 |
| escalate | 0.9 |

Recommendations are sorted by priority. **Confidence** = mean observed-step confidence × (1 − uncertainty), a documented heuristic.

## Safety enforcement (`tests/guardrails/test_defense_no_execution.py`, extended in M7)
**Static AST scan of every `hqc.defense` module** (and, since M7, of the pure `hqc.risk` package). It fails on:
- imports of process, shell, network, remote-execution, firewall, account, host or cloud-control modules;
- since M7, imports of `os`, `shutil`, `signal`, `sys`, `asyncio`, `threading`, `concurrent`, `pickle`, `marshal`, `joblib`, `shelve`, `sqlite3`, `tempfile` and `glob`;
- calls to `os.system`/`exec*`/`spawn*`/`kill`, `shutil.rmtree`, `eval`/`exec`/`compile`/`__import__` and, since M7, `open` and `breakpoint`;
- since M7, **string literals that look like admin commands**: iptables/nft/ufw/netsh, usermod/passwd/Disable-ADAccount, taskkill/pkill/kill -9, kubectl/systemctl/shutdown, ip route, sudo, ssh/scp, cloud CLIs, and so on. Docstrings describing the prohibition are allowed.

**Other checks:**
- The scanner is itself tested against violations and safe code, so it cannot pass vacuously.
- `requires_human_approval` is checked to be `Literal[True]`.
- The service exposes only `planned_actions` and `recommend`.
- Unit tests check that disruptive actions are withheld on unresolved disagreement.

## Example (SYNTHETIC scenario, run `20261007T083826Z-integration-synthetic-multistage`)
**Main chain** (76.45 CRITICAL, NEEDS ADDITIONAL EVIDENCE because of e04). Isolation, blocking and credential actions were withheld:

| Priority | Action | Target |
|---|---|---|
| 68.8 | escalate_severity | db-01 |
| 53.5 | restrict_communication | db-01 |
| 38.2 | collect_additional_evidence | web-01 |
| 22.9 | increase_monitoring | db-01 |

**Unit test without the unresolved disagreement:** the same chain at CRITICAL recommends:
- isolate db-01;
- block 203.0.113.50 (initial-access source) and 198.51.100.77 (exfiltration destination);
- reset/disable `svc-backup`;
- escalate.

All of these are pending approval.

## Limitations
- The policy table is an engineering design and has not been evaluated with analysts or on real incidents.
- The urgency values and confidence heuristic are uncalibrated.
- Targets come from event fields only. There is no asset inventory, so internal and external addresses are not distinguished.
