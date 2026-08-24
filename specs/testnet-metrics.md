# SPEC-TEST-001: Testnet Success Metrics and Failure Thresholds

**Status**: Normative  
**Version**: 0.1  
**Date**: 2026-04-09

---

## 1. Scope

This document defines the measurable success criteria and explicit failure thresholds for each PQ Chain testnet phase. It is the authoritative reference for deciding whether a phase is complete and whether advancing to the next phase is permitted.

Three testnet phases are defined:

| Phase | Label | Validator count | Audience |
|-------|-------|----------------|----------|
| Phase 2 | Devnet | 24 (all operator-controlled) | internal only |
| Phase 3-alpha | Controlled testnet | 32 (allowlisted external operators) | invited participants |
| Phase 3-public | Public testnet | up to 50 | open |

A phase is **complete** when all its MUST criteria are satisfied and all failure thresholds are clear of blocking events. A phase is **blocked** when any single CRITICAL failure condition triggers, regardless of other metrics.

---

## 2. Metric Categories

Metrics are grouped into six categories. Each metric carries a severity level:

- **CRITICAL** — blocks phase advancement; a single occurrence is disqualifying
- **BLOCKING** — must be resolved before phase exit; accumulation above threshold blocks advancement
- **ADVISORY** — tracked and reported; does not block advancement but informs Phase 2 parameter decisions

---

## 3. Phase 2 — Devnet Criteria

### 3.1 Safety

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Unintentional forks | 0 | any occurrence | CRITICAL |
| Double-spend or replay accepted | 0 | any occurrence | CRITICAL |
| Non-canonical CBOR accepted by any node | 0 | any occurrence | CRITICAL |
| Divergent state roots between nodes after finalized block | 0 | any occurrence | CRITICAL |
| Signature accepted for wrong account or wrong algorithm | 0 | any occurrence | CRITICAL |

Safety criteria admit no tolerance. A single confirmed safety violation MUST halt the devnet and be root-caused before any phase resumption.

### 3.2 Liveness

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Median block time | ≤ 2s | > 4s sustained over 10 consecutive blocks | BLOCKING |
| Block production gap (no block) | 0 gaps > 6s | any gap > 15s | BLOCKING |
| Finality latency (block proposed → irreversible) | ≤ 4s | > 10s sustained over 5 consecutive blocks | BLOCKING |
| Missed rounds (no proposal) | ≤ 5% over any 1-hour window | > 20% over any 1-hour window | BLOCKING |
| Quorum failure (block cannot be finalized) | 0 expected | any occurrence not attributable to deliberate fault injection | BLOCKING |

### 3.3 Throughput

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Sustained TPS with ML-DSA-65 under normal load | ≥ 100 TPS | < 50 TPS | BLOCKING |
| Mempool steady-state depth under 100 TPS | < 500 pending txs | > 2,000 pending txs after 5 minutes | ADVISORY |
| Signature verification CPU per block (single core, reference hardware) | < 60% utilization | > 85% sustained | BLOCKING |

The 100 TPS devnet target is a minimum protocol correctness bar, not a throughput claim. The fee model must be calibrated to the measured verification cost before the public testnet.

### 3.4 Cryptographic Correctness

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| ML-DSA-65 known-answer test (KAT) vectors: all pass | 100% | any failure | CRITICAL |
| FN-DSA-padded-512 KAT vectors: all pass | 100% | any failure | CRITICAL |
| SLH-DSA-128s KAT vectors: all pass | 100% | any failure | CRITICAL |
| ML-KEM-768 KAT vectors: all pass | 100% | any failure | CRITICAL |
| Cross-implementation consistency (liboqs vs. mlkem-native/mldsa-native) | 100% agreement on all test cases | any disagreement | CRITICAL |
| Invalid signature rejected on all nodes | 100% | any acceptance | CRITICAL |
| Signature from revoked key rejected | 100% | any acceptance | CRITICAL |

KAT vectors MUST be sourced from the NIST PQC test vector archive and the algorithm specification documents. Cross-implementation checks MUST be run on a common test corpus of at least 10,000 key pairs and message pairs per algorithm before the devnet launches.

### 3.5 Key Lifecycle

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Key rotation completes within valid_from_height + 1 block | 100% | any failure | BLOCKING |
| Revoked key rejected in all subsequent blocks | 100% | any acceptance | CRITICAL |
| Rotation from ML-DSA-65 to FN-DSA-padded-512: full flow completes | 1 successful end-to-end drill | not completed | BLOCKING |
| Rotation from ML-DSA-65 to SLH-DSA-128s: full flow completes | 1 successful end-to-end drill | not completed | BLOCKING |

### 3.6 Fee Model

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Underpriced transaction rejected before mempool entry | 100% | any admission | BLOCKING |
| Per-sender verify budget enforced | 100% | any bypass | BLOCKING |
| V-C (SLH-DSA) per-block cap enforced | 100% | any bypass | BLOCKING |
| Fee replacement policy (10% bump + tip MUST NOT decrease) | 100% | any violation | BLOCKING |
| Measured effective_sigverify_fee within 20% of benchmark reference | 100% of fee classes | > 20% deviation | ADVISORY |

### 3.7 Storage

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Measured tx storage per day at 100 TPS (ML-DSA-65) | within 25% of 30 GB/day estimate | > 50% deviation | ADVISORY |
| State root size per block | tracked; no target yet | — | ADVISORY |
| Index overhead vs. raw tx data ratio | tracked; no target yet | — | ADVISORY |

Storage metrics are advisory at the devnet stage. Measured values from the devnet MUST be used to update TESTING.md before the controlled testnet launches.

---

## 4. Phase 3-alpha — Controlled Testnet Criteria

Phase 3-alpha inherits all Phase 2 CRITICAL and BLOCKING criteria without relaxation. The following criteria are added.

### 4.1 External Operator Onboarding

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| External operators able to join via documented onboarding flow | ≥ 8 external validators | < 4 external validators after 2 weeks | BLOCKING |
| Operator API correctly rejected from public network | 100% | any external exposure | CRITICAL |
| Minimal public status endpoint (/v1/network) reachable | 100% uptime | < 95% over any 24-hour window | BLOCKING |

### 4.2 Crypto Agility Drill

At least one complete algorithm lifecycle drill MUST be executed during Phase 3-alpha. The drill covers all four deprecation steps for a test algorithm not used in production:

| Step | Required outcome |
|------|-----------------|
| Announcement proposal submitted and passed | governance record on-chain |
| Dual-accept: test algorithm still accepted | transactions pass; governance record updated |
| Discouraged: min_fee raised; new accounts cannot register | fee increase enforced; new registration rejected; existing accounts still functional |
| Banned: transactions rejected at mempool | all transactions using the banned algorithm rejected; accounts that migrated away unaffected |

Failure to complete any step is BLOCKING for phase exit.

### 4.3 State Recovery

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Snapshot generated at known height | successfully completed | failure | BLOCKING |
| New node joins via snapshot (not full replay) within time bound | ≤ 10 minutes from snapshot start | > 30 minutes | BLOCKING |
| State root after sync matches reference node | 100% | any mismatch | CRITICAL |
| Full replay consistency (reference check) | state root at height N matches snapshot-synced node | any mismatch | CRITICAL |

### 4.4 Partition Tolerance

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Network recovers consensus after minority partition healed | within 10 blocks after network reconnection | > 60 blocks | BLOCKING |
| No safety violation under minority partition | 0 forks | any fork | CRITICAL |
| No safety violation under f = ⌊n/3⌋ Byzantine validators (simulated) | 0 safety violations | any violation | CRITICAL |

Byzantine fault tests MUST be conducted by deliberately misconfiguring ⌊n/3⌋ validators (with n = 32 for Phase 3-alpha) to produce conflicting votes. The remaining honest validators MUST produce no fork and MUST NOT finalize conflicting blocks.

### 4.5 Throughput at Phase 3-alpha Scale

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Sustained TPS with ML-DSA-65 | ≥ 200 TPS | < 100 TPS | BLOCKING |
| Block time under 200 TPS load | ≤ 2s median | > 3s median over 10 minutes | BLOCKING |
| Mempool depth under 200 TPS sustained | < 1,000 pending txs | > 5,000 pending txs after 10 minutes | BLOCKING |

---

## 5. Phase 3-public — Public Testnet Criteria

Phase 3-public inherits all Phase 3-alpha CRITICAL and BLOCKING criteria. The following criteria are added or tightened.

### 5.1 Availability

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Public read API uptime | ≥ 99% over any 7-day window | < 95% | BLOCKING |
| Median API response time (GET /v1/network) | ≤ 200 ms | > 1s median over any 1-hour window | BLOCKING |
| Median API response time (GET /v1/txs/{hash}) | ≤ 300 ms | > 2s median over any 1-hour window | BLOCKING |

### 5.2 Anti-DoS Robustness

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Mempool DoS (SLH-DSA spam): block production unaffected | 0 missed blocks attributable to SLH-DSA spam | any | CRITICAL |
| Mempool DoS (oversized tx spam): per-sender budget enforced | 100% | any bypass | CRITICAL |
| API rate limiting: single-IP flood does not degrade service for others | p99 latency for other IPs ≤ 2× baseline | > 5× baseline | BLOCKING |

### 5.3 Storage and Growth

| Metric | Target | Threshold | Severity |
|--------|--------|-----------|----------|
| Measured storage growth at actual public testnet TPS | within 30% of updated projections (from Phase 2 actuals) | > 50% deviation | ADVISORY |
| Snapshot interval | ≤ 1,000 blocks | > 5,000 blocks between available snapshots | BLOCKING |
| State sync from latest snapshot | ≤ 15 minutes | > 45 minutes | BLOCKING |

### 5.4 Complete Trust Workflow Coverage

All 10 Phase 1 operation types defined in SPEC-OPS-001 MUST be exercised end-to-end on the public testnet before exit:

| Operation | Verification method |
|-----------|-------------------|
| `vault_create` | Account created, address derivation verified against formula |
| `vault_policy_update` | Policy version increments; old policy rejected |
| `token_transfer` | Balance debited and credited; implicit account creation verified |
| `attestation_create` | All 6 attestation types submitted; secondary indexes queryable |
| `attestation_revoke` | Original record preserved; revoked status reflected in API |
| `proof_anchor` | Anchor stored; retrievable by anchor_id |
| `key_add` | Key added with valid_from_height; inactive before that height |
| `key_rotate` | Old key revoked atomically; new key active in same block |
| `key_revoke` | Revoked key rejected immediately |
| `consensus_key_rotate` | Rotation window enforced; no vote gap |

Failure to complete any operation end-to-end is BLOCKING for public testnet exit.

---

## 6. Measurement Protocols

### 6.1 Reference Hardware

All benchmark measurements MUST be taken on hardware matching the reference profile:

- **CPU**: AMD Ryzen 7 7700 (Zen 4, 3.8 GHz) or documented equivalent
- **RAM**: 32 GB DDR5
- **Storage**: NVMe SSD (≥ 3,500 MB/s sequential read)
- **OS**: Linux (bare metal, not virtualized)

If measurements are taken on different hardware, a correction factor MUST be documented and applied consistently.

### 6.2 Throughput Measurement

TPS measurements MUST:

- run for a minimum of 10 continuous minutes under stable load
- exclude the first 60 seconds (warm-up period)
- report p50, p95, and p99 latency alongside throughput
- be conducted with the fee model fully active (not bypassed)
- use a transaction corpus with realistic algorithm distribution (e.g., 90% ML-DSA-65, 9% FN-DSA, 1% SLH-DSA)

### 6.3 Block Time Measurement

Block time is measured as the wall-clock interval between consecutive finalized block timestamps as recorded by the reference node. Outliers (single blocks > 5s) are reported separately from the median.

### 6.4 Cryptographic Conformance

KAT vector tests MUST be run as part of the CI pipeline. Cross-implementation checks MUST be run in CI on every merge to the main branch. A KAT failure in CI MUST block the merge.

### 6.5 Fault Injection

Fault injection tests (partition, Byzantine validators) MUST be run in an isolated testnet environment separate from the live testnet. Results from fault injection runs MUST be documented in a test report before the phase exit review.

### 6.6 API Latency Measurement

API latency is measured from the load balancer ingress to the response body completion. Measurements MUST use a distributed load generator with at least 3 geographic origins. Reported values are p50, p95, and p99.

---

## 7. Phase Exit Review

A phase exit review is required before advancing between phases. The review MUST include:

1. **Safety attestation** — written confirmation from at least 2 engineers that all CRITICAL criteria have been satisfied and no unresolved safety events have occurred
2. **Metrics report** — a structured report covering all BLOCKING and ADVISORY metrics from this document, with actuals vs. targets
3. **Failure log** — a complete list of any CRITICAL or BLOCKING events that occurred during the phase, with root-cause analyses and resolutions
4. **Parameter updates** — any fee coefficients, storage projections, or benchmark reference values updated as a result of measured actuals
5. **Updated specs** — any changes required to SPEC-TX-001, SPEC-ACCOUNT-001, SPEC-FEE-001, or SPEC-VAL-001 based on observations

The review is recorded as an entry in DECISIONS.md under a new ADR if any protocol parameter is changed as a result.

---

## 8. Criteria Not In Scope

The following are explicitly not success criteria for any testnet phase:

- raw TPS claims without the fee model active
- throughput measured with SLH-DSA excluded from the transaction corpus (SLH-DSA must be present to test the V-C cap)
- coverage percentages as a substitute for correctness evidence
- API endpoint count as a proxy for feature completeness
- validator count above the ADR-013 ceilings (24/32/50)

---

## 9. Cross-References

| Document | Relevance |
|----------|-----------|
| [SPEC-TX-001](transaction-envelope.md) | canonical encoding and validation pipeline tested in §3.1 and §3.4 |
| [SPEC-ACCOUNT-001](account-keyset-registry.md) | key lifecycle criteria in §3.5 |
| [SPEC-FEE-001](fee-model.md) | fee model criteria in §3.6 and §5.2 |
| [SPEC-VAL-001](validator-staking.md) | consensus and partition criteria in §4.4; commit overhead data in §3.3 |
| [SPEC-OPS-001](operations.md) | trust workflow coverage in §5.4 |
| [SPEC-GOV-001](governance-module.md) | crypto agility drill in §4.2 |
| [TESTING.md](../TESTING.md) | benchmark reference data; update after Phase 2 actuals |
| [DECISIONS.md](../DECISIONS.md) | ADR-013 (validator targets); phase exit parameter changes |
