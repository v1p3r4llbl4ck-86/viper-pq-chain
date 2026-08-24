# Viper PQ Chain — Dress Rehearsal Procedure

**Version**: 1.0
**Date**: 2026-04-12
**Produced by**: TASK-073 (Phase 5)
**Status**: procedure documented; execution is a Phase 6 prerequisite

This document specifies the 7-day dress rehearsal that must be completed before the Viper PQ Chain mainnet genesis block is produced. The rehearsal validates that all production parameters work together correctly under realistic conditions.

---

## §1 — Objective

The dress rehearsal answers the following questions:

1. Do the genesis parameters (tokenomics, fee coefficients, validator set) work together without unexpected interactions?
2. Does the chain sustain production-level throughput (≥100 TPS) on reference hardware?
3. Does fee distribution behave correctly under sustained load?
4. Do operational procedures (restart, snapshot import, key rotation, algorithm deprecation) execute correctly on the production config?
5. What is the observed storage growth rate?

A dress rehearsal that surfaces no blocking issues closes the final technical prerequisite for mainnet launch.

---

## §2 — Environment

### Infrastructure

| Node | Role | Hardware minimum | Location |
|---|---|---|---|
| validator-1 | Producer + validator | Reference hardware (§2.1) | Primary datacenter |
| validator-2 | Validator + follower | Reference hardware | Secondary datacenter |
| validator-3 | Validator + follower | Reference hardware | Tertiary datacenter |
| full-node-1 | Full node (no stake) | 16 GB RAM, 500 GB NVMe | Can be same datacenter as validator-1 |
| gateway-1 | API gateway / public endpoint | 8 GB RAM | Can be same host as full-node-1 |

Minimum viable rehearsal: 3 validators + 1 full node. The 5-node setup above is recommended.

### Reference Hardware (§2.1)

At least one validator must run on the Phase 4 reference hardware specification:
- CPU: AMD Ryzen 7 7700 or equivalent
- RAM: 32 GB DDR5
- Storage: 1 TB NVMe SSD (≥3,500 MB/s sequential read)
- OS: Ubuntu 22.04 LTS, release build

This is the hardware against which the SPEC-TEST-001 §3.3 (≥100 TPS) target will be confirmed.

### Configuration

All nodes must use:
- **Chain ID**: `viper-rehearsal-1` (distinct from mainnet `viper-mainnet-1`)
- Fee parameters from ADR-024 (same as mainnet)
- Staking parameters from ADR-024 (same as mainnet)
- Genesis accounts with same proportions as mainnet (different addresses are fine)
- Genesis validators: same number and hardware as the planned mainnet set

The genesis config is built using `specs/genesis-spec.md §4` (ceremony procedure) with `viper-rehearsal-1` as the chain ID. The `genesis_hash` is computed and verified by all participants before starting.

---

## §3 — Genesis Setup

1. Generate rehearsal keypairs for all validators (§3 of `docs/validator-onboarding.md`)
2. Build `configs/rehearsal-genesis.json` with rehearsal accounts and validators
3. All validators run `pqcd genesis-verify configs/rehearsal-genesis.json` and confirm the same `genesis_hash`
4. Coordinator starts the chain: `pqcd genesis-init configs/rehearsal-genesis.json`
5. All validators start their nodes and confirm height is advancing

Chain is ready when all validators are synced and height ≥ 3.

---

## §4 — Day-by-Day Checklist

### Every Day (baseline checks)

At the start and end of each day, verify:

- [ ] Chain is producing blocks (height increasing at expected rate)
- [ ] No fork detected (`tip_hash` is identical across all nodes: `GET /v1/status`)
- [ ] No unplanned sync errors in `pqchain_peer_sync_errors_total` metric
- [ ] Mempool depth is not growing unboundedly (`pqchain_mempool_depth`)
- [ ] Disk usage is within projections (check with `du -sh <data_dir>`)
- [ ] At least 1 non-validator transaction committed (proof_anchor or attestation_create)

Record height at start and end of each day to compute daily block production rate.

---

### Day 1 — Bootstrap and Baseline

**Goal**: confirm all nodes start cleanly, sync, and agree on genesis.

- [ ] All 5 nodes started from genesis
- [ ] All nodes confirm same `genesis_hash` before block 1
- [ ] Height ≥ 10 reached without manual intervention
- [ ] Prometheus metrics scraping working on all nodes
- [ ] Fee distribution: submit 10 `token_transfer` transactions; confirm fees credited to proposer
- [ ] Record baseline: height/minute, block size, mempool depth

**Pass criterion**: all nodes at same height and tip_hash by end of day.

---

### Day 2 — Load Test

**Goal**: confirm ≥100 TPS on reference hardware under production parameters.

```bash
# On the reference hardware node:
LOAD_TX_COUNT=10000 cargo test --test load_test --release -- --nocapture 2>&1 | tee /tmp/rehearsal-load-test.txt
```

- [ ] 10,000 transactions injected
- [ ] Record: effective TPS, injection TPS, mempool peak, blocks produced, duration
- [ ] SPEC-TEST-001 §3.3 target (≥100 TPS): record MET or NOT MET
- [ ] Storage growth during the test: record MB added
- [ ] Extrapolate: daily storage at observed TPS

**Pass criterion**: effective TPS ≥ 100 on reference hardware. If NOT MET, open a performance issue before proceeding.

---

### Day 3 — Cross-Algorithm Key Rotation Drill

**Goal**: confirm the key rotation workflow under production conditions.

Run the integration test:
```bash
cargo test --test key_rotation_drill -- --nocapture
```

Additionally, manually submit a `key_rotate` transaction from a rehearsal account:
- [ ] Old key (ML-DSA-65, kv=1) active before rotation
- [ ] Submit `key_rotate` with new SLH-DSA-SHA2-128s key, `valid_from_height = current + 10`
- [ ] Confirm at `valid_from_height`: new key is Active, old key is Revoked
- [ ] Confirm that a transaction signed by the revoked key is rejected

**Pass criterion**: rotation committed and state matches expectations.

---

### Day 4 — Algorithm Lifecycle Deprecation Drill

**Goal**: confirm the algorithm governance lifecycle under production conditions.

Run the integration test:
```bash
cargo test --test deprecation_drill -- --nocapture
```

Additionally, submit real governance proposals:
- [ ] Propose ML-DSA-44 → Discouraged (governance_proposal tx)
- [ ] Confirm: ML-DSA-44 tx still admitted but logs a warning
- [ ] Propose ML-DSA-44 → Deprecated
- [ ] Confirm: ML-DSA-44 tx rejected at admission

**Important**: use an algorithm not used by any validator consensus key. Using a validator's algorithm could cause liveness issues.

**Pass criterion**: governance lifecycle transitions execute correctly without chain disruption.

---

### Day 5 — Validator Restart

**Goal**: confirm that a validator can restart without losing its stake or causing liveness issues.

- [ ] Stop validator-2: `sudo systemctl stop pqcd`
- [ ] Wait 2 minutes; confirm chain continues with validators 1 and 3 (2 of 3 quorum still met)
- [ ] Restart validator-2: `sudo systemctl start pqcd`
- [ ] Confirm validator-2 catches up to current height using DiskChainStore recovery
- [ ] Confirm all 3 validators are at same height after recovery
- [ ] Confirm no liveness slash triggered (2-minute downtime is well within liveness window)

**Pass criterion**: validator restarts without slash and chain continued uninterrupted.

---

### Day 6 — Snapshot Export and Import

**Goal**: confirm that a new node can cold-start from a snapshot.

On full-node-1 or a new VM:
```bash
# Export snapshot from validator-1
pqcd snapshot-export --output /tmp/rehearsal-snapshot.bin

# On the new node: cold-start from snapshot
pqcd snapshot-import --snapshot /tmp/rehearsal-snapshot.bin --config configs/rehearsal-follower.json
pqcd start --config configs/rehearsal-follower.json
```

- [ ] Snapshot exported successfully with SHAKE-256 integrity hash
- [ ] New node imports snapshot and reports correct `state_root`
- [ ] New node syncs tail blocks (from snapshot height to current) via P2P
- [ ] New node reaches same `tip_hash` as validators
- [ ] Verify: `state_root` of new node matches validators after sync

**Pass criterion**: snapshot import produces bit-identical state root; tail sync succeeds.

---

### Day 7 — Autonomous Operation

**Goal**: confirm the chain sustains itself without any human intervention.

- [ ] No manual actions taken on Day 7
- [ ] Monitor only via dashboards and Prometheus
- [ ] Chain must produce blocks at the expected rate for 24 hours
- [ ] No CRITICAL or HIGH alerts during the day
- [ ] Fee distribution working: check proposer balances before and after

**Pass criterion**: chain runs for 24 hours without any human intervention and zero unplanned halts.

---

## §5 — Measurements to Record

At the end of the rehearsal, record the following in TESTING.md:

| Measurement | Target | Observed |
|---|---|---|
| Effective TPS (Day 2 load test) | ≥ 100 (SPEC-TEST-001 §3.3) | TBD |
| Block production rate | ~1 block / target_block_time | TBD |
| Storage growth per day (Day 2 under load) | Record for planning | TBD |
| Storage growth per day (Days 1, 3–7 at normal load) | Record for planning | TBD |
| Fee revenue per day at normal load | Record vs. ADR-024 economic model | TBD |
| Time to recover from snapshot (Day 6) | < 10 minutes for tail sync | TBD |
| Validator restart recovery time (Day 5) | < 5 minutes | TBD |

---

## §6 — Exit Criteria

The rehearsal is complete when ALL of the following are satisfied:

- [ ] 7 consecutive days completed without an unplanned halt
- [ ] Effective TPS ≥ 100 confirmed on reference hardware (Day 2)
- [ ] No CRITICAL findings discovered during the rehearsal
- [ ] Fee distribution verified correct across all 7 days
- [ ] Storage growth measured and within TESTING.md projections
- [ ] All 6 per-day drills completed (bootstrap, load, key rotation, deprecation, restart, snapshot)
- [ ] All validators confirm same `genesis_hash` derivation (Day 1)

If the exit criteria are met, the rehearsal is declared complete and mainnet launch planning can proceed.

---

## §7 — Failure Procedure

### CRITICAL failure (chain halts or state diverges)

1. Stop all nodes immediately
2. Collect logs from all validators: `journalctl -u pqcd > /tmp/validator-N-logs.txt`
3. Identify root cause — check: last common height, tip_hash divergence point, any error in commit quorum validation
4. Fix the root cause (code fix or config fix)
5. **Restart the rehearsal from Day 1** (a partial rehearsal does not satisfy the exit criteria)

### BLOCKING failure (a specific drill fails but chain continues)

1. Document the failure in detail
2. Fix the root cause
3. Re-run the failed drill on the next available day
4. The rehearsal clock continues running; the drill counts as completed when it passes

### NON-BLOCKING issue (warning, degraded performance)

1. Document the issue
2. Continue the rehearsal
3. Fix before the next rehearsal attempt or before mainnet launch (whichever comes first)

---

## §8 — Post-Rehearsal Report

Within 5 days of completing the rehearsal, produce a report covering:

1. Rehearsal summary: dates, participants, chain ID, all pass/fail per day
2. Load test numbers (Day 2) vs. SPEC-TEST-001 targets
3. Storage growth numbers vs. TESTING.md projections
4. Any issues found: severity, root cause, resolution
5. Fee coefficient recalibration decision (if the economic floor in ADR-024 needs adjustment for the actual mainnet fee target)
6. Recommendation: **proceed to mainnet** or **repeat rehearsal**

The report becomes an appendix to ADR-026 (Phase 5 exit) and a prerequisite for the genesis ceremony.

---

## Reference

- specs/genesis-spec.md (SPEC-GENESIS-001) — genesis ceremony (§4)
- specs/tokenomics.md (SPEC-TOKEN-002) — production parameters
- docs/validator-onboarding.md — hardware requirements, key generation, registration
- docs/operators/RUNBOOK.md §11 — node bootstrap
- the private runbook (private) — incident response playbooks (IR-01 through IR-06)
- the private runbook (private) — load test procedure
- TESTING.md — baseline load test results (Phase 4 reference: 129.4 TPS)
- SPEC-TEST-001 §3.3 — ≥100 TPS target; §4.5 — ≥200 TPS target
