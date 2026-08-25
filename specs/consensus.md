# Viper BFT Consensus Protocol Specification

**Spec ID**: SPEC-CONSENSUS-001  
**Version**: 0.3  
**Status**: Accepted  
**History**: v0.3 revised for the `viper-pq-1` launch (2026-04-25); that chain and its successor `viper-research-1` are retired, the protocol is unchanged on `viper-testnet-2`.  
**Date**: 2026-04-25  
**Revised by**: ADR-042 (dynamic validator set, epoch model, RANDAO+VDF proposer); ADR-051 (distributed precommit signing); ADR-053 (`viper-pq-1` genesis architecture)  
**Depends on**: ADR-007, ADR-027, ADR-042, ADR-051, ADR-053, SPEC-VAL-001, SPEC-TX-001, SPEC-ACCOUNT-001, SPEC-ADDRESS-001, SPEC-LIGHT-CLIENT-001

**Revision history**

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-Q1 | Initial three-phase Tendermint-like spec with static validator set. |
| 0.2 | 2026-04-21 | Revised by ADR-042: epoch model, dynamic validator set, RANDAO+VDF proposer selection, churn limits, emergency reconfiguration. |
| 0.3 | 2026-04-25 | **Aligned to viper-pq-1 launch code.** New §11 documents distributed precommit signing (ADR-051, TASK-167/170/171/172): every active validator signs precommits independently, the proposer waits up to `quorum_wait_ms` for ≥threshold gossiped precommits before sealing. New §12 documents the `ForkDigest` signing-domain prefix (ADR-053 §T1.2, TASK-191) layered into every consensus signing preimage. §5.4 churn-limit rewritten to the stake-weighted formula (ADR-053 §T1.5, TASK-194). §10.4 reframed under the unified `CommitPreimageMode::{Legacy, Distributed { round }}` dispatch. §3 Normative References adds SPEC-LIGHT-CLIENT-001 for the sync-committee complement (ADR-053 §T3.6, TASK-197). Migration §15 retitled "viper-pq-1 launch (historical)".

---

## 1. Scope

This document specifies the BFT consensus protocol for Viper PQ Chain. It defines the round-based state machine, message types, proposer selection, locking rules, commit material, equivocation detection, epoch model, and PQ-specific constraints that together replace the static single-producer prototype used in Phases 1–4.

The protocol is Tendermint-like with three voting phases (Prevote → Precommit → Commit) and proposer rotation. It is adapted for post-quantum signatures, with ML-DSA-65 as the default consensus key algorithm. The validator set is **dynamic**: membership transitions occur at epoch boundaries, not mid-epoch.

This spec at v0.3 was first active on the `viper-pq-1` chain (chain_id_hex `0x76697065722d70712d31`, launched 2026-04-25, since retired) and then on `viper-research-1` (retired). The public chain `viper-testnet-2` is created at genesis with the same protocol after the public release. Breaking consensus changes on a running chain MUST travel via Policy P-COMPAT-001 (ADR-052).

This specification does not cover:

- peer-to-peer message transport and gossip (SPEC-P2P-001)
- transaction processing, fee accounting, or mempool (SPEC-TX-001, SPEC-FEE-001)
- validator staking, registration, and slashing (SPEC-VAL-001)
- governance parameter updates (SPEC-GOV-001)

Normative references: ADR-007, ADR-027, ADR-042, ADR-051, ADR-053.  
Informative references: Buchman, Kwon, Milosevic, "The latest gossip on BFT consensus" (2018); Bitcoin BIP340 tagged-hash construction (consumed via ADR-053 §T2.4); Ethereum beacon-chain `ForkDigest` (motivating ADR-053 §T1.2).

---

## 2. Normative Language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are interpreted per RFC 2119.

---

## 3. Normative References

| Reference | Document |
|-----------|----------|
| ADR-007 | PoS BFT consensus direction, constrained validator set |
| ADR-027 | Adopt Tendermint-like BFT consensus with PQ signatures |
| ADR-042 | Dynamic validator set on-chain: epoch model, unbonding, slashing registry, RANDAO+VDF proposer |
| ADR-051 | Distributed precommit signing: every active validator signs, proposer aggregates |
| ADR-053 | `viper-pq-1` genesis architecture (Tier-1 §T1.2 ForkDigest, §T1.3 chain-id-bound addresses, §T1.5 stake-weighted churn; Tier-2 §T2.4 BIP340 double-tagged hashing; Tier-3 §T3.6 sync-committee light client) |
| SPEC-VAL-001 | Validator and staking model specification |
| SPEC-TX-001 | Transaction envelope specification |
| SPEC-ADDRESS-001 | Chain-id-bound address derivation |
| SPEC-ACCOUNT-001 | Account, KeySet, and Algorithm Registry specification |
| SPEC-LIGHT-CLIENT-001 | Sync-committee + compact-header attestation protocol (ADR-053 §T3.6) |

---

## 4. Definitions

**Height** (`h`): the zero-indexed position of a block in the canonical chain. The genesis block is at height 0. Height is monotonically increasing; no block may be committed at a height lower than the chain's current tip.

**Round** (`r`): the attempt number for producing a block at a given height. The first attempt at height `h` is round 0. If the round completes without a commit (proposer timeout, insufficient votes, or network fault), the round counter increments to `r+1`. Round is reset to 0 at each new height.

**Proposer**: the validator selected by the deterministic proposer-selection algorithm for `(h, r)`. The proposer is responsible for assembling and broadcasting a `Proposal` message containing a candidate block.

**Prevote**: the first-phase vote cast by a validator. A prevote indicates that the validator has received and validated the `Proposal` for `(h, r)` and judges the proposed block acceptable. A validator that does not receive a valid `Proposal` before `propose_timeout` MUST cast a nil-prevote.

**Precommit**: the second-phase vote cast by a validator after observing a polka (≥2/3 prevotes) for the same block hash. A precommit commits the validator to not voting for any conflicting block at the same height in any previous or concurrent round. A validator that does not see a polka before `prevote_timeout` MUST cast a nil-precommit.

**Commit**: the irreversible finalization of a block. A block is committed when ≥2/3+1 valid precommits for the same block hash are collected. The commit condition is sometimes written `f+1` where `f = floor((n-1)/3)` is the maximum number of Byzantine validators the protocol can tolerate.

**Polka**: a set of ≥2/3 prevotes (by voting power) for the same non-nil block hash at `(h, r)`. A polka is the precondition for issuing a precommit for a non-nil block.

**Nil vote**: a prevote or precommit for the nil hash (`[0u8; 32]`). A nil vote does not identify a specific block; it signals that the validator could not or did not prevote/precommit a real block in this round.

**Lock**: a validator that issues a `precommit(B)` at round `r` is locked on block `B` at height `h`. A locked validator MUST prevote `B` in all subsequent rounds at the same height unless it unlocks (see §8).

**View change**: the transition from round `r` to round `r+1` at the same height when a commit does not occur before the round's timeout expires. View change is triggered individually by each validator based on its local timer; no explicit view-change message is required.

**Equivocation**: the act of signing two conflicting messages of the same type at the same `(h, r, step)` where `step` ∈ {prevote, precommit}. Two messages are conflicting if they carry different `block_hash` values (at least one is non-nil). Equivocation is a slashable offense.

**Voting power**: a non-negative integer weight assigned to each active validator, proportional to its bonded stake subject to the soft-cap rule defined in SPEC-VAL-001 §6.5. In Phase 1 (before on-chain staking is fully operational), all active validators have equal voting power of 1. Quorum is evaluated against the sum of voting power of all active validators.

**Epoch**: a fixed-length period of consecutive blocks after which the validator set may be updated. The epoch duration is `epoch_duration_blocks` (governance parameter). At each epoch boundary the chain applies all queued activations and exits, redistributes rewards, and emits a `NewEpochEvent` containing the new validator set Merkle root. The validator set used for consensus is fixed for the entire epoch; no validator set change takes effect mid-epoch except forced removal via a `ValidatorTransaction::Reconfig` (emergency reconfiguration, see §18).

**Epoch boundary**: the last block `B_e` of an epoch. The block at height `first_block_of_next_epoch` begins with the updated validator set. State transitions applied at `B_e` include: activating queued candidates up to the churn limit, removing validators that have signaled exit, computing new voting powers, and updating the on-chain RANDAO accumulator.

---

## 5. Epoch Model

### 5.1 Duration and Floor

The epoch duration is set by the governance parameter `epoch_duration_blocks`. The default value corresponds to approximately **1 hour** of block production at the target block time.

The governance parameter is mutable but subject to a hard floor:

```
epoch_duration_blocks >= epoch_duration_floor
```

where `epoch_duration_floor` is the smallest value governance may set. The floor is defined as:

```
epoch_duration_floor = 4 × finality_time_blocks
```

This ensures that an epoch always spans at least four times the typical time-to-finality, providing sufficient time for evidence submission and validator set propagation across the network before the next boundary.

At the default 1-second block time with ~15-second finality:

| Parameter | Default |
|-----------|---------|
| `epoch_duration_blocks` | 3600 (≈1 hour) |
| `epoch_duration_floor` | 240 blocks (≈15 min, i.e. 4 × ~1 min finality) |
| Maximum governance-settable value | no upper bound |

Reducing `epoch_duration_blocks` below `epoch_duration_floor` MUST be rejected by the governance execution layer.

### 5.2 Validator Set at Epoch Boundary

The active validator set is fixed within an epoch. At each epoch boundary the following are applied atomically:

1. Activate queued candidates up to the **stake-weighted activation churn limit** (§5.4).
2. Remove validators that have submitted a voluntary exit and whose exit is due (within the symmetric stake-weighted exit limit, §5.4).
3. Remove jailed validators whose forced-unbonding has been confirmed by governance.
4. Recompute voting powers (applying the soft-cap rule from SPEC-VAL-001 §6.5).
5. Update the RANDAO accumulator seed for proposer selection.
6. Emit `NewEpochEvent` containing the new validator set Merkle root.

The validator set used for block production at height `h` is the set fixed at the epoch boundary immediately preceding `h`.

### 5.3 Committee Size Trajectory

The maximum active validator set size (`max_validator_set_size`) follows a planned growth trajectory governed on-chain:

| Period | Target `max_validator_set_size` |
|--------|--------------------------------|
| Genesis (Phase 8) | 64 |
| Year 2 | 256 |
| Year 5+ | 1024 (requires STARK aggregation infrastructure) |

Governance may adjust these targets ahead of schedule if the network demonstrates readiness. Scaling beyond 256 validators with naive PQ signature verification is infeasible without STARK-based commit aggregation (see §13.5).

### 5.4 Stake-weighted churn limit (ADR-053 §T1.5)

> *Previously count-based: pre-launch versions of this spec capped per-epoch activations at `max(4, active_count / 256)`. That formula is superseded by the stake-weighted form below per ADR-053 §T1.5 (TASK-194). The pre-launch count-based form is retained as a historical reference only.*

At each epoch boundary, the **per-epoch activation limit** is expressed as a fraction of total active self-bond:

```
limit_stake = max(activation_min_stake, active_stake × activation_target_bps / 10_000)
```

The epoch transition iterates the FIFO candidate queue, accumulating each candidate's `self_bond` until the next candidate would push the cumulative total past `limit_stake`. A symmetric **per-epoch exit limit** uses `exit_target_bps` and `exit_min_stake`. To preserve liveness for freshly bootstrapped networks (where `active_stake = 0`), the implementation guarantees activation of at least one candidate when the queue is non-empty.

**`viper-pq-1` genesis defaults** (`ChurnConfig::viper_pq_1` in `crates/pqc-types/src/churn.rs:50`):

| Parameter | Value | Notes |
|-----------|-------|-------|
| `activation_target_bps` | 39 | Equivalent to the pre-launch `active/256` count-based cap under roughly equal stake per validator. |
| `activation_min_stake` | 0 | Floor; defaults to zero, governance-tunable. |
| `exit_target_bps` | 313 | Equivalent to the pre-launch `active/32` exit cap. |
| `exit_min_stake` | 0 | Floor; defaults to zero, governance-tunable. |

These parameters are registry-tunable via governance proposal (planned Tier-2 follow-up). Reference implementation: `pqc_types::stake_weighted_activation_limit` and `stake_weighted_exit_limit` in `crates/pqc-types/src/churn.rs:71-82`. Application path: `pqc_state::StateStore::process_epoch_transitions` in `crates/pqc-state/src/store.rs:931`.

**Rationale.** Ethereum learned this pattern the hard way: EIP-7514 shipped a count-based activation cap, then EIP-7251 had to rewrite it stake-weighted and re-derive the slashing formula from `1/32` to `1/4096`. Doing the equivalent rewrite post-launch requires both a spec change and a slashing migration; paying the cost at genesis is ~50 LOC.

---

## 6. Proposer Selection

### 6.1 Algorithm (v1: RANDAO + VDF Hash-Based)

The proposer for `(h, r)` is selected using a RANDAO-seeded, VDF-delayed hash-based weighted sortition. This approach is PQ-safe: it relies only on collision-resistant hash functions and does not require any elliptic-curve VRF construction.

**Why not EC-VRF**: EC-VRF constructions (including ECVRF-EDWARDS25519-SHA512-ELL2 and similar) rely on the elliptic-curve discrete logarithm problem, which is broken by Shor's algorithm on a sufficiently capable quantum computer. EC-VRF MUST NOT be used for proposer selection in a post-quantum chain. The v1 RANDAO + VDF approach is adopted as the PQ-safe baseline; migration to a standardized PQ-VRF (lattice- or hash-based, pending IRTF CFRG standardization) is planned for v2 via governance once a suitable standard exists.

**Proposer selection procedure for `(h, r)`:**

```
randao_seed   = epoch_randao_accumulator(epoch(h))
vdf_output    = VDF(randao_seed || height_be64 || round_be32)
proposer_hash = SHAKE-256("VIPER-PROPOSER-V1" || vdf_output, 32)
sorted_vals   = sort_by_address(active_validator_set)
total_weight  = sum(v.voting_power for v in sorted_vals)
selector      = proposer_hash_as_u256 mod total_weight
proposer      = weighted_select(sorted_vals, selector)
```

The VDF output introduces a delay that prevents the last RANDAO contributor from predicting or biasing the proposer for the next block. The VDF parameterization (number of sequential squarings, group) is a governance parameter.

For Phase 8 (devnet/testnet), until the VDF is implemented, the following simplified form MAY be used:

```
proposer(h, r) = sorted_validators[(h + r) mod len(sorted_validators)]
```

This simplified form MUST be replaced before mainnet.

### 6.2 Proposer Selection Module

The proposer selection algorithm is exposed as a swappable module behind a stable interface (`ProposerSelector` trait). Migration from v1 (RANDAO+VDF) to v2 (PQ-VRF) is a governance parameter change that triggers a module swap at the next epoch boundary without requiring a hard fork.

### 6.3 Invariants

- The proposer selection function MUST be deterministic: every correct validator MUST compute the same proposer for any `(h, r)` given the same active validator set and the same voting power distribution.
- The active validator set used for proposer selection at height `h` is the set fixed at the epoch boundary preceding `h`. Mid-epoch changes (jailing) do not affect the proposer schedule until the next epoch boundary, except for emergency reconfigurations (§18).
- A validator that is jailed or in the `unbonding`/`exited` state MUST NOT be selected as proposer. The active set for proposer selection consists only of validators with status `active` (SPEC-VAL-001 §5.1).

---

## 7. Round State Machine

Each validator runs an independent instance of the following state machine for every height. State machine instances at different heights do not interlock; a validator MAY process messages for `h+1` before it has fully committed `h` if it has received sufficient evidence of the commit.

### 7.1 State Diagram

```
            ┌───────────────────────────────────────────────┐
            │           NewRound(h, r)                       │
            │  compute proposer = select(h, r)               │
            │  if self == proposer:                          │
            │    assemble candidate_block                    │
            │    broadcast Proposal(h, r, candidate_block)  │
            │  start timer: propose_timeout(r)              │
            └──────────────────┬────────────────────────────┘
                               │ on Proposal received OR
                               │ on propose_timeout(r) fire
                               ▼
            ┌───────────────────────────────────────────────┐
            │           Prevote(h, r)                        │
            │  if valid Proposal received:                   │
            │    if not locked OR locked_block == proposed:  │
            │      broadcast Prevote(h, r, block_hash)       │
            │    else:                                       │
            │      broadcast Prevote(h, r, nil_hash)         │
            │  else (timeout or invalid):                    │
            │    broadcast Prevote(h, r, nil_hash)           │
            │  start timer: prevote_timeout(r)              │
            └──────────────────┬────────────────────────────┘
                               │ on 2/3+ prevotes for same hash OR
                               │ on prevote_timeout(r) fire
                               ▼
            ┌───────────────────────────────────────────────┐
            │           Precommit(h, r)                      │
            │  if polka(B) observed (2/3+ prevotes for B):  │
            │    lock(B, r)                                  │
            │    broadcast Precommit(h, r, block_hash(B))   │
            │  else:                                         │
            │    broadcast Precommit(h, r, nil_hash)         │
            │  start timer: precommit_timeout(r)            │
            └──────────────────┬────────────────────────────┘
                               │ on 2/3+ precommits for same hash OR
                               │ on precommit_timeout(r) fire
                               ▼
            ┌───────────────────────────────────────────────┐
            │           Decide(h, r)                         │
            │  if 2/3+1 precommits for block B received:    │
            │    commit(B)                                   │
            │    advance to NewRound(h+1, 0)                │
            │  else:                                         │
            │    advance to NewRound(h, r+1)                │
            └───────────────────────────────────────────────┘
```

### 7.2 NewRound Step

**Inputs**: height `h`, round `r`, local lock state.

**Actions**:
1. Compute `proposer = select(h, r)`.
2. If `self == proposer`: assemble a candidate block from the mempool (using the block assembly rules in `pqc-consensus::engine`); broadcast `Proposal(h, r, block, pol_round)` to all validators. `pol_round` is -1 unless the proposer is re-proposing a previously locked block (see §8.3).
3. Start local timer `T_propose = propose_timeout(r)`.

**On `T_propose` fire**: if no valid Proposal has been received, proceed to Prevote and broadcast `Prevote(h, r, nil_hash)`.

**Invariant**: a validator MUST NOT broadcast a Proposal unless it is the designated proposer for `(h, r)`.

### 7.3 Prevote Step

**Inputs**: Proposal message (or nil), local lock state.

**Actions**:
1. If a valid Proposal for `(h, r, B)` was received:
   - If the validator is not locked, or is locked on `B`: broadcast `Prevote(h, r, block_hash(B))`.
   - If the validator is locked on a different block `B'` (at round `r' < r`) and no polka for `B` at a round `≥ r'` has been observed: broadcast `Prevote(h, r, nil_hash)`.
2. Otherwise (timeout fired or invalid proposal): broadcast `Prevote(h, r, nil_hash)`.
3. Start local timer `T_prevote = prevote_timeout(r)`.

**On receiving ≥2/3 prevotes** for the same non-nil hash at any point: record polka; if `T_prevote` has not yet fired, proceed to Precommit immediately.

**On `T_prevote` fire**: proceed to Precommit.

**Invariant**: a validator MUST broadcast exactly one Prevote per `(h, r)`. Broadcasting two prevotes with different block hashes at the same `(h, r)` is equivocation and is slashable.

### 7.4 Precommit Step

**Inputs**: collected prevotes, polka state.

**Actions**:
1. If polka `(h, r, B)` has been observed: lock on `B` at round `r`; broadcast `Precommit(h, r, block_hash(B))`.
2. Otherwise: broadcast `Precommit(h, r, nil_hash)`.
3. Start local timer `T_precommit = precommit_timeout(r)`.

**On receiving ≥2/3+1 precommits** for the same non-nil hash: proceed to Decide immediately.

**On `T_precommit` fire**: proceed to Decide without a commit (increment round).

**Invariant**: a validator MUST broadcast exactly one Precommit per `(h, r)`. Two precommits with different block hashes at the same `(h, r)` is equivocation and is slashable.

### 7.5 Decide Step

**Actions**:
1. If ≥2/3+1 valid `Precommit(h, r, B)` messages have been collected: commit `B`; record commit material (the precommit signatures); advance to `NewRound(h+1, 0)`.
2. If `max_rounds_per_height` is reached without a commit: the node enters a **liveness halt** and waits for governance recovery (see §17).
3. Otherwise: advance to `NewRound(h, r+1)`.

---

## 8. Message Types

All consensus messages are deterministic CBOR-encoded (per ADR-004) and signed with the sender's consensus key (SPEC-VAL-001 §4).

### 8.1 Proposal

Broadcast by the designated proposer to all validators.

| Field | Type | Description |
|-------|------|-------------|
| `msg_type` | u8 | `0xC1` |
| `height` | u64 | block height being proposed |
| `round` | u32 | round number |
| `block_data` | bytes | full serialized block (CBOR, same format as canonical blocks) |
| `block_hash` | bytes[32] | SHAKE-256 of `block_data` |
| `pol_round` | i32 | -1 if this is a new proposal; ≥0 if re-proposing a previously locked block (the round at which the polka was observed) |
| `proposer_address` | bytes[32] | operator address of the proposer |
| `signature` | bytes | ML-DSA-65 (or SLH-DSA-SHAKE-192s) signature over the proposal preimage (see §8.4) |

### 8.2 Prevote

Broadcast by every validator during the Prevote step.

| Field | Type | Description |
|-------|------|-------------|
| `msg_type` | u8 | `0xC2` |
| `height` | u64 | block height being voted on |
| `round` | u32 | round number |
| `block_hash` | bytes[32] | SHAKE-256 of the proposed block, or `[0u8; 32]` for nil |
| `validator_address` | bytes[32] | operator address of the voter |
| `signature` | bytes | ML-DSA-65 (or SLH-DSA-SHAKE-192s) signature over the vote preimage (see §8.4) |

### 8.3 Precommit

Broadcast by every validator during the Precommit step. Structurally identical to Prevote except for `msg_type`.

| Field | Type | Description |
|-------|------|-------------|
| `msg_type` | u8 | `0xC3` |
| `height` | u64 | block height being voted on |
| `round` | u32 | round number |
| `block_hash` | bytes[32] | SHAKE-256 of the committed block, or `[0u8; 32]` for nil |
| `validator_address` | bytes[32] | operator address of the voter |
| `signature` | bytes | ML-DSA-65 (or SLH-DSA-SHAKE-192s) signature over the vote preimage (see §8.4) |

### 8.4 Signature Preimages (ADR-053 §T1.2 + §T2.4)

Every consensus signing preimage is prefixed by the host chain's 4-byte `ForkDigest` (§12.1) and wrapped in the BIP340 double-tagged construction under a per-object domain tag (§12.2 and ADR-053 §T2.4).

**Vote preimage** (Prevote and Precommit) — `pqc_consensus::round::vote_preimage`, `crates/pqc-consensus/src/round.rs:67`:

```
body     = fork_digest[4]    ||   // 4 bytes — ADR-053 §T1.2
           height_be64       ||   // 8 bytes, big-endian
           round_be32        ||   // 4 bytes, big-endian
           step_u8           ||   // 1 byte: 0x01 = prevote, 0x02 = precommit
           block_hash             // 32 bytes (nil or real hash)
preimage = tagged_hash("VIPER-VOTE-V1", body)
         = SHAKE-256(H("VIPER-VOTE-V1") || H("VIPER-VOTE-V1") || body, 32)
```

**Proposal preimage** — `pqc_consensus::round::proposal_preimage`, `crates/pqc-consensus/src/round.rs:98`:

```
body     = fork_digest[4]    ||
           height_be64       ||
           round_be32        ||
           pol_round_i32_be  ||   // 4 bytes, two's-complement big-endian
           block_hash
preimage = tagged_hash("VIPER-PROPOSAL-V1", body)
```

The `ForkDigest` prefix scopes every consensus signature to a specific `(fork_version, genesis_validators_root)` pair, so a signed vote on `viper-pq-1` cannot be replayed on any parallel or future chain (ADR-053 §T1.2). The BIP340 double-tagged outer hash (ADR-053 §T2.4) defends against CVE-2012-2459-class domain-tag collisions: the inner `H(tag) || H(tag)` block prevents an attacker from crafting a `body'` under any other `tag'` such that the digests match.

The per-object domain tag (`"VIPER-VOTE-V1"` vs `"VIPER-PROPOSAL-V1"`) prevents cross-message-type signature reuse — a vote signature cannot verify as a proposal signature under any height/round combination.

These preimages differ from the legacy commit preimage produced by `commit_preimage` (§10.4 / `crates/pqc-consensus/src/commit.rs:221`); the two formats MUST NOT be intermixed.

---

## 9. Locking Rules

### 9.1 Lock Condition

A validator MUST lock on block `B` at round `r` when it issues `Precommit(h, r, block_hash(B))` where `block_hash(B) ≠ nil_hash`. The lock is represented as the pair `(locked_block: B, locked_round: r)`.

### 9.2 Lock in Prevote

A locked validator MUST prevote its locked block `B` in all subsequent rounds `r' > r` at the same height `h`, EXCEPT when it has observed a polka for a different block `B'` at some round `r'' > r` (an "unlock polka"). On observing an unlock polka for `B'`, the validator MUST unlock and prevote `B'`.

### 9.3 Re-proposal with `pol_round`

If the proposer for `(h, r)` is itself locked on `B` from a previous round `r_lock`, it MUST re-propose `B` and set `pol_round = r_lock`. This signals to other validators that a polka for `B` was observed at `r_lock`, allowing locked validators to verify the re-proposal is consistent before committing.

Validators that receive a Proposal with `pol_round ≥ 0` SHOULD request the polka evidence for `(h, pol_round)` if they do not already have it. They MUST NOT accept the re-proposal as unlocking without verifying the polka.

### 9.4 Invariant

A validator that is locked on `B` at round `r` MUST NOT issue a Precommit for any block `B' ≠ B` at any round `r' ≤ r` at the same height. Violation is equivocation and is slashable per §13.

---

## 10. Commit and Finalization

### 10.1 Commit Condition

A block `B` at height `h` is committed when the node collects ≥2/3+1 valid `Precommit(h, *, block_hash(B))` messages, where the signers are distinct active validators whose combined voting power exceeds the quorum threshold.

The round at which the precommits were collected is the **commit round**. Precommits from different rounds MAY be combined if they all reference the same `block_hash(B)`.

### 10.2 Irreversibility

A committed block is FINAL. There is no rollback, reorg, or undo mechanism. Any node that observes the commit material for height `h` can independently verify finality by verifying each precommit signature against the signer's registered consensus key and confirming that quorum is reached.

### 10.3 Commit Material

The commit material for height `h` consists of the set of `Precommit` messages whose signatures establish the quorum. This material:

- MUST be stored in the canonical block record for height `h` (not `h+1`); the prototype's `CommitSig` vector in `BlockRecord` is the existing representation
- is included verbatim in `block_body.commit_sigs`
- allows independent verification without re-executing the consensus rounds

**PQ overhead note**: with ML-DSA-65 and 17 quorum signers, commit material is ~56 KB per block. This is stored in the block body, not the header. The block header contains only `commit_hash = SHAKE-256(sorted_precommit_cbor)` so that lightweight clients can verify finality by checking only the header chain plus the commit hash, without downloading full commit signatures.

### 10.4 CommitSig is a Precommit message with a valid signature

The on-chain `CommitQuorumPolicy` in `pqc-consensus::commit` verifies a vector of `CommitSig` values; each `CommitSig` is a Precommit message with a valid signature. The `CommitPreimageMode` enum (`crates/pqc-consensus/src/commit.rs:43`) selects which preimage variant the verifier rebuilds:

| Mode | Preimage formula | Activation |
|------|------------------|------------|
| `Legacy` | `tagged_hash("PQC-COMMIT-V1", fork_digest[4] || height_be64 || block_hash)` (`commit.rs:221`). Self-contained, round-independent. | Default. Used by single-producer / single-validator paths and by the byte-stable replay path for blocks signed under the legacy preimage. |
| `Distributed { round }` | `tagged_hash("VIPER-VOTE-V1", fork_digest[4] || height_be64 || round_be32 || step=Precommit || block_hash)` — byte-identical to the §8.4 vote preimage at `step = Precommit`. | Active when `distributed_signing = true` (see §11). The verifier rebuilds the preimage **per CommitSig** using the sig's own `round` field (TASK-171, see §11.1 below), not a single policy-level round, so precommits collected across multiple rounds for the same `block_hash` all verify under §10.1. |

In Distributed mode, peer-collected precommits gossiped during the §7.4 Precommit step are directly usable as `CommitSig` bytes with zero re-signing — the same bytes the validator broadcast as their `SignedVote(Precommit)` are written into `block.commit_signatures` by the proposer (§11.2). This is the ADR-051 invariant: **producer and verifier build the same bytes**. Five regression-pin tests in `crates/pqc-consensus/src/commit.rs` (`adr_051_preimage_mode_tests`) lock this contract:

- `legacy_mode_matches_commit_preimage_helper` — Legacy bytes are byte-stable across the cutover.
- `distributed_mode_matches_vote_preimage_with_precommit_step_zero_round` — Distributed bytes match `vote_preimage(.., 0, Precommit, ..)`.
- `legacy_and_distributed_produce_different_preimages` — the two modes are byte-distinct (no accidental cross-verification).
- `signed_vote_precommit_roundtrip_via_distributed_mode` — an ML-DSA signature over the §8.4 Precommit preimage verifies under a Distributed-mode policy.
- `distributed_mode_accepts_precommits_from_different_rounds` — pins the §10.1 multi-round combine case (TASK-171).

The `CommitQuorumPolicy::verify` call covers the §10.1 commit condition without modification under either mode.

---

## 11. Distributed signing (ADR-051)

> *Pre-launch versions of this spec implicitly assumed a single-producer commit path: the proposer signed the block under the legacy `"PQC-COMMIT-V1"` preimage, and `commit_signatures` carried only that one signature. ADR-051 (TASK-167/170/171/172) generalised this to per-validator distributed signing for the multi-node BFT path on `viper-pq-1`.*

### 11.1 Per-validator precommit signing

Under `distributed_signing = true` (the mode mandated by ADR-051 on every multi-validator network since `viper-pq-1`):

1. Every active validator independently signs a `Precommit` message under their own consensus seed when they observe a polka for `(h, r, B)` (§7.4). The signature is over the §8.4 vote preimage at `step = Precommit`.
2. The signed `Precommit` is gossiped on the consensus pubsub topic and delivered to all peers — including the proposer for `(h, r)` — via the libp2p inbound path.
3. Each validator (proposer included) buffers gossiped precommits keyed by `(height, block_hash)` in a `pending_precommits` map until the block carrying that hash is sealed (`crates/pqcd/src/devnet.rs:146`).
4. The proposer assembles the candidate block, signs its **own** Precommit, then enters a **quorum-wait phase**: it sleeps for `distributed_signing_quorum_wait_ms` (governance-tunable, default carried in `DevnetConfig`) before sealing. During the wait, additional peer Precommits drain into `pending_precommits` (`crates/pqcd/src/devnet.rs:1457-1470`).
5. After the wait, the proposer calls `merge_distributed_precommits_into_block` (`crates/pqcd/src/devnet.rs:4082`) to drain the buffer for `(height, block_hash)` and append every peer's `(validator_address, sig_alg_id, round, signature)` tuple to `block.commit_signatures`. The proposer's own precommit was inserted earlier in the same loop iteration; the merge skips already-attached signers to avoid double-count.
6. `validate_block_commit_quorum` (`crates/pqcd/src/devnet.rs:` and the verifier in `pqc-consensus`) then enforces ≥threshold precommits per §10.1.

### 11.2 Per-signature round propagation (TASK-171)

Each `CommitSig` carries a `round: u32` field naming the round at which the signer actually signed. The verifier rebuilds the §8.4 vote preimage **per signature** using that field, not a single policy-level default (`crates/pqc-consensus/src/commit.rs:303-323`). This honours §10.1's "Precommits from different rounds MAY be combined if they all reference the same `block_hash(B)`": a quorum can mix precommits from rounds `r₀, r₁, r₂, …` provided every signature references the same block.

Before TASK-171 (commit `645c794`) the verifier built a single preimage from a hoisted policy round, silently failing any signature whose round differed — a liveness footgun that would have killed consensus the first time a timeout pushed any validator past round 0. The five `adr_051_preimage_mode_tests` in `crates/pqc-consensus/src/commit.rs:722-1163` pin both the §10.1 multi-round contract (`distributed_mode_accepts_precommits_from_different_rounds`) and the symmetric negative case (`distributed_mode_rejects_sig_with_wrong_round_field`).

In Legacy mode the preimage is round-independent and the round field is unused at the verifier (always 0 in produced blocks).

### 11.3 Quorum-wait timing parameters

| Parameter | Default | Tunable | Notes |
|-----------|---------|---------|-------|
| `distributed_signing` | `false` (devnet legacy) / `true` (multi-validator networks since `viper-pq-1`) | per-node config | Selects `CommitPreimageMode::{Legacy, Distributed}`. |
| `distributed_signing_quorum_wait_ms` | tens to hundreds of ms (operator-tuned) | per-node config | Sleep window after the proposer signs its own Precommit, before merge + seal. Setting to 0 disables waiting (proposer-only signature, equivalent to legacy single-producer). |

The wait is bounded by §14.1 round timeouts: the precommit timeout dominates, so a proposer that does not collect quorum before its own `T_precommit` fires advances the round per §7.5 and re-attempts at `r+1`.

### 11.4 Compatibility

A block built by a Distributed-mode proposer carries one signature per signer in `block.commit_signatures`, each tagged with that signer's `round`, all signing the §8.4 Precommit preimage. A node verifying that block under `CommitQuorumPolicy::with_distributed_preimage(...)` rebuilds the matching per-sig preimage and checks each ML-DSA signature in turn. The §10.1 quorum check is unchanged.

A node that lags into Legacy mode by misconfiguration MUST refuse to verify Distributed-mode commit material and vice versa: the two preimages are byte-distinct (`legacy_and_distributed_produce_different_preimages` test).

---

## 12. ForkDigest signing domains (ADR-053 §T1.2)

### 12.1 Construction

Every consensus signing preimage — Prevote, Precommit, Proposal, and the Distributed-mode CommitSig — is prefixed by the host chain's 4-byte `ForkDigest`:

```
ForkDigest = SHAKE-256(
    "VIPER-FORK-V1" || u32_be(fork_version) || genesis_validators_root,
    output_len = 4,
)
```

The reference implementation is `pqc_types::ForkDigest::compute` (`crates/pqc-types/src/fork.rs:41`). At `viper-pq-1` genesis, `fork_version = VIPER_FORK_VERSION_V1 = 1`; every hard fork bumps this value and re-derives the digest. The 4-byte digest is consumed verbatim as the leading bytes of every preimage `body` in §8.4.

### 12.2 BIP340 double-tagged outer hash (ADR-053 §T2.4)

Every preimage layered on top of the `ForkDigest` body is wrapped by the BIP340-style double-tagged hash `tagged_hash(tag, body) = SHAKE-256(H(tag) || H(tag) || body, 32)` under a per-object domain tag (`"VIPER-VOTE-V1"`, `"VIPER-PROPOSAL-V1"`, `"PQC-COMMIT-V1"` for Legacy mode commit). The construction is implemented by `pqc_crypto::tagged_hash` (`crates/pqc-crypto/src/hash.rs:111`).

The double-tag construction is immune to the CVE-2012-2459 class of attacks: an attacker cannot find any `body'` such that `tag || body` and `tag' || body'` share the same digest, because the inner `H(tag)` values each occupy a full hash block and cannot be reached by crafting `body'` alone.

### 12.3 Cross-chain replay defense

The `ForkDigest` prefix scopes every consensus signature to a specific `(fork_version, genesis_validators_root)` pair. Without it, a validator's signed vote on `viper-pq-1` would be byte-identical to a signed vote on any parallel or future chain that shares the same `"VIPER-VOTE-V1"` domain tag. With it, any verifier on a different chain reconstructs a different `ForkDigest` and the signature fails.

This is the consensus-layer counterpart to the chain-id-bound address derivation in SPEC-ADDRESS-001 §2.3 (ADR-053 §T1.3). Together the two defenses make cross-chain replay impossible at both the signature layer and the identity layer.

### 12.4 Pre-genesis placeholder

Test fixtures and pre-genesis devnet code paths use `ForkDigest::viper_pq_1_placeholder()` (`crates/pqc-types/src/fork.rs:66`) — `compute(VIPER_FORK_VERSION_V1, [0u8; 32])`. Production validators MUST configure the real digest derived from the sealed genesis validator set root (`CommitQuorumPolicy::with_fork_digest`, `crates/pqc-consensus/src/commit.rs:141`).

---

## 13. Equivocation Detection

### 13.1 Definition

Equivocation at `(h, r, step)` is the act of signing two messages of the same `step` ∈ {prevote, precommit} at the same height and round with different `block_hash` values, where at least one `block_hash` is non-nil.

Two nil-votes at the same `(h, r, step)` are NOT equivocation (a validator may retry broadcasting a nil vote due to network conditions, though well-behaved implementations SHOULD broadcast exactly once).

### 13.2 Detection

Every node MUST maintain a vote store indexed by `(validator_address, h, r, step)`. On receiving a second message at an existing key:

- If `block_hash` matches the stored message: discard the duplicate silently.
- If `block_hash` differs AND at least one is non-nil: record the evidence pair `(msg_a, msg_b)` and flag the validator as a suspected equivocator.

Evidence collection MUST NOT require trusting a single peer. A node SHOULD only accept equivocation evidence it has directly observed or received from multiple independent sources.

### 13.3 On-Chain Slashing

Equivocation evidence may be submitted as a `SlashEvidence` transaction (SPEC-VAL-001 §7). The transaction payload includes:

- `msg_a`: the first signed vote
- `msg_b`: the second signed vote
- `block_hash_a` and `block_hash_b` (at least one non-nil)

The execution layer MUST verify both signatures before applying the slash. A validator that is already jailed or exited MUST NOT be slashed again for the same incident. The slashing-side preimage reconstruction MUST use the same `VOTE_DOMAIN_TAG = "VIPER-VOTE-V1"` and the same per-sig `round` as the producer used at signing time.

---

## 14. Timeouts

Timeouts use a linear growth function to give more time in later rounds (where a network problem is likely) while keeping early rounds fast.

```
timeout(step, r) = step_base_ms + step_delta_ms × r
```

### 14.1 Default Values

| Parameter | Default | Governance-mutable | Min | Max |
|-----------|---------|-------------------|-----|-----|
| `propose_timeout_base_ms` | 3000 | yes | 1000 | 30000 |
| `propose_timeout_delta_ms` | 500 | yes | 0 | 5000 |
| `prevote_timeout_base_ms` | 1000 | yes | 500 | 10000 |
| `prevote_timeout_delta_ms` | 500 | yes | 0 | 5000 |
| `precommit_timeout_base_ms` | 1000 | yes | 500 | 10000 |
| `precommit_timeout_delta_ms` | 500 | yes | 0 | 5000 |
| `max_rounds_per_height` | 10 | yes | 3 | 100 |

### 14.2 Rationale

At `r=0`: propose=3s, prevote=1s, precommit=1s → theoretical minimum block time ~5s under good network conditions. This is conservative for Phase 1; governance may tighten it after devnet calibration.

At `r=5` (fifth retry): propose=5.5s, prevote=3.5s, precommit=3.5s → 12.5s total, giving more time if the network is partitioned.

### 14.3 Timer Semantics

Timers are local to each validator process and are not synchronized across nodes. A validator MUST NOT wait for other validators' timeouts before advancing. Clock skew between validators SHOULD be less than 500ms (NTP or equivalent); greater skew may cause unnecessary round increments.

---

## 15. PQ-Specific Considerations

### 15.1 Signature Sizes and Verification Cost

| Algorithm | Sig size | Verify/s (ref hw) | Verify latency | Consensus use |
|-----------|----------|-------------------|----------------|---------------|
| ML-DSA-65 (primary) | 3,309 B | ~4,290 | ~233 µs | default |
| SLH-DSA-SHAKE-192s (fallback) | 16,224 B | ~951 | ~1,052 µs | fallback only |

With 43 quorum precommit signatures at genesis committee size 64 (ML-DSA-65):
- Commit material: ~142 KB
- Verification time: ~10 ms (all 43 signatures)
- Acceptable for block time ≥ 1s; negligible relative to propose/prevote timeouts

At 256 validators (year 2), quorum 171 (ML-DSA-65):
- Commit material: ~566 KB per block
- Verification time: ~40 ms
- This approaches the limit of naive verification; STARK aggregation infrastructure is required before scaling beyond 256 validators.

### 15.2 Prevote + Precommit Overhead

The three-phase protocol adds prevote signatures in addition to precommit signatures. These are NOT stored in the committed block (only precommits enter the commit material). Prevote messages are ephemeral and are not persisted beyond the current height's voting period.

Total in-flight consensus message size per height per validator (ML-DSA-65):
- 1 Prevote: ~3,400 B (signature + overhead)
- 1 Precommit: ~3,400 B

For 64 genesis validators broadcasting to 63 peers each, total consensus traffic per height: ~64 × 2 × 3,400 × 63 ≈ 27 MB. The required sustained bandwidth per validator is approximately 27 MB/s at 1-second block time; the 200 Mbps minimum (25 MB/s) is tight, and 1 Gbps is recommended for genesis validators.

### 15.3 Algorithm Restrictions

- Consensus keys MUST use ML-DSA (any parameter set) as the primary algorithm.
- SLH-DSA-SHAKE-192s is permitted as a **fallback** consensus key algorithm for validators that require defense-in-depth diversification. Its verification overhead (~951 verify/s vs ~4,290/s for ML-DSA-65) means that a quorum composed entirely of SLH-DSA-192s signers would require approximately 45 ms of sequential verification at 43 signers. Nodes with SLH-DSA fallback consensus keys SHOULD be a minority of the active set.
- SLH-DSA variants other than SLH-DSA-SHAKE-192s are PROHIBITED for consensus keys.
- A consensus key's algorithm MUST have `lifecycle_status = active` at the time of use. A validator MUST rotate its consensus key before the current algorithm is deprecated.

### 15.4 Commit Hash in Block Header

To limit the header size and allow lightweight verification:

```
commit_hash = tagged_hash("VIPER-COMMIT-V1", cbor_encode(sorted_precommits))
```

where `sorted_precommits` is the set of Precommit messages sorted lexicographically by `validator_address`. The full precommit signatures are stored in `block_body.commit_sigs`. The BIP340 double-tagged outer hash (ADR-053 §T2.4) is consumed via `pqc_crypto::tagged_hash`.

This allows a node that trusts the header chain to verify that a downloaded commit payload matches the committed hash without re-running signature verification.

### 15.5 Scaling Ceiling Without Aggregation

At genesis committee size 64, naive ML-DSA-65 verification is feasible. At 256 validators, verification time approaches the minimum prevote timeout. At 1024 validators, naive verification exceeds round timeouts by an order of magnitude; STARK-based commit aggregation is a hard prerequisite for the Year 5 target. Scaling beyond 256 MUST NOT be scheduled in governance before the STARK aggregation infrastructure is operational and audited.

### 15.6 Light-client verification (cross-link to SPEC-LIGHT-CLIENT-001)

A light-client verifier (e.g. a 2046 verifier of a 2026 attestation) does not run the full BFT round protocol. Instead it follows the sync-committee protocol defined in `SPEC-LIGHT-CLIENT-001` (ADR-053 §T3.6, TASK-197): for each epoch, the active sync committee (initial size 16) signs a compact header attestation under a dedicated tagged-hash domain. The light verifier downloads epoch headers + sync-committee attestations and verifies inclusion proofs against the binary-Merkle `state_root` of each header. Sync-committee members are slashable for signing invalid headers (closing the documented Ethereum Altair flaw).

Consensus produces both the per-block `commit_sigs` (consumed by full nodes) and the per-epoch sync-committee attestation (consumed by light verifiers). Implementation: `crates/pqc-consensus/src/sync_committee.rs`. See `SPEC-LIGHT-CLIENT-001` for the full protocol.

---

## 16. viper-pq-1 launch (historical migration record)

> *This section records the one-time pre-launch migration from the static-producer prototype to the BFT consensus protocol described above. It is preserved for the audit trail. The `viper-pq-1` chain (chain_id_hex `0x76697065722d70712d31`) launched 2026-04-25 with the full §6–§12 protocol active; it has since been retired. Consensus changes on a running chain travel via Policy P-COMPAT-001 (ADR-052).*

The pre-launch prototype used a single static producer (`producer_loop` in `pqcd::devnet`). Migration to BFT consensus was incremental:

| Phase | Description |
|-------|-------------|
| A | Spec complete; code uses static `producer_loop`. |
| B (TASK-083) | Consensus engine implements `ConsensusRound` struct; prevote/precommit state machine; in-memory vote store; proposer rotation. |
| C (TASK-084) | `consensus_loop` replaces `producer_loop` on validator nodes; full nodes retain `sync_loop` (import finalized blocks). |
| D (TASK-085) | 3-node devnet uses round-based voting; view change tested; equivocation detection tested. |
| E (Phase 8 / ADR-051) | Distributed-signing path landed (TASK-167/170/171/172); per-sig round propagation (TASK-171); five `adr_051_preimage_mode_tests` pin the contract. |
| F (`viper-pq-1` launch / ADR-053) | ForkDigest signing-domain prefix (TASK-191); BIP340 double-tagged outer hash on every preimage (TASK-202); chain-id-bound addresses (TASK-192); stake-weighted churn (TASK-194); sync-committee scaffolding (TASK-197). |

The `producer_loop` is retained as `single_validator_mode` for single-node testing and development environments. It is NOT used in multi-validator deployments.

Wire format compatibility: the canonical block record format is the v0.3 layout — `BlockHeader` carries the `header_version: u16` slot and the `extension_root: [u8; 32]` reservation per ADR-053 §T1.1; `commit_sigs` carry the per-sig `round: u32` field per TASK-171. The epoch model emits `NewEpochEvent` at epoch boundaries.

---

## 17. Halt and Recovery

If `max_rounds_per_height` is reached without a commit, the node enters a **consensus halt**:

- The node MUST NOT produce or accept new blocks.
- The node MUST continue serving read APIs (`/v1/status`, `/v1/blocks`, `/v1/accounts`) with data from the last committed height.
- The node MUST emit a `pqchain_consensus_halt` metric event (Prometheus counter, see TASK-051).
- Recovery requires a governance action: either a parameter change (adjust timeouts), a validator set change (remove a misbehaving validator), or a coordinated restart with new configuration.

The halt condition is distinct from a network partition (where a minority node may not see quorum). A minority node that cannot form quorum SHOULD wait and retry rather than entering a hard halt.

---

## 18. Emergency Reconfiguration

ADR-042 introduces `ValidatorTransaction::Reconfig`, an emergency mid-epoch validator set update that bypasses normal epoch-boundary processing. This mechanism is reserved for:

- removal of a jailed validator that is actively disrupting liveness
- recovery from a mass-slashing event that drops the active set below safe quorum
- governance-ordered emergency parameter changes that cannot wait for the next epoch boundary

A `ValidatorTransaction::Reconfig` requires a supermajority governance vote (66%) and takes effect at the height following the block in which the transaction is applied. The RANDAO accumulator is NOT updated by an emergency reconfig; the proposer selection for in-progress heights continues using the epoch's existing seed.

Emergency reconfigs MUST be recorded in the block body with their full governance authorization proof to allow post-hoc auditability.

---

## 19. Safety and Liveness Properties

### 19.1 Safety

**Theorem**: If at most `f < n/3` validators are Byzantine (where `n` is the number of active validators by voting power), no two correct validators can commit conflicting blocks at the same height.

**Proof sketch**: Suppose two blocks `B` and `B'` are both committed at height `h`. Committing `B` requires ≥2/3+1 precommits for `B`, and committing `B'` requires ≥2/3+1 precommits for `B'`. By a counting argument, the two quorums must share at least one correct validator. A correct validator follows the locking rules (§9): once it has precommitted `B`, it cannot precommit `B'` at the same height without first observing an unlock polka for `B'`, which itself requires ≥2/3 prevotes for `B'` at a higher round. The lock mechanism prevents both precommits from existing at the same height for a correct validator, yielding a contradiction. Therefore no fork is possible as long as `f < n/3`. ∎

### 19.2 Liveness

**Theorem**: If at most `f < n/3` validators are Byzantine and the network is eventually synchronous, every height eventually reaches a commit.

**Proof sketch**: Under eventual synchrony, there exists a time after which all messages between correct validators are delivered within a bounded time `Δ`. Once a round `r` begins where the proposer is correct, all correct validators receive the Proposal within `Δ`, issue prevotes, observe a polka, issue precommits, and observe quorum before any timeout fires. The growing timeout schedule ensures that for some round `r* = ceil(log...)`, the timeout is large enough to accommodate `Δ`. Since Byzantine validators are bounded by `f < n/3`, correct validators always form ≥2/3+1 of voting power. ∎

### 19.3 PQ-Specific Liveness Note

The prevote and precommit timeouts MUST be larger than the maximum ML-DSA-65 verification time for the full quorum. At genesis committee size 64 (quorum 43): ~10 ms. The default `prevote_timeout_base_ms = 1000` provides a 100× margin. Governance MUST NOT reduce any timeout below 100ms without re-measuring on reference hardware.

---

## 20. Open Parameters

All parameters in §14.1 are governance-mutable. Initial values are conservative; calibration after devnet operation is expected.

| Parameter | Initial value | Rationale |
|-----------|--------------|-----------|
| `epoch_duration_blocks` | 3600 | ~1 hour at 1 s/block |
| `epoch_duration_floor` | 240 | 4× finality time floor, hardcoded |
| `max_validator_set_size` | 64 | Genesis committee; see §5.3 for trajectory |
| `propose_timeout_base_ms` | 3000 | Conservative; allows block assembly under load |
| `propose_timeout_delta_ms` | 500 | Linear growth per round |
| `prevote_timeout_base_ms` | 1000 | 100× ML-DSA quorum verification margin at 64 validators |
| `precommit_timeout_base_ms` | 1000 | Same margin |
| `max_rounds_per_height` | 10 | Hard halt after 10 failed rounds; governance can relax |

The block assembly time target of ≤500ms (from `pqc-consensus::engine` benchmarks) is NOT a timeout parameter in this spec; it is an implementation performance goal. See §16 Phase B for the benchmark requirement.

| Distributed-signing parameters | Initial value | Notes |
|-------------------------------|--------------|-------|
| `distributed_signing` | `true` on multi-validator networks | §11 — selects `CommitPreimageMode::Distributed`. |
| `distributed_signing_quorum_wait_ms` | operator-tuned | §11.3 — proposer wait window for peer precommits. |
| `activation_target_bps` | 39 | §5.4 — stake-weighted activation churn (ADR-053 §T1.5). |
| `exit_target_bps` | 313 | §5.4 — stake-weighted exit churn. |
