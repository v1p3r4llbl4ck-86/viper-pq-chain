# Fault Injection Report

**TASK-056 / TASK-065 — Phase 3-alpha exit artifact and Phase 4 gap closure**  
**SPEC-TEST-001 §4.4 — Fault injection and Byzantine validator simulation**  
**Date:** 2026-04-12 (updated from 2026-04-11)  
**Status**: Historical

> **Historical.** Report of the fault-injection runs on the Phase 3/4 devnet that preceded the retired `viper-pq-1` chain; kept unchanged for the audit trail. The scenarios are still exercised by `crates/pqcd/tests/fault_injection.rs`. "Producer" / "Follower" below are the pre-ADR-069 names of the `validator` / `full` deployment roles.

---

## Summary

This report documents the fault injection and Byzantine validator scenarios tested
as part of the Phase 3-alpha validation program (TASK-056) and the Phase 4
hardening program (TASK-065). All scenarios are exercised against the `pqcd`
devnet runtime using the integration tests in
`crates/pqcd/tests/fault_injection.rs`.

**Result: 4 scenarios tested, 4 passed.**

---

## Environment

- Prototype node: `pqcd` (Phase 4 devnet runtime, on-chain validator registry — TASK-064)
- Consensus: 3-validator set (ML-DSA-65 commit signatures), seeded from config into
  the on-chain validator registry at genesis
- Transport: ML-KEM-768 authenticated P2P (TASK-045)
- Commit quorum: ⌈2/3 × N⌉ = 2 of 3 validators required

---

## Scenario 1 — Simulated Partition Recovery

**Test:** `late_joining_follower_syncs_from_genesis`  
**File:** `crates/pqcd/tests/fault_injection.rs`

### Setup

| Role | Node | Start time |
|------|------|-----------|
| Producer | `node-1` | T=0 |
| Follower A | `node-2` | T=0 |
| Follower B | `node-3` | T=after height ≥ 4 |

Follower B is never started during Phase 1. It joins cold at Phase 2, simulating
a network partition where the node was completely cut off from the initial block
production.

### What is verified

1. Producer + Follower A converge at height ≥ 4 with matching `tip_hash` and
   `state_root`.
2. Follower B is started cold (no prior state on disk).
3. Follower B syncs all blocks from genesis via the P2P pull mechanism.
4. All three nodes converge at a height > the pre-partition height.
5. Follower B's `tip_hash` and `state_root` are identical to the producer's.
6. No node carries a sync error after convergence.

### Result

PASSED. The late-joining follower correctly syncs from genesis block by block
and reaches bit-identical chain state.

### Comparison with `follower_restart_catches_up_to_same_tip`

The restart test in `multi_node_devnet.rs` covers a follower that has prior state
on disk, shuts down, and restarts. This test covers a distinct scenario: a node
that was never online and must reconstruct chain state from block 1 purely via
P2P sync. Both paths exercise the `DiskChainStore` append path but via different
entry points.

---

## Scenario 2 — Byzantine Equivocation

**Test:** `byzantine_equivocating_commit_signature_rejected`  
**File:** `crates/pqcd/tests/fault_injection.rs`

### Setup

- A **phantom block** is built at height 1 using a different proposer address
  (`PHANTOM_PRODUCER_ADDRESS = [0x88; 32]`). Different proposer → different block
  hash H2.
- A **legitimate block** is built at height 1 with the normal proposer
  (`PRODUCER_ADDRESS = [0x99; 32]`), producing block hash H1.
- `validators[0]` produces a **valid ML-DSA-65 signature** over
  `commit_preimage(1, H2)` — the phantom block's commit preimage. This is the
  equivocating signature: cryptographically valid bytes, wrong message.
- `validators[1]` and `validators[2]` produce honest signatures over
  `commit_preimage(1, H1)`.
- The resulting commit quorum (all 3 signatures) is placed on the legitimate
  block (content = H1) and served to a follower via a KEM-authenticated
  malicious peer.

### Detection point

`validate_block_commit_quorum` in `pqc-consensus/src/commit.rs` verifies each
`CommitSig.signature` against `commit_preimage(block.header.height, block_hash)`
using the registered validator's public key. `validators[0]`'s signature fails
this check because it was produced over H2, not H1.

The error produced is `INVALID_COMMIT_SIGNATURE`.

### What is verified

1. Follower receives the equivocating block over the full KEM-authenticated P2P
   path (session handshake → block fetch → CBOR decode → quorum validation).
2. Follower rejects the block with `INVALID_COMMIT_SIGNATURE`.
3. Follower height remains at 0 after the rejection and does not advance on retry.

### Result

PASSED. The commit quorum validator correctly rejects a valid-but-equivocating
signature.

### Distinction from bit-flip corruption test

`block_with_corrupted_commit_signature_is_rejected` in `multi_node_devnet.rs`
flips a single byte in a signature, producing invalid signature bytes. This test
is different: the signature bytes are a **valid** ML-DSA-65 signature; they are
just for the wrong message (equivocation). Both produce `INVALID_COMMIT_SIGNATURE`,
confirming that the verifier does not distinguish between "garbage bytes" and
"valid signature over a different block" — any signature that does not verify
against the current block's hash is rejected.

---

## Scenario 3 — Byzantine Majority Liveness Halt (TASK-065)

**Test:** `byzantine_majority_liveness_halt`  
**File:** `crates/pqcd/tests/fault_injection.rs`  
**Closes:** Gap A from Phase 3 report

### Setup

- 3 validators configured; quorum threshold = 2 (⌈2/3 × 3⌉).
- A height-1 block is built and signed by only `validators[0]` (1 of 3 validators).
  `validators[1]` and `validators[2]` withhold their commit signatures — Byzantine
  majority (2 of 3) refuses to sign.
- The block with 1 commit signature is served to a follower via the KEM-authenticated
  P2P path.

### Detection point

`validate_block_commit_quorum` in `pqc-consensus/src/commit.rs` counts valid commit
signatures and checks `valid_commits >= policy.quorum_threshold()`. With 1 valid
signature and threshold = 2, the check fails:

```
INSUFFICIENT_COMMIT_QUORUM: required 2, got 1
```

### What is verified

1. Follower receives the undersigned block over the full KEM-authenticated P2P path.
2. Follower rejects the block with `INSUFFICIENT_COMMIT_QUORUM`.
3. Follower height remains at 0 — no advancement occurs despite repeated delivery.

### Result

PASSED. The quorum threshold check correctly enforces liveness-halt semantics:
when a Byzantine majority withholds commit signatures, no block can be accepted
and the chain does not advance.

### Distinction from equivocation scenario (Scenario 2)

In Scenario 2, all 3 validators produce signatures but one signs the wrong block
(equivocation). In Scenario 3, only 1 validator signs at all (withholding). Both
prevent quorum, but via different code paths:
- Equivocation → `INVALID_COMMIT_SIGNATURE` (verification failure for the equivocating sig)
- Withholding → `INSUFFICIENT_COMMIT_QUORUM` (too few valid signatures)

The distinction matters: equivocation is detectable and attributable; withholding
is a DoS-style liveness attack with no on-chain attribution in Phase 4.

---

## Scenario 4 — Fork-Choice Split-Brain (TASK-065)

**Test:** `split_brain_fork_chain_rejected`  
**File:** `crates/pqcd/tests/fault_injection.rs`  
**Closes:** Gap B from Phase 3 report

### Setup

A single split-brain peer serves two blocks:

| Block | Height | prev_hash | Proposer | Quorum |
|-------|--------|-----------|---------|--------|
| A1 | 1 | ANCHOR | `PRODUCER_ADDRESS` | full honest |
| B2 | 2 | H(B1_phantom) | `PHANTOM_PRODUCER_ADDRESS` | full honest |

B1_phantom is an internal phantom block (height 1, same ANCHOR prev, different
proposer). It is **not served to the follower** — it exists only to establish
the fork tip so B2 can have a different prev_hash than A1.

The split-brain peer reports tip height = 2, so the follower fetches both heights
sequentially.

### Detection point

`ChainStore::validate_stored_block` in `pqc-consensus/src/chain.rs` checks:

```
B2.header.prev_hash (= H(B1_phantom)) ≠ follower's tip (= H(A1))
→ PARENT_HASH_MISMATCH: block parent does not match current tip
```

Note that B2 has a **valid** full commit quorum (`validate_commit_proof` passes
before `validate_stored_block` is called). The rejection is purely at the
chain-linkage level, not the cryptographic level.

### What is verified

1. Follower fetches and accepts A1 from the split-brain peer → height advances to 1.
2. Follower fetches B2 → full commit quorum validation passes.
3. Follower rejects B2 with `PARENT_HASH_MISMATCH` because B2's parent is not A1.
4. Follower height remains at 1 after repeated delivery of B2.

### Result

PASSED. The chain layer correctly rejects a cryptographically valid block whose
parent hash does not match the accepted chain tip.

### Fork-choice behaviour documented

This test documents the **first-come-first-served** fork-choice behaviour of Phase
3/4: the follower accepts whichever height-1 block it receives first (A1 in this
case), then rejects any height-2 block whose parent is not A1. There is no active
fork-choice protocol — the protocol does not compare chain weight, accumulated
difficulty, or any other metric to prefer one fork over another.

This is the correct behaviour for the Phase 4 threat model: a Byzantine peer
cannot replace an accepted chain segment by serving a competing fork. Only a chain
that shares the accepted history can extend the tip.

**Remaining gap:** True split-brain — where two honest nodes each accept a
different height-1 block because they were partitioned — requires a network
partition simulation and an active fork-choice rule (ADR-007 / Phase 5 track).

---

## Remaining Gaps (not closed in TASK-065)

The following scenarios remain blocked and are deferred to Phase 5 or the HotStuff
consensus track (ADR-007).

### 1. Dynamic validator set churn

**What:** A validator joining or leaving the set mid-stream should not allow the
equivocation check to be bypassed (e.g., by claiming the equivocating signer was
not yet in the set at that height).

**Current status:** On-chain validator registry is implemented (TASK-064);
`CommitQuorumPolicy::from_state_store()` reads active validators at genesis. Full
height-indexed membership — where `ValidatorExit` or `ValidatorRegister` committed
at height H affects quorum only for blocks after H — is Phase 5 (see GAP-05 in
`specs/audit-scope.md`).

**Phase 5 path:** Height-indexed quorum membership in `DiskChainStore`; replay
must use per-height policy snapshots.

### 2. Network-level message dropping and reordering

**What:** The P2P sync layer should handle packet loss, reordering, and partial
delivery without producing incorrect chain state.

**Why not tested:** P2P is implemented as sequential HTTP pulls with a fixed
retry loop. There is no mechanism to inject network-level faults at the test level
without OS-level traffic shaping.

**Phase 5 path:** Integration with a network chaos layer (e.g., `tc netem` or
Toxiproxy) in the CI environment.

### 3. True split-brain with partition recovery

**What:** Two partitioned honest nodes each accept a different chain at height 1,
then reunite. One must roll back and adopt the other's chain.

**Why not tested:** Requires a fork-choice rule implementation and the ability to
roll back committed state — neither is in scope for Phase 4.

**Phase 5 path:** Fork-choice rule (longest chain / highest weight) + state
rollback path.

---

## Reference

- `crates/pqcd/tests/fault_injection.rs` — test implementation (Scenarios 1–4)
- `crates/pqcd/tests/multi_node_devnet.rs` — baseline multi-node scenarios
- ADR-007 — consensus protocol track (HotStuff deferred)
- ADR-020 — Phase 3 `consensus_key_rotate` record-only implementation gap
- ADR-022 — Phase 4 on-chain validator staking lifecycle (TASK-064)
- SPEC-TEST-001 §4.4 — fault injection test requirements
- `specs/audit-scope.md` — GAP-04, GAP-05 (validator set gaps)
