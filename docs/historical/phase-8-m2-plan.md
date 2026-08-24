# Phase 8 — Milestone M2: Dynamic Validator Set (TASK-113)

**Doc ID**: phase-8-m2-plan
**Status**: **CLOSED — retained as design rationale + retrospective**. M2 implementation complete 2026-04-22 (code-path steps 1–5 delivered same day as plan publication, faster than the 2–3 week estimate). Step 6 landed `#[ignore]`d with documented harness limitation. Step 7 binary deployed to devnet-2 2026-04-22. M2b N+2 follow-ups (TASK-166/167/170/171/172) all closed on `develop` by 2026-04-23. ADR-053 §T1.5 (TASK-194, 2026-04-24) subsequently replaced the count-based churn with stake-weighted churn — see SPEC-VAL-001 v0.3 banner. The chain is now `viper-pq-1` (launched 2026-04-25). This plan stays for design-decision archival; no further work is tracked here.
**Owner**: alberto
**Date**: 2026-04-22 (written), 2026-04-23 (retrospective added)
**Depends on**: ADR-035, ADR-042 (accepted); Phase 8 M1 on-chain (`develop @ 71dd44d`)
**Supersedes**: n/a (first M2 plan)

## 0. TL;DR

M2 turns the validator set from a config-file constant into an
on-chain quantity the consensus engine reads per block. Today
(2026-04-22) every component that needs "who are the validators"
reads `config.devnet.validators` — a frozen list baked into every
node's JSON config at boot. After M2 the same question is answered by
`StateStore::validators_in_order()`, which already exists (TASK-127
epoch model) but is not yet wired into the hot path.

The user-visible consequence is **join / leave at epoch boundaries
without a node restart**. Operationally, this closes the gap between
Phase 8's promised dynamic validator set (ADR-035) and the current
Phase-3-era static list, unblocking the external-cohort recruitment
(M4) and the 5-validator-for-7-days mainnet exit criterion.

Scope is deliberately narrow:
- in: plumbing per-block `StateStore` → consensus-hot-path queries,
  CommitQuorumPolicy rebuilt on demand, proposer rotation reading the
  Active set at each epoch boundary, fee distribution reading the same
  Active set per block, integration tests for join/leave scenarios.
- out: on-chain `ValidatorPeerId` registry publication (deferred to
  M2b), signed-binding verifier-chain (M2c), slashing implementation
  (slashing rules are in ADR-035 but landing them is its own
  milestone), governance-driven param changes (epoch length, churn
  limits) — those rely on M2 plumbing but are separate bodies of work.

**Effort estimate**: 2–3 calendar weeks solo. **Budget**: €0
(devnet-2 hosts already paid). **Rollback**: revert the M2 branch; the
`CommitQuorumPolicy` persisted-to-RocksDB format does not change
(M2 reconstructs at validation time from state, but the on-disk
snapshot schema stays the same), so nodes on the old code can re-open
M2-touched databases without migration.

**Exit criterion**: 3-node devnet-2 accepts a 4th validator submitting
a `ValidatorRegister` tx; at the next epoch boundary the new
validator becomes Active, the producer rotation picks it up, blocks
it proposes are accepted into quorum by the existing three, fee
distribution includes it, and `StateStore::active_validators()`
returns four entries on every node. A symmetric leave test passes in
the same run.

---

## 1. Context and Motivation

### Where M1 landed us

Phase 8 M1 (`71dd44d` on `develop`, cutover 2026-04-22T11:13Z) put the
transport on libp2p and retired the SSH tunnel. The consensus engine
it feeds is otherwise unchanged from Phase 3: the set of validators is
a config-file constant, hard-wired into proposer rotation, fee
distribution, and commit-quorum validation.

Observable pain:
- There is no way to add or remove a validator without a coordinated
  restart of all three nodes with a new `node.json`. The external-
  cohort recruitment path (M4) depends on exactly the opposite:
  submit a tx, wait for the next epoch boundary, be in the set.
- The epoch-transition code from TASK-127 (ADR-042) activates
  `Candidate` → `Active` validators at each boundary, but no consumer
  of the validator set is listening. `StateStore::process_epoch_transitions`
  runs to completion on every node and has zero effect on block
  production downstream.
- `CommitQuorumPolicy` is frozen in each node's RocksDB storage
  backend at open time. A new `Active` validator's public key is
  never added to the policy, so any block they sign fails commit-
  quorum validation (`UnauthorizedSigner`). Any validator that
  decides to exit keeps signing-weight in the policy forever, which
  is also wrong (they could re-key and sign bogus commits against
  the old pubkey).

### What ADR-035 and ADR-042 gave us

- `StateStore.validators`: `HashMap<operator_address, ValidatorRecord>`
  with `status: Candidate | Active | Unbonding | Exited`
- `StateStore::validators_in_order()` (deterministic by operator
  address) + `StateStore::active_validators()` (filtered for Active)
- Churn limits per epoch: `max(4, active_count / 256)` activations and
  `max(4, active_count / 256)` exits, applied atomically at epoch
  boundaries by `process_epoch_transitions`
- `EpochInfo::for_height` + `is_epoch_boundary` helpers for height-
  based boundary detection
- `advance_randao` accumulator (SHAKE-256) + `select_epoch_proposer`
  (hash-based sortition) for proposer selection from the Active set
- `CommitQuorumPolicy::from_state_store(store)` — already implemented
  at `crates/pqc-consensus/src/commit.rs:116`, not yet called

### What's left to *actually ship* M2

ADR-035 defines **what**. M2 fills in **how** at the integration
layer the 3-node devnet-2 needs today:

- Proposer rotation reads `active_validators()` per epoch (not a
  frozen array at startup).
- Fee distribution reads `active_validators()` per block.
- `CommitQuorumPolicy` is reconstructed from state at commit-proof
  validation time, not held as a frozen object on the storage backend.
- Epoch boundaries emit a signal the consensus loop observes, so the
  validator-address vector used for rotation is refreshed without
  restart.

---

## 2. Objectives and Out-of-Scope

### In scope (M2)

1. Dynamic proposer selection: `crates/pqcd/src/devnet.rs::consensus_loop`
   queries `store.active_validators()` at every epoch boundary, using
   the RANDAO accumulator for deterministic per-height selection.
2. Dynamic fee distribution: `crates/pqc-consensus/src/engine.rs` +
   `recovery.rs` replace `&config.validator_pool` with a `&[Address]`
   slice derived from current `active_validators()` at block-apply
   time.
3. Dynamic CommitQuorumPolicy: validation path calls
   `CommitQuorumPolicy::from_state_store(store)` on a snapshot just
   before checking commit signatures; `RocksDbChainStore` stops
   holding a frozen `CommitQuorumPolicy` object.
4. Epoch-boundary notification: `process_epoch_transitions` emits an
   event (tokio broadcast channel or a `bool` returned to
   `apply_block`) the consensus loop observes to refresh its in-memory
   `active_set` cache.
5. Integration tests exercising the four scenarios that make the new
   plumbing visible:
   - cold network genesis with 3 validators (existing behaviour
     preserved)
   - validator join: epoch N has 3, epoch N+1 has 4 after a
     `ValidatorRegister` tx in epoch N's block range
   - validator leave: epoch N has 4, epoch N+1 has 3 after a
     `ValidatorExit` tx
   - churn-limit enforcement: 5 candidates submit in the same epoch,
     only `max(4, active/256)` activate at the boundary

### Out of scope (explicitly deferred)

| Item | Deferred to |
|------|-------------|
| On-chain `ValidatorPeerId` publication | **M2b** — requires a new tx type + verifier-chain hookup; today the allow-list is pinned in `viper_libp2p.validator_peer_ids` group_vars |
| Signed PeerId binding with timelock | **M2b** |
| Slashing (equivocation / downtime) | **M2.1 / M3** — ADR-035 §slashing; separable from set-dynamism |
| Governance-driven epoch / churn changes | requires the tx type, governance proposal path, and a timelock; own milestone |
| Validator-key rotation (rotate pubkey on-chain) | **M2c** |
| NAT traversal (DCUtR + circuit-relay-v2) | Phase 9+ |
| External-cohort onboarding automation | M4 (depends on M2) |

### Non-goals

- Zero-downtime rolling upgrade. Existing 3 nodes stop and restart
  together at the M2 release window; devnet-2 accepts the maintenance
  gap.
- Backwards-compatible binary. An M1 node and an M2 node exchanging
  commits will disagree on who the current validators are (the M1
  node reads config; the M2 node reads state). All three devnet-2
  nodes must be on the M2 binary in the same window.

---

## 3. Known blockers (from the 2026-04-22 scope audit)

### 3.1 `CommitQuorumPolicy` is frozen in the RocksDB storage backend

At `crates/pqc-consensus/src/storage_rocksdb.rs:72`, the
`RocksDbChainStore` holds `commit_policy: CommitQuorumPolicy` as an
immutable field populated once at `open_*`. Validation calls through
`validate_block_commit_quorum(block, &self.commit_policy)` use that
frozen object (`storage_rocksdb.rs:929–930`, also `storage.rs:1054`).

Making validator set dynamic means this object must be reconstructed
from the current `StateStore` at each validation. Two practical
approaches:

1. **Reconstruct per-block at validation time.** Validation takes
   `&StateStore` as input (already available on the apply path).
   `CommitQuorumPolicy::from_state_store` is ~O(active_count) and runs
   once per block — negligible vs. signature verification cost.
   Storage backend stops holding the object.
2. **Cache on the validation path.** Rebuild only when the epoch
   changed since last validation, cache otherwise. Premature
   optimisation given validator counts stay small in M2.

Recommendation: go with (1). Simpler, no invalidation race to get
wrong.

### 3.2 Proposer rotation captured once at consensus-loop startup

`devnet.rs:787–798` builds `validator_addresses: Vec<[u8; 32]>` once
at `build_devnet_node` time and passes it to `consensus_loop` as a
move-captured immutable. The loop never refreshes it. ADR-042's
`select_epoch_proposer` and the epoch-boundary churn machinery in
`StateStore::process_epoch_transitions` run fine, but the proposer
address vector they'd inform is out of reach.

Fix: the consensus loop reads `store.active_validators()` at each
epoch boundary. Either push the store reference into the loop or pull
the refreshed vector via a channel. Recommendation: push the
`SharedLiveNodeState` in (same pattern as TASK-135 step 12b) and let
the loop lock briefly on each boundary.

### 3.3 Fee distribution uses `&config.validator_pool`

`engine.rs:202` and `recovery.rs:228` call `distribute_block_fees(&config.validator_pool, ...)`.
Swapping to `&store.active_validators()` is mechanical, but the
ordering must be deterministic and identical across all nodes or
every node disagrees on who received how many fees and the state
root diverges.

`StateStore::validators_in_order()` already sorts by operator
address. Fine. The only subtlety: fee-receiver list computed at
block-apply time uses the `StateStore` *before* applying the block's
own validator-set changes — otherwise a validator registered inside
the block is paid for that block. Pin the semantic explicitly in the
spec note.

### 3.4 `EpochInfo` feedback to the consensus loop

`process_epoch_transitions` runs inside `apply_block` and has no
side-effect channel to the `consensus_loop` or `producer_loop`
tasks. The in-memory `active_set` cache they'd read is detached from
the state mutation.

Option A: broadcast channel that `apply_block` emits into on boundary
crossings; consensus loop subscribes.
Option B: remove the cache entirely — loop re-reads `active_validators()`
on each iteration. Costs a short mutex on every block but avoids an
event channel.

Recommendation: option B. The cost is negligible and the cache
invalidation bug class is eliminated.

---

## 4. Implementation sequence

| Step | Scope | Duration | Acceptance |
|------|-------|----------|------------|
| 1 | Fee distribution: switch `distribute_block_fees` to read from `StateStore` instead of `config.validator_pool`; unit tests for ordering stability + "validator registered this block is not paid this block" invariant | 1 d | `cargo test --workspace --lib` green; no regressions on existing block replay equivalence tests |
| 2 | `CommitQuorumPolicy` unfrozen: remove the field from `RocksDbChainStore`; every call site rebuilds via `CommitQuorumPolicy::from_state_store(store)`; storage-backend snapshot + recovery paths adjusted | 3 d | `snapshot_export_import_roundtrip` + `snapshot_full_replay_equivalence` still pass; new test `validator_join_changes_quorum_at_epoch` passes |
| 3 | Consensus loop queries `active_validators()` per iteration (option B); remove the captured `validator_addresses` Vec from the `consensus_loop` entry signature | 1 d | `bft_consensus` integration test passes after migration |
| 4 | Integration test: validator join scenario — 3 validators bootstrap, in-block submit `ValidatorRegister`, epoch boundary activates, producer rotation emits a block signed by the 4th, other 3 accept it | 2 d | `multi_node_devnet::validator_join` new test passes |
| 5 | Integration test: validator leave scenario — `ValidatorExit` submitted, epoch boundary transitions to Unbonding then Exited, proposer rotation no longer emits for that address, commits stop being accepted from it | 2 d | `multi_node_devnet::validator_leave` new test passes |
| 6 | Integration test: churn-limit enforcement — 5 candidates register in the same epoch, only 4 activate at boundary | 1 d | `multi_node_devnet::churn_limit` new test passes |
| 7 | Devnet-2 deploy: new binary, restart, submit `ValidatorRegister` for a 4th operator (canary), wait for epoch boundary, verify 4 active validators produced ≥ 10 blocks each | 1 d | operator-run on devnet-2, evidence in `reports/m2/<date>.md` |

Total: ~11 engineering days + 1 ops day = ~2–3 calendar weeks solo.

---

## 5. Risks

- **State-root divergence via non-deterministic fee ordering.** If
  any node reads `active_validators()` in a different order from the
  others at the same block height, the fee-distribution mutations
  write different state roots. Mitigation: `validators_in_order`
  already sorts by operator address; pin the ordering invariant with
  a spec note and a pin-test (`active_set_ordering_is_byte_stable`).
- **Epoch-boundary race with block production.** If
  `process_epoch_transitions` activates a new validator at height H
  while the consensus loop has already captured the pre-H active set
  for the block it's about to sign, the pre-H producer is still
  chosen for block H but the post-H quorum policy is used to validate
  it — off-by-one. Mitigation: make `epoch_for_height(H)` the sole
  driver of the active-set query; both the selector and the quorum
  reconstruction read from the same `state.at_height(H)` snapshot.
- **Rollback hardness.** An M1 node reading the M2 RocksDB backend
  still opens correctly (storage schema unchanged) but its static
  `commit_policy` will disagree with whatever state the M2 nodes
  accumulated. Fine in practice on devnet-2 — rollback means "all
  three nodes down-version in the same window, and no `ValidatorRegister`
  txs were admitted during the M2 run." Pin this in the RUNBOOK.

---

## 6. Out-of-scope M2b (PeerId registry) — pre-work

M2 as scoped does not publish PeerId on-chain. But the M2 dynamic
set makes the existing `viper_libp2p.validator_peer_ids` group_vars
allow-list obsolete (it's a one-line config pinned at playbook time).
Once M2 ships, every node has the source of truth in the state store.
M2b does three things on top of M2:

1. New tx type `ValidatorBindPeerId` that carries a signed PeerId
   binding (signed by the validator's operator key).
2. `ValidatorRecord.peer_id: Option<PeerId>` field + a verifier
   (peer's libp2p identify key must hash to the claimed PeerId per
   SPEC-P2P-002).
3. `pqcd::p2p::is_tx_admitted` reads `state.active_validators()` for
   allow-list membership instead of the pinned `validator_peer_ids`.

Mentioned here so the M2 tests don't accidentally paint us into a
corner (e.g. hashing the PeerId differently from M2b's expectation).

---

## 7. Test harness additions

New integration tests live in `crates/pqcd/tests/multi_node_devnet.rs`
(the same file already exercises mixed-binary + malicious-peer flows).
Each new test:

- Uses the existing `start_from_config_path` helper with a 3-validator
  baseline.
- Submits a `ValidatorRegister` or `ValidatorExit` tx via
  `LiveNode::inject_tx` (the same admission path production uses).
- Fast-forwards `epoch_duration` by setting it to a small value in
  the devnet config (e.g. `epoch_duration: 5 blocks` so the test
  finishes in ≤ 5 s of wall-clock time).
- Asserts on both the state (`store.active_validators()`) and on the
  consensus behaviour (block proposer, fee receiver, quorum
  acceptance) across all three in-process nodes.

Prior-art: `snapshot_cold_start_network` in `snapshot_sync.rs` is the
template for a clean multi-node harness with real RocksDB.

---

## 8. Exit checklist

- [ ] All 7 steps in §4 complete, each with at least one passing test.
- [ ] `cargo test --workspace --lib` and
      `cargo test -p pqcd --tests` green (baseline + new tests).
- [ ] `cargo clippy --workspace -- -D warnings` clean.
- [ ] Devnet-2 validator-4 join run recorded in `reports/m2/<date>.md`
      with height / state_root convergence across all 4 nodes.
- [ ] Devnet-2 validator-4 leave run in the same report file, showing
      the set returning to 3.
- [ ] `TASKS.md` TASK-113 flipped to `[x]` with a done-date + commit
      references.
- [ ] `CHANGELOG.md` Phase 8 M2 entry added under [Unreleased] Added.
- [ ] `ROADMAP.md` Phase 8 progress table: M2 → code complete.
- [ ] RUNBOOK §21 drafted (M2 ops — validator register/exit
      procedure, verifying transition at epoch boundary, rollback
      constraints).

---

## 9. Out-of-session starting point

Next session can begin at **Step 1** (fee distribution) without any
additional prep. All input artefacts (ADR-035, ADR-042, the scope
audit in this doc, the TASK-127 epoch code) are committed on
`develop`. The existing devnet-2 cluster is stable at
`pqchain_p2p_peers_connected = 2` and will remain on M1 transport
throughout M2 development — no interaction between the two
milestones.

---

## 10. Retrospective (added 2026-04-23)

The written plan above estimated 2–3 calendar weeks solo; actual
delivery was **1 day** for the in-scope code path (§3–§7 Steps 1–5),
with one step `#[ignore]`d on a real harness limitation and a
follow-on M2b N+2 scope (ADR-051) that absorbed what was originally
planned as a smaller "per-role dispatch" item.

### What shipped (2026-04-22)

| Step | Artefact | Commit |
|------|----------|--------|
| 1 — Fee distribution | `StateStore::active_validators()` read in engine + replay path | `bcf77b9` |
| 2 — CommitQuorumPolicy rebuild per-block | removed frozen field from `RocksDbChainStore` | `73af1db` |
| 3 — consensus_loop dynamic read | `state.active_validators()` per iteration | `dddb062` |
| 4 — State→policy contract pin tests (5) | `commit.rs::m2_dynamic_policy_tests` | `3b42239` |
|    — ADR-042 churn-limit pin tests (3) | `pqc-state::tests` `max(4, active/256)` | `db0f508` |
| 4 FULL — real multi-node validator_join | `validator_register_flows_through_devnet_and_follower_converges` | `587f253` |
| 5 FULL — register + exit end-to-end | `validator_exit_flows_through_devnet_and_follower_converges` | `fbef765` |
| 6 | `rapid_fire_multi_operator_registrations_converge` — `#[ignore]` with documented LocalProposer key-holding limit (Phase 9+ needs dynamic keystore layer) | `65d9db1` |
| 7 — devnet-2 rolling binary deploy | all 3 nodes on sha256 `6265492c…` from commit `0fb5006` | n/a |

### M2b N+2 expansion (ADR-051, 2026-04-23)

What the plan §3.2 framed as "per-role proposer dispatch captured
once at startup" turned out to require a deeper rework than the
original M2 scope. Split out and tracked separately:

| Task | Scope | Commit |
|------|-------|--------|
| TASK-166 | ADR-051 preimage-mode unification — `CommitPreimageMode::{Legacy, Distributed { round }}` + `commit_preimage_for_mode` single-source-of-truth helper | `464e15c` |
| TASK-167 | Per-role dispatch in consensus_loop + two-phase block gossip + 3-node integration test | `f5228dd`, `55a3226`, `70ff826`, `b2ba6f3`, `686c706` |
| TASK-170 | 3-node test 20/20 determinism + `LocalProposer::advance_tip` fix for the stale-tip bug on non-proposer import | `8a0a719` |
| TASK-171 | Round propagation in Distributed preimage per SPEC §10.1 — `CommitSig.round: u32`, per-sig preimage rebuild, multi-round pin test | `645c794` |
| TASK-172 | libp2p Transaction gossip → mempool forwarder — `InboundP2pEvent::Transaction` variant + `handle_inbound_transaction` + un-hack TASK-12 test | `f86337a` |

### Why it delivered so fast

- **Parallel work convergence**: the M2 plan was written immediately
  after M1 landed, but several preparatory items (`StateStore::active_validators()`
  from TASK-127; per-block policy plumbing from the TASK-113 scope
  audit in this doc) were already on `develop` or one merge away.
  The plan catalogued work that was largely ready to ship.
- **Scope discipline**: §2 kept the in-scope list tight. The harder
  items (dynamic keystore for registrations beyond N=4, VDF-delayed
  RANDAO) were explicitly deferred to Phase 9, avoiding the scope
  creep that typically inflates multi-week estimates.
- **Pin-test first culture**: TASK-113 steps 3b/4 delivered pin tests
  ahead of the code, which meant each code change had a byte-level
  oracle from day one.

### Lessons for M4 / later milestones

1. **Plan estimates were 15–20× too long for in-scope code**. If the
   inputs are on `develop` already, assume "days not weeks". Timelines
   should budget recruitment/audit engagement gate-waits, not code.
2. **Test harness capacity is a real constraint**. Step 6's
   `#[ignore]` is documented as a LocalProposer key-holding limit —
   a pattern worth generalising: tests with synthetic 3-key harnesses
   cannot cover dynamic N>4 scenarios without a keystore layer that
   mirrors production. Phase 9 follow-up.
3. **A plan written same-day as its execution is a transcript, not a
   forecast**. For future milestones, either write the plan days
   ahead with honest unknowns, or mark it `retrospective` from the
   outset.

### Phase 8 exit posture

M1 + M2 + M3 code all complete; M4 archival code complete (TASK-160..165,
2026-04-23). The remaining gate is M4 workstream (b) external cohort
recruitment — unchanged by anything in this retrospective.
