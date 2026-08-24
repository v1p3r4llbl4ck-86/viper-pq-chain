# Phase 8 M1 — TASK-135/136/137 implementation plan

Drafted 2026-04-22 during the overnight sprint. Companion to
`docs/historical/phase-8-m1-plan.md` (Cluster A/B/C/D breakdown) and
`specs/p2p-libp2p.md` (SPEC-P2P-002). Focused on the three remaining
message-routing tasks that are deliberately deferred from autonomous
overnight work because they modify consensus, block-store, and mempool
paths that are load-bearing for the running devnet-2 (even in
observation mode the code compiles and links into pqcd).

## Scope recap

| Task     | Message class   | Topic                              | Primary emitter                  | Primary receiver                       |
|----------|-----------------|------------------------------------|----------------------------------|----------------------------------------|
| TASK-135 | Block           | `/viper/<chain>/blocks/1.0.0`      | Proposer commit path             | Followers' block-store insert          |
|          | BlockRequest    | `/viper/block-fetch/1.0.0` (r/r)   | Any node on height gap           | Any node with the requested range      |
| TASK-136 | ConsensusVote   | `/viper/<chain>/consensus/1.0.0`   | Validator round loop (pre/commit)| Proposer + peers' vote aggregator      |
| TASK-137 | Transaction     | `/viper/<chain>/transactions/1.0.0`| HTTP `/v1/txs` admission path    | Peers' mempool admission               |

## What already exists vs. what needs to be added

Already shipped (M1 cluster A/B):
- `pqc_p2p::GossipMessage` envelope with `MessageType` discriminant
  (0x01 Block / 0x02 ConsensusVote / 0x03 Transaction / 0x04 ValidatorUpdate)
- `SwarmHandle::publish(GossipMessage)` and the async event stream
  (`SwarmEventRx` → `ViperSwarmEvent::Message { msg_type, chain_id, payload }`)
- `crate::p2p::start_libp2p` spawning the observation task in pqcd
- Deterministic PeerId via SHA3 seed (so any code path can bind
  a validator address → PeerId by reading node.json)

Missing (to be added in 135/136/137):
- A shared handle stored in `LiveNodeState` so the consensus/block
  commit/mempool admission code can publish. Today the handle lives
  in the observation task and is dropped on shutdown; it never hands
  out references.
- Request-response protocol for `block-fetch` (not gossipsub).
  `pqc-p2p` doesn't yet expose this — needs `libp2p_request_response`
  behaviour + `SwarmCommand::Request { peer, range }` and
  `ViperSwarmEvent::BlockRequest { req, respond }` variants.
- Validator→PeerId registry. `pqc-p2p` has `ValidatorPeerId` the type
  but no runtime registry. The genesis validators array already has
  `node_id` fields from which deterministic PeerIds can be derived.
- Double-path-safe emit: while `libp2p.enable` is false the code must
  short-circuit so nothing in consensus changes. While true in
  observation-mode, emits succeed but the HTTP path remains
  authoritative — handy for A/B canary before full cutover.

## Proposed implementation sequence

**Phase 1 — shared SwarmHandle (prereq, ~4h):**

1. Change `start_libp2p` to return `(JoinHandle, Option<Arc<SwarmHandle>>)`
   instead of `(JoinHandle)`. The `Arc<SwarmHandle>` is cloneable and
   Send + Sync (libp2p's handle already is via channels).
2. Add `pub p2p_handle: Option<Arc<SwarmHandle>>` to `LiveNodeState`.
   Populated at bootstrap in `devnet.rs` right after `start_libp2p`
   returns.
3. Add a helper `fn publish_if_enabled(state, msg_type, payload)` that
   no-ops when the handle is `None`. All subsequent emit sites use
   this helper; it becomes the single choke-point that enforces the
   `libp2p.enable=false → no-op` invariant.

**Phase 2 — TASK-136 consensus vote (smallest, ~6h):**

4. In `consensus_loop` (or its successor once proposer rotation runs
   full BFT — see SPEC-CONSENSUS-001 §13 phase C), when a validator
   produces a pre-vote or commit signature, call `publish_if_enabled`
   with `MessageType::ConsensusVote` and a CBOR-encoded
   `ConsensusVoteMsg { height, round, step, validator_addr, sig }`.
   Wire format is defined in SPEC-P2P-MESSAGING §6 (`msg_type` 0xC1/0xC2/0xC3
   inner discriminant + the envelope's 0x02).
5. Add a `vote_inbound` task that consumes `ViperSwarmEvent::Message`
   matching `MessageType::ConsensusVote`, validates the PQ sig against
   the genesis validator set, and hands the vote to the consensus
   aggregator. In observation mode: log-only.
6. Integration test: 2-validator in-process swarm where each side
   produces a vote; both sides see the other's vote within the
   gossipsub heartbeat interval.

**Phase 3 — TASK-137 tx gossip (medium, ~8h):**

7. In the HTTP `/v1/txs` handler, after mempool admission succeeds,
   call `publish_if_enabled` with `MessageType::Transaction`.
8. Add a tx-inbound task that routes `MessageType::Transaction`
   messages through the same mempool admission path the HTTP
   handler uses (shared fn to avoid divergence).
9. ValidatorPeerId binding: when the validator-private topic
   `/viper/<chain>/validators/1.0.0` sees a peer, cross-check its
   PeerId against the genesis validator set. Reject transactions
   gossiped from a peer that does not claim a validator PeerId.
   (Drop-only; pre-cutover this is pure defence-in-depth.)

**Phase 4 — TASK-135 block propagation (largest, ~12h):**

10. `publish_if_enabled(MessageType::Block, cbor(block_with_sigs))`
    on the proposer commit path.
11. Block-inbound task: validate the block against chain tip, detect
    height-gap, and enqueue fetch requests if the block is >1 ahead.
12. Request-response `/viper/block-fetch/1.0.0` needs new
    `pqc-p2p` surface area:
    - `behaviour::ViperBehaviour` adds a `libp2p_request_response`
      instance with codec `block_fetch::Codec`.
    - `SwarmCommand::RequestBlocks { peer, from_height, to_height }`
      enqueues a request. On response, emits
      `ViperSwarmEvent::BlocksReceived { blocks }`.
    - Test: 2-node swarm where node B is 5 blocks behind; on first
      gossip, it issues a range fetch and catches up within 2 s.
13. Integrate with the existing sync loop (`sync_loop` in devnet.rs)
    by preferring libp2p fetch when the handle is present, falling
    back to HTTP polling otherwise. Strict choice — never both at
    once, otherwise the two paths race and double-insert.

## Acceptance criteria (to revisit at M1 exit)

- [ ] 3-validator BFT run where every commit lands on every node
      via libp2p only (`libp2p.enable=true`, tunnel stopped)
- [ ] Height gap test: kill a follower for 5 min, restart, verify
      it catches up via block-fetch without HTTP
- [ ] Mempool test: inject tx via HTTP on node A, observe tx ID
      present on nodes B and C mempool within 3 s
- [ ] Soak (TASK-144): 1h, 3 nodes, no DEGRADED samples
- [ ] `phase-8-m1-pre` tag rollback works end-to-end
      (rollback-libp2p.yml → Phase 6 operational)

## Risk register (focused on routing work)

- **Consensus vote replay.** libp2p gossipsub has IDONTWANT but no
  semantic de-dup. ConsensusVote messages are idempotent at the
  aggregator level (same sig arrives twice, second ignored) but we
  must ensure that the aggregator uses the signer address, not the
  gossipsub message id, for equivalence.
- **Block forwarding loops.** If every node re-broadcasts on receipt
  the network can drown. Gossipsub's IHAVE/IWANT handles this at
  the gossip layer but we must NOT re-publish on reception.
- **Mempool tx floods.** A single tx broadcast goes to all followers.
  Each follower must admit once; subsequent re-gossips must be
  deduplicated by tx hash before admission. The existing mempool
  already has hash-based dedup — verify it still applies.
- **ValidatorPeerId spoofing.** A malicious peer could claim a
  validator PeerId they don't control. libp2p's identify exchange
  includes the PeerId signature, so spoofing the peer_id requires
  the ed25519 private key. Since PeerId is derived from node_id
  (deterministic), we can cross-check without additional PKI.

## Out of scope for M1

- Hybrid X25519MLKEM768 TLS — deferred to M1b per ADR-041 addendum
  (2026-04-22).
- Validator discovery via on-chain registry — M2 (`ValidatorRegistry`
  contract publishes peer records, discv5 resolves).
- Multi-region mesh redundancy / ASN diversity enforcement beyond
  `max_peers_per_asn=3` (already in P2pConfig but not enforced end-to-end
  — M2 hardening).

## Rolling it out safely

1. Land 135/136/137 each as its own commit, gated on
   `libp2p.enable` — on devnet-2 the flag stays `false` throughout
   implementation, so consensus continues on HTTP.
2. Run the 2-swarm integration tests after each.
3. Add a 3-validator in-process integration test (new file,
   `crates/pqcd/tests/m1_routing.rs`) that exercises the full
   end-to-end flow with fake validators.
4. Only after all three land and tests pass: bring up a separate
   pre-prod 3-node cluster (ephemeral DigitalOcean droplets), set
   `libp2p.enable=true`, observe for >=24h, then schedule the
   maintenance window for devnet-2 cutover (TASK-141).
