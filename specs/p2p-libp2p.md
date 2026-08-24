# libp2p Implementation Specification

**Spec ID**: SPEC-P2P-002
**Version**: 0.1
**Status**: Draft
**Date**: 2026-04-21
**Complements**: SPEC-P2P-001 (Peer-to-Peer Messaging)
**Implements**: ADR-041 (P2P libp2p/QUIC/X25519MLKEM768)

---

## 1. Scope

SPEC-P2P-001 defines *what* the P2P layer must provide (broadcast semantics, latency, authentication model). This document defines *how* it is implemented in the Viper PQ Chain Rust codebase under `crates/pqc-p2p/`.

In scope:
- crate layout and module contracts
- the `SwarmHandle` actor API exposed to the rest of `pqcd`
- wiring into `pqcd` startup
- mapping from SPEC-P2P-001 gossip categories to libp2p topics and `MessageType` tags
- request-response protocols for block/snapshot fetch
- retirement plan for the Phase 6 `/internal/p2p/*` HTTP endpoints
- multiaddr configuration schema
- Prometheus metrics exported by the P2P layer
- test strategy (unit, 2-swarm integration, 3-node convergence)

Out of scope:
- consensus wire format (defined in SPEC-CONSENSUS-001 §7)
- transport TLS parameters (defined in ADR-041 §3a.2 and SPEC-P2P-001 §3a.2)
- network topology rationale (defined in SPEC-P2P-001 §3a.4)

---

## 2. Normative Language

RFC 2119. MUST/SHOULD/MAY carry their usual meaning.

---

## 3. Crate Layout

All code lives under `crates/pqc-p2p/`. The libp2p dependency is gated behind the `libp2p-backend` Cargo feature so that downstream consumers (tests, tools) that only need the message types do not pull ~60 transitive crates.

```
crates/pqc-p2p/
├── Cargo.toml        # libp2p 0.55 optional dep, feature `libp2p-backend`
└── src/
    ├── lib.rs        # public re-exports
    ├── config.rs     # P2pConfig (listen_addrs, bootstrap_peers, limits)
    ├── error.rs      # P2pError (thiserror-based)
    ├── message.rs    # GossipMessage, MessageType enum
    ├── topics.rs     # Topics::for_chain(chain_id) → four topic strings
    ├── peer.rs       # PeerInfo, ValidatorPeerId (validator_pubkey ↔ PeerId binding)
    ├── behaviour.rs  # [libp2p-backend] NetworkBehaviour composition
    ├── transport.rs  # [libp2p-backend] QUIC+TCP/TLS transport factory
    └── swarm.rs      # [libp2p-backend] SwarmHandle, commands, events
```

Dependencies on the rest of the workspace:
- `pqc-types` — block/tx CBOR types (for request-response payload decoding)
- `pqc-crypto` — ML-DSA-65 signature verification of the `ValidatorPeerId` binding

The crate MUST NOT depend on `pqcd`, `pqc-consensus`, `pqc-state`, or `pqc-storage`. Wiring those together is `pqcd`'s job.

---

## 4. Module Contracts

### 4.1 `config::P2pConfig`

```rust
pub struct P2pConfig {
    pub chain_id: String,
    pub listen_addrs: Vec<Multiaddr>,       // e.g. /ip4/0.0.0.0/udp/26656/quic-v1
    pub bootstrap_peers: Vec<Multiaddr>,    // signed via on-chain registry (§3a.5)
    pub validator_network_port: u16,        // 26656 — consensus messages
    pub vfn_network_port: u16,              // 26666 — block/snapshot RPC
    pub public_network_port: u16,           // 26676 — read-only gossip for full nodes
    pub max_peers: usize,                   // hard cap, default 128
    pub enable_mdns: bool,                  // dev-only; MUST be false in production
    pub hybrid_kem_enabled: bool,           // ADR-041 addendum; default false in M1
}
```

Loaded from `config.yaml` under a new `p2p:` section (§10).

### 4.2 `message::MessageType` and `GossipMessage`

The on-wire envelope is:

```rust
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum MessageType {
    Block = 0x01,
    ConsensusVote = 0x02,
    Transaction = 0x03,
    ValidatorUpdate = 0x04,
}
pub struct GossipMessage {
    pub msg_type: MessageType,  // outer envelope tag — GossipSub routing
    pub version: u8,
    pub chain_id: String,       // belt-and-suspenders with topic namespacing
    pub payload: Vec<u8>,       // CBOR-encoded inner payload
}
```

**Important disambiguation**: the `MessageType` byte here is the **outer gossip envelope** tag used for routing and IDONTWANT. It is **distinct** from the consensus `msg_type` byte defined in SPEC-P2P-001 §6 / SPEC-CONSENSUS-001 §7:

| Layer | Tag | Values | Purpose |
|-------|-----|--------|---------|
| Gossip envelope (this crate) | `MessageType` | `0x01 Block`, `0x02 ConsensusVote`, `0x03 Transaction`, `0x04 ValidatorUpdate` | Topic routing, dedup |
| Inner consensus CBOR | `msg_type` at offset 0 | `0xC1 Proposal`, `0xC2 Prevote`, `0xC3 Precommit` | Per SPEC-CONSENSUS-001 |

A `GossipMessage` with `msg_type = ConsensusVote` (outer) carries a CBOR-encoded payload whose first byte is `0xC1`/`0xC2`/`0xC3` (inner). Decoding the outer envelope does not decode the inner consensus byte — that is done by the consensus engine after `SwarmHandle` hands the payload up.

**Wire format (resolved 2026-04-22 — TASK-147)**: `MessageType` is serialized via `serde_repr::Serialize_repr`/`Deserialize_repr` so each variant encodes as a **single CBOR unsigned-integer byte** equal to its `#[repr(u8)]` discriminant (`0x01`..`0x04`). The default serde derives were discovered to encode C-like enums as CBOR text strings of the variant name — TASK-147 reconciled this by adopting `serde_repr` before M1 cutover froze the wire format. The migration is pinned by two tests in `crates/pqc-p2p/src/message.rs`:

- `message_type_wire_format_is_u8_discriminant` — every variant encodes to exactly one byte matching the discriminant table above.
- `message_type_rejects_unknown_discriminant` — unknown values (e.g. future `0x05`) fail to decode rather than aliasing to an existing variant.

Any future switch back to variant-name strings (or any reordering of discriminants) is therefore a wire-breaking change that CI will block.

### 4.3 `topics::Topics`

```rust
impl Topics {
    pub fn for_chain(chain_id: &str) -> Self {
        Self {
            blocks:            format!("/viper/{}/blocks/1.0.0", chain_id),
            consensus_votes:   format!("/viper/{}/consensus/votes/1.0.0", chain_id),
            transactions:      format!("/viper/{}/mempool/txs/1.0.0", chain_id),
            validator_updates: format!("/viper/{}/validators/updates/1.0.0", chain_id),
        }
    }
}
```

**Topic ↔ MessageType table** (one topic per envelope type — no overloading):

| Topic | `MessageType` | Sender | Receivers |
|-------|---------------|--------|-----------|
| `blocks/1.0.0` | `Block` | Proposer only | All validators + VFN |
| `consensus/votes/1.0.0` | `ConsensusVote` | All validators | All validators |
| `mempool/txs/1.0.0` | `Transaction` | Any peer | All validators |
| `validators/updates/1.0.0` | `ValidatorUpdate` | Current epoch proposer | All peers |

GossipSub peers that receive a `GossipMessage` whose `msg_type` disagrees with the topic it arrived on MUST drop the message and record a `pqchain_p2p_envelope_mismatch_total` metric increment.

### 4.4 `peer::ValidatorPeerId`

Binds a libp2p `PeerId` to a validator's on-chain ML-DSA-65 public key:

```rust
pub struct ValidatorPeerId {
    pub peer_id: PeerId,
    pub validator_pubkey: [u8; 1952],   // ML-DSA-65 pk
    pub binding_sig: Vec<u8>,           // ML-DSA-65 sign(SHAKE-256("viper-peer-bind:v1" ‖ peer_id))
}
```

Validators connecting to the validator-private network (port 26656) MUST present a valid `ValidatorPeerId` at session start. Peers that fail verification MUST be disconnected before any gossip state is allocated.

### 4.5 `behaviour::Behaviour` (libp2p-backend only)

`#[derive(NetworkBehaviour)]` composing:
- `gossipsub::Behaviour` — GossipSub v1.2 with IDONTWANT on, mesh low=4/high=12/optimal=6
- `kad::Behaviour` — Kademlia, mode `Server` for bootstrap nodes, `Client` for full nodes
- `identify::Behaviour` — for agent string and listen address advertisement
- `ping::Behaviour` — 20s interval, 3-strike disconnect
- `request_response::Behaviour` (two protocol IDs):
  - `/viper/block-fetch/1.0.0` — request a block by height/hash (replaces `/internal/p2p/blocks/{height}`)
  - `/viper/snapshot/1.0.0` — request a snapshot for cold start (replaces `/internal/p2p/snapshot`)

mDNS is compiled in but MUST be disabled unless `P2pConfig::enable_mdns == true` (dev only).

### 4.6 `transport::build` (libp2p-backend only)

Factory returning `(Transport, PeerId)`. Prefers QUIC (`libp2p-quic` with `tokio`), falls back to TCP+TLS via `libp2p-tcp` + `libp2p-tls`. A Noise-XX authenticated path is compiled in for the VFN network where TLS is not negotiable (e.g. a lightweight client that only supports Noise).

M1 baseline: TLS uses the **classical X25519** TLS 1.3 named group. The X25519MLKEM768 hybrid PQ group (codepoint 0x11EC) is **gated behind the `hybrid-kem-tls` feature flag and `P2pConfig::hybrid_kem_enabled`**, off by default in M1. This matches the ADR-041 2026-04-22 addendum — hybrid KEM activation is deferred to M1b pending rustls-post-quantum stabilisation and libp2p 0.56 uptake.

### 4.7 `swarm::SwarmHandle` — Public API

The rest of `pqcd` interacts with P2P solely via a single handle, which wraps an mpsc channel to an async task owning the `Swarm`:

```rust
pub enum SwarmCommand {
    PublishBlock(Vec<u8>),                    // CBOR block
    PublishVote(Vec<u8>),                     // CBOR consensus vote (Proposal/Prevote/Precommit)
    PublishTransaction(Vec<u8>),              // CBOR signed tx
    PublishValidatorUpdate(Vec<u8>),          // CBOR validator set delta
    FetchBlock { height: u64, reply: oneshot::Sender<Result<Vec<u8>, P2pError>> },
    FetchSnapshot { reply: oneshot::Sender<Result<Vec<u8>, P2pError>> },
    ConnectedPeers(oneshot::Sender<Vec<PeerInfo>>),
    Shutdown,
}

pub enum SwarmEvent {
    BlockReceived { peer: PeerId, payload: Vec<u8> },
    VoteReceived { peer: PeerId, payload: Vec<u8> },
    TransactionReceived { peer: PeerId, payload: Vec<u8> },
    ValidatorUpdateReceived { peer: PeerId, payload: Vec<u8> },
    PeerConnected(PeerInfo),
    PeerDisconnected(PeerId),
    EnvelopeMismatch { peer: PeerId, topic: String },
}

pub struct SwarmHandle {
    cmd_tx: mpsc::Sender<SwarmCommand>,
    event_rx: mpsc::Receiver<SwarmEvent>,  // wrapped in a BroadcastSubscribe in practice
}
impl SwarmHandle {
    pub async fn spawn(cfg: P2pConfig, keypair: Keypair) -> Result<(Self, JoinHandle<()>), P2pError> { .. }
    pub async fn publish_block(&self, block: &Block) -> Result<(), P2pError> { .. }
    pub async fn publish_vote(&self, vote: &ConsensusMessage) -> Result<(), P2pError> { .. }
    pub async fn publish_transaction(&self, tx: &SignedTx) -> Result<(), P2pError> { .. }
    pub async fn fetch_block(&self, height: u64) -> Result<Block, P2pError> { .. }
    pub async fn fetch_snapshot(&self) -> Result<Snapshot, P2pError> { .. }
    pub fn subscribe_events(&self) -> broadcast::Receiver<SwarmEvent> { .. }
    pub async fn connected_peers(&self) -> Result<Vec<PeerInfo>, P2pError> { .. }
    pub async fn shutdown(self) { .. }
}
```

The actor task owns the `Swarm<Behaviour>` and never yields it. The rest of `pqcd` MUST NOT import `libp2p::*` types directly — only through `pqc_p2p::*` re-exports.

---

## 5. Wiring into `pqcd`

In `crates/pqcd/src/main.rs` (or equivalent bootstrap), after config load and before the HTTP API listener starts:

```rust
let p2p_cfg = load_p2p_config(&cfg);
let (swarm_handle, _swarm_task) = SwarmHandle::spawn(p2p_cfg, keypair.clone()).await?;

// Consensus engine subscribes to votes
let mut vote_rx = swarm_handle.subscribe_events();
let consensus_vote_sink = consensus.vote_sink();   // existing mpsc in pqc-consensus
tokio::spawn(async move {
    while let Ok(ev) = vote_rx.recv().await {
        if let SwarmEvent::VoteReceived { payload, .. } = ev {
            let _ = consensus_vote_sink.send(payload).await;
        }
    }
});

// Block import path reads from BlockReceived
// Mempool reads from TransactionReceived
```

The consensus engine publishes outgoing votes by calling `swarm_handle.publish_vote(&msg).await` from the broadcast path that previously wrote to the full-node HTTP polling queue.

Block production: after the producer finalises a block, it calls `swarm_handle.publish_block(&block).await`. Receiving nodes (full nodes and non-proposing validators) validate the block delivered via `SwarmEvent::BlockReceived` and insert it into the store.

---

## 6. HTTP → libp2p Migration

These `/internal/p2p/*` endpoints on the validator's Phase 6 API are replaced by libp2p-native protocols. The endpoints MUST be removed from the binary (HTTP handler functions deleted), not merely disabled:

| Phase 6 endpoint | Replacement | MessageType / Protocol ID |
|------------------|-------------|---------------------------|
| `GET /internal/p2p/kem-pubkey` | *(removed)* — libp2p handshake replaces ML-KEM session | — |
| `POST /internal/p2p/session` | *(removed)* — libp2p handshake replaces ML-KEM session | — |
| `GET /internal/p2p/status` | Ambient: `identify` agent + gossip `blocks` topic | `identify::Behaviour` |
| `GET /internal/p2p/blocks/{height}` | request-response over QUIC | `/viper/block-fetch/1.0.0` |
| `GET /internal/p2p/snapshot` | request-response over QUIC | `/viper/snapshot/1.0.0` |

The Phase 6 SSH reverse tunnel (`pqchain-tunnel-follower1.service`) is removed by the cutover playbook (TASK-141).

Backwards compatibility: M1 binaries MUST NOT accept the old endpoints. A `--legacy-p2p` flag is explicitly NOT provided — operators running a mixed fleet MUST cut over all three nodes in a single coordinated window (see `playbooks/cutover-libp2p.yml`).

---

## 7. Request-Response Protocols

### 7.1 `/viper/block-fetch/1.0.0`

- Request: `BlockFetchRequest { height: u64 }` (CBOR, ~12 bytes)
- Response: `Block` (CBOR) or `BlockFetchError { reason: String }`
- Max response size: `max_block_size + 16 KiB` safety margin (see SPEC-P2P-001 Q6)
- Timeout: 10 s

### 7.2 `/viper/snapshot/1.0.0`

- Request: `SnapshotRequest { min_height: u64 }` (CBOR) — fetch latest snapshot at height ≥ `min_height`
- Response: streamed `Snapshot` chunks using libp2p's built-in length-prefixed framing
- Max aggregate size: 512 MiB (operational cap; trips a `pqchain_p2p_snapshot_oversize_total` metric if exceeded)
- Timeout: 5 min

Concurrency: a peer MUST refuse more than 4 concurrent snapshot requests; full-node cold starts from multiple peers are sequential.

---

## 8. Multiaddr Configuration Schema

New `p2p:` section in `config.yaml` (loaded under `config::P2pConfig`):

```yaml
p2p:
  # Chain ID is inherited from the top-level chain_id field.
  listen_addrs:
    - "/ip4/0.0.0.0/udp/26656/quic-v1"   # QUIC primary, validator network
    - "/ip4/0.0.0.0/tcp/26656"           # TCP/TLS fallback, same port (libp2p multiplexes)
  vfn_listen_addrs:
    - "/ip4/0.0.0.0/udp/26666/quic-v1"
  public_listen_addrs:
    - "/ip4/0.0.0.0/udp/26676/quic-v1"
  bootstrap_peers:
    # List of multiaddrs with /p2p/<peer_id> suffix, signed via on-chain registry.
    - "/ip4/203.0.113.10/udp/26656/quic-v1/p2p/12D3KooW..."
  max_peers: 128
  enable_mdns: false              # dev only
  hybrid_kem_enabled: false       # M1 baseline; M1b flips this
```

The legacy `ssh_tunnel_*` section MUST be removed from `config.yaml`. A startup guard in `pqcd` MUST refuse to boot if it encounters any legacy key and print a migration notice pointing to `docs/phase-8-m1-plan.md`.

---

## 9. Metrics

Exposed at `/internal/metrics` (Prometheus text format) by `pqcd`, produced from counters/gauges pushed out of the swarm task:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pqchain_p2p_peers_connected` | gauge | `network={validator,vfn,public}` | Current peer count per network |
| `pqchain_p2p_tx_rejected_unbound_peer_total` | counter | — | Transaction envelopes dropped because the publisher PeerId was absent or not in `validator_peer_ids` (§4.4 binding). Stays at 0 when the allow-list is empty. |
| `pqchain_p2p_gossip_published_total` | counter | `msg_type={block,vote,tx,validator_update}` | Envelopes sent |
| `pqchain_p2p_gossip_received_total` | counter | `msg_type,valid={true,false}` | Envelopes received, split by validation |
| `pqchain_p2p_envelope_mismatch_total` | counter | `topic` | Envelope `msg_type` ≠ topic |
| `pqchain_p2p_handshake_failures_total` | counter | `reason` | TLS/Noise/KEM handshake errors |
| `pqchain_p2p_request_response_latency_seconds` | histogram | `protocol={block_fetch,snapshot}` | RPC latency |
| `pqchain_p2p_snapshot_oversize_total` | counter | — | Snapshot exceeded operational cap |

Health probe (`scripts/p2p-health.sh` added in TASK-143) reads `pqchain_p2p_peers_connected{network="validator"}` on the validator and returns non-zero if `< expected_validators - 1`.

---

## 10. Test Strategy

M1 coverage targets, sequenced for early-return on break:

| # | Test | Scope | Target TASK |
|---|------|-------|-------------|
| T1 | `topics::for_chain` — string stability | unit | TASK-128 |
| T2 | `GossipMessage` round-trip CBOR | unit | TASK-128 |
| T3 | `ValidatorPeerId` binding sig verification | unit | TASK-131 |
| T4 | 2-swarm in-process — publish+receive on each topic | integration | TASK-133 |
| T5 | 2-swarm in-process — `/viper/block-fetch/1.0.0` round trip | integration | TASK-135 |
| T6 | 2-swarm in-process — envelope/topic mismatch drops | integration | TASK-133 |
| T7 | 3-node ansible convergence — 1h soak, canary tx + gossip metrics | system | TASK-144 |

Unit + integration MUST be green in CI before TASK-141 (cutover playbook) is executed. The 3-node convergence test is the exit criterion for M1.

---

## 11. Open Items

| # | Item | Deferred to |
|---|------|-------------|
| L1 | X25519MLKEM768 hybrid activation | M1b (ADR-041 2026-04-22 addendum) |
| L2 | `ValidatorPeerId` publication via on-chain tx | M2 (ADR-042 integration) |
| L3 | ENR-over-DNS (DNSSEC) bootstrap channel | Phase 8 hardening milestone |
| L4 | discv5 ambient discovery | Phase 8 hardening milestone |
| L5 | ASN-diversity caps enforcement | Phase 8 hardening milestone |
| L6 | NAT traversal via DCUtR + circuit-relay-v2 (light client path) | Phase 9+ |

L1–L6 do not block M1; M1 success = "validator-private + VFN networks cutover to libp2p, HTTP peer endpoints removed, 3-node devnet-2 soaks 1h with canary green."
