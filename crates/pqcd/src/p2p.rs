// SPDX-License-Identifier: BUSL-1.1
//! Phase 8 libp2p integration — ADR-041 / SPEC-P2P-002.
//!
//! Wires the `pqc-p2p` Swarm into pqcd's async runtime. During M1 the
//! Swarm is started in "observation mode": it binds its listen address,
//! joins GossipSub topics, exchanges Identify/Ping with any peer that
//! dials in, and logs received gossip messages. It does NOT yet route
//! received messages into the consensus engine or block store — that
//! wiring lands in TASK-135/136/137.
//!
//! Toggled via the `libp2p:` section in node config (see
//! `crate::node::Libp2pConfig`). Disabled by default so Phase 6 behaviour
//! (SSH tunnel + HTTP polling + ML-KEM sessions) is preserved until the
//! cutover playbook (TASK-141) flips `enable: true`.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{anyhow, Context, Result};
use pqc_consensus::{vote_preimage, RocksDbChainStore, StoredBlock, VoteStep};
use pqc_crypto::{ml_dsa_sign_with_seed, AlgId, CryptoError};
use pqc_p2p::{
    BlockFetchByHashRequest, BlockFetchByHashRequestId, BlockFetchByHashResponse,
    BlockFetchRequest, BlockFetchRequestId, BlockFetchResponse, GossipMessage, MessageType,
    NodeRole, P2pConfig, PeerId, SnapshotFetchRequest, SnapshotFetchRequestId,
    SnapshotFetchResponse, SwarmHandle, Topics,
};
use pqc_types::{decode_signed_vote, encode_signed_vote_bytes, SignedVote, MSG_TYPE_PRECOMMIT};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tracing::{info, warn};

use crate::node::NodeConfig;

/// A Block-topic gossip envelope after CBOR decode.
///
/// Produced by the swarm driver task inside [`start_libp2p`] and consumed
/// by the inbound task spawned from `devnet.rs` (TASK-135 step 11).
/// Decoding happens on the driver side so the consumer task does not see
/// malformed payloads, and so the shared-state lock held by the consumer
/// is not poisoned by CBOR parsing CPU work.
pub struct InboundBlock {
    pub source: Option<PeerId>,
    pub block: StoredBlock,
}

/// Aggregated inbound libp2p events that need chain-store access.
///
/// Produced by the swarm driver task (`route_event`) and consumed by the
/// single inbound loop in `devnet.rs`. A sum type keeps the plumbing to
/// one mpsc channel — the consumer branches on the variant and dispatches
/// to the specialised handler. TASK-135 steps 11 and 12.
pub enum InboundP2pEvent {
    /// A Block gossip envelope arrived and was CBOR-decoded successfully
    /// (TASK-135 step 11 — height-gap detection input).
    ///
    /// Boxed because `InboundBlock` embeds a full `StoredBlock` (~480
    /// bytes); the other variants are ~100 bytes each, so an unboxed
    /// `Block` would bloat every enum slot in the mpsc queue.
    Block(Box<InboundBlock>),
    /// A peer asked us to serve a range of blocks via the block-fetch
    /// request-response protocol (TASK-135 step 12b — application reads
    /// the chain store and replies via `SwarmHandle::reply_block_fetch`).
    BlockFetchRequest {
        peer: PeerId,
        request_id: BlockFetchRequestId,
        request: BlockFetchRequest,
    },
    /// A peer replied to a request we previously sent (TASK-135 step 12b).
    /// Step 13 will feed these blocks into the chain store; today we
    /// decode and log for observation.
    BlockFetchResponse {
        peer: PeerId,
        response: BlockFetchResponse,
    },
    /// A peer asked us to serve a snapshot via
    /// `/viper/{chain_id}/snapshot/1.0.0` (Phase 8 M1 cold-start).
    /// The application reads the latest checkpoint from the chain
    /// store and replies via `SwarmHandle::reply_snapshot_fetch`.
    SnapshotFetchRequest {
        peer: PeerId,
        request_id: SnapshotFetchRequestId,
        request: SnapshotFetchRequest,
    },
    /// A peer replied to a snapshot request we previously sent
    /// (Phase 8 M1 cold-start). The application bootstraps from the
    /// returned bytes. For now the consumer just decodes and logs —
    /// cold-start wiring lands in a follow-up.
    SnapshotFetchResponse {
        peer: PeerId,
        response: SnapshotFetchResponse,
    },
    /// A peer published a `SignedVote` (Precommit) over the consensus-vote
    /// gossip topic. The receiver inserts it into the per-block precommit
    /// buffer. This feeds the M2b/distributed-signing quorum-collection path
    /// — when `DevnetConfig::distributed_signing` is true, each validator
    /// signs only with its OWN seed and the proposer collects peer
    /// precommits before finalizing the block.
    Precommit {
        source: Option<PeerId>,
        vote: SignedVote,
    },
    /// A peer published a transaction envelope on the `mempool/txs/1.0.0`
    /// topic. Arrives AFTER `route_event` enforces the SPEC-P2P-002 §4.4
    /// ValidatorPeerId binding check — so `source` (when the allow-list is
    /// populated) matches an Active validator's PeerId, and the payload
    /// byte-for-byte matches what `p2p::tx_envelope` produced on the
    /// sender. The consumer re-runs admission through `try_admit`,
    /// including the per-sender budget check (SPEC-FEE-001 §10.1) so
    /// gossip-sourced txs are not exempt from spam controls. Gossipsub's
    /// native mesh forwarding means receive-side handlers MUST NOT
    /// re-publish the payload. TASK-172.
    Transaction {
        source: Option<PeerId>,
        raw_tx: Vec<u8>,
    },
    /// ADR-054 §Stage 4 — a peer asked us for a single block by its
    /// hash. The application looks up the canonical chain first and
    /// falls back to the siblings CF if absent, then replies via
    /// `SwarmHandle::reply_block_fetch_by_hash`.
    BlockFetchByHashRequest {
        peer: PeerId,
        request_id: BlockFetchByHashRequestId,
        request: BlockFetchByHashRequest,
    },
    /// ADR-054 §Stage 4 — a peer replied to a by-hash fetch. The
    /// orphan-resolution flow consumes the response: on `Some(bytes)`
    /// it re-classifies the cached children of the parent; on `None`
    /// it falls back to a different peer.
    BlockFetchByHashResponse {
        peer: PeerId,
        response: BlockFetchByHashResponse,
    },
    /// SPEC-LIGHT-CLIENT-001 §5.2 — a peer published a sync-committee
    /// `LightClientAttestation` envelope. Decoded successfully (strict
    /// §5.2 validator passed). The receive-side handler logs +
    /// increments [`P2P_LIGHT_CLIENT_ATTESTATIONS_TOTAL`] for now;
    /// quorum aggregation + slashing-rule wiring (slots `0x0005` /
    /// `0x0006` reserved by spec §6) + persistence land in follow-up
    /// commits with the verifier SDK.
    LightClientAttestation {
        source: Option<PeerId>,
        attestation: pqc_consensus::light_client::LightClientAttestation,
    },
}

/// Output of [`start_libp2p`]: the background driver task, an
/// application-side handle for publishing gossip, and a receiver for
/// decoded inbound Block envelopes. All three are `None` when libp2p is
/// disabled in config.
pub struct LibP2pStart {
    pub task: Option<JoinHandle<Result<()>>>,
    pub handle: Option<SwarmHandle>,
    pub inbound_rx: Option<mpsc::UnboundedReceiver<InboundP2pEvent>>,
}

impl LibP2pStart {
    pub fn disabled() -> Self {
        Self {
            task: None,
            handle: None,
            inbound_rx: None,
        }
    }
}

/// Connected-peer gauge — scraped by `/v1/metrics` as
/// `pqchain_p2p_peers_connected` (TASK-143 / docs/operators/RUNBOOK.md §13). Updated
/// by the observation task on each PeerConnected / PeerDisconnected
/// event. Stays at 0 on nodes with `libp2p.enable = false`.
static P2P_PEERS_CONNECTED: AtomicUsize = AtomicUsize::new(0);

/// Counter: Transaction gossip messages dropped because the publisher's
/// PeerId was absent or not in the `validator_peer_ids` allow-list
/// (SPEC-P2P-002 §4.4 ValidatorPeerId binding). Scraped by `/v1/metrics`
/// as `pqchain_p2p_tx_rejected_unbound_peer_total`. Stays at 0 when
/// the allow-list is empty (binding check disabled — current devnet-2
/// default).
static P2P_TX_REJECTED_UNBOUND_PEER: AtomicUsize = AtomicUsize::new(0);

/// Counter: inbound Block envelopes whose height was more than 1 ahead of
/// the local tip — i.e. a catch-up range exists between us and the sender.
/// Scraped by `/v1/metrics` as `pqchain_p2p_block_gap_total`. During M1
/// observation mode this counter is incremented but no fetch is issued;
/// the `/viper/block-fetch/1.0.0` request-response lands in TASK-135 step
/// 12 and wires into the sync loop in step 13.
static P2P_BLOCK_GAP_TOTAL: AtomicUsize = AtomicUsize::new(0);

/// Counter: inbound `/viper/<chain>/block-fetch/1.0.0` requests we
/// served (TASK-135 step 12b). Incremented once per
/// `BlockFetchRequestReceived` event regardless of how many block
/// bytes we end up returning (including zero — the responder may not
/// hold any of the requested heights).
static P2P_BLOCK_FETCH_REQUESTS_RECEIVED: AtomicUsize = AtomicUsize::new(0);

/// Counter: outbound `/viper/<chain>/block-fetch/1.0.0` requests we
/// issued (TASK-135 step 12b). Incremented at dispatch time — failures
/// on the wire surface later as
/// `pqchain_p2p_block_fetch_failures_total`.
static P2P_BLOCK_FETCH_REQUESTS_SENT: AtomicUsize = AtomicUsize::new(0);

/// Counter: inbound block-fetch responses observed (TASK-135 step 12b).
/// Does not distinguish successful (blocks.len() > 0) from empty
/// responses; the application logs the count per-response.
static P2P_BLOCK_FETCH_RESPONSES_RECEIVED: AtomicUsize = AtomicUsize::new(0);

/// Counter: outbound block-fetch failures (timeout / unsupported /
/// peer-disconnect mid-request). TASK-135 step 12b. Incremented once
/// per `BlockFetchFailed` swarm event.
static P2P_BLOCK_FETCH_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// Counter: blocks successfully imported via a libp2p-sourced path
/// (gossip `Next` ingest or block-fetch response ingest). TASK-135
/// step 13. Disjoint from `pqchain_blocks_imported_total`, which
/// aggregates across all ingest paths (HTTP + libp2p). Useful for
/// confirming the cutover during the TASK-141 maintenance window —
/// after `libp2p.enable=true`, the two counters should rise in
/// lockstep.
static P2P_BLOCKS_IMPORTED: AtomicUsize = AtomicUsize::new(0);

/// Counter: inbound `/viper/<chain>/snapshot/1.0.0` requests served
/// (Phase 8 M1 cold-start). Incremented once per
/// `SnapshotFetchRequestReceived` event regardless of whether we had a
/// checkpoint to ship (an empty-body reply still counts — the peer
/// learned "this node has no snapshot" at the cost of one RTT).
static P2P_SNAPSHOT_REQUESTS_RECEIVED: AtomicUsize = AtomicUsize::new(0);
/// Counter: outbound snapshot requests dispatched. Stays at 0 until
/// the cold-start consumer wiring lands.
static P2P_SNAPSHOT_REQUESTS_SENT: AtomicUsize = AtomicUsize::new(0);
/// Counter: inbound snapshot responses observed. Stays at 0 until
/// cold-start wiring lands (we do not issue outbound requests today).
static P2P_SNAPSHOT_RESPONSES_RECEIVED: AtomicUsize = AtomicUsize::new(0);
/// Counter: outbound snapshot-fetch failures (timeout / peer
/// disconnect / unsupported protocol).
static P2P_SNAPSHOT_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// Counter: inbound GossipSub envelopes whose `msg_type` discriminant
/// disagreed with the topic they arrived on, per SPEC-P2P-002 §4.2.
///
/// GossipSub subscribe/publish is topic-scoped, so in principle a
/// mismatched envelope cannot reach `route_event` at all: a peer that
/// publishes e.g. a `Transaction` envelope on the blocks topic would
/// only reach subscribers of the blocks topic, and our local decoder
/// would still surface it with a mismatched `msg.msg_type`. The spec
/// mandates the defense-in-depth check anyway so operators can
/// forensically detect a buggy or malicious publisher without the
/// bad envelope silently leaking into a type-specific handler
/// downstream. Scraped by `/v1/metrics` as
/// `pqchain_p2p_envelope_mismatch_total`. TASK-179.
static P2P_ENVELOPE_MISMATCH_TOTAL: AtomicUsize = AtomicUsize::new(0);

/// ADR-054 §Stage 4 — by-hash block-fetch counters. Mirror the
/// height-ranged variants (`P2P_BLOCK_FETCH_*`) so operators can
/// distinguish orphan-resolution traffic from regular catch-up.
static P2P_BLOCK_FETCH_BY_HASH_REQUESTS_RECEIVED: AtomicUsize = AtomicUsize::new(0);
static P2P_BLOCK_FETCH_BY_HASH_REQUESTS_SENT: AtomicUsize = AtomicUsize::new(0);
static P2P_BLOCK_FETCH_BY_HASH_RESPONSES_RECEIVED: AtomicUsize = AtomicUsize::new(0);
static P2P_BLOCK_FETCH_BY_HASH_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// SPEC-LIGHT-CLIENT-001 §5.2 — count of well-formed
/// `LightClientAttestation` envelopes accepted on the gossip topic.
/// Scraped by `/v1/metrics` as
/// `pqchain_p2p_light_client_attestations_total`. Malformed envelopes
/// are dropped and counted under `P2P_ENVELOPE_MISMATCH_TOTAL`.
static P2P_LIGHT_CLIENT_ATTESTATIONS_TOTAL: AtomicUsize = AtomicUsize::new(0);

/// Snapshot of the connected-peer count for the metrics endpoint.
pub fn peers_connected() -> usize {
    P2P_PEERS_CONNECTED.load(Ordering::Relaxed)
}

/// Set of PeerIds we are *currently* connected to. Maintained alongside the
/// `P2P_PEERS_CONNECTED` counter — incremented on `PeerConnected`, removed
/// on `PeerDisconnected`. Exposed via [`connected_peer_ids`] so the
/// stale-tip recovery loop can address a specific peer for an out-of-band
/// block-fetch when the gossip-driven gap detection has nothing to chew
/// on (e.g. a 1-block-behind node whose elected proposer is itself, with
/// N=3 quorum=3).
static CONNECTED_PEER_IDS: std::sync::Mutex<Vec<PeerId>> = std::sync::Mutex::new(Vec::new());

/// Snapshot of the currently-connected PeerIds. Returns owned `Vec`, so
/// the caller can iterate without holding the lock. Empty when the swarm
/// isn't connected to anything (or libp2p disabled).
pub fn connected_peer_ids() -> Vec<PeerId> {
    CONNECTED_PEER_IDS
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default()
}

/// Snapshot of the unbound-peer tx-rejection counter for the metrics
/// endpoint. Stays at 0 when the allow-list is empty.
pub fn tx_rejected_unbound_peer_total() -> usize {
    P2P_TX_REJECTED_UNBOUND_PEER.load(Ordering::Relaxed)
}

/// Snapshot of the height-gap counter (TASK-135 step 11). Incremented
/// each time an inbound Block envelope is classified as [`BlockInboundClass::Gap`].
pub fn block_gap_total() -> usize {
    P2P_BLOCK_GAP_TOTAL.load(Ordering::Relaxed)
}

/// Increment the height-gap counter. Called by the inbound-block
/// consumer in `devnet.rs` when a gossiped block is more than 1 height
/// ahead of the local tip.
pub(crate) fn incr_block_gap_total() {
    P2P_BLOCK_GAP_TOTAL.fetch_add(1, Ordering::Relaxed);
}

// ── TASK-135 step 12b block-fetch counters ────────────────────────────

pub fn block_fetch_requests_received_total() -> usize {
    P2P_BLOCK_FETCH_REQUESTS_RECEIVED.load(Ordering::Relaxed)
}
pub fn block_fetch_requests_sent_total() -> usize {
    P2P_BLOCK_FETCH_REQUESTS_SENT.load(Ordering::Relaxed)
}
pub fn block_fetch_responses_received_total() -> usize {
    P2P_BLOCK_FETCH_RESPONSES_RECEIVED.load(Ordering::Relaxed)
}
pub fn block_fetch_failures_total() -> usize {
    P2P_BLOCK_FETCH_FAILURES.load(Ordering::Relaxed)
}
pub fn blocks_imported_total() -> usize {
    P2P_BLOCKS_IMPORTED.load(Ordering::Relaxed)
}

pub fn snapshot_requests_received_total() -> usize {
    P2P_SNAPSHOT_REQUESTS_RECEIVED.load(Ordering::Relaxed)
}
pub fn snapshot_requests_sent_total() -> usize {
    P2P_SNAPSHOT_REQUESTS_SENT.load(Ordering::Relaxed)
}
pub fn snapshot_responses_received_total() -> usize {
    P2P_SNAPSHOT_RESPONSES_RECEIVED.load(Ordering::Relaxed)
}
pub fn snapshot_failures_total() -> usize {
    P2P_SNAPSHOT_FAILURES.load(Ordering::Relaxed)
}

// ── ADR-054 §Stage 4 by-hash block-fetch counters ─────────────────────
pub fn block_fetch_by_hash_requests_received_total() -> usize {
    P2P_BLOCK_FETCH_BY_HASH_REQUESTS_RECEIVED.load(Ordering::Relaxed)
}
pub fn block_fetch_by_hash_requests_sent_total() -> usize {
    P2P_BLOCK_FETCH_BY_HASH_REQUESTS_SENT.load(Ordering::Relaxed)
}
pub fn block_fetch_by_hash_responses_received_total() -> usize {
    P2P_BLOCK_FETCH_BY_HASH_RESPONSES_RECEIVED.load(Ordering::Relaxed)
}
pub fn block_fetch_by_hash_failures_total() -> usize {
    P2P_BLOCK_FETCH_BY_HASH_FAILURES.load(Ordering::Relaxed)
}
pub(crate) fn incr_block_fetch_by_hash_requests_sent() {
    P2P_BLOCK_FETCH_BY_HASH_REQUESTS_SENT.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot of the envelope-mismatch counter. Any non-zero reading is
/// a forensic signal that SOME publisher on the network is crossing
/// topic/MessageType lanes — either a bug in a peer's publish path or
/// a deliberate probe. SPEC-P2P-002 §4.2. TASK-179.
pub fn envelope_mismatch_total() -> usize {
    P2P_ENVELOPE_MISMATCH_TOTAL.load(Ordering::Relaxed)
}

/// Snapshot of the count of well-formed sync-committee
/// `LightClientAttestation` envelopes received and decoded successfully
/// (SPEC-LIGHT-CLIENT-001 §5.2). Pre-aggregation single-signer envelopes
/// and aggregated quorum envelopes both increment this counter; the
/// metrics layer doesn't distinguish them yet (the SDK milestone splits
/// them per `sigs.len()`). Scraped as
/// `pqchain_p2p_light_client_attestations_total`.
pub fn light_client_attestations_total() -> usize {
    P2P_LIGHT_CLIENT_ATTESTATIONS_TOTAL.load(Ordering::Relaxed)
}

/// TASK-222 §3 — gossipsub peer-score telemetry snapshot. Re-exports
/// the buckets + min/max + last-sample timestamp the libp2p sampler
/// task updates every 30 seconds. Stays at zero on nodes with
/// `libp2p.enable = false` (sampler never runs).
///
/// Why a snapshot type rather than seven free functions: the metrics
/// renderer reads all seven values in one expression block, and a
/// snapshot guarantees the values come from the same sample tick
/// (a free-function reader could observe a torn read mid-update —
/// rare but plausible at ~30 s sample cadence under high contention).
pub fn gossip_telemetry() -> pqc_p2p::peer_score::PeerScoreTelemetry {
    pqc_p2p::peer_score::current_snapshot()
}

pub(crate) fn incr_block_fetch_requests_received() {
    P2P_BLOCK_FETCH_REQUESTS_RECEIVED.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn incr_block_fetch_requests_sent() {
    P2P_BLOCK_FETCH_REQUESTS_SENT.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn incr_block_fetch_responses_received() {
    P2P_BLOCK_FETCH_RESPONSES_RECEIVED.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn incr_blocks_imported() {
    P2P_BLOCKS_IMPORTED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn incr_snapshot_requests_received() {
    P2P_SNAPSHOT_REQUESTS_RECEIVED.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn incr_snapshot_requests_sent() {
    P2P_SNAPSHOT_REQUESTS_SENT.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn incr_snapshot_responses_received() {
    P2P_SNAPSHOT_RESPONSES_RECEIVED.fetch_add(1, Ordering::Relaxed);
}

/// Classification of an inbound Block envelope's height relative to the
/// local chain tip (TASK-135 step 11). Returned by
/// [`classify_inbound_height`] so the consumer can branch on the regime
/// without re-implementing the arithmetic per call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockInboundClass {
    /// Received height is at or below our tip — we already have it (or a
    /// fork at the same height, to be handled by step 13). Drop.
    Behind,
    /// Received height is exactly `local_tip + 1`. The envelope is the
    /// next block we would accept; ingestion is deferred to step 13.
    Next,
    /// Received height is further ahead. `ahead_by` is the number of
    /// missing blocks between us and the received one (strictly ≥ 1):
    /// `ahead_by = received - local_tip - 1`. Step 12 issues a
    /// `/viper/block-fetch/1.0.0` range request for those heights.
    Gap { ahead_by: u64 },
}

/// Pure classification of an inbound block height vs the local tip. Kept
/// separate from the consumer loop so it can be unit-tested without any
/// tokio or chain-store plumbing.
pub fn classify_inbound_height(local_tip: u64, received: u64) -> BlockInboundClass {
    if received <= local_tip {
        BlockInboundClass::Behind
    } else if received == local_tip + 1 {
        BlockInboundClass::Next
    } else {
        BlockInboundClass::Gap {
            ahead_by: received - local_tip - 1,
        }
    }
}

/// Start the libp2p Swarm if enabled in config.
///
/// Returns a [`LibP2pStart`] carrying both the background driver task and
/// an application-side [`SwarmHandle`] for publishing. When libp2p is
/// disabled (`libp2p.enable = false` or the section is absent), both
/// fields are `None` — callers MUST tolerate `handle = None` without
/// producing traffic, which is exactly what [`publish_if_enabled`]
/// enforces on the call path.
///
/// The caller is responsible for ensuring `shutdown_rx` is signalled on
/// shutdown — the task joins the Swarm's own shutdown command in
/// response.
pub async fn start_libp2p(
    config: &NodeConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<LibP2pStart> {
    let Some(cfg_section) = config.libp2p.as_ref() else {
        return Ok(LibP2pStart::disabled());
    };
    if !cfg_section.enable {
        return Ok(LibP2pStart::disabled());
    }

    let role = config.devnet.role.p2p_role();

    let validator_listen: Option<SocketAddr> = match cfg_section.validator_listen.as_deref() {
        Some(s) => Some(s.parse().context("parse libp2p.validator_listen")?),
        None if matches!(role, NodeRole::Validator) => {
            Some("0.0.0.0:26656".parse().expect("valid default"))
        }
        None => None,
    };

    let vfn_listen: Option<SocketAddr> = match cfg_section.vfn_listen.as_deref() {
        Some(s) => Some(s.parse().context("parse libp2p.vfn_listen")?),
        None if matches!(role, NodeRole::ValidatorFullnode) => {
            Some("0.0.0.0:26666".parse().expect("valid default"))
        }
        None => None,
    };

    let public_listen: Option<SocketAddr> = match cfg_section.public_listen.as_deref() {
        Some(s) => Some(s.parse().context("parse libp2p.public_listen")?),
        None if matches!(role, NodeRole::PublicFullnode) => {
            Some("0.0.0.0:26676".parse().expect("valid default"))
        }
        None => None,
    };

    let p2p_cfg = P2pConfig {
        role,
        validator_listen,
        vfn_listen,
        public_listen,
        bootstrap_peers: cfg_section.bootstrap_peers.clone(),
        gossip_mesh_n: cfg_section.gossip_mesh_n.unwrap_or(2),
        gossip_mesh_n_low: cfg_section.gossip_mesh_n_low.unwrap_or(1),
        gossip_mesh_n_high: cfg_section.gossip_mesh_n_high.unwrap_or(3),
        quic_enabled: cfg_section.quic_enabled.unwrap_or(true),
        tcp_tls_fallback: cfg_section.tcp_tls_fallback.unwrap_or(true),
        max_peers_per_asn: cfg_section.max_peers_per_asn.unwrap_or(3),
        chain_id: config.chain_id_hex.clone(),
        // Hybrid PQ KEM (X25519MLKEM768) — defaults to true so that a binary
        // built with the `hybrid-kem-tls` feature defaults to PQ on the wire.
        // When the feature is OFF the flag is silently ignored (see
        // crates/pqc-p2p/src/swarm.rs `use_hybrid_kem` cfg-gate). Future
        // libp2p-config wiring may surface this in node.json's [libp2p]
        // section; until then it is build-time + crate-default driven.
        hybrid_kem_enabled: true,
    };

    // Parse the pinned validator PeerId allow-list once at bootstrap.
    // Fail fast on malformed entries — a typo here would silently pass
    // every Transaction through the binding check. Empty list is
    // explicit opt-out (current devnet-2 default per config.yaml).
    let validator_peer_ids: HashSet<PeerId> = cfg_section
        .validator_peer_ids
        .iter()
        .map(|s| {
            s.parse::<PeerId>()
                .with_context(|| format!("parse libp2p.validator_peer_ids entry {s:?}"))
        })
        .collect::<Result<_>>()?;
    if !validator_peer_ids.is_empty() {
        info!(
            allow_list_size = validator_peer_ids.len(),
            "libp2p ValidatorPeerId binding check enabled (SPEC-P2P-002 §4.4)"
        );
    }

    // Parse `devnet.libp2p_seed_salt_hex` if present. Mirrors the
    // `kem_seed_salt_hex` parsing in `devnet.rs::start_from_config_path`
    // (per the private design notes).
    // Hard-fail on malformed hex / wrong length so an operator cannot
    // boot pqcd with a partially-rotated salt that derives the wrong
    // PeerId. Legacy back-compat: absent field falls back to the
    // `node_id`-only path with a startup `warn!`.
    let libp2p_secret_salt: Option<[u8; 32]> = match &config.devnet.libp2p_seed_salt_hex {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).with_context(|| {
                format!(
                    "node {} `devnet.libp2p_seed_salt_hex` is not valid hex",
                    config.node_id
                )
            })?;
            let salt: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                anyhow!(
                    "node {} `devnet.libp2p_seed_salt_hex` decoded to {} bytes; expected 32. \
                     Regenerate with `openssl rand -hex 32` and rotate via the \
                     `pqcd wallet rotate-peer-id --in-place` flow.",
                    config.node_id,
                    v.len()
                )
            })?;
            Some(salt)
        }
        None => {
            tracing::warn!(
                node_id = %config.node_id,
                "libp2p identity keypair derived from node_id ONLY (no `devnet.libp2p_seed_salt_hex` \
                 in node.json) — legacy back-compat path. node_id is publicly observable, so \
                 the long-term libp2p Ed25519 identity is recomputable by any attacker who knows it. \
                 See R-14 in KNOWN-ISSUES.md and \
                 the private design notes Generate a salt with \
                 `openssl rand -hex 32` and set `devnet.libp2p_seed_salt_hex` to close this gap."
            );
            None
        }
    };
    let keypair = derive_keypair(&config.node_id, libp2p_secret_salt.as_ref());
    let (handle, mut rx) = pqc_p2p::spawn_swarm(p2p_cfg, keypair).context("spawn libp2p swarm")?;

    info!(node_id = %config.node_id, "libp2p swarm started (observation mode)");

    // Block-topic decoded envelopes are forwarded to an unbounded mpsc
    // channel so the consumer (spawned from devnet.rs once LiveNodeState
    // is built) can compare each block height against the local tip
    // without borrowing the swarm event loop for chain-store work.
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<InboundP2pEvent>();

    // Keep one clone for the driver task (shutdown), return the other to
    // the application for publishing. SwarmHandle wraps an mpsc::Sender
    // so cloning is essentially free (atomic refcount bump).
    let shutdown_handle = handle.clone();
    let task = tokio::spawn(async move {
        let mut shutdown_rx = shutdown_rx;
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && *shutdown_rx.borrow() {
                        info!("libp2p swarm shutting down");
                        shutdown_handle.shutdown().await;
                        return Ok(());
                    }
                }
                event = rx.recv() => {
                    match event {
                        Some(ev) => route_event(&ev, &validator_peer_ids, &inbound_tx),
                        None => {
                            warn!("libp2p swarm event channel closed");
                            return Ok(());
                        }
                    }
                }
            }
        }
    });

    Ok(LibP2pStart {
        task: Some(task),
        handle: Some(handle),
        inbound_rx: Some(inbound_rx),
    })
}

/// Publish a gossip message iff `handle` is `Some` (libp2p enabled).
///
/// Zero production impact when libp2p is disabled: the entire Swarm stack
/// is never instantiated, so `handle` is `None` and this function is a
/// no-op. Intended as the single call site that consensus/block/tx paths
/// use to emit gossip during M1 — each emit site calls this helper
/// unconditionally, and the gate is enforced here.
pub async fn publish_if_enabled(handle: Option<&SwarmHandle>, msg: GossipMessage) {
    let Some(h) = handle else { return };
    if let Err(e) = h.publish(msg).await {
        warn!(error = %e, "libp2p publish failed");
    }
}

/// Build a signed Precommit vote for a just-committed block.
///
/// Runs ML-DSA (or SLH-DSA) signing over the vote preimage defined in
/// SPEC-CONSENSUS-001 §8.4: `SHAKE-256("VIPER-VOTE-V1" || height_be64 ||
/// round_be32 || step_u8 || block_hash, 32)`, with `step = Precommit = 2`.
/// Intended to be invoked from `spawn_blocking` so the signing does not
/// block the tokio runtime.
///
/// Note on observation-mode semantics: during M1 the `round` is always 0
/// because the current producer/consensus loop does not run multi-round
/// BFT (single producer per height). The wire format still matches
/// SPEC-CONSENSUS-001 §8.3 so future consumers can validate these votes
/// once the full precommit path lands.
pub fn build_signed_precommit(
    sig_alg_id: AlgId,
    commit_seed: &[u8; 32],
    validator_address: [u8; 32],
    height: u64,
    block_hash: [u8; 32],
) -> Result<SignedVote, CryptoError> {
    let round: u32 = 0;
    let fork_digest = pqc_types::ForkDigest::viper_research_1();
    let preimage = vote_preimage(
        &fork_digest,
        height,
        round,
        VoteStep::Precommit,
        &block_hash,
    );
    let signature = ml_dsa_sign_with_seed(sig_alg_id, commit_seed, &preimage)?;
    Ok(SignedVote {
        msg_type: MSG_TYPE_PRECOMMIT,
        height,
        round,
        block_hash,
        validator_address,
        signature,
    })
}

/// Wrap a `SignedVote` in a `GossipMessage` ready to publish on the
/// `ConsensusVote` topic.
///
/// Separated from publishing so producers can construct the envelope on a
/// blocking thread (alongside signing) and then publish from the async
/// runtime without any further CPU work on the hot path.
pub fn consensus_vote_envelope(chain_id: &str, vote: &SignedVote) -> GossipMessage {
    GossipMessage::new(
        MessageType::ConsensusVote,
        chain_id,
        encode_signed_vote_bytes(vote),
    )
}

/// Wrap a raw (CBOR-encoded) transaction payload in a `GossipMessage`
/// ready to publish on the `Transaction` topic.
///
/// The `raw_tx` passed in IS the gossip payload — no re-encoding. Any
/// transform between the submitted bytes and the wire bytes would
/// invalidate the tx hash and the sender's signature, so the envelope
/// must ship them verbatim.
pub fn tx_envelope(chain_id: &str, raw_tx: Vec<u8>) -> GossipMessage {
    GossipMessage::new(MessageType::Transaction, chain_id, raw_tx)
}

/// Wrap a canonical (CBOR-encoded) `StoredBlock` payload in a
/// `GossipMessage` ready to publish on the `Block` topic.
///
/// The `block_bytes` MUST be the output of
/// `DiskChainStore::export_block_bytes` (or the static
/// `encode_block_bytes`) — anything else would produce a block hash
/// that peers cannot reproduce, breaking the header → body linkage
/// used by the commit-proof verifier on the receive side.
pub fn block_envelope(chain_id: &str, block_bytes: Vec<u8>) -> GossipMessage {
    GossipMessage::new(MessageType::Block, chain_id, block_bytes)
}

/// Wrap a CBOR-encoded `LightClientAttestation` payload (per
/// SPEC-LIGHT-CLIENT-001 §4.3, encoded via
/// `pqc_consensus::light_client::LightClientAttestation::encode`) in a
/// `GossipMessage` ready to publish on the
/// `Topics::light_client_attestations` topic.
///
/// Caller guarantees `attestation_bytes` is the output of
/// `LightClientAttestation::encode()`. The receive-side decoder runs the
/// strict §5.2 validator and rejects malformed envelopes; the
/// envelope-mismatch counter (`pqchain_p2p_envelope_mismatch_total`)
/// catches a publisher that routes to the wrong topic.
pub fn light_client_attestation_envelope(
    chain_id: &str,
    attestation_bytes: Vec<u8>,
) -> GossipMessage {
    GossipMessage::new(
        MessageType::LightClientAttestation,
        chain_id,
        attestation_bytes,
    )
}

/// Derive a deterministic libp2p Keypair from the node identity string
/// and an optional 32-byte secret salt.
///
/// Stability across restarts matters: the PeerId is derived from the
/// public key, and peers rely on it for session admission. Using
/// domain-separated SHA3-256 for consistency with the ML-KEM seed
/// derivation elsewhere in pqcd.
///
/// `secret_salt` is `Some(32 bytes)` when `node.json` carries a populated
/// `devnet.libp2p_seed_salt_hex`; `None` for legacy back-compat where
/// derivation falls back to the `node_id`-only path. The caller is
/// responsible for emitting the legacy-path `warn!` (parsing happens at
/// the swarm-spawn site so the error message can name the field). The
/// salt branch uses a hyphen-suffixed domain separator (`-salt-`) to
/// rule out preimage collision with the legacy concatenation: the
/// legacy hash `Sha3_256(b"viper-libp2p-node:" || node_id)` and the
/// salted hash `Sha3_256(b"viper-libp2p-node:" || node_id || b"-salt-"
/// || salt)` cannot collide regardless of how the operator chooses
/// `node_id`.
fn derive_keypair(node_id: &str, secret_salt: Option<&[u8; 32]>) -> pqc_p2p::Keypair {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"viper-libp2p-node:");
    h.update(node_id.as_bytes());
    if let Some(salt) = secret_salt {
        h.update(b"-salt-");
        h.update(salt.as_slice());
    }
    let mut seed: [u8; 32] = h.finalize().into();
    pqc_p2p::Keypair::ed25519_from_bytes(&mut seed)
        .expect("32-byte sha3 output is a valid ed25519 seed")
}

/// Deterministic PeerId for a node identity. Mirrors `derive_keypair`
/// internals so callers can construct bootstrap multiaddrs before the
/// remote node has started (notably integration tests that need the
/// source's PeerId inside the follower's config). Production code
/// never needs this — the local PeerId is implicit inside
/// `SwarmHandle`.
///
/// Pass `None` for `secret_salt` to reproduce a peer that boots with no
/// `devnet.libp2p_seed_salt_hex` in its `node.json` (legacy back-compat
/// path); pass `Some(&[u8; 32])` to reproduce a salt-bound PeerId.
pub fn deterministic_peer_id(node_id: &str, secret_salt: Option<&[u8; 32]>) -> pqc_p2p::PeerId {
    pqc_p2p::PeerId::from(derive_keypair(node_id, secret_salt).public())
}

/// Is a Transaction gossip message admissible under the M1
/// ValidatorPeerId binding policy? Pure so it's unit-testable without
/// tripping the global rejection counter. SPEC-P2P-002 §4.4.
///
/// An empty allow-list means explicit opt-out (current devnet-2 default
/// per ADR-041 addendum — the on-chain registry lands in M2). With a
/// populated allow-list: `source == None` is rejected (anonymous
/// gossip), and a `Some(pid)` outside the list is rejected.
fn is_tx_admitted(source: &Option<PeerId>, validator_peer_ids: &HashSet<PeerId>) -> bool {
    if validator_peer_ids.is_empty() {
        return true;
    }
    source
        .as_ref()
        .is_some_and(|pid| validator_peer_ids.contains(pid))
}

/// Expected topic string for a given envelope `msg_type` on this chain.
///
/// Mirrors the table in SPEC-P2P-002 §4.3 and the routing logic in
/// `pqc_p2p::swarm::publish_message`: each `MessageType` has exactly
/// one topic. Pure so the envelope-mismatch check is unit-testable
/// without a running swarm.
fn expected_topic_for(chain_id: &str, msg_type: MessageType) -> String {
    let topics = Topics::for_chain(chain_id);
    match msg_type {
        MessageType::Block => topics.blocks,
        MessageType::ConsensusVote => topics.consensus_votes,
        MessageType::Transaction => topics.transactions,
        MessageType::ValidatorUpdate => topics.validator_updates,
        MessageType::LightClientAttestation => topics.light_client_attestations,
    }
}

/// Does the envelope's `msg_type` agree with the topic it arrived on?
/// SPEC-P2P-002 §4.2 MANDATES dropping any frame where the two disagree
/// and incrementing `pqchain_p2p_envelope_mismatch_total`. Pure so it's
/// unit-testable without tripping the global counter. TASK-179.
fn envelope_matches_topic(msg: &GossipMessage, topic: &str) -> bool {
    expected_topic_for(&msg.chain_id, msg.msg_type) == topic
}

/// Dispatch a Swarm event: enforce the ValidatorPeerId binding check
/// for Transaction messages, decode Block payloads into an
/// [`InboundBlock`] on the consumer channel, forward Transaction bytes
/// as `InboundP2pEvent::Transaction` for mempool admission (TASK-172),
/// then log. The binding check is skipped when `validator_peer_ids`
/// is empty (opt-in for M1 per ADR-041 addendum — the on-chain registry
/// lands in M2).
fn route_event(
    ev: &pqc_p2p::ViperSwarmEvent,
    validator_peer_ids: &HashSet<PeerId>,
    inbound_tx: &mpsc::UnboundedSender<InboundP2pEvent>,
) {
    match ev {
        pqc_p2p::ViperSwarmEvent::Message {
            msg: m,
            source,
            topic,
        } => {
            // SPEC-P2P-002 §4.2 envelope↔topic binding (TASK-179).
            // Defense-in-depth: GossipSub is topic-scoped so a
            // mismatched frame should not reach us, but a buggy
            // publisher could still construct one. Drop + count
            // BEFORE any downstream dispatch so the bad payload
            // never reaches a type-specific handler.
            if !envelope_matches_topic(m, topic) {
                P2P_ENVELOPE_MISMATCH_TOTAL.fetch_add(1, Ordering::Relaxed);
                warn!(
                    msg_type = ?m.msg_type,
                    chain_id = %m.chain_id,
                    topic = %topic,
                    source = ?source,
                    "libp2p: dropping envelope with msg_type≠topic \
                     (SPEC-P2P-002 §4.2)"
                );
                return;
            }

            // SPEC-P2P-002 §4.4 binding check on the Transaction topic.
            // We check only Transaction for now; Block/ConsensusVote/
            // ValidatorUpdate binding follows once the M2 on-chain
            // registry gives us stake-weighted peer scoring (TASK-135
            // onwards).
            if matches!(m.msg_type, MessageType::Transaction)
                && !is_tx_admitted(source, validator_peer_ids)
            {
                P2P_TX_REJECTED_UNBOUND_PEER.fetch_add(1, Ordering::Relaxed);
                warn!(
                    source = ?source,
                    allow_list_size = validator_peer_ids.len(),
                    "libp2p: dropping Transaction from unbound peer (ValidatorPeerId mismatch)"
                );
                return;
            }

            info!(
                msg_type = ?m.msg_type,
                chain_id = %m.chain_id,
                payload_len = m.payload.len(),
                source = ?source,
                "libp2p gossip received"
            );
            // Observation-mode decode: attempt to parse ConsensusVote
            // payloads as SignedVote so the log shows height/round/kind.
            // A decode failure is logged at warn so operators see malformed
            // votes on the wire without the node acting on them — there is
            // still no feeder into the consensus engine during M1.
            if matches!(m.msg_type, MessageType::ConsensusVote) {
                match decode_signed_vote(&m.payload) {
                    Ok(v) => {
                        info!(
                            vote_msg_type = format!("{:#04x}", v.msg_type),
                            height = v.height,
                            round = v.round,
                            sig_len = v.signature.len(),
                            "libp2p consensus vote decoded"
                        );
                        // Only forward Precommit votes into the inbound
                        // consumer — the distributed-signing quorum path
                        // doesn't need Propose / Prevote in this baseline
                        // (those carry over to the full BFT multi-round
                        // finalizer scope, beyond the M2b scope).
                        if v.msg_type == MSG_TYPE_PRECOMMIT {
                            let _ = inbound_tx.send(InboundP2pEvent::Precommit {
                                source: *source,
                                vote: v,
                            });
                        }
                    }
                    Err(e) => warn!(error = %e, "libp2p consensus vote decode failed"),
                }
            }
            // TASK-172: Transaction gossip → mempool forwarder. The
            // binding check above already rejected unbound peers when
            // an allow-list is configured; everything that reaches this
            // point is either trusted (allow-list populated) or the
            // node is running with binding disabled (devnet-2 default).
            // `handle_inbound_transaction` re-validates the payload
            // through `try_admit` — including the per-sender budget —
            // so gossip-sourced txs are NOT exempt from admission rules.
            // Gossipsub's mesh propagates to other peers natively; the
            // consumer MUST NOT re-publish.
            if matches!(m.msg_type, MessageType::Transaction) {
                // Receiver is dropped only on shutdown; a send error at
                // that point is benign — the node is tearing down.
                let _ = inbound_tx.send(InboundP2pEvent::Transaction {
                    source: *source,
                    raw_tx: m.payload.clone(),
                });
            }
            // TASK-135 step 11: decode Block envelopes and forward to the
            // inbound consumer so it can do height-gap detection against
            // the local chain tip. Decode failures are logged but not
            // forwarded — a malformed CBOR payload cannot safely be fed
            // to a height comparison.
            if matches!(m.msg_type, MessageType::Block) {
                match RocksDbChainStore::decode_block_bytes(&m.payload) {
                    Ok(block) => {
                        info!(
                            height = block.metadata.height,
                            block_hash = %hex::encode(block.metadata.block_hash.0),
                            "libp2p block envelope decoded (observation)"
                        );
                        let inbound = InboundBlock {
                            source: *source,
                            block,
                        };
                        // Receiver is dropped only on shutdown, at which
                        // point the swarm event loop is also tearing down
                        // — a send error here is benign.
                        let _ = inbound_tx.send(InboundP2pEvent::Block(Box::new(inbound)));
                    }
                    Err(e) => warn!(
                        error = %e,
                        payload_len = m.payload.len(),
                        "libp2p block envelope decode failed"
                    ),
                }
            }
            // SPEC-LIGHT-CLIENT-001 §5.2 — decode the LightClientAttestation
            // envelope under the same strict validator the spec mandates.
            // Decode failure is dropped + counted under the envelope-
            // mismatch metric (the binding-aware counter in §4.2 — same
            // forensic surface for "publisher emitted garbage").
            if matches!(m.msg_type, MessageType::LightClientAttestation) {
                match pqc_consensus::light_client::LightClientAttestation::decode(&m.payload) {
                    Ok(att) => {
                        P2P_LIGHT_CLIENT_ATTESTATIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
                        info!(
                            epoch = att.epoch,
                            sig_count = att.sigs.len(),
                            header_root = %hex::encode(att.header_root),
                            source = ?source,
                            "libp2p light-client attestation decoded"
                        );
                        let _ = inbound_tx.send(InboundP2pEvent::LightClientAttestation {
                            source: *source,
                            attestation: att,
                        });
                    }
                    Err(e) => {
                        P2P_ENVELOPE_MISMATCH_TOTAL.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            error = e,
                            payload_len = m.payload.len(),
                            "libp2p light-client attestation decode failed (SPEC-LIGHT-CLIENT-001 §5.2)"
                        );
                    }
                }
            }
        }
        pqc_p2p::ViperSwarmEvent::PeerConnected(pid) => {
            let count = P2P_PEERS_CONNECTED.fetch_add(1, Ordering::Relaxed) + 1;
            if let Ok(mut g) = CONNECTED_PEER_IDS.lock() {
                if !g.contains(pid) {
                    g.push(*pid);
                }
            }
            info!(peer = %pid, peers_connected = count, "libp2p peer connected");
        }
        pqc_p2p::ViperSwarmEvent::PeerDisconnected(pid) => {
            // saturating decrement — fetch_sub panics on underflow in debug.
            let prev = P2P_PEERS_CONNECTED
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    Some(n.saturating_sub(1))
                })
                .unwrap_or(0);
            if let Ok(mut g) = CONNECTED_PEER_IDS.lock() {
                g.retain(|p| p != pid);
            }
            info!(peer = %pid, peers_connected = prev.saturating_sub(1), "libp2p peer disconnected");
        }
        pqc_p2p::ViperSwarmEvent::Stopped(reason) => {
            P2P_PEERS_CONNECTED.store(0, Ordering::Relaxed);
            if let Ok(mut g) = CONNECTED_PEER_IDS.lock() {
                g.clear();
            }
            warn!(%reason, "libp2p swarm stopped");
        }
        // TASK-135 step 12b — block-fetch request-response events flow
        // through to the inbound consumer so it can read/write the
        // chain store and issue `SwarmHandle::reply_block_fetch`
        // without route_event needing state access. `BlockFetchFailed`
        // stays here: it does not need state, just a warn + counter.
        pqc_p2p::ViperSwarmEvent::BlockFetchRequestReceived {
            peer,
            request_id,
            request,
        } => {
            let _ = inbound_tx.send(InboundP2pEvent::BlockFetchRequest {
                peer: *peer,
                request_id: *request_id,
                request: request.clone(),
            });
        }
        pqc_p2p::ViperSwarmEvent::BlocksReceived { peer, response } => {
            let _ = inbound_tx.send(InboundP2pEvent::BlockFetchResponse {
                peer: *peer,
                response: response.clone(),
            });
        }
        pqc_p2p::ViperSwarmEvent::BlockFetchFailed { peer, reason } => {
            P2P_BLOCK_FETCH_FAILURES.fetch_add(1, Ordering::Relaxed);
            warn!(%peer, %reason, "libp2p block-fetch failed");
        }
        // Phase 8 M1 cold-start — forward snapshot events to the
        // inbound consumer so the handler can read/write the chain
        // store without route_event needing state access.
        // `SnapshotFetchFailed` stays here: it does not need state,
        // just a warn + counter.
        pqc_p2p::ViperSwarmEvent::SnapshotFetchRequestReceived {
            peer,
            request_id,
            request,
        } => {
            let _ = inbound_tx.send(InboundP2pEvent::SnapshotFetchRequest {
                peer: *peer,
                request_id: *request_id,
                request: request.clone(),
            });
        }
        pqc_p2p::ViperSwarmEvent::SnapshotReceived { peer, response } => {
            let _ = inbound_tx.send(InboundP2pEvent::SnapshotFetchResponse {
                peer: *peer,
                response: response.clone(),
            });
        }
        pqc_p2p::ViperSwarmEvent::SnapshotFetchFailed { peer, reason } => {
            P2P_SNAPSHOT_FAILURES.fetch_add(1, Ordering::Relaxed);
            warn!(%peer, %reason, "libp2p snapshot-fetch failed");
        }
        // ADR-054 §Stage 4 — by-hash block-fetch ingress.
        pqc_p2p::ViperSwarmEvent::BlockFetchByHashRequestReceived {
            peer,
            request_id,
            request,
        } => {
            P2P_BLOCK_FETCH_BY_HASH_REQUESTS_RECEIVED.fetch_add(1, Ordering::Relaxed);
            let _ = inbound_tx.send(InboundP2pEvent::BlockFetchByHashRequest {
                peer: *peer,
                request_id: *request_id,
                request: request.clone(),
            });
        }
        pqc_p2p::ViperSwarmEvent::BlockFetchByHashReceived { peer, response } => {
            P2P_BLOCK_FETCH_BY_HASH_RESPONSES_RECEIVED.fetch_add(1, Ordering::Relaxed);
            let _ = inbound_tx.send(InboundP2pEvent::BlockFetchByHashResponse {
                peer: *peer,
                response: response.clone(),
            });
        }
        pqc_p2p::ViperSwarmEvent::BlockFetchByHashFailed { peer, reason } => {
            P2P_BLOCK_FETCH_BY_HASH_FAILURES.fetch_add(1, Ordering::Relaxed);
            warn!(%peer, %reason, "libp2p block-fetch-by-hash failed");
        }
    }
}

#[cfg(test)]
mod tests;
