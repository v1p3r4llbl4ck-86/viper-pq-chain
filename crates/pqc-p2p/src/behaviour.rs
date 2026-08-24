// SPDX-License-Identifier: BUSL-1.1
//! Composed libp2p network behaviour — ADR-041.
//!
//! GossipSub v1.2 (content-addressed IDs for PQ IDONTWANT) + Kademlia +
//! Identify + Ping + block-fetch request-response (TASK-135 step 12).

use libp2p::{
    gossipsub::{self, MessageAuthenticity, ValidationMode},
    identify, kad, ping, request_response,
    swarm::NetworkBehaviour,
    PeerId, StreamProtocol,
};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    time::Duration,
};

use crate::{
    block_fetch::{BlockFetchRequest, BlockFetchResponse},
    block_fetch_by_hash::{BlockFetchByHashRequest, BlockFetchByHashResponse},
    config::P2pConfig,
    error::P2pError,
    protocols::Protocols,
    snapshot_fetch::{SnapshotFetchRequest, SnapshotFetchResponse},
};

/// The block-fetch sub-behaviour type alias. Kept short for readability
/// at the call sites in `swarm.rs`; the full generic CBOR behaviour name
/// is otherwise a mouthful on every event-match arm.
pub type BlockFetchBehaviour =
    request_response::cbor::Behaviour<BlockFetchRequest, BlockFetchResponse>;

/// The snapshot-fetch sub-behaviour type alias (Phase 8 M1 cold-start).
pub type SnapshotFetchBehaviour =
    request_response::cbor::Behaviour<SnapshotFetchRequest, SnapshotFetchResponse>;

/// The by-hash block-fetch sub-behaviour type alias (ADR-054 §Stage 4).
pub type BlockFetchByHashBehaviour =
    request_response::cbor::Behaviour<BlockFetchByHashRequest, BlockFetchByHashResponse>;

/// Composed network behaviour for a Viper node.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ViperBehaviourEvent")]
pub struct ViperBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub block_fetch: BlockFetchBehaviour,
    pub snapshot_fetch: SnapshotFetchBehaviour,
    pub block_fetch_by_hash: BlockFetchByHashBehaviour,
}

/// Events emitted by the composed behaviour.
//
// `large_enum_variant` allow: the variants wrap libp2p sub-behaviour events
// of uneven size (`identify::Event` ~656 B vs ~320 B for the next-largest).
// Each event lives only for a single swarm poll before being consumed, so
// the stack footprint is irrelevant; boxing one variant would merely shift
// the lint to the next-largest while breaking the `From` plumbing below.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ViperBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Kademlia(kad::Event),
    Identify(identify::Event),
    Ping(ping::Event),
    BlockFetch(request_response::Event<BlockFetchRequest, BlockFetchResponse>),
    SnapshotFetch(request_response::Event<SnapshotFetchRequest, SnapshotFetchResponse>),
    BlockFetchByHash(request_response::Event<BlockFetchByHashRequest, BlockFetchByHashResponse>),
}

impl From<gossipsub::Event> for ViperBehaviourEvent {
    fn from(e: gossipsub::Event) -> Self {
        Self::Gossipsub(e)
    }
}
impl From<kad::Event> for ViperBehaviourEvent {
    fn from(e: kad::Event) -> Self {
        Self::Kademlia(e)
    }
}
impl From<identify::Event> for ViperBehaviourEvent {
    fn from(e: identify::Event) -> Self {
        Self::Identify(e)
    }
}
impl From<ping::Event> for ViperBehaviourEvent {
    fn from(e: ping::Event) -> Self {
        Self::Ping(e)
    }
}
impl From<request_response::Event<BlockFetchRequest, BlockFetchResponse>> for ViperBehaviourEvent {
    fn from(e: request_response::Event<BlockFetchRequest, BlockFetchResponse>) -> Self {
        Self::BlockFetch(e)
    }
}
impl From<request_response::Event<SnapshotFetchRequest, SnapshotFetchResponse>>
    for ViperBehaviourEvent
{
    fn from(e: request_response::Event<SnapshotFetchRequest, SnapshotFetchResponse>) -> Self {
        Self::SnapshotFetch(e)
    }
}
impl From<request_response::Event<BlockFetchByHashRequest, BlockFetchByHashResponse>>
    for ViperBehaviourEvent
{
    fn from(e: request_response::Event<BlockFetchByHashRequest, BlockFetchByHashResponse>) -> Self {
        Self::BlockFetchByHash(e)
    }
}

/// Build the composed behaviour from an identity keypair and P2P config.
pub fn build_viper_behaviour(
    key: &libp2p::identity::Keypair,
    config: &P2pConfig,
) -> Result<ViperBehaviour, P2pError> {
    let local_peer_id = PeerId::from(key.public());

    // Content-addressed message IDs — enables GossipSub IDONTWANT deduplication.
    // Critical for PQ payloads: SLH-DSA-192s sigs are ~16 KB each.
    let message_id_fn = |msg: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        msg.data.hash(&mut s);
        msg.topic.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_be_bytes().to_vec())
    };

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        // Permissive: validate envelope signatures when present. Combined
        // with `MessageAuthenticity::Signed` below, every message we
        // publish carries the libp2p ed25519 signature of our local node
        // identity. Application-layer PQ signatures in the payload remain
        // authoritative for admission; the gossipsub signature is strictly
        // for binding each message to a libp2p PeerId so downstream
        // consumers (SPEC-P2P-002 §4.4 ValidatorPeerId check) can identify
        // the original publisher without an extra round-trip.
        .validation_mode(ValidationMode::Permissive)
        .mesh_n(config.gossip_mesh_n)
        .mesh_n_low(config.gossip_mesh_n_low)
        .mesh_n_high(config.gossip_mesh_n_high)
        // libp2p requires mesh_outbound_min <= mesh_n_low and <= mesh_n / 2.
        // Default (2) breaks n=2 devnet and n=1 tests. Cap to both bounds so
        // small meshes validate; 2 is the production ceiling (matches libp2p
        // default for mesh_n >= 4).
        .mesh_outbound_min(
            config
                .gossip_mesh_n_low
                .min(config.gossip_mesh_n / 2)
                .min(2),
        )
        // 64 KB covers a full epoch validator set of SLH-DSA-192s commit sigs.
        .max_transmit_size(64 * 1024)
        .message_id_fn(message_id_fn)
        .build()
        .map_err(|e| P2pError::Config(format!("gossipsub config: {e}")))?;

    // Signed authenticity: published messages carry an ed25519 signature
    // over (sender PeerId, topic, data, seqno), letting peers recover the
    // publisher PeerId from `Message.source`. The cost is one ed25519
    // verify per deduplicated gossip message — negligible next to the PQ
    // admission sigs we already run at the application layer.
    let mut gossipsub =
        gossipsub::Behaviour::new(MessageAuthenticity::Signed(key.clone()), gossipsub_config)
            .map_err(|e| P2pError::Config(format!("gossipsub init: {e}")))?;

    // Peer scoring — TASK-222 calibration (TASK-152 baseline replaced).
    // GossipSub v1.2 peer scoring penalises misbehaving peers (invalid
    // messages, mesh failures, IP colocation, behavioural anomalies)
    // and automatically reduces gossip, publish, and then disconnects
    // at increasing severity. This is the primary per-peer rate-limit
    // mechanism in libp2p gossipsub — there is no explicit bytes/sec
    // knob by design.
    //
    // The original landing used `PeerScoreParams::default()` which
    // wires zero per-topic weights (every topic at 0.5 baseline) and
    // permissive thresholds (graylist at -16000). That is fine for a
    // 3-validator devnet but inadequate at the 64-256 validator scale
    // band. The calibrated params live in `crate::peer_score`:
    //
    //   - per-topic weights ordered blocks > votes > updates > tx,
    //     reflecting operational severity of a missed message,
    //   - tightened thresholds (graylist -4000) sized for our PQ
    //     message regime where a single invalid block is 3-16 KB of
    //     wasted bandwidth,
    //   - explicit IP colocation + behaviour penalty + slow-peer
    //     decay weights,
    //   - retain_score = 1 h to defeat reconnect-to-reset.
    //
    // See `peer_score.rs` for the full audit-readable rationale.
    let peer_score_params = crate::peer_score::viper_peer_score_params(&config.chain_id);
    let peer_score_thresholds = crate::peer_score::viper_peer_score_thresholds();
    gossipsub
        .with_peer_score(peer_score_params, peer_score_thresholds)
        .map_err(|e| P2pError::Config(format!("gossipsub peer-score: {e}")))?;

    // Kademlia DHT — bootstrap peer discovery and routing.
    let store = kad::store::MemoryStore::new(local_peer_id);
    let kademlia = kad::Behaviour::new(local_peer_id, store);

    // Identify — exchange listen addresses and protocol versions at connect time.
    let identify = identify::Behaviour::new(
        identify::Config::new("/viper/1.0.0".to_string(), key.public())
            .with_agent_version(format!("pqc-node/{}", env!("CARGO_PKG_VERSION"))),
    );

    let ping = ping::Behaviour::new(ping::Config::new());

    // Block-fetch request-response: CBOR codec over a chain-scoped
    // protocol ID (`/viper/{chain_id}/block-fetch/1.0.0`). `Full`
    // support means every node both serves requests (from its local
    // chain store) and issues them when it detects a gossip height
    // gap — role-based asymmetry is enforced at the application layer
    // (SPEC-P2P-002 §4.4 ValidatorPeerId binding), not here.
    //
    // TASK-179: explicit 10 s request timeout per SPEC-P2P-002 §7.1.
    // This matches the libp2p default today but pin it explicitly so
    // a future upstream default change cannot silently drift past the
    // spec budget (a proposer must receive its full catch-up batch
    // within one slot to avoid a round skip).
    let protocols = Protocols::for_chain(&config.chain_id);
    let block_fetch_protocol = StreamProtocol::try_from_owned(protocols.block_fetch.clone())
        .map_err(|e| P2pError::Config(format!("block-fetch protocol id: {e}")))?;
    let block_fetch_cfg =
        request_response::Config::default().with_request_timeout(Duration::from_secs(10));
    let block_fetch = request_response::cbor::Behaviour::new(
        std::iter::once((
            block_fetch_protocol,
            request_response::ProtocolSupport::Full,
        )),
        block_fetch_cfg,
    );

    // Snapshot-fetch: one-shot cold-start fetch of a trusted checkpoint.
    // Devnet-2 snapshots are ~30 KB at 100K blocks so the libp2p default
    // frame cap (~1 MiB) is plenty; the 512 MiB policy ceiling in
    // SPEC-P2P-002 §7.2 is future-proofing for archival nodes and is
    // not reached today. Revisit if a real network approaches 1 MiB.
    //
    // TASK-179: SPEC-P2P-002 §7.2 mandates two knobs the libp2p
    // defaults don't match:
    //   - 5 min (300 s) request timeout — a snapshot response can be
    //     MB-scale on archival nodes, far more than the 10 s default
    //     allows, and a cold-starting follower legitimately needs the
    //     full budget.
    //   - ≤4 concurrent inbound streams per peer — DoS mitigation
    //     during a cold-start catastrophe; the libp2p default (100)
    //     would let a malicious peer exhaust a follower's file
    //     descriptors and memory while it is trying to catch up.
    let snapshot_fetch_protocol = StreamProtocol::try_from_owned(protocols.snapshot_fetch.clone())
        .map_err(|e| P2pError::Config(format!("snapshot-fetch protocol id: {e}")))?;
    let snapshot_fetch_cfg = request_response::Config::default()
        .with_request_timeout(Duration::from_secs(300))
        .with_max_concurrent_streams(4);
    let snapshot_fetch = request_response::cbor::Behaviour::new(
        std::iter::once((
            snapshot_fetch_protocol,
            request_response::ProtocolSupport::Full,
        )),
        snapshot_fetch_cfg,
    );

    // ADR-054 §Stage 4 — by-hash block fetch. Lives alongside the
    // height-ranged block-fetch protocol and shares the same 10 s
    // request budget (a by-hash lookup is strictly cheaper than a
    // ranged fetch — single-block, single CF read). The orphan-
    // resolution flow uses this when the receiver knows exactly which
    // variant of a parent block it needs and the height-ranged form
    // cannot disambiguate.
    let block_fetch_by_hash_protocol =
        StreamProtocol::try_from_owned(protocols.block_fetch_by_hash.clone())
            .map_err(|e| P2pError::Config(format!("block-fetch-by-hash protocol id: {e}")))?;
    let block_fetch_by_hash_cfg =
        request_response::Config::default().with_request_timeout(Duration::from_secs(10));
    let block_fetch_by_hash = request_response::cbor::Behaviour::new(
        std::iter::once((
            block_fetch_by_hash_protocol,
            request_response::ProtocolSupport::Full,
        )),
        block_fetch_by_hash_cfg,
    );

    Ok(ViperBehaviour {
        gossipsub,
        kademlia,
        identify,
        ping,
        block_fetch,
        snapshot_fetch,
        block_fetch_by_hash,
    })
}
