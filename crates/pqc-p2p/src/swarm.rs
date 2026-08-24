// SPDX-License-Identifier: BUSL-1.1
//! libp2p Swarm driver — ADR-041.
//!
//! Actor pattern: `spawn()` returns `(SwarmHandle, SwarmEventRx)`.
//! The caller sends `SwarmCommand`s and receives `ViperSwarmEvent`s.

use std::collections::HashMap;

use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic},
    identity::Keypair,
    kad,
    multiaddr::Protocol,
    request_response,
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// How often the bootstrap redial loop wakes up and reconnects to any
/// configured bootstrap peer that is not currently connected.
///
/// 15 s balances recovery latency after a transient disconnect (single
/// missed gossip round at 500 ms/block = 30 blocks ≈ acceptable drift)
/// against dial thrash if the peer is down for a long period. Libp2p
/// keeps its own exponential backoff on failed dials, so even with this
/// redial cadence the actual TCP SYN rate stays bounded.
const BOOTSTRAP_REDIAL_INTERVAL: Duration = Duration::from_secs(15);

/// TASK-222 §3 — peer-score telemetry sample cadence. 30 s strikes the
/// balance between freshness (operators want < 1 min between alerts)
/// and overhead (each sample walks the connected-peer list and calls
/// `gossipsub.peer_score()` per peer; cheap but not free at 256 peers).
const PEER_SCORE_SAMPLE_INTERVAL: Duration = Duration::from_secs(30);

use crate::{
    behaviour::{build_viper_behaviour, ViperBehaviour, ViperBehaviourEvent},
    block_fetch::{BlockFetchRequest, BlockFetchResponse},
    block_fetch_by_hash::{BlockFetchByHashRequest, BlockFetchByHashResponse},
    config::P2pConfig,
    error::P2pError,
    message::{GossipMessage, MessageType},
    snapshot_fetch::{SnapshotFetchRequest, SnapshotFetchResponse},
    topics::Topics,
    transport::validator_tcp_config,
};

/// Local identifier assigned by the swarm to each inbound block-fetch
/// request it surfaces to the application (TASK-135 step 12). The
/// application uses this id to reply via [`SwarmCommand::ReplyBlockFetch`];
/// the swarm task looks the pending `ResponseChannel` up internally.
///
/// Opaque `u64` by design: callers outside this crate never need to
/// reason about libp2p-internal [`request_response::InboundRequestId`]
/// shapes, and we keep the freedom to change the underlying type.
pub type BlockFetchRequestId = u64;

/// Local identifier for inbound snapshot-fetch requests — same design
/// as [`BlockFetchRequestId`]. Kept as a separate alias so the two
/// pending-inbound maps cannot be mixed up at a call site even though
/// they share the `u64` representation.
pub type SnapshotFetchRequestId = u64;

/// Local identifier for inbound by-hash block-fetch requests — same
/// pattern as [`BlockFetchRequestId`]. ADR-054 §Stage 4.
pub type BlockFetchByHashRequestId = u64;

/// Commands sent from the application to the swarm task.
#[derive(Debug)]
pub enum SwarmCommand {
    Publish(GossipMessage),
    Dial(Multiaddr),
    /// Initiate a block-fetch request against a specific peer.
    /// TASK-135 step 12 — the application MUST have validated the
    /// `request` via [`BlockFetchRequest::validate`] first.
    RequestBlocks {
        peer: PeerId,
        request: BlockFetchRequest,
    },
    /// Reply to a previously surfaced
    /// [`ViperSwarmEvent::BlockFetchRequestReceived`]. The `request_id`
    /// MUST match the one the swarm produced; unknown ids are silently
    /// dropped because the pending channel may already have expired.
    ReplyBlockFetch {
        request_id: BlockFetchRequestId,
        response: BlockFetchResponse,
    },
    /// Issue a snapshot-fetch request against a specific peer (Phase 8
    /// M1 cold-start).
    RequestSnapshot {
        peer: PeerId,
        request: SnapshotFetchRequest,
    },
    /// Reply to a previously surfaced
    /// [`ViperSwarmEvent::SnapshotFetchRequestReceived`]. Unknown ids
    /// are silently dropped (same semantics as `ReplyBlockFetch`).
    ReplySnapshotFetch {
        request_id: SnapshotFetchRequestId,
        response: SnapshotFetchResponse,
    },
    /// ADR-054 §Stage 4 — request a specific block by hash from `peer`.
    /// Used by orphan resolution when the receiver knows the exact
    /// canonical variant it needs and height-ranged fetch cannot
    /// disambiguate (sibling-divergence scenario).
    RequestBlockByHash {
        peer: PeerId,
        request: BlockFetchByHashRequest,
    },
    /// Reply to a previously surfaced
    /// [`ViperSwarmEvent::BlockFetchByHashRequestReceived`]. Unknown
    /// ids are silently dropped.
    ReplyBlockFetchByHash {
        request_id: BlockFetchByHashRequestId,
        response: BlockFetchByHashResponse,
    },
    Shutdown,
}

/// Events emitted by the swarm task to the application.
#[derive(Debug)]
pub enum ViperSwarmEvent {
    /// A decoded gossip envelope from a subscribed topic.
    ///
    /// `source` is the `PeerId` of the original publisher as reported by
    /// gossipsub when `MessageAuthenticity::Signed` is in effect. It is
    /// `None` for anonymous or unsigned flooding — those MUST be treated
    /// as untrusted. The peer that *forwarded* us the message
    /// (`propagation_source`) is intentionally not exposed because
    /// binding checks (SPEC-P2P-002 §4.4 ValidatorPeerId) apply to the
    /// publisher, not the relay hop.
    ///
    /// `topic` is the GossipSub topic string the frame arrived on (the
    /// hash rendered back to its human form, e.g.
    /// `/viper/<chain>/blocks/1.0.0`). Required by SPEC-P2P-002 §4.2:
    /// a peer MUST drop any envelope whose `msg.msg_type` disagrees
    /// with the topic and record a `pqchain_p2p_envelope_mismatch_total`
    /// increment. In theory such a disagreement cannot reach us
    /// (GossipSub subscribe/publish is topic-scoped) but we surface
    /// the topic anyway so pqcd can do defense-in-depth.
    Message {
        msg: GossipMessage,
        source: Option<PeerId>,
        topic: String,
    },
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    /// A peer asked us to serve a range of blocks. The application
    /// reads the requested heights from its chain store and replies via
    /// [`SwarmCommand::ReplyBlockFetch`] using the `request_id` carried
    /// here. TASK-135 step 12.
    BlockFetchRequestReceived {
        peer: PeerId,
        request_id: BlockFetchRequestId,
        request: BlockFetchRequest,
    },
    /// A peer replied to a request we previously sent via
    /// [`SwarmCommand::RequestBlocks`]. TASK-135 step 12.
    BlocksReceived {
        peer: PeerId,
        response: BlockFetchResponse,
    },
    /// Outbound request-response failure — timeout, peer disconnected
    /// mid-request, unsupported protocol, etc. The application MAY
    /// retry against a different peer; the swarm does NOT retry
    /// automatically because peer selection belongs to the caller.
    BlockFetchFailed {
        peer: PeerId,
        reason: String,
    },
    /// A peer asked us to serve a snapshot-fetch request. The
    /// application reads its local checkpoint from the chain store and
    /// replies via [`SwarmCommand::ReplySnapshotFetch`] using the
    /// `request_id` carried here.
    SnapshotFetchRequestReceived {
        peer: PeerId,
        request_id: SnapshotFetchRequestId,
        request: SnapshotFetchRequest,
    },
    /// A peer replied to a snapshot-fetch request we previously sent.
    /// The application MUST cross-check the `snapshot_height` in the
    /// response against the height encoded in the snapshot CBOR body
    /// before writing — a peer that ships a mismatched pair is buggy
    /// or malicious.
    SnapshotReceived {
        peer: PeerId,
        response: SnapshotFetchResponse,
    },
    /// Outbound snapshot-fetch failure. Same retry semantics as
    /// [`Self::BlockFetchFailed`].
    SnapshotFetchFailed {
        peer: PeerId,
        reason: String,
    },
    /// ADR-054 §Stage 4 — a peer asked us for a specific block by hash.
    /// The application looks the hash up (canonical or siblings CF) and
    /// replies via [`SwarmCommand::ReplyBlockFetchByHash`].
    BlockFetchByHashRequestReceived {
        peer: PeerId,
        request_id: BlockFetchByHashRequestId,
        request: BlockFetchByHashRequest,
    },
    /// ADR-054 §Stage 4 — a peer replied to a by-hash fetch we sent.
    /// `response.block` is `None` when the peer holds neither a
    /// canonical nor a sibling block matching the hash.
    BlockFetchByHashReceived {
        peer: PeerId,
        response: BlockFetchByHashResponse,
    },
    /// Outbound by-hash fetch failure. Same retry semantics as
    /// [`Self::BlockFetchFailed`].
    BlockFetchByHashFailed {
        peer: PeerId,
        reason: String,
    },
    Stopped(String),
}

/// Owned handle to the running swarm task.
///
/// `Clone` is safe: internally this is an `mpsc::Sender`, which is reference-
/// counted. Cloning lets the swarm-driver task own one handle for its own
/// shutdown path while the application retains another for publishing.
#[derive(Clone)]
pub struct SwarmHandle {
    cmd_tx: mpsc::Sender<SwarmCommand>,
}

impl SwarmHandle {
    pub async fn publish(&self, msg: GossipMessage) -> Result<(), P2pError> {
        self.cmd_tx
            .send(SwarmCommand::Publish(msg))
            .await
            .map_err(|_| P2pError::Transport("swarm task stopped".into()))
    }

    pub async fn dial(&self, addr: Multiaddr) -> Result<(), P2pError> {
        self.cmd_tx
            .send(SwarmCommand::Dial(addr))
            .await
            .map_err(|_| P2pError::Transport("swarm task stopped".into()))
    }

    /// Issue a block-fetch request against `peer`. TASK-135 step 12.
    ///
    /// The response (or a failure) surfaces later as
    /// [`ViperSwarmEvent::BlocksReceived`] or
    /// [`ViperSwarmEvent::BlockFetchFailed`] on the event stream.
    /// The request is NOT retried internally.
    pub async fn request_blocks(
        &self,
        peer: PeerId,
        request: BlockFetchRequest,
    ) -> Result<(), P2pError> {
        self.cmd_tx
            .send(SwarmCommand::RequestBlocks { peer, request })
            .await
            .map_err(|_| P2pError::Transport("swarm task stopped".into()))
    }

    /// Reply to a previously surfaced
    /// [`ViperSwarmEvent::BlockFetchRequestReceived`]. TASK-135 step 12.
    ///
    /// The `request_id` MUST match what the swarm produced; unknown
    /// ids (e.g. because the peer already disconnected and the channel
    /// was reaped) are silently dropped on the swarm side.
    pub async fn reply_block_fetch(
        &self,
        request_id: BlockFetchRequestId,
        response: BlockFetchResponse,
    ) -> Result<(), P2pError> {
        self.cmd_tx
            .send(SwarmCommand::ReplyBlockFetch {
                request_id,
                response,
            })
            .await
            .map_err(|_| P2pError::Transport("swarm task stopped".into()))
    }

    /// Issue a snapshot-fetch request against `peer` (Phase 8 M1
    /// cold-start). The response (or a failure) surfaces later as
    /// [`ViperSwarmEvent::SnapshotReceived`] or
    /// [`ViperSwarmEvent::SnapshotFetchFailed`].
    pub async fn request_snapshot(
        &self,
        peer: PeerId,
        request: SnapshotFetchRequest,
    ) -> Result<(), P2pError> {
        self.cmd_tx
            .send(SwarmCommand::RequestSnapshot { peer, request })
            .await
            .map_err(|_| P2pError::Transport("swarm task stopped".into()))
    }

    /// Reply to a previously surfaced
    /// [`ViperSwarmEvent::SnapshotFetchRequestReceived`].
    pub async fn reply_snapshot_fetch(
        &self,
        request_id: SnapshotFetchRequestId,
        response: SnapshotFetchResponse,
    ) -> Result<(), P2pError> {
        self.cmd_tx
            .send(SwarmCommand::ReplySnapshotFetch {
                request_id,
                response,
            })
            .await
            .map_err(|_| P2pError::Transport("swarm task stopped".into()))
    }

    /// ADR-054 §Stage 4 — request a single block by hash from `peer`.
    /// The response (or a failure) surfaces later as
    /// [`ViperSwarmEvent::BlockFetchByHashReceived`] or
    /// [`ViperSwarmEvent::BlockFetchByHashFailed`].
    pub async fn request_block_by_hash(
        &self,
        peer: PeerId,
        request: BlockFetchByHashRequest,
    ) -> Result<(), P2pError> {
        self.cmd_tx
            .send(SwarmCommand::RequestBlockByHash { peer, request })
            .await
            .map_err(|_| P2pError::Transport("swarm task stopped".into()))
    }

    /// ADR-054 §Stage 4 — reply to a previously surfaced
    /// [`ViperSwarmEvent::BlockFetchByHashRequestReceived`].
    pub async fn reply_block_fetch_by_hash(
        &self,
        request_id: BlockFetchByHashRequestId,
        response: BlockFetchByHashResponse,
    ) -> Result<(), P2pError> {
        self.cmd_tx
            .send(SwarmCommand::ReplyBlockFetchByHash {
                request_id,
                response,
            })
            .await
            .map_err(|_| P2pError::Transport("swarm task stopped".into()))
    }

    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(SwarmCommand::Shutdown).await;
    }
}

pub type SwarmEventRx = mpsc::Receiver<ViperSwarmEvent>;

/// Build the libp2p Swarm and spawn its event loop.
///
/// Returns `(SwarmHandle, SwarmEventRx)`. The event loop runs as an
/// independent Tokio task.
pub fn spawn(config: P2pConfig, keypair: Keypair) -> Result<(SwarmHandle, SwarmEventRx), P2pError> {
    let topics = Topics::for_chain(&config.chain_id);
    let gossip_topics: Vec<IdentTopic> = [
        &topics.blocks,
        &topics.consensus_votes,
        &topics.transactions,
        &topics.validator_updates,
        &topics.light_client_attestations,
    ]
    .iter()
    .map(|s| IdentTopic::new(s.as_str()))
    .collect();

    // Build behaviour before SwarmBuilder takes ownership of the keypair,
    // so we can propagate config errors before entering the builder chain.
    // In libp2p 0.55+, with_behaviour() takes a closure returning B directly.
    let behaviour = build_viper_behaviour(&keypair, &config)?;

    // Hybrid PQ KEM (X25519MLKEM768) is opt-in at both BUILD time
    // (`hybrid-kem-tls` Cargo feature → pulls rustls-post-quantum) and
    // RUNTIME (P2pConfig::hybrid_kem_enabled). Same binary serves both
    // postures so a chain that wants classical X25519 and one that wants
    // hybrid PQ run on the same artefact. See
    // the private design notes.
    #[cfg(feature = "hybrid-kem-tls")]
    let use_hybrid_kem = config.hybrid_kem_enabled;
    #[cfg(not(feature = "hybrid-kem-tls"))]
    let use_hybrid_kem = false;

    if use_hybrid_kem {
        tracing::info!(
            "libp2p TLS handshake using X25519MLKEM768 hybrid PQ group \
             (rustls-post-quantum provider, vendored libp2p-tls patch)"
        );
    } else {
        tracing::info!(
            "libp2p TLS handshake using classical X25519 \
             (hybrid_kem_enabled={}, hybrid-kem-tls feature compiled in: {})",
            config.hybrid_kem_enabled,
            cfg!(feature = "hybrid-kem-tls"),
        );
    }

    // The TCP/TLS path's `with_tcp(_, tls_constructor, _)` second argument
    // is `FnOnce(&Keypair) -> Result<libp2p::tls::Config, _>`. For the QUIC
    // path, libp2p::SwarmBuilder::with_quic_config takes a closure that
    // RECEIVES the default Config (built with the SwarmBuilder's keypair)
    // and returns a transformed Config. The Config's keypair field is
    // private in upstream libp2p-quic (and we kept that privacy in the
    // vendored patch), so we capture our own clone of the keypair here
    // BEFORE passing it into SwarmBuilder.
    #[cfg(feature = "hybrid-kem-tls")]
    let keypair_for_quic = keypair.clone();

    let builder = libp2p::SwarmBuilder::with_existing_identity(keypair).with_tokio();

    let mut swarm = if use_hybrid_kem {
        #[cfg(feature = "hybrid-kem-tls")]
        {
            // rustls_post_quantum::provider() returns &'static CryptoProvider;
            // Clone gives us an owned value to hand to the libp2p-tls /
            // libp2p-quic vendor patch's `*_with_provider` constructors.
            builder
                .with_tcp(
                    validator_tcp_config(),
                    |kp: &Keypair| {
                        libp2p::tls::Config::new_with_provider(
                            kp,
                            rustls_post_quantum::provider().clone(),
                        )
                    },
                    libp2p::yamux::Config::default,
                )
                .map_err(|e| P2pError::Transport(format!("tcp transport (PQ): {e}")))?
                .with_quic_config(|_default_cfg| {
                    libp2p::quic::Config::new_with_provider(
                        &keypair_for_quic,
                        rustls_post_quantum::provider().clone(),
                    )
                })
                // /dns4 + /dns multiaddr resolution. Required to dial k8s
                // headless-service peer addresses — `pqcd ceremony` emits
                // bootstrap_peers as /dns4/<svc>/tcp/26656/p2p/<id>; without
                // the DNS layer the TCP transport rejects them upfront with
                // MultiaddrNotSupported and no peer connection ever forms.
                .with_dns()
                .map_err(|e| P2pError::Transport(format!("dns transport (PQ): {e}")))?
                .with_behaviour(|_key| behaviour)
                .map_err(|e| P2pError::Config(format!("behaviour init: {e}")))?
                .build()
        }
        #[cfg(not(feature = "hybrid-kem-tls"))]
        {
            // Unreachable: use_hybrid_kem can only be true when the feature
            // is compiled in. This branch exists so the type checker accepts
            // the if/else when the feature is off.
            unreachable!("use_hybrid_kem requires the hybrid-kem-tls feature")
        }
    } else {
        builder
            .with_tcp(
                validator_tcp_config(),
                libp2p::tls::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| P2pError::Transport(format!("tcp transport: {e}")))?
            .with_quic()
            // /dns4 + /dns multiaddr resolution (see PQ branch above).
            .with_dns()
            .map_err(|e| P2pError::Transport(format!("dns transport: {e}")))?
            .with_behaviour(|_key| behaviour)
            .map_err(|e| P2pError::Config(format!("behaviour init: {e}")))?
            .build()
    };

    for topic in &gossip_topics {
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(topic)
            .map_err(|e| P2pError::Config(format!("subscribe {}: {e}", topic.hash())))?;
    }

    swarm
        .behaviour_mut()
        .kademlia
        .set_mode(Some(kad::Mode::Server));

    if let Some(addr) = listen_addr_for_role(&config) {
        swarm
            .listen_on(addr.clone())
            .map_err(|e| P2pError::Transport(format!("listen {addr}: {e}")))?;
    }

    // Parse bootstrap peers once into (PeerId, Multiaddr) pairs. Multiaddrs
    // that embed a `/p2p/<peer-id>` suffix are the supported form — the
    // peer-id is used by the periodic redial loop (see `run_loop`) to
    // decide which peers still need a connection.
    let mut bootstrap_peers: Vec<(PeerId, Multiaddr)> = Vec::new();
    for peer_str in &config.bootstrap_peers {
        match peer_str.parse::<Multiaddr>() {
            Ok(ma) => {
                let peer_id = ma.iter().find_map(|p| match p {
                    Protocol::P2p(pid) => Some(pid),
                    _ => None,
                });
                match peer_id {
                    Some(pid) => {
                        let _ = swarm.dial(ma.clone());
                        bootstrap_peers.push((pid, ma));
                    }
                    None => warn!(
                        "bootstrap peer {peer_str} has no /p2p/ component; \
                         redial loop cannot track it"
                    ),
                }
            }
            Err(e) => warn!("invalid bootstrap peer {peer_str}: {e}"),
        }
    }

    let (cmd_tx, cmd_rx) = mpsc::channel::<SwarmCommand>(64);
    let (event_tx, event_rx) = mpsc::channel::<ViperSwarmEvent>(256);

    tokio::spawn(run_loop(
        swarm,
        cmd_rx,
        event_tx,
        gossip_topics,
        topics,
        bootstrap_peers,
    ));

    Ok((SwarmHandle { cmd_tx }, event_rx))
}

async fn run_loop(
    mut swarm: Swarm<ViperBehaviour>,
    mut cmd_rx: mpsc::Receiver<SwarmCommand>,
    event_tx: mpsc::Sender<ViperSwarmEvent>,
    subscribed_topics: Vec<IdentTopic>,
    topics: Topics,
    bootstrap_peers: Vec<(PeerId, Multiaddr)>,
) {
    // Pending inbound block-fetch requests: from the moment the swarm
    // surfaces a `BlockFetchRequestReceived` event until the application
    // replies via `ReplyBlockFetch`, the `ResponseChannel` is parked
    // here so the libp2p request_response behaviour can later complete
    // the protocol exchange. The map grows by one per inbound request
    // and shrinks by one per reply — in steady state it holds only the
    // requests being actively served.
    let mut pending_inbound: HashMap<
        BlockFetchRequestId,
        request_response::ResponseChannel<BlockFetchResponse>,
    > = HashMap::new();
    let mut next_request_id: BlockFetchRequestId = 0;

    // Same park-and-reply pattern for snapshot-fetch. Separate map
    // (vs a single generic one) so the type system refuses to mix up
    // a snapshot response with a block-fetch channel at the `remove`
    // call site.
    let mut pending_inbound_snapshot: HashMap<
        SnapshotFetchRequestId,
        request_response::ResponseChannel<SnapshotFetchResponse>,
    > = HashMap::new();
    let mut next_snapshot_request_id: SnapshotFetchRequestId = 0;

    // ADR-054 §Stage 4 — third pending-inbound map for the by-hash
    // block-fetch protocol. Same park-and-reply discipline as the
    // other two; the typed key is the load-bearing safety property.
    let mut pending_inbound_block_fetch_by_hash: HashMap<
        BlockFetchByHashRequestId,
        request_response::ResponseChannel<BlockFetchByHashResponse>,
    > = HashMap::new();
    let mut next_block_fetch_by_hash_id: BlockFetchByHashRequestId = 0;

    // Bootstrap redial ticker — TASK-148. Every BOOTSTRAP_REDIAL_INTERVAL,
    // inspect `swarm.connected_peers()` and re-dial any configured
    // bootstrap peer that is not currently connected. Libp2p's built-in
    // dial backoff keeps the actual SYN rate bounded when a peer is
    // down, so setting this to 15 s does not create dial storms.
    // `MissedTickBehavior::Delay` ensures that after a long-running
    // event handler the next tick is rescheduled from "now" instead of
    // firing a burst of queued ticks.
    let mut redial_ticker = tokio::time::interval(BOOTSTRAP_REDIAL_INTERVAL);
    redial_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Burn the first immediate tick — bootstrap peers were already
    // dialed at startup in `spawn()`, so the first redial should not
    // happen until BOOTSTRAP_REDIAL_INTERVAL has elapsed.
    redial_ticker.tick().await;

    // TASK-222 §3 — peer-score telemetry sampler. Every PEER_SCORE_SAMPLE_INTERVAL,
    // walk the gossipsub Behaviour's peer list, query each peer's
    // score, and update the buckets exposed via `pqc_p2p::peer_score`
    // globals. pqcd renders these as `pqchain_p2p_gossip_*` gauges.
    let mut peer_score_ticker = tokio::time::interval(PEER_SCORE_SAMPLE_INTERVAL);
    peer_score_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    peer_score_ticker.tick().await;

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    event,
                    &event_tx,
                    &mut swarm,
                    &mut pending_inbound,
                    &mut next_request_id,
                    &mut pending_inbound_snapshot,
                    &mut next_snapshot_request_id,
                    &mut pending_inbound_block_fetch_by_hash,
                    &mut next_block_fetch_by_hash_id,
                ).await;
            }
            _ = redial_ticker.tick() => {
                redial_missing_bootstrap_peers(&mut swarm, &bootstrap_peers);
            }
            _ = peer_score_ticker.tick() => {
                sample_peer_scores(&swarm);
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    SwarmCommand::Publish(msg) => {
                        publish_message(&mut swarm, msg, &subscribed_topics, &topics);
                    }
                    SwarmCommand::Dial(addr) => {
                        if let Err(e) = swarm.dial(addr.clone()) {
                            warn!("dial {addr}: {e}");
                        }
                    }
                    SwarmCommand::RequestBlocks { peer, request } => {
                        // Defense in depth: the application promised to
                        // validate but we re-check so a buggy caller can
                        // never put a malformed frame on the wire.
                        if let Err(e) = request.validate() {
                            warn!(%peer, error = %e, "refusing malformed BlockFetchRequest");
                            let _ = event_tx
                                .send(ViperSwarmEvent::BlockFetchFailed {
                                    peer,
                                    reason: format!("local validation: {e}"),
                                })
                                .await;
                            continue;
                        }
                        let _ = swarm
                            .behaviour_mut()
                            .block_fetch
                            .send_request(&peer, request);
                    }
                    SwarmCommand::ReplyBlockFetch { request_id, response } => {
                        match pending_inbound.remove(&request_id) {
                            Some(channel) => {
                                if swarm
                                    .behaviour_mut()
                                    .block_fetch
                                    .send_response(channel, response)
                                    .is_err()
                                {
                                    warn!(
                                        request_id,
                                        "block-fetch send_response failed (peer disconnected?)"
                                    );
                                }
                            }
                            None => {
                                // Unknown id → application replied too
                                // late, or twice. Drop quietly; the
                                // underlying channel has already been
                                // reaped by libp2p.
                                debug!(request_id, "ReplyBlockFetch for unknown request_id");
                            }
                        }
                    }
                    SwarmCommand::RequestSnapshot { peer, request } => {
                        let _ = swarm
                            .behaviour_mut()
                            .snapshot_fetch
                            .send_request(&peer, request);
                    }
                    SwarmCommand::ReplySnapshotFetch { request_id, response } => {
                        match pending_inbound_snapshot.remove(&request_id) {
                            Some(channel) => {
                                if swarm
                                    .behaviour_mut()
                                    .snapshot_fetch
                                    .send_response(channel, response)
                                    .is_err()
                                {
                                    warn!(
                                        request_id,
                                        "snapshot-fetch send_response failed (peer disconnected?)"
                                    );
                                }
                            }
                            None => {
                                debug!(
                                    request_id,
                                    "ReplySnapshotFetch for unknown request_id"
                                );
                            }
                        }
                    }
                    SwarmCommand::RequestBlockByHash { peer, request } => {
                        let _ = swarm
                            .behaviour_mut()
                            .block_fetch_by_hash
                            .send_request(&peer, request);
                    }
                    SwarmCommand::ReplyBlockFetchByHash { request_id, response } => {
                        match pending_inbound_block_fetch_by_hash.remove(&request_id) {
                            Some(channel) => {
                                if swarm
                                    .behaviour_mut()
                                    .block_fetch_by_hash
                                    .send_response(channel, response)
                                    .is_err()
                                {
                                    warn!(
                                        request_id,
                                        "block-fetch-by-hash send_response failed (peer disconnected?)"
                                    );
                                }
                            }
                            None => {
                                debug!(
                                    request_id,
                                    "ReplyBlockFetchByHash for unknown request_id"
                                );
                            }
                        }
                    }
                    SwarmCommand::Shutdown => {
                        let _ = event_tx.send(ViperSwarmEvent::Stopped("shutdown".into())).await;
                        return;
                    }
                }
            }
        }
    }
}

/// Re-dial any configured bootstrap peer that is not currently connected.
///
/// TASK-148: at production runtime, a bootstrap peer can drop (restart,
/// network blip) and libp2p will NOT re-establish the connection on its
/// own — `ConnectionClosed` is a terminal event in the swarm's view.
/// Without this periodic dial, a follower that loses its producer stays
/// disconnected until someone manually restarts the node.
///
/// `swarm.dial()` for a peer we already have an open connection to is a
/// cheap no-op at the transport layer (libp2p short-circuits it), so
/// iterating the full bootstrap list every tick is safe even when all
/// peers are healthy.
fn redial_missing_bootstrap_peers(
    swarm: &mut Swarm<ViperBehaviour>,
    bootstrap_peers: &[(PeerId, Multiaddr)],
) {
    if bootstrap_peers.is_empty() {
        return;
    }
    let connected: std::collections::HashSet<PeerId> = swarm.connected_peers().copied().collect();
    for (peer_id, addr) in bootstrap_peers {
        if connected.contains(peer_id) {
            continue;
        }
        match swarm.dial(addr.clone()) {
            Ok(_) => {
                info!(
                    peer = %peer_id,
                    addr = %addr,
                    "bootstrap peer redial (periodic)"
                );
            }
            Err(e) => {
                // DialError::DialPeerConditionFalse and similar are
                // expected when libp2p has an in-flight dial attempt
                // for the same peer already — not worth warning on.
                debug!(peer = %peer_id, addr = %addr, "bootstrap redial skipped: {e}");
            }
        }
    }
}

/// TASK-222 §3 — periodic peer-score telemetry sample. Walks the
/// gossipsub Behaviour's connected peers, queries each peer's score,
/// and updates the global counters in `crate::peer_score`. Renders to
/// `pqchain_p2p_gossip_*` gauges via `pqcd::p2p` (which reads from
/// `crate::peer_score::current_snapshot`).
fn sample_peer_scores(swarm: &Swarm<ViperBehaviour>) {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let snap = crate::peer_score::update_from_iter(
        swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .map(|(peer_id, _)| (*peer_id, swarm.behaviour().gossipsub.peer_score(peer_id))),
        now_unix,
    );
    if snap.graylisted > 0 || snap.below_publish > 0 {
        tracing::warn!(
            graylisted = snap.graylisted,
            below_publish = snap.below_publish,
            below_gossip = snap.below_gossip,
            healthy = snap.healthy,
            "peer-score telemetry: degraded peers detected",
        );
    } else {
        tracing::debug!(
            healthy = snap.healthy,
            "peer-score telemetry: all peers healthy",
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_swarm_event(
    event: SwarmEvent<ViperBehaviourEvent>,
    event_tx: &mpsc::Sender<ViperSwarmEvent>,
    swarm: &mut Swarm<ViperBehaviour>,
    pending_inbound: &mut HashMap<
        BlockFetchRequestId,
        request_response::ResponseChannel<BlockFetchResponse>,
    >,
    next_request_id: &mut BlockFetchRequestId,
    pending_inbound_snapshot: &mut HashMap<
        SnapshotFetchRequestId,
        request_response::ResponseChannel<SnapshotFetchResponse>,
    >,
    next_snapshot_request_id: &mut SnapshotFetchRequestId,
    pending_inbound_block_fetch_by_hash: &mut HashMap<
        BlockFetchByHashRequestId,
        request_response::ResponseChannel<BlockFetchByHashResponse>,
    >,
    next_block_fetch_by_hash_id: &mut BlockFetchByHashRequestId,
) {
    // `swarm` is borrowed mutably for the duration of this handler so
    // sub-behaviour callbacks (e.g. `send_response` on block-fetch) can
    // still run, but we deliberately never hand the `&mut Swarm` out
    // past this function — that's what `pending_inbound` is for.
    let _ = swarm; // suppress unused-param warning when arms don't touch it
    match event {
        SwarmEvent::Behaviour(bev) => match bev {
            ViperBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. }) => {
                // `message.source` is populated iff the publisher signed the
                // envelope with its libp2p identity (MessageAuthenticity::Signed).
                // The ValidatorPeerId binding check downstream treats `None`
                // as untrusted regardless of payload content.
                let source = message.source;
                // Topic the frame arrived on. GossipSub drops the hash
                // preimage before delivery (TopicHash is opaque) so this
                // is the only canonical identifier we can surface; the
                // Display impl renders to the human-readable topic
                // string if the hash was derived from one (IdentTopic)
                // and to the raw hex otherwise. We always subscribe via
                // IdentTopic in `spawn`, so the string is readable and
                // matches `Topics::for_chain()` output verbatim — which
                // is exactly what the §4.2 envelope-mismatch check in
                // pqcd needs.
                let topic = message.topic.to_string();
                match decode_gossip_message(message) {
                    Ok(msg) => {
                        let _ = event_tx
                            .send(ViperSwarmEvent::Message { msg, source, topic })
                            .await;
                    }
                    Err(e) => warn!("gossip decode: {e}"),
                }
            }
            ViperBehaviourEvent::Gossipsub(ev) => {
                debug!("gossipsub: {ev:?}");
            }
            ViperBehaviourEvent::Identify(ev) => {
                debug!("identify: {ev:?}");
            }
            ViperBehaviourEvent::Ping(ev) => {
                debug!("ping: {ev:?}");
            }
            ViperBehaviourEvent::Kademlia(ev) => {
                debug!("kademlia: {ev:?}");
            }
            ViperBehaviourEvent::BlockFetch(ev) => {
                handle_block_fetch_event(ev, event_tx, pending_inbound, next_request_id).await;
            }
            ViperBehaviourEvent::SnapshotFetch(ev) => {
                handle_snapshot_fetch_event(
                    ev,
                    event_tx,
                    pending_inbound_snapshot,
                    next_snapshot_request_id,
                )
                .await;
            }
            ViperBehaviourEvent::BlockFetchByHash(ev) => {
                handle_block_fetch_by_hash_event(
                    ev,
                    event_tx,
                    pending_inbound_block_fetch_by_hash,
                    next_block_fetch_by_hash_id,
                )
                .await;
            }
        },
        SwarmEvent::NewListenAddr { address, .. } => {
            info!("listening on {address}");
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            let _ = event_tx.send(ViperSwarmEvent::PeerConnected(peer_id)).await;
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            let _ = event_tx
                .send(ViperSwarmEvent::PeerDisconnected(peer_id))
                .await;
        }
        _ => {}
    }
}

/// Translate libp2p request-response events into application-level
/// [`ViperSwarmEvent`] variants. Inbound requests park their
/// `ResponseChannel` in `pending_inbound`; the application replies
/// later via [`SwarmCommand::ReplyBlockFetch`]. TASK-135 step 12.
async fn handle_block_fetch_event(
    ev: request_response::Event<BlockFetchRequest, BlockFetchResponse>,
    event_tx: &mpsc::Sender<ViperSwarmEvent>,
    pending_inbound: &mut HashMap<
        BlockFetchRequestId,
        request_response::ResponseChannel<BlockFetchResponse>,
    >,
    next_request_id: &mut BlockFetchRequestId,
) {
    match ev {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                // Reject malformed requests without surfacing them to
                // the application — a peer that ships bad frames should
                // not be able to force a chain-store lookup for
                // nonexistent heights.
                if let Err(e) = request.validate() {
                    warn!(%peer, error = %e, "dropping malformed inbound BlockFetchRequest");
                    // Dropping `channel` without sending a response
                    // causes libp2p to signal the peer with an
                    // InboundFailure; this is the correct behaviour.
                    drop(channel);
                    return;
                }
                let request_id = *next_request_id;
                *next_request_id = next_request_id.wrapping_add(1);
                pending_inbound.insert(request_id, channel);
                let _ = event_tx
                    .send(ViperSwarmEvent::BlockFetchRequestReceived {
                        peer,
                        request_id,
                        request,
                    })
                    .await;
            }
            request_response::Message::Response { response, .. } => {
                let _ = event_tx
                    .send(ViperSwarmEvent::BlocksReceived { peer, response })
                    .await;
            }
        },
        request_response::Event::OutboundFailure { peer, error, .. } => {
            let _ = event_tx
                .send(ViperSwarmEvent::BlockFetchFailed {
                    peer,
                    reason: format!("{error}"),
                })
                .await;
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            warn!(%peer, %error, "block-fetch inbound failure");
        }
        request_response::Event::ResponseSent { .. } => {
            debug!("block-fetch response sent");
        }
    }
}

/// Translate libp2p request-response events for the snapshot-fetch
/// sub-behaviour into application-level [`ViperSwarmEvent`] variants.
/// Same park-and-reply pattern as [`handle_block_fetch_event`] —
/// inbound requests stash their `ResponseChannel` in
/// `pending_inbound_snapshot`; the application replies later via
/// [`SwarmCommand::ReplySnapshotFetch`]. Phase 8 M1 cold-start.
async fn handle_snapshot_fetch_event(
    ev: request_response::Event<SnapshotFetchRequest, SnapshotFetchResponse>,
    event_tx: &mpsc::Sender<ViperSwarmEvent>,
    pending_inbound_snapshot: &mut HashMap<
        SnapshotFetchRequestId,
        request_response::ResponseChannel<SnapshotFetchResponse>,
    >,
    next_snapshot_request_id: &mut SnapshotFetchRequestId,
) {
    match ev {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let request_id = *next_snapshot_request_id;
                *next_snapshot_request_id = next_snapshot_request_id.wrapping_add(1);
                pending_inbound_snapshot.insert(request_id, channel);
                let _ = event_tx
                    .send(ViperSwarmEvent::SnapshotFetchRequestReceived {
                        peer,
                        request_id,
                        request,
                    })
                    .await;
            }
            request_response::Message::Response { response, .. } => {
                let _ = event_tx
                    .send(ViperSwarmEvent::SnapshotReceived { peer, response })
                    .await;
            }
        },
        request_response::Event::OutboundFailure { peer, error, .. } => {
            let _ = event_tx
                .send(ViperSwarmEvent::SnapshotFetchFailed {
                    peer,
                    reason: format!("{error}"),
                })
                .await;
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            warn!(%peer, %error, "snapshot-fetch inbound failure");
        }
        request_response::Event::ResponseSent { .. } => {
            debug!("snapshot-fetch response sent");
        }
    }
}

/// ADR-054 §Stage 4 — translate libp2p request-response events for the
/// by-hash block-fetch sub-behaviour into application-level events.
/// Same park-and-reply pattern as [`handle_block_fetch_event`].
async fn handle_block_fetch_by_hash_event(
    ev: request_response::Event<BlockFetchByHashRequest, BlockFetchByHashResponse>,
    event_tx: &mpsc::Sender<ViperSwarmEvent>,
    pending_inbound_block_fetch_by_hash: &mut HashMap<
        BlockFetchByHashRequestId,
        request_response::ResponseChannel<BlockFetchByHashResponse>,
    >,
    next_block_fetch_by_hash_id: &mut BlockFetchByHashRequestId,
) {
    match ev {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let request_id = *next_block_fetch_by_hash_id;
                *next_block_fetch_by_hash_id = next_block_fetch_by_hash_id.wrapping_add(1);
                pending_inbound_block_fetch_by_hash.insert(request_id, channel);
                let _ = event_tx
                    .send(ViperSwarmEvent::BlockFetchByHashRequestReceived {
                        peer,
                        request_id,
                        request,
                    })
                    .await;
            }
            request_response::Message::Response { response, .. } => {
                let _ = event_tx
                    .send(ViperSwarmEvent::BlockFetchByHashReceived { peer, response })
                    .await;
            }
        },
        request_response::Event::OutboundFailure { peer, error, .. } => {
            let _ = event_tx
                .send(ViperSwarmEvent::BlockFetchByHashFailed {
                    peer,
                    reason: format!("{error}"),
                })
                .await;
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            warn!(%peer, %error, "block-fetch-by-hash inbound failure");
        }
        request_response::Event::ResponseSent { .. } => {
            debug!("block-fetch-by-hash response sent");
        }
    }
}

fn publish_message(
    swarm: &mut Swarm<ViperBehaviour>,
    msg: GossipMessage,
    subscribed_topics: &[IdentTopic],
    topics: &Topics,
) {
    let topic_str = match msg.msg_type {
        MessageType::Block => &topics.blocks,
        MessageType::ConsensusVote => &topics.consensus_votes,
        MessageType::Transaction => &topics.transactions,
        MessageType::ValidatorUpdate => &topics.validator_updates,
        MessageType::LightClientAttestation => &topics.light_client_attestations,
    };
    let target_hash = IdentTopic::new(topic_str.as_str()).hash();
    let Some(topic) = subscribed_topics.iter().find(|t| t.hash() == target_hash) else {
        warn!("not subscribed to topic for {:?}", msg.msg_type);
        return;
    };

    let mut data = Vec::new();
    if let Err(e) = ciborium::into_writer(&msg, &mut data) {
        warn!("serialize gossip message: {e}");
        return;
    }
    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
        warn!("gossipsub publish: {e}");
    }
}

fn decode_gossip_message(raw: gossipsub::Message) -> Result<GossipMessage, P2pError> {
    ciborium::from_reader(raw.data.as_slice())
        .map_err(|e| P2pError::InvalidMessage(format!("cbor decode: {e}")))
}

fn listen_addr_for_role(config: &P2pConfig) -> Option<Multiaddr> {
    use crate::config::NodeRole;
    match config.role {
        NodeRole::Validator => config.validator_listen.map(addr_to_multiaddr),
        NodeRole::ValidatorFullnode => config.vfn_listen.map(addr_to_multiaddr),
        NodeRole::PublicFullnode => config.public_listen.map(addr_to_multiaddr),
    }
}

fn addr_to_multiaddr(a: std::net::SocketAddr) -> Multiaddr {
    format!("/ip4/{}/tcp/{}", a.ip(), a.port())
        .parse()
        .expect("valid multiaddr from SocketAddr")
}
