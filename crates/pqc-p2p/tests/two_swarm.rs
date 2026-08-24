// SPDX-License-Identifier: BUSL-1.1
//! Integration test — two in-process pqc-p2p swarms exchange GossipMessages.
//!
//! Covers SPEC-P2P-002 §10 targets:
//!   T4 — publish + receive on each topic (bidirectional)
//!   T6 — messages arrive on the topic mapped to their MessageType
//!
//! Execution: `cargo test -p pqc-p2p --features libp2p-backend`.
//!
//! Notes on n=2 mesh:
//! libp2p-gossipsub's default `mesh_n_low=4` never stabilises with only two
//! peers. This test overrides to `(low=1, n=1, high=2)` via P2pConfig —
//! doubling as a regression guard against default drift and as the same
//! parameter set used by the devnet-2 three-node cutover.

#![cfg(feature = "libp2p-backend")]

use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use pqc_p2p::{
    config::{NodeRole, P2pConfig},
    BlockFetchRequest, BlockFetchResponse, GossipMessage, Keypair, MessageType, Multiaddr, PeerId,
    SnapshotFetchRequest, SnapshotFetchResponse, SwarmEventRx, SwarmHandle, ViperSwarmEvent,
};
use tokio::time::{sleep, timeout, Instant};

const CHAIN_ID: &str = "viper-integration-test";

/// Two-peer mesh config on a fixed loopback port. TCP only — simpler than QUIC
/// for loopback tests, and covers the fallback transport path specified in ADR-041.
fn n2_config(role: NodeRole, listen: SocketAddr) -> P2pConfig {
    P2pConfig {
        role: role.clone(),
        validator_listen: matches!(role, NodeRole::Validator).then_some(listen),
        vfn_listen: matches!(role, NodeRole::ValidatorFullnode).then_some(listen),
        public_listen: matches!(role, NodeRole::PublicFullnode).then_some(listen),
        bootstrap_peers: vec![],
        gossip_mesh_n: 1,
        gossip_mesh_n_low: 1,
        gossip_mesh_n_high: 2,
        quic_enabled: false,
        tcp_tls_fallback: true,
        max_peers_per_asn: 8,
        chain_id: CHAIN_ID.into(),
        // Loopback test — classical X25519 only. The hybrid PQ path is
        // exercised by tests/hybrid_kem_negotiation.rs (which inspects
        // the rustls kx_groups list directly rather than running a
        // Swarm pair, see that file's preamble for the rationale).
        hybrid_kem_enabled: false,
    }
}

/// Pick a free loopback port in a dedicated range and bind + release to confirm.
fn reserve_port(start: u16) -> u16 {
    for port in start..(start + 200) {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        if TcpListener::bind(addr).is_ok() {
            return port;
        }
    }
    panic!("no free port found starting at {start}");
}

/// Spawn a validator swarm on a fixed port. Returns (handle, events, port).
async fn spawn_validator(port: u16) -> (SwarmHandle, SwarmEventRx, u16) {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (handle, rx) = pqc_p2p::spawn_swarm(
        n2_config(NodeRole::Validator, addr),
        Keypair::generate_ed25519(),
    )
    .expect("swarm spawn");
    sleep(Duration::from_millis(400)).await; // let the listener bind
    (handle, rx, port)
}

/// Drain events for a short window (unblocks bind-time chatter before assertions).
async fn drain_briefly(rx: &mut SwarmEventRx, window: Duration) {
    let deadline = Instant::now() + window;
    while let Ok(res) = timeout(
        deadline.saturating_duration_since(Instant::now()),
        rx.recv(),
    )
    .await
    {
        if res.is_none() {
            break;
        }
    }
}

/// Wait for the first PeerConnected event, asserting within `deadline`.
async fn expect_peer_connected(rx: &mut SwarmEventRx, tag: &str, deadline: Duration) {
    let got = timeout(deadline, async {
        while let Some(ev) = rx.recv().await {
            if matches!(ev, ViperSwarmEvent::PeerConnected(_)) {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(got, "[{tag}] no PeerConnected within {deadline:?}");
}

/// Wait for a GossipMessage of the expected type; fail on timeout or mismatch.
async fn expect_msg(rx: &mut SwarmEventRx, want: MessageType, tag: &str) -> GossipMessage {
    let deadline = Duration::from_secs(20);
    let out = timeout(deadline, async {
        while let Some(ev) = rx.recv().await {
            if let ViperSwarmEvent::Message {
                msg,
                source: _,
                topic: _,
            } = ev
            {
                if msg.msg_type == want {
                    return Some(msg);
                }
                // A message arrived on a topic that routes to a DIFFERENT
                // MessageType — e.g. a Block-envelope published on the vote
                // topic. Our swarm's publish path refuses to cross-post so
                // this cannot happen naturally; receiving one would signal
                // a topic/envelope desync bug.
                panic!(
                    "[{tag}] received unexpected {:?} when waiting for {:?}",
                    msg.msg_type, want
                );
            }
        }
        None
    })
    .await
    .ok()
    .flatten();
    out.unwrap_or_else(|| panic!("[{tag}] no {want:?} within {deadline:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_swarms_gossip_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();

    // Pick two distinct free ports. The two swarms bind and establish a
    // TCP+yamux+gossipsub session over loopback.
    let port_a = reserve_port(37100);
    let port_b = reserve_port(37300);
    assert_ne!(port_a, port_b);

    let (handle_a, mut rx_a, _) = spawn_validator(port_a).await;
    let (handle_b, mut rx_b, _) = spawn_validator(port_b).await;

    drain_briefly(&mut rx_a, Duration::from_millis(100)).await;
    drain_briefly(&mut rx_b, Duration::from_millis(100)).await;

    // A dials B.
    let dial_b: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port_b}").parse().unwrap();
    handle_a.dial(dial_b).await.expect("A dial B");

    expect_peer_connected(&mut rx_a, "A", Duration::from_secs(8)).await;
    expect_peer_connected(&mut rx_b, "B", Duration::from_secs(8)).await;

    // Let the gossipsub mesh graft — heartbeat interval is 1s; a couple is enough.
    sleep(Duration::from_secs(3)).await;

    let cases: [(MessageType, &[u8]); 4] = [
        (MessageType::Block, b"block-from-a"),
        (MessageType::ConsensusVote, b"vote-from-a"),
        (MessageType::Transaction, b"tx-from-a"),
        (MessageType::ValidatorUpdate, b"vu-from-a"),
    ];
    for (kind, payload) in cases {
        let msg = GossipMessage::new(kind, CHAIN_ID, payload.to_vec());
        handle_a.publish(msg).await.expect("A publish");
        let got = expect_msg(&mut rx_b, kind, "B").await;
        assert_eq!(got.chain_id, CHAIN_ID, "chain_id on {kind:?}");
        assert_eq!(got.payload, payload, "payload on {kind:?}");
    }

    let cases_back: [(MessageType, &[u8]); 4] = [
        (MessageType::Block, b"block-from-b"),
        (MessageType::ConsensusVote, b"vote-from-b"),
        (MessageType::Transaction, b"tx-from-b"),
        (MessageType::ValidatorUpdate, b"vu-from-b"),
    ];
    for (kind, payload) in cases_back {
        let msg = GossipMessage::new(kind, CHAIN_ID, payload.to_vec());
        handle_b.publish(msg).await.expect("B publish");
        let got = expect_msg(&mut rx_a, kind, "A").await;
        assert_eq!(got.chain_id, CHAIN_ID, "chain_id on {kind:?} (b→a)");
        assert_eq!(got.payload, payload, "payload on {kind:?} (b→a)");
    }

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// SPEC-CONSENSUS-001 §8.3 — a SignedVote (CBOR-encoded) must survive
// transport byte-for-byte when wrapped in a GossipMessage on the
// ConsensusVote topic. Guards against a regression where the envelope or
// transport layer transforms the payload in a way that would desync
// signed-vote preimages between nodes (TASK-136 prep for real BFT vote
// exchange — the current devnet emits these in observation mode and the
// wire-byte fidelity of the payload is the load-bearing invariant).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_vote_bytes_roundtrip_over_gossip() {
    let _ = tracing_subscriber::fmt::try_init();

    let port_a = reserve_port(37500);
    let port_b = reserve_port(37700);
    assert_ne!(port_a, port_b);

    let (handle_a, mut rx_a, _) = spawn_validator(port_a).await;
    let (handle_b, mut rx_b, _) = spawn_validator(port_b).await;

    drain_briefly(&mut rx_a, Duration::from_millis(100)).await;
    drain_briefly(&mut rx_b, Duration::from_millis(100)).await;

    let dial_b: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port_b}").parse().unwrap();
    handle_a.dial(dial_b).await.expect("A dial B");
    expect_peer_connected(&mut rx_a, "A", Duration::from_secs(8)).await;
    expect_peer_connected(&mut rx_b, "B", Duration::from_secs(8)).await;

    sleep(Duration::from_secs(3)).await;

    // Construct a Precommit vote with a realistic signature size (ML-DSA-65
    // upper bound, 3309 bytes) so the test doubles as a soft guard against
    // any future GossipSub max_transmit_size regression in the mesh config.
    let vote = pqc_types::SignedVote {
        msg_type: pqc_types::MSG_TYPE_PRECOMMIT,
        height: 1234,
        round: 0,
        block_hash: [0x77; 32],
        validator_address: [0x88; 32],
        signature: vec![0xA5; 3309],
    };
    let payload = pqc_types::encode_signed_vote_bytes(&vote);
    let msg = GossipMessage::new(MessageType::ConsensusVote, CHAIN_ID, payload);

    handle_a.publish(msg).await.expect("A publish vote");
    let got = expect_msg(&mut rx_b, MessageType::ConsensusVote, "B").await;
    let decoded =
        pqc_types::decode_signed_vote(&got.payload).expect("B decodes vote payload byte-for-byte");
    assert_eq!(
        decoded, vote,
        "SignedVote must survive gossip transport byte-for-byte"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

/// TASK-172 — realistic-size Transaction payload survives gossip
/// byte-for-byte. `tx_envelope` produces CBOR-encoded raw-tx bytes of
/// varying size: a regular Transfer is ~300 B, a `ValidatorRegister`
/// with ML-DSA-65 pk + SLH-DSA-SHAKE-256s archival pk runs ~3.7 KB.
/// The existing `two_swarms_gossip_roundtrip` test only covers ~10 B
/// payloads; this test guards against any GossipSub max_transmit_size
/// regression or chunk boundary bug that would only surface on
/// realistic payloads — a receive-side mempool admission would
/// silently fail if even one byte diverged.
///
/// The payload is opaque to pqc-p2p (no pqc-tx dep here by design);
/// we fabricate a pattern-filled 4 KB buffer with a magic header/tail
/// so the assertion catches both truncation and mid-buffer corruption.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_bytes_roundtrip_over_gossip_realistic_size() {
    let _ = tracing_subscriber::fmt::try_init();

    let port_a = reserve_port(40100);
    let port_b = reserve_port(40300);
    assert_ne!(port_a, port_b);

    let (handle_a, mut rx_a, _) = spawn_validator(port_a).await;
    let (handle_b, mut rx_b, _) = spawn_validator(port_b).await;

    drain_briefly(&mut rx_a, Duration::from_millis(100)).await;
    drain_briefly(&mut rx_b, Duration::from_millis(100)).await;

    let dial_b: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port_b}").parse().unwrap();
    handle_a.dial(dial_b).await.expect("A dial B");
    expect_peer_connected(&mut rx_a, "A", Duration::from_secs(8)).await;
    expect_peer_connected(&mut rx_b, "B", Duration::from_secs(8)).await;

    sleep(Duration::from_secs(3)).await;

    // 4 KB payload with magic header + sequence body + magic tail.
    // A truncation bug would drop the tail; a mid-buffer corruption
    // bug would break the sequence; re-encoding would misalign the
    // magic markers.
    let mut payload = Vec::with_capacity(4096);
    payload.extend_from_slice(b"VIPER-TX-HEAD:");
    for i in 0..(4096 - 28) {
        payload.push((i % 251) as u8);
    }
    payload.extend_from_slice(b":VIPER-TX-TAIL");
    assert_eq!(payload.len(), 4096);

    let msg = GossipMessage::new(MessageType::Transaction, CHAIN_ID, payload.clone());
    handle_a.publish(msg).await.expect("A publish tx");

    let got = expect_msg(&mut rx_b, MessageType::Transaction, "B").await;
    assert_eq!(got.chain_id, CHAIN_ID);
    assert_eq!(
        got.payload.len(),
        payload.len(),
        "tx payload length must survive transport — {} != {}",
        got.payload.len(),
        payload.len()
    );
    assert_eq!(
        got.payload, payload,
        "realistic-size tx payload must survive gossip byte-for-byte \
         — a single-byte divergence would break mempool admission on \
         the receive side (signature verify fails on tampered bytes)"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

/// SPEC-P2P-002 §4.4 — gossipsub `MessageAuthenticity::Signed` MUST
/// populate `ViperSwarmEvent::Message.source` with the publisher's
/// libp2p PeerId. This is the plumbing the M1 ValidatorPeerId binding
/// check relies on: without a `Some(source)`, pqcd cannot cross-check
/// the publisher against its pinned validator allow-list (TASK-137
/// part B). Regression guard — if someone flips back to `Anonymous`
/// authenticity this test must fail before a silent binding bypass
/// ships to devnet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gossipsub_message_source_is_publisher_peer_id() {
    let _ = tracing_subscriber::fmt::try_init();

    let port_a = reserve_port(37900);
    let port_b = reserve_port(38100);
    assert_ne!(port_a, port_b);

    // Deterministic keypair for A so we know its PeerId ahead of time.
    let keypair_a = Keypair::generate_ed25519();
    let peer_id_a = PeerId::from(keypair_a.public());

    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let (handle_a, mut rx_a) =
        pqc_p2p::spawn_swarm(n2_config(NodeRole::Validator, addr_a), keypair_a)
            .expect("swarm A spawn");
    let (handle_b, mut rx_b, _) = spawn_validator(port_b).await;
    sleep(Duration::from_millis(400)).await;

    drain_briefly(&mut rx_a, Duration::from_millis(100)).await;
    drain_briefly(&mut rx_b, Duration::from_millis(100)).await;

    let dial_b: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port_b}").parse().unwrap();
    handle_a.dial(dial_b).await.expect("A dial B");
    expect_peer_connected(&mut rx_a, "A", Duration::from_secs(8)).await;
    expect_peer_connected(&mut rx_b, "B", Duration::from_secs(8)).await;

    sleep(Duration::from_secs(3)).await;

    let msg = GossipMessage::new(
        MessageType::Transaction,
        CHAIN_ID,
        b"tx-with-source".to_vec(),
    );
    handle_a.publish(msg).await.expect("A publish tx");

    let deadline = Duration::from_secs(20);
    let source_on_b = timeout(deadline, async {
        while let Some(ev) = rx_b.recv().await {
            if let ViperSwarmEvent::Message {
                msg,
                source,
                topic: _,
            } = ev
            {
                if msg.msg_type == MessageType::Transaction {
                    return source;
                }
            }
        }
        None
    })
    .await
    .ok()
    .flatten();

    assert_eq!(
        source_on_b,
        Some(peer_id_a),
        "B must see A's PeerId as the gossip source — required for \
         ValidatorPeerId binding (TASK-137)"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

/// TASK-135 step 12 — `/viper/{chain_id}/block-fetch/1.0.0` request /
/// response roundtrip between two swarms. A issues `RequestBlocks`
/// against a known PeerId for B; B surfaces `BlockFetchRequestReceived`,
/// replies with synthetic block bytes; A observes `BlocksReceived` with
/// the exact same bytes (byte-for-byte fidelity is load-bearing — a
/// responder that encodes blocks slightly differently would break the
/// header→body linkage on the receive side).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_fetch_request_response_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();

    let port_a = reserve_port(38300);
    let port_b = reserve_port(38500);
    assert_ne!(port_a, port_b);

    // Deterministic keypair for B so A can call request_blocks with a
    // known target PeerId without having to snoop the PeerConnected
    // payload.
    let keypair_b = Keypair::generate_ed25519();
    let peer_id_b = PeerId::from(keypair_b.public());

    let (handle_a, mut rx_a, _) = spawn_validator(port_a).await;
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    let (handle_b, mut rx_b) =
        pqc_p2p::spawn_swarm(n2_config(NodeRole::Validator, addr_b), keypair_b)
            .expect("swarm B spawn");
    sleep(Duration::from_millis(400)).await;

    drain_briefly(&mut rx_a, Duration::from_millis(100)).await;
    drain_briefly(&mut rx_b, Duration::from_millis(100)).await;

    let dial_b: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port_b}").parse().unwrap();
    handle_a.dial(dial_b).await.expect("A dial B");
    expect_peer_connected(&mut rx_a, "A", Duration::from_secs(8)).await;
    expect_peer_connected(&mut rx_b, "B", Duration::from_secs(8)).await;

    // A requests heights 10..=14 (5 blocks) from B.
    let request = BlockFetchRequest {
        from_height: 10,
        to_height: 14,
    };
    handle_a
        .request_blocks(peer_id_b, request.clone())
        .await
        .expect("A request_blocks");

    // B surfaces the inbound request; reply with 5 synthetic blocks
    // that carry the height in a distinctive tag so we can verify A
    // receives them in-order and byte-for-byte.
    let (request_id_on_b, request_on_b) = timeout(Duration::from_secs(8), async {
        while let Some(ev) = rx_b.recv().await {
            if let ViperSwarmEvent::BlockFetchRequestReceived {
                request_id,
                request,
                ..
            } = ev
            {
                return Some((request_id, request));
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
    .expect("B did not surface BlockFetchRequestReceived within 8s");

    assert_eq!(
        request_on_b, request,
        "request bytes must roundtrip via CBOR"
    );

    let synthetic: Vec<Vec<u8>> = (request.from_height..=request.to_height)
        .map(|h| {
            let mut v = b"block@".to_vec();
            v.extend_from_slice(&h.to_be_bytes());
            v
        })
        .collect();
    let response = BlockFetchResponse {
        blocks: synthetic.clone(),
    };
    handle_b
        .reply_block_fetch(request_id_on_b, response)
        .await
        .expect("B reply_block_fetch");

    // A observes the response.
    let response_on_a = timeout(Duration::from_secs(8), async {
        while let Some(ev) = rx_a.recv().await {
            if let ViperSwarmEvent::BlocksReceived { response, .. } = ev {
                return Some(response);
            }
            if let ViperSwarmEvent::BlockFetchFailed { peer, reason } = ev {
                panic!("[A] unexpected BlockFetchFailed from {peer}: {reason}");
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
    .expect("A did not observe BlocksReceived within 8s");

    assert_eq!(
        response_on_a.blocks.len(),
        5,
        "expected 5 block bodies, got {}",
        response_on_a.blocks.len()
    );
    assert_eq!(
        response_on_a.blocks, synthetic,
        "block bytes must roundtrip byte-for-byte — a responder-side \
         re-encode would invalidate block hashes on the receive side"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

/// Phase 8 M1 cold-start — `/viper/{chain_id}/snapshot/1.0.0` request /
/// response roundtrip. A requests the latest snapshot from B; B serves
/// a synthetic 8 KiB payload at height 100_000; A observes
/// `SnapshotReceived` with byte-for-byte matching data. Fidelity is
/// load-bearing: `bootstrap_from_external_snapshot` will reject a
/// snapshot whose embedded `state_root` doesn't match the bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_fetch_request_response_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();

    let port_a = reserve_port(39100);
    let port_b = reserve_port(39300);
    assert_ne!(port_a, port_b);

    let keypair_b = Keypair::generate_ed25519();
    let peer_id_b = PeerId::from(keypair_b.public());

    let (handle_a, mut rx_a, _) = spawn_validator(port_a).await;
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    let (handle_b, mut rx_b) =
        pqc_p2p::spawn_swarm(n2_config(NodeRole::Validator, addr_b), keypair_b)
            .expect("swarm B spawn");
    sleep(Duration::from_millis(400)).await;

    drain_briefly(&mut rx_a, Duration::from_millis(100)).await;
    drain_briefly(&mut rx_b, Duration::from_millis(100)).await;

    let dial_b: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port_b}").parse().unwrap();
    handle_a.dial(dial_b).await.expect("A dial B");
    expect_peer_connected(&mut rx_a, "A", Duration::from_secs(8)).await;
    expect_peer_connected(&mut rx_b, "B", Duration::from_secs(8)).await;

    handle_a
        .request_snapshot(peer_id_b, SnapshotFetchRequest::default())
        .await
        .expect("A request_snapshot");

    // B sees the inbound request; reply with a synthetic snapshot.
    let (request_id_on_b, request_on_b) = timeout(Duration::from_secs(8), async {
        while let Some(ev) = rx_b.recv().await {
            if let ViperSwarmEvent::SnapshotFetchRequestReceived {
                request_id,
                request,
                ..
            } = ev
            {
                return Some((request_id, request));
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
    .expect("B did not surface SnapshotFetchRequestReceived within 8s");

    assert!(request_on_b.at_height.is_none());

    let synthetic = vec![0xBE; 8 * 1024];
    let response = SnapshotFetchResponse {
        snapshot_bytes: synthetic.clone(),
        snapshot_height: 100_000,
    };
    handle_b
        .reply_snapshot_fetch(request_id_on_b, response)
        .await
        .expect("B reply_snapshot_fetch");

    let response_on_a = timeout(Duration::from_secs(8), async {
        while let Some(ev) = rx_a.recv().await {
            if let ViperSwarmEvent::SnapshotReceived { response, .. } = ev {
                return Some(response);
            }
            if let ViperSwarmEvent::SnapshotFetchFailed { peer, reason } = ev {
                panic!("[A] unexpected SnapshotFetchFailed from {peer}: {reason}");
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
    .expect("A did not observe SnapshotReceived within 8s");

    assert_eq!(response_on_a.snapshot_height, 100_000);
    assert!(!response_on_a.is_empty());
    assert_eq!(
        response_on_a.snapshot_bytes, synthetic,
        "snapshot bytes must roundtrip byte-for-byte — state_root binding \
         breaks with any re-encode"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

/// Phase 8 M1 cold-start — empty response path: a peer that has not
/// yet written a trusted checkpoint MUST be able to reply with an
/// empty payload without synthesising garbage bytes. Surfaces as
/// `SnapshotReceived` on the requester with `is_empty() == true` and
/// `snapshot_height == 0`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_fetch_empty_response_signals_no_checkpoint() {
    let _ = tracing_subscriber::fmt::try_init();

    let port_a = reserve_port(39500);
    let port_b = reserve_port(39700);
    assert_ne!(port_a, port_b);

    let keypair_b = Keypair::generate_ed25519();
    let peer_id_b = PeerId::from(keypair_b.public());

    let (handle_a, mut rx_a, _) = spawn_validator(port_a).await;
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    let (handle_b, mut rx_b) =
        pqc_p2p::spawn_swarm(n2_config(NodeRole::Validator, addr_b), keypair_b)
            .expect("swarm B spawn");
    sleep(Duration::from_millis(400)).await;

    drain_briefly(&mut rx_a, Duration::from_millis(100)).await;
    drain_briefly(&mut rx_b, Duration::from_millis(100)).await;

    let dial_b: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port_b}").parse().unwrap();
    handle_a.dial(dial_b).await.expect("A dial B");
    expect_peer_connected(&mut rx_a, "A", Duration::from_secs(8)).await;
    expect_peer_connected(&mut rx_b, "B", Duration::from_secs(8)).await;

    handle_a
        .request_snapshot(peer_id_b, SnapshotFetchRequest::default())
        .await
        .expect("A request_snapshot");

    let request_id_on_b = timeout(Duration::from_secs(8), async {
        while let Some(ev) = rx_b.recv().await {
            if let ViperSwarmEvent::SnapshotFetchRequestReceived { request_id, .. } = ev {
                return Some(request_id);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
    .expect("B did not surface inbound request");

    handle_b
        .reply_snapshot_fetch(request_id_on_b, SnapshotFetchResponse::default())
        .await
        .expect("B reply empty");

    let response_on_a = timeout(Duration::from_secs(8), async {
        while let Some(ev) = rx_a.recv().await {
            if let ViperSwarmEvent::SnapshotReceived { response, .. } = ev {
                return Some(response);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
    .expect("A did not observe SnapshotReceived within 8s");

    assert!(
        response_on_a.is_empty(),
        "empty response must signal 'no snapshot'; got {} bytes",
        response_on_a.snapshot_bytes.len()
    );
    assert_eq!(response_on_a.snapshot_height, 0);

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

/// TASK-135 step 12 — a malformed request (range > MAX_BLOCKS_PER_REQUEST)
/// MUST fail validation locally before hitting the wire. Guards the
/// defense-in-depth check in the swarm driver (`SwarmCommand::RequestBlocks`
/// re-validates on dispatch, producing `BlockFetchFailed` without
/// contacting the peer).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_fetch_request_rejects_oversized_range() {
    let _ = tracing_subscriber::fmt::try_init();

    let port_a = reserve_port(38700);
    let port_b = reserve_port(38900);
    assert_ne!(port_a, port_b);

    let (handle_a, mut rx_a, _) = spawn_validator(port_a).await;
    let keypair_b = Keypair::generate_ed25519();
    let peer_id_b = PeerId::from(keypair_b.public());
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    let (handle_b, mut rx_b) =
        pqc_p2p::spawn_swarm(n2_config(NodeRole::Validator, addr_b), keypair_b)
            .expect("swarm B spawn");
    sleep(Duration::from_millis(400)).await;

    drain_briefly(&mut rx_a, Duration::from_millis(100)).await;
    drain_briefly(&mut rx_b, Duration::from_millis(100)).await;

    let dial_b: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port_b}").parse().unwrap();
    handle_a.dial(dial_b).await.expect("A dial B");
    expect_peer_connected(&mut rx_a, "A", Duration::from_secs(8)).await;
    expect_peer_connected(&mut rx_b, "B", Duration::from_secs(8)).await;

    // Oversized range: MAX_BLOCKS_PER_REQUEST=16, so ask for 17 heights.
    let bad = BlockFetchRequest {
        from_height: 1,
        to_height: 17,
    };
    handle_a
        .request_blocks(peer_id_b, bad)
        .await
        .expect("queued");

    // Expect BlockFetchFailed on A — no request hit the wire.
    let failed = timeout(Duration::from_secs(4), async {
        while let Some(ev) = rx_a.recv().await {
            if let ViperSwarmEvent::BlockFetchFailed { reason, .. } = ev {
                return Some(reason);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
    .expect("A did not surface BlockFetchFailed within 4s");
    assert!(
        failed.contains("local validation"),
        "reason should mention local validation, got: {failed}"
    );

    // Expect NO request to have hit B.
    let leaked = timeout(Duration::from_millis(500), async {
        while let Some(ev) = rx_b.recv().await {
            if matches!(ev, ViperSwarmEvent::BlockFetchRequestReceived { .. }) {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(
        !leaked,
        "oversized request must NOT be forwarded to the peer — validation \
         is a local no-op, not a per-peer policy"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}
