// SPDX-License-Identifier: BUSL-1.1
//! P2P networking layer for Viper PQ Chain — ADR-041.
//!
//! Transport: QUIC primary, TCP/TLS 1.3 fallback.
//! Handshake: TLS 1.3 with **classical X25519** in M1 baseline. The
//! X25519MLKEM768 hybrid-PQ group (codepoint 0x11EC,
//! draft-ietf-tls-ecdhe-mlkem-04) is the **M1b target** per ADR-041
//! 2026-04-22 addendum.
//!
//! **Status as of 2026-05-11 (re-checked, see
//! the private design notes):** rustls-post-quantum
//! 0.2.4 has shipped X25519MLKEM768 as a stable `CryptoProvider`; rustls 0.23.27+
//! enables `prefer-post-quantum` by default; the IANA codepoint is assigned.
//! The single remaining blocker is upstream `rust-libp2p` issue #6236 — the
//! `libp2p-tls` 0.6.2 and `libp2p-quic` 0.13.0 `Config` types hard-code
//! `rustls::crypto::ring::default_provider()` and offer no injection seam.
//! That issue has zero upstream movement (no assignee, no PR) since 2025-12-28.
//!
//! The `hybrid-kem-tls` Cargo feature and `P2pConfig::hybrid_kem_enabled` runtime
//! flag referenced in this doc-comment are **NOT YET DECLARED** in the crate —
//! they are the planned consumer-side wiring once the operator picks a path
//! (vendored libp2p-tls fork vs. wait-on-upstream). See the planning doc above
//! for the decision tree.
//!
//! **Honest scope**: viper-pq-1 transport authentication is *currently
//! classical*. The chain's post-quantum guarantees (ADR-053 §T1.2 ForkDigest,
//! ML-DSA validator signatures, SLH-DSA archival) apply at the *ledger* layer —
//! every signing preimage carries a PQ commitment regardless of how the bytes
//! travel between hosts. A quantum adversary capable of breaking X25519 on the
//! wire still cannot forge on-chain signatures, but could MITM the libp2p
//! handshake. That gap closes when M1b lands.
//!
//! Gossip: GossipSub v1.2 with IDONTWANT (critical for PQ signatures 2-16 KB).
//! GossipSub message authenticity uses the libp2p identity key (not ML-DSA);
//! block bodies inside the gossip envelope carry their own ML-DSA commit
//! signatures, which are the layer the consensus rules actually enforce.
//! A PQ binding of the libp2p session identity to the on-chain validator key
//! is tracked as a separate follow-up.
//!
//! Discovery: bootstrap → ENR-over-DNS → discv5/Kademlia → on-chain validator registry.

pub mod block_fetch;
pub mod block_fetch_by_hash;
pub mod config;
pub mod error;
pub mod message;
pub mod peer;
pub mod protocols;
pub mod snapshot_fetch;
pub mod topics;

#[cfg(feature = "libp2p-backend")]
pub mod behaviour;
#[cfg(feature = "libp2p-backend")]
pub mod peer_score;
#[cfg(feature = "libp2p-backend")]
pub mod swarm;
#[cfg(feature = "libp2p-backend")]
pub mod transport;

pub use block_fetch::{
    BlockFetchRequest, BlockFetchRequestError, BlockFetchResponse, MAX_BLOCKS_PER_REQUEST,
};
pub use block_fetch_by_hash::{BlockFetchByHashRequest, BlockFetchByHashResponse};
pub use config::{NodeRole, P2pConfig};
pub use error::P2pError;
pub use message::{GossipMessage, MessageType};
pub use peer::{validator_peer_id_matches, PeerInfo, ValidatorPeerId};
pub use protocols::Protocols;
pub use snapshot_fetch::{SnapshotFetchRequest, SnapshotFetchResponse};
pub use topics::Topics;

// Re-export the libp2p types that downstream crates need to build a
// SwarmHandle without pulling libp2p into their own Cargo.toml. Only
// available when the libp2p backend is compiled in.
#[cfg(feature = "libp2p-backend")]
pub use libp2p::{identity::Keypair, multiaddr::Protocol, Multiaddr, PeerId};
#[cfg(feature = "libp2p-backend")]
pub use swarm::{
    spawn as spawn_swarm, BlockFetchByHashRequestId, BlockFetchRequestId, SnapshotFetchRequestId,
    SwarmCommand, SwarmEventRx, SwarmHandle, ViperSwarmEvent,
};
