// SPDX-License-Identifier: BUSL-1.1
//! Transport configuration helpers — ADR-041.
//!
//! Actual transport is assembled in `swarm.rs` via `SwarmBuilder`:
//! - Primary: QUIC (identity from libp2p keypair, TLS 1.3 built-in)
//! - Fallback: TCP + TLS 1.3 + yamux
//!
//! X25519MLKEM768 upgrade path (draft-ietf-tls-ecdhe-mlkem-04, codepoint 0x11EC):
//! - rustls-post-quantum 0.2.4+ ships X25519MLKEM768 as a stable CryptoProvider
//!   (verified 2026-05-11 via crates.io).
//! - rustls 0.23.27+ enables `prefer-post-quantum` by default.
//! - libp2p 0.56.0 (released 2025-06-27) shipped, BUT libp2p-tls 0.6.2 and
//!   libp2p-quic 0.13.0 do NOT expose a CryptoProvider injection seam — they
//!   hard-code `rustls::crypto::ring::default_provider()`. Tracking issue
//!   `libp2p/rust-libp2p#6236` (opened 2025-12-28) has zero upstream movement.
//! - Two paths to ship X25519MLKEM768 today: (a) vendor + patch libp2p-tls
//!   and libp2p-quic into `vendor/libp2p-{tls,quic}-pq/` with `[patch.crates-io]`
//!   in the workspace root (mirror of the existing `vendor/slh-dsa/` pattern);
//!   (b) wait on #6236.
//! - Full decision tree, patch surface, and effort estimate in
//!   the private design notes.

use libp2p::tcp;

/// TCP transport config tuned for validator network.
///
/// `nodelay(true)` reduces latency for consensus vote propagation.
pub fn validator_tcp_config() -> tcp::Config {
    tcp::Config::default().nodelay(true)
}
