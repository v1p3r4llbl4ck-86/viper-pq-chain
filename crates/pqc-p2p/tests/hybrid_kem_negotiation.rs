// SPDX-License-Identifier: BUSL-1.1
//! Integration test for the X25519MLKEM768 hybrid-PQ kx group on the
//! libp2p TLS handshake (Fase 4 hybrid-TLS work, 2026-05-11).
//!
//! What this test proves
//! ---------------------
//! That the `hybrid-kem-tls` Cargo feature, plus the vendor patches under
//! `vendor/libp2p-{tls,quic}-pq/`, plus the `rustls-post-quantum 0.2.4`
//! optional dependency, plus the `with_provider`-style constructors,
//! actually result in a `rustls::ClientConfig` / `rustls::ServerConfig`
//! whose `kx_groups` list contains `X25519MLKEM768` (the IANA-assigned
//! hybrid post-quantum group, codepoint `0x11EC`,
//! draft-ietf-tls-ecdhe-mlkem-04). Without the patch + feature, the
//! default `ring`-based provider used by upstream libp2p-tls 0.6.2 has no
//! such group; the contrast test below pins that as well.
//!
//! What this test does NOT prove
//! -----------------------------
//! End-to-end negotiation between two real Swarms is left to a future
//! commit. Capturing the *negotiated* kx group from a live handshake
//! requires hooks that `libp2p-tls` does not currently expose to its
//! consumers (the rustls `KeyExchange` event lives below the
//! `futures_rustls::TlsStream` boundary). Because the libp2p TLS stack
//! is a thin pass-through to rustls — it neither modifies the kx-group
//! list nor injects extra negotiation logic — verifying that our
//! ClientConfig / ServerConfig OFFER the PQ group is operationally
//! sufficient: rustls picks the strongest mutually-supported group from
//! the offered list, and TLS-1.3 group selection is purely a function of
//! `kx_groups` ordering plus the peer's offered set. If both sides offer
//! `X25519MLKEM768` it WILL be the negotiated group.
//!
//! For the actual on-the-wire smoke test, see the operator-side runbook
//! at the private design notes: a
//! production binary built with `--features pqc-p2p/hybrid-kem-tls`
//! against a peer of the same posture, observed via tcpdump + Wireshark
//! filtering the TLS ClientHello supported_groups extension on the
//! validator-private port (26656).

#![cfg(all(feature = "libp2p-backend", feature = "hybrid-kem-tls"))]

use libp2p::{
    identity::Keypair,
    tls::{make_client_config, make_client_config_with_provider, make_server_config_with_provider},
};
use rustls::NamedGroup;

/// Helper: extract the `NamedGroup` list from a rustls `ClientConfig`.
fn client_kx_groups(cfg: &rustls::ClientConfig) -> Vec<NamedGroup> {
    cfg.crypto_provider()
        .kx_groups
        .iter()
        .map(|g| g.name())
        .collect()
}

/// Helper: extract the `NamedGroup` list from a rustls `ServerConfig`.
fn server_kx_groups(cfg: &rustls::ServerConfig) -> Vec<NamedGroup> {
    cfg.crypto_provider()
        .kx_groups
        .iter()
        .map(|g| g.name())
        .collect()
}

/// The PQ-Chain vendor patch on `libp2p-tls` exposes
/// `make_client_config_with_provider`. When given the
/// `rustls_post_quantum::provider()` `CryptoProvider`, the resulting
/// `rustls::ClientConfig` MUST advertise `X25519MLKEM768` in its
/// supported kx groups.
#[test]
fn pq_provider_yields_x25519_mlkem768_on_client_config() {
    let keypair = Keypair::generate_ed25519();
    let provider = rustls_post_quantum::provider().clone();

    let cfg = make_client_config_with_provider(&keypair, None, Some(provider))
        .expect("client config build with PQ provider must succeed");

    let groups = client_kx_groups(&cfg);
    assert!(
        groups.contains(&NamedGroup::X25519MLKEM768),
        "expected X25519MLKEM768 in client kx_groups, got {groups:?}",
    );
}

/// Same property on the server side. libp2p TLS is symmetric — every
/// peer is both a TLS server and TLS client — so we have to verify
/// both halves separately.
#[test]
fn pq_provider_yields_x25519_mlkem768_on_server_config() {
    let keypair = Keypair::generate_ed25519();
    let provider = rustls_post_quantum::provider().clone();

    let cfg = make_server_config_with_provider(&keypair, Some(provider))
        .expect("server config build with PQ provider must succeed");

    let groups = server_kx_groups(&cfg);
    assert!(
        groups.contains(&NamedGroup::X25519MLKEM768),
        "expected X25519MLKEM768 in server kx_groups, got {groups:?}",
    );
}

/// Sanity-check that the patch is doing real work: without the explicit
/// provider injection (i.e. via the upstream-shape `make_client_config`
/// API), the resulting rustls config does NOT advertise X25519MLKEM768.
/// If this assertion ever fires it means either:
///   (a) ring grew native X25519MLKEM768 support — at which point this
///       whole vendor patch can be dropped and the test should be
///       inverted; OR
///   (b) someone changed the default helper to silently include the PQ
///       provider — which would surprise consumers of the unmodified
///       upstream API and should be reverted.
#[test]
fn classical_default_config_has_no_x25519_mlkem768() {
    let keypair = Keypair::generate_ed25519();
    let cfg = make_client_config(&keypair, None).expect("default client config build must succeed");

    let groups = client_kx_groups(&cfg);
    assert!(
        !groups.contains(&NamedGroup::X25519MLKEM768),
        "default ring-based client config must NOT include X25519MLKEM768; got {groups:?}",
    );
}

/// The PQ provider does not REPLACE the classical kx groups — it ADDS
/// X25519MLKEM768 alongside them. This matters for backward
/// compatibility: a node built with `hybrid-kem-tls` ON must still be
/// able to handshake with a peer built without it. Pin that the
/// classical X25519 group survives.
#[test]
fn pq_provider_keeps_classical_x25519_for_back_compat() {
    let keypair = Keypair::generate_ed25519();
    let provider = rustls_post_quantum::provider().clone();

    let cfg = make_client_config_with_provider(&keypair, None, Some(provider))
        .expect("client config build with PQ provider must succeed");

    let groups = client_kx_groups(&cfg);
    assert!(
        groups.contains(&NamedGroup::X25519),
        "PQ provider must KEEP classical X25519 for back-compat; got {groups:?}",
    );
}
