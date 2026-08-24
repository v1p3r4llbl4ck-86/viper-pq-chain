// Copyright 2021 Parity Technologies (UK) Ltd.
// Copyright 2022 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! TLS configuration based on libp2p TLS specs.
//!
//! See <https://github.com/libp2p/specs/blob/master/tls/tls.md>.
//!
//! # PQ-Chain vendor patch (2026-05-11)
//!
//! Adds an injection seam for `rustls::crypto::CryptoProvider` so consumers
//! can plug in [`rustls-post-quantum`](https://crates.io/crates/rustls-post-quantum)
//! to enable the X25519MLKEM768 hybrid group on the TLS handshake. The
//! upstream 0.6.2 release hard-codes `rustls::crypto::ring::default_provider()`
//! at every call site; the additive patch keeps that as the default but lets
//! a caller override it via [`make_client_config_with_provider`] /
//! [`make_server_config_with_provider`] (and the matching
//! [`Config::new_with_provider`]). Tracking issue: `libp2p/rust-libp2p#6236`.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod certificate;
mod upgrade;
mod verifier;

use std::sync::Arc;

use certificate::AlwaysResolvesCert;
pub use futures_rustls::TlsStream;
use libp2p_identity::{Keypair, PeerId};
pub use upgrade::{Config, UpgradeError};

const P2P_ALPN: [u8; 6] = *b"libp2p";

/// Build a `CryptoProvider` from `ring` with libp2p-tls's required cipher suites.
///
/// PQ-Chain vendor patch: extracted into a helper so it can be reused as the
/// default-provider fallback by both the unmodified API
/// (`make_client_config`, `make_server_config`) and the new
/// `_with_provider` variants when the caller passes `None`.
fn default_libp2p_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = verifier::CIPHERSUITES.to_vec();
    provider
}

/// Create a TLS client configuration for libp2p.
pub fn make_client_config(
    keypair: &Keypair,
    remote_peer_id: Option<PeerId>,
) -> Result<rustls::ClientConfig, certificate::GenError> {
    make_client_config_with_provider(keypair, remote_peer_id, None)
}

/// Create a TLS client configuration for libp2p with an optional custom
/// `rustls::crypto::CryptoProvider`.
///
/// PQ-Chain vendor patch: when `custom_provider` is `Some`, the caller's
/// provider is used verbatim — pass e.g.
/// `rustls_post_quantum::provider()` to enable X25519MLKEM768. When `None`,
/// the default `ring`-based provider with libp2p's cipher-suite list is
/// used (preserves upstream 0.6.2 behaviour exactly).
pub fn make_client_config_with_provider(
    keypair: &Keypair,
    remote_peer_id: Option<PeerId>,
    custom_provider: Option<rustls::crypto::CryptoProvider>,
) -> Result<rustls::ClientConfig, certificate::GenError> {
    let (certificate, private_key) = certificate::generate(keypair)?;

    let provider = custom_provider.unwrap_or_else(default_libp2p_provider);

    let cert_resolver = Arc::new(
        AlwaysResolvesCert::new(certificate, &private_key)
            .expect("Client cert key DER is valid; qed"),
    );

    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            verifier::Libp2pCertificateVerifier::with_remote_peer_id(remote_peer_id),
        ))
        .with_client_cert_resolver(cert_resolver);
    crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];

    Ok(crypto)
}

/// Create a TLS server configuration for libp2p.
pub fn make_server_config(
    keypair: &Keypair,
) -> Result<rustls::ServerConfig, certificate::GenError> {
    make_server_config_with_provider(keypair, None)
}

/// Create a TLS server configuration for libp2p with an optional custom
/// `rustls::crypto::CryptoProvider`.
///
/// PQ-Chain vendor patch: see [`make_client_config_with_provider`].
pub fn make_server_config_with_provider(
    keypair: &Keypair,
    custom_provider: Option<rustls::crypto::CryptoProvider>,
) -> Result<rustls::ServerConfig, certificate::GenError> {
    let (certificate, private_key) = certificate::generate(keypair)?;

    let provider = custom_provider.unwrap_or_else(default_libp2p_provider);

    let cert_resolver = Arc::new(
        AlwaysResolvesCert::new(certificate, &private_key)
            .expect("Server cert key DER is valid; qed"),
    );

    let mut crypto = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .with_client_cert_verifier(Arc::new(verifier::Libp2pCertificateVerifier::new()))
        .with_cert_resolver(cert_resolver);
    crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];

    Ok(crypto)
}
