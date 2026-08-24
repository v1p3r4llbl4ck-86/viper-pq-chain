// SPDX-License-Identifier: BUSL-1.1
//! TLS provider initialization for `pqcd`.
//!
//! `init_pq_provider()` installs the `rustls-post-quantum` CryptoProvider
//! as the process-wide default. The libp2p TLS / QUIC paths already use
//! the provider explicitly via `*_with_provider()` constructors in
//! `pqc-p2p::swarm::spawn`; this function is for reqwest's benefit:
//! reqwest's `rustls-tls` feature picks the default provider, and a
//! default `reqwest::Client` will then offer X25519MLKEM768 in its
//! ClientHello.

use anyhow::Result;
#[cfg(feature = "hybrid-kem-tls")]
use tracing::info;
use tracing::warn;

/// Install the rustls-post-quantum CryptoProvider as the process default.
///
/// Idempotent: if a provider is already installed (e.g. a transitive dep
/// installed `ring` first), logs a warn and returns Ok. Returning Err
/// would crash the daemon on a benign race; the libp2p code path does
/// not depend on the default at all (it uses an explicit provider), so
/// reqwest is the only consumer we'd be silently downgrading. The warn
/// makes that visible without blocking startup.
#[cfg(feature = "hybrid-kem-tls")]
pub fn init_pq_provider() -> Result<()> {
    let provider = rustls_post_quantum::provider();
    match rustls::crypto::CryptoProvider::install_default(provider) {
        Ok(()) => {
            info!("PQ TLS provider installed: X25519MLKEM768 hybrid");
            Ok(())
        }
        Err(_existing) => {
            warn!(
                "rustls CryptoProvider was already installed by another \
                 component before pqcd::tls::init_pq_provider() ran. \
                 reqwest will use the pre-existing provider; libp2p \
                 TLS/QUIC paths are unaffected (they wire the PQ \
                 provider explicitly)."
            );
            Ok(())
        }
    }
}

/// Fallback when the feature is off: log the posture and return Ok.
#[cfg(not(feature = "hybrid-kem-tls"))]
pub fn init_pq_provider() -> Result<()> {
    warn!(
        "Hybrid PQ TLS feature disabled at compile time — reqwest and \
         libp2p will negotiate classical X25519 on the wire."
    );
    Ok(())
}
