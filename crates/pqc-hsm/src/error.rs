// SPDX-License-Identifier: BUSL-1.1
//! `SignerError` — failure modes a `CommitSigner` can surface.
//!
//! Per the private design notes abstraction":
//! every backend (in-process, SoftHSM, AWS CloudHSM) must classify
//! failures into the same coarse categories so the consensus loop can
//! decide between retry, failover, and operator-actionable abort
//! WITHOUT depending on backend-specific error types.

use thiserror::Error;

/// A signing failure surfaced by a `CommitSigner` impl.
///
/// Each variant carries actionable semantics:
///   - `HsmUnavailable` — transient; the consensus loop should retry
///     (HSM rebooting, network blip). After N retries it falls through
///     to "skip signing for this round" — better than halting.
///   - `InvalidPreimage` — permanent; the producer fed garbage to the
///     signer. Surfaces a config bug or a wire-format regression. NOT
///     retried.
///   - `RateLimited` — backoff; the HSM is alive but throttled. Same
///     retry shape as `HsmUnavailable` but with a longer base delay.
///   - `BackendMismatch` — permanent; the cached pubkey for this signer
///     does not derive from the underlying signing material. Caught by
///     the boot-time self-test (`CommitSigner::self_test`); reaching
///     this variant in the steady state means a key was swapped on the
///     HSM out from under the cached pubkey, which is a security
///     incident — fail closed.
///   - `Other` — catch-all for backend-specific errors not yet
///     classified. New backends should refine this into a typed variant
///     before going to production.
#[derive(Debug, Error)]
pub enum SignerError {
    /// HSM is reachable but the session/handle is not usable. Transient.
    #[error("HSM unavailable: {0}")]
    HsmUnavailable(String),

    /// Preimage failed structural validation before reaching the
    /// underlying crypto primitive. Permanent — surfaces a wire-format
    /// or call-site bug. NOT retried.
    #[error("invalid preimage: {0}")]
    InvalidPreimage(String),

    /// HSM rejected the request because of a rate limit or quota.
    /// Transient with a longer back-off than `HsmUnavailable`.
    #[error("rate limited by HSM: {0}")]
    RateLimited(String),

    /// The cached pubkey does not derive from the underlying signing
    /// material — caught by `self_test`. Fail closed in steady state:
    /// either the HSM key was swapped or the seed file is stale.
    #[error("signer self-test failed: {0}")]
    BackendMismatch(String),

    /// Catch-all for backend-specific errors not yet classified.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl SignerError {
    /// Helper: classify a SignerError as transient (worth retrying)
    /// versus permanent (a bug or security event).
    ///
    /// Used by the consensus loop's retry shim — current code does not
    /// retry inside `snapshot_block_signers` (the producer simply drops
    /// the validator from the signer set on failure), but the helper is
    /// exposed for future loops + the `viper-hsm-probe` binary.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::HsmUnavailable(_) | Self::RateLimited(_))
    }
}
