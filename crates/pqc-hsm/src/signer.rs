// SPDX-License-Identifier: BUSL-1.1
//! `CommitSigner` — HSM-friendly trait for validator commit signing.
//!
//! See the private design notes abstraction" for
//! the full design. The trait is the load-bearing seam: every backend
//! (in-process, SoftHSM, AWS CloudHSM, future YubiHSM / Thales) plugs
//! in here, and the consensus loops in `pqcd::devnet` consume only the
//! trait — never the seed bytes.
//!
//! # Refinements vs. the phase plan sketch
//!
//! The plan sketches:
//! ```ignore
//! pub trait CommitSigner: Send + Sync {
//!     fn public_key(&self) -> &[u8];
//!     fn sign_commit(&self, preimage: &[u8]) -> Result<Vec<u8>, SignerError>;
//!     fn alg_id(&self) -> AlgId;
//! }
//! ```
//! This file ships exactly that surface plus three additions justified
//! below:
//!
//!   1. `validator_address(&self) -> &[u8]` — preserves the existing
//!      `LocalCommitSigner.validator_address` field. Without it, every
//!      call site that consumes a commit-sig vector has to thread the
//!      address through a separate channel; the trait already knows
//!      which validator it signs for, so exposing it costs nothing and
//!      keeps `snapshot_block_signers`'s output shape identical.
//!   2. `self_test(&self) -> Result<(), SignerError>` — boot-time
//!      verification per HSM-PHASE-PLAN §"Boot-time validation". A
//!      default impl signs `CANARY_PREIMAGE` and verifies against
//!      `public_key()`; backends that need a different self-test
//!      (e.g. an HSM whose verify path goes through a separate API
//!      from sign) override.
//!   3. `kind(&self) -> SignerKind` — used by the boot-time logger to
//!      tell the operator which backend produced the canary OK without
//!      relying on `Debug` impls.
//!
//! All additions preserve forward compatibility: the trait stays
//! object-safe (`Box<dyn CommitSigner>`) and the type signatures match
//! the plan exactly for the three load-bearing methods.

use crate::canary::CANARY_PREIMAGE;
use crate::config::SignerKind;
use crate::error::SignerError;
use pqc_crypto::AlgId;

/// Validator commit-signing abstraction. See module docs.
///
/// Implementations MUST be `Send + Sync` so a `Vec<Box<dyn CommitSigner>>`
/// can move across the `tokio::task::spawn_blocking` boundary in the
/// consensus loops.
pub trait CommitSigner: Send + Sync {
    /// 32-byte operator address this signer signs for. Mirrors the
    /// pre-trait `LocalCommitSigner.validator_address` field.
    fn validator_address(&self) -> &[u8];

    /// Public key bytes (cached, no HSM round-trip). Matches what the
    /// chain expects in `ValidatorRecord.consensus_pk`. The
    /// `snapshot_block_signers` lookup picks the trait impl whose
    /// `public_key()` matches the on-chain record.
    fn public_key(&self) -> &[u8];

    /// Sign `preimage` under the configured algorithm + key. May incur
    /// HSM RPC; backends are expected to handle their own retry inside
    /// the call when `is_transient(&err)` would otherwise be true.
    fn sign_commit(&self, preimage: &[u8]) -> Result<Vec<u8>, SignerError>;

    /// Algorithm identifier of the signing key. Must match the
    /// validator's `consensus_alg_id` on chain.
    fn alg_id(&self) -> AlgId;

    /// Backend tag for boot-time logging + telemetry.
    fn kind(&self) -> SignerKind;

    /// Boot-time self-test. Signs `CANARY_PREIMAGE` and verifies the
    /// signature against this signer's `public_key()`. Default impl
    /// covers ML-DSA backends via `pqc_crypto::MlDsaVerifier`; backends
    /// using non-ML-DSA mechanisms (the SoftHSM RSA-2048 placeholder)
    /// override.
    ///
    /// Returns `BackendMismatch` on verification failure, transient
    /// variants on RPC issues, `InvalidPreimage` if the canary itself
    /// fails structural validation (should never happen — defensive).
    fn self_test(&self) -> Result<(), SignerError> {
        use pqc_crypto::sign::{PublicKey, Signature, SignatureVerifier};
        use pqc_crypto::MlDsaVerifier;

        let alg = self.alg_id();
        if !matches!(alg, AlgId::MlDsa44 | AlgId::MlDsa65 | AlgId::MlDsa87) {
            // The default impl only covers ML-DSA backends. Non-ML-DSA
            // backends MUST override `self_test`.
            return Err(SignerError::BackendMismatch(format!(
                "default self_test does not cover alg {alg:?}; backend must override"
            )));
        }
        let signature_bytes = self.sign_commit(CANARY_PREIMAGE)?;
        let pk = PublicKey {
            alg_id: alg,
            bytes: self.public_key().to_vec(),
        };
        let sig = Signature {
            alg_id: alg,
            bytes: signature_bytes,
        };
        MlDsaVerifier
            .verify(&pk, CANARY_PREIMAGE, &sig)
            .map_err(|e| {
                SignerError::BackendMismatch(format!("canary preimage verification failed: {e:?}"))
            })
    }
}

// Object-safety check at compile time — the trait MUST be usable as
// `Box<dyn CommitSigner>` because the consensus loops carry a
// heterogeneous `Vec` across backends.
const _: fn() = || {
    fn assert_object_safe(_: &dyn CommitSigner) {}
    let _ = assert_object_safe;
};
