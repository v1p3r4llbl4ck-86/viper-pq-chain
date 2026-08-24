// SPDX-License-Identifier: BUSL-1.1
//! `LocalKeystoreSigner` — in-process ML-DSA `CommitSigner` impl.
//!
//! Wraps a 32-byte commit seed and the cached public key derived from
//! it via `pqc_crypto::ml_dsa_public_key_from_seed`. `sign_commit`
//! delegates to `pqc_crypto::ml_dsa_sign_with_seed` — byte-identical
//! output to the pre-trait `LocalCommitSigner` path in
//! `pqcd::devnet::snapshot_block_signers`. The pre-trait code path
//! lived in two places (the keystore module and an inline struct in
//! devnet.rs); both consolidate here.
//!
//! "Local" here is the historical naming: the seed is in process
//! memory. Production validator deployments will swap this signer for
//! `AwsCloudHsmSigner` once that lands; the trait surface is identical
//! so the consumer (`pqcd::devnet`) does not change.
//!
//! # Zeroisation
//!
//! `LocalKeystoreSigner` is `ZeroizeOnDrop` — when the in-memory
//! signer is dropped (e.g. process shutdown, signer-list rebuild after
//! a keystore reload), the seed is wiped. Same posture as the existing
//! `pqc_crypto::KemSeed` zeroisation.

use crate::config::SignerKind;
use crate::error::SignerError;
use crate::signer::CommitSigner;
use pqc_crypto::{ml_dsa_public_key_from_seed, ml_dsa_sign_with_seed, AlgId};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// In-process ML-DSA commit signer keyed by a 32-byte seed.
///
/// Constructed by the `pqcd` boot path from a `KeystoreEntry` — the
/// seed/pubkey/alg fields are exactly the entry's. Once the trait
/// object is in hand, callers never touch the seed bytes again.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LocalKeystoreSigner {
    /// 32-byte operator address. Matches `KeystoreEntry`'s implicit
    /// address (the keystore key) — kept here so the trait's
    /// `validator_address()` accessor doesn't need a separate lookup.
    #[zeroize(skip)]
    validator_address: [u8; 32],
    /// 32-byte commit seed feeding `ml_dsa_*_from_seed`.
    commit_seed: [u8; 32],
    /// Cached pubkey, derived once at construction. Avoids re-derivation
    /// on every `public_key()` call (the producer hot path).
    #[zeroize(skip)]
    public_key: Vec<u8>,
    /// ML-DSA parameter set used for both pubkey derivation and signing.
    #[zeroize(skip)]
    alg_id: AlgId,
}

impl LocalKeystoreSigner {
    /// Build a signer from raw seed material. Performs the pubkey
    /// derivation up front so a malformed seed surfaces here (during
    /// boot / keystore reload) instead of at first sign.
    ///
    /// `alg_id` MUST be one of `MlDsa44 / MlDsa65 / MlDsa87`; other
    /// values produce `SignerError::InvalidPreimage` (semantically a
    /// config bug, hence permanent).
    pub fn from_seed(
        validator_address: [u8; 32],
        alg_id: AlgId,
        commit_seed: [u8; 32],
    ) -> Result<Self, SignerError> {
        if !matches!(alg_id, AlgId::MlDsa44 | AlgId::MlDsa65 | AlgId::MlDsa87) {
            return Err(SignerError::InvalidPreimage(format!(
                "LocalKeystoreSigner only supports ML-DSA; got alg {alg_id:?}"
            )));
        }
        let public_key = ml_dsa_public_key_from_seed(alg_id, &commit_seed).map_err(|e| {
            SignerError::Other(anyhow::anyhow!(
                "failed to derive ML-DSA public key from commit seed: {e:?}"
            ))
        })?;
        Ok(Self {
            validator_address,
            commit_seed,
            public_key,
            alg_id,
        })
    }

    /// Build a signer when the caller already has the cached pubkey
    /// (e.g. it came from the keystore loader where the derivation was
    /// done at file-load time). Cross-checks the cached pubkey against
    /// a fresh derivation — a mismatch surfaces a tampered keystore,
    /// raising `BackendMismatch`. The fresh derivation is a one-time
    /// cost at construction; subsequent `public_key()` calls hit the
    /// cache.
    pub fn from_keystore_entry(
        validator_address: [u8; 32],
        alg_id: AlgId,
        commit_seed: [u8; 32],
        cached_public_key: Vec<u8>,
    ) -> Result<Self, SignerError> {
        let signer = Self::from_seed(validator_address, alg_id, commit_seed)?;
        if signer.public_key != cached_public_key {
            return Err(SignerError::BackendMismatch(format!(
                "cached pubkey for validator {} does not derive from \
                 the supplied commit seed — keystore is inconsistent or tampered",
                hex::encode(validator_address),
            )));
        }
        Ok(signer)
    }
}

/// Custom `Debug` that NEVER prints the seed bytes — same posture as
/// `pqc_crypto::KemSeed`. Without this, `Result::unwrap_err` and any
/// `tracing::debug!` of a signer would include the secret.
impl std::fmt::Debug for LocalKeystoreSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKeystoreSigner")
            .field("validator_address", &hex::encode(self.validator_address))
            .field("alg_id", &self.alg_id)
            .field("public_key_len", &self.public_key.len())
            .field("commit_seed", &"[redacted]")
            .finish()
    }
}

impl CommitSigner for LocalKeystoreSigner {
    fn validator_address(&self) -> &[u8] {
        &self.validator_address
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign_commit(&self, preimage: &[u8]) -> Result<Vec<u8>, SignerError> {
        ml_dsa_sign_with_seed(self.alg_id, &self.commit_seed, preimage)
            .map_err(|e| SignerError::Other(anyhow::anyhow!("ML-DSA commit signing failed: {e:?}")))
    }

    fn alg_id(&self) -> AlgId {
        self.alg_id
    }

    fn kind(&self) -> SignerKind {
        SignerKind::LocalKeystore
    }
}

#[cfg(test)]
mod tests;
