// SPDX-License-Identifier: Apache-2.0
//! Signature verification interface.
//!
//! This module defines the protocol-level types and the `SignatureVerifier` trait.
//! Concrete implementations (liboqs, mldsa-native, stub) implement the trait.
//!
//! SPEC-TX-001 §9 — signed preimage construction.
//! SPEC-TX-001 §8 — validation pipeline steps 8-9 (signature verification).

use crate::{AlgId, CryptoError};

/// Raw public key bytes as stored in a KeySet entry (SPEC-ACCOUNT-001 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub alg_id: AlgId,
    pub bytes: Vec<u8>,
}

/// Raw signature bytes from a transaction envelope (SPEC-TX-001 §3, field 12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub alg_id: AlgId,
    pub bytes: Vec<u8>,
}

/// Verifies a post-quantum signature over a preimage.
///
/// Implementations of this trait wrap a specific crypto backend.
/// The verifier is stateless — it does not consult the Algorithm Registry.
/// Registry lifecycle checks happen before calling verify (SPEC-TX-001 §8, step 3).
pub trait SignatureVerifier: Send + Sync {
    /// Verify `signature` over `preimage` using `public_key`.
    ///
    /// The `preimage` is the signed preimage as constructed by SPEC-TX-001 §9:
    /// `b"PQC-TX-V1" || CBOR({1: tx_version, ..., 11: sig_key_version})`
    ///
    /// Returns `Ok(())` on valid signature, `Err(CryptoError::VerificationFailed)` on invalid.
    /// Returns other `CryptoError` variants for structural issues (wrong key size, unknown alg).
    fn verify(
        &self,
        public_key: &PublicKey,
        preimage: &[u8],
        signature: &Signature,
    ) -> Result<(), CryptoError>;
}

#[cfg(feature = "ml-dsa-backend")]
pub fn ml_dsa_public_key_from_seed(alg_id: AlgId, seed: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    ml_dsa_dispatch(alg_id, seed, |signing_key| {
        signing_key.verifying_key().encode()
    })
}

#[cfg(feature = "ml-dsa-backend")]
pub fn ml_dsa_sign_with_seed(
    alg_id: AlgId,
    seed: &[u8; 32],
    preimage: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    ml_dsa_dispatch(alg_id, seed, |signing_key| {
        signing_key.signing_key().sign(preimage)
    })
}

#[cfg(feature = "ml-dsa-backend")]
fn ml_dsa_dispatch<T>(
    alg_id: AlgId,
    seed: &[u8; 32],
    f: impl FnOnce(MlDsaKeypair) -> T,
) -> Result<T, CryptoError> {
    use ml_dsa::{KeyGen, MlDsa44, MlDsa65, MlDsa87};

    let keypair = match alg_id {
        AlgId::MlDsa44 => MlDsaKeypair::MlDsa44(MlDsa44::from_seed(seed.into())),
        AlgId::MlDsa65 => MlDsaKeypair::MlDsa65(MlDsa65::from_seed(seed.into())),
        AlgId::MlDsa87 => MlDsaKeypair::MlDsa87(MlDsa87::from_seed(seed.into())),
        other => return Err(CryptoError::NotASigningAlgorithm(other)),
    };

    Ok(f(keypair))
}

// ML-DSA key sizes are inherently large (MlDsa87 signing key ≈ 104 KB). This enum
// is a private dispatch helper created and consumed within a single function call —
// it never escapes ml_dsa_dispatch. Boxing would add a heap allocation with no
// benefit since the value is not stored or moved after construction.
#[cfg(feature = "ml-dsa-backend")]
#[allow(clippy::large_enum_variant)]
enum MlDsaKeypair {
    MlDsa44(ml_dsa::SigningKey<ml_dsa::MlDsa44>),
    MlDsa65(ml_dsa::SigningKey<ml_dsa::MlDsa65>),
    MlDsa87(ml_dsa::SigningKey<ml_dsa::MlDsa87>),
}

#[cfg(feature = "ml-dsa-backend")]
impl MlDsaKeypair {
    fn verifying_key(&self) -> MlDsaVerifyingKey {
        use ml_dsa::signature::Keypair;

        match self {
            Self::MlDsa44(signing_key) => MlDsaVerifyingKey::MlDsa44(signing_key.verifying_key()),
            Self::MlDsa65(signing_key) => MlDsaVerifyingKey::MlDsa65(signing_key.verifying_key()),
            Self::MlDsa87(signing_key) => MlDsaVerifyingKey::MlDsa87(signing_key.verifying_key()),
        }
    }

    fn signing_key(&self) -> MlDsaExpandedSigningKey<'_> {
        match self {
            Self::MlDsa44(signing_key) => {
                MlDsaExpandedSigningKey::MlDsa44(signing_key.signing_key())
            }
            Self::MlDsa65(signing_key) => {
                MlDsaExpandedSigningKey::MlDsa65(signing_key.signing_key())
            }
            Self::MlDsa87(signing_key) => {
                MlDsaExpandedSigningKey::MlDsa87(signing_key.signing_key())
            }
        }
    }
}

// Same rationale as MlDsaKeypair: transient dispatch enum, never stored.
#[cfg(feature = "ml-dsa-backend")]
#[allow(clippy::large_enum_variant)]
enum MlDsaVerifyingKey {
    MlDsa44(ml_dsa::VerifyingKey<ml_dsa::MlDsa44>),
    MlDsa65(ml_dsa::VerifyingKey<ml_dsa::MlDsa65>),
    MlDsa87(ml_dsa::VerifyingKey<ml_dsa::MlDsa87>),
}

#[cfg(feature = "ml-dsa-backend")]
impl MlDsaVerifyingKey {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::MlDsa44(verifying_key) => verifying_key.encode().to_vec(),
            Self::MlDsa65(verifying_key) => verifying_key.encode().to_vec(),
            Self::MlDsa87(verifying_key) => verifying_key.encode().to_vec(),
        }
    }
}

#[cfg(feature = "ml-dsa-backend")]
enum MlDsaExpandedSigningKey<'a> {
    MlDsa44(&'a ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa44>),
    MlDsa65(&'a ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>),
    MlDsa87(&'a ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa87>),
}

#[cfg(feature = "ml-dsa-backend")]
impl MlDsaExpandedSigningKey<'_> {
    fn sign(&self, preimage: &[u8]) -> Vec<u8> {
        use ml_dsa::signature::{SignatureEncoding, Signer};

        match self {
            Self::MlDsa44(signing_key) => signing_key.sign(preimage).to_bytes().as_slice().to_vec(),
            Self::MlDsa65(signing_key) => signing_key.sign(preimage).to_bytes().as_slice().to_vec(),
            Self::MlDsa87(signing_key) => signing_key.sign(preimage).to_bytes().as_slice().to_vec(),
        }
    }
}

/// Generate an SLH-DSA-SHA2-128s keypair.
///
/// Returns `(pk_bytes, sk_bytes)` where pk is 32 bytes and sk is 64 bytes.
/// Called during key rotation drills and canary tx generation (TASK-063).
///
/// Uses `rand_core 0.6` OsRng because `slh_dsa::SigningKey::new()` requires the
/// `rand_core 0.6` `CryptoRngCore` trait (the vendor-patched crate retains the 0.6 dep).
#[cfg(feature = "slh-dsa-backend")]
pub fn slh_dsa_sha2_128s_generate() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use rand_core_06::OsRng;
    use slh_dsa::{Sha2_128s, SigningKey};
    let sk = SigningKey::<Sha2_128s>::new(&mut OsRng);
    let pk: Vec<u8> = sk.as_ref().to_vec();
    let sk_bytes: Vec<u8> = sk.to_vec();
    Ok((pk, sk_bytes))
}

/// Sign `preimage` with an SLH-DSA-SHA2-128s secret key (FIPS 205, pure mode).
///
/// `sk_bytes` must be 64 bytes (SLH-DSA-SHA2-128s secret key).
/// Signing is deterministic (no additional randomness, `opt_rand = None`).
/// Returns the 7,856-byte signature as a `Vec<u8>`.
#[cfg(feature = "slh-dsa-backend")]
pub fn slh_dsa_sha2_128s_sign(sk_bytes: &[u8], preimage: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use slh_dsa::{Sha2_128s, SigningKey};
    let sk =
        SigningKey::<Sha2_128s>::try_from(sk_bytes).map_err(|_| CryptoError::InvalidKeySize)?;
    // Pure (deterministic) mode: opt_rand = None. No RNG needed for signing.
    let sig = sk
        .try_sign_with_context(preimage, b"", None)
        .map_err(|e| CryptoError::Backend(e.to_string()))?;
    Ok(sig.to_vec())
}

/// Generate an SLH-DSA-SHAKE-128s keypair.
///
/// Returns `(pk_bytes, sk_bytes)` where pk is 32 bytes and sk is 64 bytes.
/// Uses `rand_core 0.6` OsRng (vendor-patched crate retains the 0.6 dep).
#[cfg(feature = "slh-dsa-backend")]
pub fn slh_dsa_shake_128s_generate() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use rand_core_06::OsRng;
    use slh_dsa::{Shake128s, SigningKey};
    let sk = SigningKey::<Shake128s>::new(&mut OsRng);
    let pk: Vec<u8> = sk.as_ref().to_vec();
    let sk_bytes: Vec<u8> = sk.to_vec();
    Ok((pk, sk_bytes))
}

/// Sign `preimage` with an SLH-DSA-SHAKE-128s secret key (FIPS 205, pure mode).
///
/// `sk_bytes` must be 64 bytes (SLH-DSA-SHAKE-128s secret key).
/// Signing is deterministic (no additional randomness, `opt_rand = None`).
/// Returns the 7,856-byte signature as a `Vec<u8>`.
#[cfg(feature = "slh-dsa-backend")]
pub fn slh_dsa_shake_128s_sign(sk_bytes: &[u8], preimage: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use slh_dsa::{Shake128s, SigningKey};
    let sk =
        SigningKey::<Shake128s>::try_from(sk_bytes).map_err(|_| CryptoError::InvalidKeySize)?;
    let sig = sk
        .try_sign_with_context(preimage, b"", None)
        .map_err(|e| CryptoError::Backend(e.to_string()))?;
    Ok(sig.to_vec())
}

/// Generate an SLH-DSA-SHAKE-192s keypair.
///
/// Returns `(pk_bytes, sk_bytes)` where pk is 48 bytes and sk is 96 bytes.
/// Uses `rand_core 0.6` OsRng (vendor-patched crate retains the 0.6 dep).
#[cfg(feature = "slh-dsa-backend")]
pub fn slh_dsa_shake_192s_generate() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use rand_core_06::OsRng;
    use slh_dsa::{Shake192s, SigningKey};
    let sk = SigningKey::<Shake192s>::new(&mut OsRng);
    let pk: Vec<u8> = sk.as_ref().to_vec();
    let sk_bytes: Vec<u8> = sk.to_vec();
    Ok((pk, sk_bytes))
}

/// Sign `preimage` with an SLH-DSA-SHAKE-192s secret key (FIPS 205, pure mode).
///
/// `sk_bytes` must be 96 bytes (SLH-DSA-SHAKE-192s secret key).
/// Signing is deterministic (no additional randomness, `opt_rand = None`).
/// Returns the 16,224-byte signature as a `Vec<u8>`.
#[cfg(feature = "slh-dsa-backend")]
pub fn slh_dsa_shake_192s_sign(sk_bytes: &[u8], preimage: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use slh_dsa::{Shake192s, SigningKey};
    let sk =
        SigningKey::<Shake192s>::try_from(sk_bytes).map_err(|_| CryptoError::InvalidKeySize)?;
    let sig = sk
        .try_sign_with_context(preimage, b"", None)
        .map_err(|e| CryptoError::Backend(e.to_string()))?;
    Ok(sig.to_vec())
}

/// Generate an SLH-DSA-SHAKE-256s keypair.
///
/// Returns `(pk_bytes, sk_bytes)` where pk is 64 bytes and sk is 128 bytes.
/// Uses `rand_core 0.6` OsRng (vendor-patched crate retains the 0.6 dep).
#[cfg(feature = "slh-dsa-backend")]
pub fn slh_dsa_shake_256s_generate() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use rand_core_06::OsRng;
    use slh_dsa::{Shake256s, SigningKey};
    let sk = SigningKey::<Shake256s>::new(&mut OsRng);
    let pk: Vec<u8> = sk.as_ref().to_vec();
    let sk_bytes: Vec<u8> = sk.to_vec();
    Ok((pk, sk_bytes))
}

/// Sign `preimage` with an SLH-DSA-SHAKE-256s secret key (FIPS 205, pure mode).
///
/// `sk_bytes` must be 128 bytes (SLH-DSA-SHAKE-256s secret key).
/// Signing is deterministic (no additional randomness, `opt_rand = None`).
/// Returns the 29,792-byte signature as a `Vec<u8>`.
#[cfg(feature = "slh-dsa-backend")]
pub fn slh_dsa_shake_256s_sign(sk_bytes: &[u8], preimage: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use slh_dsa::{Shake256s, SigningKey};
    let sk =
        SigningKey::<Shake256s>::try_from(sk_bytes).map_err(|_| CryptoError::InvalidKeySize)?;
    let sig = sk
        .try_sign_with_context(preimage, b"", None)
        .map_err(|e| CryptoError::Backend(e.to_string()))?;
    Ok(sig.to_vec())
}

/// Stub verifier for development and testing before a real backend is wired in.
///
/// NEVER use in production. Always returns `Ok(())` for known algorithms,
/// allowing the rest of the pipeline to be exercised with synthetic test data.
#[cfg(feature = "stub-verifier")]
pub struct StubVerifier;

#[cfg(feature = "stub-verifier")]
impl SignatureVerifier for StubVerifier {
    fn verify(
        &self,
        public_key: &PublicKey,
        _preimage: &[u8],
        signature: &Signature,
    ) -> Result<(), CryptoError> {
        use crate::AlgId;

        // Reject mismatched alg_id between key and signature.
        if public_key.alg_id != signature.alg_id {
            return Err(CryptoError::NotASigningAlgorithm(signature.alg_id));
        }

        // Reject ML-KEM (not a signing algorithm).
        if matches!(signature.alg_id, AlgId::MlKem768) {
            return Err(CryptoError::NotASigningAlgorithm(signature.alg_id));
        }

        Ok(())
    }
}
