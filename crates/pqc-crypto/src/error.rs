// SPDX-License-Identifier: Apache-2.0
//! Cryptographic error types.

use crate::AlgId;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("unknown algorithm id: 0x{0:04x}")]
    UnknownAlgId(u16),

    #[error("algorithm {0:?} is not a signing algorithm")]
    NotASigningAlgorithm(AlgId),

    #[error("algorithm {0:?} is banned and cannot be used")]
    AlgorithmBanned(AlgId),

    #[error("public key length mismatch for {alg:?}: expected {expected}, got {got}")]
    PublicKeyLengthMismatch {
        alg: AlgId,
        expected: usize,
        got: usize,
    },

    #[error("signature length mismatch for {alg:?}: expected {expected}, got {got}")]
    SignatureLengthMismatch {
        alg: AlgId,
        expected: usize,
        got: usize,
    },

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("invalid public key size for the requested algorithm")]
    InvalidKeySize,

    #[error("invalid signature size for the requested algorithm")]
    InvalidSignatureSize,

    #[error("crypto backend error: {0}")]
    Backend(String),

    /// Peer-supplied KEM encapsulation key failed ML-KEM mathematical validation.
    /// Returned by `kem_encapsulate` rather than panicking, so an adversarial peer
    /// cannot crash the node by sending a malformed key.
    #[error("invalid ML-KEM encapsulation key")]
    KemInvalidKey,

    /// Bech32m encoding failed (invalid HRP or encoding error).
    #[error("bech32m encoding error: {0}")]
    Bech32mEncodingError(String),
}
